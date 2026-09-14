// Bounded memory port of RCOMage rcoreader.c/rcomain.c at
// 54ca649a9a6aba150a1fbe423f4c3aec611ee913, Copyright (C) ZiNgA BuRgA,
// distributed under LGPL-2.1. No upstream file/global state is retained.
const std = @import("std");
const memory = @import("../bytes.zig");
const config = @import("config.zig");
const lzr = @import("../lzr.zig");
const c = @cImport({
    @cInclude("zlib.h");
});
pub const nil = std.math.maxInt(u32);
const label_limit = 16 * 1024 * 1024;
const tree_limit = 32 * 1024 * 1024;
pub fn region(data: []const u8, offset: usize, length: usize) ![]const u8 {
    if (offset > data.len or length > data.len - offset) return error.InvalidRcoRange;
    return data[offset..][0..length];
}
pub fn subview(view: memory.View, offset: usize, length: usize) !memory.View {
    return .{ .owner = view.owner, .bytes = try region(view.bytes, offset, length) };
}
pub fn string(data: []const u8, offset: usize) ![]const u8 {
    const rest = try region(data, offset, data.len -| offset);
    const end = std.mem.indexOfScalar(u8, rest, 0) orelse return error.InvalidRcoString;
    return rest[0..end];
}
pub const Index = struct { label: u32, length: u32, offset: u32 };
pub const Channel = struct { length: u32, offset: u32 };
pub const Entry = struct {
    offset: usize,
    id: u8,
    kind: u8,
    label: u32,
    parent: ?usize,
    depth: usize,
    children: u32,
    end: usize = 0,
    next_offset: u32,
    format: u16 = 0,
    compression: u8 = 0,
    unknown_byte: u8 = 0,
    language: u16 = 0,
    unpacked: u32 = 0,
    source: ?memory.View = null,
    extra: []const u8 = &.{},
    indexes: []Index = &.{},
    channels: []Channel = &.{},
    output_name: []const u8 = "",
};
const TextBlock = struct { offset: usize, language: u16, next: u32, data: memory.View };
pub const Model = struct {
    allocator: std.mem.Allocator,
    backing_allocator: std.mem.Allocator,
    input: memory.View,
    tree: memory.View,
    tree_offset: usize = 0,
    endian: std.builtin.Endian,
    header: [41]u32,
    owned: std.ArrayList(memory.View) = .empty,
    blocks: std.ArrayList(TextBlock) = .empty,
    entries: std.ArrayList(Entry) = .empty,
    offsets: std.AutoHashMapUnmanaged(usize, usize) = .empty,
    tables: [10]?usize = .{null} ** 10,
    labels: []const u8 = &.{},
    events: []const u8 = &.{},

    pub fn deinit(self: *Model) void {
        for (self.owned.items) |view| view.release();
        // All graph/index/map storage belongs to the caller's invocation arena.
    }
    pub fn ps3(self: *const Model) bool {
        return self.endian == .big;
    }
    pub fn u16_at(self: *const Model, data: []const u8, pos: usize) !u16 {
        return std.mem.readInt(u16, (try region(data, pos, 2))[0..2], self.endian);
    }
    pub fn u32_at(self: *const Model, data: []const u8, pos: usize) !u32 {
        return std.mem.readInt(u32, (try region(data, pos, 4))[0..4], self.endian);
    }
    pub fn label(self: *const Model, offset: u32) ![]const u8 {
        return string(self.labels, offset);
    }
    pub fn resource_label(self: *const Model, offset: u32) ![]const u8 {
        return if (offset == 0) "No Label" else self.label(offset);
    }
    pub fn tree_region(self: *const Model, offset: usize, length: usize) !memory.View {
        if (offset < self.tree_offset) return error.InvalidRcoRange;
        return subview(self.tree, offset - self.tree_offset, length);
    }
    fn own(self: *Model, view: memory.View) !memory.View {
        errdefer view.release();
        try self.owned.append(self.allocator, view);
        return view;
    }
    pub fn decode(self: *Model, encoded: []const u8, length: usize, compression: u8) !memory.View {
        const output = try self.backing_allocator.alloc(u8, length);
        const view = try memory.Owner.take_allocated(self.backing_allocator, output);
        errdefer view.release();
        try decode_into(encoded, output, compression);
        return view;
    }
    fn decode_into(encoded: []const u8, output: []u8, compression: u8) !void {
        switch (compression) {
            1 => {
                var actual: c.uLongf = @intCast(output.len);
                if (c.uncompress(output.ptr, &actual, encoded.ptr, @intCast(encoded.len)) != c.Z_OK or actual != output.len) return error.InvalidRcoCompression;
            },
            2 => if (try lzr.decode_raw_into(encoded, output) != output.len) return error.InvalidRcoCompression,
            else => return error.InvalidRcoCompression,
        }
    }
    fn text_block(self: *Model, offset: usize) !TextBlock {
        for (self.blocks.items) |block| if (block.offset == offset) return block;
        const info = try region(self.input.bytes, offset, 16);
        if (try self.u16_at(info, 2) != 1) return error.InvalidRcoTextHeader;
        const encoded = try self.u32_at(info, 8);
        const unpacked = try self.u32_at(info, 12);
        if (encoded > label_limit or unpacked > label_limit) return error.InvalidRcoLimit;
        const view = try self.own(try self.decode(try region(self.input.bytes, offset + 16, encoded), unpacked, @intCast(self.header[3] >> 4)));
        const block: TextBlock = .{ .offset = offset, .language = try self.u16_at(info, 0), .next = try self.u32_at(info, 4), .data = view };
        if (block.next != 0 and block.next < 16 + @as(usize, encoded)) return error.InvalidRcoTextHeader;
        try self.blocks.append(self.allocator, block);
        return block;
    }
    pub fn init(allocator: std.mem.Allocator, backing_allocator: std.mem.Allocator, input: memory.View) !Model {
        _ = try region(input.bytes, 0, 164);
        const sig = std.mem.readInt(u32, input.bytes[0..4], .little);
        var self: Model = .{ .allocator = allocator, .backing_allocator = backing_allocator, .input = input, .tree = input, .header = undefined, .endian = switch (sig) {
            0x46525000 => .little,
            0x00505246 => .big,
            else => return error.InvalidRcoMagic,
        } };
        errdefer self.deinit();
        for (&self.header, 0..) |*word, i| word.* = try self.u32_at(input.bytes, i * 4);
        const h = self.header;
        if (h[2] != 0 or h[10] != nil or h[38] != nil or h[39] != nil or h[40] != nil) return error.InvalidRcoHeader;
        const compression = h[3] >> 4;
        if (compression > 2 or (compression == 1 and h[1] < 0x90) or (compression == 2 and h[1] < 0x95)) return error.InvalidRcoCompression;
        var source_text_start: usize = 0;
        var expanded_size = input.bytes.len;
        if (compression != 0) {
            const encoded = try self.u32_at(input.bytes, 164);
            const unpacked = try self.u32_at(input.bytes, 168);
            _ = try region(input.bytes, 164, 12);
            if (encoded > tree_limit or unpacked > tree_limit) return error.InvalidRcoLimit;
            const table_data = try region(input.bytes, 176, encoded);
            expanded_size = try std.math.add(usize, input.bytes.len - std.mem.alignForward(usize, encoded, 4), unpacked);
            const TextInfo = struct { offset: usize, language: u16, next: u32, encoded: u32, unpacked: u32, target: usize };
            var text_info: std.ArrayList(TextInfo) = .empty;
            var total: usize = unpacked;
            source_text_start = 176 + std.mem.alignForward(usize, encoded, 4);
            // Size the virtual region first, then decode directly into one
            // shared backing. Embedded VSMX and all languages borrow it.
            if (h[14] != nil and h[15] != 0) {
                var position: usize = h[14];
                total = std.mem.alignForward(usize, total, 4);
                while (true) {
                    const info = try region(input.bytes, position, 16);
                    if (try self.u16_at(info, 2) != 1) return error.InvalidRcoTextHeader;
                    const text_packed = try self.u32_at(info, 8);
                    const text_unpacked = try self.u32_at(info, 12);
                    const next = try self.u32_at(info, 4);
                    if (text_packed > label_limit or text_unpacked > label_limit) return error.InvalidRcoLimit;
                    _ = try region(input.bytes, position + 16, text_packed);
                    if (next != 0 and next < 16 + @as(usize, text_packed)) return error.InvalidRcoTextHeader;
                    try text_info.append(allocator, .{ .offset = position, .language = try self.u16_at(info, 0), .next = next, .encoded = text_packed, .unpacked = text_unpacked, .target = total });
                    total = try std.math.add(usize, total, std.mem.alignForward(usize, text_unpacked, 4));
                    expanded_size = try std.math.add(usize, try std.math.sub(usize, expanded_size, std.mem.alignForward(usize, text_packed, 4)), std.mem.alignForward(usize, text_unpacked, 4));
                    if (next == 0) break;
                    position = try std.math.add(usize, position, next);
                }
            }
            const combined = try backing_allocator.alloc(u8, total);
            self.tree = try self.own(try memory.Owner.take_allocated(backing_allocator, combined));
            self.tree_offset = 164;
            @memset(combined, 0);
            try decode_into(table_data, combined[0..unpacked], @intCast(compression));
            for (text_info.items) |info| {
                const target = combined[info.target..][0..info.unpacked];
                try decode_into(try region(input.bytes, info.offset + 16, info.encoded), target, @intCast(compression));
                try self.blocks.append(allocator, .{ .offset = info.offset, .language = info.language, .next = info.next, .data = .{ .owner = self.tree.owner, .bytes = target } });
            }
        }
        if (h[17] > label_limit or h[19] > label_limit) return error.InvalidRcoLimit;
        for ([_]usize{ 16, 18 }) |p| {
            if (h[p] > expanded_size or h[p + 1] > expanded_size - h[p]) return error.InvalidRcoRange;
        }
        if (h[17] != 0) self.labels = (try self.tree_region(h[16], h[17])).bytes;
        if (h[19] != 0) self.events = (try self.tree_region(h[18], h[19])).bytes;
        for ([_]usize{ 28, 30 }) |p| {
            if (h[p] != nil) {
                if (h[p + 1] > label_limit) return error.InvalidRcoLimit;
                if (h[p] > expanded_size or h[p + 1] > expanded_size - h[p]) return error.InvalidRcoRange;
            }
        }
        try self.parse_entries(h[4]);
        const pointers = [_]usize{ 0, 4, 5, 6, 9, 8, 7, 11, 12, 13 };
        for (self.entries.items, 0..) |entry, i| {
            if (entry.parent != 0 or entry.id < 2) continue;
            if (h[pointers[entry.id]] == nil or self.tables[entry.id] != null) return error.InvalidRcoTable;
            self.tables[entry.id] = i;
        }
        for (2..10) |id| if (h[pointers[id]] != nil and self.tables[id] == null) return error.InvalidRcoTable;
        // The CLI associates compressed text by its second, physical chain.
        if (self.tables[3]) |table| {
            if (h[15] != 0 and compression != 0) {
                var position = source_text_start;
                while (true) {
                    const block = try self.text_block(position);
                    var child = table + 1;
                    while (child < self.entries.items[table].end) : (child = self.entries.items[child].end) {
                        const entry = &self.entries.items[child];
                        if (entry.language == block.language) {
                            entry.source = block.data;
                            entry.unpacked = @intCast(block.data.bytes.len);
                            break;
                        }
                    }
                    if (block.next == 0) break;
                    position = try std.math.add(usize, position, block.next);
                }
            } else {
                var child = table + 1;
                while (child < self.entries.items[table].end) : (child = self.entries.items[child].end) {
                    self.entries.items[child].source = try subview(input, if (h[15] == 0) 0 else h[14], h[15]);
                    self.entries.items[child].unpacked = h[15];
                }
            }
        }
        for ([_]struct { id: usize, p: usize }{ .{ .id = 3, .p = 14 }, .{ .id = 4, .p = 32 }, .{ .id = 6, .p = 34 }, .{ .id = 5, .p = 36 } }) |pair| {
            if (self.tables[pair.id]) |table| if (self.entries.items[table].children != 0) {
                _ = try region(input.bytes, h[pair.p], h[pair.p + 1]);
            };
        }
        for (self.entries.items) |entry| {
            if (entry.id == 3 and entry.kind == 1) {
                const data = if (entry.source) |view| view.bytes else input.bytes[0..0];
                for (entry.indexes) |index| {
                    _ = try self.resource_label(index.label);
                    if (index.length != 0) _ = try region(data, index.offset, index.length);
                }
            }
            if (entry.id == 8 or entry.id == 9) {
                const attributes = config.attributes(self.ps3(), entry.id, entry.kind) orelse return error.InvalidRcoType;
                var pos: usize = 0;
                for (attributes) |attribute| {
                    if (attribute.is_ref()) {
                        _ = try self.reference(entry.extra, pos);
                        pos += 8;
                    } else pos += 4;
                }
            }
        }
        return self;
    }

    fn parse_entries(self: *Model, start: usize) !void {
        const Frame = struct { entry: usize, remaining: u32 };
        var stack: std.ArrayList(Frame) = .empty;
        var position = start;
        while (true) {
            const raw = (try self.tree_region(position, 40)).bytes;
            const type_id = try self.u16_at(raw, 0);
            const id: u8 = @truncate(type_id >> 8);
            const kind: u8 = @truncate(type_id);
            if (id < 1 or id > 9 or try self.u16_at(raw, 2) != 0 or try self.u32_at(raw, 32) != 0 or try self.u32_at(raw, 36) != 0) return error.InvalidRcoEntry;
            const head_size = try self.u32_at(raw, 8);
            if (head_size != 0 and head_size != 40) return error.InvalidRcoEntry;
            var entry: Entry = .{ .offset = position, .id = id, .kind = kind, .label = try self.u32_at(raw, 4), .parent = if (stack.items.len != 0) stack.items[stack.items.len - 1].entry else null, .depth = stack.items.len + 1, .children = try self.u32_at(raw, 16), .next_offset = try self.u32_at(raw, 20) };
            if (entry.children > 65536) return error.InvalidRcoLimit;
            if (entry.label != nil) _ = try self.label(entry.label);
            const entry_size = try self.u32_at(raw, 12);
            position += 40;
            var extra_size: usize = 0;
            switch (id) {
                1 => if (kind != 1) return error.InvalidRcoType,
                2 => {
                    if (kind != 1) return error.InvalidRcoType;
                    const data = (try self.tree_region(position, 8)).bytes;
                    const offset = try self.u32_at(data, 0);
                    const length = try self.u32_at(data, 4);
                    entry.source = try self.tree_region(try std.math.add(usize, position + 8, offset), length);
                    entry.unpacked = length;
                    extra_size = std.mem.alignForward(usize, 8 + @as(usize, length), 4);
                },
                3 => if (kind == 1) {
                    const data = (try self.tree_region(position, 8)).bytes;
                    entry.language = try self.u16_at(data, 0);
                    entry.format = try self.u16_at(data, 2);
                    const count = try self.u32_at(data, 4);
                    if (entry.format > 2 or count > 65536) return error.InvalidRcoText;
                    extra_size = 8 + @as(usize, count) * 12;
                    const indexes = (try self.tree_region(position + 8, @as(usize, count) * 12)).bytes;
                    entry.indexes = try self.allocator.alloc(Index, count);
                    for (entry.indexes, 0..) |*index, i| index.* = .{ .label = try self.u32_at(indexes, i * 12), .length = try self.u32_at(indexes, i * 12 + 4), .offset = try self.u32_at(indexes, i * 12 + 8) };
                } else if (kind != 0) return error.InvalidRcoType,
                4, 5 => if (kind == 1) {
                    const data = (try self.tree_region(position, 12)).bytes;
                    entry.format = try self.u16_at(data, 0);
                    const compression = try self.u16_at(data, 2);
                    entry.compression = @truncate(compression);
                    entry.unknown_byte = @truncate(compression >> 8);
                    if (entry.compression > 2) return error.InvalidRcoCompression;
                    const full_size: usize = if (self.ps3()) 20 else 16;
                    extra_size = full_size;
                    if (entry.compression == 0 and (entry.next_offset == 0 or entry.next_offset < 40 + full_size)) extra_size -= 4;
                    const encoded = try self.u32_at(data, 4);
                    const offset = try self.u32_at(data, 8);
                    if (self.ps3() and try self.u32_at((try self.tree_region(position, 16)).bytes, 12) != 1) return error.InvalidRcoImage;
                    entry.unpacked = if (extra_size == full_size) try self.u32_at((try self.tree_region(position, full_size)).bytes, full_size - 4) else encoded;
                    // Uncompressed PS3 entries always use the packed length.
                    if (self.ps3() and entry.compression == 0) entry.unpacked = encoded;
                    const source_offset = try std.math.add(usize, self.header[if (id == 4) @as(usize, 32) else 36], offset);
                    entry.source = try subview(self.input, source_offset, encoded);
                } else if (kind != 0) return error.InvalidRcoType,
                6 => if (kind == 1) {
                    const data = (try self.tree_region(position, 12)).bytes;
                    entry.format = try self.u16_at(data, 0);
                    const count = try self.u16_at(data, 2);
                    const length = try self.u32_at(data, 4);
                    const offset = try self.u32_at(data, 8);
                    entry.unpacked = length;
                    entry.source = try subview(self.input, try std.math.add(usize, self.header[34], offset), length);
                    extra_size = 12 + @as(usize, @max(count, 2)) * 8;
                    const channels = (try self.tree_region(position + 12, extra_size - 12)).bytes;
                    entry.channels = try self.allocator.alloc(Channel, count);
                    for (0..@max(count, 2)) |i| {
                        const size = try self.u32_at(channels, i * 8);
                        const address = try self.u32_at(channels, i * 8 + 4);
                        if (i >= count) {
                            if (size != 0 or address != nil) return error.InvalidRcoSound;
                        } else {
                            if (address < offset) return error.InvalidRcoSound;
                            entry.channels[i] = .{ .length = size, .offset = address - offset };
                            _ = try region(entry.source.?.bytes, address - offset, size);
                        }
                    }
                } else if (kind != 0) return error.InvalidRcoType,
                7 => if (kind == 1) {
                    extra_size = 12;
                } else if (kind != 0) return error.InvalidRcoType,
                8, 9 => {
                    const attributes = config.attributes(self.ps3(), id, kind) orelse return error.InvalidRcoType;
                    if ((id == 8 and kind != 0) or (id == 9 and kind > 1)) {
                        extra_size = config.words(attributes) * 4;
                        if (extra_size == 0) return error.InvalidRcoType;
                        const declared = if (id == 8) entry_size else entry.next_offset;
                        if (declared != 0 and declared != extra_size + 40) return error.InvalidRcoEntrySize;
                    }
                },
                else => unreachable,
            }
            entry.extra = (try self.tree_region(position, extra_size)).bytes;
            position = try std.math.add(usize, position, extra_size);
            const index = self.entries.items.len;
            const slot = try self.offsets.getOrPut(self.allocator, entry.offset);
            if (slot.found_existing) return error.InvalidRcoGraph;
            slot.value_ptr.* = index;
            try self.entries.append(self.allocator, entry);
            if (entry.children != 0) {
                try stack.append(self.allocator, .{ .entry = index, .remaining = entry.children });
                continue;
            }
            try self.finish_entry(index, position);
            while (stack.items.len != 0) {
                const frame = &stack.items[stack.items.len - 1];
                frame.remaining -= 1;
                if (frame.remaining != 0) break;
                const parent = frame.entry;
                _ = stack.pop();
                try self.finish_entry(parent, position);
            }
            if (stack.items.len == 0) break;
        }
    }
    fn finish_entry(self: *Model, index: usize, position: usize) !void {
        const entry = &self.entries.items[index];
        entry.end = self.entries.items.len;
        if (entry.next_offset != 0 and entry.next_offset != position - entry.offset) return error.InvalidRcoEntrySize;
    }
    pub const Reference = struct { prefix: []const u8, value: []const u8 };
    pub fn reference(self: *const Model, data: []const u8, position: usize) !Reference {
        // PS3 stores the reference discriminator as two endian-swapped shorts,
        // unlike its pointer and ordinary integer fields.
        const type_bytes = try region(data, position, 4);
        const kind = if (self.ps3()) @as(u32, std.mem.readInt(u16, type_bytes[0..2], .big)) | (@as(u32, std.mem.readInt(u16, type_bytes[2..4], .big)) << 16) else try self.u32_at(data, position);
        const pointer = try self.u32_at(data, position + 4);
        switch (kind) {
            0x400 => return .{ .prefix = "event:", .value = try string(self.events, pointer) },
            0x401 => {
                var value: []const u8 = "";
                if (self.tables[3]) |table| if (self.entries.items[table].children != 0) {
                    const indexes = self.entries.items[table + 1].indexes;
                    if (pointer >= indexes.len) return error.InvalidRcoReference;
                    value = try self.label(indexes[pointer].label);
                };
                return .{ .prefix = "text:", .value = value };
            },
            0xffff => {
                if (pointer != nil) return error.InvalidRcoReference;
                return .{ .prefix = "nothing", .value = "" };
            },
            0x402, 0x403, 0x405, 0x407, 0x408, 0x409 => {
                const index = self.offsets.get(pointer) orelse return error.InvalidRcoReference;
                const target = self.entries.items[index];
                return .{ .prefix = switch (kind) {
                    0x402 => "image:",
                    0x403 => "model:",
                    0x405 => "font:",
                    0x407 => "object2:",
                    0x408 => "anim:",
                    else => "object:",
                }, .value = if (target.label == nil) "" else try self.label(target.label) };
            },
            else => return error.InvalidRcoReference,
        }
    }
    pub fn field_word(self: *const Model, data: []const u8, pos: usize, kind: config.Kind) !u32 {
        if (kind == .unk) return std.mem.readInt(u32, (try region(data, pos, 4))[0..4], .little);
        return self.u32_at(data, pos);
    }
};
