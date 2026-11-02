//! Publication policy for PSP/PS1 DOCUMENT manuals: a port of the former Python
//! helper's `__main__.extract`, minus Pillow (replaced by `checkPng`).
const std = @import("std");
const document = @import("zig_psp_decrypt").document;

pub const max_source = 128 * 1024 * 1024;
const max_pixels: u64 = 16 * 1024 * 1024;
const max_ordinal = 999;

const png_signature = [8]u8{ 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };

/// Structural PNG check: signature, per-chunk CRC, IHDR first, one IEND at the very end.
/// No inflate and no pixel decoding.
pub fn checkPng(bytes: []const u8) error{InvalidPng}!void {
    if (bytes.len < png_signature.len or !std.mem.eql(u8, bytes[0..8], &png_signature)) return error.InvalidPng;
    var pos: usize = 8;
    var first = true;
    while (true) {
        if (bytes.len - pos < 12) return error.InvalidPng;
        const length: usize = std.mem.readInt(u32, bytes[pos..][0..4], .big);
        if (length > bytes.len - pos - 12) return error.InvalidPng;
        const kind = bytes[pos + 4 ..][0..4];
        const data = bytes[pos + 8 ..][0..length];
        const stored = std.mem.readInt(u32, bytes[pos + 8 + length ..][0..4], .big);
        if (std.hash.Crc32.hash(bytes[pos + 4 .. pos + 8 + length]) != stored) return error.InvalidPng;
        if (first) {
            if (!std.mem.eql(u8, kind, "IHDR") or length != 13) return error.InvalidPng;
            const width: u64 = std.mem.readInt(u32, data[0..4], .big);
            const height: u64 = std.mem.readInt(u32, data[4..8], .big);
            if (width == 0 or height == 0 or width * height > max_pixels) return error.InvalidPng;
            first = false;
        } else if (std.mem.eql(u8, kind, "IHDR")) {
            return error.InvalidPng;
        }
        pos += 12 + length;
        if (std.mem.eql(u8, kind, "IEND")) {
            if (pos != bytes.len) return error.InvalidPng;
            return;
        }
    }
}

const FrameKey = struct { offset: u32, size: u32 };

const Collector = struct {
    arena: std.mem.Allocator,
    source_len: usize,
    psp: std.ArrayList([]const u8) = .empty,
    /// Distinct PS3 frames by ordinal (1..999).
    ps3_only: [max_ordinal + 1]?[]const u8 = @splat(null),
    frames: std.AutoHashMapUnmanaged(FrameKey, []const u8) = .empty,

    fn collect(self: *Collector, platform: document.Platform, ordinal: u16, frame: document.Frame, png: []const u8) anyerror!void {
        switch (platform) {
            .psp => if (ordinal != self.psp.items.len + 1 or ordinal > max_ordinal) return error.InvalidDocument,
            .ps3 => if (ordinal == 0 or ordinal > max_ordinal or self.ps3_only[ordinal] != null) return error.InvalidDocument,
        }
        if (frame.size == 0 or @as(u64, frame.offset) + frame.size > self.source_len) return error.InvalidDocument;
        try checkPng(png);
        const key = FrameKey{ .offset = frame.offset, .size = frame.size };
        if (self.frames.get(key)) |previous| {
            if (!std.mem.eql(u8, previous, png)) return error.InvalidDocument;
        }
        const copy = try self.arena.dupe(u8, png);
        try self.frames.put(self.arena, key, copy);
        switch (platform) {
            .psp => try self.psp.append(self.arena, copy),
            .ps3 => self.ps3_only[ordinal] = copy,
        }
    }
};

/// Decodes a manual and publishes it via `emit(context, path, null)` for directories and
/// `emit(context, path, bytes)` for files. Nothing is emitted unless the whole manual succeeds.
pub fn extract(
    allocator: std.mem.Allocator,
    source: []const u8,
    docinfo: ?[]const u8,
    context: anytype,
    comptime emit: fn (@TypeOf(context), []const u8, ?[]const u8) anyerror!void,
) anyerror!void {
    if (source.len > max_source) return error.InvalidDocument;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    var collector = Collector{ .arena = arena_state.allocator(), .source_len = source.len };

    const header = try document.decode(allocator, source, docinfo, &collector, Collector.collect);
    defer header.deinit(allocator);

    const count = header.pages_total;
    const ps3_count = header.pages_total_ps3;
    if (count > max_ordinal or header.pages.len != count or collector.psp.items.len != count or ps3_count > count)
        return error.InvalidDocument;

    var ps3: [max_ordinal + 1]?[]const u8 = collector.ps3_only;
    if (ps3_count == 0) {
        for (ps3) |slot| if (slot != null) return error.InvalidDocument;
    }
    for (header.pages[0..ps3_count], 1..) |info, ordinal| {
        if (ps3[ordinal] != null) continue;
        const linked = collector.frames.get(.{ .offset = info.ps3.offset, .size = info.ps3.size }) orelse
            return error.InvalidDocument;
        ps3[ordinal] = linked;
    }

    var path_buffer: [16]u8 = undefined;
    if (count > 0) try emit(context, "psp", null);
    for (collector.psp.items, 1..) |bytes, ordinal| {
        const path = try std.fmt.bufPrint(&path_buffer, "psp/{d:0>3}.png", .{ordinal});
        try emit(context, path, bytes);
    }
    if (ps3_count > 0) try emit(context, "ps3", null);
    for (ps3[1..], 1..) |slot, ordinal| {
        const bytes = slot orelse continue;
        const path = try std.fmt.bufPrint(&path_buffer, "ps3/{d:0>3}.png", .{ordinal});
        try emit(context, path, bytes);
    }
}

fn appendChunk(list: *std.ArrayList(u8), kind: *const [4]u8, data: []const u8) !void {
    const gpa = std.testing.allocator;
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, @intCast(data.len), .big);
    try list.appendSlice(gpa, &word);
    try list.appendSlice(gpa, kind);
    try list.appendSlice(gpa, data);
    var crc = std.hash.Crc32.init();
    crc.update(kind);
    crc.update(data);
    std.mem.writeInt(u32, &word, crc.final(), .big);
    try list.appendSlice(gpa, &word);
}

fn testPng(width: u32, height: u32, iend_count: usize, trailing: []const u8, corrupt_crc: bool) !std.ArrayList(u8) {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, &png_signature);
    var ihdr: [13]u8 = @splat(0);
    std.mem.writeInt(u32, ihdr[0..4], width, .big);
    std.mem.writeInt(u32, ihdr[4..8], height, .big);
    ihdr[8] = 8;
    try appendChunk(&list, "IHDR", &ihdr);
    try appendChunk(&list, "IDAT", "x");
    for (0..iend_count) |_| try appendChunk(&list, "IEND", "");
    if (corrupt_crc) list.items[list.items.len - 1] ^= 1;
    try list.appendSlice(std.testing.allocator, trailing);
    return list;
}

test "checkPng accepts a minimal structurally valid PNG" {
    var png = try testPng(2, 3, 1, "", false);
    defer png.deinit(std.testing.allocator);
    try checkPng(png.items);
}

test "checkPng rejects bad signature, CRC, trailing data and truncation" {
    var png = try testPng(2, 3, 1, "", false);
    defer png.deinit(std.testing.allocator);
    var bad_sig = try png.clone(std.testing.allocator);
    defer bad_sig.deinit(std.testing.allocator);
    bad_sig.items[1] = 'X';
    try std.testing.expectError(error.InvalidPng, checkPng(bad_sig.items));
    try std.testing.expectError(error.InvalidPng, checkPng(png.items[0 .. png.items.len - 1]));
    try std.testing.expectError(error.InvalidPng, checkPng(""));

    var bad_crc = try testPng(2, 3, 1, "", true);
    defer bad_crc.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(bad_crc.items));

    var trailing = try testPng(2, 3, 1, "\x00", false);
    defer trailing.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(trailing.items));
}

test "checkPng rejects missing and duplicated IEND" {
    var none = try testPng(2, 3, 0, "", false);
    defer none.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(none.items));
    var two = try testPng(2, 3, 2, "", false);
    defer two.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(two.items));
}

test "checkPng enforces the IHDR pixel budget" {
    var edge = try testPng(4096, 4096, 1, "", false);
    defer edge.deinit(std.testing.allocator);
    try checkPng(edge.items);
    var over = try testPng(4097, 4096, 1, "", false);
    defer over.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(over.items));
    var huge = try testPng(0xffff_ffff, 0xffff_ffff, 1, "", false);
    defer huge.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(huge.items));
    var zero = try testPng(0, 5, 1, "", false);
    defer zero.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidPng, checkPng(zero.items));
}
