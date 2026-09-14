// Native memory-only RCO dump. Parser and serializers are focused ports of
// RCOMage 54ca649a9a6aba150a1fbe423f4c3aec611ee913 (ZiNgA BuRgA, LGPL-2.1).
// Default dump only: raw images/models/VSMX, split sound channels, language XML.
const std = @import("std");
const memory = @import("bytes.zig");
const model = @import("rco/model.zig");
const config = @import("rco/config.zig");
const xml = @import("rco/xml.zig");

// The external dumper uses 260-byte C path buffers. Ordinary labels alone are
// truncated to 216 bytes; VSMX labels and language names are not truncated.
fn output_path(allocator: std.mem.Allocator, raw: []const u8) ![]const u8 {
    if (raw.len >= 260 or raw.len == 0 or raw[0] == '/' or std.mem.indexOfScalar(u8, raw, 0) != null) return error.InvalidRcoPath;
    var components: std.ArrayList([]const u8) = .empty;
    var parts = std.mem.splitScalar(u8, raw, '/');
    while (parts.next()) |part| {
        // Every traversed intermediate must already be an existing directory;
        // e.g. resources/missing/../name still fails in the original fopen.
        if (components.items.len != 0 and !(components.items.len == 1 and std.mem.eql(u8, components.items[0], "resources"))) return error.InvalidRcoPath;
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (components.items.len == 0) return error.InvalidRcoPath;
            _ = components.pop();
        } else {
            try components.append(allocator, part);
        }
    }
    if (components.items.len == 0) return error.InvalidRcoPath;
    return std.mem.join(allocator, "/", components.items);
}
const Outputs = struct {
    allocator: std.mem.Allocator,
    names: std.StringHashMapUnmanaged(void) = .empty,
    xml_files: std.StringArrayHashMapUnmanaged(memory.View) = .empty,
    fn deinit(self: *Outputs) void {
        for (self.xml_files.values()) |view| view.release();
    }
    fn reserve(self: *Outputs, name: []const u8, overwrite: bool) !void {
        if (std.mem.eql(u8, name, "resources")) return error.InvalidRcoPath;
        const slot = try self.names.getOrPut(self.allocator, name);
        if (slot.found_existing and !overwrite) return error.DuplicateRcoResource;
    }
    fn remember_xml(self: *Outputs, name: []const u8, view: memory.View) !void {
        const slot = try self.xml_files.getOrPut(self.allocator, name);
        if (slot.found_existing) slot.value_ptr.release();
        slot.value_ptr.* = view.retain();
    }
};
fn raw_resource(m: *model.Model, entry: model.Entry) !memory.View {
    const source = entry.source orelse return error.InvalidRcoResource;
    if (entry.compression == 0) {
        if (source.bytes.len == 0 or source.bytes.len != entry.unpacked) return error.InvalidRcoResource;
        return source.retain();
    }
    const decoded = try m.decode(source.bytes, entry.unpacked, entry.compression);
    if (decoded.bytes.len == 0) {
        decoded.release();
        return error.InvalidRcoResource;
    }
    return decoded;
}
fn resource_base(m: *const model.Model, entry: model.Entry) ![]const u8 {
    const label = try m.resource_label(entry.label);
    return label[0..@min(label.len, 216)];
}
fn resource_extension(entry: model.Entry) []const u8 {
    if (entry.id == 6) return if (entry.format == 1) "vag" else "dat";
    const items = config.misc.named(if (entry.id == 4) "imageformats" else "modelformats");
    // The pinned CLI's <= comparison selects its empty map terminator too.
    return if (entry.format < items.len) items[entry.format].name else if (entry.format == items.len) "" else "dat";
}

/// Input remains immutable and borrowed throughout this synchronous call.
/// Every emitted file is a retained-capable view; the consumer may retain it.
/// A null view is the resources directory, distinct from an empty file.
/// Callback errors abort immediately, and every local owner is released.
pub fn walk(allocator: std.mem.Allocator, input: memory.View, context: anytype, comptime emit: anytype) !void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    var m = try model.Model.init(temporary, allocator, input);
    defer m.deinit();
    var outputs: Outputs = .{ .allocator = temporary };
    defer outputs.deinit();
    try emit(context, "resources", null);
    for ([_]usize{ 4, 6, 5 }) |id| {
        const table = m.tables[id] orelse continue;
        var child = table + 1;
        while (child < m.entries.items[table].end) : (child = m.entries.items[child].end) {
            const entry = &m.entries.items[child];
            if (entry.id != id or entry.kind != 1) return error.InvalidRcoResource;
            const base = try resource_base(&m, entry.*);
            const extension = resource_extension(entry.*);
            if (id == 6) {
                for (entry.channels, 0..) |channel, index| {
                    const raw_name = try std.fmt.allocPrint(temporary, "resources/{s}.ch{d}.{s}", .{ base, index, extension });
                    const name = try output_path(temporary, raw_name);
                    try outputs.reserve(name, false);
                    const view = try model.subview(entry.source orelse return error.InvalidRcoResource, channel.offset, channel.length);
                    if (view.bytes.len == 0) return error.InvalidRcoResource;
                    try emit(context, name, view);
                }
                if (entry.channels.len != 0) entry.output_name = try std.fmt.allocPrint(temporary, "resources/{s}.ch*.vag", .{base});
            } else {
                const raw_name = try std.fmt.allocPrint(temporary, "resources/{s}.{s}", .{ base, extension });
                const name = try output_path(temporary, raw_name);
                try outputs.reserve(name, false);
                const view = try raw_resource(&m, entry.*);
                defer view.release();
                try emit(context, name, view);
                entry.output_name = raw_name;
            }
        }
    }
    if (m.tables[3]) |table| {
        var child = table + 1;
        while (child < m.entries.items[table].end) : (child = m.entries.items[child].end) {
            const entry = &m.entries.items[child];
            if (entry.id != 3 or entry.kind != 1) return error.InvalidRcoText;
            const language = try xml.mapped(temporary, config.misc.named("languages"), entry.language);
            const raw_name = try std.fmt.allocPrint(temporary, "resources/{s}.xml", .{language});
            const name = try output_path(temporary, raw_name);
            // Unlike dump_resource(), dump_text_resources() opens with "wb"
            // without an existence check: duplicate languages are last-write.
            try outputs.reserve(name, true);
            const bytes = xml.language(&m, allocator, entry.*) catch |err| return switch (err) {
                error.WriteFailed => error.OutOfMemory,
                else => err,
            };
            const view = try memory.Owner.take_allocated(allocator, bytes);
            defer view.release();
            try outputs.remember_xml(name, view);
            entry.output_name = raw_name;
        }
    }
    for (outputs.xml_files.keys(), outputs.xml_files.values()) |name, view| {
        try xml.validate(view.bytes);
        try emit(context, name, view);
    }
    if (m.tables[2] != null) {
        for (m.entries.items) |*entry| {
            if (entry.parent != 0 or entry.id != 2) continue;
            const label = if (entry.label == 0) "vsmx" else try m.label(entry.label);
            const raw_name = try std.fmt.allocPrint(temporary, "resources/{s}.vsmx", .{label});
            const name = try output_path(temporary, raw_name);
            try outputs.reserve(name, false);
            const view = try raw_resource(&m, entry.*);
            defer view.release();
            try emit(context, name, view);
            entry.output_name = raw_name;
        }
    }
    const bytes = xml.structure(&m, allocator) catch |err| return switch (err) {
        error.WriteFailed => error.OutOfMemory,
        else => err,
    };
    const structure = try memory.Owner.take_allocated(allocator, bytes);
    defer structure.release();
    // Validate only final file values, matching the helper's post-output check.
    try xml.validate(structure.bytes);
    try emit(context, "structure.xml", structure);
}

test "RCO serialization preserves allocator errors and retained output lifetime" {
    const Check = struct {
        fn emit(last: *?memory.View, _: []const u8, value: ?memory.View) !void {
            if (value) |view| {
                if (last.*) |previous| previous.release();
                last.* = view.retain();
            }
        }
        fn run(allocator: std.mem.Allocator) !void {
            const source = try allocator.alloc(u8, 204);
            @memset(source, 0);
            @memcpy(source[0..4], "\x00PRF");
            std.mem.writeInt(u32, source[4..8], 0x100, .little);
            for ([_]usize{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 39, 40 }) |word| {
                std.mem.writeInt(u32, source[word * 4 ..][0..4], 0xffffffff, .little);
            }
            std.mem.writeInt(u32, source[16..20], 164, .little);
            std.mem.writeInt(u16, source[164..166], 0x101, .little);
            std.mem.writeInt(u32, source[168..172], 0xffffffff, .little);
            std.mem.writeInt(u32, source[172..176], 40, .little);
            std.mem.writeInt(u32, source[176..180], 40, .little);
            const input = try memory.Owner.take_allocated(allocator, source);
            defer input.release();
            var last: ?memory.View = null;
            defer if (last) |view| view.release();
            try walk(allocator, input, &last, emit);
            try xml.validate((last orelse return error.MissingOutput).bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
}
