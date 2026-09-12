const std = @import("std");

/// These readers borrow source slices; callers own names, hashes and storage.
pub fn walkSce(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    if (bytes.len < 8 or !std.mem.startsWith(u8, bytes, "~SCE")) return error.InvalidSce;
    const offset = std.mem.readInt(u32, bytes[4..8], .little);
    if (offset < 8 or offset >= bytes.len) return error.InvalidSce;
    try emit(context, "payload.psp", bytes[offset..]);
}

/// Expose the raw card bytes; this does not verify the VMP signature.
pub fn walkVmp(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    if (bytes.len != 0x20080 or !std.mem.startsWith(u8, bytes, "\x00PMV") or
        std.mem.readInt(u32, bytes[4..8], .little) != 0x80) return error.InvalidVmp;
    try emit(context, "memorycard.mcr", bytes[0x80..]);
}

test "VMP preserves the complete card and rejects inconsistent wrapper bounds" {
    var bytes: [0x20081]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PMV");
    std.mem.writeInt(u32, bytes[4..8], 0x80, .little);
    bytes[0x80] = 0xa7;
    bytes[0x2007f] = 0x5c;
    const Consumer = struct {
        fn emit(expected: []const u8, _: []const u8, payload: []const u8) !void {
            try std.testing.expectEqualSlices(u8, expected, payload);
        }
    };
    try walkVmp(bytes[0..0x20080], bytes[0x80..0x20080], Consumer.emit);
    try std.testing.expectError(error.InvalidVmp, walkVmp(bytes[0..0x2007f], &.{}, Consumer.emit));
    try std.testing.expectError(error.InvalidVmp, walkVmp(&bytes, &.{}, Consumer.emit));
    std.mem.writeInt(u32, bytes[4..8], 0x7f, .little);
    try std.testing.expectError(error.InvalidVmp, walkVmp(bytes[0..0x20080], &.{}, Consumer.emit));
}

pub fn parsePbp(bytes: []const u8) !@import("zig_psp_pbp").Pbp {
    return @import("zig_psp_pbp").Pbp.parse(bytes) catch return error.InvalidPbp;
}

pub fn walkPbp(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    try (try parsePbp(bytes)).walk(context, emit);
}

test "PBP rejects reversed offsets before emitting" {
    var bytes: [40]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PBP");
    std.mem.writeInt(u32, bytes[4..8], 0x10000, .little);
    for (0..8) |i| std.mem.writeInt(u32, bytes[8 + i * 4 ..][0..4], 40, .little);
    std.mem.writeInt(u32, bytes[12..16], 39, .little);
    const Callback = struct {
        fn emit(_: void, _: []const u8, _: ?[]const u8) !void {
            return error.UnexpectedEmit;
        }
    };
    try std.testing.expectError(error.InvalidPbp, walkPbp(&bytes, {}, Callback.emit));
    try std.testing.expectError(error.InvalidSce, walkSce("~SCE\xFF\xFF\xFF\xFF", {}, Callback.emit));
}

/// Match only bounded PSP wrappers inside little-endian MIPS ELF files.
/// Like pspdecrypt's FindReboot, this locates embedded bytes, not ELF sections.
pub fn embeddedPsp(bytes: []const u8, start: usize) ?struct { offset: usize, size: usize } {
    if (bytes.len < 52 or !std.mem.startsWith(u8, bytes, "\x7fELF") or
        bytes[4] != 1 or bytes[5] != 1 or std.mem.readInt(u16, bytes[18..20], .little) != 8) return null;
    var cursor = start;
    while (std.mem.indexOfPos(u8, bytes, cursor, "~PSP")) |offset| {
        cursor = offset + 4;
        if (bytes.len - offset < 0x150) continue;
        const header = bytes[offset..];
        const size = std.mem.readInt(u32, header[0x2c..0x30], .little);
        const compressed = std.mem.readInt(u32, header[0xb0..0xb4], .little);
        if (size < 0x150 or size > header.len or compressed == 0 or compressed > size - 0x150) continue;
        return .{ .offset = offset, .size = size };
    }
    return null;
}

pub fn walkElf(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    var cursor: usize = 0;
    while (embeddedPsp(bytes, cursor)) |item| {
        var name: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, "embedded-{x}.psp", .{item.offset});
        try emit(context, path, bytes[item.offset..][0..item.size]);
        cursor = item.offset + item.size;
    }
}

test "embedded PSP scan skips invalid candidates and bounds declared size" {
    var bytes: [1024]u8 = @splat(0);
    @memcpy(bytes[0..6], "\x7fELF\x01\x01");
    std.mem.writeInt(u16, bytes[18..20], 8, .little);
    @memcpy(bytes[64..68], "~PSP"); // Invalid header before the real wrapper.
    @memcpy(bytes[128..132], "~PSP");
    std.mem.writeInt(u32, bytes[128 + 0x2c ..][0..4], 400, .little);
    std.mem.writeInt(u32, bytes[128 + 0xb0 ..][0..4], 64, .little);
    const found = embeddedPsp(&bytes, 0).?;
    try std.testing.expectEqual(@as(usize, 128), found.offset);
    try std.testing.expectEqual(@as(usize, 400), found.size);
    try std.testing.expectEqual(null, embeddedPsp(&bytes, 528));
    std.mem.writeInt(u32, bytes[128 + 0x2c ..][0..4], 1024, .little);
    try std.testing.expectEqual(null, embeddedPsp(&bytes, 0));
}

test "Zig-PSP PBP reader borrows slices and preserves the entire final section" {
    var bytes: [104]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PBP");
    std.mem.writeInt(u32, bytes[4..8], 0x10000, .little);
    for (0..8) |i| std.mem.writeInt(u32, bytes[8 + i * 4 ..][0..4], 40, .little);
    @memset(bytes[40..], 0x5a);
    const pbp = try parsePbp(&bytes);
    const tail = pbp.get("DATA.BIN").?;
    try std.testing.expectEqual(@as(usize, 64), tail.len);
    try std.testing.expectEqual(bytes[40..].ptr, tail.ptr);
    try std.testing.expectEqualSlices(u8, bytes[40..], tail);
    try std.testing.expectEqual(@as(usize, 0), pbp.get("DATA.PSP").?.len);
    // The dependency's file API uses the same reader and keeps the full tail too.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const input_path = try std.fmt.allocPrint(allocator, "{s}/source.pbp", .{directory});
    defer allocator.free(input_path);
    const output_path = try std.fmt.allocPrint(allocator, "{s}/output", .{directory});
    defer allocator.free(output_path);
    const file = try tmp.dir.createFile(io, "source.pbp", .{});
    try file.writeStreamingAll(io, &bytes);
    file.close(io);
    try @import("zig_psp_pbp").unpack_pbp(allocator, io, input_path, output_path);
    const unpacked = try tmp.dir.readFileAlloc(io, "output/DATA.BIN", allocator, .unlimited);
    defer allocator.free(unpacked);
    try std.testing.expectEqualSlices(u8, tail, unpacked);
    std.mem.writeInt(u32, bytes[36..40], 105, .little);
    try std.testing.expectError(error.InvalidPbp, parsePbp(&bytes));
    std.mem.writeInt(u32, bytes[36..40], 40, .little);
    bytes[0] = 1;
    try std.testing.expectError(error.InvalidPbp, parsePbp(&bytes));
    bytes[0] = 0;
    std.mem.writeInt(u32, bytes[4..8], 0x10001, .little);
    _ = try parsePbp(&bytes); // Observed in the retail echochrome demo.
    std.mem.writeInt(u32, bytes[4..8], 0x20001, .little);
    try std.testing.expectError(error.InvalidPbp, parsePbp(&bytes));
    try std.testing.expectError(error.InvalidPbp, parsePbp(bytes[0..39]));
}
