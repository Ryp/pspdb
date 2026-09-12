const std = @import("std");

/// These readers borrow source slices; callers own names, hashes and storage.
pub fn walkSce(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    if (bytes.len < 8 or !std.mem.startsWith(u8, bytes, "~SCE")) return error.InvalidSce;
    const offset = std.mem.readInt(u32, bytes[4..8], .little);
    if (offset < 8 or offset >= bytes.len) return error.InvalidSce;
    try emit(context, "payload.psp", bytes[offset..]);
}

pub fn walkPbp(bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    if (bytes.len < 40 or !std.mem.startsWith(u8, bytes, "\x00PBP")) return error.InvalidPbp;
    const names = [_][]const u8{ "PARAM.SFO", "ICON0.PNG", "ICON1.PMF", "PIC0.PNG", "PIC1.PNG", "SND0.AT3", "DATA.PSP", "DATA.PSAR" };
    var offsets: [9]usize = undefined;
    for (offsets[0..8], 0..) |*offset, i| offset.* = std.mem.readInt(u32, bytes[8 + i * 4 ..][0..4], .little);
    offsets[8] = bytes.len;
    // Validate every range before emitting anything.
    if (offsets[0] < 40) return error.InvalidPbp;
    for (offsets[0..8], offsets[1..]) |start, end| if (start > end or end > bytes.len) return error.InvalidPbp;
    for (names, offsets[0..8], offsets[1..]) |name, start, end| {
        if (start != end) try emit(context, name, bytes[start..end]);
    }
}

test "PBP rejects reversed offsets before emitting" {
    var bytes: [40]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PBP");
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
