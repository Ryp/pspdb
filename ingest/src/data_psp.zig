const std = @import("std");
const crypto = @import("zig_psp_npumdimg_crypto");

/// NPUMDIMG's DATA.PSP metadata, not the executable DATA.PSP used by other PBPs.
/// All slices borrow the input. PARAM.SFO is needed separately for verification.
pub const Header = struct {
    signature: *const [40]u8,
    content_id: []const u8,
    content_id_field: *const [48]u8,
    flags: u32,
    opnssmp: ?[]const u8,
    startdat: ?[]const u8,

    pub fn parse(bytes: []const u8) !Header {
        if (bytes.len < 0x594) return error.InvalidDataPsp;
        const id = bytes[0x560..0x590];
        const end = std.mem.indexOfScalar(u8, id, 0) orelse return error.InvalidDataPsp;
        if (end == 0) return error.InvalidDataPsp;
        for (id[0..end]) |ch| if (ch < 0x20 or ch > 0x7e) return error.InvalidDataPsp;
        for (id[end..]) |ch| if (ch != 0) return error.InvalidDataPsp;
        const offset = std.mem.readInt(u32, bytes[0x30..0x34], .little);
        const size = std.mem.readInt(u32, bytes[0x34..0x38], .little);
        if ((offset == 0) != (size == 0)) return error.InvalidDataPsp;
        if (size != 0 and (offset < 0x594 or offset > bytes.len or size > bytes.len - offset)) return error.InvalidDataPsp;
        const end_start: usize = if (size != 0) offset else bytes.len;
        const startdat = if (end_start >= 0x5a8 and std.mem.eql(u8, bytes[0x5a0..0x5a8], "STARTDAT")) bytes[0x5a0..end_start] else null;
        return .{ .signature = bytes[0..40], .content_id = id[0..end], .content_id_field = id, .flags = std.mem.readInt(u32, bytes[0x590..0x594], .big), .opnssmp = if (size != 0) bytes[offset..][0..size] else null, .startdat = startdat };
    }

    pub fn signedHash(self: Header, sfo: []const u8) [20]u8 {
        return crypto.signedHash(sfo, self.content_id_field);
    }

    pub fn verify(self: Header, sfo: []const u8) !bool {
        return crypto.verify(sfo, self.content_id_field, self.signature);
    }
};

test "DATA.PSP bounds, endian, borrowed fields and optional sections" {
    var bytes: [0x5c0]u8 = @splat(0);
    @memcpy(bytes[0x560..][0..7], "TEST-ID");
    std.mem.writeInt(u32, bytes[0x590..0x594], 2, .big);
    var parsed = try Header.parse(&bytes);
    try std.testing.expectEqual(@as(u32, 2), parsed.flags);
    try std.testing.expectEqual(bytes[0x560..].ptr, parsed.content_id.ptr);
    try std.testing.expectEqual(null, parsed.opnssmp);
    for (0..0x594) |len| try std.testing.expectError(error.InvalidDataPsp, Header.parse(bytes[0..len]));
    std.mem.writeInt(u32, bytes[0x30..0x34], 0x5b0, .little);
    try std.testing.expectError(error.InvalidDataPsp, Header.parse(&bytes));
    std.mem.writeInt(u32, bytes[0x34..0x38], 16, .little);
    @memcpy(bytes[0x5a0..0x5a8], "STARTDAT");
    parsed = try Header.parse(&bytes);
    try std.testing.expectEqual(@as(usize, 16), parsed.opnssmp.?.len);
    try std.testing.expectEqual(@as(usize, 16), parsed.startdat.?.len);
    std.mem.writeInt(u32, bytes[0x34..0x38], 17, .little);
    try std.testing.expectError(error.InvalidDataPsp, Header.parse(&bytes));
}
