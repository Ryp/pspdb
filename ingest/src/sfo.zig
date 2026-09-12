const std = @import("std");

/// Values borrow the SFO buffer. Missing metadata is allowed; malformed input
/// is rejected rather than inventing metadata or silently misreading offsets.
pub const Metadata = struct {
    disc_version: ?[]const u8 = null,
    disc_id: ?[]const u8 = null,
    title: ?[]const u8 = null,
    required_firmware: ?[]const u8 = null,
};

fn int(comptime T: type, bytes: []const u8, offset: usize) !T {
    if (offset > bytes.len or @sizeOf(T) > bytes.len - offset) return error.InvalidSfo;
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

pub fn parse(bytes: []const u8) !Metadata {
    if (bytes.len == 0) return .{};
    if (bytes.len < 20 or !std.mem.eql(u8, bytes[0..4], "\x00PSF") or try int(u32, bytes, 4) != 0x101) return error.InvalidSfo;
    const keys: usize = try int(u32, bytes, 8);
    const values: usize = try int(u32, bytes, 12);
    const count: usize = try int(u32, bytes, 16);
    if (keys < 20 or keys > values or values > bytes.len or count > (keys - 20) / 16) return error.InvalidSfo;
    var result: Metadata = .{};
    for (0..count) |i| {
        const offset = 20 + i * 16;
        const key_offset: usize = try int(u16, bytes, offset);
        if (key_offset >= values - keys) return error.InvalidSfo;
        const key_bytes = bytes[keys + key_offset .. values];
        const key_end = std.mem.indexOfScalar(u8, key_bytes, 0) orelse return error.InvalidSfo;
        const key = key_bytes[0..key_end];
        const format = try int(u16, bytes, offset + 2);
        const length: usize = try int(u32, bytes, offset + 4);
        const maximum: usize = try int(u32, bytes, offset + 8);
        const data_offset: usize = try int(u32, bytes, offset + 12);
        if (length > maximum or data_offset > bytes.len - values or maximum > bytes.len - values - data_offset) return error.InvalidSfo;
        inline for (.{ .{ "DISC_ID", "disc_id" }, .{ "DISC_VERSION", "disc_version" }, .{ "TITLE", "title" }, .{ "PSP_SYSTEM_VER", "required_firmware" } }) |field| {
            if (std.mem.eql(u8, key, field[0])) {
                if (format != 0x204 or length == 0 or @field(result, field[1]) != null) return error.InvalidSfo;
                const data = bytes[values + data_offset ..][0..length];
                if (data[data.len - 1] != 0 or !std.unicode.utf8ValidateSlice(data[0 .. data.len - 1])) return error.InvalidSfo;
                @field(result, field[1]) = data[0 .. data.len - 1];
            }
        }
    }
    return result;
}

test "missing and malformed SFO" {
    try std.testing.expectEqual(null, (try parse("")).disc_id);
    try std.testing.expectError(error.InvalidSfo, parse("not an SFO"));
}
