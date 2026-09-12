const std = @import("std");

/// Observed UMD_DATA.BIN fields, borrowed from the original bytes. Field lengths
/// vary between releases, so delimiters, not fixed offsets, define the layout.
pub const Record = struct {
    identifier: []const u8,
    uid: []const u8,
    type_code: []const u8,
    media_code: []const u8,
    extra: []const u8,

    pub fn mediaDescription(self: Record) []const u8 {
        if (std.mem.eql(u8, self.media_code, "G")) return "game/update";
        if (std.mem.eql(u8, self.media_code, "V")) return "video";
        return "unknown";
    }
};

pub fn parse(bytes: []const u8) !Record {
    var fields = std.mem.splitScalar(u8, bytes, '|');
    var values: [4][]const u8 = undefined;
    for (&values) |*value| {
        value.* = std.mem.trimEnd(u8, fields.next() orelse return error.MalformedUmdData, "\x00");
        if (value.len == 0) return error.MalformedUmdData;
    }
    return .{
        .identifier = values[0],
        .uid = values[1],
        .type_code = values[2],
        .media_code = values[3],
        .extra = fields.rest(),
    };
}

test "game and video records have variable field lengths" {
    const game = try parse("UMDT-99872|8D53CBDF6A4FC495|0001|G" ++ "\x00" ** 13 ++ "|");
    try std.testing.expectEqualStrings("UMDT-99872", game.identifier);
    try std.testing.expectEqualStrings("game/update", game.mediaDescription());
    const video = try parse("UMD Authoring Demo  |AB9B89|0002|V" ++ "\x00" ** 13 ++ "|");
    try std.testing.expectEqualStrings("UMD Authoring Demo  ", video.identifier);
    try std.testing.expectEqualStrings("AB9B89", video.uid);
    try std.testing.expectEqualStrings("video", video.mediaDescription());
}

test "unknown fields are retained and missing fields rejected" {
    const record = try parse("label|id|9999|X|extra|");
    try std.testing.expectEqualStrings("unknown", record.mediaDescription());
    try std.testing.expectEqualStrings("extra|", record.extra);
    try std.testing.expectError(error.MalformedUmdData, parse("not a record"));
    try std.testing.expectError(error.MalformedUmdData, parse("label|id|0001||"));
}
