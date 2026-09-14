const std = @import("std");

/// Values borrow the SFO buffer. Missing metadata is allowed; malformed input
/// is rejected rather than inventing metadata or silently misreading offsets.
pub const Metadata = struct {
    disc_version: ?[]const u8 = null,
    disc_id: ?[]const u8 = null,
    title: ?[]const u8 = null,
    required_firmware: ?[]const u8 = null,
};

/// Select catalog fields from Zig-PSP's parsed SFO. Values still borrow bytes.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Metadata {
    return parseImpl(allocator, bytes, null);
}

pub fn parsePkg(allocator: std.mem.Allocator, bytes: []const u8, title_owner: *[]u8) !Metadata {
    return parseImpl(allocator, bytes, title_owner);
}

fn parseImpl(allocator: std.mem.Allocator, bytes: []const u8, title_owner: ?*[]u8) !Metadata {
    if (bytes.len == 0) return .{};
    const parsed = @import("zig_psp_sfo").readSFO(allocator, bytes) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidSfo,
    };
    defer parsed.deinit(allocator);
    var result: Metadata = .{};
    for (parsed.table) |entry| {
        const key = parsed.key(entry);
        inline for (.{ .{ "DISC_ID", "disc_id" }, .{ "DISC_VERSION", "disc_version" }, .{ "TITLE", "title" }, .{ "PSP_SYSTEM_VER", "required_firmware" } }) |field| {
            if (std.mem.eql(u8, key, field[0])) {
                const data = parsed.data(entry);
                if (entry.data_fmt != .UTF8 or data.len == 0 or @field(result, field[1]) != null) return error.InvalidSfo;
                const end = std.mem.indexOfScalar(u8, data, 0) orelse return error.InvalidSfo;
                const text = data[0..end];
                if (!std.unicode.utf8ValidateSlice(text)) {
                    // Some retail PS1 SFOs use CP1252 trademark in otherwise ASCII TITLE.
                    // Normalize catalog text only; the original SFO object is untouched.
                    if (!std.mem.eql(u8, key, "TITLE") or title_owner == null) return error.InvalidSfo;
                    var length: usize = 0;
                    for (text) |c| {
                        if (c >= 128 and c != 0x99) return error.InvalidSfo;
                        length += if (c == 0x99) @as(usize, 3) else 1;
                    }
                    const normalized = try allocator.alloc(u8, length);
                    var pos: usize = 0;
                    for (text) |c| {
                        if (c == 0x99) { @memcpy(normalized[pos..][0..3], "™"); pos += 3; }
                        else { normalized[pos] = c; pos += 1; }
                    }
                    title_owner.?.* = normalized;
                    result.title = normalized;
                } else @field(result, field[1]) = text;
            }
        }
    }
    return result;
}

test "missing and malformed SFO" {
    try std.testing.expectEqual(null, (try parse(std.testing.allocator, "")).disc_id);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, "not an SFO"));
}

fn fixture() [74]u8 {
    var bytes: [74]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PSF");
    std.mem.writeInt(u32, bytes[4..8], 0x101, .little);
    std.mem.writeInt(u32, bytes[8..12], 52, .little);
    std.mem.writeInt(u32, bytes[12..16], 65, .little);
    std.mem.writeInt(u32, bytes[16..20], 2, .little);
    std.mem.writeInt(u16, bytes[22..24], 0x204, .little);
    std.mem.writeInt(u32, bytes[24..28], 5, .little);
    std.mem.writeInt(u32, bytes[28..32], 5, .little);
    std.mem.writeInt(u16, bytes[36..38], 6, .little);
    std.mem.writeInt(u16, bytes[38..40], 0x404, .little);
    std.mem.writeInt(u32, bytes[40..44], 4, .little);
    std.mem.writeInt(u32, bytes[44..48], 4, .little);
    std.mem.writeInt(u32, bytes[48..52], 5, .little);
    @memcpy(bytes[52..65], "TITLE\x00REGION\x00");
    @memcpy(bytes[65..70], "Demo\x00");
    std.mem.writeInt(u32, bytes[70..74], 0x8000, .little);
    return bytes;
}

test "Zig-PSP SFO fields borrow the original input and ignore unrelated types" {
    var bytes = fixture();
    const result = try parse(std.testing.allocator, &bytes);
    try std.testing.expectEqualStrings("Demo", result.title.?);
    try std.testing.expectEqual(bytes[65..].ptr, result.title.?.ptr);
    try std.testing.expectEqual(null, result.disc_id);
    // Unknown formats in unrelated fields are retained by the dependency.
    std.mem.writeInt(u16, bytes[38..40], 0xffff, .little);
    try std.testing.expectEqualStrings("Demo", (try parse(std.testing.allocator, &bytes)).title.?);
}

test "SFO strings end at the first NUL within their declared data" {
    var bytes = fixture();
    @memcpy(bytes[65..70], "Hi\x00\x04\xff");
    try std.testing.expectEqualStrings("Hi", (try parse(std.testing.allocator, &bytes)).title.?);
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    try std.testing.expectEqualStrings("Hi", (try parsePkg(std.testing.allocator, &bytes, &owner)).title.?);

    // A terminator in the allocated slot but outside data_len is not valid.
    std.mem.writeInt(u32, bytes[24..28], 2, .little);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &bytes));
}

test "Zig-PSP SFO rejects malformed tables, keys, values and duplicate metadata" {
    const allocator = std.testing.allocator;
    for (0..11) |case| {
        var bytes = fixture();
        switch (case) {
            0 => bytes[0] = 1,
            1 => std.mem.writeInt(u32, bytes[16..20], 0xffffffff, .little),
            2 => std.mem.writeInt(u32, bytes[8..12], 19, .little),
            3 => std.mem.writeInt(u32, bytes[12..16], 75, .little),
            4 => std.mem.writeInt(u16, bytes[20..22], 13, .little),
            5 => std.mem.writeInt(u32, bytes[24..28], 6, .little),
            6 => std.mem.writeInt(u32, bytes[32..36], 0xffffffff, .little),
            7 => @memset(bytes[52..65], 'X'),
            8 => bytes[69] = 'X',
            9 => bytes[65] = 0xff,
            10 => {
                std.mem.writeInt(u16, bytes[36..38], 0, .little);
                std.mem.writeInt(u16, bytes[38..40], 0x204, .little);
                std.mem.writeInt(u32, bytes[40..44], 5, .little);
                std.mem.writeInt(u32, bytes[44..48], 5, .little);
                std.mem.writeInt(u32, bytes[48..52], 0, .little);
            },
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidSfo, parse(allocator, &bytes));
    }
    var bytes = fixture();
    for (0..bytes.len) |length| {
        if (length == 0) continue; // Missing metadata is supported.
        try std.testing.expectError(error.InvalidSfo, parse(allocator, bytes[0..length]));
    }
}


test "PKG title normalizes legacy trademark without changing source" {
    var bytes = fixture();
    bytes[68] = 0x99;
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    const result = try parsePkg(std.testing.allocator, &bytes, &owner);
    try std.testing.expectEqualStrings("Dem™", result.title.?);
    try std.testing.expectEqual(@as(u8, 0x99), bytes[68]);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &bytes));
}
