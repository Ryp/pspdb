const std = @import("std");

/// Values borrow the SFO buffer, except a normalized title owned by the caller.
/// Missing metadata is allowed; malformed input is rejected.
pub const Metadata = struct {
    disc_version: ?[]const u8 = null,
    disc_id: ?[]const u8 = null,
    title: ?[]const u8 = null,
    required_firmware: ?[]const u8 = null,
    category: ?[]const u8 = null,
};

/// A supplied title owner must start empty and be freed even if parsing fails.
/// Without an owner, selected strings retain strict UTF-8 validation.
/// Normalization affects catalog text only, never the original SFO bytes.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, title_owner: ?*[]u8) !Metadata {
    return parseImpl(allocator, bytes, title_owner, null);
}

/// Declared compatibility class among released PSP hardware, not authenticity.
pub const UpdateTarget = enum { psp, @"psp-go" };

pub const UpdateMetadata = struct {
    metadata: Metadata,
    updater_version: []const u8,
    updater_target: ?UpdateTarget,
};

/// Root updater recognition alone selects UPDATER_VER and typed BOOTABLE.
/// Generic SFO/PBP consumers retain their validation of unrelated fields.
pub fn parseUpdate(allocator: std.mem.Allocator, bytes: []const u8) !UpdateMetadata {
    var fields: UpdateFields = .{};
    const metadata = try parseImpl(allocator, bytes, null, &fields);
    const value = fields.version orelse return error.MissingUpdaterVersion;
    if (value.len == 0) return error.MissingUpdaterVersion;
    return .{
        .metadata = metadata,
        .updater_version = value,
        .updater_target = if (fields.bootable) |bootable| switch (bootable) {
            1 => .psp,
            2 => .@"psp-go",
            else => null,
        } else null,
    };
}

const UpdateFields = struct {
    version: ?[]const u8 = null,
    bootable: ?u32 = null,
};

fn parseImpl(allocator: std.mem.Allocator, bytes: []const u8, title_owner: ?*[]u8, update: ?*UpdateFields) !Metadata {
    if (bytes.len == 0) return .{};
    const parsed = @import("zig_psp_sfo").readSFO(allocator, bytes) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidSfo,
    };
    defer parsed.deinit(allocator);
    var result: Metadata = .{};
    for (parsed.table) |entry| {
        const key = parsed.key(entry);
        if (update) |fields| {
            if (std.mem.eql(u8, key, "BOOTABLE")) {
                const data = parsed.data(entry);
                if (entry.data_fmt != .Int32 or data.len != 4 or fields.bootable != null) return error.InvalidSfo;
                fields.bootable = std.mem.readInt(u32, data[0..4], .little);
                continue;
            }
        }
        const target: *?[]const u8 = selected: {
            inline for (.{ .{ "DISC_ID", "disc_id" }, .{ "DISC_VERSION", "disc_version" }, .{ "TITLE", "title" }, .{ "PSP_SYSTEM_VER", "required_firmware" }, .{ "CATEGORY", "category" } }) |field| {
                if (std.mem.eql(u8, key, field[0])) break :selected &@field(result, field[1]);
            }
            if (std.mem.eql(u8, key, "UPDATER_VER")) {
                if (update) |fields| break :selected &fields.version;
            }
            continue;
        };
        const data = parsed.data(entry);
        if (entry.data_fmt != .UTF8 or data.len == 0 or target.* != null) return error.InvalidSfo;
        const end = std.mem.indexOfScalar(u8, data, 0) orelse return error.InvalidSfo;
        const text = data[0..end];
        if (!std.unicode.utf8ValidateSlice(text)) {
            // Some PSP and PS1 SFOs use CP1252 trademark, copyright and
            // registered signs, the right single quotation mark, or one
            // Shift-JIS middle dot in otherwise ASCII TITLE. No other legacy
            // byte sequence is accepted.
            if (!std.mem.eql(u8, key, "TITLE") or title_owner == null) return error.InvalidSfo;
            var length: usize = 0;
            var i: usize = 0;
            while (i < text.len) {
                const sign = legacy_title_sign(text[i..]) orelse return error.InvalidSfo;
                length += sign.text.len;
                i += sign.consumed;
            }
            const normalized = try allocator.alloc(u8, length);
            var pos: usize = 0;
            i = 0;
            while (i < text.len) {
                const sign = legacy_title_sign(text[i..]).?;
                @memcpy(normalized[pos..][0..sign.text.len], sign.text);
                pos += sign.text.len;
                i += sign.consumed;
            }
            title_owner.?.* = normalized;
            target.* = normalized;
        } else target.* = text;
    }
    return result;
}

/// Decode the legacy sequence starting `rest`: ASCII passes through.
fn legacy_title_sign(rest: []const u8) ?struct { text: []const u8, consumed: usize } {
    if (rest[0] < 128) return .{ .text = rest[0..1], .consumed = 1 };
    // Shift-JIS 0x81 0x45 is the katakana middle dot (U+30FB): the English
    // C&C Red Alert (EP0006-NPEF00028) title ends "Red Alert\x81E", where the
    // French edition has "Red Alert™". 0x45 is the pair's trail byte, not "E".
    if (rest[0] == 0x81 and rest.len > 1 and rest[1] == 0x45) return .{ .text = "・", .consumed = 2 };
    return .{ .text = switch (rest[0]) {
        0x99 => "™",
        0xa9 => "©",
        0xae => "®",
        // Right single quotation mark (U+2019), used as an apostrophe in
        // some European PSN titles, e.g. "Everybody’s Golf 2" (NPEE00025).
        0x92 => "’",
        else => return null,
    }, .consumed = 1 };
}

test "missing and malformed SFO" {
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    try std.testing.expectEqual(null, (try parse(std.testing.allocator, "", &owner)).disc_id);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, "not an SFO", &owner));
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
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    const result = try parse(std.testing.allocator, &bytes, &owner);
    try std.testing.expectEqualStrings("Demo", result.title.?);
    try std.testing.expectEqual(bytes[65..].ptr, result.title.?.ptr);
    try std.testing.expectEqual(null, result.disc_id);
    // Unknown formats in unrelated fields are retained by the dependency.
    std.mem.writeInt(u16, bytes[38..40], 0xffff, .little);
    try std.testing.expectEqualStrings("Demo", (try parse(std.testing.allocator, &bytes, &owner)).title.?);
}

test "SFO strings end at the first NUL within their declared data" {
    var bytes = fixture();
    @memcpy(bytes[65..70], "Hi\x00\x04\xff");
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    try std.testing.expectEqualStrings("Hi", (try parse(std.testing.allocator, &bytes, &owner)).title.?);

    // A terminator in the allocated slot but outside data_len is not valid.
    std.mem.writeInt(u32, bytes[24..28], 2, .little);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &bytes, &owner));
}

test "Zig-PSP SFO rejects malformed tables, keys, values and duplicate metadata" {
    const allocator = std.testing.allocator;
    var owner: []u8 = &.{};
    defer allocator.free(owner);
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
        try std.testing.expectError(error.InvalidSfo, parse(allocator, &bytes, &owner));
    }

    var bytes = fixture();
    for (0..bytes.len) |length| {
        if (length == 0) continue; // Missing metadata is supported.
        try std.testing.expectError(error.InvalidSfo, parse(allocator, bytes[0..length], &owner));
    }
}

test "selected title normalizes legacy trademark, copyright, registered, apostrophe and middle-dot signs without changing source" {
    var bytes = fixture();
    bytes[68] = 0x99;
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &bytes, null));
    for ([_]struct { u8, u8, []const u8 }{ .{ 0x99, 0xa9, "De™©" }, .{ 0xae, 'o', "De®o" }, .{ 0x92, 's', "De’s" }, .{ 0x81, 0x45, "De・" } }) |case| {
        bytes[67] = case[0];
        bytes[68] = case[1];
        var owner: []u8 = &.{};
        defer std.testing.allocator.free(owner);
        const result = try parse(std.testing.allocator, &bytes, &owner);
        try std.testing.expectEqualStrings(case[2], result.title.?);
        try std.testing.expectEqual(case[0], bytes[67]);
    }
    // Other legacy bytes stay invalid: the left single quote, any other
    // Shift-JIS pair, and a lead byte cut off by the terminator.
    for ([_][2]u8{ .{ 'e', 0x91 }, .{ 0x81, 0x46 }, .{ 'e', 0x81 } }) |case| {
        bytes[67] = case[0];
        bytes[68] = case[1];
        var owner: []u8 = &.{};
        defer std.testing.allocator.free(owner);
        try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &bytes, &owner));
    }
}

fn category_fixture(comptime count: usize) [20 + 16 * count + 9 + 3 * count]u8 {
    var bytes: [20 + 16 * count + 9 + 3 * count]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PSF");
    std.mem.writeInt(u32, bytes[4..8], 0x101, .little);
    std.mem.writeInt(u32, bytes[8..12], 20 + 16 * count, .little);
    std.mem.writeInt(u32, bytes[12..16], 20 + 16 * count + 9, .little);
    std.mem.writeInt(u32, bytes[16..20], count, .little);
    inline for (0..count) |index| {
        const entry = 20 + 16 * index;
        std.mem.writeInt(u16, bytes[entry + 2 ..][0..2], 0x204, .little);
        std.mem.writeInt(u32, bytes[entry + 4 ..][0..4], 3, .little);
        std.mem.writeInt(u32, bytes[entry + 8 ..][0..4], 3, .little);
        std.mem.writeInt(u32, bytes[entry + 12 ..][0..4], 3 * index, .little);
        @memcpy(bytes[20 + 16 * count + 9 + 3 * index ..][0..3], "MG\x00");
    }
    @memcpy(bytes[20 + 16 * count ..][0..9], "CATEGORY\x00");
    return bytes;
}

test "selected CATEGORY borrows the input and rejects duplicates" {
    var owner: []u8 = &.{};
    defer std.testing.allocator.free(owner);
    var bytes = category_fixture(1);
    const result = try parse(std.testing.allocator, &bytes, &owner);
    try std.testing.expectEqualStrings("MG", result.category.?);
    try std.testing.expectEqual(bytes[45..].ptr, result.category.?.ptr);
    var duplicate = category_fixture(2);
    try std.testing.expectError(error.InvalidSfo, parse(std.testing.allocator, &duplicate, &owner));
}
