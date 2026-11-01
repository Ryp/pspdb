//! Empty-key PGD decryption for PS1 Classic DATA.PSAR (PSXtract-2 `decrypt_pgd`
//! with flag 2). The version key is derived from the PGD's own MAC at 0x70
//! (`bbmac_getkey`); the DNAS key 1A90 authenticates the header MAC at 0x80.
//! Unlike PSXtract, the table MAC at 0x60 and every per-block MAC are verified
//! before any plaintext is produced. The source is never modified.
const std = @import("std");

const psp_decrypt = @import("zig_psp_decrypt");

pub const Error = error{
    /// Structural problem: short buffer, zero/non power-of-two block size, offsets out of range.
    InvalidPgd,
    /// MAC at 0x80 (DNAS header MAC) does not verify.
    PgdHeaderMacMismatch,
    /// Version key could not be derived from the MAC at 0x70.
    PgdKeyDerivationFailed,
    /// MAC at 0x60 over the block MAC table does not verify.
    PgdTableMacMismatch,
    /// A per-block MAC does not verify.
    PgdBlockMacMismatch,
    PgdDecryptionFailed,
    OutOfMemory,
};

/// Plaintext payload (`data_size` bytes; PSXtract writes exactly these bytes as
/// ISO_HEADER*.BIN / ISO_MAP.BIN / SPECIAL_DATA.BIN / UNKNOWN_DATA.BIN).
pub const Owned = struct {
    bytes: []u8,

    pub fn deinit(self: Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

/// Authenticate and decrypt one PGD. `bytes` must start at the PGD header
/// (0x90 bytes) and may extend past the PGD; only the span the header declares
/// is read. Sources larger than 2 GiB - 1 are rejected.
pub fn decrypt(allocator: std.mem.Allocator, bytes: []const u8) Error!Owned {
    if (bytes.len < 0x90 or bytes.len > std.math.maxInt(i32)) return error.InvalidPgd;
    const out = try allocator.alloc(u8, bytes.len);
    errdefer allocator.free(out);
    const result = psp_decrypt.pgd.decryptPsx(bytes, out);
    if (result < 0) return switch (result) {
        -2 => error.PgdHeaderMacMismatch,
        -3 => error.PgdDecryptionFailed,
        -5 => error.PgdTableMacMismatch,
        -6 => error.PgdBlockMacMismatch,
        -7 => error.PgdKeyDerivationFailed,
        else => error.InvalidPgd,
    };
    const size: usize = @intCast(result);
    if (size > out.len) return error.InvalidPgd;
    return .{ .bytes = try allocator.realloc(out, size) };
}

/// Synthetic PGD builder for unit tests (this file and psar.zig). Uses the same
/// libkirk primitives, with an explicit version key, so no real content is needed.
pub const testing_support = struct {
    const amctrl = psp_decrypt.amctrl;
    const dnas_key1a90 = psp_decrypt.pgd.dnas_key1a90;

    pub const Options = struct {
        block_size: u32 = 0x400,
        version_key: [16]u8 = @splat(0x31),
        /// Zero-pad the result to this length (e.g. the 0xB6600 ISO header span).
        total_len: usize = 0,
        /// Declare a different block size / data offset in the (encrypted) header
        /// than the one used to lay out and authenticate the PGD.
        declared_block_size: ?u32 = null,
        declared_data_offset: ?u32 = null,
    };

    fn mac(kind: i32, out: []u8, input: []u8, key: ?*[16]u8, dnas: bool) void {
        var state: amctrl.MacKey = .{};
        std.debug.assert(amctrl.macInit(&state, kind) == 0);
        std.debug.assert(amctrl.macUpdate(&state, input) == 0);
        const key_ptr: ?*const [16]u8 = if (dnas) &dnas_key1a90 else if (key) |k| k else null;
        std.debug.assert(amctrl.macFinal(&state, out[0..16], key_ptr) == 0);
    }

    fn crypt(kind: i32, bytes: []u8, seed: []u8, key: *[16]u8) void {
        var state: amctrl.CipherKey = .{};
        std.debug.assert(amctrl.cipherInit(&state, kind, 2, seed[0..16], key, 0) == 0);
        std.debug.assert(amctrl.cipherUpdate(&state, bytes) == 0);
        std.debug.assert(amctrl.cipherFinal(&state) == 0);
    }

    pub fn build(allocator: std.mem.Allocator, payload: []const u8, options: Options) ![]u8 {
        // Only the fixed-key profile (drm_type 1, key_index 1: mac/cipher type 1) is
        // buildable here: type 2 is fuse-id bound (KIRK 5/8 unavailable in the
        // decryption-only libkirk build) and type 3 needs bbmac_build_final2.
        const mac_type: i32 = 1;
        const cipher_type: i32 = 1;
        const aligned = (payload.len + 15) & ~@as(usize, 15);
        const blocks = (aligned + options.block_size - 1) / options.block_size;
        const total = @max(0x90 + aligned + blocks * 16, options.total_len);
        const pgd = try allocator.alloc(u8, total);
        errdefer allocator.free(pgd);
        @memset(pgd, 0);
        var key = options.version_key;
        @memcpy(pgd[0..4], "\x00PGD");
        std.mem.writeInt(u32, pgd[4..8], 1, .little); // key_index
        std.mem.writeInt(u32, pgd[8..12], 1, .little); // drm_type
        for (pgd[0x10..0x20], 0..) |*byte, i| byte.* = @intCast(0xA0 + i);
        for (pgd[0x30..0x40], 0..) |*byte, i| byte.* = @intCast(0x50 + i);
        std.mem.writeInt(u32, pgd[0x44..0x48], @intCast(payload.len), .little);
        std.mem.writeInt(u32, pgd[0x48..0x4c], options.declared_block_size orelse options.block_size, .little);
        std.mem.writeInt(u32, pgd[0x4c..0x50], options.declared_data_offset orelse 0x90, .little);

        const data = pgd[0x90 .. 0x90 + aligned];
        @memcpy(data[0..payload.len], payload);
        crypt(cipher_type, data, pgd[0x30..0x40], &key);
        const table = pgd[0x90 + aligned ..][0 .. blocks * 16];
        for (0..blocks) |block| {
            const start = block * options.block_size;
            const end = @min(start + options.block_size, aligned);
            mac(mac_type, table[block * 16 ..][0..16], data[start..end], &key, false);
        }
        mac(mac_type, pgd[0x60..0x70], table, &key, false);
        crypt(cipher_type, pgd[0x30..0x60], pgd[0x10..0x20], &key);
        mac(mac_type, pgd[0x70..0x80], pgd[0..0x70], &key, false);
        mac(mac_type, pgd[0x80..0x90], pgd[0..0x80], null, true);
        return pgd;
    }
};

const testing = std.testing;
const build = testing_support.build;

test "PGD round trip with block size and key variants" {
    const allocator = testing.allocator;
    var payload: [1000]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i *% 7 +% 3);
    const cases = [_]testing_support.Options{
        .{},
        .{ .block_size = 16 },
        .{ .block_size = 0x800 },
        .{ .block_size = 0x100, .version_key = @splat(0xC3) },
    };
    for (cases) |options| {
        const pgd = try build(allocator, &payload, options);
        defer allocator.free(pgd);
        const plain = try decrypt(allocator, pgd);
        defer plain.deinit(allocator);
        try testing.expectEqualSlices(u8, &payload, plain.bytes);
    }
}

test "PGD ignores bytes after the declared span and leaves the source untouched" {
    const allocator = testing.allocator;
    const pgd = try build(allocator, "0123456789abcdefXYZ", .{ .total_len = 0x400 });
    defer allocator.free(pgd);
    const copy = try allocator.dupe(u8, pgd);
    defer allocator.free(copy);
    const plain = try decrypt(allocator, pgd);
    defer plain.deinit(allocator);
    try testing.expectEqualStrings("0123456789abcdefXYZ", plain.bytes);
    try testing.expectEqualSlices(u8, copy, pgd);
}

test "PGD MAC failures are reported per layer" {
    const allocator = testing.allocator;
    var payload: [0x900]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i);
    const pgd = try build(allocator, &payload, .{});
    defer allocator.free(pgd);
    const aligned: usize = 0x900;
    const table = 0x90 + aligned;

    // Header MAC at 0x80 covers 0x00..0x80.
    for ([_]usize{ 0x04, 0x08, 0x20, 0x50, 0x70, 0x80 }) |offset| {
        const bad = try allocator.dupe(u8, pgd);
        defer allocator.free(bad);
        bad[offset] ^= 1;
        try testing.expectError(error.PgdHeaderMacMismatch, decrypt(allocator, bad));
    }
    // Table MAC at 0x60 (re-authenticating the header would need the key, so
    // damage the table itself: the header stays valid).
    {
        const bad = try allocator.dupe(u8, pgd);
        defer allocator.free(bad);
        bad[table + 3] ^= 0x80;
        try testing.expectError(error.PgdTableMacMismatch, decrypt(allocator, bad));
    }
    // A damaged block fails only its own MAC; the table is still intact.
    for ([_]usize{ 0x90, 0x90 + 0x3ff, 0x90 + 0x400, 0x90 + aligned - 1 }) |offset| {
        const bad = try allocator.dupe(u8, pgd);
        defer allocator.free(bad);
        bad[offset] ^= 1;
        try testing.expectError(error.PgdBlockMacMismatch, decrypt(allocator, bad));
    }
}

test "PGD rejects malformed structure" {
    const allocator = testing.allocator;
    const pgd = try build(allocator, "0123456789abcdef", .{});
    defer allocator.free(pgd);

    try testing.expectError(error.InvalidPgd, decrypt(allocator, pgd[0..0x8f]));
    // Truncated table: the header MACs stay valid, the span no longer fits.
    try testing.expectError(error.InvalidPgd, decrypt(allocator, pgd[0 .. pgd.len - 1]));
    for ([_]u32{ 0, 3, 0x300, 0x400 + 8 }) |declared| {
        const bad = try build(allocator, "0123456789abcdef", .{ .block_size = 16, .declared_block_size = declared });
        defer allocator.free(bad);
        try testing.expectError(error.InvalidPgd, decrypt(allocator, bad));
    }
    for ([_]u32{ 0, 0x80, 0xA0, 0x10000 }) |declared| {
        const bad = try build(allocator, "0123456789abcdef", .{ .declared_data_offset = declared });
        defer allocator.free(bad);
        try testing.expectError(error.InvalidPgd, decrypt(allocator, bad));
    }
    // Wrong DNAS/fixed key: random bytes never authenticate.
    var junk: [0x100]u8 = undefined;
    for (&junk, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% 1);
    try testing.expectError(error.PgdHeaderMacMismatch, decrypt(allocator, &junk));
}
