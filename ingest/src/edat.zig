const std = @import("std");

extern fn pspdb_edat_decode(source: [*]const u8, output: [*]u8, length: usize, version: u32, flags: u32, rap: *const [16]u8) c_int;

const block_size = 16384;
const max_plaintext = 64 << 20;
const max_source = max_plaintext + max_plaintext / block_size * 16 + 0x110;

const Header = struct {
    version: u32,
    flags: u32,
    length: usize,
    identifier: []const u8,
};

/// Return the canonical content ID borrowed from a structurally valid EDAT.
/// This is safe for license lookup, not authenticated identity: decode verifies
/// the keyed header MAC after the caller supplies the corresponding RAP.
pub fn content_id(bytes: []const u8) ![]const u8 {
    return (try parse_header(bytes)).identifier;
}

/// Authenticate and decrypt a supported NPD v1/v2 license-2 EDAT in memory.
/// Input is borrowed, may be unaligned and is never changed. The caller owns
/// the exact-size result, including a valid empty payload. All keyed header,
/// metadata and ciphertext MACs must pass before any plaintext is returned.
/// Filename-dependent title hashes, ECDSA signatures and the optional footer
/// are not separately authenticated, matching the former bounded helper.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, rap: ?[16]u8) ![]u8 {
    const header = try parse_header(bytes);
    const license = rap orelse return error.MissingEdatRap;
    const output = try allocator.alloc(u8, header.length);
    errdefer allocator.free(output);
    if (pspdb_edat_decode(bytes.ptr, output.ptr, output.len, header.version, header.flags, &license) != 1)
        return error.EdatAuthenticationFailed;
    return output;
}

fn parse_header(bytes: []const u8) !Header {
    if (bytes.len < 0x100 or !std.mem.eql(u8, bytes[0..4], "NPD\x00")) return error.InvalidEdat;
    if (bytes.len > max_source) return error.InvalidEdatSize;
    const version = std.mem.readInt(u32, bytes[4..8], .big);
    const license_type = std.mem.readInt(u32, bytes[8..12], .big);
    const flags = std.mem.readInt(u32, bytes[0x80..0x84], .big);
    const declared_block_size = std.mem.readInt(u32, bytes[0x84..0x88], .big);
    if ((version != 1 and version != 2) or license_type != 2 or
        (flags != 0 and flags != 0x0c) or (version == 1 and flags != 0) or
        declared_block_size != block_size) return error.UnsupportedEdat;

    const declared_length = std.mem.readInt(u64, bytes[0x88..0x90], .big);
    if (declared_length > max_plaintext) return error.InvalidEdatSize;
    const length: usize = @intCast(declared_length);
    const blocks = (length + block_size - 1) / block_size;
    const padded_size = (length + 15) & ~@as(usize, 15);
    const data_end = 0x100 + blocks * 16 + padded_size;
    // The original source retains the optional 16-byte packer footer.
    if (bytes.len != data_end and bytes.len != data_end + 16) return error.InvalidEdatSize;

    const identifier = bytes[0x10..0x34];
    for (identifier, 0..) |byte, index| {
        const valid = switch (index) {
            0, 1 => std.ascii.isUpper(byte),
            2...5, 17, 18 => std.ascii.isDigit(byte),
            6, 19 => byte == '-',
            7...15 => std.ascii.isUpper(byte) or std.ascii.isDigit(byte),
            16 => byte == '_',
            20...35 => std.ascii.isAlphanumeric(byte) or byte == '_',
            else => unreachable,
        };
        if (!valid) return error.InvalidEdatContentId;
    }
    if (!std.mem.allEqual(u8, bytes[0x34..0x40], 0)) return error.InvalidEdatContentId;
    return .{ .version = version, .flags = flags, .length = length, .identifier = identifier };
}

fn empty_fixture() [0x100]u8 {
    var bytes: [0x100]u8 = @splat(0);
    @memcpy(bytes[0..4], "NPD\x00");
    std.mem.writeInt(u32, bytes[4..8], 2, .big);
    std.mem.writeInt(u32, bytes[8..12], 2, .big);
    @memcpy(bytes[0x10..0x34], "EP0000-NPEZ00000_00-0000000000000000");
    std.mem.writeInt(u32, bytes[0x84..0x88], block_size, .big);
    return bytes;
}

test "EDAT license lookup rejects unsafe IDs and noncanonical padding" {
    const original = empty_fixture();
    try std.testing.expectEqualStrings("EP0000-NPEZ00000_00-0000000000000000", try content_id(&original));
    for ([_]usize{ 0x10, 0x16, 0x20, 0x24, 0x33, 0x34, 0x3f }) |offset| {
        var bytes = original;
        bytes[offset] = '/';
        try std.testing.expectError(error.InvalidEdatContentId, content_id(&bytes));
    }
}

test "EDAT rejects impossible spans before allocating or looking up a RAP" {
    var bytes = empty_fixture();
    try std.testing.expectError(error.InvalidEdat, decode(std.testing.allocator, bytes[0..0xff], null));
    std.mem.writeInt(u64, bytes[0x88..0x90], 1, .big);
    try std.testing.expectError(error.InvalidEdatSize, decode(std.testing.allocator, &bytes, null));
    std.mem.writeInt(u64, bytes[0x88..0x90], max_plaintext + 1, .big);
    try std.testing.expectError(error.InvalidEdatSize, decode(std.testing.allocator, &bytes, null));
    std.mem.writeInt(u64, bytes[0x88..0x90], std.math.maxInt(u64), .big);
    try std.testing.expectError(error.InvalidEdatSize, decode(std.testing.allocator, &bytes, null));
}

test "EDAT never accepts an empty payload without its keyed MACs" {
    const bytes = empty_fixture();
    try std.testing.expectError(error.MissingEdatRap, decode(std.testing.allocator, &bytes, null));
    try std.testing.expectError(error.EdatAuthenticationFailed, decode(std.testing.allocator, &bytes, @splat(0)));
}

// Synthetic licenses and data only. Reuse the pinned crypto to sign fixtures;
// no retail license material or plaintext is embedded in the test executable.
const FixtureCrypto = struct {
    extern fn get_rif_key(rap: *const [16]u8, rif: *[16]u8) void;
    extern fn generate_key(mode: c_int, version: c_int, key_final: *[16]u8, iv_final: *[16]u8, key: *const [16]u8, iv: *const [16]u8) void;
    extern fn generate_hash(mode: c_int, version: c_int, hash_final: *[16]u8, hash: *const [16]u8) void;
    extern fn aesecb128_encrypt(key: *const [16]u8, input: *const [16]u8, output: *[16]u8) void;
    extern fn aescbc128_encrypt(key: *const [16]u8, iv: *[16]u8, input: [*]const u8, output: [*]u8, length: c_int) void;
    extern fn cmac_hash_forge(key: *const [16]u8, key_len: c_int, input: [*]const u8, input_len: c_int, hash: *[16]u8) void;
};

fn signed_fixture(allocator: std.mem.Allocator, payload: []const u8, version: u32, flags: u32) ![]u8 {
    const blocks = (payload.len + block_size - 1) / block_size;
    const data_offset = 0x100 + blocks * 16;
    const padded_size = (payload.len + 15) & ~@as(usize, 15);
    const bytes = try allocator.alloc(u8, data_offset + padded_size);
    @memset(bytes, 0);
    @memcpy(bytes[0..0x100], &empty_fixture());
    std.mem.writeInt(u32, bytes[4..8], version, .big);
    std.mem.writeInt(u32, bytes[0x80..0x84], flags, .big);
    std.mem.writeInt(u64, bytes[0x88..0x90], payload.len, .big);
    @memset(bytes[0x40..0x50], 0x41);
    @memset(bytes[0x60..0x70], 0x62);
    @memcpy(bytes[data_offset..][0..payload.len], payload);
    const mode: c_int = if (flags & 8 != 0) 0x10000002 else 2;
    const rap: [16]u8 = @splat(0);
    var key: [16]u8 = undefined;
    FixtureCrypto.get_rif_key(&rap, &key);
    var hash_key: [16]u8 = undefined;
    FixtureCrypto.generate_hash(mode, 0, &hash_key, &key);
    for (0..blocks) |block| {
        var block_key: [16]u8 = @splat(0);
        var iv: [16]u8 = @splat(0);
        if (version == 2) {
            @memcpy(block_key[0..12], bytes[0x60..0x6c]);
            @memcpy(&iv, bytes[0x40..0x50]);
        }
        std.mem.writeInt(u32, block_key[12..16], @intCast(block), .big);
        var derived_key: [16]u8 = undefined;
        var crypto_key: [16]u8 = undefined;
        var crypto_iv: [16]u8 = undefined;
        var block_hash_key: [16]u8 = undefined;
        FixtureCrypto.aesecb128_encrypt(&key, &block_key, &derived_key);
        FixtureCrypto.generate_key(mode, 0, &crypto_key, &crypto_iv, &derived_key, &iv);
        FixtureCrypto.generate_hash(mode, 0, &block_hash_key, &derived_key);
        const offset = block * block_size;
        const ciphertext = bytes[data_offset + offset ..][0..@min(block_size, padded_size - offset)];
        FixtureCrypto.aescbc128_encrypt(&crypto_key, &crypto_iv, ciphertext.ptr, ciphertext.ptr, @intCast(ciphertext.len));
        FixtureCrypto.cmac_hash_forge(&block_hash_key, 16, ciphertext.ptr, @intCast(ciphertext.len), bytes[0x100 + block * 16 ..][0..16]);
    }
    FixtureCrypto.cmac_hash_forge(&hash_key, 16, bytes[0x100..].ptr, @intCast(blocks * 16), bytes[0x90..0xa0]);
    FixtureCrypto.cmac_hash_forge(&hash_key, 16, bytes.ptr, 0xa0, bytes[0xa0..0xb0]);
    return bytes;
}

test "EDAT authenticates every block before returning immutable unaligned plaintext" {
    const allocator = std.testing.allocator;
    const payload = [_]u8{0x31} ** (block_size + 1);
    const fixture = try signed_fixture(allocator, &payload, 2, 0x0c);
    defer allocator.free(fixture);
    const storage = try allocator.alloc(u8, fixture.len + 1);
    defer allocator.free(storage);
    const bytes = storage[1..];
    @memcpy(bytes, fixture);
    const plaintext = try decode(allocator, bytes, @splat(0));
    defer allocator.free(plaintext);
    try std.testing.expectEqualSlices(u8, &payload, plaintext);
    try std.testing.expectEqualSlices(u8, fixture, bytes);

    // Header, metadata tag/table, early block, and final AES padding damage.
    // A late failure must discard the already-decrypted first block as well.
    for ([_]usize{ 0x50, 0xa0, 0x90, 0x100, 0x120, fixture.len - 1 }) |offset| {
        bytes[offset] ^= 1;
        try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, bytes, @splat(0)));
        bytes[offset] ^= 1;
    }
    try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, bytes, @splat(1)));
    try std.testing.expectError(error.InvalidEdatSize, decode(allocator, bytes[0 .. bytes.len - 1], @splat(0)));
}

test "EDAT supports unencrypted keys and authenticated empty payloads" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 1, 2 }) |version| {
        const fixture = try signed_fixture(allocator, "", version, 0);
        defer allocator.free(fixture);
        const plaintext = try decode(allocator, fixture, @splat(0));
        defer allocator.free(plaintext);
        try std.testing.expectEqualSlices(u8, "", plaintext);
    }
}
