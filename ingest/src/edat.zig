const std = @import("std");

extern fn pspdb_edat_decode(source: [*]const u8, source_size: usize, output: [*]u8, length: usize, license: *const [16]u8) c_int;
extern fn pspdb_edat_verify_marker(source: [*]const u8) c_int;

const block_size = 16384;
const max_plaintext = 64 << 20;
// Compressed SDAT carries 0x20 bytes of metadata per block and may not shrink.
const max_source = max_plaintext + max_plaintext / block_size * 0x20 + 0x110;

const sdat_flag: u32 = 0x0100_0000;
const compressed_flag: u32 = 0x1;
const interleaved_flag: u32 = 0x20;
/// SDAT | encrypted block keys | compressed (plus the unnamed 0x4 bit).
const sdat_compressed_flags: u32 = 0x0100_000d;
/// NPD v3 license-2 packages (PS3-KEY.EDAT, ISO.BIN.EDAT, MINIS.EDAT): HMAC
/// block hashes with the 0x20-byte metadata preceding the data.
const interleaved_flags: u32 = 0x3c;

const Header = struct {
    version: u32,
    license_type: u32,
    flags: u32,
    length: usize,
    identifier: []const u8,

    fn sdat(self: Header) bool {
        return self.flags & sdat_flag != 0;
    }
};

/// Return the canonical content ID borrowed from a structurally valid EDAT.
/// This is safe for license lookup, not authenticated identity: decode verifies
/// the keyed header MAC after the caller supplies the corresponding RAP.
pub fn content_id(bytes: []const u8) ![]const u8 {
    return (try parse_header(bytes)).identifier;
}

/// Authenticate and decrypt a supported NPD EDAT/SDAT in memory: v1/v2
/// license-2, v3 license-2 flags 0x3c (single block), type-3 empty markers,
/// and SDAT (license 0, public fixed key, flags 0x0100000D, compressed).
/// Input is borrowed, may be unaligned and is never changed. The caller owns
/// the exact-size result, including a valid empty payload. All keyed header,
/// metadata and per-block MACs must pass before a block is decrypted and the
/// whole result is discarded on any failure. Filename-dependent title hashes,
/// ECDSA signatures and the optional footer are not separately authenticated,
/// matching the former bounded helper. SDAT's key is public, so its MACs prove
/// integrity, not origin. SDAT never needs a RAP.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, rap: ?[16]u8) ![]u8 {
    const header = try parse_header(bytes);
    const license: [16]u8 = if (header.license_type == 3 or header.sdat())
        @splat(0)
    else
        rap orelse return error.MissingEdatRap;
    const output = try allocator.alloc(u8, header.length);
    errdefer allocator.free(output);
    if (pspdb_edat_decode(bytes.ptr, bytes.len, output.ptr, output.len, &license) != 1)
        return error.EdatAuthenticationFailed;
    return output;
}

/// True for an SDAT container; the content ID field of those is not a licence key.
pub fn is_sdat(bytes: []const u8) bool {
    const header = parse_header(bytes) catch return false;
    return header.sdat();
}

/// A license-2 EDAT that declares an empty payload is a licence marker beside
/// the package's EBOOT.PBP: it has no ciphertext, so nothing is lost without
/// the buyer's RAP. Its RIF-keyed header MAC cannot be checked then; instead the
/// header's dev_hash must authenticate under a public klicensee. Callers try a
/// RAP-authenticated `decode` first and use this only when no RAP exists.
pub fn unlicensed_marker(bytes: []const u8) !bool {
    const header = try parse_header(bytes);
    return header.license_type == 2 and header.length == 0 and pspdb_edat_verify_marker(bytes.ptr) == 1;
}

fn parse_header(bytes: []const u8) !Header {
    if (bytes.len < 0x100 or !std.mem.eql(u8, bytes[0..4], "NPD\x00")) return error.InvalidEdat;
    if (bytes.len > max_source) return error.InvalidEdatSize;
    const version = std.mem.readInt(u32, bytes[4..8], .big);
    const license_type = std.mem.readInt(u32, bytes[8..12], .big);
    const flags = std.mem.readInt(u32, bytes[0x80..0x84], .big);
    const declared_block_size = std.mem.readInt(u32, bytes[0x84..0x88], .big);
    const sdat = flags == sdat_compressed_flags;
    const interleaved = flags == interleaved_flags;
    if (declared_block_size != block_size or
        !(sdat or interleaved or ((version == 1 or version == 2) and (flags == 0 or (version == 2 and flags == 0x0c)))))
        return error.UnsupportedEdat;

    const declared_length = std.mem.readInt(u64, bytes[0x88..0x90], .big);
    if (declared_length > max_plaintext) return error.InvalidEdatSize;
    const supported_license = if (sdat)
        (version == 2 or version == 3) and license_type == 0
    else if (interleaved)
        version == 3 and license_type == 2
    else
        license_type == 2 or (license_type == 3 and version == 2 and flags == 0x0c and declared_length == 0);
    if (!supported_license) return error.UnsupportedEdat;
    const length: usize = @intCast(declared_length);
    const blocks = (length + block_size - 1) / block_size;
    const padded_size = (length + 15) & ~@as(usize, 15);
    if (sdat) {
        // Compressed blocks have independent offsets; the native decoder bounds
        // every one of them. Only the metadata table must exist here.
        if (bytes.len < 0x100 + blocks * 0x20) return error.InvalidEdatSize;
    } else {
        // Interleaved v3 packages store one 0x20-byte metadata header before
        // the data of their single supported block.
        if (interleaved and blocks > 1) return error.UnsupportedEdat;
        const data_end = 0x100 + (if (interleaved) blocks * 0x20 else blocks * 16) + padded_size;
        // The original source retains the optional 16-byte packer footer.
        if (bytes.len != data_end and bytes.len != data_end + 16) return error.InvalidEdatSize;
    }

    // SDAT carries no licensed content ID: its field is empty for the observed type 0.
    const identifier = bytes[0x10..0x34];
    if (!sdat) {
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
    }
    return .{ .version = version, .flags = flags, .license_type = license_type, .length = length, .identifier = identifier };
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

test "EDAT licence markers are recognized only by an authentic dev_hash on an empty license-2 header" {
    const allocator = std.testing.allocator;
    const omac_key_2 = @extern(*const [16]u8, .{ .name = "NPDRM_OMAC_KEY_2" });
    const marker = try signed_fixture(allocator, "", 2, 0x0c, 2);
    defer allocator.free(marker);
    try std.testing.expect(!try unlicensed_marker(marker));
    // Retail markers sign their header identity with the all-zero klicensee.
    FixtureCrypto.cmac_hash_forge(omac_key_2, 16, marker.ptr, 0x60, marker[0x60..0x70]);
    try std.testing.expect(try unlicensed_marker(marker));
    // Any change to the identity it covers, such as the content ID, breaks it.
    marker[0x12] ^= 1;
    try std.testing.expect(!try unlicensed_marker(marker));
    marker[0x12] ^= 1;

    const payload = try signed_fixture(allocator, "data", 2, 0x0c, 2);
    defer allocator.free(payload);
    FixtureCrypto.cmac_hash_forge(omac_key_2, 16, payload.ptr, 0x60, payload[0x60..0x70]);
    try std.testing.expect(!try unlicensed_marker(payload));

    const free_marker = try signed_fixture(allocator, "", 2, 0x0c, 3);
    defer allocator.free(free_marker);
    FixtureCrypto.cmac_hash_forge(omac_key_2, 16, free_marker.ptr, 0x60, free_marker[0x60..0x70]);
    try std.testing.expect(!try unlicensed_marker(free_marker));
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
    extern fn hmac_hash_forge(key: *const [20]u8, key_len: c_int, input: [*]const u8, input_len: c_int, hash: *[20]u8) void;
};

fn signed_fixture(allocator: std.mem.Allocator, payload: []const u8, version: u32, flags: u32, license_type: u32) ![]u8 {
    const blocks = (payload.len + block_size - 1) / block_size;
    const data_offset = 0x100 + blocks * 16;
    const padded_size = (payload.len + 15) & ~@as(usize, 15);
    const bytes = try allocator.alloc(u8, data_offset + padded_size);
    @memset(bytes, 0);
    @memcpy(bytes[0..0x100], &empty_fixture());
    std.mem.writeInt(u32, bytes[4..8], version, .big);
    std.mem.writeInt(u32, bytes[8..12], license_type, .big);
    std.mem.writeInt(u32, bytes[0x80..0x84], flags, .big);
    std.mem.writeInt(u64, bytes[0x88..0x90], payload.len, .big);
    @memset(bytes[0x40..0x50], 0x41);
    @memset(bytes[0x60..0x70], 0x62);
    @memcpy(bytes[data_offset..][0..payload.len], payload);
    const mode: c_int = if (flags & 8 != 0) 0x10000002 else 2;
    const rap: [16]u8 = @splat(0);
    var key: [16]u8 = @splat(0);
    if (license_type == 2) FixtureCrypto.get_rif_key(&rap, &key);
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
    const payload: [block_size + 1]u8 = @splat(0x31);
    const fixture = try signed_fixture(allocator, &payload, 2, 0x0c, 2);
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
        const fixture = try signed_fixture(allocator, "", version, 0, 2);
        defer allocator.free(fixture);
        const plaintext = try decode(allocator, fixture, @splat(0));
        defer allocator.free(plaintext);
        try std.testing.expectEqualSlices(u8, "", plaintext);
    }
}

test "EDAT authenticates empty type-3 update markers without a RAP" {
    const allocator = std.testing.allocator;
    const fixture = try signed_fixture(allocator, "", 2, 0x0c, 3);
    defer allocator.free(fixture);
    const plaintext = try decode(allocator, fixture, null);
    defer allocator.free(plaintext);
    try std.testing.expectEqualSlices(u8, "", plaintext);

    fixture[0x40] ^= 1;
    try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, fixture, null));
    fixture[0x40] ^= 1;

    const unsupported = try signed_fixture(allocator, "not a marker", 2, 0x0c, 3);
    defer allocator.free(unsupported);
    try std.testing.expectError(error.UnsupportedEdat, decode(allocator, unsupported, null));
}

// --- SDAT and interleaved v3 fixtures -------------------------------------

const Variant = enum { interleaved, sdat_raw, sdat_packed };

/// Literal-only encoder for the EDAT range coder, a mirror of lz.c's decoder:
/// every byte is a raw character, so this exercises the bounded decompressor
/// without a real compressed corpus. Returns the stream, head byte first.
const LiteralCoder = struct {
    probability: [0xcc8]u8 = @splat(0x80),
    out: std.ArrayList(u8) = .empty,
    low: u64 = 0,
    range: u32 = 0xffff_ffff,
    cache: u8 = 0,
    cache_size: u64 = 1,

    fn shift_low(self: *LiteralCoder, allocator: std.mem.Allocator) !void {
        if (@as(u32, @truncate(self.low)) < 0xff00_0000 or (self.low >> 32) != 0) {
            const carry: u8 = @intCast(self.low >> 32);
            var byte = self.cache;
            while (true) {
                try self.out.append(allocator, byte +% carry);
                byte = 0xff;
                self.cache_size -= 1;
                if (self.cache_size == 0) break;
            }
            self.cache = @truncate(self.low >> 24);
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00ff_ffff) << 8;
    }

    fn encode(self: *LiteralCoder, allocator: std.mem.Allocator, slot: usize, bit: u1) !void {
        const c = &self.probability[slot];
        const value = (self.range >> 8) * @as(u32, c.*);
        c.* -= c.* >> 3;
        if (bit == 1) {
            self.range = value;
            c.* += 31;
        } else {
            self.low += value;
            self.range -= value;
        }
        while (self.range >> 24 == 0) {
            self.range <<= 8;
            try self.shift_low(allocator);
        }
    }
};

fn lz_literals(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var coder: LiteralCoder = .{};
    errdefer coder.out.deinit(allocator);
    var previous: u8 = 0;
    for (data, 0..) |byte, position| {
        try coder.encode(allocator, 0xb68, 0);
        const context = (((position & 7) << 8) + previous) & 7;
        var index: usize = 1;
        var shift: u4 = 8;
        while (shift > 0) {
            shift -= 1;
            const bit: u1 = @truncate(byte >> @as(u3, @intCast(shift)));
            try coder.encode(allocator, context * 0xff + index - 1, bit);
            index = (index << 1) | bit;
        }
        previous = byte;
    }
    // The decoder reads one more raw-character flag, then sees the output full.
    try coder.encode(allocator, 0xb68, 0);
    for (0..5) |_| try coder.shift_low(allocator);
    coder.out.items[0] = 0; // dictionary head: shift 0
    return coder.out.toOwnedSlice(allocator);
}

fn variant_fixture(allocator: std.mem.Allocator, payload: []const u8, variant: Variant) ![]u8 {
    const sdat = variant != .interleaved;
    const blocks = (payload.len + block_size - 1) / block_size;
    const section: usize = 0x20;
    const flags: u32 = if (sdat) sdat_compressed_flags else interleaved_flags;
    // Stored block images before encryption: zero-padded to AES blocks.
    const stored = try allocator.alloc([]u8, blocks);
    const lengths = try allocator.alloc(usize, blocks);
    defer {
        for (stored) |item| allocator.free(item);
        allocator.free(stored);
        allocator.free(lengths);
    }
    var total: usize = 0;
    for (stored, lengths, 0..) |*item, *length, block| {
        const plain = payload[block * block_size ..][0..@min(block_size, payload.len - block * block_size)];
        const raw = if (variant == .sdat_packed) try lz_literals(allocator, plain) else try allocator.dupe(u8, plain);
        defer allocator.free(raw);
        const padded = try allocator.alloc(u8, (raw.len + 15) & ~@as(usize, 15));
        @memset(padded, 0);
        @memcpy(padded[0..raw.len], raw);
        item.* = padded;
        length.* = raw.len;
        total += padded.len;
    }
    const data_offset = 0x100 + blocks * section;
    const bytes = try allocator.alloc(u8, data_offset + total);
    @memset(bytes, 0);
    @memcpy(bytes[0..0x100], &empty_fixture());
    if (sdat) @memset(bytes[0x10..0x40], 0);
    std.mem.writeInt(u32, bytes[4..8], if (sdat) 2 else 3, .big);
    std.mem.writeInt(u32, bytes[8..12], if (sdat) 0 else 2, .big);
    std.mem.writeInt(u32, bytes[0x80..0x84], flags, .big);
    std.mem.writeInt(u64, bytes[0x88..0x90], payload.len, .big);
    @memset(bytes[0x40..0x50], 0x41);
    @memset(bytes[0x60..0x70], 0x62);

    var key: [16]u8 = undefined;
    if (sdat) {
        const sdat_key = @extern(*const [16]u8, .{ .name = "SDAT_KEY" });
        for (&key, 0..) |*byte, index| byte.* = bytes[0x60 + index] ^ sdat_key[index];
    } else {
        const rap: [16]u8 = @splat(0);
        FixtureCrypto.get_rif_key(&rap, &key);
    }
    var header_key: [16]u8 = undefined;
    FixtureCrypto.generate_hash(0x10000002, 0, &header_key, &key);
    const hash_mode: c_int = if (sdat) 0x10000002 else 0x10000001;
    var cursor = data_offset;
    for (stored, lengths, 0..) |item, length, block| {
        var block_key: [16]u8 = @splat(0);
        var iv: [16]u8 = undefined;
        @memcpy(block_key[0..12], bytes[0x60..0x6c]);
        @memcpy(&iv, bytes[0x40..0x50]);
        std.mem.writeInt(u32, block_key[12..16], @intCast(block), .big);
        var derived_key: [16]u8 = undefined;
        FixtureCrypto.aesecb128_encrypt(&key, &block_key, &derived_key);
        var hash_source = derived_key;
        if (!sdat) FixtureCrypto.aesecb128_encrypt(&key, &derived_key, &hash_source);
        var crypto_key: [16]u8 = undefined;
        var crypto_iv: [16]u8 = undefined;
        FixtureCrypto.generate_key(0x10000002, 0, &crypto_key, &crypto_iv, &derived_key, &iv);
        var block_hash_key: [16]u8 = undefined;
        FixtureCrypto.generate_hash(hash_mode, 0, &block_hash_key, &hash_source);
        const ciphertext = bytes[cursor..][0..item.len];
        @memcpy(ciphertext, item);
        FixtureCrypto.aescbc128_encrypt(&crypto_key, &crypto_iv, ciphertext.ptr, ciphertext.ptr, @intCast(ciphertext.len));
        const meta = bytes[0x100 + block * section ..][0..0x20];
        if (sdat) {
            FixtureCrypto.cmac_hash_forge(&block_hash_key, 16, ciphertext.ptr, @intCast(ciphertext.len), meta[0..16]);
            // Hide {offset, length, compressed} the way upstream's dec_section reads it.
            var fields: [16]u8 = @splat(0);
            std.mem.writeInt(u32, fields[0..4], @intCast(cursor >> 4), .big);
            std.mem.writeInt(u32, fields[8..12], @intCast(length), .big);
            std.mem.writeInt(u32, fields[12..16], @intFromBool(variant == .sdat_packed), .big);
            const first = [16]u8{ 0xC, 0xD, 0xE, 0xF, 0x4, 0x5, 0x6, 0x7, 0xC, 0xD, 0xE, 0xF, 0x4, 0x5, 0x6, 0x7 };
            const second = [16]u8{ 0x8, 0x9, 0xA, 0xB, 0x8, 0x9, 0xA, 0xB, 0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3 };
            for (0..16) |index| meta[16 + index] = fields[index] ^ meta[first[index]] ^ meta[second[index]];
        } else {
            var key20: [20]u8 = @splat(0);
            @memcpy(key20[0..16], &block_hash_key);
            var mac: [20]u8 = undefined;
            FixtureCrypto.hmac_hash_forge(&key20, 20, ciphertext.ptr, @intCast(ciphertext.len), &mac);
            @memcpy(meta[0..16], mac[0..16]);
        }
        cursor += item.len;
    }
    FixtureCrypto.cmac_hash_forge(&header_key, 16, bytes[0x100..].ptr, @intCast(blocks * section), bytes[0x90..0xa0]);
    FixtureCrypto.cmac_hash_forge(&header_key, 16, bytes.ptr, 0xa0, bytes[0xa0..0xb0]);
    return bytes;
}

fn sdat_payload(allocator: std.mem.Allocator, length: usize) ![]u8 {
    const payload = try allocator.alloc(u8, length);
    for (payload, 0..) |*byte, index| byte.* = if (index % 97 < 90) 'A' else @truncate(index * 7);
    return payload;
}

test "SDAT with raw and literal-compressed blocks authenticates without a RAP" {
    const allocator = std.testing.allocator;
    const payload = try sdat_payload(allocator, block_size + 777);
    defer allocator.free(payload);
    for ([_]Variant{ .sdat_raw, .sdat_packed }) |variant| {
        const fixture = try variant_fixture(allocator, payload, variant);
        defer allocator.free(fixture);
        try std.testing.expect(is_sdat(fixture));
        const plain = try decode(allocator, fixture, null);
        defer allocator.free(plain);
        try std.testing.expectEqualSlices(u8, payload, plain);

        // Header, metadata table (tag and entries), and each block's ciphertext.
        for ([_]usize{ 0x50, 0x70, 0x90, 0xa0, 0x100, 0x13f, fixture.len - 1 }) |offset| {
            fixture[offset] ^= 1;
            try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, fixture, null));
            fixture[offset] ^= 1;
        }
        for ([_]usize{ 0x140, 0x141 }) |offset| {
            fixture[offset] ^= 0x80;
            try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, fixture, null));
            fixture[offset] ^= 0x80;
        }
        try std.testing.expectError(error.InvalidEdatSize, decode(allocator, fixture[0..0x13f], null));
    }
}

test "SDAT rejects unsupported profiles before decoding" {
    const allocator = std.testing.allocator;
    const payload = try sdat_payload(allocator, 100);
    defer allocator.free(payload);
    const fixture = try variant_fixture(allocator, payload, .sdat_raw);
    defer allocator.free(fixture);
    std.mem.writeInt(u32, fixture[8..12], 2, .big); // licensed NPD without the SDAT-only flags pairing
    try std.testing.expectError(error.UnsupportedEdat, decode(allocator, fixture, null));
    std.mem.writeInt(u32, fixture[8..12], 0, .big);
    std.mem.writeInt(u32, fixture[0x80..0x84], 0x8100_000d, .big); // debug data
    try std.testing.expectError(error.UnsupportedEdat, decode(allocator, fixture, null));
    std.mem.writeInt(u32, fixture[0x80..0x84], sdat_compressed_flags, .big);
    std.mem.writeInt(u32, fixture[4..8], 1, .big);
    try std.testing.expectError(error.UnsupportedEdat, decode(allocator, fixture, null));
}

test "NPD v3 interleaved license-2 EDAT authenticates with its RAP" {
    const allocator = std.testing.allocator;
    const payload: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const fixture = try variant_fixture(allocator, &payload, .interleaved);
    defer allocator.free(fixture);
    try std.testing.expect(!is_sdat(fixture));
    try std.testing.expectError(error.MissingEdatRap, decode(allocator, fixture, null));
    const plain = try decode(allocator, fixture, @splat(0));
    defer allocator.free(plain);
    try std.testing.expectEqualSlices(u8, &payload, plain);
    try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, fixture, @splat(2)));
    for ([_]usize{ 0x50, 0x90, 0xa0, 0x100, 0x110, 0x120, 0x12f }) |offset| {
        fixture[offset] ^= 1;
        try std.testing.expectError(error.EdatAuthenticationFailed, decode(allocator, fixture, @splat(0)));
        fixture[offset] ^= 1;
    }
    // Only the single-block layout has been observed.
    std.mem.writeInt(u64, fixture[0x88..0x90], block_size + 1, .big);
    try std.testing.expectError(error.UnsupportedEdat, decode(allocator, fixture, @splat(0)));
}
