const std = @import("std");

const pgd = @import("pgd.zig");

const pgd_offset = 0x90;
const pgd_size = 0xb0;
const plain_size = pgd_offset + pgd_size;

/// `USRDIR/CONTENT/PSP-KEY.EDAT` of PC Engine Archives: a `\0PSPEDAT` header
/// (content ID at 0x10) followed at 0x90 by a fixed-key PGD (drm_type 1) whose
/// 16-byte payload is the content key. The PGD's version key is recovered from
/// the file itself (PPSSPP libkirk logic), so no licence or RAP is involved.
pub const key_size = 16;

/// Authenticate the embedded PGD (header MACs, table MAC and every block MAC)
/// and return its 16-byte payload. Only the PGD is authenticated: the PSPEDAT
/// header (content ID and the digest fields at 0x40..0x90) and the optional 16
/// unrecognized trailing bytes of 336-byte files are checked for shape only.
pub fn content_key(bytes: []const u8) ![key_size]u8 {
    if (bytes.len != plain_size and bytes.len != plain_size + 16) return error.InvalidPspEdat;
    return open(bytes, pgd_size);
}

fn open(bytes: []const u8, embedded_size: usize) ![key_size]u8 {
    if (bytes.len < pgd_offset + embedded_size or !std.mem.eql(u8, bytes[0..8], "\x00PSPEDAT") or
        !std.mem.eql(u8, bytes[8..16], "\x02\x00\x00\x00\x90\x00\x00\x01") or
        !std.mem.allEqual(u8, bytes[0x34..0x40], 0))
        return error.InvalidPspEdat;
    for (bytes[0x10..0x34]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return error.InvalidPspEdat;
    }
    var allocator_buffer: [pgd_size + 64]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&allocator_buffer);
    const plain = try pgd.decode(fixed.allocator(), bytes[pgd_offset..][0..embedded_size]);
    if (plain.len != key_size) return error.InvalidPspEdat;
    return plain[0..key_size].*;
}

// Synthetic file: a PGD generated with libkirk's own MAC/cipher primitives for a
// chosen version key, verified against an independent PPSSPP pgd_open. Its
// payload and ID are invented; no retail material is embedded.
const fixture_hex =
    "005053504544415402000000900000015550303030302d4e5055463030303030" ++
    "5f30302d50434554455354303030303030303030000000000000000000000000" ++
    "40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6db" ++
    "e0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b" ++
    "80858a8f94999ea3a8adb2b7bcc1c6cb00504744010000000100000000000000" ++
    "303336393c3f4245484b4e5154575a5d00000000000000000000000000000000" ++
    "2fa4e10a8d17d9042ddd74c6f201a8819d39f077d606951ea91a60127000ef28" ++
    "5cd728797cf554c4d16fa5b5a87c2d3be40e3f4bce69a567e3737f6afe47b983" ++
    "642728c989a95c184f918080d85cddd01c0cc3ec8373b0bd0cac82db5628a142" ++
    "5ef55c2489b5aa9def543b936fdb7b76b6bde2d62f2c604553bf3ed5fe06ee2a" ++
    "202122232425262728292a2b2c2d2e2f";

fn fixture() [fixture_hex.len / 2]u8 {
    var bytes: [fixture_hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, fixture_hex) catch unreachable;
    return bytes;
}

const fixture_key = [key_size]u8{ 0xc0, 0xde, 0xca, 0xfe, 0x50, 0x43, 0x45, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79 };

test "PSP-KEY.EDAT recovers its content key from the file alone" {
    const original = fixture();
    try std.testing.expectEqualSlices(u8, &fixture_key, &try content_key(&original));
    // The 320-byte form omits the trailing 16 bytes.
    try std.testing.expectEqualSlices(u8, &fixture_key, &try content_key(original[0..plain_size]));
}

test "PSP-KEY.EDAT authenticates its PGD and rejects malformed wrappers" {
    const original = fixture();
    // PGD header, MAC fields, table MAC, ciphertext and block MAC.
    for ([_]usize{ 0x90 + 0x20, 0x90 + 0x60, 0x90 + 0x70, 0x90 + 0x80, 0x90 + 0x90, 0x90 + 0xa0, plain_size - 1 }) |offset| {
        var damaged = original;
        damaged[offset] ^= 1;
        try std.testing.expectError(error.PgdAuthenticationFailed, content_key(&damaged));
    }
    // Wrapper fields outside the PGD are shape-checked and never alter the key.
    var altered = original;
    altered[0x50] ^= 1;
    altered[plain_size + 3] ^= 1;
    try std.testing.expectEqualSlices(u8, &fixture_key, &try content_key(&altered));
    for ([_]usize{ 0, 7, 8, 12, 15, 0x10, 0x34, 0x3f }) |offset| {
        var damaged = original;
        damaged[offset] ^= 0x40;
        try std.testing.expectError(error.InvalidPspEdat, content_key(&damaged));
    }
    try std.testing.expectError(error.InvalidPspEdat, content_key(original[0 .. plain_size - 1]));
    try std.testing.expectError(error.InvalidPspEdat, content_key(original[0 .. plain_size + 1]));
}
