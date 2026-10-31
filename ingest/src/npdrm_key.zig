//! EDAT licence keys of PSN PSP/PS1 packages, derived from the package itself.
//!
//! USRDIR/CONTENT/EBOOT.PBP carries a protected header (an NPUMDIMG header or a
//! PS1 Classic PGD) whose own MAC yields the PSP "version key" V (libkirk
//! `bbmac_getkey`). The package's EDAT key, the klicensee X that
//! `rap2rif(RAP)` produces, is a fixed AES-128 relation of it:
//!
//!     X = AES-128-ECB-DECRYPT(key_357C[(kind - 1) * 16 ..][0..16], V)
//!
//! where key_357C is the public 0x30-byte table behind libkirk's
//! `sceNpDrmGetFixedKey` and kind is the NPUMDIMG version byte (2 or 3) or 1 for
//! a PGD. The RAP is the exact inverse of make_npdata's `rap_to_klicensee`.
//! A PGD header is checked against its DNAS-keyed MAC first; an NPUMDIMG header
//! has no independent authentication, so every consumer must treat the key as a
//! candidate that the EDAT's own MACs confirm. No licence file is involved. Key bytes never leave this module's return values: callers compare
//! or hash them, and zero them after use.
const std = @import("std");
const pkg = @import("pkg.zig");

const Aes128 = std.crypto.core.aes.Aes128;

extern fn pspdb_npdrm_version_key(psar: [*]const u8, size: usize, version_key: *[16]u8, kind: *u8) c_int;

pub const eboot_path = "USRDIR/CONTENT/EBOOT.PBP";

/// Longest PSAR prefix any supported header needs: PSISOIMG0000's PGD header
/// ends at 0x400 + 0x90; a PSTITLEIMG000000 PGD at 0x200 and NPUMDIMG at 0xd0.
const psar_prefix_size = 0x400 + 0x90;

/// Public libkirk table (amctrl.c `key_357C`), one AES-128 key per kind.
const key_357c = [48]u8{
    0x07, 0x3D, 0x9E, 0x9D, 0xA8, 0xFD, 0x3B, 0x2F, 0x63, 0x18, 0x93, 0x2E, 0xF8, 0x57, 0xA6, 0x64,
    0x37, 0x49, 0xB7, 0x01, 0xCA, 0xE2, 0xE0, 0xC5, 0x44, 0x2E, 0x06, 0xB6, 0x1E, 0xFF, 0x84, 0xF2,
    0x9D, 0x31, 0xB8, 0x5A, 0xC8, 0xFA, 0x16, 0x80, 0x73, 0x60, 0x18, 0x82, 0x18, 0x77, 0x91, 0x9D,
};

// make_npdata RAP constants (RAP_KEY, RAP_PBOX, RAP_E1, RAP_E2).
const rap_key = [16]u8{ 0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF };
const rap_pbox = [16]u8{ 0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09 };
const rap_e1 = [16]u8{ 0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5 };
const rap_e2 = [16]u8{ 0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74 };

/// The EDAT key (klicensee) a RAP stands for; the forward direction, as make_npdata.
pub fn rap_to_klicensee(rap: [16]u8) [16]u8 {
    var key: [16]u8 = undefined;
    Aes128.initDec(rap_key).decrypt(&key, &rap);
    for (0..5) |_| {
        for (0..16) |i| {
            const p = rap_pbox[i];
            key[p] ^= rap_e1[p];
        }
        var i: usize = 15;
        while (i >= 1) : (i -= 1) key[rap_pbox[i]] ^= key[rap_pbox[i - 1]];
        var borrow: u8 = 0;
        for (0..16) |j| {
            const p = rap_pbox[j];
            const value = key[p] -% borrow;
            if (borrow != 1 or value != 0xFF) borrow = @intFromBool(value < rap_e2[p]);
            key[p] = value -% rap_e2[p];
        }
    }
    return key;
}

/// Exact inverse of `rap_to_klicensee`: the RAP file contents for a klicensee.
pub fn klicensee_to_rap(klicensee: [16]u8) [16]u8 {
    var key = klicensee;
    for (0..5) |_| {
        var borrow: u8 = 0;
        for (0..16) |i| {
            const p = rap_pbox[i];
            const value = key[p] +% rap_e2[p];
            const next: u8 = if (borrow == 1 and value == 0xFF) 1 else @intFromBool(value < rap_e2[p]);
            key[p] = value +% borrow;
            borrow = next;
        }
        for (1..16) |i| key[rap_pbox[i]] ^= key[rap_pbox[i - 1]];
        for (0..16) |i| {
            const p = rap_pbox[i];
            key[p] ^= rap_e1[p];
        }
    }
    var rap: [16]u8 = undefined;
    Aes128.initEnc(rap_key).encrypt(&rap, &key);
    std.crypto.secureZero(u8, &key);
    return rap;
}

/// The key_357C step: kind 1 (PS1 PGD), 2 or 3 (NPUMDIMG version byte).
pub fn klicensee_from_version_key(kind: u8, version_key: [16]u8) error{UnsupportedNpdrmKind}![16]u8 {
    if (kind < 1 or kind > 3) return error.UnsupportedNpdrmKind;
    var klicensee: [16]u8 = undefined;
    Aes128.initDec(key_357c[(kind - 1) * 16 ..][0..16].*).decrypt(&klicensee, &version_key);
    return klicensee;
}

/// RAP file contents derived from PSAR header bytes (a prefix of
/// DATA.PSAR, at most `psar_prefix_size` long). `null` when the header is not
/// an NPDRM one at all.
pub fn rap_from_psar_header(psar: []const u8) !?[16]u8 {
    var version_key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &version_key);
    var kind: u8 = 0;
    switch (pspdb_npdrm_version_key(psar.ptr, psar.len, &version_key, &kind)) {
        0 => {},
        1, 2, 3 => return null, // Not NPDRM, truncated, or a header class without a klicensee.
        4 => return error.NpdrmHeaderAuthenticationFailed,
        else => return error.NpdrmKeyDerivationFailed,
    }
    var klicensee = try klicensee_from_version_key(kind, version_key);
    defer std.crypto.secureZero(u8, &klicensee);
    return klicensee_to_rap(klicensee);
}

/// The package's RAP, derived from its own EBOOT.PBP; `null` for a package
/// without an EBOOT or without an NPUMDIMG/PS1 PGD header in its DATA.PSAR. Only
/// the PBP header and the first bytes of DATA.PSAR are decrypted; the game
/// payload is left alone, so it is safe to call before the package walk.
pub fn derive_rap(allocator: std.mem.Allocator, package: pkg.Package) !?[16]u8 {
    const head = (try package.read_file_range(allocator, eboot_path, 0, 0x28)) orelse return null;
    defer allocator.free(head);
    if (head.len < 0x28 or !std.mem.eql(u8, head[0..4], "\x00PBP")) return null;
    const psar_offset = std.mem.readInt(u32, head[0x24..0x28], .little);
    const prefix = (try package.read_file_range(allocator, eboot_path, psar_offset, psar_prefix_size)) orelse return null;
    defer allocator.free(prefix);
    return rap_from_psar_header(prefix);
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

// Synthetic values only; the vectors come from the independent Python
// reference implementation of make_npdata's rap_to_klicensee.
const vector_rap = [16]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
const vector_klicensee = [16]u8{ 0xc6, 0x06, 0x27, 0xa6, 0x5e, 0x46, 0x6a, 0x92, 0x92, 0x6b, 0x83, 0xc2, 0xf7, 0xa5, 0x4e, 0xed };
const vector_version_key = [16]u8{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };

const FixtureCrypto = struct {
    extern fn get_rif_key(rap: *const [16]u8, rif: *[16]u8) void;
};

test "RAP to klicensee matches the reference and make_npdata's get_rif_key" {
    try testing.expectEqualSlices(u8, &vector_klicensee, &rap_to_klicensee(vector_rap));
    var prng = std.Random.DefaultPrng.init(0x5eed);
    for (0..64) |_| {
        var rap: [16]u8 = undefined;
        prng.random().bytes(&rap);
        var native: [16]u8 = undefined;
        FixtureCrypto.get_rif_key(&rap, &native);
        try testing.expectEqualSlices(u8, &native, &rap_to_klicensee(rap));
    }
}

test "klicensee to RAP inverts RAP to klicensee, including borrow chains" {
    try testing.expectEqualSlices(u8, &vector_rap, &klicensee_to_rap(vector_klicensee));
    var prng = std.Random.DefaultPrng.init(0x1234);
    for (0..512) |_| {
        var rap: [16]u8 = undefined;
        prng.random().bytes(&rap);
        try testing.expectEqualSlices(u8, &rap, &klicensee_to_rap(rap_to_klicensee(rap)));
    }
    // Saturated and zero bytes exercise the 0xFF borrow special case.
    for ([_]u8{ 0x00, 0xff, 0x67 }) |fill| {
        const rap: [16]u8 = @splat(fill);
        try testing.expectEqualSlices(u8, &rap, &klicensee_to_rap(rap_to_klicensee(rap)));
    }
}

test "key_357C step selects one AES key per kind" {
    const expected = [3][16]u8{
        .{ 0x9d, 0xd1, 0x76, 0xb1, 0x51, 0xab, 0x31, 0x9c, 0x1d, 0xfe, 0x7a, 0x5f, 0xba, 0x0b, 0x08, 0x7a },
        .{ 0x45, 0xb0, 0x18, 0xdb, 0x61, 0x71, 0xad, 0x1e, 0xe9, 0x1f, 0xe6, 0xdf, 0xcd, 0x63, 0x5d, 0xd5 },
        .{ 0xcf, 0x6b, 0x66, 0xf6, 0x6a, 0x27, 0x3b, 0xd9, 0x9c, 0xc1, 0xb1, 0x70, 0x33, 0x81, 0x73, 0x21 },
    };
    for (expected, 1..) |want, kind| {
        try testing.expectEqualSlices(u8, &want, &(try klicensee_from_version_key(@intCast(kind), vector_version_key)));
    }
    try testing.expectError(error.UnsupportedNpdrmKind, klicensee_from_version_key(0, vector_version_key));
    try testing.expectError(error.UnsupportedNpdrmKind, klicensee_from_version_key(4, vector_version_key));
}

const Libkirk = struct {
    const MacKey = extern struct { kind: c_int, key: [16]u8, pad: [16]u8, pad_size: c_int };
    extern fn kirk_init_prx() void;
    extern fn sceDrmBBMacInit(mkey: *MacKey, kind: c_int) c_int;
    extern fn sceDrmBBMacUpdate(mkey: *MacKey, buf: [*]u8, size: c_int) c_int;
    extern fn sceDrmBBMacFinal(mkey: *MacKey, buf: [*]u8, vkey: ?[*]u8) c_int;
    extern fn sceUtilsBufferCopyWithRange(out: [*]u8, out_size: c_int, in: [*]u8, in_size: c_int, cmd: c_int) c_int;

    /// Type-3 BBMAC as stored in an NPUMDIMG header: the MAC computed under the
    /// version key, KIRK-4 encrypted with key seed 0x63 (Final2 reverses this).
    fn npumdimg_bbmac(header: []u8, version_key: *[16]u8) [16]u8 {
        kirk_init_prx();
        var mac: MacKey = undefined;
        std.debug.assert(sceDrmBBMacInit(&mac, 3) == 0);
        std.debug.assert(sceDrmBBMacUpdate(&mac, header.ptr, @intCast(header.len)) == 0);
        var tag: [16]u8 = undefined;
        std.debug.assert(sceDrmBBMacFinal(&mac, &tag, version_key) == 0);
        var buffer: [0x14 + 16]u8 align(4) = undefined;
        for ([_]u32{ 4, 0, 0, 0x63, 16 }, 0..) |word, i| std.mem.writeInt(u32, buffer[i * 4 ..][0..4], word, .little);
        @memcpy(buffer[0x14..], &tag);
        std.debug.assert(sceUtilsBufferCopyWithRange(&buffer, buffer.len, &buffer, 16, 4) == 0);
        return buffer[0x14..][0..16].*;
    }
};

fn expect_derivation(psar: []const u8, kind: u8, version_key: [16]u8) !void {
    var recovered: [16]u8 = undefined;
    var recovered_kind: u8 = 0;
    try testing.expectEqual(@as(c_int, 0), pspdb_npdrm_version_key(psar.ptr, psar.len, &recovered, &recovered_kind));
    try testing.expectEqual(kind, recovered_kind);
    try testing.expectEqualSlices(u8, &version_key, &recovered);
    const rap = (try rap_from_psar_header(psar)).?;
    const klicensee = try klicensee_from_version_key(kind, version_key);
    try testing.expectEqualSlices(u8, &rap, &klicensee_to_rap(klicensee));
    try testing.expectEqualSlices(u8, &klicensee, &rap_to_klicensee(rap));
}

test "PS1 PGD header yields its authenticated version key and RAP" {
    const allocator = testing.allocator;
    const pgd = try @import("psx/pgd.zig").testing_support.build(allocator, "synthetic payload", .{ .version_key = vector_version_key });
    defer allocator.free(pgd);
    for ([_]struct { magic: []const u8, offset: usize }{
        .{ .magic = "PSISOIMG0000", .offset = 0x400 },
        .{ .magic = "PSTITLEIMG000000", .offset = 0x200 },
    }) |layout| {
        const psar = try allocator.alloc(u8, layout.offset + pgd.len);
        defer allocator.free(psar);
        @memset(psar, 0);
        @memcpy(psar[0..layout.magic.len], layout.magic);
        @memcpy(psar[layout.offset..], pgd);
        try expect_derivation(psar, 1, vector_version_key);

        // Any header byte covered by the DNAS MAC invalidates the key; a header
        // class this derivation does not know stays silent instead.
        for ([_]usize{ 0x10, 0x4c, 0x6f, 0x70, 0x7f, 0x80, 0x8f }) |index| {
            psar[layout.offset + index] ^= 1;
            try testing.expectError(error.NpdrmHeaderAuthenticationFailed, rap_from_psar_header(psar));
            psar[layout.offset + index] ^= 1;
        }
        try testing.expectEqual(@as(?[16]u8, null), try rap_from_psar_header(psar[0 .. layout.offset + 0x8f]));
        psar[layout.offset] = 'X';
        try testing.expectEqual(@as(?[16]u8, null), try rap_from_psar_header(psar));
    }
    try testing.expectEqual(@as(?[16]u8, null), try rap_from_psar_header("PSISOIMG0000"));
}

test "NPUMDIMG header yields its authenticated version key and RAP for both kinds" {
    for ([_]u8{ 2, 3 }) |kind| {
        var header: [0x100]u8 = @splat(0);
        @memcpy(header[0..8], "NPUMDIMG");
        header[8] = kind;
        for (header[0x10..0xc0], 0..) |*byte, i| byte.* = @truncate(i *% 7 +% kind);
        var version_key = vector_version_key;
        const bbmac = Libkirk.npumdimg_bbmac(header[0..0xc0], &version_key);
        @memcpy(header[0xc0..0xd0], &bbmac);
        try expect_derivation(&header, kind, version_key);
        const original = (try rap_from_psar_header(&header)).?;

        // NPUMDIMG has no independent authentication: every header or MAC byte
        // changes the recovered key (so a wrong key is caught by the EDAT MACs).
        for ([_]usize{ 0x0a, 0x10, 0x5f, 0xbf, 0xc0, 0xcf }) |index| {
            header[index] ^= 1;
            const changed = (try rap_from_psar_header(&header)).?;
            try testing.expect(!std.mem.eql(u8, &changed, &original));
            header[index] ^= 1;
        }
        try testing.expectEqual(@as(?[16]u8, null), try rap_from_psar_header(header[0..0xcf]));
        // Only versions 2 and 3 select a klicensee row.
        header[8] = 1;
        try testing.expectEqual(@as(?[16]u8, null), try rap_from_psar_header(&header));
    }
}
