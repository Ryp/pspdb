//! Port of libkirk/amctrl.c: BBMAC and BBCipher as used by PGD handling.
//!
//! The C keeps one thread-local `kirk_buf[0x814]`; every use fully rewrites
//! what it later reads, so a zeroed per-call stack buffer is equivalent.
//! `kirk_buf` is passed to KIRK as one 0x814-byte buffer for both in and out
//! (the C passes `size` as insize although the buffer holds `size + 0x14`).
//!
//! KIRK cmd 5/8 (fuse-id keyed) do not exist in `sceUtilsBufferCopyWithRange`
//! and return -1, so every type-2 path that reaches kirk5/kirk8 fails with
//! 0x80510312, exactly as in the C build.
//!
//! Not ported (unreachable from PSPDB): sceNpDrmGetFixedKey, pgd_open,
//! pgd_decrypt_block, pgd_close; BBCipher mode 1 (encrypt) because it needs
//! CMD14 (PRNG from time + uninitialised stack): cipherInit returns the
//! kirk14 failure code 0x80510315 for mode 1 after setting type/seed.

const std = @import("std");
const kirk = @import("kirk.zig");

const kirk_buf_len = 0x814;
const KbBuf = [kirk_buf_len]u8;

const loc_1CD4 = [16]u8{ 0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB };
const loc_1CE4 = [16]u8{ 0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45 };
const loc_1CF4 = [16]u8{ 0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E };

/// MAC_KEY. `kind` is the C `type` (2: fuse-id key, otherwise fixed key; 3: bbmac is encrypted again).
pub const MacKey = struct {
    kind: i32 = 0,
    key: [16]u8 = @splat(0),
    pad: [16]u8 = @splat(0),
    pad_size: i32 = 0,
};

/// CIPHER_KEY.
pub const CipherKey = struct {
    kind: u32 = 0,
    seed: u32 = 0,
    key: [16]u8 = @splat(0),
};

fn writeHeader(buf: *KbBuf, mode: u32, key_type: i32, size: usize) void {
    std.mem.writeInt(u32, buf[0..4], mode, .little);
    std.mem.writeInt(u32, buf[4..8], 0, .little);
    std.mem.writeInt(u32, buf[8..12], 0, .little);
    std.mem.writeInt(i32, buf[12..16], key_type, .little);
    std.mem.writeInt(i32, buf[16..20], @intCast(size), .little);
}

fn doKirk4(buf: *KbBuf, size: usize, key_type: i32) i32 {
    writeHeader(buf, 4, key_type, size);
    if (kirk.bufferCopyWithRange(buf, buf, kirk.KIRK_CMD_ENCRYPT_IV_0) != 0) return @bitCast(@as(u32, 0x80510311));
    return 0;
}

fn doKirk7(buf: *KbBuf, size: usize, key_type: i32) i32 {
    writeHeader(buf, 5, key_type, size);
    if (kirk.bufferCopyWithRange(buf, buf, kirk.KIRK_CMD_DECRYPT_IV_0) != 0) return @bitCast(@as(u32, 0x80510311));
    return 0;
}

fn kirk5(buf: *KbBuf, size: usize) i32 {
    writeHeader(buf, 4, 0x0100, size);
    if (kirk.bufferCopyWithRange(buf, buf, kirk.KIRK_CMD_ENCRYPT_IV_FUSE) != 0) return @bitCast(@as(u32, 0x80510312));
    return 0;
}

fn kirk8(buf: *KbBuf, size: usize) i32 {
    writeHeader(buf, 5, 0x0100, size);
    if (kirk.bufferCopyWithRange(buf, buf, kirk.KIRK_CMD_DECRYPT_IV_FUSE) != 0) return @bitCast(@as(u32, 0x80510312));
    return 0;
}

fn err(code: u32) i32 {
    return @bitCast(code);
}

/// sub_158: CBC-chain `size` bytes at buf+0x14 with `key` as running IV, then
/// store the last ciphertext block back into `key`.
fn sub158(buf: *KbBuf, size: usize, key: *[16]u8, key_type: i32) i32 {
    for (0..16) |i| buf[0x14 + i] ^= key[i];
    const retv = doKirk4(buf, size, key_type);
    if (retv != 0) return retv;
    key.* = buf[size + 4 ..][0..16].*;
    return 0;
}

/// sceDrmBBMacInit.
pub fn macInit(key: *MacKey, kind: i32) i32 {
    key.kind = kind;
    key.pad_size = 0;
    key.key = @splat(0);
    key.pad = @splat(0);
    return 0;
}

/// sceDrmBBMacUpdate. Mirrors the C exactly, including that a call which
/// leaves `size == 0` after splitting off the trailing pad (old pad of 16
/// bytes plus < 17 new bytes) drops the old pad without encrypting it.
pub fn macUpdate(key: *MacKey, data: []const u8) i32 {
    if (key.pad_size > 16) return err(0x80510302);
    if (key.pad_size < 0) return err(0x80510302); // C would index with a negative size

    const ps: usize = @intCast(key.pad_size);
    if (ps + data.len <= 16) {
        @memcpy(key.pad[ps..][0..data.len], data);
        key.pad_size += @intCast(data.len);
        return 0;
    }

    var kb: KbBuf = @splat(0);
    const kbuf = kb[0x14..];
    @memcpy(kbuf[0..ps], key.pad[0..ps]);

    var p = ps;
    var new_pad = (ps + data.len) & 0x0f;
    if (new_pad == 0) new_pad = 16;
    key.pad_size = @intCast(new_pad);

    var size = data.len - new_pad;
    @memcpy(key.pad[0..new_pad], data[size..][0..new_pad]);

    const key_type: i32 = if (key.kind == 2) 0x3A else 0x38;

    var off: usize = 0;
    while (size != 0) {
        const ksize: usize = if (size + p >= 0x0800) 0x0800 else size + p;
        @memcpy(kbuf[p..ksize], data[off..][0 .. ksize - p]);
        const retv = sub158(&kb, ksize, &key.key, key_type);
        if (retv != 0) return retv;
        size -= ksize - p;
        off += ksize - p;
        p = 0;
    }
    return 0;
}

/// Left shift by one bit with the Rb (0x87) reduction (CMAC subkey step).
fn shiftSubkey(tmp: *[16]u8) void {
    const t0: u8 = if (tmp[0] & 0x80 != 0) 0x87 else 0;
    for (0..15) |i| tmp[i] = (tmp[i] << 1) | (tmp[i + 1] >> 7);
    tmp[15] = (tmp[15] << 1) ^ t0;
}

/// sceDrmBBMacFinal: writes the 16-byte MAC to `out` only on success, then
/// resets `key`. `version_key` (may be null) is applied as the last step.
pub fn macFinal(key: *MacKey, out: *[16]u8, version_key: ?*const [16]u8) i32 {
    if (key.pad_size > 16 or key.pad_size < 0) return err(0x80510302);

    const code: i32 = if (key.kind == 2) 0x3A else 0x38;
    var kb: KbBuf = @splat(0);
    const kbuf = kb[0x14..];

    var retv = doKirk4(&kb, 16, code);
    if (retv != 0) return retv;
    var tmp: [16]u8 = kbuf[0..16].*;

    shiftSubkey(&tmp);

    const ps: usize = @intCast(key.pad_size);
    if (ps < 16) {
        shiftSubkey(&tmp);
        key.pad[ps] = 0x80;
        if (ps + 1 < 16) @memset(key.pad[ps + 1 ..], 0);
    }

    for (0..16) |i| key.pad[i] ^= tmp[i];

    kbuf[0..16].* = key.pad;
    var tmp1: [16]u8 = key.key;

    retv = sub158(&kb, 0x10, &tmp1, code);
    if (retv != 0) return retv;

    for (0..16) |i| tmp1[i] ^= loc_1CD4[i];

    if (key.kind == 2) {
        kbuf[0..16].* = tmp1;

        retv = kirk5(&kb, 0x10);
        if (retv != 0) return retv;

        retv = doKirk4(&kb, 0x10, code);
        if (retv != 0) return retv;

        tmp1 = kbuf[0..16].*;
    }

    if (version_key) |vkey| {
        for (0..16) |i| tmp1[i] ^= vkey[i];
        kbuf[0..16].* = tmp1;

        retv = doKirk4(&kb, 0x10, code);
        if (retv != 0) return retv;

        tmp1 = kbuf[0..16].*;
    }

    out.* = tmp1;

    key.key = @splat(0);
    key.pad = @splat(0);
    key.pad_size = 0;
    key.kind = 0;
    return 0;
}

/// sceDrmBBMacFinal2: `mac` is INPUT only (the expected bbmac, compared with
/// the computed one; type 3 first decrypts a copy with kirk7 key 0x63).
/// Returns 0x80510300 on mismatch. The C ignores the kirk7 return value.
pub fn macFinal2(key: *MacKey, mac: *const [16]u8, version_key: ?*const [16]u8) i32 {
    const kind = key.kind;
    var tmp: [16]u8 = undefined;
    const retv = macFinal(key, &tmp, version_key);
    if (retv != 0) return retv;

    var kb: KbBuf = @splat(0);
    if (kind == 3) {
        kb[0x14..][0..16].* = mac.*;
        _ = doKirk7(&kb, 0x10, 0x63);
    } else {
        kb[0..16].* = mac.*;
    }

    if (!std.mem.eql(u8, kb[0..16], &tmp)) return err(0x80510300);
    return 0;
}

/// bbmac_getkey: recovers the version key from `bbmac`; writes `version_key`
/// only on success. The C ignores both kirk7 return values.
pub fn getKey(key: *MacKey, bbmac: *const [16]u8, version_key: *[16]u8) i32 {
    const kind = key.kind;
    var tmp: [16]u8 = undefined;
    const retv = macFinal(key, &tmp, null);
    if (retv != 0) return retv;

    var kb: KbBuf = @splat(0);
    if (kind == 3) {
        kb[0x14..][0..16].* = bbmac.*;
        _ = doKirk7(&kb, 0x10, 0x63);
    } else {
        kb[0..16].* = bbmac.*;
    }

    const tmp1: [16]u8 = kb[0..16].*;
    kb[0x14..][0..16].* = tmp1;

    const code: i32 = if (kind == 2) 0x3A else 0x38;
    _ = doKirk7(&kb, 0x10, code);

    for (0..16) |i| version_key[i] = tmp[i] ^ kb[i];
    return 0;
}

// ------------------------------------------------------------------ BBCipher

/// sub_1F8: kirk7-decrypt `size` bytes at buf+0x14 into buf, XOR the first
/// block with `key`, then set `key` to the last input block.
fn sub1F8(buf: *KbBuf, size: usize, key: *[16]u8, key_type: i32) i32 {
    const tmp: [16]u8 = buf[size + 0x14 - 16 ..][0..16].*;

    const retv = doKirk7(buf, size, key_type);
    if (retv != 0) return retv;

    for (0..16) |i| buf[i] ^= key[i];

    key.* = tmp;
    return 0;
}

/// sub_428: CTR-like keystream (one kirk7 per chunk) XORed into `dbuf`.
fn sub428(kb: *KbBuf, dbuf: []u8, ckey: *CipherKey) i32 {
    const size = dbuf.len;
    var tmp1: [16]u8 = undefined;
    var tmp2: [16]u8 = undefined;

    kb[0x14..][0..16].* = ckey.key;
    for (0..16) |i| kb[0x14 + i] ^= loc_1CF4[i];

    const r1 = if (ckey.kind == 2) kirk8(kb, 16) else doKirk7(kb, 16, 0x39);
    if (r1 != 0) return r1;

    for (0..16) |i| kb[i] ^= loc_1CE4[i];

    tmp2 = kb[0..16].*;

    if (ckey.seed == 1) {
        tmp1 = @splat(0);
    } else {
        tmp1 = tmp2;
        std.mem.writeInt(u32, tmp1[12..16], ckey.seed -% 1, .little);
    }

    var i: usize = 0;
    while (i < size) : (i += 16) {
        @memcpy(kb[0x14 + i ..][0..12], tmp2[0..12]);
        std.mem.writeInt(u32, kb[0x14 + i + 12 ..][0..4], ckey.seed, .little);
        ckey.seed +%= 1;
    }

    const r2 = sub1F8(kb, size, &tmp1, 0x63);
    if (r2 != 0) return r2;

    for (dbuf, 0..) |*b, j| b.* ^= kb[j];
    return 0;
}

/// sceDrmBBCipherInit. `kind` 1: fixed key, 2: fuse id. `mode` 2 (decrypt)
/// derives key = header_key ^ version_key (version_key may be null) and
/// seed+1; any mode other than 1/2 only stores `kind`. Mode 1 is not
/// supported (see module comment).
pub fn cipherInit(key: *CipherKey, kind: i32, mode: i32, header_key: *[16]u8, version_key: ?*[16]u8, seed: u32) i32 {
    key.kind = @bitCast(kind);
    if (mode == 2) {
        key.seed = seed +% 1;
        key.key = header_key.*;
        if (version_key) |vk| {
            for (0..16) |i| key.key[i] ^= vk[i];
        }
        return 0;
    } else if (mode == 1) {
        key.seed = 1;
        return err(0x80510315);
    }
    return 0;
}

/// sceDrmBBCipherUpdate: decrypts/encrypts `data` in place in chunks of 0x800.
pub fn cipherUpdate(key: *CipherKey, data: []u8) i32 {
    var retv: i32 = 0;
    var p: usize = 0;
    var kb: KbBuf = @splat(0);
    while (data.len - p > 0) {
        const dsize = @min(data.len - p, 0x0800);
        retv = sub428(&kb, data[p..][0..dsize], key);
        if (retv != 0) break;
        p += dsize;
    }
    return retv;
}

/// sceDrmBBCipherFinal.
pub fn cipherFinal(key: *CipherKey) i32 {
    key.key = @splat(0);
    key.kind = 0;
    key.seed = 0;
    return 0;
}
