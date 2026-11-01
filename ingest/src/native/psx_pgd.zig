//! Port of `pspdb_psx_pgd_decrypt` (src/psx/pgd_psx.c): empty-key PGD
//! decryption for PS1 Classic DATA.PSAR (PSXtract-2 decrypt_pgd, flag 2).

const std = @import("std");
const amctrl = @import("amctrl.zig");

const int_max: usize = std.math.maxInt(i32);

const invalid: i32 = -1;
const header_mac: i32 = -2;
const cipher_err: i32 = -3;
const bad_argument: i32 = -4;
const table_mac: i32 = -5;
const block_mac: i32 = -6;
const key_err: i32 = -7;

const dnas_key1a90 = [16]u8{
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

fn readLe32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn verifyMac(mac_type: i32, bytes: []const u8, expected: *const [16]u8, key: *const [16]u8) bool {
    if (bytes.len == 0 or bytes.len > int_max) return false;
    var mac: amctrl.MacKey = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    if (amctrl.macInit(&mac, mac_type) != 0) return false;
    if (amctrl.macUpdate(&mac, bytes) != 0) return false;
    if (amctrl.macFinal2(&mac, expected, key) != 0) return false;
    return true;
}

/// Returns data_size (> 0) with plaintext in output[0..aligned), or a negative code.
pub fn decrypt(source: []const u8, output: []u8) i32 {
    if (source.len < 0x90 or source.len > int_max) return bad_argument;

    var header: [0x90]u8 = source[0..0x90].*;
    var version_key: [16]u8 = undefined;
    var mac: amctrl.MacKey = .{};
    var cipher: amctrl.CipherKey = .{};
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(&mac));
        std.crypto.secureZero(u8, std.mem.asBytes(&cipher));
        std.crypto.secureZero(u8, &version_key);
        std.crypto.secureZero(u8, &header);
    }

    var mac_type: i32 = 2;
    var cipher_type: i32 = 2;
    if (readLe32(header[8..]) == 1) {
        mac_type = if (readLe32(header[4..]) > 1) 3 else 1;
        cipher_type = 1;
    }

    if (!verifyMac(mac_type, header[0..0x80], header[0x80..][0..16], &dnas_key1a90)) return header_mac;
    if (amctrl.macInit(&mac, mac_type) != 0 or amctrl.macUpdate(&mac, header[0..0x70]) != 0 or
        amctrl.getKey(&mac, header[0x70..][0..16], &version_key) != 0)
    {
        return key_err;
    }
    if (amctrl.cipherInit(&cipher, cipher_type, 2, header[0x10..][0..16], &version_key, 0) != 0 or
        amctrl.cipherUpdate(&cipher, header[0x30..][0..0x30]) != 0 or
        amctrl.cipherFinal(&cipher) != 0)
    {
        return cipher_err;
    }

    const data_size: u64 = readLe32(header[0x44..]);
    const block_size: u64 = readLe32(header[0x48..]);
    const data_offset: u64 = readLe32(header[0x4c..]);

    // PSXtract decrypts from 0x90 regardless of data_offset; reject others.
    if (data_size == 0 or block_size == 0 or (block_size & (block_size - 1)) != 0 or
        data_offset != 0x90)
    {
        return invalid;
    }
    const aligned_size = (data_size + 15) & ~@as(u64, 15);
    const block_count = (aligned_size + block_size - 1) / block_size;
    if (data_offset > source.len) return invalid;
    const remaining = source.len - data_offset;
    if (aligned_size > remaining or block_count > (remaining - aligned_size) / 16) return invalid;
    if (aligned_size > output.len) return bad_argument;
    const table_offset: usize = @intCast(data_offset + aligned_size);
    const aligned: usize = @intCast(aligned_size);
    const offset0: usize = @intCast(data_offset);
    const bsize: usize = @intCast(block_size);
    const count: usize = @intCast(block_count);

    if (!verifyMac(mac_type, source[table_offset..][0 .. count * 16], header[0x60..][0..16], &version_key)) {
        return table_mac;
    }
    var block: usize = 0;
    while (block < count) : (block += 1) {
        const offset = block * bsize;
        const size = @min(aligned - offset, bsize);
        if (!verifyMac(mac_type, source[offset0 + offset ..][0..size], source[table_offset + block * 16 ..][0..16], &version_key)) {
            return block_mac;
        }
    }

    const out = output[0..aligned];
    @memcpy(out, source[offset0..][0..aligned]);
    if (amctrl.cipherInit(&cipher, cipher_type, 2, header[0x30..][0..16], &version_key, 0) != 0 or
        amctrl.cipherUpdate(&cipher, out) != 0 or
        amctrl.cipherFinal(&cipher) != 0)
    {
        @memset(out, 0);
        return cipher_err;
    }
    return @intCast(data_size);
}
