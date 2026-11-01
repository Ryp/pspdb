//! Port of `pspdb_pgd_decode` (src/pgd_native.c): fixed-key OPNSSMP PGD profile.
//! No unauthenticated plaintext is produced: header, MAC table and every
//! ciphertext block are verified before decryption.

const std = @import("std");
const amctrl = @import("amctrl.zig");

const int_max: usize = std.math.maxInt(i32);

const dnas_key1a90 = [16]u8{
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

fn readLe32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn verifyMac(bytes: []const u8, expected: *const [16]u8, key: *const [16]u8) bool {
    if (bytes.len > int_max) return false;
    var mac: amctrl.MacKey = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    if (amctrl.macInit(&mac, 1) != 0) return false;
    if (amctrl.macUpdate(&mac, bytes) != 0) return false;
    if (amctrl.macFinal2(&mac, expected, key) != 0) return false;
    return true;
}

/// Returns data_size (> 0) on success, or a negative code (-1 invalid, -2 MAC,
/// -3 cipher/key, -4 bad argument/bounds).
pub fn decode(source: []const u8, output: []u8) i32 {
    if (source.len < 0xb0 or source.len > int_max or
        output.len < source.len or !std.mem.eql(u8, source[0..4], "\x00PGD"))
    {
        return -4;
    }
    if (readLe32(source[4..]) != 1 or readLe32(source[8..]) != 1) return -1;

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

    if (!verifyMac(header[0..0x80], header[0x80..][0..16], &dnas_key1a90)) return -2;
    if (amctrl.macInit(&mac, 1) != 0 or amctrl.macUpdate(&mac, header[0..0x70]) != 0 or
        amctrl.getKey(&mac, header[0x70..][0..16], &version_key) != 0)
    {
        return -3;
    }
    if (amctrl.cipherInit(&cipher, 1, 2, header[0x10..][0..16], &version_key, 0) != 0 or
        amctrl.cipherUpdate(&cipher, header[0x30..][0..0x30]) != 0 or
        amctrl.cipherFinal(&cipher) != 0)
    {
        return -3;
    }

    const data_size: usize = readLe32(header[0x44..]);
    const block_size: usize = readLe32(header[0x48..]);
    const data_offset: usize = readLe32(header[0x4c..]);
    if (data_size == 0 or block_size < 16 or block_size > (1 << 20) or
        (block_size & (block_size - 1)) != 0 or
        data_offset < header.len or (data_offset & 15) != 0)
    {
        return -4;
    }
    const aligned_size = (data_size + 15) & ~@as(usize, 15);
    if (aligned_size > output.len or data_offset > source.len or
        aligned_size > source.len - data_offset)
    {
        return -4;
    }
    const block_count = (aligned_size + block_size - 1) / block_size;
    const table_offset = data_offset + aligned_size;
    const table_size = block_count * 16;
    if (table_offset > source.len or table_size != source.len - table_offset) return -4;

    if (!verifyMac(source[table_offset..][0..table_size], header[0x60..][0..16], &version_key)) return -2;
    var block: usize = 0;
    while (block < block_count) : (block += 1) {
        const offset = block * block_size;
        const size = @min(aligned_size - offset, block_size);
        if (!verifyMac(source[data_offset + offset ..][0..size], source[table_offset + block * 16 ..][0..16], &version_key)) {
            return -2;
        }
    }

    const out = output[0..aligned_size];
    @memcpy(out, source[data_offset..][0..aligned_size]);
    if (amctrl.cipherInit(&cipher, 1, 2, header[0x30..][0..16], &version_key, 0) != 0 or
        amctrl.cipherUpdate(&cipher, out) != 0 or
        amctrl.cipherFinal(&cipher) != 0)
    {
        @memset(out, 0);
        return -3;
    }
    return @intCast(data_size);
}
