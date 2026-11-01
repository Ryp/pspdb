//! Port of `pspdb_pops_decode` (pops_native.cpp).
const std = @import("std");
const amctrl = @import("amctrl.zig");
const prx = @import("prx_decrypter.zig");

const dnas_key1a90 = [16]u8{
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

fn le32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

/// `output` must not overlap either input.
pub fn decode(psp: []const u8, data_bin: []const u8, output: []u8) i32 {
    const int_max: usize = std.math.maxInt(i32);
    if (psp.len < 0x150 or psp.len > int_max or
        !std.mem.eql(u8, psp[0..4], "~PSP") or psp[0x7c] != 20 or
        le32(psp, 0xd0) != 0x0daa06f0)
    {
        return -10;
    }
    const declared: usize = le32(psp, 0x2c);
    const compressed: usize = le32(psp, 0xb0);
    const offset: usize = le32(psp, 0xb4);
    if (declared < 0x150 or declared > psp.len or output.len < declared or
        compressed == 0 or compressed > int_max or offset > declared - 0xd0 or
        ((compressed + 15) & ~@as(usize, 15)) > declared - 0xd0 - offset)
    {
        return -11;
    }

    var pgd_offset: usize = undefined;
    if (data_bin.len >= 12 and std.mem.eql(u8, data_bin[0..12], "PSISOIMG0000")) {
        pgd_offset = 0x400;
    } else if (data_bin.len >= 13 and std.mem.eql(u8, data_bin[0..13], "PSTITLEIMG000")) {
        // The C compares 13 bytes against a 14-byte literal's prefix.
        pgd_offset = 0x200;
    } else {
        return -12;
    }
    if (pgd_offset > data_bin.len or data_bin.len - pgd_offset < 0x90) return -13;
    var pgd: [0x90]u8 = data_bin[pgd_offset..][0..0x90].*;
    defer std.crypto.secureZero(u8, &pgd);
    if (!std.mem.eql(u8, pgd[0..4], "\x00PGD")) return -14;
    // Fixed-key profile only; fuse-bound profiles are rejected.
    if (le32(&pgd, 4) != 1 or le32(&pgd, 8) != 1) return -15;

    var seed: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    var mac: amctrl.MacKey = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    if (amctrl.macInit(&mac, 1) != 0 or amctrl.macUpdate(&mac, pgd[0..0x80]) != 0 or
        amctrl.macFinal2(&mac, pgd[0x80..][0..16], &dnas_key1a90) != 0)
    {
        return -16;
    }
    if (amctrl.macInit(&mac, 1) != 0 or amctrl.macUpdate(&mac, pgd[0..0x70]) != 0 or
        amctrl.getKey(&mac, pgd[0x70..][0..16], &seed) != 0)
    {
        return -17;
    }

    const result = prx.decryptPrx(psp, output, @intCast(declared), &seed);
    if (result < 0) return -18;
    if (@as(usize, @intCast(result)) != compressed) return -19;
    return result;
}
