//! Port of `pspdb_npdrm_version_key` (npdrm_key.c).
const std = @import("std");
const amctrl = @import("amctrl.zig");

const ok = 0;
const unrecognized = 1;
const short = 2;
const unsupported = 3;
const authentication = 4;
const kirk_failed = 5;

const dnas_key1a90 = [16]u8{
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5,
    0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
};

fn le32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

/// True when the MAC of `bytes` under `key` equals `expected`.
fn verifyMac(mac_type: i32, bytes: []const u8, expected: *const [16]u8, key: *const [16]u8) bool {
    var mac: amctrl.MacKey = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    return amctrl.macInit(&mac, mac_type) == 0 and
        amctrl.macUpdate(&mac, bytes) == 0 and
        amctrl.macFinal2(&mac, expected, key) == 0;
}

fn versionKeyOf(mac_type: i32, bytes: []const u8, bbmac: *const [16]u8, key: *[16]u8) bool {
    var mac: amctrl.MacKey = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    return amctrl.macInit(&mac, mac_type) == 0 and
        amctrl.macUpdate(&mac, bytes) == 0 and
        amctrl.getKey(&mac, bbmac, key) == 0;
}

pub fn versionKey(psar: []const u8, version_key: *[16]u8, kind: *u8) i32 {
    var header: [0xD0]u8 = undefined;
    var key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &header);
    defer std.crypto.secureZero(u8, &key);
    const size = psar.len;

    if (size >= 8 and std.mem.eql(u8, psar[0..8], "NPUMDIMG")) {
        if (size < 0xD0) return short;
        header = psar[0..0xD0].*;
        if (header[8] != 2 and header[8] != 3) return unsupported;
        if (!versionKeyOf(3, header[0..0xC0], header[0xC0..][0..16], &key)) return kirk_failed;
        if (!verifyMac(3, header[0..0xC0], header[0xC0..][0..16], &key)) return authentication;
        kind.* = header[8];
    } else {
        var offset: usize = undefined;
        if (size >= 12 and std.mem.eql(u8, psar[0..12], "PSISOIMG0000")) {
            offset = 0x400;
        } else if (size >= 16 and std.mem.eql(u8, psar[0..16], "PSTITLEIMG000000")) {
            offset = 0x200;
        } else {
            return unrecognized;
        }
        if (size < offset + 0x90) return short;
        header[0..0x90].* = psar[offset..][0..0x90].*;
        if (!std.mem.eql(u8, header[0..4], "\x00PGD")) return unrecognized;
        // drm_type 1 selects MAC 1 (3 when key_index > 1); MAC 2 is fuse-id bound.
        if (le32(&header, 8) != 1) return unsupported;
        const mac_type: i32 = if (le32(&header, 4) > 1) 3 else 1;
        if (!verifyMac(mac_type, header[0..0x80], header[0x80..][0..16], &dnas_key1a90)) return authentication;
        if (!versionKeyOf(mac_type, header[0..0x70], header[0x70..][0..16], &key)) return kirk_failed;
        kind.* = 1;
    }
    version_key.* = key;
    return ok;
}
