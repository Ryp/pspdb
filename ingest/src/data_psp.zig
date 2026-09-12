const std = @import("std");
const c = @cImport({
    @cInclude("openssl/ec.h");
    @cInclude("openssl/ecdsa.h");
    @cInclude("openssl/bn.h");
});

/// NPUMDIMG's DATA.PSP metadata, not the executable DATA.PSP used by other PBPs.
/// All slices borrow the input. PARAM.SFO is needed separately for verification.
pub const Header = struct {
    signature: *const [40]u8,
    content_id: []const u8,
    content_id_field: *const [48]u8,
    flags: u32,
    opnssmp: ?[]const u8,
    startdat: ?[]const u8,

    pub fn parse(bytes: []const u8) !Header {
        if (bytes.len < 0x594) return error.InvalidDataPsp;
        const id = bytes[0x560..0x590];
        const end = std.mem.indexOfScalar(u8, id, 0) orelse return error.InvalidDataPsp;
        if (end == 0) return error.InvalidDataPsp;
        for (id[0..end]) |ch| if (ch < 0x20 or ch > 0x7e) return error.InvalidDataPsp;
        for (id[end..]) |ch| if (ch != 0) return error.InvalidDataPsp;
        const offset = std.mem.readInt(u32, bytes[0x30..0x34], .little);
        const size = std.mem.readInt(u32, bytes[0x34..0x38], .little);
        if ((offset == 0) != (size == 0)) return error.InvalidDataPsp;
        if (size != 0 and (offset < 0x594 or offset > bytes.len or size > bytes.len - offset)) return error.InvalidDataPsp;
        const end_start: usize = if (size != 0) offset else bytes.len;
        const startdat = if (end_start >= 0x5a8 and std.mem.eql(u8, bytes[0x5a0..0x5a8], "STARTDAT")) bytes[0x5a0..end_start] else null;
        return .{ .signature = bytes[0..40], .content_id = id[0..end], .content_id_field = id, .flags = std.mem.readInt(u32, bytes[0x590..0x594], .big), .opnssmp = if (size != 0) bytes[offset..][0..size] else null, .startdat = startdat };
    }

    pub fn signedHash(self: Header, sfo: []const u8) [20]u8 {
        var sha = std.crypto.hash.Sha1.init(.{});
        sha.update(sfo);
        sha.update(self.content_id_field);
        return sha.finalResult();
    }

    pub fn verify(self: Header, sfo: []const u8) !bool {
        return verifyHash(self.signedHash(sfo), self.signature.*);
    }
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn number(comptime hex: []const u8) !*c.BIGNUM {
    const bytes = comptime hexBytes(hex);
    return c.BN_bin2bn(&bytes, bytes.len, null) orelse error.CryptoFailure;
}

/// KIRK command 0x11 curve (libkirk) and NPUMDIMG public key (sign_np).
/// Only public-key verification is implemented; OpenSSL owns EC arithmetic.
fn verifyHash(hash: [20]u8, signature: [40]u8) !bool {
    const ctx = c.BN_CTX_new() orelse return error.CryptoFailure;
    defer c.BN_CTX_free(ctx);
    const p = try number("ffffffffffffffff00000001ffffffffffffffff");
    defer c.BN_free(p);
    const a = try number("ffffffffffffffff00000001fffffffffffffffc");
    defer c.BN_free(a);
    const b = try number("a68bedc33418029c1d3ce33b9a321fccbb9e0f0b");
    defer c.BN_free(b);
    const n = try number("fffffffffffffffeffffb5ae3c523e63944f2127");
    defer c.BN_free(n);
    const gx = try number("128ec4256487fd8fdf64e2437bc0a1f6d5afde2c");
    defer c.BN_free(gx);
    const gy = try number("5958557eb1db001260425524dbc379d5ac5f4adf");
    defer c.BN_free(gy);
    const qx = try number("0121ea6ecdb23a3e2375671c5362e8e28b1e783b");
    defer c.BN_free(qx);
    const qy = try number("1a2732158b8ced98466c18a3ac3b1106afb4ec3b");
    defer c.BN_free(qy);
    const group = c.EC_GROUP_new_curve_GFp(p, a, b, ctx) orelse return error.CryptoFailure;
    defer c.EC_GROUP_free(group);
    const g = c.EC_POINT_new(group) orelse return error.CryptoFailure;
    defer c.EC_POINT_free(g);
    if (c.EC_POINT_set_affine_coordinates(group, g, gx, gy, ctx) != 1 or c.EC_GROUP_set_generator(group, g, n, null) != 1) return error.CryptoFailure;
    const q = c.EC_POINT_new(group) orelse return error.CryptoFailure;
    defer c.EC_POINT_free(q);
    if (c.EC_POINT_set_affine_coordinates(group, q, qx, qy, ctx) != 1) return error.CryptoFailure;
    const key = c.EC_KEY_new() orelse return error.CryptoFailure;
    defer c.EC_KEY_free(key);
    if (c.EC_KEY_set_group(key, group) != 1 or c.EC_KEY_set_public_key(key, q) != 1 or c.EC_KEY_check_key(key) != 1) return error.CryptoFailure;
    const sig = c.ECDSA_SIG_new() orelse return error.CryptoFailure;
    defer c.ECDSA_SIG_free(sig);
    const r = c.BN_bin2bn(signature[0..20], 20, null) orelse return error.CryptoFailure;
    const s = c.BN_bin2bn(signature[20..40], 20, null) orelse {
        c.BN_free(r);
        return error.CryptoFailure;
    };
    if (c.ECDSA_SIG_set0(sig, r, s) != 1) {
        c.BN_free(r);
        c.BN_free(s);
        return error.CryptoFailure;
    }
    const result = c.ECDSA_do_verify(&hash, hash.len, sig, key);
    return switch (result) {
        0 => false,
        1 => true,
        else => error.CryptoFailure,
    };
}

test "echochrome signature independently verified and tampering rejected" {
    const hash = hexBytes("d294c6860cc56de9b5b0e0b76a42ff50f9c78abc");
    const sig = hexBytes("cba716299384c15c0e7a2836c4f3364e54d396359c15412bfc34f9ad481af8383210aa36889cc087");
    try std.testing.expect(try verifyHash(hash, sig));
    var bad = hash;
    bad[0] ^= 1;
    try std.testing.expect(!try verifyHash(bad, sig));
    var bad_sig = sig;
    bad_sig[0] ^= 1;
    try std.testing.expect(!try verifyHash(hash, bad_sig));
    try std.testing.expect(!try verifyHash(hash, @splat(0)));
}

test "DATA.PSP bounds, endian, borrowed fields and optional sections" {
    var bytes: [0x5c0]u8 = @splat(0);
    @memcpy(bytes[0x560..][0..7], "TEST-ID");
    std.mem.writeInt(u32, bytes[0x590..0x594], 2, .big);
    var parsed = try Header.parse(&bytes);
    try std.testing.expectEqual(@as(u32, 2), parsed.flags);
    try std.testing.expectEqual(bytes[0x560..].ptr, parsed.content_id.ptr);
    try std.testing.expectEqual(null, parsed.opnssmp);
    for (0..0x594) |len| try std.testing.expectError(error.InvalidDataPsp, Header.parse(bytes[0..len]));
    std.mem.writeInt(u32, bytes[0x30..0x34], 0x5b0, .little);
    try std.testing.expectError(error.InvalidDataPsp, Header.parse(&bytes));
    std.mem.writeInt(u32, bytes[0x34..0x38], 16, .little);
    @memcpy(bytes[0x5a0..0x5a8], "STARTDAT");
    parsed = try Header.parse(&bytes);
    try std.testing.expectEqual(@as(usize, 16), parsed.opnssmp.?.len);
    try std.testing.expectEqual(@as(usize, 16), parsed.startdat.?.len);
    std.mem.writeInt(u32, bytes[0x34..0x38], 17, .little);
    try std.testing.expectError(error.InvalidDataPsp, Header.parse(&bytes));
}
