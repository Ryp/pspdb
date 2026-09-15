const std = @import("std");
const decoded_output = @import("decoded.zig");

const max_source_size = 64 << 10;

extern fn pspdb_pgd_decode(source: [*]const u8, source_size: usize, output: [*]u8, output_size: usize) c_int;

/// Authenticate and decrypt a fixed-key OPNSSMP PGD. The source is immutable;
/// the caller owns the exact-size plaintext returned only after every MAC passes.
pub fn decode(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    if (source.len < 0xb0 or source.len > max_source_size or !std.mem.startsWith(u8, source, "\x00PGD"))
        return error.InvalidPgd;
    const output = try allocator.alloc(u8, source.len);
    errdefer allocator.free(output);
    const result = pspdb_pgd_decode(source.ptr, source.len, output.ptr, output.len);
    if (result < 0) return switch (result) {
        -1 => error.UnsupportedPgd,
        -2 => error.PgdAuthenticationFailed,
        -3 => error.PgdDecryptionFailed,
        else => error.InvalidPgd,
    };
    const size: usize = @intCast(result);
    if (size > output.len) return error.InvalidPgd;
    return allocator.realloc(output, size);
}

pub fn extract(allocator: std.mem.Allocator, source: []const u8) !decoded_output.Output {
    const output = try decode(allocator, source);
    return .{ .bytes = output, .format = decoded_output.identify(output) };
}

const fixture_hex =
    "005047440100000001000000000000002c78afca7f67afc36b7c574f36e5dc98" ++
    "00000000000000000000000000000000d73f661e34713d0dcfe7515d018a5f3f" ++
    "bb1bc2e2b039f149bd260c9389011d85a43666504abc6d55a2493cd9a4f4c57c" ++
    "392e48898c7669d00889adb928be354f19d52266ae322d3a3bc8b33ffdf29e85" ++
    "a4a0ec58e1222369427ac4f4aa1d53f4d2ec47245a45ef760d476f870e89b6f" ++
    "11650f796745ea1593ea26847743e6068c2462691de991b111bb1438de32fad23" ++
    "3f935d7be2fcf21768bbbcb62f0aa3bd";

fn fixture() [fixture_hex.len / 2]u8 {
    var bytes: [fixture_hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, fixture_hex) catch unreachable;
    return bytes;
}

test "fixed-key PGD authenticates header table and every ciphertext block" {
    const allocator = std.testing.allocator;
    const original = fixture();
    const plain = try decode(allocator, &original);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("synthetic opnssmp payload", plain);

    for ([_]usize{ 0x20, 0x60, 0x80, 0x90, original.len - 1 }) |offset| {
        var damaged = original;
        damaged[offset] ^= 1;
        try std.testing.expectError(error.PgdAuthenticationFailed, decode(allocator, &damaged));
    }
    try std.testing.expectError(error.InvalidPgd, decode(allocator, original[0 .. original.len - 1]));
}

test "PGD rejects profiles outside fixed-key OPNSSMP" {
    var bytes = fixture();
    bytes[4] = 2;
    try std.testing.expectError(error.UnsupportedPgd, decode(std.testing.allocator, &bytes));
}
