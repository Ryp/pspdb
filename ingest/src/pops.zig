const std = @import("std");
const decoded_output = @import("decoded.zig");

extern fn pspdb_pops_decode(psp: [*]const u8, psp_len: usize, data_bin: [*]const u8, data_bin_len: usize, output: [*]u8, output_len: usize) c_int;

/// Authenticate and decrypt DATA.PSP using its sibling DATA.BIN title context.
/// Inputs are borrowed, immutable and may be unaligned. The caller owns the
/// returned gzip stream or ELF module; recursive extraction expands it later.
pub fn decode(allocator: std.mem.Allocator, psp_bytes: []const u8, data_bin_bytes: []const u8) ![]u8 {
    if (psp_bytes.len < 0x150) return error.InvalidPops;
    if (psp_bytes.len > std.math.maxInt(c_int)) return error.InvalidPopsSize;
    const declared = std.mem.readInt(u32, psp_bytes[0x2c..0x30], .little);
    if (declared < 0x150 or declared > psp_bytes.len) return error.InvalidPopsSize;

    // The PRX decoder reconstructs KIRK headers in the complete declared envelope.
    const output = try allocator.alloc(u8, declared);
    errdefer allocator.free(output);
    const result = pspdb_pops_decode(psp_bytes.ptr, psp_bytes.len, data_bin_bytes.ptr, data_bin_bytes.len, output.ptr, output.len);
    switch (result) {
        -10 => return error.InvalidPops,
        -11 => return error.InvalidPopsSize,
        -12 => return error.InvalidPopsContext,
        -13, -14 => return error.InvalidPopsPgd,
        -15 => return error.UnsupportedPopsPgdProfile,
        -16 => return error.PopsPgdAuthenticationFailed,
        -17 => return error.PopsKeyRecoveryFailed,
        -18 => return error.PopsDecryptionFailed,
        else => if (result <= 0 or result > output.len) return error.PopsSizeMismatch,
    }
    const size: usize = @intCast(result);
    const payload = output[0..size];
    if (!std.mem.startsWith(u8, payload, "\x1f\x8b\x08") and !std.mem.startsWith(u8, payload, "\x7fELF")) {
        return error.UnexpectedPopsPayload;
    }
    return allocator.realloc(output, size);
}

pub fn extract(allocator: std.mem.Allocator, psp_bytes: []const u8, data_bin_bytes: []const u8) !decoded_output.Output {
    const output = try decode(allocator, psp_bytes, data_bin_bytes);
    return .{ .bytes = output, .format = decoded_output.identify(output) };
}
