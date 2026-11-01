// PSPDB's PRX decode policy (size, magic and code mapping consumed by prx.zig)
// around Zig-PSP's pspDecryptPRX port. Codes match the former C wrapper.
const std = @import("std");
const decryptPrx = @import("zig_psp_decrypt").prx.decryptPrx;

// sizeof(PSP_Header); also the minimum accepted input size.
const psp_header_size = 0x150;

fn readLe32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}

/// `pspdb_prx_decode`. `output` doubles as the reconstruction workspace and
/// must hold at least `input.len` bytes; it must not overlap `input`.
pub fn prxDecode(input: []const u8, output: []u8) i32 {
    if (input.len < psp_header_size or input.len > std.math.maxInt(i32) or
        output.len < input.len) return -1;
    if (!std.mem.eql(u8, input[0..4], "~PSP") and !std.mem.eql(u8, input[0..8], "PSPsysGP")) return -1;

    const expected = readLe32(input, 0xB0);
    if (expected == 0 or expected > input.len) return -2;

    // Known recipes fail terminally; KIRK checks CMAC or both type-6 ECDSA
    // signatures before releasing plaintext. No payload-only fallback.
    const result = decryptPrx(input, output, @intCast(input.len), null);
    // A matched PRX header followed by failed KIRK integrity is terminal.
    if (result == -4) return -5;
    if (result < 0) return -3;
    if (@as(u32, @intCast(result)) != expected) return -4;
    return result;
}
