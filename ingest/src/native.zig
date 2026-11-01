//! Pure-Zig replacements for the pspdecrypt code the ingest links. The crypto
//! lives in Zig-PSP (`zig_psp_decrypt`, `kirk`); `prx` and `psar` are the
//! PSPDB-specific wrappers. Compared with the C by `zig build native-diff`
//! until the cutover.
const decrypt = @import("zig_psp_decrypt");

pub const kirk = @import("kirk");
pub const amctrl = decrypt.amctrl;
pub const kle = decrypt.kle;
pub const pgd = decrypt.pgd;
pub const pops = decrypt.pops;
pub const npdrm = decrypt.npdrm;
pub const prx = @import("native/prx.zig");
pub const psar = @import("native/psar.zig");

test {
    _ = prx;
    _ = psar;
}
