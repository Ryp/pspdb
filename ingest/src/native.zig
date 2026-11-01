//! Pure-Zig ports of the pspdecrypt code the ingest links, compared with the C
//! entry points by `zig build native-diff` until the cutover.
pub const kirk = @import("native/kirk.zig");
pub const amctrl = @import("native/amctrl.zig");
pub const kle = @import("native/kle.zig");
pub const prx_decrypter = @import("native/prx_decrypter.zig");
pub const psar = @import("native/psar.zig");
pub const pgd = @import("native/pgd.zig");
pub const psx_pgd = @import("native/psx_pgd.zig");
pub const pops = @import("native/pops.zig");
pub const npdrm_key = @import("native/npdrm_key.zig");

test {
    _ = kirk;
    _ = amctrl;
    _ = kle;
    _ = prx_decrypter;
    _ = psar;
    _ = pgd;
    _ = psx_pgd;
    _ = pops;
    _ = npdrm_key;
}
