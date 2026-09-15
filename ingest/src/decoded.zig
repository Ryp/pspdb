const std = @import("std");

pub const Format = enum {
    unknown,
    elf,
    gzip,
    kl3e,
    kl4e,
    iso,
    psp,

    pub fn extension(self: Format) []const u8 {
        return switch (self) {
            .unknown => "bin",
            .elf => "elf",
            .gzip => "gz",
            .kl3e => "kl3e",
            .kl4e => "kl4e",
            .iso => "iso",
            .psp => "psp",
        };
    }
};

pub const Output = struct {
    bytes: []u8,
    format: Format,
    content_format: ?Format = null,
};

pub fn isPspElf(bytes: []const u8) bool {
    return bytes.len >= 52 and
        std.mem.eql(u8, bytes[0..4], "\x7fELF") and
        bytes[4] == 1 and // ELFCLASS32
        bytes[5] == 1 and // ELFDATA2LSB
        bytes[6] == 1 and // EV_CURRENT
        std.mem.readInt(u16, bytes[18..20], .little) == 8 and // EM_MIPS
        std.mem.readInt(u32, bytes[20..24], .little) == 1 and
        std.mem.readInt(u16, bytes[40..42], .little) == 52;
}

/// Identify formats whose complete decoded stream has a validated signature.
pub fn identify(bytes: []const u8) Format {
    if (isPspElf(bytes)) return .elf;
    if (std.mem.startsWith(u8, bytes, "~PSP") or std.mem.startsWith(u8, bytes, "PSPsysGP")) return .psp;
    if (std.mem.startsWith(u8, bytes, "\x1f\x8b\x08")) return .gzip;
    if (std.mem.startsWith(u8, bytes, "KL3E")) return .kl3e;
    if (std.mem.startsWith(u8, bytes, "KL4E")) return .kl4e;
    return .unknown;
}

test "decoded ELF identification requires a PSP ELF header" {
    var elf: [52]u8 = @splat(0);
    @memcpy(elf[0..7], "\x7fELF\x01\x01\x01");
    std.mem.writeInt(u16, elf[16..18], 0xffa0, .little);
    std.mem.writeInt(u16, elf[18..20], 8, .little);
    std.mem.writeInt(u32, elf[20..24], 1, .little);
    std.mem.writeInt(u16, elf[40..42], 52, .little);
    try std.testing.expectEqual(Format.elf, identify(&elf));
    try std.testing.expectEqual(Format.unknown, identify("\x7fELFdata"));
    elf[18] = 0;
    try std.testing.expectEqual(Format.unknown, identify(&elf));
    try std.testing.expectEqual(Format.psp, identify("~PSPdata"));
    try std.testing.expectEqual(Format.psp, identify("PSPsysGPdata"));
    try std.testing.expectEqual(Format.gzip, identify("\x1f\x8b\x08data"));
    try std.testing.expectEqual(Format.kl3e, identify("KL3Edata"));
    try std.testing.expectEqual(Format.kl4e, identify("KL4Edata"));
    try std.testing.expectEqual(Format.unknown, identify("opaque"));
}
