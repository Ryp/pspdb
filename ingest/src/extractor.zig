const std = @import("std");

const containers = @import("containers.zig");

pub const Kind = enum { psar, rco, prx, sce, pbp, gzip, elf, kl3e, kl4e, edat, npumdimg, iso9660, pops, psx, vmp, document };

const document_prefix = "\x00PGD\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";

fn fixed_document_signature(bytes: []const u8) bool {
    return bytes.len >= 24 and
        (std.mem.eql(u8, bytes[16..24], "\x67\x68\xbd\x14\xca\x5d\x47\x4a") or
            std.mem.eql(u8, bytes[16..24], "\xdf\xf3\xca\xc7\x94\x95\x48\x29"));
}

/// Only an observed same-directory DOCINFO can resolve this candidate.
pub fn paired_document_candidate(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, document_prefix) and !fixed_document_signature(bytes);
}

pub fn detect(bytes: []const u8) ?Kind {
    if (std.mem.startsWith(u8, bytes, "NPD\x00")) return .edat;
    if (std.mem.startsWith(u8, bytes, "NPUMDIMG")) {
        // The big-endian version tag identifies metadata for an external payload.
        if (bytes.len >= 12 and std.mem.eql(u8, bytes[8..11], "\x00\x00\x00") and bytes[11] != 0) return null;
        return .npumdimg;
    }
    if (bytes.len >= 32775 and bytes[32768] == 1 and std.mem.eql(u8, bytes[32769..32774], "CD001") and bytes[32774] == 1) return .iso9660;
    if (std.mem.startsWith(u8, bytes, "PSAR")) return .psar;
    if (std.mem.startsWith(u8, bytes, "\x00PRF")) return .rco;
    if (std.mem.startsWith(u8, bytes, "~PSP") or std.mem.startsWith(u8, bytes, "PSPsysGP")) return .prx;
    if (std.mem.startsWith(u8, bytes, "~SCE")) return .sce;
    if (std.mem.startsWith(u8, bytes, "\x00PBP")) return .pbp;
    if (std.mem.startsWith(u8, bytes, "\x00PMV")) return .vmp;
    // Fixed-key DES ciphertext of the DOC magic/version block, not generic PGD.
    // Header/table/page integrity is checked by the bounded upstream reader.
    if (std.mem.startsWith(u8, bytes, document_prefix) and fixed_document_signature(bytes)) return .document;
    if (std.mem.startsWith(u8, bytes, "\x1f\x8b\x08")) return .gzip;
    if (std.mem.startsWith(u8, bytes, "KL3E")) return .kl3e;
    if (std.mem.startsWith(u8, bytes, "KL4E")) return .kl4e;
    if (containers.embedded_psp(bytes, 0) != null) return .elf;
    return null;
}

pub const Provenance = struct { name: []const u8, sha256: ?[]const u8 = null, version: ?[]const u8 = null, options: []const []const u8 = &.{} };

test "format detection uses signatures" {
    try std.testing.expectEqual(Kind.npumdimg, detect("NPUMDIMG").?);
    try std.testing.expectEqual(Kind.npumdimg, detect("NPUMDIMG\x02\x00\x00\x00").?);
    try std.testing.expectEqual(null, detect("NPUMDIMG\x00\x00\x00\x02"));
    try std.testing.expectEqual(null, detect("NPUMDIMG\x00\x00\x00\x03"));
    try std.testing.expectEqual(Kind.npumdimg, detect("NPUMDIMG\x03\x00\x00\x00").?);
    try std.testing.expectEqual(Kind.edat, detect("NPD\x00").?);
    try std.testing.expectEqual(null, detect("NPD"));
    try std.testing.expectEqual(null, detect("NPUMD"));
    try std.testing.expectEqual(Kind.psar, detect("PSAR\x03").?);
    try std.testing.expectEqual(Kind.rco, detect("\x00PRF").?);
    try std.testing.expectEqual(null, detect("not an archive"));
}

test "PSMF and raw MPEG files remain opaque" {
    try std.testing.expectEqual(null, detect("PSMF"));
    try std.testing.expectEqual(null, detect("PSMF0014\x00\x00\x10\x00\x00\x00\x01\xba"));
    try std.testing.expectEqual(null, detect("\x00\x00\x01\xba"));
    try std.testing.expectEqual(null, detect("\x00\x00\x01\xba\x44"));
    try std.testing.expectEqual(null, detect("\x00\x00\x01\xba\x21"));
}

test "legacy DOC signatures remain distinct from generic PGD" {
    const prefix = "\x00PGD\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";
    try std.testing.expectEqual(Kind.document, detect(prefix ++ "\x67\x68\xbd\x14\xca\x5d\x47\x4a").?);
    try std.testing.expectEqual(Kind.document, detect(prefix ++ "\xdf\xf3\xca\xc7\x94\x95\x48\x29").?);
    try std.testing.expectEqual(null, detect(prefix ++ "\x00\x00\x00\x00\x00\x00\x00\x00"));
    try std.testing.expectEqual(null, detect(prefix ++ "\x67\x68\xbd\x14\xca\x5d\x47"));
}
