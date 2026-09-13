const std = @import("std");

const containers = @import("containers.zig");
const memory = @import("bytes.zig");

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

/// Zig owns temporary output until its immediate files have been read into memory.
pub const Output = struct {
    path: []const u8,
    provenance: std.json.Parsed(Provenance),

    pub fn deinit(self: Output, allocator: std.mem.Allocator, io: std.Io) void {
        std.Io.Dir.cwd().deleteTree(io, self.path) catch {};
        allocator.free(self.path);
        self.provenance.deinit();
    }

    pub fn walk(self: Output, allocator: std.mem.Allocator, io: std.Io, context: anytype, comptime emit: anytype) !void {
        var work = try std.Io.Dir.cwd().openDir(io, self.path, .{});
        defer work.close(io);
        var directory = try work.openDir(io, "output", .{ .iterate = true });
        defer directory.close(io);
        var walker = try directory.walk(allocator);
        defer walker.deinit();
        var files: usize = 0;
        while (try walker.next(io)) |entry| {
            switch (entry.kind) {
                .directory => try emit(context, entry.path, null),
                .file => {
                    const bytes = try entry.dir.readFileAlloc(io, entry.basename, allocator, .unlimited);
                    const view = memory.Owner.allocated(allocator, bytes) catch |err| {
                        allocator.free(bytes);
                        return err;
                    };
                    defer view.release();
                    try emit(context, entry.path, view);
                    files += 1;
                },
                else => return error.UnsupportedExtractedEntry,
            }
        }
        if (files == 0) return error.EmptyExtraction;
    }
};

/// Python only extracts and reports tool provenance. No Python catalog/store work.
pub const Adapter = struct {
    store: ?[]const u8,
    catalog: []const u8,
    state: ?*const @import("catalog_state.zig").State = null,
    rap_directory: ?[]const u8 = null,

    pub fn extract(_: Adapter, allocator: std.mem.Allocator, io: std.Io, hash: [64]u8, input: []const u8, kind: Kind, docinfo: ?[]const u8) !Output {
        if (docinfo != null and kind != .document) return error.InvalidExtractionContext;
        var random: [16]u8 = undefined;
        try io.randomSecure(&random);
        const work_path = try std.fmt.allocPrint(allocator, "/tmp/pspdb-extract-{s}", .{std.fmt.bytesToHex(random, .lower)});
        errdefer allocator.free(work_path);
        try std.Io.Dir.cwd().createDir(io, work_path, .fromMode(0o700));
        errdefer std.Io.Dir.cwd().deleteTree(io, work_path) catch {};
        var work = try std.Io.Dir.cwd().openDir(io, work_path, .{});
        defer work.close(io);
        try work.writeFile(io, .{ .sub_path = "input", .data = input });
        if (docinfo) |bytes| {
            try work.writeFile(io, .{ .sub_path = "docinfo", .data = bytes });
        }
        try work.createDir(io, "output", .default_dir);

        const source = try std.Io.Dir.path.join(allocator, &.{ work_path, "input" });
        defer allocator.free(source);
        const output = try std.Io.Dir.path.join(allocator, &.{ work_path, "output" });
        defer allocator.free(output);
        const companion = try std.Io.Dir.path.join(allocator, &.{ work_path, "docinfo" });
        defer allocator.free(companion);
        const argv = [_][]const u8{
            "uv",           "run",  "--no-project", "--offline", "python",     "-c",                                  @embedFile("extractor_adapter"),
            @tagName(kind), source, "--output",     output,      "--versions", @embedFile("extractor_versions_json"), "--docinfo",
            companion,
        };
        const result = try std.process.run(allocator, io, .{ .argv = argv[0..if (docinfo != null) argv.len else argv.len - 2] });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        var buffer: [2048]u8 = undefined;
        const stderr = try io.lockStderr(&buffer, null);
        defer io.unlockStderr();
        try stderr.file_writer.interface.print("{s} {s}: {s}\n", .{ @tagName(kind), hash, result.stderr });
        try stderr.file_writer.interface.flush();
        switch (result.term) {
            .exited => |code| if (code != 0) return error.ExtractionFailed,
            else => return error.ExtractionFailed,
        }
        const provenance = try std.json.parseFromSlice(Provenance, allocator, result.stdout, .{ .allocate = .alloc_always });
        return .{ .path = work_path, .provenance = provenance };
    }
};

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
