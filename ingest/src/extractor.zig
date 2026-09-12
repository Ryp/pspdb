const std = @import("std");
const memory = @import("bytes.zig");

pub const Kind = enum { psar, rco, prx, sce, pbp, gzip, elf, kl3e, kl4e };

pub fn detect(bytes: []const u8) ?Kind {
    if (std.mem.startsWith(u8, bytes, "PSAR")) return .psar;
    if (std.mem.startsWith(u8, bytes, "\x00PRF")) return .rco;
    if (std.mem.startsWith(u8, bytes, "~PSP")) return .prx;
    if (std.mem.startsWith(u8, bytes, "~SCE")) return .sce;
    if (std.mem.startsWith(u8, bytes, "\x00PBP")) return .pbp;
    if (std.mem.startsWith(u8, bytes, "\x1f\x8b\x08")) return .gzip;
    if (std.mem.startsWith(u8, bytes, "KL3E")) return .kl3e;
    if (std.mem.startsWith(u8, bytes, "KL4E")) return .kl4e;
    if (@import("containers.zig").embeddedPsp(bytes, 0) != null) return .elf;
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
        var directory = try std.Io.Dir.cwd().openDir(io, self.path, .{ .iterate = true });
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
    store: []const u8,
    catalog: []const u8,

    pub fn extract(self: Adapter, allocator: std.mem.Allocator, io: std.Io, hash: [64]u8, kind: Kind) !Output {
        var random: [16]u8 = undefined;
        try io.randomSecure(&random);
        const output = try std.fmt.allocPrint(allocator, "/tmp/pspdb-extract-{s}", .{std.fmt.bytesToHex(random, .lower)});
        errdefer allocator.free(output);
        try std.Io.Dir.cwd().createDir(io, output, .default_dir);
        errdefer std.Io.Dir.cwd().deleteTree(io, output) catch {};
        const source = try std.fmt.allocPrint(allocator, "{s}/sha256/{s}/{s}/{s}", .{ self.store, hash[0..2], hash[2..4], hash });
        defer allocator.free(source);
        const result = try std.process.run(allocator, io, .{ .argv = &.{
            "uv",           "run",  "--no-project", "--offline", "python", "-c", @embedFile("extractor_adapter"),
            @tagName(kind), source, "--output",     output,
        } });
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
        return .{ .path = output, .provenance = provenance };
    }
};

test "format detection uses signatures" {
    try std.testing.expectEqual(Kind.psar, detect("PSAR\x03").?);
    try std.testing.expectEqual(Kind.rco, detect("\x00PRF").?);
    try std.testing.expectEqual(null, detect("not an archive"));
}
