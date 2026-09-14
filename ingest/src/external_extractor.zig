const std = @import("std");
const extractor = @import("extractor.zig");
const memory = @import("bytes.zig");

/// Zig owns temporary output until its immediate files have been read into memory.
pub const Output = struct {
    path: []const u8,
    provenance: std.json.Parsed(extractor.Provenance),

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
                    const view = try memory.Owner.take_allocated(allocator, bytes);
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
pub fn extract(allocator: std.mem.Allocator, io: std.Io, hash: [64]u8, input: []const u8, kind: extractor.Kind, docinfo: ?[]const u8) !Output {
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
    const provenance = try std.json.parseFromSlice(extractor.Provenance, allocator, result.stdout, .{ .allocate = .alloc_always });
    return .{ .path = work_path, .provenance = provenance };
}
