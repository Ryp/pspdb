const std = @import("std");

/// Read-only snapshot of provenance and dependency freshness at run startup.
pub const State = struct {
    fresh_trees: std.json.ArrayHashMap(bool),
    fresh_isos: std.json.ArrayHashMap(bool),
};

pub fn load(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !std.json.Parsed(State) {
    // Load the embedded helper as a module so the status command uses exactly
    // the same provenance definitions and revisions as this executable.
    const bootstrap =
        \\import sys, types
        \\adapter = types.ModuleType('extract_external')
        \\sys.modules[adapter.__name__] = adapter
        \\exec(sys.argv.pop(1), adapter.__dict__)
        \\exec(sys.argv.pop(1))
    ;
    const result = try std.process.run(allocator, io, .{ .argv = &.{
        "uv",
        "run",
        "--no-project",
        "--offline",
        "python",
        "-c",
        bootstrap,
        @embedFile("extractor_adapter"),
        @embedFile("catalog_status"),
        "--versions",
        @embedFile("extractor_versions_json"),
        "--catalog",
        root,
        "--json",
    } });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("{s}", .{result.stderr});
            return error.CatalogConflict;
        },
        else => return error.CatalogStatusFailed,
    }
    return std.json.parseFromSlice(State, allocator, result.stdout, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}
