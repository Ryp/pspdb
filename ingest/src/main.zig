const std = @import("std");
const ingest = @import("ingest.zig");

const Options = struct {
    folders: []const []const u8 = &.{},
    threads: usize = 1,
    store: ?[]const u8 = null,
    catalog: ?[]const u8 = null,
    skip_existing: bool = false,
    progress: bool = true,
    help: bool = false,
};

fn parse_args(allocator: std.mem.Allocator, args: []const []const u8, default_threads: usize) !Options {
    var options: Options = .{ .threads = default_threads };
    var folders: std.ArrayList([]const u8) = .empty;
    defer folders.deinit(allocator);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--skip-existing")) {
            options.skip_existing = true;
        } else if (std.mem.eql(u8, arg, "--no-progress")) {
            options.progress = false;
        } else if (std.mem.eql(u8, arg, "--help")) {
            options.help = true;
        } else if (std.mem.eql(u8, arg, "--catalog")) {
            i += 1;
            if (i == args.len) return error.MissingCatalogPath;
            options.catalog = args[i];
        } else if (std.mem.eql(u8, arg, "--store")) {
            i += 1;
            if (i == args.len) return error.MissingStorePath;
            options.store = args[i];
        } else if (std.mem.eql(u8, arg, "--threads")) {
            i += 1;
            if (i == args.len) return error.MissingThreadCount;
            options.threads = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidThreadCount;
            if (options.threads == 0) return error.InvalidThreadCount;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        } else {
            try folders.append(allocator, arg);
        }
    }
    if (!options.help) {
        if (folders.items.len == 0) return error.MissingFolder;
        if (options.skip_existing and options.catalog == null) return error.SkipExistingRequiresCatalog;
    }
    options.folders = try folders.toOwnedSlice(allocator);
    return options;
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const options = parse_args(init.arena.allocator(), args[1..], std.Thread.getCpuCount() catch 1) catch |err| {
        std.debug.print("pspdb-ingest: {s}\nUsage: pspdb-ingest FOLDER... [--catalog PATH] [--skip-existing] [--store PATH] [--threads N] [--no-progress]\n", .{@errorName(err)});
        return 2;
    };
    if (options.help) {
        std.debug.print("Usage: pspdb-ingest FOLDER... [--catalog PATH] [--skip-existing] [--store PATH] [--threads N] [--no-progress]\nHash .iso/.pkg/.zip contents across one or more folders using a shared worker pool and summary; failed folders do not stop the remaining inputs. ZIP ISO/PKG members decompressed in memory. ISOs require root UMD_DATA.BIN; retail PSP/PS1 PKGs retain original entry paths. --store writes file objects to the existing SHA-256 store layout.\n--catalog writes adjacent <hash>-ingest.json and <hash>-tree.json under <extractor>/v<version>/. --skip-existing skips current ISO/PKG results and checks nested extractor provenance (requires --catalog; off by default).\nPSAR/RCO/PRX/SCE/PBP/gzip files are processed automatically when --store and --catalog are set; external adapters run through uv.\n--threads caps all application threads (default: available logical CPUs).\n", .{});
        return 0;
    }

    // Only Progress may spawn an I/O task. Ingestion uses explicit threads.
    var threaded = std.Io.Threaded.init(init.gpa, .{
        .async_limit = .nothing,
        .concurrent_limit = if (options.threads > 1 and options.progress) .limited(1) else .nothing,
        .environ = init.minimal.environ,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const store = if (options.store) |path| blk: {
        try std.Io.Dir.cwd().createDirPath(io, path);
        break :blk try std.Io.Dir.cwd().realPathFileAlloc(io, path, init.arena.allocator());
    } else null;
    const catalog = if (options.catalog) |path| blk: {
        try std.Io.Dir.cwd().createDirPath(io, path);
        break :blk try std.Io.Dir.cwd().realPathFileAlloc(io, path, init.arena.allocator());
    } else null;
    const freshness = if (options.skip_existing) try @import("catalog_state.zig").load(init.gpa, io, catalog.?) else null;
    defer if (freshness) |state| state.deinit();
    const state = if (freshness) |*value| &value.value else null;
    const rap_directory = @import("licenses.zig").directory_path(init.arena.allocator(), init.environ_map) catch |err| switch (err) {
        error.MissingHomeDirectory => null,
        else => return err,
    };
    const extractor_adapter: ?@import("extractor.zig").Adapter = if (catalog != null) .{
        .store = store,
        .catalog = catalog.?,
        .state = state,
        .rap_directory = rap_directory,
    } else null;
    const live = options.progress and options.threads > 1 and (std.Io.File.stderr().isTty(io) catch false);
    const root = if (live) std.Progress.start(io, .{
        .root_name = "ISO ingestion",
        .initial_delay_ns = .fromMilliseconds(50),
    }) else std.Progress.Node.none;
    const worker_count = options.threads - @as(usize, if (live) 1 else 0);
    ingest.log(io, "Ingesting {d} folders (thread cap {d}, ingest workers {d}, progress task {d})\n", .{
        options.folders.len, options.threads, worker_count, @as(usize, if (live) 1 else 0),
    });
    const stats = ingest.run(init.gpa, io, options.folders, worker_count, options.threads, root, store, catalog, options.skip_existing, extractor_adapter, state) catch |err| {
        root.end();
        std.debug.print("pspdb-ingest: {s}\n", .{@errorName(err)});
        return 1;
    };
    root.end();
    std.debug.print("Summary: {d} directories scanned, {d} files ignored, {d} symlinks skipped, {d} input candidates, {d} accepted, {d} errors, {d} source input bytes.\n", .{
        stats.directories, stats.ignored, stats.symlinks, stats.candidates, stats.processed, stats.errors, stats.bytes,
    });
    std.debug.print("Already cataloged: {d} sources skipped.\n", .{stats.skipped});
    std.debug.print("ZIPs: {d} scanned, {d} ISO/PKG members, {d} other members ignored.\n", .{ stats.zip_archives, stats.zip_members, stats.ignored_members });
    return if (stats.errors != 0) 1 else 0;
}

test "CLI requires a folder and a positive thread cap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    _ = try parse_args(allocator, &.{"folder"}, 4);
    try std.testing.expectError(error.MissingFolder, parse_args(allocator, &.{}, 4));
    try std.testing.expectError(error.MissingStorePath, parse_args(allocator, &.{ "folder", "--store" }, 4));
    const stored = try parse_args(allocator, &.{ "folder", "--store", "objects" }, 4);
    try std.testing.expectEqualStrings("objects", stored.store.?);
    try std.testing.expectError(error.InvalidThreadCount, parse_args(allocator, &.{ "folder", "--threads", "0" }, 4));
    const options = try parse_args(allocator, &.{ "folder", "--threads", "1", "--no-progress" }, 4);
    try std.testing.expectEqual(@as(usize, 1), options.threads);
    try std.testing.expect(!options.progress);
}

test {
    _ = @import("processor.zig");
    _ = @import("zip.zig");
    _ = ingest;
    _ = @import("catalog.zig");
}
