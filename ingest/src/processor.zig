const std = @import("std");
pub const memory = @import("bytes.zig");
const iso = @import("iso_reader.zig");
pub const extractor = @import("extractor.zig");
const StoreWriter = @import("store.zig").Writer;
pub const umd = @import("umd_data.zig");
const sfo = @import("sfo.zig");

/// Queue-owned extraction input. Native readers borrow subranges of input.
pub const Task = struct {
    name: []const u8,
    input: memory.View,
    hash: [64]u8,
    kind: extractor.Kind,

    pub fn deinit(self: Task, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.input.release();
    }
};

/// Shared by one ISO's jobs; only discovery deduplication needs this lock.
/// enqueue takes ownership of a task on success only.
pub const Dispatch = struct {
    context: *anyopaque,
    enqueue: *const fn (*anyopaque, Task) anyerror!void,
    adapter: extractor.Adapter,
    mutex: std.Io.Mutex = .init,
    visited: std.AutoHashMap([64]u8, void),

    fn inspect(self: *Dispatch, allocator: std.mem.Allocator, io: std.Io, name: []const u8, input: memory.View, hash: [64]u8) !void {
        const kind = extractor.detect(input.bytes) orelse return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const visited = try self.visited.getOrPut(hash);
        if (visited.found_existing) return;
        errdefer _ = self.visited.remove(hash);
        const task = Task{ .name = try allocator.dupe(u8, name), .input = input.retain(), .hash = hash, .kind = kind };
        errdefer task.deinit(allocator);
        try self.enqueue(self.context, task);
    }
};

pub const Counts = struct { stored: usize = 0, reused: usize = 0 };

pub const Entry = struct {
    path: []const u8,
    type: enum { directory, file },
    size_bytes: ?u64 = null,
    sha256: ?[64]u8 = null,

    pub fn jsonStringify(self: Entry, json: *std.json.Stringify) !void {
        try json.beginObject();
        try json.objectField("path");
        try json.write(self.path);
        try json.objectField("type");
        try json.write(self.type);
        if (self.type == .file) {
            try json.objectField("size_bytes");
            try json.write(self.size_bytes.?);
            try json.objectField("sha256");
            try json.write(@as([]const u8, &self.sha256.?));
        }
        try json.endObject();
    }
};

pub const Result = struct {
    size_bytes: u64,
    umd_bytes: []u8,
    record: umd.Record,
    game_sfo_bytes: []u8 = &.{},
    video_sfo_bytes: []u8 = &.{},
    updater_sfo_bytes: []u8 = &.{},
    metadata: sfo.Metadata = .{},
    entries: []Entry = &.{},
    sha256: [64]u8 = undefined,
    sha1: [40]u8 = undefined,
    stored: usize = 0,
    reused: usize = 0,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        allocator.free(self.umd_bytes);
        allocator.free(self.game_sfo_bytes);
        allocator.free(self.video_sfo_bytes);
        allocator.free(self.updater_sfo_bytes);
        for (self.entries) |entry| allocator.free(entry.path);
        allocator.free(self.entries);
    }
};

fn readMetadata(allocator: std.mem.Allocator, bytes: []const u8) !Result {
    if (bytes.len == 0) return error.EmptyFile;
    const umd_bytes = (try iso.readFile(allocator, bytes, "UMD_DATA.BIN")) orelse return error.MissingUmdData;
    var result: Result = .{ .size_bytes = bytes.len, .umd_bytes = umd_bytes, .record = undefined };
    errdefer result.deinit(allocator);
    result.record = try umd.parse(umd_bytes);
    result.game_sfo_bytes = (try iso.readFile(allocator, bytes, "PSP_GAME/PARAM.SFO")) orelse &.{};
    result.video_sfo_bytes = (try iso.readFile(allocator, bytes, "UMD_VIDEO/PARAM.SFO")) orelse &.{};
    const game = try sfo.parse(result.game_sfo_bytes);
    const video = try sfo.parse(result.video_sfo_bytes);
    // One disc-level metadata record: prefer the game SFO when both exist.
    result.metadata = if (result.game_sfo_bytes.len != 0) game else video;
    if (result.game_sfo_bytes.len == 0 and result.video_sfo_bytes.len == 0) {
        result.updater_sfo_bytes = (try iso.readFile(allocator, bytes, "PSP_GAME/SYSDIR/UPDATE/PARAM.SFO")) orelse &.{};
        // An updater-only disc takes its title here, but MSTKUPDATE is not its disc ID.
        const updater = try sfo.parse(result.updater_sfo_bytes);
        result.metadata.title = updater.title;
        result.metadata.disc_version = updater.disc_version;
    }
    return result;
}

/// Read and validate metadata first, then inventory, hash and store file contents.
/// Only libarchive's private descriptor view is patched; whole-ISO hashing uses
/// the unchanged input. The reader retains one file for the synchronous callback.
pub fn processIso(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8) !Result {
    return (try processIsoChecked(allocator, io, bytes, store, null, null)).?;
}

pub fn processIsoChecked(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8, catalog: ?@import("catalog.zig").Cache, dispatch: ?*Dispatch) !?Result {
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    var sha1 = std.crypto.hash.Sha1.init(.{});
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = offset + @min(bytes.len - offset, 64 * 1024);
        sha256.update(bytes[offset..end]);
        sha1.update(bytes[offset..end]);
        offset = end;
    }
    const iso_hash = std.fmt.bytesToHex(sha256.finalResult(), .lower);
    if (catalog) |root| {
        if (try @import("catalog.zig").contains(allocator, io, root, iso_hash, bytes.len)) return null;
    }
    var result = try readMetadata(allocator, bytes);
    errdefer result.deinit(allocator);
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .paths = .init(allocator) };
    defer inventory.deinit();
    try iso.walk(allocator, bytes, &inventory, Inventory.emitView);
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    result.entries = try inventory.finish();
    result.sha256 = iso_hash;
    result.sha1 = std.fmt.bytesToHex(sha1.finalResult(), .lower);
    return result;
}

/// Ingest owns names, inventory records, hashes and store writes. The reader
/// only lends paths and payloads for the duration of emit.
const Inventory = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: ?[]const u8,
    dispatch: ?*Dispatch,
    counts: Counts = .{},
    owner: ?*memory.Owner = null,
    entries: std.ArrayList(Entry) = .empty,
    paths: std.StringHashMap(usize),

    fn deinit(self: *Inventory) void {
        self.paths.deinit();
        for (self.entries.items) |entry| self.allocator.free(entry.path);
        self.entries.deinit(self.allocator);
    }

    // Native readers emit slices borrowed from the task's backing owner.
    fn emit(self: *Inventory, name: []const u8, contents: ?[]const u8) anyerror!void {
        try self.emitView(name, if (contents) |bytes| .{ .bytes = bytes, .owner = self.owner.? } else null);
    }

    fn emitView(self: *Inventory, name: []const u8, contents: ?memory.View) !void {
        try validatePath(name);
        if (self.paths.contains(name)) return error.DuplicateIsoPath;
        var entry = Entry{ .path = try self.allocator.dupe(u8, name), .type = if (contents != null) .file else .directory };
        errdefer self.allocator.free(entry.path);
        if (contents) |view| {
            const payload = view.bytes;
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
            entry.sha256 = std.fmt.bytesToHex(hash, .lower);
            entry.size_bytes = payload.len;
            if (self.store) |root| {
                if (try StoreWriter.init(self.allocator, self.io, root, entry.sha256.?, payload.len)) |new_writer| {
                    var writer = new_writer;
                    defer writer.deinit();
                    try writer.write(payload);
                    if (try writer.finish(self.allocator, entry.sha256.?, payload.len)) self.counts.stored += 1 else self.counts.reused += 1;
                } else self.counts.reused += 1;
            }
        }
        if (contents) |view| {
            if (self.dispatch) |dispatch| try dispatch.inspect(self.allocator, self.io, name, view, entry.sha256.?);
        }
        try self.paths.put(entry.path, self.entries.items.len);
        try self.entries.append(self.allocator, entry);
    }

    fn finish(self: *Inventory) ![]Entry {
        for (self.entries.items) |entry| {
            if (std.mem.lastIndexOfScalar(u8, entry.path, '/')) |slash| {
                const parent = self.paths.get(entry.path[0..slash]) orelse return error.MissingIsoDirectory;
                if (self.entries.items[parent].type != .directory) return error.InvalidIsoPath;
            }
        }
        std.mem.sort(Entry, self.entries.items, {}, struct {
            fn less(_: void, a: Entry, b: Entry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.less);
        return self.entries.toOwnedSlice(self.allocator);
    }
};

/// Process only this extraction's immediate tree. Descendants go to Dispatch.
pub fn processTask(allocator: std.mem.Allocator, io: std.Io, task: Task, dispatch: *Dispatch) !Counts {
    if (dispatch.adapter.state) |state| {
        if (state.fresh_trees.map.contains(&task.hash)) {
            if (try reuseTask(allocator, io, task, dispatch)) |counts| return counts;
        }
    }

    var inventory = Inventory{
        .allocator = allocator,
        .io = io,
        .store = dispatch.adapter.store,
        .dispatch = dispatch,
        .owner = task.input.owner,
        .paths = .init(allocator),
    };
    defer inventory.deinit();
    var output: ?extractor.Output = null;
    defer if (output) |value| value.deinit(allocator, io);
    const provenance: extractor.Provenance = switch (task.kind) {
        .sce => blk: {
            try @import("containers.zig").walkSce(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = @import("extractor_versions").sce };
        },
        .elf => blk: {
            try @import("containers.zig").walkElf(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = @import("extractor_versions").elf };
        },
        .pbp => blk: {
            try @import("containers.zig").walkPbp(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = @import("extractor_versions").pbp };
        },
        else => blk: {
            output = try dispatch.adapter.extract(allocator, io, task.hash, task.kind);
            try output.?.walk(allocator, io, &inventory, Inventory.emitView);
            break :blk output.?.provenance.value;
        },
    };
    const entries = try inventory.finish();
    defer {
        for (entries) |entry| allocator.free(entry.path);
        allocator.free(entries);
    }
    try @import("catalog.zig").publishExtraction(allocator, io, dispatch.adapter.catalog, task.hash, task.input.bytes.len, entries, provenance, @tagName(task.kind));
    return inventory.counts;
}

/// Reuse an unchanged immediate inventory, but still visit its derived children.
fn reuseTask(allocator: std.mem.Allocator, io: std.Io, task: Task, dispatch: *Dispatch) !?Counts {
    const revision = switch (task.kind) {
        inline else => |kind| @field(@import("extractor_versions"), @tagName(kind)),
    };
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-tree.json", .{ dispatch.adapter.catalog, @tagName(task.kind), revision, task.hash });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    const SavedEntry = struct { path: []const u8, type: []const u8, sha256: ?[]const u8 = null, size_bytes: ?u64 = null };
    const Saved = struct { sha256: []const u8, size_bytes: u64, entries: []SavedEntry };
    const parsed = try std.json.parseFromSlice(Saved, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.sha256, &task.hash) or parsed.value.size_bytes != task.input.bytes.len) return error.CatalogConflict;
    var counts: Counts = .{};
    for (parsed.value.entries) |entry| {
        try validatePath(entry.path);
        if (std.mem.eql(u8, entry.type, "directory")) continue;
        const hash = entry.sha256 orelse return error.CatalogConflict;
        if (hash.len != 64) return error.CatalogConflict;
        for (hash) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.CatalogConflict;
        const object_path = try std.fmt.allocPrint(allocator, "{s}/sha256/{s}/{s}/{s}", .{ dispatch.adapter.store, hash[0..2], hash[2..4], hash });
        defer allocator.free(object_path);
        const object = std.Io.Dir.cwd().openFile(io, object_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer object.close(io);
        const info = try object.stat(io);
        if (info.kind != .file or entry.size_bytes == null or info.size != entry.size_bytes.?) return error.CorruptObject;
        const payload = try allocator.alloc(u8, std.math.cast(usize, info.size) orelse return error.CorruptObject);
        const view = memory.Owner.allocated(allocator, payload) catch |err| {
            allocator.free(payload);
            return err;
        };
        defer view.release();
        if (try object.readPositionalAll(io, payload, 0) != payload.len) return error.CorruptObject;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
        const actual = std.fmt.bytesToHex(digest, .lower);
        if (entry.size_bytes == null or payload.len != entry.size_bytes.? or !std.mem.eql(u8, &actual, hash)) return error.CorruptObject;
        try dispatch.inspect(allocator, io, entry.path, view, actual);
        counts.reused += 1;
    }
    return counts;
}

fn validatePath(name: []const u8) !void {
    if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidIsoPath;
    for (name) |ch| if (ch < 32 or ch == '\\' or ch == ':') return error.InvalidIsoPath;
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidIsoPath;
}

/// Open and map one image read-only; optional outputs go only to the store.
/// V1 targets POSIX: direct mmap avoids an implicit whole-file heap fallback.
pub fn processFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, store: ?[]const u8, catalog: ?@import("catalog.zig").Cache, dispatch: ?*Dispatch) !?Result {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    if (stat.size == 0) return error.EmptyFile;
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooLarge;

    const mapping = try std.posix.mmap(null, size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, file.handle, 0);
    const input = memory.Owner.mapped(allocator, mapping) catch |err| {
        std.posix.munmap(mapping);
        return err;
    };
    defer input.release();
    const result = try processIsoChecked(allocator, io, mapping, store, catalog, dispatch);
    errdefer if (result) |value| value.deinit(allocator);
    const after = try file.stat(io);
    if (stat.size != after.size or stat.mtime.nanoseconds != after.mtime.nanoseconds or stat.ctime.nanoseconds != after.ctime.nanoseconds) return error.SourceChanged;
    return result;
}

test "processor rejects non-ISO bytes" {
    try std.testing.expectError(error.EmptyFile, processIso(std.testing.allocator, std.testing.io, "", null));
    try std.testing.expectError(error.InvalidIso, processIso(std.testing.allocator, std.testing.io, "not an ISO", null));
}

test "failed enqueue releases retained input and rolls back visited hash" {
    const allocator = std.testing.allocator;
    const Reject = struct {
        fn enqueue(_: *anyopaque, _: Task) !void {
            return error.TestQueueFailure;
        }
    };
    var context: u8 = 0;
    var dispatch = Dispatch{
        .context = &context,
        .enqueue = Reject.enqueue,
        .adapter = .{ .store = "unused", .catalog = "unused" },
        .visited = .init(allocator),
    };
    defer dispatch.visited.deinit();
    const input = try memory.Owner.allocated(allocator, try allocator.dupe(u8, "PSARinput"));
    defer input.release();
    try std.testing.expectError(error.TestQueueFailure, dispatch.inspect(allocator, std.testing.io, "test.psar", input, @splat('a')));
    try std.testing.expectEqual(@as(usize, 1), input.owner.references.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), dispatch.visited.count());
}

test "native descendants retain slices and never read their source from the store" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const Queue = struct {
        task: ?Task = null,
        fn enqueue(context: *anyopaque, task: Task) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.task != null) return error.UnexpectedTask;
            self.task = task;
        }
    };
    var queue = Queue{};
    defer if (queue.task) |task| task.deinit(allocator);
    var dispatch = Dispatch{
        .context = &queue,
        .enqueue = Queue.enqueue,
        .adapter = .{ .store = root, .catalog = root },
        .visited = .init(allocator),
    };
    defer dispatch.visited.deinit();
    // Two native SCE wrappers: the second borrows a subrange of the first.
    const payload = "~SCE\x08\x00\x00\x00~SCE\x08\x00\x00\x00plain";
    const input = try memory.Owner.allocated(allocator, try allocator.dupe(u8, payload));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    {
        defer input.release();
        const counts = try processTask(allocator, io, .{ .name = "outer.sce", .input = input, .hash = hash, .kind = .sce }, &dispatch);
        try std.testing.expectEqual(@as(usize, 1), counts.stored);
        try std.testing.expectEqual(input.owner, queue.task.?.input.owner);
        try std.testing.expectEqual(input.bytes.ptr + 8, queue.task.?.input.bytes.ptr);
    }
    // Remove the child's stored source; it must still decode from retained RAM.
    const child = queue.task.?;
    queue.task = null;
    defer child.deinit(allocator);
    const source = try std.fmt.allocPrint(allocator, "sha256/{s}/{s}/{s}", .{ child.hash[0..2], child.hash[2..4], child.hash });
    defer allocator.free(source);
    try tmp.dir.deleteFile(io, source);
    const counts = try processTask(allocator, io, child, &dispatch);
    try std.testing.expectEqual(@as(usize, 1), counts.stored);
    try std.testing.expectEqual(null, queue.task);
}

test {
    _ = umd;
    _ = sfo;
    _ = @import("iso_view.zig");
}
