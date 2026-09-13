const std = @import("std");
const processor = @import("processor.zig");
const zip = @import("zip.zig");

pub const Stats = struct {
    directories: usize = 0,
    ignored: usize = 0,
    symlinks: usize = 0,
    candidates: usize = 0,
    processed: usize = 0,
    skipped: usize = 0,
    errors: usize = 0,
    bytes: u64 = 0,
    zip_archives: usize = 0,
    zip_members: usize = 0,
    ignored_members: usize = 0,
};

const SharedZip = struct {
    archive: zip.Archive,
    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize) = .init(1),

    fn retain(self: *SharedZip) void {
        _ = self.references.fetchAdd(1, .monotonic);
    }

    fn release(self: *SharedZip) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        self.archive.close();
        self.allocator.destroy(self);
    }
};

const Member = struct { source: *SharedZip, entry: std.zip.Iterator.Entry, name: []const u8 };
const Extraction = struct { group: *Group, task: processor.Task };
const JobKind = enum { directory, iso, zip, member, extraction };
const Job = struct {
    path: []const u8,
    kind: JobKind,
    member: ?Member = null,
    extraction: ?Extraction = null,

    fn isIntake(self: Job) bool {
        return self.kind == .iso or self.kind == .member;
    }

    fn deinit(self: Job, allocator: std.mem.Allocator) void {
        if (self.extraction) |extraction| {
            extraction.task.deinit(allocator);
        } else allocator.free(self.path);
        if (self.member) |member| member.source.release();
    }
};

/// Completion follows the ISO's work; memory ownership follows byte views.
/// pending/counts/failure are protected by the pool mutex. The intake alone
/// writes result, before surrendering its initial pending reference.
const Group = struct {
    pool: *Pool,
    path: []const u8,
    dispatch: ?processor.Dispatch,
    pending: usize = 1,
    counts: processor.Counts = .{},
    failure: ?anyerror = null,
    result: ?processor.Result = null,
    progress: std.Progress.Node,
};

// The queue owns paths until a worker takes them. `outstanding` includes both
// queued and active jobs: an empty queue is not completion while a scan runs.
const Pool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: ?[]const u8,
    catalog: ?[]const u8,
    skip_existing: bool,
    state: ?*const @import("catalog_state.zig").State = null,
    extractor_adapter: ?processor.extractor.Adapter,
    mutex: std.Io.Mutex = .init,
    changed: std.Io.Condition = .init,
    jobs: std.ArrayList(Job) = .empty,
    outstanding: usize = 0,
    directories_pending: usize = 0,
    intake_active: usize = 0,
    intake_limit: usize,
    intake_candidates: usize = 0,
    stats: Stats = .{},
    scan_progress: std.Progress.Node,
    iso_progress: std.Progress.Node,
    extraction_progress: std.Progress.Node,

    fn enqueue(self: *Pool, path: []const u8, kind: JobKind) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.jobs.append(self.allocator, .{ .path = path, .kind = kind });
        self.outstanding += 1;
        if (kind == .directory) self.directories_pending += 1 else self.stats.candidates += 1;
        if (kind == .iso) self.addIntakeCandidate();
        self.changed.signal(self.io);
    }

    fn addIntakeCandidate(self: *Pool) void {
        self.intake_candidates += 1;
        self.iso_progress.setEstimatedTotalItems(self.intake_candidates);
    }

    // Extraction is preferred, then discovery, then intake below the cap.
    // A gated input stays queued: no worker holds a slot while waiting for it.
    fn take(self: *Pool) ?Job {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.outstanding != 0) {
            if (self.takeReady()) |job| return job;
            self.changed.waitUncancelable(self.io, &self.mutex);
        }
        return null;
    }

    /// Called with the pool mutex held.
    fn takeReady(self: *Pool) ?Job {
        var selected: ?usize = null;
        var best: usize = 3;
        for (self.jobs.items, 0..) |job, i| {
            if (job.isIntake() and self.intake_active >= self.intake_limit) continue;
            const priority: usize = if (job.kind == .extraction) 0 else if (job.isIntake()) 2 else 1;
            if (priority <= best) {
                selected = i;
                best = priority;
            }
        }
        if (selected) |i| {
            const job = self.jobs.swapRemove(i);
            if (job.isIntake()) self.intake_active += 1;
            return job;
        }
        return null;
    }

    fn finish(self: *Pool, kind: JobKind) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.outstanding -= 1;
        if (kind == .iso or kind == .member) self.intake_active -= 1;
        if (kind == .directory) {
            self.directories_pending -= 1;
            if (self.directories_pending == 0) {
                self.scan_progress.end();
                self.scan_progress = .none;
            }
        }
        self.changed.broadcast(self.io);
    }

    fn fail(self: *Pool, path: []const u8, err: anyerror) void {
        self.mutex.lockUncancelable(self.io);
        self.stats.errors += 1;
        self.mutex.unlock(self.io);
        log(self.io, "Rejected {s}: {s}\n", .{ path, @errorName(err) });
    }

    fn scan(self: *Pool, path: []const u8) !void {
        var dir = try std.Io.Dir.cwd().openDir(self.io, path, .{ .iterate = true, .follow_symlinks = false });
        defer dir.close(self.io);
        var iterator = dir.iterate();
        while (try iterator.next(self.io)) |entry| {
            // Some filesystems do not supply a type in directory entries.
            const kind = if (entry.kind == .unknown) blk: {
                const stat = dir.statFile(self.io, entry.name, .{ .follow_symlinks = false }) catch |err| {
                    self.fail(entry.name, err);
                    continue;
                };
                break :blk stat.kind;
            } else entry.kind;
            if (kind == .directory or (kind == .file and (isIso(entry.name) or isPkg(entry.name) or isZip(entry.name)))) {
                const child = try std.Io.Dir.path.join(self.allocator, &.{ path, entry.name });
                self.enqueue(child, if (kind == .directory) .directory else if (isZip(entry.name)) .zip else .iso) catch |err| {
                    self.allocator.free(child);
                    return err;
                };
            } else {
                self.mutex.lockUncancelable(self.io);
                if (kind == .sym_link) self.stats.symlinks += 1 else self.stats.ignored += 1;
                self.mutex.unlock(self.io);
            }
        }
        self.mutex.lockUncancelable(self.io);
        self.stats.directories += 1;
        self.scan_progress.setCompletedItems(self.stats.directories);
        self.mutex.unlock(self.io);
    }

    fn createGroup(self: *Pool, path: []const u8) !*Group {
        const group = try self.allocator.create(Group);
        errdefer self.allocator.destroy(group);
        const name = try self.allocator.dupe(u8, path);
        group.* = .{
            .pool = self,
            .path = name,
            .dispatch = if (self.extractor_adapter) |adapter| .{
                .context = group,
                .enqueue = enqueueExtraction,
                .adapter = adapter,
                .visited = .init(self.allocator),
            } else null,
            .progress = self.extraction_progress.start(std.Io.Dir.path.basename(path), 0),
        };
        return group;
    }

    fn enqueueExtraction(context: *anyopaque, task: processor.Task) !void {
        const group: *Group = @ptrCast(@alignCast(context));
        const self = group.pool;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.jobs.append(self.allocator, .{
            .path = task.name,
            .kind = .extraction,
            .extraction = .{ .group = group, .task = task },
        });
        group.pending += 1;
        self.outstanding += 1;
        self.changed.signal(self.io);
    }

    fn complete(self: *Pool, group: *Group, counts: processor.Counts, failure: ?anyerror) void {
        self.mutex.lockUncancelable(self.io);
        group.counts.stored += counts.stored;
        group.counts.reused += counts.reused;
        if (group.failure == null) group.failure = failure;
        group.pending -= 1;
        const finished = group.pending == 0;
        self.mutex.unlock(self.io);
        if (!finished) return;
        defer {
            group.progress.end();
            if (group.dispatch) |*dispatch| dispatch.visited.deinit();
            if (group.result) |result| result.deinit(self.allocator);
            self.allocator.free(group.path);
            self.allocator.destroy(group);
        }
        if (group.failure) |err| {
            self.fail(group.path, err);
            return;
        }
        if (group.result) |*result| {
            result.stored += group.counts.stored;
            result.reused += group.counts.reused;
            if (self.catalog) |root| @import("catalog.zig").publish(self.allocator, self.io, root, result.*) catch |err| {
                self.fail(group.path, err);
                return;
            };
            self.mutex.lockUncancelable(self.io);
            self.stats.processed += 1;
            self.stats.bytes += result.size_bytes;
            self.mutex.unlock(self.io);
            self.printSummary(group.path, result.*);
        }
    }

    fn skipCache(self: *const Pool) ?@import("catalog.zig").Cache {
        if (!self.skip_existing) return null;
        return .{ .root = self.catalog.?, .state = self.state.? };
    }

    fn process(self: *Pool, job: Job) !void {
        const progress = self.iso_progress.start(std.Io.Dir.path.basename(job.path), 0);
        defer progress.end();
        const group = try self.createGroup(job.path);
        const dispatch = if (group.dispatch) |*value| value else null;
        group.result = (if (job.member) |member|
            self.processZipMember(member, dispatch)
        else
            processor.processFile(self.allocator, self.io, job.path, self.store, self.skipCache(), dispatch)) catch |err| {
            self.complete(group, .{}, err);
            return;
        };
        if (group.result == null) self.skip(job.path);
        self.complete(group, .{}, null);
    }

    fn processZip(self: *Pool, path: []const u8) !void {
        const source = try self.allocator.create(SharedZip);
        source.* = .{ .allocator = self.allocator, .archive = zip.Archive.open(self.io, path) catch |err| {
            self.allocator.destroy(source);
            return err;
        } };
        defer source.release();
        var iterator = try source.archive.iterator();
        var found: usize = 0;
        while (try iterator.next()) |entry| {
            const name = try source.archive.name(entry);
            if (!isIso(name) and !isPkg(name)) {
                self.mutex.lockUncancelable(self.io);
                self.stats.ignored_members += 1;
                self.mutex.unlock(self.io);
                continue;
            }
            const label = try std.fmt.allocPrint(self.allocator, "{s}!{s}", .{ path, name });
            errdefer self.allocator.free(label);
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            try self.jobs.append(self.allocator, .{
                .path = label,
                .kind = .member,
                .member = .{ .source = source, .entry = entry, .name = name },
            });
            source.retain();
            found += 1;
            self.stats.zip_members += 1;
            self.addIntakeCandidate();
            self.outstanding += 1;
            self.changed.signal(self.io);
        }
        self.mutex.lockUncancelable(self.io);
        self.stats.zip_archives += 1;
        self.mutex.unlock(self.io);
        if (found == 0) log(self.io, "Skipped ZIP {s}: no ISO/PKG members\n", .{path});
    }

    fn processZipMember(self: *Pool, member: Member, dispatch: ?*processor.Dispatch) !?processor.Result {
        const bytes = try member.source.archive.read(member.entry, member.name, self.allocator);
        const input = processor.memory.Owner.allocated(self.allocator, bytes) catch |err| {
            self.allocator.free(bytes);
            return err;
        };
        defer input.release();
        return if (isPkg(member.name)) processor.processPkgChecked(self.allocator, self.io, input.bytes, self.store, self.skipCache(), dispatch) else processor.processIsoChecked(self.allocator, self.io, input.bytes, self.store, self.skipCache(), dispatch);
    }

    fn extract(self: *Pool, extraction: Extraction) void {
        const task = extraction.task;
        const progress = extraction.group.progress.start(task.name, 0);
        const counts = processor.processTask(self.allocator, self.io, task, &extraction.group.dispatch.?) catch |err| {
            log(self.io, "Extraction {s} {s}: {s}\n", .{ @tagName(task.kind), task.name, @errorName(err) });
            progress.end();
            self.complete(extraction.group, .{}, err);
            return;
        };
        progress.end();
        self.complete(extraction.group, counts, null);
    }

    fn skip(self: *Pool, path: []const u8) void {
        self.mutex.lockUncancelable(self.io);
        self.stats.skipped += 1;
        self.mutex.unlock(self.io);
        log(self.io, "Skipped {s}: source already in catalog\n", .{path});
    }

    fn printSummary(self: *Pool, path: []const u8, result: processor.Result) void {
        if (result.kind == .pkg) {
            const line = std.json.Stringify.valueAlloc(self.allocator, .{
                .source = path,
                .kind = "pkg",
                .content_id = result.content_id,
                .pkg_bytes = result.size_bytes,
                .sha256 = &result.sha256,
                .sha1 = &result.sha1,
                .entry_count = result.entries.len,
                .stored_objects = result.stored,
                .reused_objects = result.reused,
            }, .{}) catch return;
            defer self.allocator.free(line);
            log(self.io, "{s}\n", .{line});
            return;
        }
        // JSON escapes control characters in labels and preserves unknown fields.
        const line = std.json.Stringify.valueAlloc(self.allocator, .{
            .source = path,
            .identifier = result.record.identifier,
            .uid = result.record.uid,
            .type_code = result.record.type_code,
            .media_code = result.record.media_code,
            .media = result.record.mediaDescription(),
            .extra = result.record.extra,
            .umd_data_bytes = result.umd_bytes.len,
            .iso_bytes = result.size_bytes,
            .sha256 = &result.sha256,
            .sha1 = &result.sha1,
            .entry_count = result.entries.len,
            .stored_objects = result.stored,
            .reused_objects = result.reused,
        }, .{}) catch |err| {
            self.fail(path, err);
            return;
        };
        defer self.allocator.free(line);
        log(self.io, "{s}\n", .{line});
    }

    fn worker(self: *Pool) void {
        while (self.take()) |job| {
            defer job.deinit(self.allocator);
            defer self.finish(job.kind);
            switch (job.kind) {
                .directory => self.scan(job.path) catch |err| self.fail(job.path, err),
                .iso, .member => self.process(job) catch |err| self.fail(job.path, err),
                .extraction => self.extract(job.extraction.?),
                .zip => self.processZip(job.path) catch |err| self.fail(job.path, err),
            }
        }
    }
};

pub fn log(io: std.Io, comptime format: []const u8, args: anytype) void {
    var buffer: [2048]u8 = undefined;
    const stderr = io.lockStderr(&buffer, null) catch return;
    defer io.unlockStderr();
    stderr.file_writer.interface.print(format, args) catch return;
    stderr.file_writer.interface.flush() catch {};
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, folders: []const []const u8, worker_count: usize, max_threads: usize, root: std.Progress.Node, store: ?[]const u8, catalog: ?[]const u8, skip_existing: bool, extractor_adapter: ?processor.extractor.Adapter, state: ?*const @import("catalog_state.zig").State) !Stats {
    std.debug.assert(worker_count >= 1);
    var pool: Pool = .{
        .allocator = allocator,
        .io = io,
        .store = store,
        .catalog = catalog,
        .skip_existing = skip_existing,
        .state = state,
        .extractor_adapter = extractor_adapter,
        .intake_limit = @max(1, max_threads / 4),
        .scan_progress = root.start("Scanning directories", 0),
        .iso_progress = root.start("ISO/PKG intake", 0),
        .extraction_progress = root.start("Pending ISO extractions", 0),
    };
    defer pool.scan_progress.end();
    defer pool.iso_progress.end();
    defer pool.extraction_progress.end();
    defer {
        for (pool.jobs.items) |job| job.deinit(allocator);
        pool.jobs.deinit(allocator);
    }
    for (folders) |folder| {
        const initial = try allocator.dupe(u8, folder);
        pool.enqueue(initial, .directory) catch |err| {
            allocator.free(initial);
            return err;
        };
    }
    // Main also does useful work. If a thread cannot be created, finish queued
    // work with those already running, then report the startup failure.
    var threads: std.ArrayList(std.Thread) = .empty;
    defer threads.deinit(allocator);
    try threads.ensureTotalCapacity(allocator, worker_count - 1);
    for (0..worker_count - 1) |_| {
        const thread = std.Thread.spawn(.{}, Pool.worker, .{&pool}) catch |err| {
            pool.fail("worker startup", err);
            break;
        };
        threads.appendAssumeCapacity(thread);
    }
    pool.worker();
    for (threads.items) |thread| thread.join();
    return pool.stats;
}

fn isIso(name: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(name, ".iso");
}

fn isZip(name: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(name, ".zip");
}

test "discovery uses only a case-insensitive ISO extension" {
    try std.testing.expect(isIso("game.iSo"));
    try std.testing.expect(!isIso("game.iso.part"));
    try std.testing.expect(!isIso("game.zip"));
}

test "intake gate leaves workers free for discovery and child extraction" {
    var pool = Pool{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .store = null,
        .catalog = null,
        .skip_existing = false,
        .extractor_adapter = null,
        .intake_limit = 2,
        .scan_progress = .none,
        .iso_progress = .none,
        .extraction_progress = .none,
    };
    defer pool.jobs.deinit(pool.allocator);
    try pool.jobs.append(pool.allocator, .{ .path = "one.iso", .kind = .iso });
    try pool.jobs.append(pool.allocator, .{ .path = "archive.zip!two.iso", .kind = .member });
    try pool.jobs.append(pool.allocator, .{ .path = "three.pkg", .kind = .iso });
    pool.outstanding = 3;
    const first = pool.takeReady().?;
    try std.testing.expect(first.isIntake());
    try std.testing.expect(pool.takeReady().?.isIntake());
    try std.testing.expectEqual(null, pool.takeReady());
    try pool.jobs.append(pool.allocator, .{ .path = "folder", .kind = .directory });
    try pool.jobs.append(pool.allocator, .{ .path = "module.psp", .kind = .extraction });
    try std.testing.expectEqual(JobKind.extraction, pool.takeReady().?.kind);
    try std.testing.expectEqual(JobKind.directory, pool.takeReady().?.kind);
    try std.testing.expectEqual(null, pool.takeReady());
    pool.finish(first.kind);
    try std.testing.expect(pool.takeReady().?.isIntake());
}

fn isPkg(name: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(name, ".pkg");
}
