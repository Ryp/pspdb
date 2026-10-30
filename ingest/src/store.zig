const std = @import("std");

/// Object layout: sha256/aa/bb/<full lowercase digest>.
///
/// Publication is batched. New objects are written unsynced to `.incoming/`;
/// a flush issues one `syncfs` for the whole batch and only then renames each
/// object into place without replacement. A name therefore only ever appears
/// once its bytes are durable, so readers trust a present object of the
/// recorded size instead of re-reading the whole store to rehash it. One
/// filesystem sync per batch replaces one fsync per object, which bounded an
/// HDD-backed btrfs store at a few hundred objects per second.
///
/// Objects larger than the cap are still hashed, cataloged and extracted;
/// only their bytes stay out of the store.
pub const Store = struct {
    allocator: std.mem.Allocator,
    root_path: []const u8,
    root: std.Io.Dir,
    max_object_bytes: u64,
    mutex: std.Io.Mutex = .init,
    flush_mutex: std.Io.Mutex = .init,
    pending: std.ArrayList(Pending) = .empty,
    pending_bytes: u64 = 0,
    /// Digests written but not yet published, including the batch being
    /// flushed: a concurrent writer of the same bytes reuses that object.
    inflight: std.AutoHashMapUnmanaged([64]u8, void) = .empty,
    counter: u64 = 0,

    pub const batch_objects = 4096;
    pub const batch_bytes = 1 << 30;

    const Pending = struct { digest: [64]u8, temp: [temp_len]u8 };
    const temp_len = ".incoming/".len + 64 + 1 + 16;

    pub fn init(allocator: std.mem.Allocator, io: std.Io, root_path: []const u8, max_object_bytes: u64) !Store {
        // A path-only handle (the default) is rejected by syncfs with EBADF.
        // `.incoming/` is created on the first new object, so runs that only
        // reuse or reject objects leave the store untouched.
        const root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
        return .{ .allocator = allocator, .root_path = root_path, .root = root, .max_object_bytes = max_object_bytes };
    }

    /// Unpublished objects are discarded: callers flush before success.
    pub fn deinit(self: *Store, io: std.Io) void {
        for (self.pending.items) |item| self.root.deleteFile(io, &item.temp) catch {};
        self.pending.deinit(self.allocator);
        self.inflight.deinit(self.allocator);
        self.root.close(io);
    }

    pub fn accepts(self: *const Store, size: u64) bool {
        return size <= self.max_object_bytes;
    }

    /// Returns true when these bytes become a new object, false when an
    /// identical published or in-flight object is reused.
    pub fn put(self: *Store, io: std.Io, digest: [64]u8, bytes: []const u8) !bool {
        if (try self.present_object(io, digest, bytes.len)) return false;
        var item: Pending = .{ .digest = digest, .temp = undefined };
        {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            const slot = try self.inflight.getOrPut(self.allocator, digest);
            if (slot.found_existing) return false;
            self.counter += 1;
            _ = std.fmt.bufPrint(&item.temp, ".incoming/{s}.{x:0>16}", .{ &digest, self.counter }) catch unreachable;
        }
        var queued = false;
        defer if (!queued) self.forget(io, digest);
        try self.write_temp(io, &item.temp, bytes);
        errdefer self.root.deleteFile(io, &item.temp) catch {};
        const full = blk: {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            try self.pending.append(self.allocator, item);
            self.pending_bytes += bytes.len;
            break :blk self.pending.items.len >= batch_objects or self.pending_bytes >= batch_bytes;
        };
        queued = true;
        if (full) try self.flush(io);
        return true;
    }

    /// Make every object written so far durable and visible. Flushes are
    /// serialized, so on return all earlier puts are published.
    pub fn flush(self: *Store, io: std.Io) !void {
        self.flush_mutex.lockUncancelable(io);
        defer self.flush_mutex.unlock(io);
        const batch = blk: {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            const items = self.pending;
            self.pending = .empty;
            self.pending_bytes = 0;
            break :blk items;
        };
        var items = batch;
        defer items.deinit(self.allocator);
        if (items.items.len == 0) return;
        var published: usize = 0;
        // Unpublished temporaries stay discoverable for deinit cleanup.
        errdefer {
            self.mutex.lockUncancelable(io);
            self.pending.appendSlice(self.allocator, items.items[published..]) catch {};
            self.mutex.unlock(io);
        }
        try std.posix.syncfs(self.root.handle);
        for (items.items) |item| {
            var path: [object_len]u8 = undefined;
            const destination = object_path(&path, item.digest);
            try self.root.createDirPath(io, destination[0 .. destination.len - 65]);
            self.root.renamePreserve(&item.temp, self.root, destination, io) catch |err| switch (err) {
                error.PathAlreadyExists => self.root.deleteFile(io, &item.temp) catch {},
                else => return err,
            };
            published += 1;
            self.forget(io, item.digest);
        }
    }

    fn forget(self: *Store, io: std.Io, digest: [64]u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        _ = self.inflight.remove(digest);
    }

    fn write_temp(self: *Store, io: std.Io, temp: []const u8, bytes: []const u8) !void {
        const file = self.create_temp(io, temp) catch |err| switch (err) {
            error.FileNotFound => blk: {
                try self.root.createDirPath(io, ".incoming");
                break :blk try self.create_temp(io, temp);
            },
            else => return err,
        };
        defer file.close(io);
        errdefer self.root.deleteFile(io, temp) catch {};
        try file.writeStreamingAll(io, bytes);
    }

    fn create_temp(self: *Store, io: std.Io, temp: []const u8) !std.Io.File {
        return self.root.createFile(io, temp, .{ .exclusive = true }) catch |err| switch (err) {
            // A temporary left by a crashed run is never published: replace it.
            error.PathAlreadyExists => {
                try self.root.deleteFile(io, temp);
                return self.root.createFile(io, temp, .{ .exclusive = true });
            },
            else => return err,
        };
    }

    fn present_object(self: *Store, io: std.Io, digest: [64]u8, size: u64) !bool {
        var path: [object_len]u8 = undefined;
        return present_at(io, self.root, object_path(&path, digest), size);
    }
};

const object_len = "sha256/aa/bb/".len + 64;

fn object_path(buffer: *[object_len]u8, digest: [64]u8) []const u8 {
    return std.fmt.bufPrint(buffer, "sha256/{s}/{s}/{s}", .{ digest[0..2], digest[2..4], &digest }) catch unreachable;
}

/// Presence and exact size only. Atomic publication makes the digest in the
/// path authoritative; a stored size that disagrees with the record is real
/// damage the run must not hide.
pub fn present(io: std.Io, path: []const u8, size: u64) !bool {
    return present_at(io, std.Io.Dir.cwd(), path, size);
}

fn present_at(io: std.Io, dir: std.Io.Dir, path: []const u8, size: u64) !bool {
    const file = dir.openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.size != size) return error.CorruptObject;
    return true;
}

test "objects become visible only after flush and are never duplicated" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    var store = try Store.init(allocator, io, root, std.math.maxInt(u64));
    defer store.deinit(io);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expect(try store.put(io, hex, "abc"));
    try std.testing.expect(!try store.put(io, hex, "abc"));
    try std.testing.expect(!try store.present_object(io, hex, 3));
    try store.flush(io);
    try std.testing.expect(try store.present_object(io, hex, 3));
    try std.testing.expect(!try store.put(io, hex, "abc"));
    var incoming = try tmp.dir.openDir(io, ".incoming", .{ .iterate = true });
    defer incoming.close(io);
    var entries = incoming.iterate();
    try std.testing.expectEqual(null, try entries.next(io));
}
