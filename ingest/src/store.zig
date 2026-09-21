const std = @import("std");

/// Object layout: sha256/aa/bb/<full lowercase digest>.
/// Each worker owns its temporary file; publication never replaces an object.
/// Publication order is: fsync the payload, link it exclusively into place,
/// then fsync the containing directory. A name therefore only ever appears
/// once its bytes are durable, so readers trust a present object of the
/// recorded size instead of re-reading the whole store to rehash it.
pub const Writer = struct {
    atomic: std.Io.File.Atomic,
    io: std.Io,
    root: []const u8,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, root: []const u8, digest: [64]u8, size: u64) !?Writer {
        const destination = try std.Io.Dir.path.join(allocator, &.{ root, "sha256", digest[0..2], digest[2..4], &digest });
        defer allocator.free(destination);
        if (try present(io, destination, size)) return null;
        const path = try std.Io.Dir.path.join(allocator, &.{ root, ".incoming", "pending" });
        defer allocator.free(path);
        var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .make_path = true });
        // Atomic retains the destination string, which we replace at finish.
        atomic.dest_sub_path = "pending";
        return Writer{ .atomic = atomic, .io = io, .root = root };
    }

    pub fn deinit(self: *Writer) void {
        self.atomic.deinit(self.io);
    }

    pub fn write(self: *Writer, bytes: []const u8) !void {
        try self.atomic.file.writeStreamingAll(self.io, bytes);
    }

    pub fn finish(self: *Writer, allocator: std.mem.Allocator, digest: [64]u8, size: u64) !bool {
        const path = try std.Io.Dir.path.join(allocator, &.{ self.root, "sha256", digest[0..2], digest[2..4], &digest });
        defer allocator.free(path);
        try std.Io.Dir.cwd().createDirPath(self.io, std.Io.Dir.path.dirname(path).?);
        if (try present(self.io, path, size)) return false;
        try self.atomic.file.sync(self.io);
        self.atomic.dest_sub_path = path;
        self.atomic.link(self.io) catch |err| switch (err) {
            error.PathAlreadyExists => {
                if (!try present(self.io, path, size)) return error.ObjectDisappeared;
                return false;
            },
            else => return err,
        };
        // No directory fsync: losing the *name* after a crash only means the
        // object is absent and gets re-extracted, whereas losing *bytes* under a
        // live name would poison every later reuse. Only the latter needs a
        // barrier, and paying one fsync per object would defeat cheap reuse.
        return true;
    }
};

/// Presence and exact size only. Atomic publication makes the digest in the
/// path authoritative; a stored size that disagrees with the record is real
/// damage the run must not hide.
pub fn present(io: std.Io, path: []const u8, size: u64) !bool {
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.size != size) return error.CorruptObject;
    return true;
}

