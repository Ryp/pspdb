const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Object layout: sha256/aa/bb/<full lowercase digest>.
/// Each worker owns its temporary file; publication never replaces an object.
pub const Writer = struct {
    atomic: std.Io.File.Atomic,
    io: std.Io,
    root: []const u8,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, root: []const u8, digest: [64]u8, size: u64) !?Writer {
        const destination = try std.Io.Dir.path.join(allocator, &.{ root, "sha256", digest[0..2], digest[2..4], &digest });
        defer allocator.free(destination);
        if (try verify(io, destination, digest, size)) return null;
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
        if (try verify(self.io, path, digest, size)) return false;
        try self.atomic.file.sync(self.io);
        self.atomic.dest_sub_path = path;
        self.atomic.link(self.io) catch |err| switch (err) {
            error.PathAlreadyExists => {
                if (!try verify(self.io, path, digest, size)) return error.ObjectDisappeared;
                return false;
            },
            else => return err,
        };
        return true;
    }
};

fn verify(io: std.Io, path: []const u8, expected: [64]u8, size: u64) !bool {
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.size != size) return error.CorruptObject;
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        total += n;
        hash.update(buffer[0..n]);
    }
    if (total != size or !std.mem.eql(u8, &expected, &std.fmt.bytesToHex(hash.finalResult(), .lower))) return error.CorruptObject;
    return true;
}
