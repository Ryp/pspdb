const std = @import("std");

pub fn directory_path(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    const home = environ.get("HOME");
    if (environ.get("PSPDB_RAP_DIR")) |configured| {
        if (configured.len != 0) return expand_home(allocator, configured, home);
    }
    if (environ.get("XDG_DATA_HOME")) |configured| {
        if (configured.len != 0) {
            const data = try expand_home(allocator, configured, home);
            defer allocator.free(data);
            return std.Io.Dir.path.join(allocator, &.{ data, "pspdb", "licenses" });
        }
    }
    return std.Io.Dir.path.join(allocator, &.{ home orelse return error.MissingHomeDirectory, ".local", "share", "pspdb", "licenses" });
}

fn expand_home(allocator: std.mem.Allocator, path: []const u8, home: ?[]const u8) ![]u8 {
    if (std.mem.eql(u8, path, "~")) return allocator.dupe(u8, home orelse return error.MissingHomeDirectory);
    if (std.mem.startsWith(u8, path, "~/")) {
        return std.Io.Dir.path.join(allocator, &.{ home orelse return error.MissingHomeDirectory, path[2..] });
    }
    return allocator.dupe(u8, path);
}

/// Only the key boundary performs I/O. The decoder receives the resulting bytes.
pub fn read_rap(io: std.Io, directory_path_bytes: []const u8, content_id: []const u8) ![16]u8 {
    if (content_id.len != 36 or std.mem.indexOfAny(u8, content_id, "/\\\x00") != null) return error.InvalidEdatContentId;
    var directory = std.Io.Dir.cwd().openDir(io, directory_path_bytes, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return error.MissingEdatRap,
        else => return err,
    };
    defer directory.close(io);
    var filename: [40:0]u8 = undefined;
    @memcpy(filename[0..36], content_id);
    @memcpy(filename[36..40], ".rap");
    filename[40] = 0;
    // Do not block on a FIFO or follow a key symlink before inspecting its type.
    const descriptor = std.c.openat(directory.handle, &filename, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true });
    if (descriptor < 0) return switch (std.posix.errno(descriptor)) {
        .NOENT => error.MissingEdatRap,
        .LOOP, .NOTDIR, .INVAL => error.InvalidEdatRap,
        .NOMEM => error.OutOfMemory,
        else => |err| std.posix.unexpectedErrno(err),
    };
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = true } };
    defer file.close(io);
    const info = try file.stat(io);
    if (info.kind != .file or info.size != 16) return error.InvalidEdatRap;
    var bytes: [17]u8 = undefined;
    const count = try file.readPositionalAll(io, &bytes, 0);
    if (count != 16) return error.InvalidEdatRap;
    return bytes[0..16].*;
}
