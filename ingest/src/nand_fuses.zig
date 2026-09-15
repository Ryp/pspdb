const std = @import("std");

pub fn directory_path(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    const home = environ.get("HOME");
    if (environ.get("PSPDB_NAND_FUSE_DIR")) |configured| {
        if (configured.len != 0) return expand_home(allocator, configured, home);
    }
    if (environ.get("XDG_DATA_HOME")) |configured| {
        if (configured.len != 0) {
            const data = try expand_home(allocator, configured, home);
            defer allocator.free(data);
            return std.Io.Dir.path.join(allocator, &.{ data, "pspdb", "nand-fuses" });
        }
    }
    return std.Io.Dir.path.join(allocator, &.{ home orelse return error.MissingHomeDirectory, ".local", "share", "pspdb", "nand-fuses" });
}

fn expand_home(allocator: std.mem.Allocator, path: []const u8, home: ?[]const u8) ![]u8 {
    if (std.mem.eql(u8, path, "~")) return allocator.dupe(u8, home orelse return error.MissingHomeDirectory);
    if (std.mem.startsWith(u8, path, "~/")) {
        return std.Io.Dir.path.join(allocator, &.{ home orelse return error.MissingHomeDirectory, path[2..] });
    }
    return allocator.dupe(u8, path);
}

/// Only this private key boundary performs I/O. Neither paths nor contents are
/// included in errors; the caller must clear the root-local returned value.
pub fn read_fuse(io: std.Io, directory_path_bytes: []const u8, digest: [64]u8) !?u64 {
    var filename: [69:0]u8 = undefined;
    for (digest, 0..) |byte, index| {
        if (!std.ascii.isHex(byte)) return error.InvalidNandFuseId;
        filename[index] = std.ascii.toLower(byte);
    }
    @memcpy(filename[64..69], ".fuse");
    filename[69] = 0;
    var directory = std.Io.Dir.cwd().openDir(io, directory_path_bytes, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.NotDir, error.SymLinkLoop => return error.InvalidNandFuseId,
        else => return err,
    };
    defer directory.close(io);
    // Reject symlinks and inspect special files without waiting on a FIFO.
    const descriptor = std.c.openat(directory.handle, &filename, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true });
    if (descriptor < 0) return switch (std.posix.errno(descriptor)) {
        .NOENT => null,
        .LOOP, .NOTDIR, .INVAL, .NXIO, .NODEV => error.InvalidNandFuseId,
        .NOMEM => error.OutOfMemory,
        else => |err| std.posix.unexpectedErrno(err),
    };
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = true } };
    defer file.close(io);
    const info = try file.stat(io);
    if (info.kind != .file or info.size < 16 or info.size > 18) return error.InvalidNandFuseId;
    var bytes: [19]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    const count = try file.readPositionalAll(io, &bytes, 0);
    return try parse(bytes[0..count]);
}

fn parse(bytes: []const u8) error{InvalidNandFuseId}!u64 {
    switch (bytes.len) {
        16 => {},
        17 => if (bytes[16] != '\n') return error.InvalidNandFuseId,
        18 => if (!std.mem.eql(u8, bytes[16..], "\r\n")) return error.InvalidNandFuseId,
        else => return error.InvalidNandFuseId,
    }
    var value: u64 = 0;
    for (bytes[0..16]) |byte| {
        const nibble: u64 = switch (byte) {
            '0'...'9' => byte - '0',
            'a'...'f' => byte - 'a' + 10,
            'A'...'F' => byte - 'A' + 10,
            else => return error.InvalidNandFuseId,
        };
        value = (value << 4) | nibble;
    }
    return value;
}

test "fuse directory precedence and home expansion" {
    const allocator = std.testing.allocator;
    const Case = struct { home: ?[]const u8, data: ?[]const u8 = null, override: ?[]const u8 = null, expected: ?[]const u8 };
    for ([_]Case{
        .{ .home = "/synthetic-home", .expected = "/synthetic-home/.local/share/pspdb/nand-fuses" },
        .{ .home = "/synthetic-home", .data = "~/data", .expected = "/synthetic-home/data/pspdb/nand-fuses" },
        .{ .home = "/synthetic-home", .data = "/unused", .override = "~", .expected = "/synthetic-home" },
        .{ .home = null, .data = "/data", .override = "", .expected = "/data/pspdb/nand-fuses" },
        .{ .home = null, .override = "/private-keys", .expected = "/private-keys" },
        .{ .home = null, .data = "", .expected = null },
        .{ .home = null, .override = "~/keys", .expected = null },
    }) |case| {
        var environ = std.process.Environ.Map.init(allocator);
        defer environ.deinit();
        if (case.home) |value| try environ.put("HOME", value);
        if (case.data) |value| try environ.put("XDG_DATA_HOME", value);
        if (case.override) |value| try environ.put("PSPDB_NAND_FUSE_DIR", value);
        if (case.expected) |expected| {
            const actual = try directory_path(allocator, &environ);
            defer allocator.free(actual);
            try std.testing.expectEqualStrings(expected, actual);
        } else {
            try std.testing.expectError(error.MissingHomeDirectory, directory_path(allocator, &environ));
        }
    }
}

test "fuse text accepts only exact hexadecimal with one optional line terminator" {
    for ([_][]const u8{ "0123456789abcdef", "0123456789ABCDEF\n", "0123456789aBcDeF\r\n" }) |text| {
        try std.testing.expectEqual(@as(u64, 0x0123456789abcdef), try parse(text));
    }
    try std.testing.expectEqual(@as(u64, 0), try parse("0000000000000000"));
    try std.testing.expectEqual(std.math.maxInt(u64), try parse("FFFFFFFFFFFFFFFF"));
    for ([_][]const u8{
        "",                       "0123456789abcde",     "0123456789abcdef0",  "0x0123456789abcd",     "0123456789abcdeg",
        " 123456789abcdef",       "0123456789abcde ",    "0123456789abcdef\r", "0123456789abcdef\n\n", "0123456789abcdef\nextra",
        "0123456789abcdef\r\n\n", "0123456789abcde\x00",
    }) |text| {
        try std.testing.expectError(error.InvalidNandFuseId, parse(text));
    }
}

test "fuse lookup distinguishes missing keys and rejects unsafe present files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(directory);
    const missing = try std.Io.Dir.path.join(allocator, &.{ directory, "missing" });
    defer allocator.free(missing);
    const digest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".*;
    const filename = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.fuse";
    try std.testing.expectEqual(@as(?u64, null), try read_fuse(io, missing, digest));
    try std.testing.expectEqual(@as(?u64, null), try read_fuse(io, directory, digest));
    try tmp.dir.writeFile(io, .{ .sub_path = filename, .data = "0123456789AbCdEf\r\n" });
    try std.testing.expectEqual(@as(?u64, 0x0123456789abcdef), try read_fuse(io, directory, digest));
    try tmp.dir.writeFile(io, .{ .sub_path = filename, .data = "0123456789abcdef\r\nextra" });
    try std.testing.expectError(error.InvalidNandFuseId, read_fuse(io, directory, digest));
    try tmp.dir.deleteFile(io, filename);
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = "0123456789abcdef" });
    try tmp.dir.symLink(io, "target", filename, .{});
    try std.testing.expectError(error.InvalidNandFuseId, read_fuse(io, directory, digest));
    try tmp.dir.deleteFile(io, filename);
    try tmp.dir.createDir(io, filename, .default_dir);
    try std.testing.expectError(error.InvalidNandFuseId, read_fuse(io, directory, digest));
    try tmp.dir.symLink(io, ".", "linked-directory", .{ .is_directory = true });
    const linked = try std.Io.Dir.path.join(allocator, &.{ directory, "linked-directory" });
    defer allocator.free(linked);
    try std.testing.expectError(error.InvalidNandFuseId, read_fuse(io, linked, digest));
}
