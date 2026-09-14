const std = @import("std");

/// ZIP metadata and compressed data stay mapped; only the selected ISO is
/// allocated. Names borrow the mapping and read() returns an owned buffer.
pub const Archive = struct {
    io: std.Io,
    file: std.Io.File,
    mapping: []align(std.heap.page_size_min) u8,
    reader: std.Io.File.Reader,

    pub fn open(io: std.Io, path: []const u8) !Archive {
        const file = try std.Io.Dir.cwd().openFile(io, path, .{
            .mode = .read_only,
            .follow_symlinks = false,
        });
        errdefer file.close(io);
        const stat = try file.stat(io);
        if (stat.kind != .file) return error.NotRegularFile;
        if (stat.size == 0) return error.EmptyFile;
        const size = std.math.cast(usize, stat.size) orelse return error.FileTooLarge;
        const mapping = try std.posix.mmap(null, size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, file.handle, 0);
        return .{ .io = io, .file = file, .mapping = mapping, .reader = file.reader(io, &.{}) };
    }

    pub fn close(self: *Archive) void {
        std.posix.munmap(self.mapping);
        self.file.close(self.io);
        self.* = undefined;
    }

    pub fn iterator(self: *Archive) !std.zip.Iterator {
        const result = try std.zip.Iterator.init(&self.reader);
        _ = try self.range(result.cd_zip_offset, result.cd_size);
        return result;
    }

    fn range(self: *const Archive, offset: u64, length: u64) ![]const u8 {
        if (offset > self.mapping.len or length > self.mapping.len - offset)
            return error.ZipTruncated;
        return self.mapping[@intCast(offset)..@intCast(offset + length)];
    }

    pub fn name(self: *Archive, entry: std.zip.Iterator.Entry) ![]const u8 {
        const offset = try std.math.add(u64, entry.header_zip_offset, @sizeOf(std.zip.CentralDirectoryFileHeader));
        return self.range(offset, entry.filename_len);
    }

    pub fn read(self: *Archive, entry: std.zip.Iterator.Entry, filename: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const central = try self.range(entry.header_zip_offset, @sizeOf(std.zip.CentralDirectoryFileHeader));
        const attributes = std.mem.readInt(u32, central[38..42], .little);
        const unix_kind = (attributes >> 16) & 0xf000;
        if ((unix_kind != 0 and unix_kind != 0x8000) or attributes & 0x10 != 0)
            return error.ZipNotRegularFile;

        const local = try self.range(entry.file_offset, @sizeOf(std.zip.LocalFileHeader));
        if (!std.mem.eql(u8, local[0..4], &std.zip.local_file_header_sig)) return error.ZipBadFileOffset;
        const flags = std.mem.readInt(u16, local[6..8], .little);
        if (flags & 1 != 0) return error.ZipEncryptionUnsupported;
        if (flags != @as(u16, @bitCast(entry.flags))) return error.ZipMismatchFlags;
        if (std.mem.readInt(u16, local[8..10], .little) != @intFromEnum(entry.compression_method))
            return error.ZipMismatchCompressionMethod;
        const filename_len = std.mem.readInt(u16, local[26..28], .little);
        const extra_len = std.mem.readInt(u16, local[28..30], .little);
        const name_offset = try std.math.add(u64, entry.file_offset, local.len);
        if (!std.mem.eql(u8, filename, try self.range(name_offset, filename_len))) return error.ZipMismatchFilename;
        const data_offset = try std.math.add(u64, name_offset, @as(u64, filename_len) + extra_len);
        const compressed = try self.range(data_offset, entry.compressed_size);
        const size = std.math.cast(usize, entry.uncompressed_size) orelse return error.FileTooLarge;
        switch (entry.compression_method) {
            .store, .deflate => {},
            else => return error.UnsupportedCompressionMethod,
        }
        const output = try allocator.alloc(u8, size);
        errdefer allocator.free(output);
        switch (entry.compression_method) {
            .store => {
                if (compressed.len != output.len) return error.ZipMismatchUncompLen;
                @memcpy(output, compressed);
            },
            .deflate => {
                var input: std.Io.Reader = .fixed(compressed);
                var window: [std.compress.flate.max_window_len]u8 = undefined;
                var decoder: std.compress.flate.Decompress = .init(&input, .raw, &window);
                decoder.reader.readSliceAll(output) catch return decoder.err orelse error.ZipMismatchUncompLen;
                if (decoder.reader.takeByte()) |_| {
                    return error.ZipMismatchUncompLen;
                } else |err| switch (err) {
                    error.EndOfStream => {},
                    else => return decoder.err orelse error.ZipInvalidDeflate,
                }
                if (input.seek != compressed.len) return error.ZipMismatchCompLen;
            },
            else => unreachable,
        }
        if (std.hash.Crc32.hash(output) != entry.crc32) return error.ZipCrcMismatch;
        return output;
    }
};

// Generated with Python's zipfile; one DEFLATE member, independent of our reader.
const fixture = "\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00\x91\x4a\x2b\x5d\xd1\x72\x46\x58\x16\x00\x00\x00\x2c\x01\x00\x00\x11\x00\x00\x00" ++
    "folder/sample.ISO" ++ "\xcb\x48\xcd\xc9\xc9\x57\xc8\x2c\xce\x57\x48\xaa\x2c\x49\x2d\xce\x18\xe5\xe2\xe6\x02\x00" ++
    "\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x08\x00\x91\x4a\x2b\x5d\xd1\x72\x46\x58\x16\x00\x00\x00\x2c\x01\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00" ++
    "folder/sample.ISO" ++ "\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x3f\x00\x00\x00\x45\x00\x00\x00\x00\x00";

test "DEFLATE member is decoded in memory with size and CRC validation" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture.zip", .data = fixture });
    const path = try tmp.dir.realPathFileAlloc(io, "fixture.zip", allocator);
    defer allocator.free(path);
    var archive = try Archive.open(io, path);
    defer archive.close();
    var entries = try archive.iterator();
    const entry = (try entries.next()).?;
    const filename = try archive.name(entry);
    try std.testing.expectEqualStrings("folder/sample.ISO", filename);
    const bytes = try archive.read(entry, filename, allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("hello iso bytes" ** 20, bytes);
    try std.testing.expectEqual(null, try entries.next());
    var bad = entry;
    bad.crc32 ^= 1;
    try std.testing.expectError(error.ZipCrcMismatch, archive.read(bad, filename, allocator));
    bad = entry;
    bad.uncompressed_size -= 1;
    try std.testing.expectError(error.ZipMismatchUncompLen, archive.read(bad, filename, allocator));
    bad = entry;
    bad.compressed_size = fixture.len;
    try std.testing.expectError(error.ZipTruncated, archive.read(bad, filename, allocator));
    try std.testing.expectError(error.ZipMismatchFilename, archive.read(entry, "wrong.iso", allocator));
}

test "stored member and malformed archive handling" {
    const stored = "\x50\x4b\x03\x04\x14\x00\x00\x00\x00\x00\x91\x4a\x2b\x5d\xd1\x72\x46\x58\x2c\x01\x00\x00\x2c\x01\x00\x00\x11\x00\x00\x00" ++
        "folder/sample.ISO" ++ "hello iso bytes" ** 20 ++
        "\x50\x4b\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\x91\x4a\x2b\x5d\xd1\x72\x46\x58\x2c\x01\x00\x00\x2c\x01\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00" ++
        "folder/sample.ISO" ++ "\x50\x4b\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x3f\x00\x00\x00\x5b\x01\x00\x00\x00\x00";
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture.zip", .data = stored });
    const path = try tmp.dir.realPathFileAlloc(io, "fixture.zip", allocator);
    defer allocator.free(path);
    {
        var archive = try Archive.open(io, path);
        defer archive.close();
        var entries = try archive.iterator();
        const entry = (try entries.next()).?;
        const filename = try archive.name(entry);
        const bytes = try archive.read(entry, filename, allocator);
        defer allocator.free(bytes);
        try std.testing.expectEqualStrings("hello iso bytes" ** 20, bytes);
    }
    var corrupted = stored.*;
    // A Unix symlink must never be treated as an ISO payload.
    std.mem.writeInt(u32, corrupted[347 + 38 ..][0..4], 0xa1ff0000, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture.zip", .data = &corrupted });
    {
        var archive = try Archive.open(io, path);
        defer archive.close();
        var entries = try archive.iterator();
        const entry = (try entries.next()).?;
        try std.testing.expectError(error.ZipNotRegularFile, archive.read(entry, try archive.name(entry), allocator));
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture.zip", .data = "not a zip" });
    var archive = try Archive.open(io, path);
    defer archive.close();
    if (archive.iterator()) |_| return error.ExpectedMalformedZipRejection else |_| {}
}
