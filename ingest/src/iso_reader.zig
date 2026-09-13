const std = @import("std");
const c = @import("archive");
const memory = @import("bytes.zig");
const IsoView = @import("iso_view.zig").IsoView;

/// Read a named file independently of enumeration order. Caller owns the bytes.
pub fn read_file(allocator: std.mem.Allocator, bytes: []const u8, wanted: []const u8) !?[]u8 {
    const path = if (std.mem.startsWith(u8, wanted, "./")) wanted[2..] else wanted;
    return read_file_depth(allocator, bytes, path, false, 0);
}

/// Read metadata independently of inventory order. Shared extents are exposed
/// as hard links by libarchive: reopen and read the target's bytes in that case.
fn read_file_depth(allocator: std.mem.Allocator, bytes: []const u8, wanted: []const u8, case_sensitive: bool, depth: usize) !?[]u8 {
    if (depth == 32) return error.InvalidIsoHardlink;
    var view: IsoView = .{ .bytes = bytes };
    const archive = c.archive_read_new() orelse return error.OutOfMemory;
    defer _ = c.archive_read_free(archive);
    if (c.archive_read_support_format_iso9660(archive) != c.ARCHIVE_OK) return error.IsoReaderUnavailable;
    if (c.archive_read_open(archive, &view, null, IsoView.read, null) != c.ARCHIVE_OK) return error.InvalidIso;
    var entry: ?*c.struct_archive_entry = null;
    while (true) {
        const status = c.archive_read_next_header(archive, &entry);
        if (status == c.ARCHIVE_EOF) return null;
        if (status != c.ARCHIVE_OK) return error.InvalidIso;
        const pathname = c.archive_entry_pathname(entry);
        if (pathname == null) return error.InvalidIso;
        var name: []const u8 = std.mem.span(pathname);
        if (std.mem.startsWith(u8, name, "./")) name = name[2..];
        const matches = if (case_sensitive) std.mem.eql(u8, name, wanted) else std.ascii.eqlIgnoreCase(name, wanted);
        if (!matches) continue;
        const hardlink = c.archive_entry_hardlink(entry);
        if (hardlink != null) {
            var target = std.mem.span(hardlink);
            if (std.mem.startsWith(u8, target, "./")) target = target[2..];
            // A backend link names an exact path, not a metadata spelling variant.
            return (try read_file_depth(allocator, bytes, target, true, depth + 1)) orelse error.UnresolvedIsoHardlink;
        }
        if (c.archive_entry_filetype(entry) != c.PSPDB_ARCHIVE_REGULAR) return error.MetadataNotRegularFile;
        const length = c.archive_entry_size(entry);
        if (length < 0 or length > bytes.len) return error.InvalidMetadataSize;
        const data = try allocator.alloc(u8, @intCast(length));
        errdefer allocator.free(data);
        var offset: usize = 0;
        while (offset < data.len) {
            const count = c.archive_read_data(archive, data[offset..].ptr, data.len - offset);
            if (count <= 0) return error.TruncatedMetadata;
            offset += @intCast(count);
        }
        return data;
    }
}

/// Emit each logical path synchronously. Null contents denotes a directory;
/// a non-null slice (including an empty slice) denotes a file. Names and byte views
/// are borrowed until emit returns; consumers may retain byte views. Callback errors stop enumeration immediately.
/// No hashing, storage, catalog publication or filesystem extraction occurs here.
pub fn walk(allocator: std.mem.Allocator, bytes: []const u8, context: anytype, comptime emit: anytype) !void {
    var view: IsoView = .{ .bytes = bytes };
    const archive = c.archive_read_new() orelse return error.OutOfMemory;
    defer _ = c.archive_read_free(archive);
    if (c.archive_read_support_format_iso9660(archive) != c.ARCHIVE_OK) return error.IsoReaderUnavailable;
    if (c.archive_read_open(archive, &view, null, IsoView.read, null) != c.ARCHIVE_OK) return error.InvalidIso;
    var header: ?*c.struct_archive_entry = null;
    while (true) {
        const status = c.archive_read_next_header(archive, &header);
        if (status == c.ARCHIVE_EOF) break;
        if (status != c.ARCHIVE_OK) return error.InvalidIso;
        const pathname = c.archive_entry_pathname(header);
        if (pathname == null) return error.InvalidIso;
        var name = std.mem.span(pathname);
        if (std.mem.startsWith(u8, name, "./")) name = name[2..];
        if (std.mem.eql(u8, name, ".") or name.len == 0) continue;
        const kind = c.archive_entry_filetype(header);
        const hardlink = c.archive_entry_hardlink(header);
        if (kind == c.PSPDB_ARCHIVE_DIRECTORY) {
            try emit(context, name, null);
        } else if (hardlink != null) {
            // Resolve libarchive's shared-extent alias to bytes, keeping that
            // backend detail out of the consumer's file callback.
            var target = std.mem.span(hardlink);
            if (std.mem.startsWith(u8, target, "./")) target = target[2..];
            const payload = (try read_file_depth(allocator, bytes, target, true, 0)) orelse return error.UnresolvedIsoHardlink;
            const payload_view = try memory.Owner.take_allocated(allocator, payload);
            defer payload_view.release();
            try emit(context, name, payload_view);
        } else if (kind == c.PSPDB_ARCHIVE_REGULAR) {
            const size = c.archive_entry_size(header);
            if (size < 0 or size > bytes.len) return error.InvalidIsoFileSize;
            const payload = try allocator.alloc(u8, @intCast(size));
            const payload_view = try memory.Owner.take_allocated(allocator, payload);
            defer payload_view.release();
            var total: usize = 0;
            while (total < payload.len) {
                const count = c.archive_read_data(archive, payload[total..].ptr, payload.len - total);
                if (count < 0) return error.InvalidIsoFileData;
                if (count == 0) return error.TruncatedIsoFile;
                total += @intCast(count);
            }
            var extra: [1]u8 = undefined;
            const remaining = c.archive_read_data(archive, &extra, extra.len);
            if (remaining < 0) return error.InvalidIsoFileData;
            if (remaining != 0) return error.InvalidIsoFileSize;
            try emit(context, name, payload_view);
        } else return error.UnsupportedIsoEntry;
    }
}
