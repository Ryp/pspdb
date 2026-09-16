const std = @import("std");
const c = @import("archive");
const memory = @import("bytes.zig");
const iso_view = @import("iso_view.zig");
const IsoView = iso_view.IsoView;
const iconv = @cImport({
    @cInclude("iconv.h");
});

const Path = struct {
    bytes: []const u8,
    raw: []const u8,
    allocation: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator, raw: []const u8) !Path {
        const bytes = if (std.mem.startsWith(u8, raw, "./")) raw[2..] else raw;
        if (std.unicode.utf8ValidateSlice(bytes)) return .{ .bytes = bytes, .raw = bytes };
        const converter = iconv.iconv_open("utf-8", "CP932");
        if (converter == @as(iconv.iconv_t, @ptrFromInt(std.math.maxInt(usize)))) return error.InvalidIsoPath;
        defer _ = iconv.iconv_close(converter);
        const buffer = try allocator.alloc(u8, try std.math.mul(usize, bytes.len, 3));
        errdefer allocator.free(buffer);
        var input_ptr: [*c]u8 = @constCast(bytes.ptr);
        var remaining = bytes.len;
        var output_ptr: [*c]u8 = buffer.ptr;
        var available = buffer.len;
        // A CP932 character expands to at most three UTF-8 bytes. With that
        // bound, any iconv error or non-reversible conversion is invalid input.
        if (iconv.iconv(converter, &input_ptr, &remaining, &output_ptr, &available) != 0 or remaining != 0)
            return error.InvalidIsoPath;
        return .{ .bytes = buffer[0 .. buffer.len - available], .raw = bytes, .allocation = buffer };
    }

    fn deinit(self: Path, allocator: std.mem.Allocator) void {
        if (self.allocation) |buffer| allocator.free(buffer);
    }
};

/// Read a named file independently of enumeration order. Caller owns the bytes.
/// Unrelated pathname decoding belongs to inventory, not metadata lookup.
pub fn read_file(allocator: std.mem.Allocator, bytes: []const u8, wanted: []const u8) !?[]u8 {
    return read_file_depth(allocator, bytes, wanted, false, 0);
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
        var name = std.mem.span(pathname);
        if (std.mem.startsWith(u8, name, "./")) name = name[2..];
        const matches = if (case_sensitive) std.mem.eql(u8, name, wanted) else std.ascii.eqlIgnoreCase(name, wanted);
        if (!matches) continue;
        const hardlink = c.archive_entry_hardlink(entry);
        if (hardlink != null) {
            const target = try Path.init(allocator, std.mem.span(hardlink));
            defer target.deinit(allocator);
            // Validate the same encoding as the displayed path, but keep the
            // backend lookup byte-exact even if two spellings normalize alike.
            return (try read_file_depth(allocator, bytes, target.raw, true, depth + 1)) orelse error.UnresolvedIsoHardlink;
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

pub const Mastering = iso_view.Mastering;

/// Match only the known root layout, and check the effective Rock Ridge view
/// as well as the ISO directory extents before lending any source subrange.
pub fn mastering(allocator: std.mem.Allocator, bytes: []const u8) !?Mastering {
    const result = (try iso_view.mastering(bytes)) orelse return null;
    var view: IsoView = .{ .bytes = bytes };
    const archive = c.archive_read_new() orelse return error.OutOfMemory;
    defer _ = c.archive_read_free(archive);
    if (c.archive_read_support_format_iso9660(archive) != c.ARCHIVE_OK) return error.IsoReaderUnavailable;
    if (c.archive_read_open(archive, &view, null, IsoView.read, null) != c.ARCHIVE_OK) return error.InvalidIso;
    var header: ?*c.struct_archive_entry = null;
    var found = [_]bool{false} ** Mastering.names.len;
    while (true) {
        const status = c.archive_read_next_header(archive, &header);
        if (status == c.ARCHIVE_EOF) break;
        if (status != c.ARCHIVE_OK) return error.InvalidIso;
        const pathname = c.archive_entry_pathname(header);
        if (pathname == null) return error.InvalidIso;
        const name = try Path.init(allocator, std.mem.span(pathname));
        defer name.deinit(allocator);
        if (std.mem.eql(u8, name.bytes, ".") or name.bytes.len == 0) continue;
        const index = for (Mastering.names, 0..) |expected, candidate_index| {
            if (std.mem.eql(u8, name.bytes, expected)) break candidate_index;
        } else return error.InvalidIsoMasteringWrapper;
        if (found[index] or c.archive_entry_filetype(header) != c.PSPDB_ARCHIVE_REGULAR or
            c.archive_entry_hardlink(header) != null or c.archive_entry_size(header) != result.files[index].len)
            return error.InvalidIsoMasteringWrapper;
        // The primary directory is an extent locator, not a second filesystem
        // implementation. Confirm that libarchive's effective file view agrees
        // (including alternate descriptors and Rock Ridge transformations).
        // Ordinary contiguous files point straight into the source, so this
        // check neither copies nor scans their payload a second time.
        const expected = result.files[index];
        var total: usize = 0;
        while (true) {
            var block: ?*const anyopaque = null;
            var length: usize = 0;
            var offset: c.la_int64_t = 0;
            const data_status = c.archive_read_data_block(archive, &block, &length, &offset);
            if (data_status == c.ARCHIVE_EOF) break;
            if (data_status != c.ARCHIVE_OK or offset < 0 or offset != total or length == 0 or length > expected.len - total)
                return error.InvalidIsoMasteringWrapper;
            const data = @as([*]const u8, @ptrCast(block orelse return error.InvalidIsoMasteringWrapper))[0..length];
            const source = expected[total..][0..length];
            if (data.ptr != source.ptr and !std.mem.eql(u8, data, source)) return error.InvalidIsoMasteringWrapper;
            total += length;
        }
        if (total != expected.len) return error.InvalidIsoMasteringWrapper;
        found[index] = true;
    }
    for (found) |present| if (!present) return error.InvalidIsoMasteringWrapper;
    return result;
}

/// The verified mastering members are contiguous source slices. The normal
/// inventory callback hashes/stores each one and queues USER_L0 as ISO9660.
pub fn walk_mastering(image: Mastering, owner: *memory.Owner, context: anytype, comptime emit: anytype) !void {
    for (Mastering.names, image.files) |name, bytes| {
        try emit(context, name, memory.View{ .owner = owner, .bytes = bytes });
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
        const path = try Path.init(allocator, std.mem.span(pathname));
        defer path.deinit(allocator);
        const name = path.bytes;
        if (std.mem.eql(u8, name, ".") or name.len == 0) continue;
        const kind = c.archive_entry_filetype(header);
        const hardlink = c.archive_entry_hardlink(header);
        if (kind == c.PSPDB_ARCHIVE_DIRECTORY) {
            try emit(context, name, null);
        } else if (hardlink != null) {
            // Resolve libarchive's shared-extent alias to bytes, keeping that
            // backend detail out of the consumer's file callback.
            const target = try Path.init(allocator, std.mem.span(hardlink));
            defer target.deinit(allocator);
            const payload = (try read_file_depth(allocator, bytes, target.raw, true, 0)) orelse return error.UnresolvedIsoHardlink;
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
