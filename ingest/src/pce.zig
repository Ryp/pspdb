//! PC Engine Archives (PlayStation Store "PC Engine Archives" / TurboGrafx):
//! the XOR obfuscation layer and the container inside `CONTENT.DAT` and the
//! SDAT-decoded `CONTENT1.sdat`, the CD-ROM² TOC (`*.hcd`) and the Sony
//! zlib-chunked data-track container (`*_NN.bin`) that holds a 2048-byte
//! sector ISO image (a PC Engine CD image, not an ISO9660 filesystem).
//!
//! Layering (see README, "PC Engine Archives"):
//!   plain[i] = data[i] ^ key16[i & 15] ^ public_table[i & 511]
//!   plain    = 0x80-byte header + count * 0x50-byte entries + payloads
//! The XOR layer is obfuscation, not cryptography: nothing here authenticates
//! a container. CONTENT.DAT is only structure-checked; CONTENT1.sdat is
//! additionally integrity-verified by its SDAT MACs before it reaches this module.
const std = @import("std");

const zlib = @import("c_zlib");

/// The fixed public 512-byte XOR table. It is `keys/public.key` of qwikrazor87's
/// PCE_py_tool (archive.org item `pce-cd-tools`), byte-identical to the table the
/// PS3 emulator embeds, and is the same for every game. SHA-256 of the table:
/// b2d7084c90257943a9b00a22493da7fa3f52113bba222b2e243e6917e4457165 (tested).
pub const public_table: [512]u8 = .{
    0x7a, 0xe4, 0x14, 0x19, 0xe9, 0x2e, 0x5d, 0xb4, 0x03, 0x33, 0xa9, 0x1d, 0x9b, 0x6f, 0x47, 0x05,
    0xce, 0x0b, 0xeb, 0xe4, 0xa0, 0xe7, 0xa6, 0x9b, 0x8c, 0x0e, 0x97, 0x43, 0xd8, 0x65, 0x5f, 0xce,
    0x8e, 0xd9, 0xc3, 0x37, 0x3c, 0xe4, 0x65, 0x52, 0xcc, 0x1a, 0xaa, 0x44, 0x62, 0xfa, 0x6e, 0xc8,
    0x10, 0xaa, 0xa5, 0x42, 0x86, 0x57, 0x7e, 0x93, 0x3d, 0x78, 0x8c, 0xdb, 0x96, 0x1a, 0xdb, 0x9e,
    0xd3, 0xda, 0x8f, 0xc2, 0xab, 0x0f, 0xc9, 0xe9, 0xa5, 0x98, 0x17, 0x86, 0x3d, 0x62, 0x39, 0x92,
    0xa0, 0xce, 0x32, 0x2d, 0xbf, 0x1c, 0x47, 0x36, 0x5a, 0x30, 0xfa, 0xc3, 0x57, 0x8a, 0xbb, 0xb2,
    0x3e, 0x0b, 0x70, 0x88, 0x6a, 0xab, 0x1d, 0x01, 0xe1, 0xbc, 0x9d, 0xee, 0x3f, 0xf7, 0x56, 0xda,
    0x3f, 0xfa, 0x3a, 0xc8, 0xe7, 0xae, 0xdf, 0xb6, 0x92, 0x58, 0x67, 0x7b, 0x15, 0x05, 0x91, 0x1a,
    0xdc, 0x65, 0x48, 0x31, 0xf2, 0xb0, 0x27, 0xf4, 0xb1, 0x31, 0x4c, 0x03, 0x7f, 0x59, 0xf6, 0x62,
    0xda, 0x1f, 0x83, 0x5d, 0x50, 0xf3, 0xcb, 0x90, 0x2b, 0xb9, 0xf6, 0x11, 0x44, 0xa2, 0xeb, 0xdb,
    0x2a, 0x82, 0x11, 0xda, 0xaf, 0x24, 0xe8, 0x8f, 0xd2, 0x45, 0x17, 0xb6, 0x61, 0xdc, 0x37, 0x38,
    0x61, 0x04, 0xa0, 0xf6, 0x82, 0x34, 0xca, 0xe9, 0x99, 0xb8, 0x06, 0x38, 0xba, 0x16, 0xb0, 0x0e,
    0x45, 0x71, 0xd8, 0xfc, 0x47, 0x1c, 0xb3, 0xb5, 0x36, 0xf4, 0x8a, 0x0a, 0xdb, 0x14, 0x2e, 0x4f,
    0x82, 0xbd, 0xaf, 0x3f, 0x01, 0xf5, 0x59, 0xf6, 0xb8, 0x28, 0x40, 0xf7, 0x1e, 0xaf, 0xd4, 0xbc,
    0x95, 0x08, 0x70, 0xf0, 0x03, 0x3b, 0xf1, 0x45, 0x51, 0xea, 0xc0, 0x8d, 0xa9, 0xbf, 0x0d, 0x84,
    0x89, 0xb6, 0xb6, 0xfd, 0x66, 0x70, 0x0d, 0x50, 0x18, 0xe2, 0x43, 0x1f, 0xdb, 0xbb, 0x97, 0x86,
    0x1f, 0xce, 0x75, 0xd2, 0xa4, 0x3e, 0x4b, 0x46, 0xcc, 0x6a, 0xee, 0x16, 0x35, 0xcb, 0x4d, 0xf9,
    0x1a, 0xbb, 0x6d, 0x67, 0xf9, 0xd7, 0x55, 0x25, 0xfa, 0x20, 0xd8, 0x21, 0xf7, 0xd2, 0x69, 0x96,
    0x53, 0x39, 0x6d, 0xda, 0x4a, 0x3b, 0xe0, 0x4b, 0x6a, 0x6f, 0x31, 0xfc, 0x82, 0xf7, 0x1b, 0x4c,
    0x95, 0x49, 0x04, 0x1f, 0x4d, 0x30, 0x8d, 0x48, 0x78, 0x4f, 0xd7, 0x83, 0x65, 0x2a, 0x4f, 0xfa,
    0x00, 0x58, 0xc3, 0xfb, 0x5e, 0x72, 0xaf, 0xdf, 0xda, 0x21, 0xfd, 0x89, 0xa6, 0x59, 0xa3, 0x03,
    0x05, 0x8b, 0x8b, 0xad, 0xcd, 0x4a, 0x48, 0x23, 0xac, 0x25, 0x62, 0xfa, 0x63, 0x5d, 0xe5, 0x3f,
    0x20, 0x36, 0xfb, 0x29, 0x34, 0x1f, 0xee, 0x23, 0x9a, 0x25, 0x44, 0x2b, 0x32, 0x03, 0xa2, 0x1e,
    0xac, 0xd4, 0x7e, 0xd9, 0x9e, 0xa1, 0x2c, 0xb6, 0x0f, 0xa0, 0x4f, 0x39, 0x10, 0xb5, 0x7c, 0x7d,
    0x3c, 0xbd, 0x69, 0x6f, 0x5e, 0x79, 0xce, 0xe5, 0x9d, 0x68, 0x13, 0xa8, 0x05, 0x1c, 0xf0, 0xa8,
    0x82, 0x43, 0x4d, 0x8e, 0xdf, 0x0b, 0xa0, 0x7e, 0x0a, 0x45, 0x1a, 0x94, 0xd0, 0xb4, 0x12, 0xe5,
    0xa8, 0xc7, 0xef, 0x75, 0x9a, 0x32, 0xc0, 0x33, 0x05, 0x98, 0x3b, 0x35, 0x8e, 0x84, 0xb1, 0xf3,
    0xb0, 0xa7, 0xb6, 0xcc, 0x67, 0xed, 0x9e, 0x30, 0x1c, 0xea, 0x65, 0x19, 0x5e, 0x3a, 0x15, 0xe9,
    0x55, 0x2d, 0xff, 0x3e, 0x2c, 0x7a, 0x0d, 0x50, 0x83, 0x19, 0x89, 0x46, 0xcf, 0x6a, 0xf0, 0x86,
    0x93, 0x26, 0xe4, 0x29, 0xfe, 0x46, 0x7e, 0xbb, 0x28, 0xbf, 0x58, 0xb0, 0xcd, 0xa7, 0xd4, 0xca,
    0x83, 0x52, 0xe0, 0x60, 0x84, 0x73, 0xc6, 0x35, 0x99, 0x65, 0x49, 0x4d, 0x64, 0x57, 0x60, 0xb1,
    0xf9, 0xde, 0x85, 0x38, 0x56, 0xeb, 0xea, 0x0f, 0xaf, 0x44, 0x15, 0x6d, 0x21, 0x5d, 0x82, 0xdb,
};

pub const key_size = 16;
pub const header_size = 0x80;
pub const entry_size = 0x50;
pub const name_size = 0x40;
pub const max_entries = 4096;
/// Largest container accepted (the observed maximum is about 120 MiB).
pub const max_container_size = 256 << 20;
pub const sector_size = 2048;
/// Every Sony zlib chunk of a data track inflates to this size, except the last.
pub const chunk_size = 0x40000;
/// Largest ISO produced from one data track (a CD holds at most ~700 MiB).
pub const max_iso_size = 1 << 30;
const ipl_signature = "PC Engine CD-ROM SYSTEM";
const ipl_offset = 2080;

/// Return an XOR-decoded copy of `source`. The result is owned by the caller.
pub fn decrypt(allocator: std.mem.Allocator, source: []const u8, key: [key_size]u8) ![]u8 {
    if (source.len > max_container_size) return error.PceContainerTooLarge;
    const output = try allocator.alloc(u8, source.len);
    errdefer allocator.free(output);
    var stream = keystream(key);
    var offset: usize = 0;
    while (offset < source.len) : (offset += stream.len) {
        const count = @min(stream.len, source.len - offset);
        for (output[offset..][0..count], source[offset..][0..count], stream[0..count]) |*out, in, mask| out.* = in ^ mask;
    }
    return output;
}

/// XOR-decode a buffer owned by the caller (the SDAT plaintext).
pub fn decrypt_in_place(buffer: []u8, key: [key_size]u8) void {
    const stream = keystream(key);
    var offset: usize = 0;
    while (offset < buffer.len) : (offset += stream.len) {
        const count = @min(stream.len, buffer.len - offset);
        for (buffer[offset..][0..count], stream[0..count]) |*byte, mask| byte.* ^= mask;
    }
}

// key16[i & 15] ^ table[i & 511] repeats every lcm(16, 512) = 512 bytes.
fn keystream(key: [key_size]u8) [512]u8 {
    var stream: [512]u8 = undefined;
    for (&stream, public_table, 0..) |*mask, table, index| mask.* = table ^ key[index & 15];
    return stream;
}

pub const Entry = struct { name: []const u8, offset: usize, size: usize };

/// Validate a decoded container and return its entries; names borrow `plain`.
/// The caller owns the slice. Rejected: bad magic, a count above 4096 or of
/// zero, a table past the end, names that are empty, non-printable-ASCII, `.`,
/// `..`, or contain `/`, `\\` or `:`, or lack NUL padding, duplicate names
/// (also case-insensitively), nonzero entry trailers, payloads outside
/// the file or inside the table, and overlapping payloads.
pub fn parse(allocator: std.mem.Allocator, plain: []const u8) ![]Entry {
    if (plain.len < header_size or plain.len > max_container_size or !std.mem.eql(u8, plain[0..4], "\x12\x34\x56\x78"))
        return error.InvalidPceContainer;
    const count = std.mem.readInt(u32, plain[0x28..0x2c], .little);
    if (count > max_entries) return error.TooManyPceEntries;
    if (count == 0) return error.InvalidPceContainer;
    const table_end = header_size + @as(usize, count) * entry_size;
    if (table_end > plain.len) return error.InvalidPceContainer;

    const entries = try allocator.alloc(Entry, count);
    errdefer allocator.free(entries);
    for (entries, 0..) |*entry, index| {
        const raw = plain[header_size + index * entry_size ..][0..entry_size];
        const name = std.mem.sliceTo(raw[0..name_size], 0);
        if (!safe_name(name) or !std.mem.allEqual(u8, raw[name.len..name_size], 0)) return error.InvalidPceName;
        if (!std.mem.allEqual(u8, raw[0x48..0x50], 0)) return error.InvalidPceTrailer;
        const offset = std.mem.readInt(u32, raw[0x40..0x44], .little);
        const size = std.mem.readInt(u32, raw[0x44..0x48], .little);
        if (offset < table_end or @as(u64, offset) + size > plain.len) return error.InvalidPceEntry;
        entry.* = .{ .name = name, .offset = offset, .size = size };
    }
    // Names are unique in any case folding, so a case-insensitive file system
    // downstream cannot merge two entries. Linear scan: count <= 4096.
    for (entries, 0..) |entry, index| {
        for (entries[0..index]) |previous| {
            if (std.ascii.eqlIgnoreCase(previous.name, entry.name)) return error.DuplicatePceName;
        }
    }
    // Payload ranges must not overlap, whatever order the table lists them in.
    const order = try allocator.alloc(u32, count);
    defer allocator.free(order);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    std.mem.sort(u32, order, entries, struct {
        fn less(list: []Entry, a: u32, b: u32) bool {
            return list[a].offset < list[b].offset;
        }
    }.less);
    var end: usize = table_end;
    for (order) |index| {
        const entry = entries[index];
        if (entry.size == 0) continue;
        if (entry.offset < end) return error.OverlappingPceEntries;
        end = entry.offset + entry.size;
    }
    return entries;
}

fn safe_name(name: []const u8) bool {
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |byte| {
        if (byte < 0x21 or byte > 0x7e or byte == '/' or byte == '\\' or byte == ':') return false;
    }
    return true;
}

pub const Track = struct { number: u32, code: bool, file: []const u8, start: u32, length: u32 };

/// Drive-timing directives that precede the tracks of some TOCs, e.g. `readwait,0.20`.
/// They affect only the PSP emulator and are accepted once each, as plain decimals.
fn timing_directive(line: []const u8, seen: *[2]bool) !bool {
    inline for (.{ "readwait,", "playwait," }, 0..) |prefix, index| {
        if (std.mem.startsWith(u8, line, prefix)) {
            const value = std.mem.trim(u8, line[prefix.len..], " ");
            const dot = std.mem.indexOfScalar(u8, value, '.');
            _ = try decimal(if (dot) |at| value[0..at] else value);
            if (dot) |at| _ = try decimal(value[at + 1 ..]);
            if (seen[index]) return error.InvalidPceToc;
            seen[index] = true;
            return true;
        }
    }
    return false;
}

const max_tracks = 99;

/// Parse a `HCDnnnn.hcd` TOC: lines `trackNN,audio|code ,<file>,<LBA>,<sectors>`,
/// optionally after one `readwait,N.NN` and one `playwait,N.NN` line.
/// Track numbers must ascend, names must be safe container names, and nothing
/// else may appear. Names borrow `text`; the caller owns the slice.
pub fn parse_toc(allocator: std.mem.Allocator, text: []const u8) ![]Track {
    var tracks: std.ArrayList(Track) = .empty;
    errdefer tracks.deinit(allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    var directives: [2]bool = .{ false, false };
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        if (tracks.items.len == 0 and try timing_directive(line, &directives)) continue;
        if (tracks.items.len == max_tracks) return error.InvalidPceToc;
        var fields = std.mem.splitScalar(u8, line, ',');
        const label = fields.next().?;
        const kind = std.mem.trim(u8, fields.next() orelse return error.InvalidPceToc, " ");
        const file = std.mem.trim(u8, fields.next() orelse return error.InvalidPceToc, " ");
        const start_text = std.mem.trim(u8, fields.next() orelse return error.InvalidPceToc, " ");
        const length_text = std.mem.trim(u8, fields.next() orelse return error.InvalidPceToc, " ");
        if (fields.next() != null or !std.mem.startsWith(u8, label, "track")) return error.InvalidPceToc;
        const number = try decimal(label["track".len..]);
        const code = std.mem.eql(u8, kind, "code");
        if (!code and !std.mem.eql(u8, kind, "audio")) return error.InvalidPceToc;
        if (!safe_name(file)) return error.InvalidPceToc;
        if (tracks.items.len != 0 and number <= tracks.items[tracks.items.len - 1].number) return error.InvalidPceToc;
        try tracks.append(allocator, .{ .number = number, .code = code, .file = file, .start = try decimal(start_text), .length = try decimal(length_text) });
    }
    if (tracks.items.len == 0) return error.InvalidPceToc;
    return tracks.toOwnedSlice(allocator);
}

fn decimal(text: []const u8) !u32 {
    if (text.len == 0 or text.len > 9) return error.InvalidPceToc;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidPceToc;
    return std.fmt.parseInt(u32, text, 10) catch error.InvalidPceToc;
}

/// Inflate a Sony data-track container into its 2048-byte-sector image:
/// `u32 n; n * {u32 offset, u32 size}; n independent zlib streams`. The TOC
/// fixes the image size (`sectors * 2048`, at most 1 GiB): the chunk count
/// must match, every stream inflates completely to exactly 0x40000 bytes (the
/// last one to the remainder), streams are in order, do not overlap and end at
/// the end of the file. The writer pads each stream to a multiple of 4 bytes with
/// unspecified bytes: a stream's size must be 4-aligned and at most 3 bytes
/// may follow its zlib trailer; anything longer is trailing data. With `require_ipl` the
/// "PC Engine CD-ROM SYSTEM" header of sector 1 must be present. Nothing is
/// returned on failure.
pub fn decode_track(allocator: std.mem.Allocator, bin: []const u8, sectors: u32, require_ipl: bool) ![]u8 {
    const total = @as(u64, sectors) * sector_size;
    if (total == 0 or total > max_iso_size) return error.InvalidPceTrack;
    const count: usize = @intCast((total + chunk_size - 1) / chunk_size);
    if (bin.len < 4 or std.mem.readInt(u32, bin[0..4], .little) != count) return error.InvalidPceTrack;
    const table_end = 4 + count * 8;
    if (bin.len < table_end) return error.InvalidPceTrack;
    var cursor: usize = table_end;
    for (0..count) |index| {
        const offset = std.mem.readInt(u32, bin[4 + index * 8 ..][0..4], .little);
        const size = std.mem.readInt(u32, bin[8 + index * 8 ..][0..4], .little);
        if (offset != cursor or size == 0 or size % 4 != 0 or @as(u64, offset) + size > bin.len) return error.InvalidPceTrack;
        cursor += size;
    }
    if (cursor != bin.len) return error.InvalidPceTrack;

    const output = try allocator.alloc(u8, @intCast(total));
    errdefer allocator.free(output);
    for (0..count) |index| {
        const offset = std.mem.readInt(u32, bin[4 + index * 8 ..][0..4], .little);
        const size = std.mem.readInt(u32, bin[8 + index * 8 ..][0..4], .little);
        const target = output[index * chunk_size ..][0..@min(chunk_size, output.len - index * chunk_size)];
        try inflate_exact(bin[offset..][0..size], target);
    }
    if (require_ipl and (output.len < ipl_offset + ipl_signature.len or
        !std.mem.eql(u8, output[ipl_offset..][0..ipl_signature.len], ipl_signature)))
        return error.InvalidPceTrack;
    return output;
}

fn inflate_exact(source: []const u8, target: []u8) !void {
    var stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream);
    if (zlib.inflateInit_(&stream, zlib.zlibVersion(), @sizeOf(zlib.z_stream)) != zlib.Z_OK) return error.OutOfMemory;
    defer _ = zlib.inflateEnd(&stream);
    stream.next_in = @constCast(source.ptr);
    stream.avail_in = @intCast(source.len);
    stream.next_out = target.ptr;
    stream.avail_out = @intCast(target.len);
    // Z_FINISH: a short output buffer or truncated input is an error, never partial.
    if (zlib.inflate(&stream, zlib.Z_FINISH) != zlib.Z_STREAM_END or stream.avail_in > 3 or stream.avail_out != 0)
        return error.InvalidPceTrack;
}

// ---- tests ----------------------------------------------------------------

/// Test helper (also used by processor tests): build a plain container.
pub const File = struct { []const u8, []const u8 };

pub fn build_container(allocator: std.mem.Allocator, files: []const File) ![]u8 {
    var total: usize = header_size + files.len * entry_size;
    for (files) |file| total += (file[1].len + 15) & ~@as(usize, 15);
    const bytes = try allocator.alloc(u8, total + 16);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], "\x12\x34\x56\x78");
    std.mem.writeInt(u32, bytes[0x28..0x2c], @intCast(files.len), .little);
    var cursor: usize = header_size + files.len * entry_size;
    for (files, 0..) |file, index| {
        const raw = bytes[header_size + index * entry_size ..][0..entry_size];
        @memcpy(raw[0..file[0].len], file[0]);
        std.mem.writeInt(u32, raw[0x40..0x44], @intCast(cursor), .little);
        std.mem.writeInt(u32, raw[0x44..0x48], @intCast(file[1].len), .little);
        @memcpy(bytes[cursor..][0..file[1].len], file[1]);
        cursor += (file[1].len + 15) & ~@as(usize, 15);
    }
    return bytes;
}

/// Test helper: the inverse of `decrypt`.
pub fn encrypt_in_place(buffer: []u8, key: [key_size]u8) void {
    decrypt_in_place(buffer, key);
}

/// Test helper: a Sony track container with one independent zlib stream per chunk.
pub fn build_track(allocator: std.mem.Allocator, image: []const u8) ![]u8 {
    return build_padded_track(allocator, image, 0);
}

/// Test helper: streams padded to 4 bytes with junk, plus `extra` more 4-byte groups.
pub fn build_padded_track(allocator: std.mem.Allocator, image: []const u8, extra: usize) ![]u8 {
    const count = (image.len + chunk_size - 1) / chunk_size;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendNTimes(allocator, 0, 4 + count * 8);
    std.mem.writeInt(u32, output.items[0..4], @intCast(count), .little);
    for (0..count) |index| {
        const chunk = image[index * chunk_size ..][0..@min(chunk_size, image.len - index * chunk_size)];
        const bound = zlib.compressBound(@intCast(chunk.len));
        const packed_bytes = try allocator.alloc(u8, bound);
        defer allocator.free(packed_bytes);
        var length: zlib.uLongf = bound;
        if (zlib.compress(packed_bytes.ptr, &length, chunk.ptr, @intCast(chunk.len)) != zlib.Z_OK) return error.CompressFailed;
        const padded = (length + 3) / 4 * 4 + extra * 4;
        std.mem.writeInt(u32, output.items[4 + index * 8 ..][0..4], @intCast(output.items.len), .little);
        std.mem.writeInt(u32, output.items[8 + index * 8 ..][0..4], @intCast(padded), .little);
        try output.appendSlice(allocator, packed_bytes[0..length]);
        try output.appendNTimes(allocator, 0xaa, padded - length);
    }
    return output.toOwnedSlice(allocator);
}

test "public table is the pinned PCE_py_tool key" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&public_table, &digest, .{});
    try std.testing.expectEqualStrings("b2d7084c90257943a9b00a22493da7fa3f52113bba222b2e243e6917e4457165", &std.fmt.bytesToHex(digest, .lower));
}

test "XOR layer is position-periodic and symmetric" {
    const allocator = std.testing.allocator;
    const key: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const plain = try allocator.alloc(u8, 1300);
    defer allocator.free(plain);
    for (plain, 0..) |*byte, index| byte.* = @truncate(index * 31);
    const coded = try allocator.dupe(u8, plain);
    defer allocator.free(coded);
    decrypt_in_place(coded, key);
    for (coded, plain, 0..) |c, p, index| try std.testing.expectEqual(p ^ key[index & 15] ^ public_table[index & 511], c);
    const round = try decrypt(allocator, coded, key);
    defer allocator.free(round);
    try std.testing.expectEqualSlices(u8, plain, round);
    try std.testing.expectError(error.PceContainerTooLarge, decrypt(allocator, @as([*]const u8, plain.ptr)[0 .. max_container_size + 1], key));
}

const sample_files = [_]File{
    .{ "CONFIG.PS3", "config text" },
    .{ "GAME.PCE", "rom bytes rom bytes rom bytes" },
    .{ "psp_001.png", "png" },
};

test "container parser lists entries under their original names" {
    const allocator = std.testing.allocator;
    const plain = try build_container(allocator, &sample_files);
    defer allocator.free(plain);
    const entries = try parse(allocator, plain);
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("GAME.PCE", entries[1].name);
    try std.testing.expectEqualStrings("rom bytes rom bytes rom bytes", plain[entries[1].offset..][0..entries[1].size]);
}

fn expect_rejected(plain: []const u8, expected: anyerror) !void {
    try std.testing.expectError(expected, parse(std.testing.allocator, plain));
}

test "container parser rejects every malformed layout" {
    const allocator = std.testing.allocator;
    const good = try build_container(allocator, &sample_files);
    defer allocator.free(good);
    const table = header_size;
    var bad = try allocator.dupe(u8, good);
    defer allocator.free(bad);

    bad[0] ^= 1;
    try expect_rejected(bad, error.InvalidPceContainer);
    bad[0] ^= 1;
    try expect_rejected(good[0 .. header_size - 1], error.InvalidPceContainer);

    std.mem.writeInt(u32, bad[0x28..0x2c], 4097, .little);
    try expect_rejected(bad, error.TooManyPceEntries);
    std.mem.writeInt(u32, bad[0x28..0x2c], 0, .little);
    try expect_rejected(bad, error.InvalidPceContainer);
    std.mem.writeInt(u32, bad[0x28..0x2c], 4096, .little); // table beyond the buffer
    try expect_rejected(bad, error.InvalidPceContainer);
    std.mem.writeInt(u32, bad[0x28..0x2c], 3, .little);

    // Payload outside the file, inside the table, and overlapping its neighbour.
    std.mem.writeInt(u32, bad[table + 0x44 ..][0..4], @intCast(good.len), .little);
    try expect_rejected(bad, error.InvalidPceEntry);
    @memcpy(bad[table + 0x44 ..][0..4], good[table + 0x44 ..][0..4]);
    std.mem.writeInt(u32, bad[table + 0x40 ..][0..4], header_size, .little);
    try expect_rejected(bad, error.InvalidPceEntry);
    @memcpy(bad[table + 0x40 ..][0..4], good[table + 0x40 ..][0..4]);
    @memcpy(bad[table + entry_size + 0x40 ..][0..4], good[table + 0x40 ..][0..4]);
    try expect_rejected(bad, error.OverlappingPceEntries);
    @memcpy(bad[table + entry_size + 0x40 ..][0..4], good[table + entry_size + 0x40 ..][0..4]);

    // Trailers must be zero.
    bad[table + 0x4f] = 1;
    try expect_rejected(bad, error.InvalidPceTrailer);
    bad[table + 0x4f] = 0;

    // Unsafe, empty, duplicate and unpadded names.
    for ([_][]const u8{ "", "..", ".", "a/b", "a\\b", "c:x", "sp ace", "caf\xc3\xa9", "tab\tx" }) |name| {
        @memset(bad[table..][0..name_size], 0);
        @memcpy(bad[table..][0..name.len], name);
        try expect_rejected(bad, error.InvalidPceName);
    }
    @memcpy(bad[table..][0..name_size], good[table..][0..name_size]);
    bad[table + 0x20] = 'x'; // data after the NUL terminator
    try expect_rejected(bad, error.InvalidPceName);
    @memcpy(bad[table..][0..name_size], good[table..][0..name_size]);
    @memset(bad[table + entry_size ..][0..name_size], 0);
    @memcpy(bad[table + entry_size ..][0.."config.ps3".len], "config.ps3"); // duplicate, other case
    try expect_rejected(bad, error.DuplicatePceName);
}

test "TOC parser reads tracks and rejects anything else" {
    const allocator = std.testing.allocator;
    const text = "readwait,0.20\r\nplaywait,0.00\r\ntrack01,audio,X_01.at3,000150,003596\r\ntrack02,code ,X_02.bin,003746,000008\r\n\r\n";
    const tracks = try parse_toc(allocator, text);
    defer allocator.free(tracks);
    try std.testing.expectEqual(@as(usize, 2), tracks.len);
    try std.testing.expect(!tracks[0].code and tracks[1].code);
    try std.testing.expectEqualStrings("X_02.bin", tracks[1].file);
    try std.testing.expectEqual(@as(u32, 3746), tracks[1].start);
    try std.testing.expectEqual(@as(u32, 8), tracks[1].length);
    for ([_][]const u8{
        "", "track01,audio,a.at3,1", "track01,video,a.at3,1,1", "trackxx,code,a.bin,1,1", "track01,code,a/b.bin,1,1",
        "track02,code,a.bin,1,1\ntrack01,code,b.bin,1,1", "track01,code,a.bin,1,1,1", "track01,code,a.bin,-1,1", "comment",
        "track01,code,..,1,1", "track01,code,a.bin,1,99999999999", "readwait,0.20\nreadwait,0.20\ntrack01,code,a.bin,1,1",
        "readwait,x\ntrack01,code,a.bin,1,1", "track01,code,a.bin,1,1\nreadwait,0.20",
    }) |bad| try std.testing.expectError(error.InvalidPceToc, parse_toc(allocator, bad));
}

fn sample_image(allocator: std.mem.Allocator, sectors: usize) ![]u8 {
    const image = try allocator.alloc(u8, sectors * sector_size);
    for (image, 0..) |*byte, index| byte.* = @truncate(index / 5);
    @memcpy(image[ipl_offset..][0..ipl_signature.len], ipl_signature);
    return image;
}

test "data track inflates to the TOC-sized image" {
    const allocator = std.testing.allocator;
    // 0x40000 + 0x1000 bytes: two chunks, the second one short.
    const image = try sample_image(allocator, chunk_size / sector_size + 2);
    defer allocator.free(image);
    const track = try build_track(allocator, image);
    defer allocator.free(track);
    const sectors: u32 = @intCast(image.len / sector_size);
    const decoded = try decode_track(allocator, track, sectors, true);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, image, decoded);
    // Other data tracks are not required to carry the IPL header.
    image[ipl_offset] = 'X';
    const other = try build_track(allocator, image);
    defer allocator.free(other);
    try std.testing.expectError(error.InvalidPceTrack, decode_track(allocator, other, sectors, true));
    const no_ipl = try decode_track(allocator, other, sectors, false);
    allocator.free(no_ipl);
}

test "data track tolerates alignment padding but not trailing data" {
    const allocator = std.testing.allocator;
    const image = try sample_image(allocator, 8);
    defer allocator.free(image);
    for ([_]usize{ 0, 1 }) |extra| {
        const padded = try build_padded_track(allocator, image, extra);
        defer allocator.free(padded);
        const result = decode_track(allocator, padded, 8, true);
        if (extra == 0) {
            const decoded = try result;
            defer allocator.free(decoded);
            try std.testing.expectEqualSlices(u8, image, decoded);
        } else {
            try std.testing.expectError(error.InvalidPceTrack, result);
        }
    }
    // An unaligned stream size is rejected even when its inflated bytes are right.
    const good = try build_track(allocator, image);
    defer allocator.free(good);
    const unaligned = try allocator.dupe(u8, good);
    defer allocator.free(unaligned);
    std.mem.writeInt(u32, unaligned[8..12], std.mem.readInt(u32, good[8..12], .little) - 1, .little);
    try std.testing.expectError(error.InvalidPceTrack, decode_track(allocator, unaligned, 8, true));
}

test "data track rejects length, structure and stream damage" {
    const allocator = std.testing.allocator;
    const image = try sample_image(allocator, chunk_size / sector_size + 2);
    defer allocator.free(image);
    const sectors: u32 = @intCast(image.len / sector_size);
    const good = try build_track(allocator, image);
    defer allocator.free(good);
    const bad = try allocator.dupe(u8, good);
    defer allocator.free(bad);
    const expect = struct {
        fn rejected(bytes: []const u8, count: u32) !void {
            try std.testing.expectError(error.InvalidPceTrack, decode_track(std.testing.allocator, bytes, count, false));
        }
    }.rejected;

    // The TOC length must match exactly: longer, shorter, zero, and past the cap.
    try expect(good, sectors + 1);
    try expect(good, sectors - 1);
    try expect(good, sectors + chunk_size / sector_size);
    try expect(good, 0);
    try expect(good, max_iso_size / sector_size + 1);
    // Truncated container and zlib stream; trailing garbage.
    try expect(good[0 .. good.len - 1], sectors);
    try expect(good[0..7], sectors);
    var longer = try allocator.alloc(u8, good.len + 1);
    defer allocator.free(longer);
    @memcpy(longer[0..good.len], good);
    longer[good.len] = 0;
    try expect(longer, sectors);
    // Table: wrong count, overlap, gap, out-of-range, zero size.
    std.mem.writeInt(u32, bad[0..4], 3, .little);
    try expect(bad, sectors);
    @memcpy(bad, good);
    @memcpy(bad[12..16], good[4..8]); // second stream starts where the first does
    try expect(bad, sectors);
    @memcpy(bad, good);
    std.mem.writeInt(u32, bad[12..16], std.mem.readInt(u32, good[12..16], .little) + 1, .little); // gap
    try expect(bad, sectors);
    @memcpy(bad, good);
    std.mem.writeInt(u32, bad[8..12], 0, .little);
    try expect(bad, sectors);
    @memcpy(bad, good);
    std.mem.writeInt(u32, bad[8..12], @intCast(good.len), .little);
    try expect(bad, sectors);
    // A corrupted deflate stream and a stream that inflates too short / too long.
    @memcpy(bad, good);
    bad[good.len - 5] ^= 0xff;
    try expect(bad, sectors);
    const short_image = try allocator.dupe(u8, image[0 .. image.len - 16]);
    defer allocator.free(short_image);
    const short = try build_track(allocator, short_image);
    defer allocator.free(short);
    try expect(short, sectors);
    const long_image = try allocator.alloc(u8, image.len + 16);
    defer allocator.free(long_image);
    @memcpy(long_image[0..image.len], image);
    @memset(long_image[image.len..], 7);
    const long = try build_track(allocator, long_image);
    defer allocator.free(long);
    try expect(long, sectors);
}
