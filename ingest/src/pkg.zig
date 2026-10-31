//! Read retail PSP/PS1 PKGs without filtering or rewriting their entry paths.
//! Format reference: mmozeiko/pkg2zip pkg2zip.c (header, entry table, AES-CTR).
const std = @import("std");
const memory = @import("bytes.zig");
const crypto = @import("zig_psp_pkg_crypto");

fn integer(comptime T: type, bytes: []const u8, offset: usize) !T {
    if (offset > bytes.len or @sizeOf(T) > bytes.len - offset) return error.InvalidPkg;
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .big);
}

/// Identity fields from the unencrypted header. They are readable even when
/// the platform, content type or payload is unsupported, so a failed package
/// can still be catalogued under its content ID.
pub const Header = struct {
    content_id: []const u8,
    content_type: ?u32 = null,
    package_flags: ?u32 = null,
    table: ?u32 = null,
};

pub fn read_header(bytes: []const u8) !Header {
    if (bytes.len < 192 or !std.mem.eql(u8, bytes[0..4], "\x7fPKG")) return error.InvalidPkg;
    const cid = std.mem.sliceTo(bytes[48..96], 0);
    if (cid.len != 36 or cid[6] != '-' or cid[16] != '_' or cid[19] != '-' or !std.unicode.utf8ValidateSlice(cid)) return error.InvalidPkg;
    for (cid) |c| if (c < 32 or c > 126) return error.InvalidPkg;
    var header: Header = .{ .content_id = cid };
    var pos: usize = try integer(u32, bytes, 8);
    const count = try integer(u32, bytes, 12);
    const meta_size: usize = try integer(u32, bytes, 16);
    if (pos < 192 or pos > bytes.len or meta_size > bytes.len - pos) return error.InvalidPkg;
    const end = pos + meta_size;
    for (0..count) |_| {
        if (pos > end or end - pos < 8) return error.InvalidPkg;
        const kind = try integer(u32, bytes, pos);
        const length: usize = try integer(u32, bytes, pos + 4);
        pos += 8;
        if (length > end - pos) return error.InvalidPkg;
        const value = bytes[pos..][0..length];
        if (kind == 2) header.content_type = try integer(u32, value, 0);
        if (kind == 3) header.package_flags = try integer(u32, value, 0);
        if (kind == 13) header.table = try integer(u32, value, 0);
        pos += length;
    }
    return header;
}

pub const Package = struct {
    bytes: []const u8,
    encrypted: []const u8,
    iv: [16]u8,
    count: usize,
    table: usize,
    content_id: []const u8,
    content_type: u32,
    package_flags: ?u32 = null,

    pub fn init(bytes: []const u8) !Package {
        if (bytes.len < 192 or !std.mem.eql(u8, bytes[0..4], "\x7fPKG")) return error.InvalidPkg;
        if (try integer(u16, bytes, 4) != 0x8000 or try integer(u16, bytes, 6) != 2) return error.UnsupportedPkg;
        if (try integer(u64, bytes, 24) != bytes.len) return error.InvalidPkg;
        const offset = std.math.cast(usize, try integer(u64, bytes, 32)) orelse return error.InvalidPkg;
        const size = std.math.cast(usize, try integer(u64, bytes, 40)) orelse return error.InvalidPkg;
        if (offset < 192 or offset > bytes.len or size > bytes.len - offset) return error.InvalidPkg;
        const header = try read_header(bytes);
        // The metadata table must also end before the encrypted payload.
        const meta_pos: usize = try integer(u32, bytes, 8);
        if (meta_pos > offset or try integer(u32, bytes, 16) > offset - meta_pos) return error.InvalidPkg;
        const result: Package = .{ .bytes = bytes, .encrypted = bytes[offset..][0..size], .iv = bytes[112..128].*, .count = try integer(u32, bytes, 20), .table = header.table orelse 0, .content_id = header.content_id, .content_type = header.content_type orelse 0, .package_flags = header.package_flags };
        // Type 9 includes PSP themes; PS3 themes remain excluded by the platform check.
        switch (result.content_type) {
            6, 7, 9, 0xe, 0xf, 0x10 => {},
            else => return error.UnsupportedPkg,
        }
        if (result.table % 16 != 0 or result.table > size or result.count > (size - result.table) / 32) return error.InvalidPkg;
        return result;
    }

    fn decrypt(self: Package, offset: usize, output: []u8, key: crypto.Key) !void {
        if (offset % 16 != 0 or offset > self.encrypted.len or output.len > self.encrypted.len - offset) return error.InvalidPkg;
        crypto.crypt(key, &self.iv, offset, self.encrypted[offset..][0..output.len], output);
    }

    const Entry = struct {
        name: []u8,
        offset: usize,
        size: usize,
        key: crypto.Key,
        directory: bool,
    };

    fn entry(self: Package, allocator: std.mem.Allocator, index: usize) !Entry {
        var raw: [32]u8 = undefined;
        try self.decrypt(self.table + index * 32, &raw, .psp);
        const no: usize = try integer(u32, &raw, 0);
        const ns: usize = try integer(u32, &raw, 4);
        const offset = std.math.cast(usize, try integer(u64, &raw, 8)) orelse return error.InvalidPkg;
        const size = std.math.cast(usize, try integer(u64, &raw, 16)) orelse return error.InvalidPkg;
        if (ns == 0 or ns > 4096 or offset % 16 != 0 or offset > self.encrypted.len or size > self.encrypted.len - offset) return error.InvalidPkg;
        const key = crypto.entryKey(raw[24]);
        const name = try allocator.alloc(u8, ns);
        errdefer allocator.free(name);
        try self.decrypt(no, name, key);
        const directory = raw[27] == 4 or raw[27] == 18;
        if (directory and size != 0) return error.InvalidPkg;
        return .{ .name = name, .offset = offset, .size = size, .key = key, .directory = directory };
    }

    pub fn read_file(self: Package, allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
        for (0..self.count) |i| {
            const e = try self.entry(allocator, i);
            defer allocator.free(e.name);
            if (e.directory or !std.mem.eql(u8, e.name, path)) continue;
            const data = try allocator.alloc(u8, e.size);
            errdefer allocator.free(data);
            try self.decrypt(e.offset, data, e.key);
            return data;
        }
        return null;
    }

    /// Decrypt at most `len` bytes of one file starting at `offset`, without
    /// decrypting the rest of it. The range is clipped to the file: a start past
    /// the end yields an empty slice, a missing file `null`.
    pub fn read_file_range(self: Package, allocator: std.mem.Allocator, path: []const u8, offset: usize, len: usize) !?[]u8 {
        for (0..self.count) |i| {
            const e = try self.entry(allocator, i);
            defer allocator.free(e.name);
            if (e.directory or !std.mem.eql(u8, e.name, path)) continue;
            const start = @min(offset, e.size);
            const count = @min(len, e.size - start);
            // The CTR stream is addressed in whole blocks: decrypt from the
            // preceding block boundary and drop the lead-in.
            const lead = start % 16;
            const data = try allocator.alloc(u8, lead + count);
            errdefer allocator.free(data);
            try self.decrypt(e.offset + start - lead, data, e.key);
            if (lead != 0) std.mem.copyForwards(u8, data[0..count], data[lead..]);
            return try allocator.realloc(data, count);
        }
        return null;
    }

    pub fn walk(self: Package, allocator: std.mem.Allocator, context: anytype, comptime emit: anytype) !void {
        for (0..self.count) |i| {
            const e = try self.entry(allocator, i);
            defer allocator.free(e.name);
            if (e.directory) {
                try emit(context, e.name, null);
            } else {
                const data = try allocator.alloc(u8, e.size);
                const view = try memory.Owner.take_allocated(allocator, data);
                defer view.release();
                try self.decrypt(e.offset, data, e.key);
                try emit(context, e.name, view);
            }
        }
    }
};

test "invalid and unsupported PKG headers" {
    try std.testing.expectError(error.InvalidPkg, Package.init("not a package"));
    var bytes: [192]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x7fPKG");
    try std.testing.expectError(error.UnsupportedPkg, Package.init(&bytes));
}

test "header identity survives an unsupported platform" {
    var bytes: [256]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x7fPKG");
    std.mem.writeInt(u16, bytes[4..6], 0x8000, .big);
    std.mem.writeInt(u16, bytes[6..8], 1, .big); // PS3 platform
    @memcpy(bytes[48..84], "EP0082-NPEB00173_00-THEXDERNEO000000");
    std.mem.writeInt(u32, bytes[8..12], 192, .big);
    std.mem.writeInt(u32, bytes[12..16], 1, .big);
    std.mem.writeInt(u32, bytes[16..20], 12, .big);
    std.mem.writeInt(u32, bytes[192..196], 2, .big);
    std.mem.writeInt(u32, bytes[196..200], 4, .big);
    std.mem.writeInt(u32, bytes[200..204], 5, .big);
    try std.testing.expectError(error.UnsupportedPkg, Package.init(&bytes));
    const header = try read_header(&bytes);
    try std.testing.expectEqualStrings("EP0082-NPEB00173_00-THEXDERNEO000000", header.content_id);
    try std.testing.expectEqual(@as(?u32, 5), header.content_type);
    try std.testing.expectEqual(@as(?u32, null), header.package_flags);
    // A malformed content ID gives no identity at all.
    bytes[54] = 'X';
    try std.testing.expectError(error.InvalidPkg, read_header(&bytes));
}

test "ranged reads decrypt only the requested extent from any start" {
    const allocator = std.testing.allocator;
    var plain: [112]u8 = @splat(0);
    std.mem.writeInt(u32, plain[0..4], 32, .big);
    std.mem.writeInt(u32, plain[4..8], 3, .big);
    std.mem.writeInt(u64, plain[8..16], 48, .big);
    std.mem.writeInt(u64, plain[16..24], 64, .big);
    plain[24] = 0x90;
    plain[27] = 3;
    @memcpy(plain[32..35], "A/B");
    for (plain[48..], 0..) |*byte, i| byte.* = @truncate(i *% 5 +% 1);
    const payload = plain[48..].*;

    var bytes: [256 + plain.len]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x7fPKG");
    std.mem.writeInt(u16, bytes[4..6], 0x8000, .big);
    std.mem.writeInt(u16, bytes[6..8], 2, .big);
    std.mem.writeInt(u32, bytes[8..12], 192, .big);
    std.mem.writeInt(u32, bytes[12..16], 1, .big);
    std.mem.writeInt(u32, bytes[16..20], 12, .big);
    std.mem.writeInt(u32, bytes[20..24], 1, .big);
    std.mem.writeInt(u64, bytes[24..32], bytes.len, .big);
    std.mem.writeInt(u64, bytes[32..40], 256, .big);
    std.mem.writeInt(u64, bytes[40..48], plain.len, .big);
    @memcpy(bytes[48..84], "UP9000-NPUG00001_00-FIXTURE000000000");
    std.mem.writeInt(u32, bytes[192..196], 2, .big);
    std.mem.writeInt(u32, bytes[196..200], 4, .big);
    std.mem.writeInt(u32, bytes[200..204], 7, .big);
    crypto.crypt(.psp, bytes[112..128], 0, &plain, bytes[256..]);

    const package = try Package.init(&bytes);
    try std.testing.expectEqual(@as(?[]u8, null), try package.read_file_range(allocator, "A/C", 0, 16));
    for ([_]usize{ 0, 1, 15, 16, 17, 63, 64, 70 }) |start| {
        for ([_]usize{ 0, 1, 16, 100 }) |len| {
            const range = (try package.read_file_range(allocator, "A/B", start, len)).?;
            defer allocator.free(range);
            const from = @min(start, payload.len);
            try std.testing.expectEqualSlices(u8, payload[from..@min(start + len, payload.len)], range);
        }
    }
    const whole = (try package.read_file(allocator, "A/B")).?;
    defer allocator.free(whole);
    try std.testing.expectEqualSlices(u8, &payload, whole);
}
