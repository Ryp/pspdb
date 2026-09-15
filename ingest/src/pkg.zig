//! Read retail PSP/PS1 PKGs without filtering or rewriting their entry paths.
//! Format reference: mmozeiko/pkg2zip pkg2zip.c (header, entry table, AES-CTR).
const std = @import("std");
const memory = @import("bytes.zig");
const crypto = @import("zig_psp_pkg_crypto");

fn integer(comptime T: type, bytes: []const u8, offset: usize) !T {
    if (offset > bytes.len or @sizeOf(T) > bytes.len - offset) return error.InvalidPkg;
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .big);
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
        const cid = std.mem.sliceTo(bytes[48..96], 0);
        if (cid.len != 36 or cid[6] != '-' or cid[16] != '_' or cid[19] != '-' or !std.unicode.utf8ValidateSlice(cid)) return error.InvalidPkg;
        for (cid) |c| if (c < 32 or c > 126) return error.InvalidPkg;
        var result: Package = .{ .bytes = bytes, .encrypted = bytes[offset..][0..size], .iv = bytes[112..128].*, .count = try integer(u32, bytes, 20), .table = 0, .content_id = cid, .content_type = 0 };
        var pos: usize = try integer(u32, bytes, 8);
        const count = try integer(u32, bytes, 12);
        const meta_size: usize = try integer(u32, bytes, 16);
        if (pos < 192 or pos > offset or meta_size > offset - pos) return error.InvalidPkg;
        const end = pos + meta_size;
        for (0..count) |_| {
            if (pos > end or end - pos < 8) return error.InvalidPkg;
            const kind = try integer(u32, bytes, pos);
            const length: usize = try integer(u32, bytes, pos + 4);
            pos += 8;
            if (length > end - pos) return error.InvalidPkg;
            const value = bytes[pos..][0..length];
            if (kind == 2) result.content_type = try integer(u32, value, 0);
            if (kind == 3) result.package_flags = try integer(u32, value, 0);
            if (kind == 13) result.table = try integer(u32, value, 0);
            pos += length;
        }
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
