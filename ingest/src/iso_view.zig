const std = @import("std");
const c = @import("archive");

/// Feed libarchive borrowed ISO bytes, except for a copied PSP descriptor.
/// Observed PSP images use type/version/file-structure-version 1/1/2, which
/// libarchive rejects. Present 1/1/1 to it without modifying the source slice.
/// This tolerates the mastering convention; it does not claim full enhanced
/// ISO9660 semantics. Libarchive still owns general filesystem parsing.
pub const IsoView = struct {
    bytes: []const u8,
    offset: usize = 0,
    descriptors: bool = true,
    descriptor_copy: [2048]u8 = undefined,

    fn next(self: *IsoView) []const u8 {
        const remaining = self.bytes[self.offset..];
        if (remaining.len == 0) return remaining;
        var chunk = remaining;
        if (self.offset < 16 * 2048) {
            chunk = remaining[0..@min(remaining.len, 16 * 2048 - self.offset)];
        } else if (self.descriptors) {
            if (remaining.len >= 2048 and std.mem.eql(u8, remaining[1..6], "CD001")) {
                chunk = remaining[0..2048];
                if (chunk[0] == 255) self.descriptors = false;
                if (chunk[0] == 1 and chunk[6] == 1 and chunk[881] == 2) {
                    @memcpy(&self.descriptor_copy, chunk);
                    self.descriptor_copy[881] = 1;
                    chunk = &self.descriptor_copy;
                }
            } else {
                self.descriptors = false;
            }
        }
        self.offset += chunk.len;
        return chunk;
    }

    pub fn read(_: ?*c.struct_archive, context: ?*anyopaque, buffer: [*c]?*const anyopaque) callconv(.c) isize {
        const self: *IsoView = @ptrCast(@alignCast(context.?));
        const chunk = self.next();
        buffer.* = chunk.ptr;
        return @intCast(chunk.len);
    }
};

/// A mastering container has exactly these four regular root files. The
/// bounded slices retain the original container bytes, including its inner ISO.
pub const Mastering = struct {
    pub const names = [_][]const u8{ "CONT_L0.IMG", "MDI.IMG", "UMD_AUTH.DAT", "USER_L0.IMG" };
    files: [names.len][]const u8,

    pub fn logical_bytes(self: Mastering) []const u8 {
        return self.files[3];
    }
};

fn dual32(bytes: []const u8) !u32 {
    const value = std.mem.readInt(u32, bytes[0..4], .little);
    if (value != std.mem.readInt(u32, bytes[4..8], .big)) return error.InvalidIso;
    return value;
}

fn dual16(bytes: []const u8) !u16 {
    const value = std.mem.readInt(u16, bytes[0..2], .little);
    if (value != std.mem.readInt(u16, bytes[2..4], .big)) return error.InvalidIso;
    return value;
}

fn extent(bytes: []const u8, record: []const u8) ![]const u8 {
    if (record.len < 34 or record[1] != 0 or record[26] != 0 or record[27] != 0 or
        try dual16(record[28..32]) != 1) return error.InvalidIso;
    const offset = @as(u64, try dual32(record[2..10])) * 2048;
    const length = try dual32(record[10..18]);
    if (offset > bytes.len or length > bytes.len - offset) return error.InvalidIso;
    return bytes[@intCast(offset)..][0..length];
}

fn primary_volume(bytes: []const u8) ![]const u8 {
    if (bytes.len < 17 * 2048) return error.InvalidIso;
    const descriptor = bytes[16 * 2048 ..][0..2048];
    if (descriptor[0] != 1 or !std.mem.eql(u8, descriptor[1..6], "CD001") or descriptor[6] != 1 or
        (descriptor[881] != 1 and descriptor[881] != 2) or
        try dual16(descriptor[128..132]) != 2048) return error.InvalidIso;
    const length = @as(u64, try dual32(descriptor[80..88])) * 2048;
    if (length < 17 * 2048 or length > bytes.len) return error.InvalidIso;
    const volume = bytes[0..@intCast(length)];
    const root_length = descriptor[156];
    if (root_length < 34 or descriptor[181] != 2) return error.InvalidIso;
    _ = try extent(volume, descriptor[156..][0..root_length]);
    return volume;
}

/// This is only an extent locator for the proved mastering layout, not a
/// general ISO filesystem parser. The reader also verifies libarchive's names
/// and regular-file types before using these slices.
pub fn mastering(bytes: []const u8) !?Mastering {
    const volume = try primary_volume(bytes);
    const descriptor = volume[16 * 2048 ..][0..2048];
    const root = try extent(volume, descriptor[156..][0..descriptor[156]]);
    var result: Mastering = undefined;
    var found = [_]bool{false} ** Mastering.names.len;
    var offset: usize = 0;
    while (offset < root.len) {
        const length = root[offset];
        if (length == 0) {
            offset += @min(root.len - offset, 2048 - offset % 2048);
            continue;
        }
        if (length < 34 or length > root.len - offset or length > 2048 - offset % 2048) return error.InvalidIso;
        const record = root[offset..][0..length];
        offset += length;
        const name_length = record[32];
        if (name_length == 0 or name_length > record.len - 33) return error.InvalidIso;
        var name = record[33..][0..name_length];
        if (name.len == 1 and name[0] <= 1) continue;
        if (std.mem.endsWith(u8, name, ";1")) name = name[0 .. name.len - 2];
        const index = for (Mastering.names, 0..) |expected, candidate_index| {
            if (std.mem.eql(u8, name, expected)) break candidate_index;
        } else return null;
        if (found[index] or record[25] != 0) return error.InvalidIsoMasteringWrapper;
        found[index] = true;
        result.files[index] = try extent(volume, record);
    }
    for (found) |present| if (!present) return null;
    _ = try primary_volume(result.logical_bytes());
    return result;
}

test "PSP view changes only descriptor version and never source bytes" {
    var bytes = [_]u8{0} ** (20 * 2048);
    const base = 16 * 2048;
    bytes[base] = 1;
    @memcpy(bytes[base + 1 ..][0..5], "CD001");
    bytes[base + 6] = 1;
    bytes[base + 881] = 2;
    bytes[base + 2048] = 255;
    @memcpy(bytes[base + 2049 ..][0..5], "CD001");
    var view: IsoView = .{ .bytes = &bytes };
    const before = bytes;
    try std.testing.expectEqual(bytes[0..base].ptr, view.next().ptr);
    const descriptor = view.next();
    try std.testing.expectEqual(@as(u8, 1), descriptor[881]);
    try std.testing.expectEqualSlices(u8, bytes[base..][0..881], descriptor[0..881]);
    try std.testing.expectEqualSlices(u8, bytes[base + 882 ..][0 .. 2048 - 882], descriptor[882..]);
    try std.testing.expectEqual(bytes[base + 2048 ..].ptr, view.next().ptr);
    try std.testing.expectEqual(bytes[base + 4096 ..].ptr, view.next().ptr);
    try std.testing.expectEqual(@as(usize, 0), view.next().len);
    try std.testing.expectEqualSlices(u8, &before, &bytes);
}
