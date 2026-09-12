const std = @import("std");
const c = @import("archive");

/// Feed libarchive borrowed ISO bytes, except for a copied PSP descriptor.
/// Observed PSP images use type/version/file-structure-version 1/1/2, which
/// libarchive rejects. Present 1/1/1 to it without modifying the source slice.
/// This tolerates the mastering convention; it does not claim full enhanced
/// ISO9660 semantics. All filesystem parsing remains libarchive's job.
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
