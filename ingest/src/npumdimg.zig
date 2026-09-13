const std = @import("std");

extern fn pspdb_npumdimg_decode(
    source: [*]const u8,
    size: usize,
    allocate: *const fn (*anyopaque, usize) callconv(.c) ?[*]u8,
    context: *anyopaque,
) c_int;

const Allocation = struct {
    allocator: std.mem.Allocator,
    output: ?[]u8 = null,

    fn allocate(context: *anyopaque, size: usize) callconv(.c) ?[*]u8 {
        const self: *Allocation = @ptrCast(@alignCast(context));
        const output = self.allocator.alloc(u8, size) catch return null;
        self.output = output;
        return output.ptr;
    }
};

/// Decode NPUMDIMG using pinned pkg2zip AES/LZRC, entirely in memory. The
/// immutable input is borrowed and may be unaligned; the caller owns the exact
/// padded ISO allocation (including the complete final block). Every failure
/// discards partial output. Header/key derivation and the inherited ISO PVD
/// sanity check do not authenticate the image or its contents.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var allocation: Allocation = .{ .allocator = allocator };
    errdefer if (allocation.output) |output| allocator.free(output);
    switch (pspdb_npumdimg_decode(bytes.ptr, bytes.len, Allocation.allocate, &allocation)) {
        0 => {},
        1 => return error.InvalidNpumdimg,
        2 => return error.UnsupportedNpumdimgBlockSize,
        3 => return error.InvalidNpumdimgSectorRange,
        4 => return error.InvalidNpumdimgTable,
        5 => return error.InvalidNpumdimgBlock,
        6 => return error.InvalidNpumdimgLzrc,
        7 => return error.InvalidNpumdimgOutputSize,
        8 => return error.OutOfMemory,
        else => return error.NpumdimgNativeFailure,
    }
    const output = allocation.output orelse return error.NpumdimgNativeFailure;
    // Preserve the former adapter's exact byte check, not a broader ISO parser.
    if (output.len < 32775 or !std.mem.eql(u8, output[32768..32775], "\x01CD001\x01"))
        return error.InvalidNpumdimgIso;
    return output;
}
