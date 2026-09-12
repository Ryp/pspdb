const std = @import("std");
extern fn pops_decrypt(psp: [*]const u8, psp_size: usize, data: [*]const u8, data_size: usize, output: [*]u8) c_int;
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3) return error.ExpectedPbpAndOutput;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], a, .unlimited);
    const pbp = try @import("pbp").Pbp.parse(bytes);
    const psp = pbp.get("DATA.PSP") orelse return error.MissingExecutable;
    const data = pbp.get("DATA.BIN") orelse return error.MissingDiscPayload;
    const output = try a.alloc(u8, psp.len);
    const size = pops_decrypt(psp.ptr, psp.len, data.ptr, data.len, output.ptr);
    if (size < 0) {
        std.debug.print("POPS decryption failed: {d}\n", .{size});
        return error.PopsDecryptionFailed;
    }
    if (size == 0 or size > output.len) return error.InvalidOutputSize;
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = args[2], .data = output[0..@intCast(size)] });
}
