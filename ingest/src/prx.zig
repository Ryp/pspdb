const std = @import("std");

const gzip_decoder = @import("gzip.zig");
const kle = @import("kle.zig");
const lzr_decoder = @import("lzr.zig");

const prx_encrypt = @import("zig_psp_prx_encrypt");

extern fn pspdb_prx_decode(input: [*]const u8, input_len: usize, output: [*]u8, output_len: usize) c_int;

const max_decoded_size = 64 << 20;

/// Decrypt a ~PSP module or PSPsysGP resource and expand any gzip/KL/LZR payload.
/// The caller owns the result; input may be unaligned and is never changed.
/// Uses upstream's type fallback and integrity checks, not full authentication:
/// Type-6 and type-9 ECDSA signatures are not authenticated.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len < 0x150) return error.InvalidPrx;
    const module = std.mem.startsWith(u8, bytes, "~PSP");
    if (!module and !std.mem.startsWith(u8, bytes, "PSPsysGP")) return error.InvalidPrx;
    if (bytes.len > std.math.maxInt(c_int)) return error.InvalidPrxSize;
    const expected = std.mem.readInt(u32, bytes[0xb0..0xb4], .little);
    if (expected == 0 or expected > bytes.len) return error.InvalidPrxSize;
    const elf_size = std.mem.readInt(u32, bytes[0x28..0x2c], .little);
    // PSPsysGP shares KIRK offsets, but not the module compression fields.
    const attributes = if (module) std.mem.readInt(u16, bytes[6..8], .little) else 0;

    // Upstream reconstructs KIRK headers in this buffer before decrypting over
    // them. Keep its full workspace until it finishes; never shrink an intermediate.
    const output = try allocator.alloc(u8, bytes.len);
    errdefer allocator.free(output);
    const result = pspdb_prx_decode(bytes.ptr, bytes.len, output.ptr, output.len);
    switch (result) {
        -1 => return error.InvalidPrx,
        -2 => return error.InvalidPrxSize,
        -3 => return error.PrxDecryptionFailed,
        -4 => return error.PrxSizeMismatch,
        else => if (result <= 0 or result != expected) return error.PrxSizeMismatch,
    }
    if (try expand_payload(allocator, output[0..expected], if (attributes & 1 != 0) elf_size else null)) |expanded| {
        allocator.free(output);
        return expanded;
    }
    // Uncompressed envelopes may include data beyond elf_size (e.g. update PRXs).
    // Preserve the complete KIRK-declared payload rather than truncating it.
    return allocator.realloc(output, expected);
}

fn expand_payload(allocator: std.mem.Allocator, payload: []const u8, declared_size: ?usize) !?[]u8 {
    const gzip = std.mem.startsWith(u8, payload, "\x1f\x8b");
    const kl = std.mem.startsWith(u8, payload, "KL3E") or std.mem.startsWith(u8, payload, "KL4E");
    const lzr = std.mem.startsWith(u8, payload, "2RLZ");
    if (!gzip and !kl and !lzr) return null;
    if (declared_size) |size| {
        if (size == 0 or size > max_decoded_size) return error.InvalidPrxSize;
        const output = try allocator.alloc(u8, size);
        errdefer allocator.free(output);
        const actual = (if (gzip)
            gzip_decoder.decode_member_into(payload, output)
        else if (kl)
            kle.decodeInto(payload, output)
        else
            lzr_decoder.decodeInto(payload, output)) catch |err| return switch (err) {
            error.GzipOutputTooSmall, error.KleOutputTooSmall, error.LzrOutputTooSmall => error.PrxSizeMismatch,
            else => err,
        };
        if (actual != size) return error.PrxSizeMismatch;
        return output;
    }
    // Firmware resources can use an uncompressed ~PSP envelope around a
    // KL/LZR/gzip stream: elf_size then describes that stream, not its expanded
    // bytes. Firmware callers supply capacity (e.g. loadexec's 2 MiB reboot
    // buffer), not exact size. Keep the same bounded policy for every codec.
    return if (gzip)
        try gzip_decoder.decode_member_bounded(allocator, payload, max_decoded_size)
    else if (kl)
        try kle.decode(allocator, payload)
    else
        try lzr_decoder.decode(allocator, payload);
}

test "contextual KL enforces declared output only when the envelope declares compression" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "KL3E", "KL4E" }) |magic| {
        var payload = "KL3E\x80\x00\x00\x00\x03abc".*;
        @memcpy(payload[0..4], magic);
        const original = payload;
        var storage: [3]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&storage);
        const exact = (try expand_payload(fixed.allocator(), &payload, 3)).?;
        defer fixed.allocator().free(exact);
        try std.testing.expectEqualStrings("abc", exact);
        try std.testing.expectEqualSlices(u8, &original, &payload);
        try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, &payload, 2));
        try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, &payload, 4));
        try std.testing.expectError(error.InvalidKle, expand_payload(allocator, payload[0 .. payload.len - 1], 3));
        const resource = (try expand_payload(allocator, &payload, null)).?;
        defer allocator.free(resource);
        try std.testing.expectEqualStrings("abc", resource);
    }
    const coded = "KL4E\x07\x90\xcc\xe4\x56\xe6\x8a\x53\x77\x3b\x32\x9d\x00\x00\x00";
    const expanded = (try expand_payload(allocator, coded, 8)).?;
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("offsets!", expanded);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 7));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 9));
}

test "contextual LZR expands resource streams and enforces compressed envelope size" {
    const allocator = std.testing.allocator;
    const direct = "2RLZ\xff\x00\x00\x00\x03abc\xa5";
    var storage: [3]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const exact = (try expand_payload(fixed.allocator(), direct, 3)).?;
    defer fixed.allocator().free(exact);
    try std.testing.expectEqualStrings("abc", exact);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, direct, 2));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, direct, 4));
    try std.testing.expectError(error.InvalidLzr, expand_payload(allocator, direct[0 .. direct.len - 1], 3));

    const coded = "2RLZ\x08\xc8\x63\x3d\xbe\x16\x38\x4a\xd2\x32\xf6\x60\x00\x00\x00";
    const resource = (try expand_payload(allocator, coded, null)).?;
    defer allocator.free(resource);
    try std.testing.expectEqualStrings("offsets!", resource);
    const expanded = (try expand_payload(allocator, coded, 8)).?;
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("offsets!", expanded);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 7));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 9));
    try std.testing.expectError(error.InvalidLzr, expand_payload(allocator, coded[0 .. coded.len - 1], 8));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, coded, max_decoded_size + 1));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, coded, 0));
}

test "contextual gzip checks declared length after a complete member" {
    const member = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x01\x03\x00\xfc\xffabc\xc2\x41\x24\x35\x03\x00\x00\x00";
    const allocator = std.testing.allocator;
    const output = (try expand_payload(allocator, member ++ "\x00envelope tail", 3)).?;
    defer allocator.free(output);
    try std.testing.expectEqualStrings("abc", output);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, member, 2));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, member, 4));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, member, max_decoded_size + 1));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, member, 0));
}

fn signed_fixture(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var input: std.Io.Reader = .fixed(payload);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try prx_encrypt.encrypt(allocator, &input, payload.len, &output.writer);
    return output.toOwnedSlice();
}

test "PRX rejects truncated headers and impossible declared sizes" {
    var bytes: [0x150]u8 = @splat(0);
    @memcpy(bytes[0..4], "~PSP");
    try std.testing.expectError(error.InvalidPrx, decode(std.testing.allocator, bytes[0..0x14f]));
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes));
    std.mem.writeInt(u32, bytes[0xb0..0xb4], bytes.len + 1, .little);
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes));
    std.mem.writeInt(u32, bytes[0xb0..0xb4], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes));
}

test "PRX preserves unaligned input and rejects truncation or modified headers" {
    const allocator = std.testing.allocator;
    const payload = "\x7fELF native PRX immutable input";
    const fixture = try signed_fixture(allocator, payload);
    defer allocator.free(fixture);
    const storage = try allocator.alloc(u8, fixture.len + 1);
    defer allocator.free(storage);
    const unaligned = storage[1..];
    @memcpy(unaligned, fixture);
    const output = try decode(allocator, unaligned);
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, fixture, unaligned);
    try std.testing.expectEqual(std.mem.readInt(u32, fixture[0x28..0x2c], .little), output.len);
    // The signer pads the ELF before compression and forges a CMAC block after
    // the member. PRX consumes one complete member, not those envelope bytes.
    try std.testing.expectEqualSlices(u8, payload, output[0..payload.len]);
    try std.testing.expect(std.mem.allEqual(u8, output[payload.len..], 0));

    // Missing CBC padding previously let libkirk read a block beyond the file.
    try std.testing.expectError(error.PrxDecryptionFailed, decode(allocator, unaligned[0 .. unaligned.len - 1]));
    unaligned[0x0a] ^= 1;
    try std.testing.expectError(error.PrxDecryptionFailed, decode(allocator, unaligned));
}

test "concurrent PRX jobs retain independent KIRK state and owned results" {
    const allocator = std.testing.allocator;
    const first = try signed_fixture(allocator, "\x7fELF first concurrent PRX");
    defer allocator.free(first);
    const second = try signed_fixture(allocator, "\x7fELF second concurrent PRX");
    defer allocator.free(second);
    const first_plain = try decode(allocator, first);
    defer allocator.free(first_plain);
    const second_plain = try decode(allocator, second);
    defer allocator.free(second_plain);

    const Worker = struct {
        start: *std.atomic.Value(bool),
        input: []const u8,
        expected: []const u8,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
            self.check() catch |err| {
                self.failure = err;
            };
        }

        fn check(self: *@This()) !void {
            for (0..4) |_| {
                const decoded = try decode(std.heap.page_allocator, self.input);
                defer std.heap.page_allocator.free(decoded);
                if (!std.mem.eql(u8, self.expected, decoded)) return error.ConcurrentPrxMismatch;
            }
        }
    };
    var start: std.atomic.Value(bool) = .init(false);
    var workers: [4]Worker = undefined;
    {
        var threads: [workers.len]std.Thread = undefined;
        var spawned: usize = 0;
        defer {
            start.store(true, .release);
            for (threads[0..spawned]) |thread| thread.join();
        }
        for (&workers, 0..) |*worker, index| {
            worker.* = .{
                .start = &start,
                .input = if (index % 2 == 0) first else second,
                .expected = if (index % 2 == 0) first_plain else second_plain,
            };
            threads[index] = try std.Thread.spawn(.{}, Worker.run, .{worker});
            spawned += 1;
        }
        start.store(true, .release);
    }
    for (workers) |worker| if (worker.failure) |err| return err;
}
