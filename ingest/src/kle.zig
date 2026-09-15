//! In-memory KL3E/KL4E decoding using the pinned, bounds-checked pspdecrypt decoder.
const std = @import("std");
const decoded_output = @import("decoded.zig");

extern fn decompress_kle_bounded(output: [*]u8, output_size: c_int, input: [*]const u8, input_size: c_int, is_kl4e: c_int) c_int;

const output_too_small: c_int = @bitCast(@as(u32, 0x80000104));
const invalid_format: c_int = @bitCast(@as(u32, 0x80000108));
const max_decoded_size = 64 << 20;

/// Decode into borrowed, bounded storage without allocating or changing input.
/// A complete stream may use less than output.len; capacity exhaustion is
/// KleOutputTooSmall, distinct from malformed or truncated input.
pub fn decodeInto(bytes: []const u8, output: []u8) !usize {
    if (bytes.len < 9 or (!std.mem.eql(u8, bytes[0..4], "KL3E") and !std.mem.eql(u8, bytes[0..4], "KL4E"))) return error.InvalidKle;
    const input = bytes[4..];
    const input_size = std.math.cast(c_int, input.len) orelse return error.InvalidKle;
    if (output.len > max_decoded_size) return error.KleOutputTooLarge;
    const decoded = decompress_kle_bounded(output.ptr, @intCast(output.len), input.ptr, input_size, @intFromBool(bytes[2] == '4'));
    if (decoded == output_too_small) return error.KleOutputTooSmall;
    if (decoded <= 0) return error.InvalidKle;
    return @intCast(decoded);
}

/// The input is borrowed and immutable; the returned allocation belongs to the caller.
/// Empty, malformed and truncated streams are InvalidKle. Only capacity exhaustion
/// retries; exhausting the PSP's 64 MiB bound is KleOutputTooLarge.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len < 9 or (!std.mem.eql(u8, bytes[0..4], "KL3E") and !std.mem.eql(u8, bytes[0..4], "KL4E"))) return error.InvalidKle;
    const input = bytes[4..];
    _ = std.math.cast(c_int, input.len) orelse return error.InvalidKle;
    var capacity: usize = 1 << 20;
    if (input[0] & 0x80 != 0) {
        // Only direct-copy streams have a decoded length. Avoid speculative buffers.
        const size = std.mem.readInt(u32, input[1..5], .big);
        if (size == 0) return error.InvalidKle;
        if (size > max_decoded_size) return error.KleOutputTooLarge;
        if (size > input.len - 5) return error.InvalidKle;
        capacity = size;
    }
    while (true) {
        const output = try allocator.alloc(u8, capacity);
        const decoded = decodeInto(bytes, output) catch |err| {
            allocator.free(output);
            if (err != error.KleOutputTooSmall) return err;
            if (capacity == max_decoded_size) return error.KleOutputTooLarge;
            // Discard the failed attempt: growing it with realloc could copy bytes
            // that the next decoder invocation immediately overwrites.
            capacity = @min(capacity * 2, max_decoded_size);
            continue;
        };
        errdefer allocator.free(output);
        // Shrink in place when supported; callers must be able to free the slice.
        return allocator.realloc(output, decoded);
    }
}

pub fn extract(allocator: std.mem.Allocator, bytes: []const u8) !decoded_output.Output {
    const output = try decode(allocator, bytes);
    return .{ .bytes = output, .format = decoded_output.identify(output) };
}

test "direct-copy KL variants use exact storage and leave input untouched" {
    for ([_][]const u8{ "KL3E", "KL4E" }) |magic| {
        var input = "KL3E\x80\x00\x00\x00\x03abcignored".*;
        @memcpy(input[0..4], magic);
        const original = input;
        var storage: [3]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&storage);
        const decoded = try decode(fixed.allocator(), &input);
        defer fixed.allocator().free(decoded);
        try std.testing.expectEqualStrings("abc", decoded);
        try std.testing.expectEqualSlices(u8, &original, &input);
        decoded[0] = 'z';
        try std.testing.expectEqual(@as(u8, 'a'), input[9]);
    }
}

test "KL headers, empty output and declared output cap are rejected before allocation" {
    const allocator = std.testing.allocator;
    const direct = "KL4E\x80\x00\x00\x00\x03abc";
    for (0..direct.len) |length| try std.testing.expectError(error.InvalidKle, decode(allocator, direct[0..length]));
    try std.testing.expectError(error.InvalidKle, decode(allocator, "KL5E\x80\x00\x00\x00\x01a"));
    try std.testing.expectError(error.InvalidKle, decode(allocator, "KL3E\x80\x00\x00\x00\x00"));
    // Exactly the cap is not an output-limit error; this stream lacks its payload.
    try std.testing.expectError(error.InvalidKle, decode(allocator, "KL4E\x80\x04\x00\x00\x00"));
    try std.testing.expectError(error.KleOutputTooLarge, decode(allocator, "KL4E\x80\x04\x00\x00\x01"));
    try std.testing.expectError(error.KleOutputTooLarge, decode(allocator, "KL3E\x80\xff\xff\xff\xff"));
}

test "bounded KL direct copy distinguishes truncation from output exhaustion" {
    const input = "\x80\x00\x00\x00\x03abc";
    var output: [4]u8 = @splat(0xa5);
    try std.testing.expectEqual(@as(c_int, 3), decompress_kle_bounded(&output, 3, input, input.len, 1));
    try std.testing.expectEqualSlices(u8, "abc\xa5", &output);
    try std.testing.expectEqual(output_too_small, decompress_kle_bounded(&output, 2, input, input.len, 1));
    // Missing source bytes must never request a larger output/retry.
    try std.testing.expectEqual(invalid_format, decompress_kle_bounded(&output, 2, input, input.len - 1, 1));
    try std.testing.expectEqual(invalid_format, decompress_kle_bounded(&output, 4, input, 4, 1));
    try std.testing.expectEqual(invalid_format, decompress_kle_bounded(&output, 4, input, -1, 1));
}

// Arithmetic-coded literals with shift 7 followed by the 255 end marker. The
// contexts depend on output position; absolute host addresses must not affect it.
const compressed = "\x07\x90\xcc\xe4\x56\xe6\x8a\x53\x77\x3b\x32\x9d\x00\x00\x00";

test "compressed KL output is independent of buffer alignment and accepts exact capacity" {
    for ([_]c_int{ 0, 1 }) |variant| {
        for (0..8) |offset| {
            var storage: [24]u8 align(8) = @splat(0xa5);
            const output = storage[offset..][0..8];
            try std.testing.expectEqual(@as(c_int, 8), decompress_kle_bounded(output.ptr, 8, compressed, compressed.len, variant));
            try std.testing.expectEqualStrings("offsets!", output);
            try std.testing.expectEqual(@as(u8, 0xa5), storage[offset + 8]);
            try std.testing.expectEqual(output_too_small, decompress_kle_bounded(output.ptr, 7, compressed, compressed.len, variant));
        }
    }
    const decoded = try decode(std.testing.allocator, "KL4E" ++ compressed);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("offsets!", decoded);
}

test "compressed KL truncation never succeeds or requests larger output" {
    var output: [16]u8 = undefined;
    for (0..compressed.len) |length| {
        try std.testing.expectEqual(invalid_format, decompress_kle_bounded(&output, output.len, compressed, @intCast(length), 1));
    }
    try std.testing.expectError(error.InvalidKle, decode(std.testing.allocator, "KL3E\x00\x00\x00\x00\x00"));
}

test "compressed KL overlapping backreferences respect remaining output capacity" {
    // One literal, a distance-one copy of two bytes, then the end marker.
    const input = "\x00\x9e\x77\xff\x80\x00\x00\x00";
    for ([_]c_int{ 0, 1 }) |variant| {
        var output: [4]u8 = @splat(0xa5);
        try std.testing.expectEqual(@as(c_int, 3), decompress_kle_bounded(&output, 3, input, input.len, variant));
        try std.testing.expectEqualSlices(u8, "aaa\xa5", &output);
        try std.testing.expectEqual(output_too_small, decompress_kle_bounded(&output, 2, input, input.len, variant));
        try std.testing.expectEqual(invalid_format, decompress_kle_bounded(&output, 4, input, input.len - 1, variant));
    }
}
