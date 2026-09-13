//! Bounded in-memory 2RLZ decoding, ported from libLZR 0.11 by BenHur.
//! Algorithm source: pinned pspdecrypt libLZR.c (CC BY-SA 3.0).
const std = @import("std");

const max_decoded_size = 64 << 20;

fn body(bytes: []const u8) ![]const u8 {
    if (bytes.len < 9 or !std.mem.eql(u8, bytes[0..4], "2RLZ")) return error.InvalidLzr;
    const input = bytes[4..];
    // Unlike LZRC, LZR includes the output position in its literal context.
    // Shifts 5..8 are the named 8/16/32/64-bit data types in libLZR.h; the
    // smaller shifts also have defined contexts in the original algorithm.
    if (input[0] < 0x80 and input[0] > 8) return error.InvalidLzr;
    return input;
}

fn directLength(input: []const u8) !usize {
    const size = std.mem.readInt(u32, input[1..5], .big);
    if (size == 0) return error.InvalidLzr;
    if (size > max_decoded_size) return error.LzrOutputTooLarge;
    // libLZRCompress appends one padding byte and LZRDecompress consumes it
    // after the literal data. Its value is not part of the decoded output.
    if (size >= input.len - 5) return error.InvalidLzr;
    return size;
}

const Decoder = struct {
    input: []const u8,
    cursor: usize = 0,
    mask: u32 = 0xffffffff,
    code: u32,
    probabilities: [2800]u8 = @splat(0x80),

    fn normalize(self: *Decoder, test_mask: u32) !void {
        if (test_mask <= 0x00ffffff) {
            if (self.cursor == self.input.len) return error.InvalidLzr;
            self.code = (self.code << 8) | self.input[self.cursor];
            self.cursor += 1;
            self.mask = test_mask << 8;
        }
    }

    fn bit(self: *Decoder, index: usize, test_mask: ?*u32) !u1 {
        if (index >= self.probabilities.len) return error.InvalidLzr;
        try self.normalize(if (test_mask) |value| value.* else self.mask);
        const probability = &self.probabilities[index];
        const bound = (self.mask >> 8) * probability.*;
        if (test_mask) |value| value.* = bound;
        probability.* -= probability.* >> 3;
        if (self.code < bound) {
            self.mask = bound;
            probability.* += 31;
            return 1;
        }
        self.code -= bound;
        self.mask -= bound;
        return 0;
    }

    fn number(self: *Decoder, n_bits: u5, base: usize, stride: usize, flag: *u1) !u32 {
        var value: u32 = 1;
        if (n_bits >= 3) {
            value = (value << 1) | try self.bit(base + 3 * stride, null);
            if (n_bits >= 4) {
                value = (value << 1) | try self.bit(base + 3 * stride, null);
                if (n_bits >= 5) {
                    try self.normalize(self.mask);
                    var remaining = n_bits;
                    while (remaining >= 5) : (remaining -= 1) {
                        value <<= 1;
                        self.mask >>= 1;
                        if (self.code < self.mask) {
                            value += 1;
                        } else {
                            self.code -= self.mask;
                        }
                    }
                }
            }
        }
        flag.* = try self.bit(base, null);
        value = (value << 1) | flag.*;
        if (n_bits >= 1) {
            value = (value << 1) | try self.bit(base + stride, null);
            if (n_bits >= 2) value = (value << 1) | try self.bit(base + 2 * stride, null);
        }
        return value;
    }
};

/// Decode into borrowed storage without allocating or changing the input.
/// Invalid headers, truncation, impossible distances and empty output are
/// InvalidLzr. Only a valid literal/copy exceeding capacity is LzrOutputTooSmall.
/// Compressed streams must reach their end marker, even at exact capacity.
/// Storage larger than the 64 MiB PSP bound is LzrOutputTooLarge.
pub fn decodeInto(bytes: []const u8, output: []u8) !usize {
    const input = try body(bytes);
    if (output.len > max_decoded_size) return error.LzrOutputTooLarge;
    if (input[0] & 0x80 != 0) {
        const size = try directLength(input);
        if (size > output.len) return error.LzrOutputTooSmall;
        @memcpy(output[0..size], input[5..][0..size]);
        return size;
    }

    var decoder: Decoder = .{
        .input = input[5..],
        .code = std.mem.readInt(u32, input[1..5], .big),
    };
    const shift: u5 = @intCast(input[0]);
    var produced: usize = 0;
    var state: usize = 0;
    var last_byte: u8 = 0;
    while (true) {
        var model = 2488 + state;
        if (try decoder.bit(model, null) == 0) {
            if (state != 0) state -= 1;
            const context = (((((produced & 7) << 8) + last_byte) >> shift) & 7) * 255;
            var literal: usize = 1;
            while (literal <= 255) literal = (literal << 1) | try decoder.bit(context + literal - 1, null);
            if (produced == output.len) return error.LzrOutputTooSmall;
            output[produced] = @truncate(literal);
            produced += 1;
        } else {
            var test_mask = decoder.mask;
            var n_bits: i32 = -1;
            var flag: u1 = undefined;
            while (true) {
                model += 8;
                flag = try decoder.bit(model, &test_mask);
                n_bits += flag;
                if (flag == 0 or n_bits == 6) break;
            }

            var distance_model: usize = @intCast(2033 + n_bits);
            var distance_threshold: i32 = 64;
            var sequence_length: u32 = 1;
            if (n_bits >= 0) {
                const length_bits: u5 = @intCast(n_bits);
                model = 2552 + (@as(usize, length_bits) << 5) + (((produced << length_bits) & 3) << 3) + state;
                sequence_length = try decoder.number(length_bits, model, 8, &flag);
                if (sequence_length == 255) {
                    if (produced == 0) return error.InvalidLzr;
                    return produced;
                }
                if (flag != 0 or n_bits > 0) {
                    distance_model += 56;
                    distance_threshold = 352;
                }
            }

            var tree: usize = 1;
            while (true) {
                n_bits = @as(i32, @intCast(tree << 4)) - distance_threshold;
                flag = try decoder.bit(distance_model + (tree << 3), null);
                tree = (tree << 1) | flag;
                if (n_bits >= 0) break;
            }

            var distance: u32 = 1;
            if (flag != 0 or n_bits > 0) {
                if (flag == 0) n_bits -= 8;
                // number(n) has n+1 value bits following its leading one.
                // n > 25 therefore cannot reference any byte within 64 MiB.
                // Reject before the original C's signed-number shifts overflow.
                if (n_bits > 25 * 8) return error.InvalidLzr;
                distance = try decoder.number(@intCast(@divExact(n_bits, 8)), @intCast(2344 + n_bits), 1, &flag);
            }
            if (distance > produced) return error.InvalidLzr;
            const count = sequence_length + 1;
            if (count > output.len - produced) return error.LzrOutputTooSmall;
            const end = produced + count;
            state = 6 + ((end + 1) & 1);
            // Forward byte copying intentionally supports overlapping matches.
            while (produced < end) : (produced += 1) output[produced] = output[produced - distance];
        }
        last_byte = output[produced - 1];
    }
}

/// The input is borrowed and immutable; the caller owns the returned allocation.
/// Only capacity exhaustion retries, up to 64 MiB. Malformed/truncated streams
/// never become successful partial output and all failed allocations are freed.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const input = try body(bytes);
    var capacity: usize = if (input[0] & 0x80 != 0) try directLength(input) else 1 << 20;
    while (true) {
        const output = try allocator.alloc(u8, capacity);
        const decoded = decodeInto(bytes, output) catch |err| {
            allocator.free(output);
            if (err != error.LzrOutputTooSmall) return err;
            if (capacity == max_decoded_size) return error.LzrOutputTooLarge;
            capacity = @min(capacity * 2, max_decoded_size);
            continue;
        };
        errdefer allocator.free(output);
        return allocator.realloc(output, decoded);
    }
}

// Synthetic arithmetic-coded streams; no firmware bytes are embedded here.
const compressed = "2RLZ\x08\xc8\x63\x3d\xbe\x16\x38\x4a\xd2\x32\xf6\x60\x00\x00\x00";
const overlapping = "2RLZ\x05\xcf\x34\x83\x18\xed\x60\x00\x00\x00";

test "LZR direct-copy requires its skipped padding byte and preserves input" {
    var input = "2RLZ\xff\x00\x00\x00\x03abc\xa5tail".*;
    const original = input;
    var storage: [3]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const decoded = try decode(fixed.allocator(), &input);
    defer fixed.allocator().free(decoded);
    try std.testing.expectEqualStrings("abc", decoded);
    try std.testing.expectEqualSlices(u8, &original, &input);
    var output: [4]u8 = @splat(0xa5);
    try std.testing.expectEqual(@as(usize, 3), try decodeInto(input[0..13], output[0..3]));
    try std.testing.expectEqualSlices(u8, "abc\xa5", &output);
    try std.testing.expectError(error.LzrOutputTooSmall, decodeInto(&input, output[0..2]));
    for (0..13) |length| try std.testing.expectError(error.InvalidLzr, decodeInto(input[0..length], output[0..2]));
}

test "LZR rejects invalid types, empty streams and oversized declarations" {
    var output: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidLzr, decodeInto("2RLZ\x09\x00\x00\x00\x00", &output));
    try std.testing.expectError(error.InvalidLzr, decodeInto("2RLZ\x7f\x00\x00\x00\x00", &output));
    try std.testing.expectError(error.InvalidLzr, decodeInto("2RLZ\xff\x00\x00\x00\x00\x00", &output));
    try std.testing.expectError(error.InvalidLzr, decodeInto("2RLZ\x05\x00\x00\x00\x00\x00", &output));
    try std.testing.expectError(error.InvalidLzr, decode(std.testing.allocator, "2RLZ\xff\x04\x00\x00\x00"));
    try std.testing.expectError(error.LzrOutputTooLarge, decode(std.testing.allocator, "2RLZ\xff\x04\x00\x00\x01"));
}

test "LZR coded literals use position contexts and require an end marker at exact capacity" {
    for (0..8) |offset| {
        var storage: [17]u8 align(8) = @splat(0xa5);
        const output = storage[offset..][0..8];
        try std.testing.expectEqual(@as(usize, 8), try decodeInto(compressed, output));
        try std.testing.expectEqualStrings("offsets!", output);
        try std.testing.expectEqual(@as(u8, 0xa5), storage[offset + 8]);
        try std.testing.expectError(error.LzrOutputTooSmall, decodeInto(compressed, output[0..7]));
    }
    const decoded = try decode(std.testing.allocator, compressed);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("offsets!", decoded);
    var output: [8]u8 = undefined;
    for (0..compressed.len) |length| try std.testing.expectError(error.InvalidLzr, decodeInto(compressed[0..length], &output));
}

test "LZR overlapping short and long matches check distance and remaining capacity" {
    var output: [131]u8 = @splat(0xa5);
    try std.testing.expectEqual(@as(usize, 130), try decodeInto(overlapping, output[0..130]));
    try std.testing.expectEqualSlices(u8, &([_]u8{'a'} ** 130), output[0..130]);
    try std.testing.expectEqual(@as(u8, 0xa5), output[130]);
    try std.testing.expectError(error.LzrOutputTooSmall, decodeInto(overlapping, output[0..129]));
    for (0..overlapping.len) |length| try std.testing.expectError(error.InvalidLzr, decodeInto(overlapping[0..length], &output));
    // One literal followed by a distance-two copy has no valid source byte.
    const invalid = "2RLZ\x05\xcf\x32\xbf\x80\x00\x00\x00";
    try std.testing.expectError(error.InvalidLzr, decodeInto(invalid, &output));
    try std.testing.expectError(error.InvalidLzr, decodeInto(invalid, output[0..1]));
}
