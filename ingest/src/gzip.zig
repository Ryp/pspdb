const std = @import("std");
const decoded_output = @import("decoded.zig");

fn decode_member(input: *std.Io.Reader, output: *std.Io.Writer, window: []u8, limit: usize) !void {
    const start = output.end;
    var decoder: std.compress.flate.Decompress = .init(input, .gzip, window);
    var remaining = limit;
    while (remaining != 0) {
        remaining -= decoder.reader.stream(output, .limited(remaining)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.WriteFailed => return error.WriteFailed,
            else => return decoder.err orelse error.InvalidGzip,
        };
    }
    if (remaining == 0) {
        if (decoder.reader.takeByte()) |_| {
            return error.GzipOutputTooSmall;
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => return decoder.err orelse error.InvalidGzip,
        }
    }
    const member = output.buffered()[start..];
    const trailer = decoder.container_metadata.gzip;
    if (std.hash.Crc32.hash(member) != trailer.crc or
        @as(u32, @truncate(member.len)) != trailer.count) return error.InvalidGzip;
}

pub const Member = struct {
    written: usize,
    consumed: usize,
};

/// Decode one complete gzip member into borrowed storage, validating its trailer.
/// Bytes after that member belong to the enclosing format, not this gzip stream.
/// Insufficient storage is GzipOutputTooSmall; no allocation or input mutation.
pub fn decode_member_info(bytes: []const u8, output: []u8) !Member {
    var input: std.Io.Reader = .fixed(bytes);
    var writer: std.Io.Writer = .fixed(output);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    decode_member(&input, &writer, &window, output.len) catch |err| return switch (err) {
        error.WriteFailed => error.GzipOutputTooSmall,
        else => err,
    };
    return .{ .written = writer.end, .consumed = input.seek };
}

pub fn decode_member_into(bytes: []const u8, output: []u8) !usize {
    return (try decode_member_info(bytes, output)).written;
}

/// Decode a single member with an unknown output size, capped by limit.
/// Enclosing-format trailing bytes are ignored, as in decode_member_into.
pub fn decode_member_bounded(allocator: std.mem.Allocator, bytes: []const u8, limit: usize) ![]u8 {
    var input: std.Io.Reader = .fixed(bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    decode_member(&input, &output.writer, &window, limit) catch |err| return switch (err) {
        error.WriteFailed => error.OutOfMemory,
        error.GzipOutputTooSmall => error.GzipOutputTooLarge,
        else => err,
    };
    return output.toOwnedSlice();
}

/// Decode all members before exposing output; verify each trailer's CRC and size.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var input: std.Io.Reader = .fixed(bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    while (input.seek < bytes.len) {
        decode_member(&input, &output.writer, &window, std.math.maxInt(usize)) catch |err| return switch (err) {
            error.WriteFailed => error.OutOfMemory,
            else => err,
        };
        // Python's gzip reader accepts zero padding after and between members.
        while (input.seek < bytes.len and bytes[input.seek] == 0) input.seek += 1;
    }
    return output.toOwnedSlice();
}

pub fn extract(allocator: std.mem.Allocator, bytes: []const u8) !decoded_output.Output {
    const output = try decode(allocator, bytes);
    return .{ .bytes = output, .format = decoded_output.identify(output) };
}

test "gzip enclosing member boundary differs from standalone member and padding semantics" {
    // A stored DEFLATE block for "abc", followed by its CRC32 and ISIZE.
    const member = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x01\x03\x00\xfc\xffabc\xc2\x41\x24\x35\x03\x00\x00\x00";
    const allocator = std.testing.allocator;
    var output: [3]u8 = undefined;
    const info = try decode_member_info(member ++ "\x00envelope tail", &output);
    try std.testing.expectEqual(@as(usize, 3), info.written);
    try std.testing.expectEqual(member.len, info.consumed);
    try std.testing.expectEqualStrings("abc", &output);
    try std.testing.expectError(error.GzipOutputTooSmall, decode_member_into(member, output[0..2]));
    const bounded = try decode_member_bounded(allocator, member, output.len);
    defer allocator.free(bounded);
    try std.testing.expectEqualStrings("abc", bounded);
    try std.testing.expectError(error.GzipOutputTooLarge, decode_member_bounded(allocator, member, 2));
    const joined = try decode(allocator, member ++ "\x00\x00" ++ member ++ "\x00");
    defer allocator.free(joined);
    try std.testing.expectEqualStrings("abcabc", joined);
    if (decode(allocator, member ++ "\x00envelope tail")) |unexpected| {
        allocator.free(unexpected);
        return error.UnexpectedGzipSuccess;
    } else |_| {}
    for (0..member.len) |length| {
        if (decode_member_into(member[0..length], &output)) |_| {
            return error.UnexpectedGzipSuccess;
        } else |_| {}
    }
    for ([_]usize{ member.len - 8, member.len - 4 }) |offset| {
        var damaged = member.*;
        damaged[offset] ^= 1;
        try std.testing.expectError(error.InvalidGzip, decode_member_into(&damaged, &output));
        try std.testing.expectError(error.InvalidGzip, decode(allocator, &damaged));
    }
}
