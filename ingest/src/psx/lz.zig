//! PS1 Classics block decompressor: exact port of PSXtract-2 `src/lz.cpp`
//! `decompress` (range-coded LZ, probability bytes start at 0x80, +31 / >>3
//! updates) including the pspdb patch's `start == end` guard.
//!
//! Differences from the C source are limited to safety: every input read is
//! bounds-checked and every length/offset is validated against the output.
//! The C `head < 0` branch is dead code (`head` is unsigned) and is not ported.
const std = @import("std");

/// 16 CD sectors of 2352 bytes.
pub const block_size: usize = 16 * 2352;

pub const Error = error{
    /// The range decoder tried to read past the end of the input slice.
    TruncatedInput,
    /// A back-reference underflows the block start or overflows its end.
    InvalidStream,
};

const table_size = 0xA70;

const Decoder = struct {
    range: u32,
    code: u32,
    /// Matches the C `src` pointer: reads are `in[pos + 5]`.
    pos: usize,
    in: []const u8,
    tmp: [table_size]u8,

    fn decodeRange(self: *Decoder) Error!bool {
        if ((self.range >> 24) != 0) return false;
        const at = self.pos + 5;
        if (at >= self.in.len) return error.TruncatedInput;
        self.range <<= 8;
        self.code = (self.code << 8) +% self.in[at];
        self.pos += 1;
        return true;
    }

    /// `index` mirrors the optional `int *index` of the C code.
    fn decodeBit(self: *Decoder, index: ?*i32, at: usize) Error!u1 {
        var val = self.range;
        const c = self.tmp[at];
        if (try self.decodeRange()) {
            val *%= c;
        } else {
            val = (val >> 8) *% c;
        }
        self.tmp[at] = c - (c >> 3);
        if (index) |i| i.* = i.* *% 2;
        if (self.code < val) {
            self.range = val;
            self.tmp[at] +%= 31;
            if (index) |i| i.* +%= 1;
            return 1;
        }
        self.code -= val;
        self.range -= val;
        return 0;
    }

    fn decodeNumber(self: *Decoder, ptr: usize, index_in: i32, bit_flag: *u1) Error!i32 {
        var index = index_in;
        var i: i32 = 1;
        if (index >= 3) {
            _ = try self.decodeBit(&i, ptr + 0x18);
            if (index >= 4) {
                _ = try self.decodeBit(&i, ptr + 0x18);
                if (index >= 5) {
                    _ = try self.decodeRange();
                    while (index >= 5) : (index -= 1) {
                        i *%= 2;
                        self.range >>= 1;
                        if (self.code < self.range) {
                            i +%= 1;
                        } else {
                            self.code -= self.range;
                        }
                    }
                }
            }
        }
        bit_flag.* = try self.decodeBit(&i, ptr);
        if (index >= 1) {
            _ = try self.decodeBit(&i, ptr + 0x8);
            if (index >= 2) {
                _ = try self.decodeBit(&i, ptr + 0x10);
            }
        }
        return i;
    }

    fn decodeWord(self: *Decoder, ptr: usize, index_in: i32, bit_flag: *u1) Error!i32 {
        var i: i32 = 1;
        var index = @divTrunc(index_in, 8);
        if (index >= 3) {
            _ = try self.decodeBit(&i, ptr);
            if (index >= 4) {
                _ = try self.decodeBit(&i, ptr);
                if (index >= 5) {
                    _ = try self.decodeRange();
                    while (index >= 5) : (index -= 1) {
                        i *%= 2;
                        self.range >>= 1;
                        if (self.code < self.range) {
                            i +%= 1;
                        } else {
                            self.code -= self.range;
                        }
                    }
                }
            }
        }
        bit_flag.* = try self.decodeBit(&i, ptr + 3);
        if (index >= 1) {
            _ = try self.decodeBit(&i, ptr + 2);
            if (index >= 2) {
                _ = try self.decodeBit(&i, ptr + 1);
            }
        }
        return i;
    }
};

/// Decompress one block; `out` is filled completely or an error is returned.
/// `in` is the compressed block including any zero padding the caller wants
/// the range decoder to see (PSXtract reads from a zero-filled 37,632-byte
/// buffer, so callers pass the whole padded buffer).
pub fn decompress(out: *[block_size]u8, in: []const u8) Error!void {
    return decompressInto(out, in);
}

/// Same algorithm with a caller-chosen output size (used by tests).
pub fn decompressInto(out: []u8, in: []const u8) Error!void {
    if (in.len < 5) return error.TruncatedInput;
    const size = out.len;

    var d: Decoder = .{
        .range = 0xFFFFFFFF,
        .code = (@as(u32, in[1]) << 24) | (@as(u32, in[2]) << 16) | (@as(u32, in[3]) << 8) | in[4],
        .pos = 0,
        .in = in,
        .tmp = undefined,
    };
    @memset(d.tmp[0..0xA60], 0x80);
    @memset(d.tmp[0xA60..], 0);

    const head: u5 = @truncate(in[0]); // x86 masks int shift counts to 5 bits
    var offset: i32 = 0;
    var prev: u8 = 0;
    var start: usize = 0;

    while (true) {
        // A match or literal may exactly fill the block (patch guard).
        if (start == size) return;

        const sect1: usize = @intCast(offset + 0x920);
        if ((try d.decodeBit(null, sect1)) == 0) {
            // Raw char.
            if (offset > 0) offset -= 1;

            const ctx: i32 = ((@as(i32, @intCast(start & 7)) << 8) + prev) >> head;
            const sect: i32 = (ctx & 7) * 0xFF - 1;
            var index: i32 = 1;
            while (true) {
                const at: usize = @intCast(sect + index);
                _ = try d.decodeBit(&index, at);
                if ((index >> 8) != 0) break;
            }
            out[start] = @truncate(@as(u32, @bitCast(index)));
            start += 1;
        } else {
            // Compressed char stream.
            var index: i32 = -1;
            var bit_flag: u1 = 0;
            var s1 = sect1;
            while (true) {
                s1 += 8;
                bit_flag = try d.decodeBit(null, s1);
                index += bit_flag;
                if (!(bit_flag != 0 and index < 6)) break;
            }

            var b_size: i32 = 0x40;
            var s2: usize = @intCast(index + 0x7F1);
            var data_length: i32 = undefined;

            if (index >= 0 or bit_flag != 0) {
                const sh: u5 = @intCast(index);
                const lo: i32 = @intCast((start << sh) & 3);
                const sect: usize = @intCast((index << 5) | (lo << 3) | (offset & 7));
                data_length = try d.decodeNumber(0x960 + sect, index, &bit_flag);
                if (data_length != 3 and (index > 0 or bit_flag != 0)) {
                    s2 += 0x38;
                    b_size = 0x80;
                }
            } else {
                data_length = 1;
            }

            var diff: i32 = 0;
            var shift: i32 = 1;
            while (true) {
                diff = (shift << 4) - b_size;
                const at = s2 + @as(usize, @intCast(shift << 3));
                bit_flag = try d.decodeBit(&shift, at);
                if (diff >= 0) break;
            }

            var data_offset: i32 = undefined;
            if (diff > 0 or bit_flag != 0) {
                if (bit_flag == 0) diff -= 8;
                const p3: usize = 0x8A8 + @as(usize, @intCast(diff));
                data_offset = try d.decodeWord(p3, diff, &bit_flag);
            } else {
                data_offset = 1;
            }

            // data_offset >= 1 and data_length >= 1 by construction, but the
            // checks below do not rely on it.
            const buf_start: i64 = @as(i64, @intCast(start)) - data_offset;
            const buf_end: i64 = @as(i64, @intCast(start)) + data_length + 1;
            if (buf_start < 0) return error.InvalidStream;
            if (buf_end > size) return error.InvalidStream;

            offset = @intCast(((buf_end + 1) & 1) + 6);

            var src: usize = @intCast(buf_start);
            const end: usize = @intCast(buf_end);
            while (true) {
                out[start] = out[src];
                start += 1;
                src += 1;
                if (start >= end) break;
            }
        }
        prev = out[start - 1];
    }
}

// Regression vector from tools/psxtract/test_lz.cpp: a back-reference fills
// the caller's output capacity exactly.
const vector = [_]u8{
    0x06, 0xff, 0x84, 0xcf, 0x7b, 0x15, 0x89, 0x09,
    0x0b, 0x4e, 0x91, 0xcc, 0x5c, 0xb8, 0x71, 0x11,
    0x3a, 0x87, 0x74, 0x51, 0x31, 0xda, 0x52, 0x6f,
};

fn paddedVector() [1024]u8 {
    var buf: [1024]u8 = @splat(0);
    @memcpy(buf[0..vector.len], &vector);
    return buf;
}

test "lz: back-reference fills the output exactly" {
    const input = paddedVector();
    var out: [16]u8 = @splat(0xa5);
    try decompressInto(&out, &input);
    for (out[0..15]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expectEqual(@as(u8, 2), out[15]);
}

test "lz: a match exceeding capacity is rejected without writing past it" {
    const input = paddedVector();
    var buf: [19]u8 = @splat(0xa5);
    try std.testing.expectError(error.InvalidStream, decompressInto(buf[1..18], &input));
    try std.testing.expectEqual(@as(u8, 0xa5), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xa5), buf[18]);
}

test "lz: truncated input is rejected" {
    var out: [16]u8 = @splat(0);
    try std.testing.expectError(error.TruncatedInput, decompressInto(&out, vector[0..4]));
    try std.testing.expectError(error.TruncatedInput, decompressInto(&out, &.{}));
    // The vector consumes renormalisation bytes beyond the 5-byte header.
    try std.testing.expectError(error.TruncatedInput, decompressInto(&out, vector[0..5]));
}

test "lz: code == range stream decodes to a zero block" {
    // head 0, code 0xFFFFFFFF: every decoded bit is 0, so every literal is 0.
    const input = [_]u8{ 0, 0xff, 0xff, 0xff, 0xff } ++ @as([4096]u8, @splat(0));
    var out: [block_size]u8 = undefined;
    @memset(&out, 0x77);
    try decompress(&out, &input);
    for (out) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "lz: block decode runs out of input without zero padding" {
    const input = [_]u8{ 0, 0xff, 0xff, 0xff, 0xff };
    var out: [block_size]u8 = undefined;
    try std.testing.expectError(error.TruncatedInput, decompress(&out, &input));
}
