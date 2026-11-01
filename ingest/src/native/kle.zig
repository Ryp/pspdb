//! KL3E/KL4E range decoder: port of pspdecrypt's bounded `decompress_kle_bounded[_member]`.
//! Inputs here exclude the 4-byte magic, exactly like the C entry points.
//! Return values are the C ints: >0 decoded size, otherwise a SCE error code.
const std = @import("std");

pub const output_too_small: i32 = @bitCast(@as(u32, 0x80000104));
pub const invalid_format: i32 = @bitCast(@as(u32, 0x80000108));

const Decoder = struct {
    input: []const u8,
    pos: usize,
    input_val: u32,
    range: u32 = 0xffffffff,
    failed: bool = false,

    fn readByte(self: *Decoder) u8 {
        if (self.pos >= self.input.len) {
            self.failed = true;
            return 0;
        }
        const b = self.input[self.pos];
        self.pos += 1;
        return b;
    }

    fn readBit(self: *Decoder, prob_ptr: *u8, decay: u3, bonus: u8) u32 {
        var prob = prob_ptr.*;
        var bound: u32 = undefined;
        if ((self.range >> 24) == 0) {
            self.input_val = (self.input_val << 8) +% self.readByte();
            bound = self.range *% prob;
            self.range <<= 8;
        } else {
            bound = (self.range >> 8) *% prob;
        }
        prob -%= prob >> decay;
        if (self.input_val >= bound) {
            self.input_val -%= bound;
            self.range -%= bound;
            prob_ptr.* = prob;
            return 0;
        } else {
            self.range = bound;
            prob_ptr.* = prob +% bonus;
            return 1;
        }
    }

    fn readBitUniform(self: *Decoder) u32 {
        if ((self.range >> 24) == 0) {
            self.input_val = (self.input_val << 8) +% self.readByte();
            self.range = self.range << 7;
        } else {
            self.range = self.range >> 1;
        }
        if (self.input_val >= self.range) {
            self.input_val -%= self.range;
            return 0;
        }
        return 1;
    }

    fn readBitUniformNoNormal(self: *Decoder) u32 {
        self.range >>= 1;
        if (self.input_val >= self.range) {
            self.input_val -%= self.range;
            return 0;
        }
        return 1;
    }

    /// Literal byte; the context uses the stream offset, never the host address.
    fn outputRaw(self: *Decoder, probs: *[2040]u8, cur_byte: *u32, out: *u8, out_offset: usize, shift: u3) void {
        const mask: u32 = @as(u32, @intCast(out_offset & 7)) << 8 | (cur_byte.* & 0xff);
        const base: usize = ((mask >> shift) & 7) * 255;
        cur_byte.* = 1;
        while (cur_byte.* < 0x100) {
            const prob = &probs[base + cur_byte.* - 1];
            cur_byte.* <<= 1;
            if (self.readBit(prob, 3, 31) != 0) cur_byte.* |= 1;
        }
        out.* = @truncate(cur_byte.*);
    }
};

/// C `decompress_kle_bounded_member`. `consumed` is zeroed first and is only set
/// on success (direct copy: 5 + n - (n != 0); compressed: bytes read through the
/// end marker). Sizes beyond i32 are clamped to what the C `int` parameters hold.
pub fn decompressKleBoundedMember(out: []u8, in: []const u8, is_kl4e: bool, consumed: *usize) i32 {
    consumed.* = 0;
    const in_size: usize = @min(in.len, std.math.maxInt(i32));
    if (in_size < 5) return invalid_format;
    if (out.len == 0) return output_too_small;
    const out_size: usize = @min(out.len, std.math.maxInt(i32));
    const input = in[0..in_size];
    const buf = out[0..out_size];

    var dec = Decoder{
        .input = input,
        .pos = 5,
        .input_val = std.mem.readInt(u32, input[1..5], .big),
    };

    // Uncompressed stream: the header word is the length.
    if (input[0] & 0x80 != 0) {
        const n = dec.input_val;
        if (n > in_size - 5) return invalid_format;
        if (n > out_size) return output_too_small;
        @memcpy(buf[0..n], input[5..][0..n]);
        consumed.* = 5 + @as(usize, n) - @intFromBool(n != 0);
        return @intCast(n);
    }

    var lit_probs: [2040]u8 = undefined;
    var copy_dist_bits_probs: [304]u8 = undefined;
    var copy_dist_probs: [144]u8 = undefined;
    var copy_count_bits_probs: [64]u8 = undefined;
    var copy_count_probs: [256]u8 = undefined;
    const init_prob: u8 = 128 - (@as(u8, (input[0] >> 3) & 3) << 4);
    @memset(&lit_probs, init_prob);
    @memset(&copy_count_bits_probs, init_prob);
    @memset(&copy_dist_bits_probs, init_prob);
    @memset(&copy_count_probs, init_prob);
    @memset(&copy_dist_probs, init_prob);

    // The C walks a pointer into copy_count_bits_probs; keep it as an index.
    var cc_idx: usize = 0;
    const shift: u3 = @intCast(input[0] & 7);
    var cur_byte: u32 = 0;
    var cur: usize = 0; // curOut - outBuf

    dec.outputRaw(&lit_probs, &cur_byte, &buf[0], 0, shift);

    while (true) {
        if (dec.failed) return invalid_format;
        cur += 1;
        const is_copy = dec.readBit(&copy_count_bits_probs[cc_idx], 4, 15);
        if (dec.failed) return invalid_format;
        if (is_copy == 0) {
            if (cc_idx > 0) cc_idx -= 1;
            if (cur == out_size) return output_too_small;
            dec.outputRaw(&lit_probs, &cur_byte, &buf[cur], cur, shift);
            continue;
        }

        var copy_count: u32 = 1;
        var copy_count_bits: i32 = -1;
        while (copy_count_bits < 6) {
            cc_idx += 8;
            if (dec.readBit(&copy_count_bits_probs[cc_idx], 4, 15) == 0) break;
            copy_count_bits += 1;
        }

        var pow_limit: i32 = undefined;
        var dist_bits_index: i32 = undefined;
        if (copy_count_bits >= 0) {
            const ccb: u5 = @intCast(copy_count_bits);
            const pi: usize = (@as(usize, ccb) << 5) |
                (((cur & 3) << (ccb + 3)) & 0x18) |
                (cc_idx & 7);
            const probs = copy_count_probs[pi..];
            if (ccb < 3) {
                copy_count = 1;
            } else {
                copy_count = 2 + dec.readBit(&probs[24], 3, 31);
                if (ccb > 3) {
                    copy_count = (copy_count << 1) | dec.readBit(&probs[24], 3, 31);
                    if (ccb > 4) {
                        copy_count = (copy_count << 1) | dec.readBitUniform();
                    }
                    var i: u32 = 5;
                    while (i < ccb) : (i += 1) {
                        copy_count = (copy_count << 1) | dec.readBitUniformNoNormal();
                    }
                }
            }
            copy_count = copy_count << 1;
            if (dec.readBit(&probs[0], 3, 31) != 0) {
                copy_count |= 1;
                if (copy_count_bits <= 0) {
                    pow_limit = if (is_kl4e) 256 else 128;
                    dist_bits_index = 56 + copy_count_bits;
                }
            } else {
                if (copy_count_bits <= 0) {
                    pow_limit = 64;
                    dist_bits_index = copy_count_bits;
                }
            }
            if (copy_count_bits > 0) {
                copy_count = (copy_count << 1) | dec.readBit(&probs[8], 3, 31);
                if (copy_count_bits != 1) {
                    copy_count = copy_count << 1;
                    if (dec.readBit(&probs[16], 3, 31) != 0) {
                        copy_count += 1;
                        if (copy_count == 0xFF) {
                            if (dec.failed) return invalid_format;
                            consumed.* = dec.pos;
                            return @intCast(cur);
                        }
                    }
                }
                dist_bits_index = 56 + copy_count_bits;
                pow_limit = if (is_kl4e) 256 else 128;
            }
        } else {
            pow_limit = 64;
            dist_bits_index = copy_count_bits;
        }

        // Number of bits in the distance code.
        var cur_pow: i32 = 8;
        var skip = false;
        var copy_dist_bits: i32 = undefined;
        var copy_dist: u32 = 0;
        while (true) {
            // The base index may be -1; combine before indexing.
            const idx: usize = @intCast(dist_bits_index + cur_pow - 7);
            cur_pow <<= 1;
            copy_dist_bits = cur_pow - pow_limit;
            if (dec.readBit(&copy_dist_bits_probs[idx], 3, 31) == 0) {
                if (copy_dist_bits >= 0) {
                    if (copy_dist_bits != 0) {
                        copy_dist_bits -= 8;
                        break;
                    }
                    copy_dist = 0;
                    skip = true;
                    break;
                }
            } else {
                cur_pow += 8;
                if (copy_dist_bits >= 0) break;
            }
        }

        if (!skip) {
            if (copy_dist_bits < 0 or copy_dist_bits > copy_dist_probs.len - 4) return invalid_format;
            const cp: usize = @intCast(copy_dist_bits);
            const probs = copy_dist_probs[cp..];
            var read_bits: i32 = @divTrunc(copy_dist_bits, 8);
            if (read_bits < 3) {
                copy_dist = 1;
            } else {
                copy_dist = 2 + dec.readBit(&probs[3], 3, 31);
                if (read_bits > 3) {
                    copy_dist = (copy_dist << 1) | dec.readBit(&probs[3], 3, 31);
                    if (read_bits > 4) {
                        copy_dist = (copy_dist << 1) | dec.readBitUniform();
                        read_bits -= 1;
                    }
                    while (read_bits > 4) {
                        copy_dist = copy_dist << 1;
                        copy_dist +%= dec.readBitUniformNoNormal();
                        read_bits -= 1;
                    }
                }
            }
            copy_dist = copy_dist << 1;
            if (dec.readBit(&probs[0], 3, 31) != 0) {
                if (read_bits > 0) copy_dist +%= 1;
            } else {
                if (read_bits <= 0) copy_dist -%= 1;
            }
            if (read_bits > 0) {
                copy_dist = copy_dist << 1;
                if (dec.readBit(&probs[1], 3, 31) != 0) {
                    if (read_bits != 1) copy_dist +%= 1;
                } else {
                    if (read_bits == 1) copy_dist -%= 1;
                }
                if (read_bits != 1) {
                    copy_dist = copy_dist << 1;
                    if (dec.readBit(&probs[2], 3, 31) == 0) copy_dist -%= 1;
                }
            }
        }

        if (dec.failed) return invalid_format;
        if (copy_dist >= cur) return invalid_format;
        if (@as(usize, copy_count) + 1 > out_size - cur) return output_too_small;
        // Forward byte copy: overlapping references replicate earlier output.
        const src = cur - copy_dist - 1;
        var k: usize = 0;
        while (k < @as(usize, copy_count) + 1) : (k += 1) buf[cur + k] = buf[src + k];
        cur_byte = buf[cur + copy_count];
        cur += copy_count;
        cc_idx = 6 + (cur & 1);
    }
}

/// C `decompress_kle_bounded`.
pub fn decompressKleBounded(out: []u8, in: []const u8, is_kl4e: bool) i32 {
    var consumed: usize = undefined;
    return decompressKleBoundedMember(out, in, is_kl4e, &consumed);
}

test "direct copy and bounds" {
    const input = "\x80\x00\x00\x00\x03abc";
    var out: [4]u8 = @splat(0xa5);
    try std.testing.expectEqual(@as(i32, 3), decompressKleBounded(out[0..3], input, true));
    try std.testing.expectEqualSlices(u8, "abc\xa5", &out);
    try std.testing.expectEqual(output_too_small, decompressKleBounded(out[0..2], input, true));
    try std.testing.expectEqual(invalid_format, decompressKleBounded(out[0..2], input[0 .. input.len - 1], true));
    try std.testing.expectEqual(invalid_format, decompressKleBounded(&out, input[0..4], true));
}

test "compressed stream and member accounting" {
    const compressed = "\x07\x90\xcc\xe4\x56\xe6\x8a\x53\x77\x3b\x32\x9d\x00\x00\x00";
    var out: [8]u8 = undefined;
    var used: usize = undefined;
    try std.testing.expectEqual(@as(i32, 8), decompressKleBoundedMember(&out, compressed, true, &used));
    try std.testing.expectEqualStrings("offsets!", &out);
    try std.testing.expect(used > 5 and used <= compressed.len);
    try std.testing.expectEqual(output_too_small, decompressKleBounded(out[0..7], compressed, false));
    for (0..compressed.len) |n| {
        try std.testing.expectEqual(invalid_format, decompressKleBounded(&out, compressed[0..n], true));
    }
}
