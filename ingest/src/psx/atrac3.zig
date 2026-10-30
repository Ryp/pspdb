//! PS1 Classics audio: CDDA payload unscrambling and bit-exact ATRAC3 decoding.
//!
//! Replaces `tools/psxtract/atrac3.cpp` (+ FFmpeg built with GCC x87 flags) and
//! the PSXtract-2 `unscramble_atrac_data` / `convert_wav_to_bin` audio path.
//! The decoder is the trimmed, patched FFmpeg ATRAC3 subset in
//! `atrac3/pspdb_atrac3.c` (see `atrac3/NOTICE`); it reproduces the Sony ACM

//! oracle `vib-track02-oracle.wav` (whole 28 MB track).
const std = @import("std");

const c = struct {
    extern fn pspdb_atrac3_pcm_size(nframes: usize) usize;
    extern fn pspdb_atrac3_decode(frames: [*]const u8, nframes: usize, pcm: [*]u8, pcm_capacity: usize) c_int;
};

/// Bytes per ATRAC3 frame (two 192-byte channel units) == PSXtract `NBYTES`.
pub const frame_bytes: usize = 0x180;
pub const sector_size: usize = 2352;
/// Largest accepted CDDA payload; a full 80-minute disc at 132 kbit/s is ~80 MB.
pub const max_payload: usize = 256 << 20;

pub const Error = error{
    /// Payload is empty, not a multiple of 384 bytes, too large, or too short to
    /// outlast the 1165 priming samples; or `sectors` is out of range.
    InvalidAtrac3Size,
    /// The x87 control word is not extended precision / round-to-nearest.
    Atrac3Arithmetic,
    /// A frame failed ATRAC3 validation.
    InvalidAtrac3Stream,
    OutOfMemory,
};

/// Port of PSXtract `unscramble_atrac_data` (in place). `buf` is the track's
/// `audio_entry->size` bytes; a trailing partial 384-byte chunk is left
/// untouched exactly as upstream. Each chunk starts from `tmp2` (initially the
/// CDDA entry checksum, rotated right by one per chunk); the running value
/// chains over the *scrambled* words.
pub fn unscramble(buf: []u8, checksum: u32) void {
    const words_per_chunk = frame_bytes / 4;
    var tmp2 = checksum;
    var chunk: usize = 0;
    while ((chunk + 1) * frame_bytes <= buf.len) : (chunk += 1) {
        var tmp = tmp2;
        const base = chunk * frame_bytes;
        for (0..words_per_chunk) |k| {
            const at = base + k * 4;
            const value = std.mem.readInt(u32, buf[at..][0..4], .little);
            std.mem.writeInt(u32, buf[at..][0..4], tmp ^ value, .little);
            tmp = tmp2 +% value *% 123456789;
        }
        tmp2 = std.math.rotr(u32, tmp2, 1);
    }
}

/// Decode an unscrambled CDDA payload and return exactly the bytes PSXtract
/// copies after the track's pregap: the transport WAV from file offset 44
/// (the two high bytes of its little-endian PCM size field, then the stereo
/// s16le PCM), truncated or zero-padded to `sectors * 2352`.
/// Transport rules: 1165 priming samples are dropped; each sample is
/// `trunc(clamp(-float * 32768))`; the PCM length is `frames * 4096 - 4660`.
pub fn decodeTrack(alloc: std.mem.Allocator, cdda_payload: []const u8, sectors: u32) Error![]u8 {
    if (cdda_payload.len == 0 or cdda_payload.len % frame_bytes != 0 or cdda_payload.len > max_payload)
        return error.InvalidAtrac3Size;
    const out_len = std.math.mul(usize, sectors, sector_size) catch return error.InvalidAtrac3Size;
    if (out_len > std.math.maxInt(i32)) return error.InvalidAtrac3Size;

    const nframes = cdda_payload.len / frame_bytes;
    const pcm_len = c.pspdb_atrac3_pcm_size(nframes);
    if (pcm_len == 0) return error.InvalidAtrac3Size;

    const full_len = pcm_len + 2;
    const buf = try alloc.alloc(u8, @max(full_len, out_len));
    errdefer alloc.free(buf);
    const status = c.pspdb_atrac3_decode(cdda_payload.ptr, nframes, buf[2..].ptr, pcm_len);
    switch (status) {
        0 => {},
        -1 => return error.Atrac3Arithmetic,
        -2 => return error.InvalidAtrac3Stream,
        else => return error.InvalidAtrac3Size,
    }
    // WAV bytes 44..45 are the high half of the u32 PCM size at offset 42.
    buf[0] = @truncate(pcm_len >> 16);
    buf[1] = @truncate(pcm_len >> 24);
    if (out_len > full_len) @memset(buf[full_len..out_len], 0);
    if (buf.len == out_len) return buf;
    return alloc.realloc(buf, out_len);
}

const testing = std.testing;
const fragment = @embedFile("atrac3/fragment.at3");

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "decodeTrack matches the Sony ACM oracle prefix (60 frames, padded)" {
    // fragment.at3: first 60 frames of Vib-Ribbon track 02 (unscrambled payload).
    // Expected hashes come from vib-track02-oracle.wav (offset 46..., PCM
    // 60*4096-4660 = 241100 bytes), prefixed with the two WAV size bytes 03 00.
    try testing.expectEqualStrings(
        "51c7f1f88413db8332b4afe76d787def521277cf4615fabe6f30631194d89aae",
        &sha256Hex(fragment),
    );
    const padded = try decodeTrack(testing.allocator, fragment, 105);
    defer testing.allocator.free(padded);
    try testing.expectEqual(@as(usize, 105 * sector_size), padded.len);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x00 }, padded[0..2]);
    try testing.expectEqualStrings(
        "b81281915efcbaccc3b94c7fd0f0618a7aac52db3ad32adaa91dd2e0292b0c9a",
        &sha256Hex(padded),
    );
    // PCM payload itself, without the quirk bytes and padding.
    try testing.expectEqualStrings(
        "c57a43995b6d71f204ccc581ddebae1ea7c4b18f96738f3fbe0359491e09db3c",
        &sha256Hex(padded[2..][0..241100]),
    );
    for (padded[2 + 241100 ..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "decodeTrack truncates to the requested sector count" {
    const out = try decodeTrack(testing.allocator, fragment, 20);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 20 * sector_size), out.len);
    try testing.expectEqualStrings(
        "17287b0aecf401b80bf28a5dbcc86c25fb177b9d1cf85adb8c05c3bff3235767",
        &sha256Hex(out),
    );
}

test "decodeTrack rejects malformed payload sizes" {
    try testing.expectError(error.InvalidAtrac3Size, decodeTrack(testing.allocator, &.{}, 1));
    try testing.expectError(error.InvalidAtrac3Size, decodeTrack(testing.allocator, fragment[0 .. frame_bytes + 1], 1));
    // One frame (1024 samples) does not outlast the 1165 priming samples.
    try testing.expectError(error.InvalidAtrac3Size, decodeTrack(testing.allocator, fragment[0..frame_bytes], 1));
    try testing.expectError(error.InvalidAtrac3Size, decodeTrack(testing.allocator, fragment, std.math.maxInt(u32)));
}

test "decodeTrack reports undecodable frames" {
    var bad: [2 * frame_bytes]u8 = @splat(0xff);
    try testing.expectError(error.InvalidAtrac3Stream, decodeTrack(testing.allocator, &bad, 1));
}

test "unscramble inverts the PSX scrambler and leaves a partial chunk alone" {
    var plain: [3 * frame_bytes + 100]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    prng.random().bytes(&plain);

    // Forward scramble: s = p ^ tmp, tmp = tmp2 + s * 123456789 (chains on s).
    const checksum: u32 = 0xdeadbeef;
    var scrambled = plain;
    var tmp2 = checksum;
    var chunk: usize = 0;
    while ((chunk + 1) * frame_bytes <= scrambled.len) : (chunk += 1) {
        var tmp = tmp2;
        for (0..frame_bytes / 4) |k| {
            const at = chunk * frame_bytes + k * 4;
            const p = std.mem.readInt(u32, scrambled[at..][0..4], .little);
            const s = p ^ tmp;
            std.mem.writeInt(u32, scrambled[at..][0..4], s, .little);
            tmp = tmp2 +% s *% 123456789;
        }
        tmp2 = std.math.rotr(u32, tmp2, 1);
    }
    try testing.expect(!std.mem.eql(u8, &plain, &scrambled));
    unscramble(&scrambled, checksum);
    try testing.expectEqualSlices(u8, &plain, &scrambled);
}
