//! CD-ROM XA sector reconstruction for PS1 Classics data tracks.
//!
//! Exact in-memory port of PSXtract-2 `cdrom.cpp` `fixImage` (sync + BCD MSF
//! header regeneration, Mode 2 form 1 EDC and RSPC P/Q parity, form 2 EDC
//! inference from boot sectors 12-15, mode 0 zero padding), plus the TOC-derived
//! sector-count / gap helpers from `psxtract.cpp` (`data_track_sectors`,
//! `fix_iso`).
//!
//! Differences from PSXtract: failures are reported as errors instead of being
//! silently ignored, and everything works in place on a caller-owned buffer.
//! The EDC and RSPC tables are generated at comptime.

const std = @import("std");

pub const sector_size: usize = 2352;
/// Pregap frames (2 s) PSXtract adds in front of the data track (`GAP_FRAMES`).
pub const gap_frames: u32 = 150;
/// Absolute LBA of MSF 00:02:00, where PSXtract starts numbering the headers.
pub const psx_start_lba: u32 = 150;

const sync_size = 12;
const header_offset = sync_size;
const header_size = 4;
const subheader_offset = header_offset + header_size; // 16
const subheader_size = 8;
const form1_user_offset = subheader_offset + subheader_size; // 24
const form1_edc_offset = form1_user_offset + 2048; // 2072
const form2_edc_offset = form1_user_offset + 2324; // 2348
const edc_size = 4;
const parity_p_offset = form1_edc_offset + edc_size; // 2076
const parity_p_size = 43 * 2 * 2; // 172
const parity_q_offset = parity_p_offset + parity_p_size; // 2248
const bootloader_sectors = 16;
/// Largest absolute LBA expressible as BCD MSF (99:59:74).
const max_lba: u32 = (99 * 60 + 59) * 75 + 74;

const sync_pattern = [sync_size]u8{ 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// EDC lookup: reflected CRC-32 with polynomial 0xD8018001 (ECMA-130 annex A),
/// identical to PSXtract's embedded `EDCTable`.
const edc_table: [256]u32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*e, n| {
        var v: u32 = @intCast(n);
        for (0..8) |_| v = (v >> 1) ^ (if (v & 1 != 0) @as(u32, 0xD8018001) else 0);
        e.* = v;
    }
    break :blk t;
};

/// Per-position RS coefficients (the high-byte multiplier) of PSXtract's
/// `RSPCTable[43][256]`; the low-byte multiplier is always `coef ^ 1`.
const rspc_coef = [43]u8{
    0xae, 0xd9, 0x6c, 0xb8, 0xd2, 0xe7, 0x73, 0x39, 0x1c, 0x80, 0xce, 0xe9, 0x74, 0xb4, 0xd4, 0xe4,
    0xfc, 0xf0, 0xf6, 0xf5, 0x7a, 0xb3, 0x59, 0x2c, 0x98, 0xc2, 0xef, 0x77, 0x3b, 0x1d, 0x0e, 0x89,
    0x44, 0xac, 0xd8, 0xe2, 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03,
};

/// Multiplication in GF(2^8) modulo x^8+x^4+x^3+x^2+1 (0x11D).
fn gfMul(a_in: u8, b_in: u8) u8 {
    var a: u16 = a_in;
    var b: u8 = b_in;
    var r: u8 = 0;
    while (b != 0) : (b >>= 1) {
        if (b & 1 != 0) r ^= @as(u8, @truncate(a));
        a <<= 1;
        if (a & 0x100 != 0) a ^= 0x11D;
    }
    return r;
}

/// `rspc_table[j][b] = (b * c_j) << 8 | (b * (c_j ^ 1))` over GF(2^8).
const rspc_table: [43][256]u16 = blk: {
    @setEvalBranchQuota(4_000_000);
    var t: [43][256]u16 = undefined;
    for (&t, rspc_coef) |*row, c| {
        for (row, 0..) |*e, b| {
            const hi: u16 = gfMul(@intCast(b), c);
            const lo: u16 = gfMul(@intCast(b), c ^ 1);
            e.* = (hi << 8) | lo;
        }
    }
    break :blk t;
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub const FixError = error{
    /// Image is empty, not a multiple of 2352 bytes, or shorter than the
    /// 16 boot sectors needed for form 2 EDC inference (PSXtract
    /// `ERROR_IMAGE_INCOMPLETE`).
    ImageIncomplete,
    /// A Mode 1 sector was found (`ERROR_UNSUPPORTED_MODE`).
    UnsupportedMode1,
    /// Sector mode byte other than 0, 1 or 2 (`ERROR_UNEXPECTED_MODE`; PSXtract
    /// treats this as "non-standard pregap before audio" and keeps the output
    /// written so far — use `fixImagePartial` to get the same prefix).
    UnexpectedMode,
    /// A mode 0 sector with non-zero payload (`ERROR_MODE0_IS_NOT_0`).
    Mode0NotZero,
    /// MSF of a sector would exceed 99:59:74.
    LbaOutOfRange,
};

/// Counters as logged by PSXtract `make_cdrom`.
pub const FixStats = struct {
    mode0_sectors: u32 = 0,
    /// Always 0: Mode 1 is rejected (`error.UnsupportedMode1`).
    mode1_sectors: u32 = 0,
    mode2_form1_sectors: u32 = 0,
    mode2_form2_sectors: u32 = 0,
    form2_boot_sectors_with_edc: u32 = 0,
    form2_boot_sectors_without_edc: u32 = 0,
    /// Sectors processed (== image sectors on success; PSXtract `totalsectors`).
    total_sectors: u32 = 0,
    /// Number of subheader/copy field mismatches (PSXtract warnings).
    subheader_mismatches: u32 = 0,
    /// Form 2 EDC mode chosen by inference: true = compute, false = zero.
    form2_edc_computed: bool = false,
};

// ---------------------------------------------------------------------------
// EDC / ECC primitives
// ---------------------------------------------------------------------------

/// EDC over `data` (initial value 0, no final XOR), as stored little-endian.
pub fn edc(data: []const u8) u32 {
    var e: u32 = 0;
    for (data) |b| {
        e ^= b;
        e = (e >> 8) ^ edc_table[e & 0xFF];
    }
    return e;
}

fn putU32le(dst: []u8, v: u32) void {
    std.mem.writeInt(u32, dst[0..4], v, .little);
}

/// Write P and Q parity of a Mode 2 form 1 sector. The header (bytes 12..16)
/// MUST already be zeroed; user data and EDC must be final.
fn writeParity(s: *[sector_size]u8) void {
    // P parity: 43 columns of 24 rows, parity rows at +0 and +86.
    for (0..43) |i| {
        var x: u16 = 0;
        var y: u16 = 0;
        var src: usize = header_offset + 2 * i;
        for (19..43) |j| {
            x ^= rspc_table[j][s[src]];
            y ^= rspc_table[j][s[src + 1]];
            src += 2 * 43;
        }
        const dst = parity_p_offset + 2 * i;
        s[dst] = @intCast(x >> 8);
        s[dst + 2 * 43] = @intCast(x & 0xFF);
        s[dst + 1] = @intCast(y >> 8);
        s[dst + 2 * 43 + 1] = @intCast(y & 0xFF);
    }
    // Q parity: 26 diagonals of 43 words over header..P parity.
    const wrap = header_size + subheader_size + 2048 + edc_size + parity_p_size; // 2236
    for (0..26) |i| {
        var x: u16 = 0;
        var y: u16 = 0;
        var src: usize = header_offset + 2 * 43 * i;
        for (0..43) |j| {
            x ^= rspc_table[j][s[src]];
            y ^= rspc_table[j][s[src + 1]];
            src += 2 * 44;
            if (src >= parity_q_offset) src -= wrap;
        }
        const dst = parity_q_offset + 2 * i;
        s[dst] = @intCast(x >> 8);
        s[dst + 2 * 26] = @intCast(x & 0xFF);
        s[dst + 1] = @intCast(y >> 8);
        s[dst + 2 * 26 + 1] = @intCast(y & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// MSF
// ---------------------------------------------------------------------------

const Msf = struct {
    m: u8,
    s: u8,
    f: u8,

    /// BCD MSF of absolute LBA; null if beyond 99:59:74.
    fn fromLba(lba: u32) ?Msf {
        if (lba > max_lba) return null;
        const frames = lba % 75;
        const secs = (lba / 75) % 60;
        const mins = lba / 75 / 60;
        return .{ .m = bcd(mins), .s = bcd(secs), .f = bcd(frames) };
    }
};

fn bcd(v: u32) u8 {
    return @intCast(((v / 10) << 4) | (v % 10));
}

// ---------------------------------------------------------------------------
// fixImage
// ---------------------------------------------------------------------------

/// Reconstruct a raw 2352-byte-per-sector CD image in place.
///
/// `start_lba` is the absolute LBA of the first sector. PSXtract numbers the
/// first header 00:02:00, i.e. `psx_start_lba` (150); pass that for byte parity.
pub fn fixImage(image: []u8, start_lba: u32) FixError!FixStats {
    var stats = FixStats{};
    try fixImagePartial(image, start_lba, false, &stats);
    return stats;
}

/// Like `fixImage` but exposes the counters even on failure. After an error,
/// `stats.total_sectors` is the number of fully processed sectors, matching
/// what PSXtract returns (`make_cdrom` yields `totalsectors` even on
/// `ERROR_UNEXPECTED_MODE`) — sectors before it are fixed, the rest untouched.
///
/// `tail_nonzero` states that the file PSXtract reads continues past `image`
/// with non-zero data (the block-aligned DATA_TRACK.BIN is longer than the TOC
/// sector count). Its "remainder is zero" scan runs to the end of that file, so
/// a mode 0 sector is then never the start of the zero padding.
pub fn fixImagePartial(image: []u8, start_lba: u32, tail_nonzero: bool, stats: *FixStats) FixError!void {
    if (image.len == 0 or image.len % sector_size != 0) return error.ImageIncomplete;
    const n = image.len / sector_size;
    if (n < bootloader_sectors) return error.ImageIncomplete;
    if (start_lba > max_lba or n - 1 > max_lba - start_lba) return error.LbaOutOfRange;

    // Form 2 EDC mode inference from boot sectors 12-15 (before any change).
    for (12..16) |i| {
        const sec = image[i * sector_size ..][0..sector_size];
        if (std.mem.readInt(u32, sec[form2_edc_offset..][0..4], .little) == 0) {
            stats.form2_boot_sectors_without_edc += 1;
        } else {
            stats.form2_boot_sectors_with_edc += 1;
        }
    }
    const compute_form2 = stats.form2_boot_sectors_without_edc < stats.form2_boot_sectors_with_edc;
    stats.form2_edc_computed = compute_form2;

    // First sector index from which every following sector is entirely zero
    // (lazily computed; makes the "is the remainder zero padding" test O(1)).
    var zero_tail_start: ?usize = null;

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const s: *[sector_size]u8 = image[i * sector_size ..][0..sector_size];
        const msf = Msf.fromLba(start_lba + @as(u32, @intCast(i))) orelse return error.LbaOutOfRange;
        const mode = s[header_offset + 3];

        switch (mode) {
            0 => {
                if (!std.mem.allEqual(u8, s[subheader_offset..], 0)) return error.Mode0NotZero;
                if (zero_tail_start == null) {
                    var t = n;
                    while (t > 0 and std.mem.allEqual(u8, image[(t - 1) * sector_size ..][0..sector_size], 0)) t -= 1;
                    zero_tail_start = t;
                }
                if (!tail_nonzero and zero_tail_start.? <= i + 1) {
                    // Start of the zero padding: this sector and all that follow
                    // are all-zero mode 0 sectors (already zero in memory).
                    @memset(s, 0);
                    const rest: u32 = @intCast(n - i);
                    stats.mode0_sectors += rest;
                    stats.total_sectors += rest;
                    return;
                }
                // Mode 0 sector followed by more data: PSXtract keeps it as an
                // (otherwise empty) Mode 2 sector with sync and header.
                @memcpy(s[0..sync_size], &sync_pattern);
                s[header_offset + 0] = msf.m;
                s[header_offset + 1] = msf.s;
                s[header_offset + 2] = msf.f;
                s[header_offset + 3] = 2;
                stats.mode0_sectors += 1;
            },
            1 => return error.UnsupportedMode1,
            2 => {
                @memcpy(s[0..sync_size], &sync_pattern);
                // Subheader copies are only checked, never repaired.
                for (0..4) |k| {
                    if (s[subheader_offset + k] != s[subheader_offset + 4 + k]) stats.subheader_mismatches += 1;
                }
                const is_form2 = s[subheader_offset + 2] & 0x20 != 0;
                if (is_form2) {
                    s[header_offset + 0] = msf.m;
                    s[header_offset + 1] = msf.s;
                    s[header_offset + 2] = msf.f;
                    s[header_offset + 3] = 2;
                    putU32le(s[form2_edc_offset..], if (compute_form2) edc(s[subheader_offset..form2_edc_offset]) else 0);
                    stats.mode2_form2_sectors += 1;
                } else {
                    putU32le(s[form1_edc_offset..], edc(s[subheader_offset..form1_edc_offset]));
                    @memset(s[header_offset..][0..header_size], 0);
                    writeParity(s);
                    s[header_offset + 0] = msf.m;
                    s[header_offset + 1] = msf.s;
                    s[header_offset + 2] = msf.f;
                    s[header_offset + 3] = 2;
                    stats.mode2_form1_sectors += 1;
                }
            },
            else => return error.UnexpectedMode,
        }
        stats.total_sectors += 1;
    }
}

// ---------------------------------------------------------------------------
// TOC-derived sector count and data gap (PSXtract data_track_sectors/fix_iso)
// ---------------------------------------------------------------------------

pub const TocError = error{InvalidToc};

/// BCD minute/second/frame triple as stored in the ISO header TOC.
pub const BcdMsf = struct { m: u8, s: u8, f: u8 };

fn bcdToDec(v: u8) i64 {
    // PSXtract: 10 * (v - v % 16) / 16 + v % 16 (no nibble validation).
    return 10 * @as(i64, v >> 4) + (v & 0x0F);
}

fn framesWithGap(t: BcdMsf, gap_seconds: i64) i64 {
    return bcdToDec(t.m) * 60 * 75 + (bcdToDec(t.s) - gap_seconds) * 75 + bcdToDec(t.f);
}

/// Expected number of data-track sectors: `(next - track1) - 150`, where both
/// are INDEX 01 times. Track starts are taken minus the 2 s pregap; the
/// lead-out (`next_is_leadout`, used when track 1 is the last track) is taken
/// as stored — exactly as PSXtract `get_track_size_from_cue` does.
pub fn dataTrackSectors(track1: BcdMsf, next: BcdMsf, next_is_leadout: bool) TocError!u32 {
    const cur = framesWithGap(track1, 2);
    if (cur < 0) return error.InvalidToc;
    const nxt = framesWithGap(next, if (next_is_leadout) 0 else 2);
    if (nxt < 0) return error.InvalidToc;
    const size = nxt - cur - gap_frames;
    if (size < 0 or size > std.math.maxInt(u32)) return error.InvalidToc;
    return @intCast(size);
}

/// Pregap before the following track: `expected - actual + 150` (PSXtract
/// `fix_iso` return value; 150 when the data track was fully reconstructed).
pub fn dataGap(expected_sectors: u32, actual_sectors: u32) TocError!u32 {
    if (actual_sectors > expected_sectors) return error.InvalidToc;
    return expected_sectors - actual_sectors + gap_frames;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Same generator as the throwaway C-harness fixture (xorshift32).
const Rng = struct {
    x: u32,
    fn next(self: *Rng) u8 {
        var x = self.x;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.x = x;
        return @truncate(x);
    }
};

const Kind = enum { f1, f2, m0, zero };

fn genSector(r: *Rng, kind: Kind, edc_nonzero: bool) [sector_size]u8 {
    var s: [sector_size]u8 = undefined;
    for (&s) |*b| b.* = r.next();
    switch (kind) {
        .zero => s = @splat(0),
        .m0 => {
            @memset(s[16..], 0);
            s[15] = 0;
        },
        .f1, .f2 => {
            s[15] = 2;
            const sub: u8 = if (kind == .f1) 0x08 else 0x20;
            s[16..20].* = .{ 1, 2, sub, 0x40 };
            s[20..24].* = s[16..20].*;
            if (kind == .f2) {
                if (!edc_nonzero) {
                    @memset(s[2348..2352], 0);
                } else if (std.mem.allEqual(u8, s[2348..2352], 0)) {
                    s[2348] = 1;
                }
            }
        },
    }
    return s;
}

const fixture_sectors = 24;

fn buildFixture(edc_in_boot: bool) [fixture_sectors * sector_size]u8 {
    var img: [fixture_sectors * sector_size]u8 = undefined;
    var r = Rng{ .x = 0x12345678 };
    var idx: usize = 0;
    const put = struct {
        fn f(buf: *[fixture_sectors * sector_size]u8, at: *usize, s: [sector_size]u8) void {
            buf[at.* * sector_size ..][0..sector_size].* = s;
            at.* += 1;
        }
    }.f;
    for (0..12) |_| put(&img, &idx, genSector(&r, .f1, true));
    for (0..4) |_| put(&img, &idx, genSector(&r, .f2, edc_in_boot));
    put(&img, &idx, genSector(&r, .f1, true)); // 16
    put(&img, &idx, genSector(&r, .f2, true)); // 17
    put(&img, &idx, genSector(&r, .f2, false)); // 18
    var mm = genSector(&r, .f1, true); // 19: submode copy mismatch
    mm[16..20].* = .{ 1, 2, 0x08, 0x40 };
    mm[20..24].* = .{ 1, 2, 0x28, 0x40 };
    put(&img, &idx, mm);
    put(&img, &idx, genSector(&r, .m0, true)); // 20: mode 0 followed by data
    put(&img, &idx, genSector(&r, .f1, true)); // 21
    put(&img, &idx, genSector(&r, .m0, true)); // 22: zero padding starts
    put(&img, &idx, genSector(&r, .zero, true)); // 23
    return img;
}

// Per-sector CRC-32 of the output of the unmodified PSXtract-2 cdrom.cpp
// (compiled as a throwaway C++ harness) for the fixtures above.
const crc_boot_edc = [fixture_sectors]u32{
    0xec691191, 0xdce6a548, 0x3f37f381, 0xa60e30b2, 0x8f3fda1e, 0x9b943da0,
    0x47ec3667, 0x08376ac4, 0x6065e8ac, 0x3e089a3e, 0x91e0b00c, 0x08642354,
    0x74f53498, 0x0ec05150, 0x3c8fc77c, 0x237ff5b7, 0xec5515f6, 0xe7536d9d,
    0x4919451f, 0xd5b3ac3e, 0x0601edfb, 0x6002e38d, 0xbe97ce3f, 0xbe97ce3f,
};
const crc_boot_noedc = [fixture_sectors]u32{
    0xec691191, 0xdce6a548, 0x3f37f381, 0xa60e30b2, 0x8f3fda1e, 0x9b943da0,
    0x47ec3667, 0x08376ac4, 0x6065e8ac, 0x3e089a3e, 0x91e0b00c, 0x08642354,
    0xa0d855c9, 0x18ece10f, 0x564a9f3e, 0xb65ae8cc, 0xec5515f6, 0x92a7be52,
    0xd2f4ea4e, 0xd5b3ac3e, 0x0601edfb, 0x6002e38d, 0xbe97ce3f, 0xbe97ce3f,
};

fn expectCrcs(img: []const u8, want: *const [fixture_sectors]u32) !void {
    for (0..fixture_sectors) |i| {
        const got = std.hash.Crc32.hash(img[i * sector_size ..][0..sector_size]);
        testing.expectEqual(want[i], got) catch |err| {
            std.debug.print("sector {d}: got 0x{x:0>8} want 0x{x:0>8}\n", .{ i, got, want[i] });
            return err;
        };
    }
}

test "tables match PSXtract embedded tables" {
    // CRC-32 of the little-endian dump of the upstream tables.
    var buf: [43 * 256 * 2]u8 = undefined;
    for (rspc_table, 0..) |row, j| {
        for (row, 0..) |v, b| std.mem.writeInt(u16, buf[(j * 256 + b) * 2 ..][0..2], v, .little);
    }
    try testing.expectEqual(@as(u32, 0x37b70b65), std.hash.Crc32.hash(&buf));
    var ebuf: [256 * 4]u8 = undefined;
    for (edc_table, 0..) |v, i| std.mem.writeInt(u32, ebuf[i * 4 ..][0..4], v, .little);
    try testing.expectEqual(@as(u32, 0x9e43db92), std.hash.Crc32.hash(&ebuf));
    // spot checks against the literal first/last entries of cdrom.h
    try testing.expectEqual(@as(u32, 0x90910101), edc_table[1]);
    try testing.expectEqual(@as(u32, 0x7070FF00), edc_table[255]);
    try testing.expectEqual(@as(u16, 0xAEAF), rspc_table[0][1]);
    try testing.expectEqual(@as(u16, 0x4143), rspc_table[0][2]);
    try testing.expectEqual(@as(u16, 0xD9D8), rspc_table[1][1]);
}

test "edc is the standard CD-ROM EDC (CRC of 'check' style vector)" {
    try testing.expectEqual(@as(u32, 0), edc(&[_]u8{}));
    try testing.expectEqual(@as(u32, 0), edc(&[_]u8{ 0, 0, 0, 0 }));
    // one byte 0x01 -> table[1]
    try testing.expectEqual(@as(u32, 0x90910101), edc(&[_]u8{1}));
}

test "form 1: EDC and P/Q parity match PSXtract C reference" {
    var img = buildFixture(true);
    const stats = try fixImage(&img, psx_start_lba);
    try testing.expectEqual(@as(u32, 15), stats.mode2_form1_sectors);

    var want: [280]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "57a4927bf8414da27fdb79a310b9a6dcdfaf867753ed10fc6c3018d6f20b65d75c05ae2f094eb43f8c1c65f881970c578eb2865e940640dd107d4e607f08f6fe578cb799d5ce6e5c8bafc7c5f4f2399f02d39dc5240da3391295e3eaed9c79a88d42b01f1c16118892032c91ffc9f69c5b762be711cce873077ceddf84a32042269455ebee5e95f3e0f571045918fd3637177ce8cc340d0414b1bb9c0917fe61f67688c98b94846e8b6816a23c7135c7af0e1b504fdd62f3080d27110d7a2d68749d1e754c8c04348f63f5278ce0cb9790d27ac3ab034696f4a00446aa4bf274139935d9c198eaa62543f091e0781c54a55cc1ffad3d24552015c3c627ba430fefa3bbbd666eae1a8d337603354f25ab972419a0d2a543f2");
    try testing.expectEqualSlices(u8, &want, img[form1_edc_offset..sector_size]);
    const hdr = [_]u8{ 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, 0x02 };
    try testing.expectEqualSlices(u8, &hdr, img[0..16]);
}

test "full fixture parity with C reference, boot sectors with EDC => form 2 EDC computed" {
    var img = buildFixture(true);
    const st = try fixImage(&img, psx_start_lba);
    try expectCrcs(&img, &crc_boot_edc);
    try testing.expectEqual(@as(u32, 3), st.mode0_sectors);
    try testing.expectEqual(@as(u32, 0), st.mode1_sectors);
    try testing.expectEqual(@as(u32, 15), st.mode2_form1_sectors);
    try testing.expectEqual(@as(u32, 6), st.mode2_form2_sectors);
    try testing.expectEqual(@as(u32, 4), st.form2_boot_sectors_with_edc);
    try testing.expectEqual(@as(u32, 0), st.form2_boot_sectors_without_edc);
    try testing.expectEqual(@as(u32, 24), st.total_sectors);
    try testing.expectEqual(@as(u32, 1), st.subheader_mismatches);
    try testing.expect(st.form2_edc_computed);
    // form 2 sector 12: EDC covers subheader..user data and is non-zero
    try testing.expect(!std.mem.allEqual(u8, img[12 * sector_size + form2_edc_offset ..][0..4], 0));
    // MSF of sector 20 (mode 0 followed by data): 00:02:20 -> BCD, mode 2
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x20, 0x02 }, img[20 * sector_size + 12 ..][0..4]);
    // zero padding stays fully zero
    try testing.expect(std.mem.allEqual(u8, img[22 * sector_size ..], 0));
}

test "full fixture parity with C reference, boot sectors without EDC => form 2 EDC zeroed" {
    var img = buildFixture(false);
    const st = try fixImage(&img, psx_start_lba);
    try expectCrcs(&img, &crc_boot_noedc);
    try testing.expectEqual(@as(u32, 0), st.form2_boot_sectors_with_edc);
    try testing.expectEqual(@as(u32, 4), st.form2_boot_sectors_without_edc);
    try testing.expect(!st.form2_edc_computed);
    try testing.expect(std.mem.allEqual(u8, img[17 * sector_size + form2_edc_offset ..][0..4], 0));
    try testing.expectEqual(@as(u32, 6), st.mode2_form2_sectors);
}

test "boot EDC inference tie goes to zero (PSXtract: without >= with)" {
    var img = buildFixture(true);
    // clear the EDC of two of the four boot sectors => 2 with, 2 without
    @memset(img[12 * sector_size + form2_edc_offset ..][0..4], 0);
    @memset(img[13 * sector_size + form2_edc_offset ..][0..4], 0);
    const st = try fixImage(&img, psx_start_lba);
    try testing.expectEqual(@as(u32, 2), st.form2_boot_sectors_with_edc);
    try testing.expectEqual(@as(u32, 2), st.form2_boot_sectors_without_edc);
    try testing.expect(!st.form2_edc_computed);
    try testing.expect(std.mem.allEqual(u8, img[14 * sector_size + form2_edc_offset ..][0..4], 0));
    // one with, three without => zero; three with, one without => compute
    var img3 = buildFixture(true);
    @memset(img3[12 * sector_size + form2_edc_offset ..][0..4], 0);
    const st3 = try fixImage(&img3, psx_start_lba);
    try testing.expect(st3.form2_edc_computed);
}

fn makeForm1Image(comptime n: usize) [n * sector_size]u8 {
    var img: [n * sector_size]u8 = undefined;
    var r = Rng{ .x = 0xCAFEBABE };
    for (0..n) |i| img[i * sector_size ..][0..sector_size].* = genSector(&r, .f1, true);
    return img;
}

test "MSF BCD boundaries" {
    // 00:59:74 -> 01:00:00
    var img = makeForm1Image(17);
    const lba: u32 = 59 * 75 + 74;
    _ = try fixImage(&img, lba);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x59, 0x74, 0x02 }, img[12..16]);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x02 }, img[sector_size + 12 ..][0..4]);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01, 0x02 }, img[2 * sector_size + 12 ..][0..4]);

    // 00:09:74 -> 00:10:00 and 00:00:09 -> 00:00:10
    var img2 = makeForm1Image(17);
    _ = try fixImage(&img2, 9 * 75 + 74);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x09, 0x74, 0x02 }, img2[12..16]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x10, 0x00, 0x02 }, img2[sector_size + 12 ..][0..4]);
    var img3 = makeForm1Image(17);
    _ = try fixImage(&img3, 9);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x09, 0x02 }, img3[12..16]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x10, 0x02 }, img3[sector_size + 12 ..][0..4]);

    // 09:59:74 -> 10:00:00
    var img4 = makeForm1Image(17);
    _ = try fixImage(&img4, (9 * 60 + 59) * 75 + 74);
    try testing.expectEqualSlices(u8, &.{ 0x09, 0x59, 0x74, 0x02 }, img4[12..16]);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x00, 0x00, 0x02 }, img4[sector_size + 12 ..][0..4]);

    // default start 00:02:00, sector 16 => 00:02:16
    var img5 = makeForm1Image(17);
    _ = try fixImage(&img5, psx_start_lba);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x00, 0x02 }, img5[12..16]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x16, 0x02 }, img5[16 * sector_size + 12 ..][0..4]);

    // beyond 99:59:74
    var img6 = makeForm1Image(17);
    try testing.expectError(error.LbaOutOfRange, fixImage(&img6, max_lba - 15));
    var img7 = makeForm1Image(17);
    _ = try fixImage(&img7, max_lba - 16);
    try testing.expectEqualSlices(u8, &.{ 0x99, 0x59, 0x74, 0x02 }, img7[16 * sector_size + 12 ..][0..4]);
}

test "errors: mode 1, unexpected mode, mode 0 payload, incomplete" {
    var img = makeForm1Image(20);
    img[18 * sector_size + 15] = 1;
    try testing.expectError(error.UnsupportedMode1, fixImage(&img, psx_start_lba));

    var img2 = makeForm1Image(20);
    img2[18 * sector_size + 15] = 3;
    var st = FixStats{};
    try testing.expectError(error.UnexpectedMode, fixImagePartial(&img2, psx_start_lba, false, &st));
    try testing.expectEqual(@as(u32, 18), st.total_sectors);
    try testing.expectEqual(@as(u32, 18), st.mode2_form1_sectors);

    var img3 = makeForm1Image(20);
    img3[17 * sector_size + 15] = 0; // mode 0 with random payload
    try testing.expectError(error.Mode0NotZero, fixImage(&img3, psx_start_lba));

    var short = makeForm1Image(15);
    try testing.expectError(error.ImageIncomplete, fixImage(&short, psx_start_lba));
    var odd: [sector_size * 16 + 1]u8 = @splat(0);
    try testing.expectError(error.ImageIncomplete, fixImage(&odd, psx_start_lba));
    try testing.expectError(error.ImageIncomplete, fixImage(odd[0..0], psx_start_lba));
}

test "mode 0 mid-stream is kept as empty mode 2; trailing zeros are padding" {
    var img = makeForm1Image(20);
    // sector 5: mode 0, zero payload, header garbage; later data remains
    @memset(img[5 * sector_size + 16 ..][0 .. sector_size - 16], 0);
    img[5 * sector_size + 15] = 0;
    // sectors 18, 19 all zero
    @memset(img[18 * sector_size ..], 0);
    const st = try fixImage(&img, psx_start_lba);
    try testing.expectEqual(@as(u32, 3), st.mode0_sectors);
    try testing.expectEqual(@as(u32, 20), st.total_sectors);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x05, 0x02 }, img[5 * sector_size + 12 ..][0..4]);
    try testing.expect(std.mem.allEqual(u8, img[5 * sector_size + 16 ..][0 .. sector_size - 16], 0));
    try testing.expect(std.mem.allEqual(u8, img[18 * sector_size ..], 0));
    // sector 17 is not padding: normal form 1
    try testing.expectEqual(@as(u8, 2), img[17 * sector_size + 15]);
}

test "non-zero data past the image keeps a trailing mode 0 sector as empty mode 2" {
    // PSXtract scans the whole block-aligned file for the zero-padding test.
    var img = makeForm1Image(20);
    @memset(img[19 * sector_size ..], 0);
    var plain = img;
    var st = FixStats{};
    try fixImagePartial(&plain, psx_start_lba, false, &st);
    try testing.expect(std.mem.allEqual(u8, plain[19 * sector_size ..], 0));

    var st2 = FixStats{};
    try fixImagePartial(&img, psx_start_lba, true, &st2);
    try testing.expectEqual(@as(u32, 20), st2.total_sectors);
    try testing.expectEqualSlices(u8, &sync_pattern, img[19 * sector_size ..][0..sync_size]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x19, 0x02 }, img[19 * sector_size + 12 ..][0..4]);
    try testing.expect(std.mem.allEqual(u8, img[19 * sector_size + 16 ..][0 .. sector_size - 16], 0));
}

test "dataTrackSectors and dataGap" {
    const t1 = BcdMsf{ .m = 0x00, .s = 0x02, .f = 0x00 };
    const t2 = BcdMsf{ .m = 0x05, .s = 0x12, .f = 0x30 };
    const frames_t2: u32 = (5 * 60 + 12) * 75 + 30; // absolute
    // (t2 - 150) - (t1 - 150) - 150
    try testing.expectEqual(frames_t2 - 2 * 75 - 150, try dataTrackSectors(t1, t2, false));
    // last track: lead-out used as stored, no 2 s subtraction
    const lo = BcdMsf{ .m = 0x10, .s = 0x00, .f = 0x00 };
    try testing.expectEqual(@as(u32, 10 * 60 * 75 - 0 - 150), try dataTrackSectors(t1, lo, true));
    // track 1 earlier than 2 s / negative sizes are rejected
    try testing.expectError(error.InvalidToc, dataTrackSectors(.{ .m = 0, .s = 1, .f = 0 }, t2, false));
    try testing.expectError(error.InvalidToc, dataTrackSectors(t1, .{ .m = 0, .s = 0x03, .f = 0 }, false));

    try testing.expectEqual(@as(u32, 150), try dataGap(1000, 1000));
    try testing.expectEqual(@as(u32, 160), try dataGap(1000, 990));
    try testing.expectError(error.InvalidToc, dataGap(10, 11));
}
