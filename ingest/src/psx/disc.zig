//! PS1 Classics `DATA.PSAR` -> raw CD images, in memory.
//!
//! Reproduces the PSXtract-2 revision 3 per-disc pipeline (`decrypt_single_disc`,
//! `decrypt_multi_disc`) without scratch files:
//!
//!   1. sector count of the data track from the ISO-header TOC (`data_track_sectors`),
//!   2. block table -> raw data track + TRASH/OVERDUMP (`build_data_track`),
//!   3. EDC/ECC reconstruction (`fix_iso`); a track that stops at a non-standard
//!      sector keeps the sectors written so far and widens the gap before audio,
//!   4. prebaked CUE selection by serial (`check_prebaked_cue_file`), used only for the
//!      single-disc pregap/length overrides (multi-disc runs pass none, as PSXtract),
//!   5. per CDDA entry: unscramble, ATRAC3 decode, pregap + PCM + zero padding
//!      (`build_audio_at3`, `convert_wav_to_bin`),
//!   6. one image per disc: fixed data track followed by every audio track.
//!
//! Deliberate differences from PSXtract: no prompts and no CUE-title naming (several
//! prebaked candidates are resolved by their `REM MD5` against the rebuilt data track,
//! otherwise `AmbiguousPsxCue`), and the block/PGD changes documented in `blocks.zig`
//! and `pgd.zig`. Auxiliary outputs follow PSXtract's "last disc wins" file semantics.
const std = @import("std");
const psar = @import("psar.zig");
const blocks = @import("blocks.zig");
const cdrom = @import("cdrom.zig");
const atrac3 = @import("atrac3.zig");
const cue = @import("cue.zig");

const sector_size: usize = cdrom.sector_size;
const toc_leadout: usize = 0x414;
const toc_track1: usize = 0x41E;
const toc_record: usize = 10;

pub const Image = struct {
    /// 1-based ISO map slot (1 for a single-disc container). Order of `Output.discs`.
    index: u8,
    /// Raw 2352-byte sectors: reconstructed data track, then every audio track.
    bytes: []u8,
    /// Decrypted ISO header payload (ISO_HEADER.BIN / ISO_HEADER_<index>.BIN).
    header: []u8,
};

/// Owns every buffer. A consumer may move a field out and reset it to `&.{}`/null.
pub const Output = struct {
    kind: psar.Kind,
    discs: []Image,
    /// Raw STARTDAT header + PNG (STARTDAT.BIN).
    startdat: ?[]u8,
    /// Decrypted ISO map (ISO_MAP.BIN, multi-disc only).
    iso_map: ?[]u8,
    /// Decrypted special data (SPECIAL_DATA.BIN).
    special_data: ?[]u8,
    /// TRASH.BIN: prefix of the last non-empty trash block of the last disc that had one.
    trash: []u8,
    /// OVERDUMP.BIN: the last disc's overdump remainders.
    overdump: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        for (self.discs) |disc| {
            allocator.free(disc.bytes);
            allocator.free(disc.header);
        }
        allocator.free(self.discs);
        if (self.startdat) |bytes| allocator.free(bytes);
        if (self.iso_map) |bytes| allocator.free(bytes);
        if (self.special_data) |bytes| allocator.free(bytes);
        allocator.free(self.trash);
        allocator.free(self.overdump);
        self.* = undefined;
    }
};

const Built = struct {
    image: []u8,
    trash: []u8,
    overdump: []u8,

    fn deinit(self: *Built, allocator: std.mem.Allocator) void {
        allocator.free(self.image);
        allocator.free(self.trash);
        allocator.free(self.overdump);
    }
};

pub fn convert(allocator: std.mem.Allocator, data_psar: []const u8) !Output {
    var container = try psar.parse(allocator, data_psar);
    defer container.deinit(allocator);

    var images: std.ArrayList(Image) = .empty;
    errdefer {
        for (images.items) |disc| {
            allocator.free(disc.bytes);
            allocator.free(disc.header);
        }
        images.deinit(allocator);
    }
    var trash: []u8 = &.{};
    errdefer allocator.free(trash);
    var overdump: []u8 = &.{};
    errdefer allocator.free(overdump);

    for (container.discs) |disc| {
        var built = try convertDisc(allocator, data_psar, disc, container.kind == .single);
        errdefer built.deinit(allocator);
        const header = try allocator.dupe(u8, disc.header);
        errdefer allocator.free(header);
        try images.append(allocator, .{ .index = disc.index, .bytes = built.image, .header = header });
        // PSXtract reopens TRASH.BIN only for a non-empty prefix (an earlier disc's file
        // survives) and OVERDUMP.BIN with "wb" for every disc (the last disc wins).
        if (built.trash.len != 0) {
            allocator.free(trash);
            trash = built.trash;
        } else allocator.free(built.trash);
        allocator.free(overdump);
        overdump = built.overdump;
    }

    const startdat: ?[]u8 = if (container.startdat) |bytes| try allocator.dupe(u8, bytes) else null;
    errdefer if (startdat) |bytes| allocator.free(bytes);
    const discs = try images.toOwnedSlice(allocator);

    const iso_map = container.iso_map;
    container.iso_map = null;
    const special_data = container.special_data;
    container.special_data = null;
    return .{
        .kind = container.kind,
        .discs = discs,
        .startdat = startdat,
        .iso_map = iso_map,
        .special_data = special_data,
        .trash = trash,
        .overdump = overdump,
    };
}

fn bcdMsf(header: []const u8, record: usize) cdrom.BcdMsf {
    return .{ .m = header[record + 7], .s = header[record + 8], .f = header[record + 9] };
}

/// `data_track_sectors`: (next track start - track 1 start) - 150, where the next
/// track is TOC record 2 when it exists and the lead-out otherwise.
fn dataSectors(disc: psar.Disc) !u32 {
    const has_next = disc.toc.tracks.len >= 2;
    return cdrom.dataTrackSectors(
        bcdMsf(disc.header, toc_track1),
        bcdMsf(disc.header, if (has_next) toc_track1 + toc_record else toc_leadout),
        !has_next,
    );
}

/// `get_track_size_from_cue` for the audio track stored at TOC index `index`.
fn audioTocFrames(disc: psar.Disc, index: usize) !i64 {
    const tracks = disc.toc.tracks;
    if (index >= tracks.len) return error.InvalidToc;
    const next: ?i64 = if (index + 1 < tracks.len) tracks[index + 1].start_lba else null;
    const frames = cue.tocTrackFrames(tracks[index].start_lba, next, disc.toc.leadout_lba);
    if (frames < 0) return error.InvalidToc;
    return frames;
}

/// One candidate is taken as is; several are resolved by the data-track MD5 recorded in
/// the CUE (plan change 1); none or an unresolved set of several is an error.
fn selectCandidate(candidates: []const cue.Candidate, data_track: []const u8) error{AmbiguousPsxCue}!?cue.Candidate {
    if (candidates.len == 0) return null;
    if (candidates.len == 1) return candidates[0];
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(data_track, &md5, .{});
    var match: ?cue.Candidate = null;
    for (candidates) |candidate| {
        if (!cue.md5Matches(candidate, &md5)) continue;
        if (match != null) return error.AmbiguousPsxCue;
        match = candidate;
    }
    return match orelse error.AmbiguousPsxCue;
}

fn convertDisc(allocator: std.mem.Allocator, data_psar: []const u8, disc: psar.Disc, single: bool) !Built {
    const sectors = try dataSectors(disc);
    var track = try blocks.buildDataTrack(allocator, data_psar, disc, sectors);
    errdefer track.deinit(allocator);

    // `make_cdrom` stops at an unexpected sector mode ("non-standard pregap before
    // audio") keeping the output so far; every other failure aborts.
    var stats: cdrom.FixStats = .{};
    cdrom.fixImagePartial(track.iso, cdrom.psx_start_lba, track.tail_nonzero, &stats) catch |err| switch (err) {
        error.UnexpectedMode => {},
        else => return err,
    };
    const fixed_len = @as(usize, stats.total_sectors) * sector_size;
    const data_gap = try cdrom.dataGap(sectors, stats.total_sectors);

    var found: [cue.max_candidates]cue.Candidate = undefined;
    const candidate = try selectCandidate(cue.lookup(disc.serial, &found), track.iso[0..fixed_len]);
    // Overrides exist only for single-disc runs with a prebaked CUE (multi-disc: NULL).
    const override_storage: ?cue.Overrides = if (single and candidate != null) cue.overrides(candidate.?) else null;
    const overrides: ?*const cue.Overrides = if (override_storage) |*value| value else null;

    // Layout pass: AT3 sector count from the TOC and override, then pregap/PCM/total bytes.
    var layouts: [cue.max_tracks]cue.BinLayout = undefined;
    if (disc.cdda.len > layouts.len) return error.InvalidCddaTable;
    var total = fixed_len;
    for (disc.cdda, 0..) |_, i| {
        const track_number: u32 = @intCast(i + 2);
        const frames = try audioTocFrames(disc, i + 1);
        const track_sectors = try cue.at3TrackSectors(frames, overrides, track_number);
        layouts[i] = try cue.binLayout(overrides, track_number, data_gap, @as(i64, track_sectors) * @as(i64, @intCast(sector_size)));
        total = try std.math.add(usize, total, layouts[i].total_bytes);
    }

    track.iso = try allocator.realloc(track.iso, total);
    @memset(track.iso[fixed_len..], 0);
    var offset = fixed_len;
    for (disc.cdda, layouts[0..disc.cdda.len]) |entry, layout| {
        const source = try psar.cddaSource(data_psar, disc, entry);
        const payload = try allocator.dupe(u8, source[0..entry.size]);
        defer allocator.free(payload);
        atrac3.unscramble(payload, entry.checksum);
        const pcm = try atrac3.decodeTrack(allocator, payload, layout.data_bytes / @as(u32, @intCast(sector_size)));
        defer allocator.free(pcm);
        std.debug.assert(pcm.len == layout.data_bytes);
        @memcpy(track.iso[offset + layout.pregap_bytes ..][0..pcm.len], pcm);
        offset += layout.total_bytes;
    }
    return .{ .image = track.iso, .trash = track.trash, .overdump = track.overdump };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const pgd = @import("pgd.zig");

const block_bytes = psar.iso_block_size;
const fragment = @embedFile("atrac3/fragment.at3");

fn frameMsf(frames: u32) [3]u8 {
    const bcd = struct {
        fn of(value: u32) u8 {
            return @intCast(((value / 10) << 4) | (value % 10));
        }
    }.of;
    return .{ bcd(frames / 4500), bcd(frames / 75 % 60), bcd(frames % 75) };
}

const TocSpec = struct { offset: usize, kind: u8, number: u8, abs_frames: u32 };

const HeaderSpec = struct {
    serial: []const u8,
    toc: []const TocSpec,
    /// {offset, size, marker} relative to the disc's block base.
    blocks: []const [3]u32,
    /// {offset, size, checksum}.
    cdda: []const [3]u32 = &.{},
};

fn isoHeader(allocator: std.mem.Allocator, spec: HeaderSpec) ![]u8 {
    const header = try allocator.alloc(u8, 0x3C00 + (spec.blocks.len + 1) * 32);
    @memset(header, 0);
    @memcpy(header[1..][0..spec.serial.len], spec.serial);
    @memcpy(header[0xE2C..][0..5], "TITLE");
    for (spec.toc) |record| {
        header[record.offset] = record.kind;
        header[record.offset + 2] = record.number;
        @memcpy(header[record.offset + 7 ..][0..3], &frameMsf(record.abs_frames));
    }
    for (spec.cdda, 0..) |entry, i| {
        const at = 0x800 + i * 16;
        std.mem.writeInt(u32, header[at..][0..4], entry[0], .little);
        std.mem.writeInt(u32, header[at + 4 ..][0..4], entry[1], .little);
        std.mem.writeInt(u32, header[at + 12 ..][0..4], entry[2], .little);
    }
    for (spec.blocks, 0..) |entry, i| {
        const at = 0x3C00 + i * 32;
        std.mem.writeInt(u32, header[at..][0..4], entry[0], .little);
        std.mem.writeInt(u16, header[at + 4 ..][0..2], @intCast(entry[1]), .little);
        std.mem.writeInt(u16, header[at + 6 ..][0..2], @intCast(entry[2]), .little);
    }
    return header;
}

fn putHeader(allocator: std.mem.Allocator, data: []u8, at: usize, spec: HeaderSpec) !void {
    const payload = try isoHeader(allocator, spec);
    defer allocator.free(payload);
    const encrypted = try pgd.testing_support.build(allocator, payload, .{ .total_len = psar.iso_header_size });
    defer allocator.free(encrypted);
    @memcpy(data[at..][0..psar.iso_header_size], encrypted[0..psar.iso_header_size]);
}

/// One raw 16-sector data block: Mode 2 form 1 sectors tagged `tag`; sector 16 of the
/// image carries the ISO9660 descriptor. `mode_fault` names a sector with mode byte 5.
fn dataBlock(block: *[block_bytes]u8, first_sector: usize, tag: u8, mode_fault: ?usize) void {
    @memset(block, tag);
    for (0..16) |i| {
        const sector = block[i * sector_size ..][0..sector_size];
        const global = first_sector + i;
        @memset(sector[16..24], 0);
        sector[15] = if (mode_fault == global) 5 else 2;
        if (global == 16) @memcpy(sector[24..31], "\x01CD001\x01");
    }
}

fn putDataTrack(data: []u8, base: usize, sectors: usize, tag: u8, mode_fault: ?usize) void {
    var block: [block_bytes]u8 = undefined;
    for (0..sectors / 16) |i| {
        dataBlock(&block, i * 16, tag, mode_fault);
        @memcpy(data[base + i * block_bytes ..][0..block_bytes], &block);
    }
}

fn putAux(data: []u8, at: usize) void {
    @memset(data[at..][0..block_bytes], 0);
    @memcpy(data[at..][0..4], "TRSH");
}

const data_blocks = [_][3]u32{ .{ 0, block_bytes, 1 }, .{ block_bytes, block_bytes, 1 } };
const aux_blocks = data_blocks ++ [_][3]u32{.{ 2 * block_bytes, block_bytes, 0 }};
const data_toc = [_]TocSpec{
    .{ .offset = toc_leadout, .kind = 0x41, .number = 0xA2, .abs_frames = 150 + 32 },
    .{ .offset = toc_track1, .kind = 0x41, .number = 1, .abs_frames = 150 },
};

fn singleDisc(allocator: std.mem.Allocator, spec: HeaderSpec, extra: usize) ![]u8 {
    const data = try allocator.alloc(u8, psar.iso_base_offset + 0x40000 + extra);
    @memset(data, 0);
    @memcpy(data[0..12], "PSISOIMG0000");
    try putHeader(allocator, data, psar.iso_header_offset, spec);
    return data;
}

test "single data-only disc is rebuilt with auxiliaries" {
    const allocator = testing.allocator;
    const data = try singleDisc(allocator, .{ .serial = "TEST_00000", .toc = &data_toc, .blocks = &aux_blocks }, 0);
    defer allocator.free(data);
    putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
    putAux(data, psar.iso_base_offset + 2 * block_bytes);

    var output = try convert(allocator, data);
    defer output.deinit(allocator);
    try testing.expectEqual(psar.Kind.single, output.kind);
    try testing.expectEqual(@as(usize, 1), output.discs.len);
    try testing.expectEqual(@as(u8, 1), output.discs[0].index);
    const image = output.discs[0].bytes;
    try testing.expectEqual(32 * sector_size, image.len);
    // Sync + MSF 00:02:00 / 00:02:01 regenerated, ISO descriptor preserved.
    try testing.expectEqualSlices(u8, &.{ 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0x00, 0x02, 0x00, 0x02 }, image[0..16]);
    try testing.expectEqual(@as(u8, 0x01), image[sector_size + 14]);
    try testing.expectEqualSlices(u8, "\x01CD001\x01", image[16 * sector_size + 24 ..][0..7]);
    try testing.expectEqualStrings("TEST_00000", std.mem.sliceTo(output.discs[0].header[1..16], 0));
    try testing.expectEqualStrings("TRSH", output.trash);
    try testing.expectEqual(block_bytes - 4, output.overdump.len);
    try testing.expect(output.startdat == null and output.iso_map == null and output.special_data == null);
}

fn audioToc(track_two: u32, leadout: u32) [3]TocSpec {
    return .{
        .{ .offset = toc_leadout, .kind = 0x41, .number = 0xA2, .abs_frames = leadout },
        .{ .offset = toc_track1, .kind = 0x41, .number = 1, .abs_frames = 150 },
        .{ .offset = toc_track1 + toc_record, .kind = 0x01, .number = 2, .abs_frames = track_two },
    };
}

/// Scrambled form of `plain` for `atrac3.unscramble` with `checksum` (inverse chain).
fn scramble(plain: []u8, checksum: u32) void {
    var tmp2 = checksum;
    var chunk: usize = 0;
    while ((chunk + 1) * atrac3.frame_bytes <= plain.len) : (chunk += 1) {
        var tmp = tmp2;
        for (0..atrac3.frame_bytes / 4) |k| {
            const at = chunk * atrac3.frame_bytes + k * 4;
            const scrambled = std.mem.readInt(u32, plain[at..][0..4], .little) ^ tmp;
            std.mem.writeInt(u32, plain[at..][0..4], scrambled, .little);
            tmp = tmp2 +% scrambled *% 123456789;
        }
        tmp2 = std.math.rotr(u32, tmp2, 1);
    }
}

test "audio track follows the data track: pregap, PCM from WAV offset 44, padding" {
    const allocator = testing.allocator;
    const cdda_offset = 0x40000;
    const checksum = 0x1234_5678;
    // Track 2 starts at 00:04:32 (data track = 32 sectors); 250 frames to the lead-out.
    const toc = audioToc(150 + 32 + 150, 150 + 32 + 250);
    const data = try singleDisc(allocator, .{
        .serial = "TEST_00001",
        .toc = &toc,
        .blocks = &data_blocks,
        .cdda = &.{.{ cdda_offset, fragment.len, checksum }},
    }, fragment.len + atrac3.frame_bytes);
    defer allocator.free(data);
    putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
    const scrambled = data[psar.iso_base_offset + cdda_offset ..][0..fragment.len];
    @memcpy(scrambled, fragment);
    scramble(scrambled, checksum);

    var output = try convert(allocator, data);
    defer output.deinit(allocator);
    const image = output.discs[0].bytes;
    // Data gap is 150, so the pregap is 149 sectors and 101 sectors of PCM follow.
    try testing.expectEqual((32 + 250) * sector_size, image.len);
    const audio = image[32 * sector_size ..];
    try testing.expect(std.mem.allEqual(u8, audio[0 .. 149 * sector_size], 0));
    const pcm = try atrac3.decodeTrack(allocator, fragment, 101);
    defer allocator.free(pcm);
    try testing.expectEqualSlices(u8, pcm, audio[149 * sector_size ..]);
}

test "TOC audio record without CDDA entries yields only the data track" {
    const allocator = testing.allocator;
    const toc = audioToc(150 + 32 + 150, 150 + 32 + 250);
    const data = try singleDisc(allocator, .{ .serial = "TEST_00002", .toc = &toc, .blocks = &data_blocks }, 0);
    defer allocator.free(data);
    putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
    var output = try convert(allocator, data);
    defer output.deinit(allocator);
    try testing.expectEqual(32 * sector_size, output.discs[0].bytes.len);
}

test "CDDA entry without a TOC record or outside the PSAR is rejected" {
    const allocator = testing.allocator;
    {
        const data = try singleDisc(allocator, .{
            .serial = "TEST_00003",
            .toc = &data_toc,
            .blocks = &data_blocks,
            .cdda = &.{.{ 0x40000, fragment.len, 1 }},
        }, fragment.len + atrac3.frame_bytes);
        defer allocator.free(data);
        putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
        try testing.expectError(error.InvalidToc, convert(allocator, data));
    }
    {
        const toc = audioToc(150 + 32 + 150, 150 + 32 + 250);
        const data = try singleDisc(allocator, .{
            .serial = "TEST_00004",
            .toc = &toc,
            .blocks = &data_blocks,
            .cdda = &.{.{ 0x40000, 0x100000, 1 }},
        }, 0);
        defer allocator.free(data);
        putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
        try testing.expectError(error.AudioOutOfRange, convert(allocator, data));
    }
}

test "an unexpected sector mode keeps the sectors so far" {
    const allocator = testing.allocator;
    const data = try singleDisc(allocator, .{ .serial = "TEST_00005", .toc = &data_toc, .blocks = &data_blocks }, 0);
    defer allocator.free(data);
    putDataTrack(data, psar.iso_base_offset, 32, 0x77, 20);
    var output = try convert(allocator, data);
    defer output.deinit(allocator);
    try testing.expectEqual(20 * sector_size, output.discs[0].bytes.len);
}

test "serial with one prebaked CUE converts; several unresolved candidates fail" {
    const allocator = testing.allocator;
    {
        const data = try singleDisc(allocator, .{ .serial = "ESPM_70001", .toc = &data_toc, .blocks = &data_blocks }, 0);
        defer allocator.free(data);
        putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
        var output = try convert(allocator, data);
        defer output.deinit(allocator);
        try testing.expectEqual(32 * sector_size, output.discs[0].bytes.len);
    }
    {
        // Jet Moto 2 has -1 and -2 variants; synthetic data matches neither MD5.
        const data = try singleDisc(allocator, .{ .serial = "SCUS_94167", .toc = &data_toc, .blocks = &data_blocks }, 0);
        defer allocator.free(data);
        putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
        try testing.expectError(error.AmbiguousPsxCue, convert(allocator, data));
    }
}

fn syntheticCandidate(key: []const u8, md5: [16]u8) cue.Candidate {
    return .{ .key = key, .title = key, .data_md5 = md5, .leadout_frames = 0, .track_count = 0, .track_bytes = &.{} };
}

test "candidate selection: none, one, md5-resolved, ambiguous" {
    const image = "rebuilt data track";
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(image, &md5, .{});
    const other: [16]u8 = @splat(1);
    const a = syntheticCandidate("A-1", other);
    const b = syntheticCandidate("A-2", md5);
    const c = syntheticCandidate("A-3", other);
    try testing.expect((try selectCandidate(&.{}, image)) == null);
    try testing.expectEqualStrings("A-1", (try selectCandidate(&.{a}, image)).?.key);
    try testing.expectEqualStrings("A-2", (try selectCandidate(&.{ a, b, c }, image)).?.key);
    try testing.expectError(error.AmbiguousPsxCue, selectCandidate(&.{ a, c }, image));
    try testing.expectError(error.AmbiguousPsxCue, selectCandidate(&.{ b, syntheticCandidate("A-4", md5) }, image));
}

const disc1_at = 0x10000;
const disc3_at = 0x200000;

test "multi disc: disc order, auxiliaries, last disc wins" {
    const allocator = testing.allocator;
    const special_at = disc3_at + psar.iso_base_offset + 0x40000;
    const startdat_at = special_at - 0x100;
    const data = try allocator.alloc(u8, special_at + 0x400);
    defer allocator.free(data);
    @memset(data, 0);
    @memcpy(data[0..16], "PSTITLEIMG000000");
    std.mem.writeInt(u32, data[0x10..][0..4], startdat_at, .little);

    var map: [0x200]u8 = @splat(0);
    std.mem.writeInt(u32, map[0..][0..4], disc1_at, .little);
    std.mem.writeInt(u32, map[8..][0..4], disc3_at, .little);
    std.mem.writeInt(u32, map[0x84..][0..4], special_at, .little);
    const map_pgd = try pgd.testing_support.build(allocator, &map, .{ .block_size = 0x200 });
    defer allocator.free(map_pgd);
    @memcpy(data[psar.iso_map_offset..][0..map_pgd.len], map_pgd);

    // Disc 1 carries an aux block; disc 3 (slot 3, slot 2 empty) does not.
    try putHeader(allocator, data, disc1_at + psar.iso_header_offset, .{ .serial = "TEST_10001", .toc = &data_toc, .blocks = &aux_blocks });
    try putHeader(allocator, data, disc3_at + psar.iso_header_offset, .{ .serial = "TEST_10003", .toc = &data_toc, .blocks = &data_blocks });
    putDataTrack(data, disc1_at + psar.iso_base_offset, 32, 0x11, null);
    putAux(data, disc1_at + psar.iso_base_offset + 2 * block_bytes);
    putDataTrack(data, disc3_at + psar.iso_base_offset, 32, 0x33, null);

    @memcpy(data[startdat_at..][0..8], "STARTDAT");
    std.mem.writeInt(u32, data[startdat_at + 0x10 ..][0..4], 24, .little);
    std.mem.writeInt(u32, data[startdat_at + 0x14 ..][0..4], 2, .little);
    const special_payload: [0x30]u8 = @splat(0x55);
    const special = try pgd.testing_support.build(allocator, &special_payload, .{});
    defer allocator.free(special);
    @memcpy(data[special_at..][0..special.len], special);

    var output = try convert(allocator, data[0 .. special_at + special.len]);
    defer output.deinit(allocator);
    try testing.expectEqual(psar.Kind.multi, output.kind);
    try testing.expectEqual(@as(usize, 2), output.discs.len);
    try testing.expectEqual(@as(u8, 1), output.discs[0].index);
    try testing.expectEqual(@as(u8, 3), output.discs[1].index);
    try testing.expectEqual(@as(u8, 0x11), output.discs[0].bytes[20 * sector_size + 100]);
    try testing.expectEqual(@as(u8, 0x33), output.discs[1].bytes[20 * sector_size + 100]);
    try testing.expectEqualStrings("TEST_10003", std.mem.sliceTo(output.discs[1].header[1..16], 0));
    // TRASH survives from disc 1; OVERDUMP is disc 3's (empty).
    try testing.expectEqualStrings("TRSH", output.trash);
    try testing.expectEqual(@as(usize, 0), output.overdump.len);
    try testing.expectEqual(@as(usize, 26), output.startdat.?.len);
    try testing.expectEqual(@as(usize, 0x200), output.iso_map.?.len);
    try testing.expectEqual(@as(usize, 0x30), output.special_data.?.len);
}

test "allocation failures never leak" {
    const allocator = testing.allocator;
    const data = try singleDisc(allocator, .{ .serial = "TEST_00006", .toc = &data_toc, .blocks = &aux_blocks }, 0);
    defer allocator.free(data);
    putDataTrack(data, psar.iso_base_offset, 32, 0x77, null);
    putAux(data, psar.iso_base_offset + 2 * block_bytes);
    try testing.checkAllAllocationFailures(allocator, struct {
        fn run(alloc: std.mem.Allocator, bytes: []const u8) !void {
            var output = try convert(alloc, bytes);
            output.deinit(alloc);
        }
    }.run, .{@as([]const u8, data)});
}
