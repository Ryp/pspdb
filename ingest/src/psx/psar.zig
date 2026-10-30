//! PS1 Classic DATA.PSAR container (PSISOIMG0000 single disc / PSTITLEIMG000000
//! multi disc): STARTDAT, ISO_MAP, ISO header(s), special and unknown data.
//! Ports PSXtract-2 `extract_startdat`, `decrypt_{single,multi}_disc`,
//! `decrypt_iso_header/map`, `decrypt_special/unknown_data` with every offset and
//! length bounds-checked against the input. All PGDs are authenticated through
//! `pgd.decrypt` (header, table and every block MAC) before use.
const std = @import("std");
const pgd = @import("pgd.zig");

pub const iso_header_offset = 0x400; // single disc; multi: disc offset + this
pub const iso_header_size = 0xB6600;
pub const iso_base_offset = 0x100000; // first data block: disc offset + this
pub const iso_map_offset = 0x200;
pub const iso_map_size = 0x2A0;
pub const iso_block_size = 16 * 2352; // 37632: size < this => compressed
pub const max_discs = 5;
/// PSXtract reads `size + 0x180` bytes per CDDA entry (unscrambling spill).
pub const cdda_trailer = 0x180;
/// Special/unknown PGDs are PNG/memory-snapshot sized; cap what we decrypt.
pub const max_aux_pgd = 64 << 20;

const toc_offset = 0x400; // A0, A1, A2 (lead-out) then tracks, 10-byte records
const toc_leadout = 0x414;
const toc_track1 = 0x41E;
const toc_record = 10;
const cdda_table = 0x800;
const cdda_record = 16;
const block_table = 0x3C00;
const block_record = 32;
const max_tracks = (cdda_table - toc_track1) / toc_record; // 99 TOC records fit before the CDDA table
const max_cdda = 98; // audio tracks: 99 tracks minus the data track
const startdat_header_size = 24;

pub const Error = pgd.Error || error{
    /// Not PSISOIMG0000 / PSTITLEIMG000000, or shorter than its fixed header.
    InvalidPsar,
    /// STARTDAT offset/header/size outside the PSAR.
    InvalidStartdat,
    /// ISO header PGD window (0xB6600) or ISO_MAP window (0x2A0) exceeds the PSAR.
    TruncatedPsar,
    /// Decrypted ISO map/header too short for the fixed fields PSXtract reads.
    InvalidIsoMap,
    InvalidIsoHeader,
    /// Lead-out or track 1 TOC record missing/invalid.
    InvalidToc,
    InvalidCddaTable,
    /// Block entry larger than one 16-sector block, or empty table.
    InvalidBlockTable,
    /// Block data lies outside the PSAR.
    BlockOutOfRange,
    /// Multi-disc map without any disc offset.
    NoDiscs,
    InvalidSpecialData,
    InvalidUnknownData,
    AudioOutOfRange,
};

pub const Kind = enum { single, multi };

pub const BlockEntry = struct {
    /// Relative to `Disc.blocks_base`.
    offset: u32,
    /// Stored byte count; `< iso_block_size` means compressed, otherwise raw.
    size: u16,
    /// 0 = block feeds TRASH/OVERDUMP accounting (PSXtract `marker == 0`).
    marker: u16,
};

pub const CddaEntry = struct {
    /// Relative to `Disc.blocks_base`. Not range-checked by `parse` (see `cddaSource`).
    offset: u32,
    size: u32,
    /// Seed for `atrac3.unscramble`.
    checksum: u32,
};

pub const TocTrack = struct {
    /// Track number, BCD-decoded.
    number: u8,
    /// Control/type byte without the 0x40 data bit (0x01/0x21 audio, 0x41/0x61 data).
    is_audio: bool,
    /// INDEX 01 (P-time) MSF of the raw TOC record converted to frames with
    /// PSXtract's arithmetic: `(mm*60 + ss)*75 + ff`, no lead-in subtraction.
    /// Track 1 is normally 150 (00:02:00).
    start_lba: u32,
};

pub const Toc = struct {
    /// A0/A1 pseudo-tracks (BCD-decoded PMIN).
    first_track: u8,
    last_track: u8,
    /// Lead-out (A2) position in the same MSF-frame unit as `TocTrack.start_lba`.
    /// PSXtract data-track sectors = `leadout_lba - 150` (track 1 at 150);
    /// last audio track = `leadout_lba - start_lba + 150`.
    leadout_lba: u32,
    tracks: []TocTrack,
};

pub const Disc = struct {
    /// 1-based slot (multi: position in the ISO map, so 1..5; single: 1).
    index: u8,
    /// Decrypted ISO header payload (what PSXtract writes as ISO_HEADER*.BIN).
    header: []u8,
    /// `header[1..16]` up to the first NUL. Borrows `header`.
    serial: []const u8,
    /// `header[0xE2C..+0x80]` up to the first NUL (UTF-8). Borrows `header`.
    title: []const u8,
    toc: Toc,
    blocks: []BlockEntry,
    /// Absolute offset in DATA.PSAR of block offset 0 and of CDDA offset 0.
    blocks_base: usize,
    cdda: []CddaEntry,

    pub fn deinit(self: *Disc, allocator: std.mem.Allocator) void {
        allocator.free(self.header);
        allocator.free(self.toc.tracks);
        allocator.free(self.blocks);
        allocator.free(self.cdda);
        self.* = undefined;
    }
};

pub const Psar = struct {
    kind: Kind,
    /// Raw STARTDAT header + PNG (PSXtract STARTDAT.BIN); borrows the input.
    startdat: ?[]const u8,
    /// Decrypted ISO_MAP payload (multi only).
    iso_map: ?[]u8,
    /// Decrypted special-data payload (SPECIAL_DATA.BIN).
    special_data: ?[]u8,
    /// Decrypted unknown-data payload (UNKNOWN_DATA.BIN; single only).
    unknown_data: ?[]u8,
    /// Ordered by slot (disc index).
    discs: []Disc,

    pub fn deinit(self: *Psar, allocator: std.mem.Allocator) void {
        for (self.discs) |*disc| disc.deinit(allocator);
        allocator.free(self.discs);
        if (self.iso_map) |bytes| allocator.free(bytes);
        if (self.special_data) |bytes| allocator.free(bytes);
        if (self.unknown_data) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
};

fn le32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn le16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn cstring(bytes: []const u8) []const u8 {
    return bytes[0 .. std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len];
}

/// Parse and authenticate a DATA.PSAR. `data` must outlive the result
/// (`startdat` borrows it).
pub fn parse(allocator: std.mem.Allocator, data: []const u8) Error!Psar {
    if (data.len < 0x10) return error.InvalidPsar;
    const kind: Kind = if (std.mem.eql(u8, data[0..12], "PSISOIMG0000"))
        .single
    else if (std.mem.eql(u8, data[0..16], "PSTITLEIMG000000"))
        .multi
    else
        return error.InvalidPsar;

    const startdat_offset: u32 = le32(data, if (kind == .multi) 0x10 else 0xC);
    var result: Psar = .{
        .kind = kind,
        .startdat = try startdatSlice(data, startdat_offset),
        .iso_map = null,
        .special_data = null,
        .unknown_data = null,
        .discs = &.{},
    };
    errdefer result.deinit(allocator);

    var discs: std.ArrayList(Disc) = .empty;
    errdefer {
        for (discs.items) |*disc| disc.deinit(allocator);
        discs.deinit(allocator);
    }

    var special_offset: u32 = 0;
    switch (kind) {
        .single => {
            try discs.ensureUnusedCapacity(allocator, 1);
            discs.appendAssumeCapacity(try parseDisc(allocator, data, 1, 0));
            const header = discs.items[0].header;
            special_offset = le32(header, 0xE20);
            const unknown_offset = le32(header, 0xED4);
            if (startdat_offset > 0 and unknown_offset != 0) {
                if (unknown_offset > startdat_offset or startdat_offset - unknown_offset < 0x90)
                    return error.InvalidUnknownData;
                result.unknown_data = try decryptAux(allocator, data[unknown_offset..startdat_offset], error.InvalidUnknownData, 1);
            }
        },
        .multi => {
            if (data.len < iso_map_offset + iso_map_size) return error.TruncatedPsar;
            const map = try pgd.decrypt(allocator, data[iso_map_offset..][0..iso_map_size]);
            result.iso_map = map.bytes;
            if (map.bytes.len < 0x88) return error.InvalidIsoMap;
            special_offset = le32(map.bytes, 0x84);
            for (0..max_discs) |slot| {
                const disc_offset = le32(map.bytes, slot * 4);
                if (disc_offset == 0) continue;
                try discs.ensureUnusedCapacity(allocator, 1);
                discs.appendAssumeCapacity(try parseDisc(allocator, data, @intCast(slot + 1), disc_offset));
            }
            if (discs.items.len == 0) return error.NoDiscs;
        },
    }
    if (special_offset != 0) {
        if (special_offset > data.len or data.len - special_offset < 0x90) return error.InvalidSpecialData;
        result.special_data = try decryptAux(allocator, data[special_offset..], error.InvalidSpecialData, 0x1C);
    }

    result.discs = try discs.toOwnedSlice(allocator);
    return result;
}

/// STARTDAT header (24 bytes: magic[8], u32 x2, header_size, data_size) and the
/// raw span header_size + data_size, exactly as PSXtract writes STARTDAT.BIN.
fn startdatSlice(data: []const u8, offset: u32) Error!?[]const u8 {
    if (offset == 0) return null;
    if (offset > data.len or data.len - offset < startdat_header_size) return error.InvalidStartdat;
    const header_size = le32(data, offset + 0x10);
    const data_size = le32(data, offset + 0x14);
    const total = @as(u64, header_size) + data_size;
    if (header_size < startdat_header_size or total > data.len - offset) return error.InvalidStartdat;
    return data[offset..][0..@intCast(total)];
}

fn decryptAux(allocator: std.mem.Allocator, bytes: []const u8, err: Error, min_payload: usize) Error![]u8 {
    if (bytes.len > max_aux_pgd) return err;
    const plain = try pgd.decrypt(allocator, bytes);
    if (plain.bytes.len < min_payload) {
        plain.deinit(allocator);
        return err;
    }
    return plain.bytes;
}

fn bcd(value: u8) u32 {
    return @as(u32, value >> 4) * 10 + (value & 15);
}

fn isTrackType(kind: u16) bool {
    return kind == 0x01 or kind == 0x21 or kind == 0x41 or kind == 0x61;
}

fn frames(header: []const u8, record: usize) u32 {
    return (bcd(header[record + 7]) * 60 + bcd(header[record + 8])) * 75 + bcd(header[record + 9]);
}

fn parseDisc(allocator: std.mem.Allocator, data: []const u8, index: u8, disc_offset: u32) Error!Disc {
    const header_at = @as(u64, disc_offset) + iso_header_offset;
    if (header_at > data.len or data.len - header_at < iso_header_size) return error.TruncatedPsar;
    const blocks_base_wide = @as(u64, disc_offset) + iso_base_offset;
    if (blocks_base_wide > data.len) return error.BlockOutOfRange;
    const blocks_base: usize = @intCast(blocks_base_wide);

    const plain = try pgd.decrypt(allocator, data[@intCast(header_at)..][0..iso_header_size]);
    const header = plain.bytes;
    errdefer allocator.free(header);
    if (header.len < block_table + block_record) return error.InvalidIsoHeader;

    // Table of contents.
    const leadout_kind = le16(header, toc_leadout);
    if (!isTrackType(leadout_kind)) return error.InvalidToc;
    var track_count: usize = 0;
    while (track_count < max_tracks and isTrackType(le16(header, toc_track1 + track_count * toc_record))) track_count += 1;
    if (track_count == 0) return error.InvalidToc;
    const tracks = try allocator.alloc(TocTrack, track_count);
    errdefer allocator.free(tracks);
    for (tracks, 0..) |*track, i| {
        const record = toc_track1 + i * toc_record;
        track.* = .{
            .number = @intCast(bcd(header[record + 2])),
            .is_audio = (header[record] & 0x40) == 0,
            .start_lba = frames(header, record),
        };
    }

    // CDDA table: 16-byte {offset, size, pad, checksum} until offset == 0.
    var cdda_count: usize = 0;
    while (le32(header, cdda_table + cdda_count * cdda_record) != 0) : (cdda_count += 1) {
        if (cdda_count == max_cdda) return error.InvalidCddaTable;
    }
    const cdda = try allocator.alloc(CddaEntry, cdda_count);
    errdefer allocator.free(cdda);
    for (cdda, 0..) |*entry, i| {
        const record = cdda_table + i * cdda_record;
        entry.* = .{ .offset = le32(header, record), .size = le32(header, record + 4), .checksum = le32(header, record + 12) };
    }

    // Block table: 32-byte {offset u32, size u16, marker u16, checksum[16], pad[8]} until size == 0.
    var block_count: usize = 0;
    while (block_table + (block_count + 1) * block_record <= header.len and
        le16(header, block_table + block_count * block_record + 4) != 0) block_count += 1;
    if (block_count == 0) return error.InvalidBlockTable;
    const blocks = try allocator.alloc(BlockEntry, block_count);
    errdefer allocator.free(blocks);
    for (blocks, 0..) |*block, i| {
        const record = block_table + i * block_record;
        block.* = .{ .offset = le32(header, record), .size = le16(header, record + 4), .marker = le16(header, record + 6) };
        if (block.size > iso_block_size) return error.InvalidBlockTable;
        if (@as(u64, block.offset) + block.size > data.len - blocks_base) return error.BlockOutOfRange;
    }

    return .{
        .index = index,
        .header = header,
        .serial = cstring(header[1..16]),
        .title = cstring(header[0xE2C..][0..0x80]),
        .toc = .{
            .first_track = @intCast(bcd(header[toc_offset + 7])),
            .last_track = @intCast(bcd(header[toc_offset + toc_record + 7])),
            .leadout_lba = frames(header, toc_leadout),
            .tracks = tracks,
        },
        .blocks = blocks,
        .blocks_base = blocks_base,
        .cdda = cdda,
    };
}

/// The `size + 0x180` source bytes PSXtract reads for a CDDA entry, bounds-checked
/// (a disc whose CDDA pointers are unused, e.g. Resident Evil 2, never calls this).
pub fn cddaSource(data: []const u8, disc: Disc, entry: CddaEntry) error{AudioOutOfRange}![]const u8 {
    const start = @as(u64, disc.blocks_base) + entry.offset;
    const end = start + @as(u64, entry.size) + cdda_trailer;
    if (end > data.len) return error.AudioOutOfRange;
    return data[@intCast(start)..@intCast(end)];
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const build_pgd = pgd.testing_support.build;

const TestDisc = struct {
    serial: []const u8 = "SLUS_000.01",
    title: []const u8 = "SYNTHETIC TITLE",
    special_offset: u32 = 0,
    unknown_offset: u32 = 0,
    /// {offset, size, marker} (relative to the disc's block base).
    blocks: []const [3]u32 = &.{ .{ 0, 100, 1 }, .{ 100, iso_block_size, 0 } },
    cdda: []const [3]u32 = &.{.{ 0x10000, 0x1000, 0xDEADBEEF }},
};

fn tocRecord(header: []u8, offset: usize, kind: u8, number: u8, index1: [3]u8) void {
    header[offset] = kind;
    header[offset + 2] = number;
    header[offset + 7] = index1[0];
    header[offset + 8] = index1[1];
    header[offset + 9] = index1[2];
}

fn isoHeaderPayload(allocator: std.mem.Allocator, spec: TestDisc) ![]u8 {
    const header = try allocator.alloc(u8, block_table + (spec.blocks.len + 1) * block_record);
    @memset(header, 0);
    @memcpy(header[1 .. 1 + spec.serial.len], spec.serial);
    @memcpy(header[0xE2C..][0..spec.title.len], spec.title);
    std.mem.writeInt(u32, header[0xE20..][0..4], spec.special_offset, .little);
    std.mem.writeInt(u32, header[0xED4..][0..4], spec.unknown_offset, .little);
    tocRecord(header, 0x400, 0x41, 0xA0, .{ 0x01, 0x20, 0x00 });
    tocRecord(header, 0x40A, 0x41, 0xA1, .{ 0x02, 0x00, 0x00 });
    tocRecord(header, 0x414, 0x41, 0xA2, .{ 0x03, 0x41, 0x17 });
    tocRecord(header, 0x41E, 0x41, 0x01, .{ 0x00, 0x02, 0x00 });
    tocRecord(header, 0x428, 0x01, 0x02, .{ 0x01, 0x42, 0x00 });
    for (spec.cdda, 0..) |entry, i| {
        const at = cdda_table + i * cdda_record;
        std.mem.writeInt(u32, header[at..][0..4], entry[0], .little);
        std.mem.writeInt(u32, header[at + 4 ..][0..4], entry[1], .little);
        std.mem.writeInt(u32, header[at + 12 ..][0..4], entry[2], .little);
    }
    for (spec.blocks, 0..) |entry, i| {
        const at = block_table + i * block_record;
        std.mem.writeInt(u32, header[at..][0..4], entry[0], .little);
        std.mem.writeInt(u16, header[at + 4 ..][0..2], @intCast(entry[1]), .little);
        std.mem.writeInt(u16, header[at + 6 ..][0..2], @intCast(entry[2]), .little);
    }
    return header;
}

fn put(psar: []u8, offset: usize, bytes: []const u8) void {
    @memcpy(psar[offset..][0..bytes.len], bytes);
}

fn putIsoHeader(allocator: std.mem.Allocator, psar: []u8, at: usize, spec: TestDisc) !void {
    const payload = try isoHeaderPayload(allocator, spec);
    defer allocator.free(payload);
    const pgd_bytes = try build_pgd(allocator, payload, .{ .total_len = iso_header_size });
    defer allocator.free(pgd_bytes);
    put(psar, at, pgd_bytes[0..iso_header_size]);
}

const unknown_at = 0x110000;
const startdat_at = 0x120000;
const special_at = 0x120100;

fn singleFixture(allocator: std.mem.Allocator) ![]u8 {
    const total = special_at + 0x200;
    const psar = try allocator.alloc(u8, total);
    @memset(psar, 0);
    put(psar, 0, "PSISOIMG0000");
    std.mem.writeInt(u32, psar[0xC..][0..4], startdat_at, .little);
    try putIsoHeader(allocator, psar, iso_header_offset, .{ .special_offset = special_at, .unknown_offset = unknown_at });

    const unknown = try build_pgd(allocator, "unknown memory snapshot", .{ .block_size = 16 });
    defer allocator.free(unknown);
    put(psar, unknown_at, unknown);

    put(psar, startdat_at, "STARTDAT");
    std.mem.writeInt(u32, psar[startdat_at + 8 ..][0..4], 1, .little);
    std.mem.writeInt(u32, psar[startdat_at + 12 ..][0..4], 1, .little);
    std.mem.writeInt(u32, psar[startdat_at + 0x10 ..][0..4], 80, .little);
    std.mem.writeInt(u32, psar[startdat_at + 0x14 ..][0..4], 4, .little);
    put(psar, startdat_at + 80, "\x89PNG");

    var special_payload: [0x1C + 8]u8 = undefined;
    @memset(special_payload[0..0x1C], 0xAA);
    @memcpy(special_payload[0x1C..], "PNGDATA!");
    const special = try build_pgd(allocator, &special_payload, .{});
    defer allocator.free(special);
    put(psar, special_at, special);
    // Special data runs to the end of the PSAR: shrink the buffer to its exact extent.
    return allocator.realloc(psar, special_at + special.len);
}

test "single disc container" {
    const allocator = testing.allocator;
    const data = try singleFixture(allocator);
    defer allocator.free(data);

    var psar = try parse(allocator, data);
    defer psar.deinit(allocator);
    try testing.expectEqual(Kind.single, psar.kind);
    try testing.expect(psar.iso_map == null);
    try testing.expectEqual(@as(usize, 84), psar.startdat.?.len);
    try testing.expectEqualStrings("STARTDAT", psar.startdat.?[0..8]);
    try testing.expectEqualStrings("unknown memory snapshot", psar.unknown_data.?);
    try testing.expectEqual(@as(usize, 0x1C + 8), psar.special_data.?.len);
    try testing.expectEqualStrings("PNGDATA!", psar.special_data.?[0x1C..]);

    try testing.expectEqual(@as(usize, 1), psar.discs.len);
    const disc = psar.discs[0];
    try testing.expectEqual(@as(u8, 1), disc.index);
    try testing.expectEqualStrings("SLUS_000.01", disc.serial);
    try testing.expectEqualStrings("SYNTHETIC TITLE", disc.title);
    try testing.expectEqual(@as(usize, iso_base_offset), disc.blocks_base);
    try testing.expectEqual(@as(u8, 1), disc.toc.first_track);
    try testing.expectEqual(@as(u8, 2), disc.toc.last_track);
    try testing.expectEqual(@as(u32, (3 * 60 + 41) * 75 + 17), disc.toc.leadout_lba);
    try testing.expectEqual(@as(usize, 2), disc.toc.tracks.len);
    try testing.expectEqual(TocTrack{ .number = 1, .is_audio = false, .start_lba = 150 }, disc.toc.tracks[0]);
    try testing.expectEqual(TocTrack{ .number = 2, .is_audio = true, .start_lba = (60 + 42) * 75 }, disc.toc.tracks[1]);
    try testing.expectEqual(@as(usize, 2), disc.blocks.len);
    try testing.expectEqual(BlockEntry{ .offset = 0, .size = 100, .marker = 1 }, disc.blocks[0]);
    try testing.expectEqual(BlockEntry{ .offset = 100, .size = iso_block_size, .marker = 0 }, disc.blocks[1]);
    try testing.expectEqual(@as(usize, 1), disc.cdda.len);
    try testing.expectEqual(CddaEntry{ .offset = 0x10000, .size = 0x1000, .checksum = 0xDEADBEEF }, disc.cdda[0]);
    // Data window for the CDDA entry: size + 0x180, inside the PSAR.
    try testing.expectEqual(@as(usize, 0x1000 + cdda_trailer), (try cddaSource(data, disc, disc.cdda[0])).len);
    try testing.expectError(error.AudioOutOfRange, cddaSource(data, disc, .{ .offset = 0x30000, .size = 0x1000, .checksum = 0 }));
}

test "single disc without STARTDAT skips unknown data" {
    const allocator = testing.allocator;
    const data = try singleFixture(allocator);
    defer allocator.free(data);
    const copy = try allocator.dupe(u8, data);
    defer allocator.free(copy);
    std.mem.writeInt(u32, copy[0xC..][0..4], 0, .little);
    var psar = try parse(allocator, copy);
    defer psar.deinit(allocator);
    try testing.expect(psar.startdat == null);
    try testing.expect(psar.unknown_data == null);
    try testing.expect(psar.special_data != null);
}

test "PSAR MAC failures at ISO header table and block, special and unknown data" {
    const allocator = testing.allocator;
    const data = try singleFixture(allocator);
    defer allocator.free(data);
    const header_payload = block_table + 3 * block_record;
    const header_aligned = (header_payload + 15) & ~@as(usize, 15);
    const damaged = [_]struct { offset: usize, err: anyerror }{
        .{ .offset = iso_header_offset + 0x20, .err = error.PgdHeaderMacMismatch },
        .{ .offset = iso_header_offset + 0x90 + header_aligned + 5, .err = error.PgdTableMacMismatch },
        .{ .offset = iso_header_offset + 0x90 + 0x1234, .err = error.PgdBlockMacMismatch },
        .{ .offset = unknown_at + 0x90 + 3, .err = error.PgdBlockMacMismatch },
        .{ .offset = special_at + 0x10, .err = error.PgdHeaderMacMismatch },
    };
    for (damaged) |case| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        copy[case.offset] ^= 1;
        try testing.expectError(case.err, parse(allocator, copy));
    }
}

test "PSAR bounds and structure rejections" {
    const allocator = testing.allocator;
    const data = try singleFixture(allocator);
    defer allocator.free(data);

    try testing.expectError(error.InvalidPsar, parse(allocator, data[0..8]));
    {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        copy[2] = 'X';
        try testing.expectError(error.InvalidPsar, parse(allocator, copy));
    }
    // ISO header window truncated.
    {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        std.mem.writeInt(u32, copy[0xC..][0..4], 0, .little);
        try testing.expectError(error.TruncatedPsar, parse(allocator, copy[0 .. iso_header_offset + iso_header_size - 1]));
    }
    // STARTDAT outside / undersized header / oversized payload.
    const startdat_cases = [_]struct { offset: u32, header_size: u32, data_size: u32 }{
        .{ .offset = 0xFFFFFFF0, .header_size = 80, .data_size = 4 },
        .{ .offset = startdat_at, .header_size = 23, .data_size = 4 },
        .{ .offset = startdat_at, .header_size = 80, .data_size = 0xFFFFFFFF },
        .{ .offset = startdat_at, .header_size = 0xFFFFFFFF, .data_size = 0xFFFFFFFF },
    };
    for (startdat_cases) |case| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        std.mem.writeInt(u32, copy[0xC..][0..4], case.offset, .little);
        std.mem.writeInt(u32, copy[startdat_at + 0x10 ..][0..4], case.header_size, .little);
        std.mem.writeInt(u32, copy[startdat_at + 0x14 ..][0..4], case.data_size, .little);
        try testing.expectError(error.InvalidStartdat, parse(allocator, copy));
    }
    // Unknown data must lie before STARTDAT and hold at least a PGD header.
    for ([_]u32{ startdat_at + 1, startdat_at - 0x80 }) |unknown_offset| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        try putIsoHeader(allocator, copy, iso_header_offset, .{ .special_offset = special_at, .unknown_offset = unknown_offset });
        try testing.expectError(error.InvalidUnknownData, parse(allocator, copy));
    }
    // Special data offset beyond the PSAR, or without room for a PGD header.
    for ([_]u32{ @intCast(data.len + 1), @intCast(data.len - 0x8F), 0xFFFFFFFF }) |special_offset| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        try putIsoHeader(allocator, copy, iso_header_offset, .{ .special_offset = special_offset, .unknown_offset = unknown_at });
        try testing.expectError(error.InvalidSpecialData, parse(allocator, copy));
    }
}

test "PSAR rejects bad block, TOC and CDDA tables" {
    const allocator = testing.allocator;
    const data = try singleFixture(allocator);
    defer allocator.free(data);
    const oversized = [_][3]u32{.{ 0, iso_block_size + 1, 1 }};
    const far = [_][3]u32{.{ 0xFFFFFFFF, 100, 1 }};
    const past_end = [_][3]u32{.{ @intCast(data.len - iso_base_offset - 99), 100, 1 }};
    const last_byte = [_][3]u32{.{ @intCast(data.len - iso_base_offset - 100), 100, 1 }};
    const cases = [_]struct { spec: TestDisc, err: ?anyerror }{
        .{ .spec = .{ .special_offset = special_at, .unknown_offset = unknown_at, .blocks = &oversized }, .err = error.InvalidBlockTable },
        .{ .spec = .{ .special_offset = special_at, .unknown_offset = unknown_at, .blocks = &.{} }, .err = error.InvalidBlockTable },
        .{ .spec = .{ .special_offset = special_at, .unknown_offset = unknown_at, .blocks = &far }, .err = error.BlockOutOfRange },
        .{ .spec = .{ .special_offset = special_at, .unknown_offset = unknown_at, .blocks = &past_end }, .err = error.BlockOutOfRange },
        .{ .spec = .{ .special_offset = special_at, .unknown_offset = unknown_at, .blocks = &last_byte }, .err = null },
    };
    for (cases) |case| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        try putIsoHeader(allocator, copy, iso_header_offset, case.spec);
        if (case.err) |expected| {
            try testing.expectError(expected, parse(allocator, copy));
        } else {
            // The block ending exactly at the last PSAR byte is accepted.
            var ok = try parse(allocator, copy);
            ok.deinit(allocator);
        }
    }

    // Missing lead-out / track records and an unterminated CDDA table.
    const payload = try isoHeaderPayload(allocator, .{ .special_offset = special_at, .unknown_offset = unknown_at });
    defer allocator.free(payload);
    const toc_cases = [_]usize{ 0x414, 0x41E };
    for (toc_cases) |offset| {
        const mutated = try allocator.dupe(u8, payload);
        defer allocator.free(mutated);
        mutated[offset] = 0;
        const pgd_bytes = try build_pgd(allocator, mutated, .{ .total_len = iso_header_size });
        defer allocator.free(pgd_bytes);
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        put(copy, iso_header_offset, pgd_bytes[0..iso_header_size]);
        try testing.expectError(error.InvalidToc, parse(allocator, copy));
    }
    {
        const mutated = try allocator.dupe(u8, payload);
        defer allocator.free(mutated);
        for (0..max_cdda + 1) |i| std.mem.writeInt(u32, mutated[cdda_table + i * cdda_record ..][0..4], 0x1000, .little);
        const pgd_bytes = try build_pgd(allocator, mutated, .{ .total_len = iso_header_size });
        defer allocator.free(pgd_bytes);
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        put(copy, iso_header_offset, pgd_bytes[0..iso_header_size]);
        try testing.expectError(error.InvalidCddaTable, parse(allocator, copy));
    }
    // Decrypted header shorter than the block table start.
    {
        const pgd_bytes = try build_pgd(allocator, payload[0..0x800], .{ .total_len = iso_header_size });
        defer allocator.free(pgd_bytes);
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        put(copy, iso_header_offset, pgd_bytes[0..iso_header_size]);
        try testing.expectError(error.InvalidIsoHeader, parse(allocator, copy));
    }
}

const disc1_at = 0x2000;
const disc3_at = disc1_at + 0x120000;

fn multiFixture(allocator: std.mem.Allocator) ![]u8 {
    const special_off = disc3_at + 0x100000 + 0x1000;
    const startdat_off = disc3_at + 0x100000 + 0x800;
    const psar = try allocator.alloc(u8, special_off + 0x200);
    @memset(psar, 0);
    put(psar, 0, "PSTITLEIMG000000");
    std.mem.writeInt(u32, psar[0x10..][0..4], startdat_off, .little);

    var map: [0x200]u8 = undefined;
    @memset(&map, 0);
    std.mem.writeInt(u32, map[0..][0..4], disc1_at, .little);
    std.mem.writeInt(u32, map[8..][0..4], disc3_at, .little);
    @memcpy(map[0x65..][0..11], "SLUS_999.99");
    std.mem.writeInt(u32, map[0x84..][0..4], special_off, .little);
    @memcpy(map[0x10C..][0..9], "MULTI SET");
    const map_pgd = try build_pgd(allocator, &map, .{ .block_size = 0x200 });
    defer allocator.free(map_pgd);
    try testing.expect(map_pgd.len <= iso_map_size);
    put(psar, iso_map_offset, map_pgd);

    try putIsoHeader(allocator, psar, disc1_at + iso_header_offset, .{ .serial = "SLUS_999.01", .special_offset = 0, .blocks = &.{.{ 0, 64, 1 }} });
    try putIsoHeader(allocator, psar, disc3_at + iso_header_offset, .{ .serial = "SLUS_999.03", .blocks = &.{ .{ 0, 64, 1 }, .{ 64, 128, 0 } }, .cdda = &.{} });

    put(psar, startdat_off, "STARTDAT");
    std.mem.writeInt(u32, psar[startdat_off + 0x10 ..][0..4], 24, .little);
    std.mem.writeInt(u32, psar[startdat_off + 0x14 ..][0..4], 2, .little);

    var special_payload: [0x30]u8 = undefined;
    @memset(&special_payload, 0x55);
    const special = try build_pgd(allocator, &special_payload, .{});
    defer allocator.free(special);
    put(psar, special_off, special);
    return allocator.realloc(psar, special_off + special.len);
}

test "multi disc container" {
    const allocator = testing.allocator;
    const data = try multiFixture(allocator);
    defer allocator.free(data);

    var psar = try parse(allocator, data);
    defer psar.deinit(allocator);
    try testing.expectEqual(Kind.multi, psar.kind);
    try testing.expectEqual(@as(usize, 0x200), psar.iso_map.?.len);
    try testing.expectEqual(@as(usize, 26), psar.startdat.?.len);
    try testing.expect(psar.unknown_data == null);
    try testing.expectEqual(@as(usize, 0x30), psar.special_data.?.len);
    try testing.expectEqual(@as(usize, 2), psar.discs.len);
    try testing.expectEqual(@as(u8, 1), psar.discs[0].index);
    try testing.expectEqual(@as(u8, 3), psar.discs[1].index);
    try testing.expectEqualStrings("SLUS_999.01", psar.discs[0].serial);
    try testing.expectEqualStrings("SLUS_999.03", psar.discs[1].serial);
    try testing.expectEqual(@as(usize, disc1_at + iso_base_offset), psar.discs[0].blocks_base);
    try testing.expectEqual(@as(usize, disc3_at + iso_base_offset), psar.discs[1].blocks_base);
    try testing.expectEqual(@as(usize, 1), psar.discs[0].blocks.len);
    try testing.expectEqual(@as(usize, 2), psar.discs[1].blocks.len);
    try testing.expectEqual(@as(usize, 0), psar.discs[1].cdda.len);
}

test "multi disc MAC failures and bounds" {
    const allocator = testing.allocator;
    const data = try multiFixture(allocator);
    defer allocator.free(data);

    // ISO map header MAC, map block, and the second disc's ISO header.
    const damaged = [_]struct { offset: usize, err: anyerror }{
        .{ .offset = iso_map_offset + 0x40, .err = error.PgdHeaderMacMismatch },
        .{ .offset = iso_map_offset + 0x90 + 7, .err = error.PgdBlockMacMismatch },
        .{ .offset = disc3_at + iso_header_offset + 0x20, .err = error.PgdHeaderMacMismatch },
        .{ .offset = disc3_at + iso_header_offset + 0x90 + 0x500, .err = error.PgdBlockMacMismatch },
    };
    for (damaged) |case| {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        copy[case.offset] ^= 1;
        try testing.expectError(case.err, parse(allocator, copy));
    }
    {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        std.mem.writeInt(u32, copy[0x10..][0..4], 0, .little);
        try testing.expectError(error.TruncatedPsar, parse(allocator, copy[0 .. iso_map_offset + iso_map_size - 1]));
        try testing.expectError(error.TruncatedPsar, parse(allocator, copy[0 .. disc3_at + iso_header_offset + iso_header_size - 1]));
    }
    // ISO map with no discs.
    {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        var map: [0x200]u8 = undefined;
        @memset(&map, 0);
        const map_pgd = try build_pgd(allocator, &map, .{ .block_size = 0x200 });
        defer allocator.free(map_pgd);
        put(copy, iso_map_offset, map_pgd);
        try testing.expectError(error.NoDiscs, parse(allocator, copy));
    }
    // ISO map payload shorter than the special-data field.
    {
        const copy = try allocator.dupe(u8, data);
        defer allocator.free(copy);
        const map_pgd = try build_pgd(allocator, "tiny", .{});
        defer allocator.free(map_pgd);
        put(copy, iso_map_offset, map_pgd);
        try testing.expectError(error.InvalidIsoMap, parse(allocator, copy));
    }
}
