//! PS1 Classics data-track assembly: port of PSXtract-2 `build_data_track`
//! (`psxtract.cpp:473`) operating on an in-memory DATA.PSAR.
//!
//! Each block-table entry names a 16-sector (37,632-byte) block, stored either
//! compressed (`size < 37632`, see `lz.zig`) or raw (`size == 37632`).
//! Blocks with `marker == 0` additionally feed TRASH/OVERDUMP using the
//! release executable's scan: the first word-aligned all-zero 32-bit word from
//! the block start ends the TRASH prefix; the rest of the block (including
//! that word) is appended to OVERDUMP.  A block without such a word is
//! entirely TRASH and contributes nothing to OVERDUMP (plan change 3).
//! TRASH keeps the last non-empty prefix; OVERDUMP accumulates.
const std = @import("std");
const lz = @import("lz.zig");

pub const sector_size: usize = 2352;
pub const block_size: usize = lz.block_size;

/// Upper bound on the data-track length (90 min of CD frames plus slack).
pub const max_sectors: u32 = 450_000;
/// Upper bound on block-table entries processed (covers `max_sectors`).
pub const max_blocks: usize = max_sectors / 16 + 1;

pub const Error = error{
    /// `sectors` is above `max_sectors`.
    TooManySectors,
    /// Block table longer than `max_blocks`.
    TooManyBlocks,
    /// A block entry is larger than a block or points outside the PSAR.
    InvalidBlock,
    /// A compressed block failed to decode.
    InvalidCompressedBlock,
    /// The block table holds fewer sectors than requested.
    ImageIncomplete,
};

pub const DataTrack = struct {
    /// `sectors * 2352` bytes: raw user-sector data (DATA_TRACK.BIN, pre-fixImage).
    iso: []u8,
    /// Last non-empty TRASH prefix (TRASH.BIN); may be empty.
    trash: []u8,
    /// Concatenated OVERDUMP remainders (OVERDUMP.BIN); may be empty.
    overdump: []u8,
    /// Any non-zero byte of the block-aligned DATA_TRACK.BIN beyond `iso` (the
    /// last block's remainder and every block after the requested sectors).
    tail_nonzero: bool,

    pub fn deinit(self: *DataTrack, allocator: std.mem.Allocator) void {
        allocator.free(self.iso);
        allocator.free(self.trash);
        allocator.free(self.overdump);
        self.* = undefined;
    }
};

/// Length of the TRASH prefix of an aux block: offset of the first aligned
/// zero word, or `block_size` if there is none.
fn trashPrefix(block: *const [block_size]u8) usize {
    var n: usize = 0;
    while (n + 4 <= block_size) : (n += 4) {
        if (std.mem.readInt(u32, block[n..][0..4], .little) == 0) return n;
    }
    return block_size;
}

/// `disc` needs `blocks: []const BlockEntry` (`offset: u32`, `size: u16`,
/// `marker: u16`) and `blocks_base: usize` (absolute offset in `psar`), i.e.
/// the U1 `psar.Disc`.  A `size == 0` entry terminates the table, as in
/// PSXtract.
pub fn buildDataTrack(
    allocator: std.mem.Allocator,
    psar: []const u8,
    disc: anytype,
    sectors: u32,
) !DataTrack {
    if (sectors > max_sectors) return error.TooManySectors;

    var count: usize = 0;
    for (disc.blocks) |entry| {
        if (entry.size == 0) break;
        count += 1;
    }
    if (count > max_blocks) return error.TooManyBlocks;
    if (count * 16 < sectors) return error.ImageIncomplete;

    const iso = try allocator.alloc(u8, @as(usize, sectors) * sector_size);
    errdefer allocator.free(iso);

    const scratch = try allocator.alloc(u8, 2 * block_size);
    defer allocator.free(scratch);
    const comp: *[block_size]u8 = scratch[0..block_size];
    const decomp: *[block_size]u8 = scratch[block_size..][0..block_size];

    var trash: std.ArrayList(u8) = .empty;
    errdefer trash.deinit(allocator);
    var overdump: std.ArrayList(u8) = .empty;
    errdefer overdump.deinit(allocator);

    var written: usize = 0;
    var tail_nonzero = false;
    for (disc.blocks[0..count]) |entry| {
        const size: usize = entry.size;
        if (size > block_size) return error.InvalidBlock;
        const begin = std.math.add(usize, disc.blocks_base, entry.offset) catch return error.InvalidBlock;
        const end = std.math.add(usize, begin, size) catch return error.InvalidBlock;
        if (end > psar.len) return error.InvalidBlock;

        if (size < block_size) {
            // PSXtract decodes from a zero-filled block-sized buffer.
            @memcpy(comp[0..size], psar[begin..end]);
            @memset(comp[size..], 0);
            lz.decompress(decomp, comp) catch return error.InvalidCompressedBlock;
        } else {
            @memcpy(decomp, psar[begin..end]);
        }

        if (entry.marker == 0) {
            const prefix = trashPrefix(decomp);
            if (prefix != 0) {
                trash.clearRetainingCapacity();
                try trash.appendSlice(allocator, decomp[0..prefix]);
            }
            try overdump.appendSlice(allocator, decomp[prefix..]);
        }

        const n = if (written < iso.len) @min(block_size, iso.len - written) else 0;
        @memcpy(iso[written..][0..n], decomp[0..n]);
        written += n;
        if (!tail_nonzero and !std.mem.allEqual(u8, decomp[n..], 0)) tail_nonzero = true;
    }

    const trash_owned = try trash.toOwnedSlice(allocator);
    errdefer allocator.free(trash_owned);
    const overdump_owned = try overdump.toOwnedSlice(allocator);
    return .{ .iso = iso, .trash = trash_owned, .overdump = overdump_owned, .tail_nonzero = tail_nonzero };
}

// ---- tests ----

const TestEntry = struct { offset: u32, size: u16, marker: u16 };
const TestDisc = struct { blocks: []const TestEntry, blocks_base: usize };

/// Build a PSAR with `blocks_base` 0x40 and the given payloads back to back.
fn testPsar(allocator: std.mem.Allocator, payloads: []const []const u8, markers: []const u16, entries: []TestEntry) ![]u8 {
    var psar: std.ArrayList(u8) = .empty;
    errdefer psar.deinit(allocator);
    try psar.appendNTimes(allocator, 0xEE, 0x40);
    for (payloads, markers, entries) |p, m, *e| {
        e.* = .{ .offset = @intCast(psar.items.len - 0x40), .size = @intCast(p.len), .marker = m };
        try psar.appendSlice(allocator, p);
    }
    return psar.toOwnedSlice(allocator);
}

fn aux(allocator: std.mem.Allocator, block: *const [block_size]u8) !DataTrack {
    var entries: [1]TestEntry = undefined;
    const psar = try testPsar(allocator, &.{block}, &.{0}, &entries);
    defer allocator.free(psar);
    return buildDataTrack(allocator, psar, TestDisc{ .blocks = &entries, .blocks_base = 0x40 }, 16);
}

test "aux: immediate zero word => whole block is OVERDUMP, no TRASH" {
    const a = std.testing.allocator;
    var block: [block_size]u8 = @splat(0);
    var dt = try aux(a, &block);
    defer dt.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), dt.trash.len);
    try std.testing.expectEqualSlices(u8, &block, dt.overdump);
    try std.testing.expectEqualSlices(u8, &block, dt.iso);
}

test "aux: sync prefix is not skipped" {
    const a = std.testing.allocator;
    var block: [block_size]u8 = @splat(0);
    block[1] = 0xff;
    block[2] = 0xff;
    block[3] = 0xff;
    @memset(block[4..8], 0x33);
    var dt = try aux(a, &block);
    defer dt.deinit(a);
    try std.testing.expectEqualSlices(u8, block[0..8], dt.trash);
    try std.testing.expectEqualSlices(u8, block[8..], dt.overdump);
}

test "aux: last word zero" {
    const a = std.testing.allocator;
    var block: [block_size]u8 = @splat(0x33);
    @memset(block[block_size - 4 ..], 0);
    var dt = try aux(a, &block);
    defer dt.deinit(a);
    try std.testing.expectEqualSlices(u8, block[0 .. block_size - 4], dt.trash);
    try std.testing.expectEqualSlices(u8, block[block_size - 4 ..], dt.overdump);
}

test "aux: no terminator => whole block TRASH, empty OVERDUMP, ISO intact" {
    const a = std.testing.allocator;
    const block: [block_size]u8 = @splat(0x33);
    var dt = try aux(a, &block);
    defer dt.deinit(a);
    try std.testing.expectEqualSlices(u8, &block, dt.trash);
    try std.testing.expectEqual(@as(usize, 0), dt.overdump.len);
    try std.testing.expectEqualSlices(u8, &block, dt.iso);
}

test "aux: TRASH keeps last non-empty prefix, OVERDUMP accumulates" {
    const a = std.testing.allocator;
    var b0: [block_size]u8 = @splat(0);
    @memset(b0[0..8], 0x11);
    var b1: [block_size]u8 = @splat(0); // empty prefix: TRASH untouched
    b1[block_size - 1] = 9;
    var entries: [2]TestEntry = undefined;
    const psar = try testPsar(a, &.{ &b0, &b1 }, &.{ 0, 0 }, &entries);
    defer a.free(psar);
    var dt = try buildDataTrack(a, psar, TestDisc{ .blocks = &entries, .blocks_base = 0x40 }, 32);
    defer dt.deinit(a);
    try std.testing.expectEqualSlices(u8, b0[0..8], dt.trash);
    try std.testing.expectEqual(@as(usize, 2 * block_size - 8), dt.overdump.len);
    try std.testing.expectEqualSlices(u8, b0[8..], dt.overdump[0 .. block_size - 8]);
    try std.testing.expectEqualSlices(u8, &b1, dt.overdump[block_size - 8 ..]);
}

test "raw and compressed blocks, marker != 0 skips aux, trimming to sectors" {
    const a = std.testing.allocator;
    var raw: [block_size]u8 = @splat(0);
    for (&raw, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    // head 0, code 0xFFFFFFFF, then implicit zero padding: a zero block.
    const compressed = [_]u8{ 0, 0xff, 0xff, 0xff, 0xff };
    var entries: [2]TestEntry = undefined;
    const psar = try testPsar(a, &.{ &raw, &compressed }, &.{ 1, 1 }, &entries);
    defer a.free(psar);
    const disc: TestDisc = .{ .blocks = &entries, .blocks_base = 0x40 };

    var dt = try buildDataTrack(a, psar, disc, 20);
    defer dt.deinit(a);
    try std.testing.expectEqual(@as(usize, 20 * sector_size), dt.iso.len);
    try std.testing.expectEqualSlices(u8, &raw, dt.iso[0..block_size]);
    for (dt.iso[block_size..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expectEqual(@as(usize, 0), dt.trash.len);
    try std.testing.expectEqual(@as(usize, 0), dt.overdump.len);
    // Only zeros follow the 20 requested sectors (rest of block 1, then block 2).
    try std.testing.expect(!dt.tail_nonzero);
}

test "tail_nonzero reports data beyond the requested sectors" {
    const a = std.testing.allocator;
    var raw: [block_size]u8 = @splat(0);
    raw[9 * sector_size + 100] = 1; // absolute sector 25: past 20 requested sectors, inside 32
    const zero: [block_size]u8 = @splat(0);
    var entries: [2]TestEntry = undefined;
    const psar = try testPsar(a, &.{ &zero, &raw }, &.{ 1, 1 }, &entries);
    defer a.free(psar);
    const disc: TestDisc = .{ .blocks = &entries, .blocks_base = 0x40 };
    var past = try buildDataTrack(a, psar, disc, 20);
    defer past.deinit(a);
    try std.testing.expect(past.tail_nonzero);
    var inside = try buildDataTrack(a, psar, disc, 32);
    defer inside.deinit(a);
    try std.testing.expect(!inside.tail_nonzero);
}

test "table shorter than requested sectors, size-0 terminator, bad entries" {
    const a = std.testing.allocator;
    const raw: [block_size]u8 = @splat(1);
    var entries: [3]TestEntry = undefined;
    const psar = try testPsar(a, &.{ &raw, &raw, &raw }, &.{ 1, 1, 1 }, &entries);
    defer a.free(psar);
    const base = 0x40;

    // Only two blocks before the terminator.
    entries[2].size = 0;
    try std.testing.expectError(error.ImageIncomplete, buildDataTrack(a, psar, TestDisc{ .blocks = &entries, .blocks_base = base }, 33));
    var dt = try buildDataTrack(a, psar, TestDisc{ .blocks = &entries, .blocks_base = base }, 32);
    dt.deinit(a);

    // Oversized block.
    var bad = entries;
    bad[0].size = block_size + 1;
    try std.testing.expectError(error.InvalidBlock, buildDataTrack(a, psar, TestDisc{ .blocks = &bad, .blocks_base = base }, 16));
    // Offset outside the PSAR.
    bad = entries;
    bad[0].offset = @intCast(psar.len);
    try std.testing.expectError(error.InvalidBlock, buildDataTrack(a, psar, TestDisc{ .blocks = &bad, .blocks_base = base }, 16));
    // Too many sectors.
    try std.testing.expectError(error.TooManySectors, buildDataTrack(a, psar, TestDisc{ .blocks = &entries, .blocks_base = base }, max_sectors + 1));
}

test "compressed block that cannot decode is rejected" {
    const a = std.testing.allocator;
    // All-ones code: every bit decodes as 1 => back-reference before block start.
    const compressed = [_]u8{ 0, 0, 0, 0, 0 };
    var entries: [1]TestEntry = undefined;
    const psar = try testPsar(a, &.{&compressed}, &.{1}, &entries);
    defer a.free(psar);
    try std.testing.expectError(error.InvalidCompressedBlock, buildDataTrack(a, psar, TestDisc{ .blocks = &entries, .blocks_base = 0x40 }, 16));
}
