//! Differential harness: current C entry points vs the pure-Zig ports in native/.
//!
//! Usage: native-diff [--corpus PATH] [--kind K] [--limit N]
//!   --corpus  TSV from tools/native_corpus.py (kind\tsha256\tstore_path, plus
//!             pops/npdrm/psx_pgd context rows)
//!   --kind    only rows of kind K; the deterministic primitive section runs
//!             when no --kind is given or K is `random`
//!   --limit   stop after N corpus rows (after the kind filter)
//!
//! Every comparison checks return codes and the complete output buffers (both
//! sides start from the same 0xA5 fill, so stray writes show up). Key bytes and
//! decrypted content are never printed; only kind, sha256, codes and the first
//! differing offset. Exit status is 1 if anything differs.
//!
//! Adding a phase-2 kind: write `fn caseX(ctx: *Ctx, fields: []const []const u8)
//! Outcome`, add a prong in `runRow`. Rows without a prong count as skipped.
const std = @import("std");
const Allocator = std.mem.Allocator;

const kirk = @import("native/kirk.zig");
const amctrl = @import("native/amctrl.zig");
const kle = @import("native/kle.zig");
const prx_decrypter = @import("native/prx_decrypter.zig");

// psar_native.cpp calls back into Zig exports (pspdb_psar_lzr/hash) that live
// in the ingest module and are only analyzed through its call graph; referencing
// the entry point links them, as in the ingest executable.
comptime {
    _ = &@import("ingest").main;
}

/// The C implementation, declared exactly as the ingest sources declare it.
const c = struct {
    const MacKey = extern struct { kind: c_int, key: [16]u8, pad: [16]u8, pad_size: c_int };
    const CipherKey = extern struct { kind: u32, seed: u32, key: [16]u8 };

    extern fn pspdb_prx_decode(input: [*]const u8, input_len: usize, output: [*]u8, output_len: usize) c_int;
    extern fn decompress_kle_bounded(output: [*]u8, output_size: c_int, input: [*]const u8, input_size: c_int, is_kl4e: c_int) c_int;

    extern fn kirk_init_prx() void;
    extern fn sceUtilsBufferCopyWithRange(out: ?[*]u8, out_size: c_int, in: ?[*]u8, in_size: c_int, cmd: c_int) c_int;
    extern fn kirk4(out: [*]u8, in: [*]const u8, size: usize, key_id: c_int) void;
    extern fn kirk7(out: [*]u8, in: [*]const u8, size: usize, key_id: c_int) void;

    extern fn sceDrmBBMacInit(mkey: *MacKey, kind: c_int) c_int;
    extern fn sceDrmBBMacUpdate(mkey: *MacKey, buf: [*]u8, size: c_int) c_int;
    extern fn sceDrmBBMacFinal(mkey: *MacKey, buf: [*]u8, vkey: ?[*]u8) c_int;
    extern fn sceDrmBBMacFinal2(mkey: *MacKey, out: [*]u8, vkey: ?[*]u8) c_int;
    extern fn bbmac_getkey(mkey: *MacKey, bbmac: [*]u8, vkey: [*]u8) c_int;
    extern fn sceDrmBBCipherInit(ckey: *CipherKey, kind: c_int, mode: c_int, header_key: [*]u8, version_key: ?[*]u8, seed: u32) c_int;
    extern fn sceDrmBBCipherUpdate(ckey: *CipherKey, data: [*]u8, size: c_int) c_int;
    extern fn sceDrmBBCipherFinal(ckey: *CipherKey) c_int;
};

const fill_byte: u8 = 0xA5;
const kle_output_too_small: i32 = @bitCast(@as(u32, 0x80000104));
const max_decoded_size = 64 << 20;
const max_pgd_size = 64 << 10;
const dnas_key1a90 = [16]u8{ 0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43 };

/// Optional key argument as C sees it: NULL or a pointer to the array.
fn optPtr(v: *?[16]u8) ?[*]u8 {
    if (v.*) |*p| return p;
    return null;
}

const Outcome = enum { same, differ, skipped, read_error };

const Stat = struct {
    name: []const u8,
    same: usize = 0,
    differ: usize = 0,
    skipped: usize = 0,
    read_error: usize = 0,
};

const Ctx = struct {
    gpa: Allocator,
    io: std.Io,
    stats: std.ArrayList(Stat) = .empty,
    kind: []const u8 = "",
    sha: []const u8 = "",
    /// Mismatches in the row/case currently running.
    diffs: usize = 0,

    fn alloc(ctx: *Ctx, n: usize) []u8 {
        return ctx.gpa.alloc(u8, n) catch @panic("out of memory");
    }

    fn filled(ctx: *Ctx, n: usize) []u8 {
        const buf = ctx.alloc(n);
        @memset(buf, fill_byte);
        return buf;
    }

    fn dupe(ctx: *Ctx, bytes: []const u8) []u8 {
        return ctx.gpa.dupe(u8, bytes) catch @panic("out of memory");
    }

    fn begin(ctx: *Ctx, kind: []const u8, sha: []const u8) void {
        ctx.kind = kind;
        ctx.sha = sha;
        ctx.diffs = 0;
    }

    fn finish(ctx: *Ctx) Outcome {
        return if (ctx.diffs == 0) .same else .differ;
    }

    fn stat(ctx: *Ctx, name: []const u8) *Stat {
        for (ctx.stats.items) |*s| if (std.mem.eql(u8, s.name, name)) return s;
        ctx.stats.append(ctx.gpa, .{ .name = ctx.gpa.dupe(u8, name) catch @panic("out of memory") }) catch @panic("out of memory");
        return &ctx.stats.items[ctx.stats.items.len - 1];
    }

    fn record(ctx: *Ctx, name: []const u8, outcome: Outcome) void {
        const s = ctx.stat(name);
        switch (outcome) {
            .same => s.same += 1,
            .differ => s.differ += 1,
            .skipped => s.skipped += 1,
            .read_error => s.read_error += 1,
        }
    }

    fn report(ctx: *Ctx, label: []const u8, c_code: i32, z_code: i32, offset: ?usize) void {
        ctx.diffs += 1;
        std.debug.print("DIFF kind={s} sha256={s} check={s} c={d} (0x{x:0>8}) zig={d} (0x{x:0>8}) first_diff=", .{
            ctx.kind, ctx.sha, label, c_code, @as(u32, @bitCast(c_code)), z_code, @as(u32, @bitCast(z_code)),
        });
        if (offset) |o| std.debug.print("{d}\n", .{o}) else std.debug.print("-\n", .{});
    }

    /// Compare every status code, then the output buffers.
    fn checkCodes(ctx: *Ctx, label: []const u8, c_codes: []const i32, z_codes: []const i32, c_out: []const u8, z_out: []const u8) void {
        for (c_codes, z_codes) |a, b| {
            if (a != b) return ctx.report(label, a, b, null);
        }
        if (std.mem.indexOfDiff(u8, c_out, z_out)) |offset| {
            ctx.report(label, c_codes[c_codes.len - 1], z_codes[z_codes.len - 1], offset);
        }
    }

    fn check(ctx: *Ctx, label: []const u8, c_code: i32, z_code: i32, c_out: []const u8, z_out: []const u8) void {
        ctx.checkCodes(label, &[_]i32{c_code}, &[_]i32{z_code}, c_out, z_out);
    }

    fn readFile(ctx: *Ctx, path: []const u8) ?[]u8 {
        return std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .unlimited) catch null;
    }
};

// ---------------------------------------------------------------------------
// Corpus cases
// ---------------------------------------------------------------------------

fn casePrx(ctx: *Ctx, path: []const u8) Outcome {
    const bytes = ctx.readFile(path) orelse return .read_error;
    defer ctx.gpa.free(bytes);
    // prx.zig allocates exactly input.len for the workspace.
    const out_c = ctx.filled(bytes.len);
    defer ctx.gpa.free(out_c);
    const out_z = ctx.filled(bytes.len);
    defer ctx.gpa.free(out_z);
    const rc_c = c.pspdb_prx_decode(bytes.ptr, bytes.len, out_c.ptr, out_c.len);
    const rc_z = prx_decrypter.prxDecode(bytes, out_z);
    ctx.check("prx_decode", rc_c, rc_z, out_c, out_z);
    return ctx.finish();
}

fn caseKle(ctx: *Ctx, path: []const u8) Outcome {
    const bytes = ctx.readFile(path) orelse return .read_error;
    defer ctx.gpa.free(bytes);
    // Preconditions of kle.zig decodeInto/decode: anything failing them never reaches C.
    if (bytes.len < 9 or (!std.mem.eql(u8, bytes[0..4], "KL3E") and !std.mem.eql(u8, bytes[0..4], "KL4E"))) return .skipped;
    const input = bytes[4..];
    if (input.len > std.math.maxInt(i32)) return .skipped;
    const is_kl4e = bytes[2] == '4';
    var capacity: usize = 1 << 20;
    if (input[0] & 0x80 != 0) {
        const size = std.mem.readInt(u32, input[1..5], .big);
        if (size == 0 or size > max_decoded_size or size > input.len - 5) return .skipped;
        capacity = size;
    }
    // Same capacity growth as kle.zig decode(): only output-too-small retries.
    while (true) {
        const out_c = ctx.filled(capacity);
        defer ctx.gpa.free(out_c);
        const out_z = ctx.filled(capacity);
        defer ctx.gpa.free(out_z);
        const rc_c = c.decompress_kle_bounded(out_c.ptr, @intCast(capacity), input.ptr, @intCast(input.len), @intFromBool(is_kl4e));
        const rc_z = kle.decompressKleBounded(out_z, input, is_kl4e);
        ctx.check("decompress_kle_bounded", rc_c, rc_z, out_c, out_z);
        if (rc_c != kle_output_too_small or capacity == max_decoded_size) break;
        capacity = @min(capacity * 2, max_decoded_size);
    }
    return ctx.finish();
}

fn casePgd(ctx: *Ctx, path: []const u8) Outcome {
    const src = ctx.readFile(path) orelse return .read_error;
    defer ctx.gpa.free(src);
    if (src.len < 0xb0 or src.len > max_pgd_size or !std.mem.eql(u8, src[0..4], "\x00PGD")) return .skipped;

    const header: [0x90]u8 = src[0..0x90].*;

    // The primitives as pgd_native.c exercises them, under both fixed-key types.
    for ([_]i32{ 1, 3 }) |kind| {
        macFinalPair(ctx, "mac_final_plain", kind, header[0..0x70], 0x20, null);
        macFinalPair(ctx, "mac_final_dnas", kind, header[0..0x80], 0x40, dnas_key1a90);
        macFinal2Pair(ctx, "mac_final2_dnas", kind, header[0..0x80], header[0x80..0x90].*, dnas_key1a90);
        macFinal2Pair(ctx, "mac_final2_null", kind, header[0..0x70], header[0x70..0x80].*, null);
    }

    // pspdb_pgd_decode, step by step; the C results drive both sides.
    macFinal2Pair(ctx, "header_mac_80", 1, header[0..0x80], header[0x80..0x90].*, dnas_key1a90);
    const version_key = getKeyPair(ctx, "bbmac_getkey_70", 1, header[0..0x70], header[0x70..0x80].*) orelse return ctx.finish();

    var hdr = header;
    cipherPair(ctx, "cipher_header", 1, 2, header[0x10..0x20].*, version_key, 0, header[0x30..0x60], hdr[0x30..0x60]);

    const data_size: usize = std.mem.readInt(u32, hdr[0x44..0x48], .little);
    const block_size: usize = std.mem.readInt(u32, hdr[0x48..0x4c], .little);
    const data_offset: usize = std.mem.readInt(u32, hdr[0x4c..0x50], .little);
    if (data_size == 0 or block_size < 16 or block_size > (1 << 20) or (block_size & (block_size - 1)) != 0 or
        data_offset < hdr.len or (data_offset & 15) != 0) return ctx.finish();
    const aligned = (data_size + 15) & ~@as(usize, 15);
    if (aligned > src.len or data_offset > src.len or aligned > src.len - data_offset) return ctx.finish();
    const block_count = (aligned + block_size - 1) / block_size;
    const table_offset = data_offset + aligned;
    const table_size = block_count * 16;
    if (table_offset > src.len or table_size != src.len - table_offset) return ctx.finish();

    macFinal2Pair(ctx, "table_mac_60", 1, src[table_offset..][0..table_size], hdr[0x60..0x70].*, version_key);
    for (0..block_count) |block| {
        const offset = block * block_size;
        const size = @min(aligned - offset, block_size);
        macFinal2Pair(ctx, "block_mac", 1, src[data_offset + offset ..][0..size], src[table_offset + block * 16 ..][0..16].*, version_key);
    }
    const plain = ctx.alloc(aligned);
    defer ctx.gpa.free(plain);
    cipherPair(ctx, "cipher_data", 1, 2, hdr[0x30..0x40].*, version_key, 0, src[data_offset..][0..aligned], plain);
    return ctx.finish();
}

// ---------------------------------------------------------------------------
// AMCTRL pair helpers (C vs Zig on identical inputs)
// ---------------------------------------------------------------------------

const MacResult = struct {
    codes: [4]i32 = @splat(0),
    out: [16]u8 = @splat(fill_byte),
};

/// init, update(data[0..split]), update(data[split..]), final(vkey).
fn macFinalPair(ctx: *Ctx, label: []const u8, kind: i32, data: []const u8, split_hint: usize, vkey: ?[16]u8) void {
    const split = @min(split_hint, data.len);
    var cr: MacResult = .{};
    var zr: MacResult = .{};
    {
        var key: c.MacKey = std.mem.zeroes(c.MacKey);
        const scratch = ctx.dupe(data);
        defer ctx.gpa.free(scratch);
        var vk = vkey;
        cr.codes[0] = c.sceDrmBBMacInit(&key, kind);
        cr.codes[1] = c.sceDrmBBMacUpdate(&key, scratch.ptr, @intCast(split));
        cr.codes[2] = c.sceDrmBBMacUpdate(&key, scratch.ptr + split, @intCast(data.len - split));
        cr.codes[3] = c.sceDrmBBMacFinal(&key, &cr.out, optPtr(&vk));
    }
    {
        var key: amctrl.MacKey = undefined;
        var vk = vkey;
        zr.codes[0] = amctrl.macInit(&key, kind);
        zr.codes[1] = amctrl.macUpdate(&key, data[0..split]);
        zr.codes[2] = amctrl.macUpdate(&key, data[split..]);
        zr.codes[3] = amctrl.macFinal(&key, &zr.out, if (vk) |*v| v else null);
    }
    ctx.checkCodes(label, &cr.codes, &zr.codes, &cr.out, &zr.out);
}

/// init, update(data), final2(expected, vkey). `expected` is an input in C; both
/// sides must leave it untouched.
fn macFinal2Pair(ctx: *Ctx, label: []const u8, kind: i32, data: []const u8, expected: [16]u8, vkey: ?[16]u8) void {
    var codes_c: [3]i32 = undefined;
    var codes_z: [3]i32 = undefined;
    var exp_c = expected;
    var exp_z = expected;
    {
        var key: c.MacKey = std.mem.zeroes(c.MacKey);
        const scratch = ctx.dupe(data);
        defer ctx.gpa.free(scratch);
        var vk = vkey;
        codes_c[0] = c.sceDrmBBMacInit(&key, kind);
        codes_c[1] = c.sceDrmBBMacUpdate(&key, scratch.ptr, @intCast(data.len));
        codes_c[2] = c.sceDrmBBMacFinal2(&key, &exp_c, optPtr(&vk));
    }
    {
        var key: amctrl.MacKey = undefined;
        var vk = vkey;
        codes_z[0] = amctrl.macInit(&key, kind);
        codes_z[1] = amctrl.macUpdate(&key, data);
        codes_z[2] = amctrl.macFinal2(&key, &exp_z, if (vk) |*v| v else null);
    }
    ctx.checkCodes(label, &codes_c, &codes_z, &exp_c, &exp_z);
}

/// init, update(data), bbmac_getkey(bbmac). Returns C's version key when it succeeded.
fn getKeyPair(ctx: *Ctx, label: []const u8, kind: i32, data: []const u8, bbmac: [16]u8) ?[16]u8 {
    var codes_c: [3]i32 = undefined;
    var codes_z: [3]i32 = undefined;
    var out_c: [16]u8 = @splat(fill_byte);
    var out_z: [16]u8 = @splat(fill_byte);
    {
        var key: c.MacKey = std.mem.zeroes(c.MacKey);
        const scratch = ctx.dupe(data);
        defer ctx.gpa.free(scratch);
        var mac = bbmac;
        codes_c[0] = c.sceDrmBBMacInit(&key, kind);
        codes_c[1] = c.sceDrmBBMacUpdate(&key, scratch.ptr, @intCast(data.len));
        codes_c[2] = c.bbmac_getkey(&key, &mac, &out_c);
    }
    {
        var key: amctrl.MacKey = undefined;
        const mac = bbmac;
        codes_z[0] = amctrl.macInit(&key, kind);
        codes_z[1] = amctrl.macUpdate(&key, data);
        codes_z[2] = amctrl.getKey(&key, &mac, &out_z);
    }
    ctx.checkCodes(label, &codes_c, &codes_z, &out_c, &out_z);
    return if (codes_c[2] == 0) out_c else null;
}

/// init, update(data), final. `data_out` receives C's transformed data (len == data.len).
fn cipherPair(ctx: *Ctx, label: []const u8, kind: i32, mode: i32, header_key: [16]u8, vkey: ?[16]u8, seed: u32, data: []const u8, data_out: []u8) void {
    std.debug.assert(data_out.len == data.len);
    var codes_c: [3]i32 = undefined;
    var codes_z: [3]i32 = undefined;
    var hk_c = header_key;
    var hk_z = header_key;
    var vk_c = vkey;
    var vk_z = vkey;
    const buf_c = ctx.dupe(data);
    defer ctx.gpa.free(buf_c);
    const buf_z = ctx.dupe(data);
    defer ctx.gpa.free(buf_z);
    {
        var key = std.mem.zeroes(c.CipherKey);
        codes_c[0] = c.sceDrmBBCipherInit(&key, kind, mode, &hk_c, optPtr(&vk_c), seed);
        codes_c[1] = c.sceDrmBBCipherUpdate(&key, buf_c.ptr, @intCast(buf_c.len));
        codes_c[2] = c.sceDrmBBCipherFinal(&key);
    }
    {
        var key: amctrl.CipherKey = undefined;
        codes_z[0] = amctrl.cipherInit(&key, kind, mode, &hk_z, if (vk_z) |*v| v else null, seed);
        codes_z[1] = amctrl.cipherUpdate(&key, buf_z);
        codes_z[2] = amctrl.cipherFinal(&key);
    }
    ctx.checkCodes(label, &codes_c, &codes_z, buf_c, buf_z);
    // Key arguments must also end up identical (C may scribble on them).
    if (!std.mem.eql(u8, &hk_c, &hk_z)) ctx.report(label, codes_c[2], codes_z[2], 0);
    if (vk_c != null and !std.mem.eql(u8, &vk_c.?, &vk_z.?)) ctx.report(label, codes_c[2], codes_z[2], 0);
    @memcpy(data_out, buf_c);
}

// ---------------------------------------------------------------------------
// Deterministic pseudo-random primitive section
// ---------------------------------------------------------------------------

const random_seed: u64 = 0x5053_5044_4246_4d54;
const kirk_cases = 3000;
const helper_cases = 600;
const mac_cases = 900;
const cipher_cases = 600;

fn putU32(buf: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, buf[offset..][0..4], value, .little);
}

/// One sceUtilsBufferCopyWithRange comparison. `alias` runs out==in (one buffer).
/// `out_len` is ignored when aliasing. cmd 14 compares codes only: its output
/// mixes time(0) and stack garbage and is not reproducible.
fn kirkCase(ctx: *Ctx, label: []const u8, cmd: i32, input: []const u8, out_len: usize, alias: bool) void {
    if (alias) {
        const buf_c = ctx.dupe(input);
        defer ctx.gpa.free(buf_c);
        const buf_z = ctx.dupe(input);
        defer ctx.gpa.free(buf_z);
        const n: c_int = @intCast(buf_c.len);
        const rc_c = c.sceUtilsBufferCopyWithRange(buf_c.ptr, n, buf_c.ptr, n, cmd);
        const rc_z = kirk.bufferCopyWithRange(buf_z, buf_z, cmd);
        ctx.check(label, rc_c, rc_z, buf_c, buf_z);
        return;
    }
    const in_c = ctx.dupe(input);
    defer ctx.gpa.free(in_c);
    const in_z = ctx.dupe(input);
    defer ctx.gpa.free(in_z);
    const out_c = ctx.filled(out_len);
    defer ctx.gpa.free(out_c);
    const out_z = ctx.filled(out_len);
    defer ctx.gpa.free(out_z);
    const rc_c = c.sceUtilsBufferCopyWithRange(out_c.ptr, @intCast(out_c.len), in_c.ptr, @intCast(in_c.len), cmd);
    const rc_z = kirk.bufferCopyWithRange(out_z, in_z, cmd);
    if (cmd == 14) {
        ctx.check(label, rc_c, rc_z, &.{}, &.{});
    } else {
        ctx.check(label, rc_c, rc_z, out_c, out_z);
    }
    if (rc_c == rc_z) ctx.check(label, rc_c, rc_z, in_c, in_z);
}

/// Valid-bounds CMD4/CMD7 input: header(0x14) + nb blocks + slack. Only data_size
/// within the buffer is generated; the C reads data_size unchecked.
fn makeCbcInput(ctx: *Ctx, r: std.Random, mode: u32) []u8 {
    const nb = r.intRangeAtMost(usize, 0, 40);
    const slack = r.intRangeAtMost(usize, 0, 16);
    const buf = ctx.alloc(0x14 + nb * 16 + slack);
    r.bytes(buf);
    const data_size: u32 = switch (r.intRangeLessThan(u8, 0, 10)) {
        0 => 0,
        1 => if (nb > 0) @intCast(nb * 16 - r.intRangeAtMost(usize, 0, 15)) else 0,
        else => @intCast(nb * 16),
    };
    const keyseed: u32 = switch (r.intRangeLessThan(u8, 0, 12)) {
        0 => @as(u32, 0x80) + r.int(u8),
        1 => r.int(u32),
        else => r.intRangeLessThan(u32, 0, 0x80),
    };
    putU32(buf, 0, if (r.intRangeLessThan(u8, 0, 8) == 0) r.intRangeAtMost(u32, 0, 7) else mode);
    putU32(buf, 0xc, keyseed);
    putU32(buf, 0x10, data_size);
    return buf;
}

fn makeCmd1Input(ctx: *Ctx, r: std.Random) []u8 {
    const len = 0x90 + r.intRangeAtMost(usize, 0, 0x170);
    const buf = ctx.alloc(len);
    r.bytes(buf);
    const avail: u32 = @intCast(len - 0x90);
    putU32(buf, 0x60, switch (r.intRangeLessThan(u8, 0, 8)) {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => r.int(u32),
        else => 1,
    });
    buf[0x64] = if (r.boolean()) 1 else r.int(u8);
    const offset: u32 = if (r.intRangeLessThan(u8, 0, 4) == 0) r.intRangeAtMost(u32, 0, avail + 8) else 16 * r.intRangeAtMost(u32, 0, avail / 16);
    const size: u32 = switch (r.intRangeLessThan(u8, 0, 8)) {
        0 => 0,
        1 => r.intRangeAtMost(u32, 0, avail + 40),
        else => if (avail >= offset) r.intRangeAtMost(u32, 0, avail - offset) else 0,
    };
    putU32(buf, 0x70, size);
    putU32(buf, 0x74, offset);
    return buf;
}

fn makeCmd11Input(ctx: *Ctx, r: std.Random) []u8 {
    const n = r.intRangeAtMost(usize, 0, 300);
    const buf = ctx.alloc(4 + n + r.intRangeAtMost(usize, 0, 8));
    r.bytes(buf);
    putU32(buf, 0, switch (r.intRangeLessThan(u8, 0, 8)) {
        0 => 0,
        1 => @intCast(n / 2),
        else => @intCast(n),
    });
    return buf;
}

fn runKirkRandom(ctx: *Ctx, r: std.Random) void {
    const name = "random:kirk_cmd";
    for (0..kirk_cases) |i| {
        var tag: [32]u8 = undefined;
        ctx.begin(name, std.fmt.bufPrint(&tag, "case-{d}", .{i}) catch unreachable);
        const alias = r.boolean();
        // cmd 14 (PRNG) is excluded: its C output mixes time() and stack
        // garbage, and no ported caller reaches it (cipherInit mode 2 only).
        switch (r.intRangeLessThan(u8, 0, 13)) {
            0, 1, 2 => {
                const input = makeCbcInput(ctx, r, 4);
                defer ctx.gpa.free(input);
                kirkCase(ctx, "cmd4", 4, input, input.len, alias);
            },
            3, 4, 5 => {
                const input = makeCbcInput(ctx, r, 5);
                defer ctx.gpa.free(input);
                kirkCase(ctx, "cmd7", 7, input, input.len, alias);
            },
            6, 7 => {
                const input = makeCmd1Input(ctx, r);
                defer ctx.gpa.free(input);
                kirkCase(ctx, "cmd1", 1, input, input.len + 0x40, alias);
            },
            8, 9 => {
                const input = makeCmd1Input(ctx, r);
                defer ctx.gpa.free(input);
                kirkCase(ctx, "cmd10", 10, input, 0x20, false);
            },
            10, 11 => {
                const input = makeCmd11Input(ctx, r);
                defer ctx.gpa.free(input);
                kirkCase(ctx, "cmd11", 11, input, 0x20, false);
            },
            12 => {
                // Unimplemented in sceUtilsBufferCopyWithRange: -1.
                const input = makeCbcInput(ctx, r, 4);
                defer ctx.gpa.free(input);
                const cmds = [_]i32{ 0, 2, 3, 5, 6, 8, 9, 15, 18, 99, -1 };
                kirkCase(ctx, "cmd_other", cmds[r.intRangeLessThan(usize, 0, cmds.len)], input, input.len, false);
            },
            else => kirkCase(ctx, "cmd14", 14, &.{}, r.intRangeAtMost(usize, 0, 0x40), false),
        }
        ctx.record(name, ctx.finish());
    }
}

fn runHelperRandom(ctx: *Ctx, r: std.Random) void {
    const name = "random:kirk4_kirk7";
    for (0..helper_cases) |i| {
        var tag: [32]u8 = undefined;
        ctx.begin(name, std.fmt.bufPrint(&tag, "case-{d}", .{i}) catch unreachable);
        const n = 16 * r.intRangeAtMost(usize, 1, 64);
        const key_id: i32 = r.intRangeLessThan(i32, 0, 0x80);
        const decrypt = r.boolean();
        const alias = r.boolean();
        const input = ctx.alloc(n);
        defer ctx.gpa.free(input);
        r.bytes(input);
        const label = if (decrypt) "kirk7" else "kirk4";
        if (alias) {
            const buf_c = ctx.dupe(input);
            defer ctx.gpa.free(buf_c);
            const buf_z = ctx.dupe(input);
            defer ctx.gpa.free(buf_z);
            if (decrypt) c.kirk7(buf_c.ptr, buf_c.ptr, n, key_id) else c.kirk4(buf_c.ptr, buf_c.ptr, n, key_id);
            if (decrypt) kirk.kirk7(buf_z, buf_z, key_id) else kirk.kirk4(buf_z, buf_z, key_id);
            ctx.check(label, 0, 0, buf_c, buf_z);
        } else {
            const out_c = ctx.filled(n);
            defer ctx.gpa.free(out_c);
            const out_z = ctx.filled(n);
            defer ctx.gpa.free(out_z);
            if (decrypt) c.kirk7(out_c.ptr, input.ptr, n, key_id) else c.kirk4(out_c.ptr, input.ptr, n, key_id);
            if (decrypt) kirk.kirk7(out_z, input, key_id) else kirk.kirk4(out_z, input, key_id);
            ctx.check(label, 0, 0, out_c, out_z);
        }
        ctx.record(name, ctx.finish());
    }
}

fn randomBlob(ctx: *Ctx, r: std.Random) []u8 {
    const len: usize = switch (r.intRangeLessThan(u8, 0, 6)) {
        0 => r.intRangeAtMost(usize, 0, 40),
        1 => 16 * r.intRangeAtMost(usize, 0, 8),
        2 => r.intRangeAtMost(usize, 0x7f0, 0x830),
        3 => r.intRangeAtMost(usize, 0, 5000),
        else => 16 * r.intRangeAtMost(usize, 0, 200),
    };
    const buf = ctx.alloc(len);
    r.bytes(buf);
    return buf;
}

fn runMacRandom(ctx: *Ctx, r: std.Random) void {
    const name = "random:amctrl_mac";
    for (0..mac_cases) |i| {
        var tag: [32]u8 = undefined;
        ctx.begin(name, std.fmt.bufPrint(&tag, "case-{d}", .{i}) catch unreachable);
        const kind = r.intRangeAtMost(i32, 1, 3);
        const data = randomBlob(ctx, r);
        defer ctx.gpa.free(data);
        const split = r.intRangeAtMost(usize, 0, data.len);
        var vkey_value: [16]u8 = undefined;
        r.bytes(&vkey_value);
        const vkey: ?[16]u8 = if (r.boolean()) vkey_value else null;
        macFinalPair(ctx, "mac_final", kind, data, split, vkey);

        // Final2: expected is the true MAC about half the time (types 1/2 only; type 3
        // decrypts the expected value first, so a random one just exercises the mismatch).
        var expected: [16]u8 = undefined;
        r.bytes(&expected);
        if (kind != 3 and r.boolean()) {
            var key: c.MacKey = std.mem.zeroes(c.MacKey);
            const scratch = ctx.dupe(data);
            defer ctx.gpa.free(scratch);
            var vk: ?[16]u8 = if (vkey != null) vkey_value else null;
            _ = c.sceDrmBBMacInit(&key, kind);
            _ = c.sceDrmBBMacUpdate(&key, scratch.ptr, @intCast(scratch.len));
            _ = c.sceDrmBBMacFinal(&key, &expected, optPtr(&vk));
        }
        macFinal2Pair(ctx, "mac_final2", kind, data, expected, vkey);
        _ = getKeyPair(ctx, "bbmac_getkey", kind, data, expected);
        ctx.record(name, ctx.finish());
    }
}

fn runCipherRandom(ctx: *Ctx, r: std.Random) void {
    const name = "random:amctrl_cipher";
    for (0..cipher_cases) |i| {
        var tag: [32]u8 = undefined;
        ctx.begin(name, std.fmt.bufPrint(&tag, "case-{d}", .{i}) catch unreachable);
        const kind = r.intRangeAtMost(i32, 1, 2);
        // Every caller uses mode 2; mode 1 needs the unreproducible cmd 14 PRNG.
        const mode: i32 = 2;
        const data = randomBlob(ctx, r);
        defer ctx.gpa.free(data);
        var header_key: [16]u8 = undefined;
        r.bytes(&header_key);
        var vkey: [16]u8 = undefined;
        r.bytes(&vkey);
        const seed: u32 = if (r.boolean()) 0 else r.int(u32);
        const out = ctx.alloc(data.len);
        defer ctx.gpa.free(out);
        cipherPair(ctx, "cipher", kind, mode, header_key, if (r.intRangeLessThan(u8, 0, 4) == 0) null else vkey, seed, data, out);
        ctx.record(name, ctx.finish());
    }
}

fn runRandom(ctx: *Ctx) void {
    var prng = std.Random.Xoshiro256.init(random_seed);
    const r = prng.random();
    runKirkRandom(ctx, r);
    runHelperRandom(ctx, r);
    runMacRandom(ctx, r);
    runCipherRandom(ctx, r);
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

fn runRow(ctx: *Ctx, fields: []const []const u8) Outcome {
    const kind = fields[0];
    if (fields.len < 3) return .skipped;
    const path = fields[2];
    if (std.mem.eql(u8, kind, "prx")) return casePrx(ctx, path);
    if (std.mem.eql(u8, kind, "kl3e") or std.mem.eql(u8, kind, "kl4e")) return caseKle(ctx, path);
    if (std.mem.eql(u8, kind, "pgd")) return casePgd(ctx, path);
    // Phase 2: psar, psx_pgd, pops, npdrm.
    return .skipped;
}

const Options = struct {
    corpus: ?[]const u8 = null,
    kind: ?[]const u8 = null,
    limit: ?usize = null,
};

fn usage() u8 {
    std.debug.print("Usage: native-diff [--corpus PATH] [--kind K] [--limit N]\n", .{});
    return 2;
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var options: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--corpus") or std.mem.eql(u8, arg, "--kind") or std.mem.eql(u8, arg, "--limit")) {
            i += 1;
            if (i == args.len) return usage();
            if (std.mem.eql(u8, arg, "--corpus")) options.corpus = args[i];
            if (std.mem.eql(u8, arg, "--kind")) options.kind = args[i];
            if (std.mem.eql(u8, arg, "--limit")) options.limit = std.fmt.parseInt(usize, args[i], 10) catch return usage();
        } else return usage();
    }

    var ctx: Ctx = .{ .gpa = init.gpa, .io = init.io };
    // The C library keeps its KIRK AES context in thread-local state.
    c.kirk_init_prx();

    var processed: usize = 0;
    if (options.corpus) |corpus| {
        const text = std.Io.Dir.cwd().readFileAlloc(init.io, corpus, init.gpa, .unlimited) catch |err| {
            std.debug.print("native-diff: cannot read corpus {s}: {s}\n", .{ corpus, @errorName(err) });
            return 2;
        };
        defer init.gpa.free(text);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (options.limit) |limit| if (processed >= limit) break;
            var fields_buf: [8][]const u8 = undefined;
            var count: usize = 0;
            var parts = std.mem.splitScalar(u8, line, '\t');
            while (parts.next()) |part| {
                if (count == fields_buf.len) break;
                fields_buf[count] = part;
                count += 1;
            }
            if (count < 2) continue;
            const fields = fields_buf[0..count];
            if (options.kind) |wanted| if (!std.mem.eql(u8, wanted, fields[0])) continue;
            processed += 1;
            ctx.begin(fields[0], fields[1]);
            ctx.record(fields[0], runRow(&ctx, fields));
        }
    }

    if (options.kind == null or std.mem.eql(u8, options.kind.?, "random")) runRandom(&ctx);

    var total_differ: usize = 0;
    std.debug.print("\n{s:<24} {s:>8} {s:>8} {s:>8} {s:>10}\n", .{ "kind", "same", "differ", "skipped", "read_error" });
    for (ctx.stats.items) |s| {
        std.debug.print("{s:<24} {d:>8} {d:>8} {d:>8} {d:>10}\n", .{ s.name, s.same, s.differ, s.skipped, s.read_error });
        total_differ += s.differ;
    }
    if (total_differ != 0) {
        std.debug.print("\nFAIL: {d} differing case(s)\n", .{total_differ});
        return 1;
    }
    std.debug.print("\nOK: no differences\n", .{});
    return 0;
}

test {
    _ = kirk;
    _ = amctrl;
    _ = kle;
    _ = prx_decrypter;
}
