//! Differential harness: recorded DOCUMENT extractions vs the pure-Zig document.zig.
//!
//! Usage: document-diff --corpus PATH [--limit N]
//!   --corpus  JSONL from tools/document_corpus.py
//!   --limit   stop after N rows
//!
//! Each row's objects are re-extracted; the emitted (path, kind, sha256, size)
//! list, or the error, must equal what the catalog recorded. Only mismatching
//! rows are printed. Exit status is 1 if anything differs, 2 on usage errors.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const document = @import("ingest").document;

// Exports used by the ingest module's C wrappers are only analyzed through its
// call graph; referencing the entry point links them.
comptime {
    _ = &@import("ingest").main;
}

const Entry = struct {
    path: []const u8,
    directory: bool,
    sha256: ?[]const u8,
    size: ?u64,

    fn less(_: void, a: Entry, b: Entry) bool {
        return std.mem.lessThan(u8, a.path, b.path);
    }

    fn eql(a: Entry, b: Entry) bool {
        if (!std.mem.eql(u8, a.path, b.path) or a.directory != b.directory or a.size != b.size) return false;
        if ((a.sha256 == null) != (b.sha256 == null)) return false;
        return a.sha256 == null or std.mem.eql(u8, a.sha256.?, b.sha256.?);
    }

    fn print(self: Entry) void {
        if (self.directory) {
            std.debug.print("{s} (directory)", .{self.path});
        } else {
            std.debug.print("{s} (file sha256={s} size={?d})", .{ self.path, self.sha256 orelse "-", self.size });
        }
    }
};

/// Collected by `emit`; everything is owned by the row arena.
const Collector = struct {
    arena: Allocator,
    entries: std.ArrayList(Entry) = .empty,
};

fn emit(collector: *Collector, path: []const u8, bytes: ?[]const u8) anyerror!void {
    const owned_path = try collector.arena.dupe(u8, path);
    if (bytes) |data| {
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(data, &digest, .{});
        const hex = try collector.arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
        try collector.entries.append(collector.arena, .{ .path = owned_path, .directory = false, .sha256 = hex, .size = data.len });
    } else {
        try collector.entries.append(collector.arena, .{ .path = owned_path, .directory = true, .sha256 = null, .size = null });
    }
}

const Outcome = enum { same, differ, read_error };

fn usage() u8 {
    std.debug.print("Usage: document-diff --corpus PATH [--limit N]\n", .{});
    return 2;
}

fn str(value: std.json.Value) ?[]const u8 {
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

fn parseEntries(arena: Allocator, value: std.json.Value) !std.ArrayList(Entry) {
    var list: std.ArrayList(Entry) = .empty;
    if (value != .array) return error.InvalidRow;
    for (value.array.items) |item| {
        if (item != .array or item.array.items.len != 4) return error.InvalidRow;
        const f = item.array.items;
        const path = str(f[0]) orelse return error.InvalidRow;
        const kind = str(f[1]) orelse return error.InvalidRow;
        const sha: ?[]const u8 = if (f[2] == .null) null else (str(f[2]) orelse return error.InvalidRow);
        const size: ?u64 = switch (f[3]) {
            .null => null,
            .integer => |n| std.math.cast(u64, n) orelse return error.InvalidRow,
            else => return error.InvalidRow,
        };
        try list.append(arena, .{ .path = path, .directory = std.mem.eql(u8, kind, "directory"), .sha256 = sha, .size = size });
    }
    return list;
}

fn readObject(io: std.Io, gpa: Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited);
}

fn runRow(io: std.Io, gpa: Allocator, line: []const u8) Outcome {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{}) catch return .read_error;
    if (parsed != .object) return .read_error;
    const obj = parsed.object;
    const source_sha = str(obj.get("source") orelse return .read_error) orelse return .read_error;
    const source_path = str(obj.get("source_path") orelse return .read_error) orelse return .read_error;
    const docinfo_value = obj.get("docinfo") orelse return .read_error;
    const docinfo_sha: ?[]const u8 = if (docinfo_value == .null) null else str(docinfo_value);
    const docinfo_path: ?[]const u8 = if (docinfo_sha != null) str(obj.get("docinfo_path") orelse return .read_error) else null;
    const expect_error = switch (obj.get("expect_error") orelse return .read_error) {
        .bool => |b| b,
        else => return .read_error,
    };
    const expected = parseEntries(arena, obj.get("entries") orelse return .read_error) catch return .read_error;
    const docinfo_name = docinfo_sha orelse "-";

    const source = readObject(io, gpa, source_path) catch return .read_error;
    defer gpa.free(source);
    const docinfo: ?[]u8 = if (docinfo_path) |path| readObject(io, gpa, path) catch return .read_error else null;
    defer if (docinfo) |bytes| gpa.free(bytes);

    var collector: Collector = .{ .arena = arena };
    document.extract(gpa, source, docinfo, &collector, emit) catch |err| {
        if (expect_error) return .same;
        std.debug.print("DIFF {s} {s}: unexpected error {s}\n", .{ source_sha, docinfo_name, @errorName(err) });
        return .differ;
    };
    if (expect_error) {
        std.debug.print("DIFF {s} {s}: expected an error, extraction succeeded ({d} entries)\n", .{ source_sha, docinfo_name, collector.entries.items.len });
        return .differ;
    }

    std.mem.sort(Entry, collector.entries.items, {}, Entry.less);
    std.mem.sort(Entry, expected.items, {}, Entry.less);
    const got = collector.entries.items;
    const want = expected.items;
    const common = @min(got.len, want.len);
    var index: usize = 0;
    while (index < common and Entry.eql(got[index], want[index])) index += 1;
    if (index == got.len and index == want.len) return .same;
    std.debug.print("DIFF {s} {s}: entry {d} (got {d} entries, want {d}): got ", .{ source_sha, docinfo_name, index, got.len, want.len });
    if (index < got.len) got[index].print() else std.debug.print("<end>", .{});
    std.debug.print(", want ", .{});
    if (index < want.len) want[index].print() else std.debug.print("<end>", .{});
    std.debug.print("\n", .{});
    return .differ;
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var corpus: ?[]const u8 = null;
    var limit: ?usize = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--corpus") or std.mem.eql(u8, arg, "--limit")) {
            i += 1;
            if (i == args.len) return usage();
            if (std.mem.eql(u8, arg, "--corpus")) {
                corpus = args[i];
            } else {
                limit = std.fmt.parseInt(usize, args[i], 10) catch return usage();
            }
        } else return usage();
    }
    const corpus_path = corpus orelse return usage();

    const text = std.Io.Dir.cwd().readFileAlloc(init.io, corpus_path, init.gpa, .unlimited) catch |err| {
        std.debug.print("document-diff: cannot read corpus {s}: {s}\n", .{ corpus_path, @errorName(err) });
        return 2;
    };
    defer init.gpa.free(text);

    var rows: usize = 0;
    var same: usize = 0;
    var differ: usize = 0;
    var read_errors: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (limit) |max| if (rows >= max) break;
        rows += 1;
        switch (runRow(init.io, init.gpa, line)) {
            .same => same += 1,
            .differ => differ += 1,
            .read_error => {
                read_errors += 1;
                std.debug.print("READ ERROR row {d}\n", .{rows});
            },
        }
    }

    std.debug.print("\nrows {d}  same {d}  differ {d}  read errors {d}\n", .{ rows, same, differ, read_errors });
    if (differ != 0 or read_errors != 0) {
        std.debug.print("FAIL\n", .{});
        return 1;
    }
    std.debug.print("OK: no differences\n", .{});
    return 0;
}
