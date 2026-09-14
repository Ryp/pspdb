//! Native PSAR extraction with source-order last-write-wins. Small outputs stay
//! in memory; larger archives replay validated input rather than retain it all.
const std = @import("std");
const memory = @import("bytes.zig");
const lzr = @import("lzr.zig");

const native_emit = *const fn (?*anyopaque, [*]const u8, usize, ?[*]const u8, usize, c_int) callconv(.c) c_int;
extern fn pspdb_psar_walk(input: [*]const u8, size: usize, context: ?*anyopaque, emit: native_emit) c_int;

// The legacy custom SHA-256 IV and 28-byte output are standard SHA-224. Its
// caller deliberately preserves the last four bytes of the destination.
export fn pspdb_psar_hash(custom: c_int, first: ?[*]const u8, first_size: usize, second: ?[*]const u8, second_size: usize, output: [*]u8) void {
    const a = if (first_size == 0) "" else first.?[0..first_size];
    const b = if (second_size == 0) "" else second.?[0..second_size];
    if (custom != 0) {
        var hash = std.crypto.hash.sha2.Sha224.init(.{});
        hash.update(a);
        hash.update(b);
        hash.final(output[0..28]);
    } else {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(a);
        hash.update(b);
        hash.final(output[0..32]);
    }
}

// PSAR's chained compression members need the exact upstream input endpoint.
export fn pspdb_psar_lzr(input: [*]const u8, size: usize, output: [*]u8, capacity: usize, consumed: *usize) c_int {
    consumed.* = 0;
    const member = lzr.decode_raw_member_into(input[0..size], output[0..capacity]) catch return -1;
    if (member.written > std.math.maxInt(c_int)) return -1;
    consumed.* = member.consumed;
    return @intCast(member.written);
}

fn native_status(result: c_int) !void {
    return switch (result) {
        0 => {},
        -2 => error.OutOfMemory,
        -4 => error.PsarCryptoUnavailable,
        else => error.InvalidPsar,
    };
}

fn native_contents(bytes: ?[*]const u8, size: usize, directory: c_int) !?[]const u8 {
    return if (directory != 0) null else if (bytes) |data| data[0..size] else if (size == 0) "" else error.InvalidPsar;
}

const Collector = struct {
    // An allocation policy, not an output/format limit. Beyond this budget,
    // retain only final names and event positions and decode immutable input again.
    const retention_limit = 8 * 1024 * 1024;
    const Output = struct {
        event: usize,
        directory: bool,
        size: usize,
        contents: ?memory.View = null,
    };
    allocator: std.mem.Allocator,
    outputs: std.StringArrayHashMapUnmanaged(Output) = .{},
    failure: ?anyerror = null,
    events: usize = 0,
    retained: usize = 0,
    replay: bool = false,

    fn deinit(self: *Collector) void {
        for (self.outputs.keys(), self.outputs.values()) |name, output| {
            self.allocator.free(name);
            if (output.contents) |view| view.release();
        }
        self.outputs.deinit(self.allocator);
    }

    fn valid_name(name: []const u8) bool {
        if (name.len == 0 or name[0] == '/' or name[name.len - 1] == '/') return false;
        var parts = std.mem.splitScalar(u8, name, '/');
        while (parts.next()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
            for (part) |byte| if (byte < 0x20 or byte == '\\' or byte == ':') return false;
        }
        return true;
    }

    fn collect(self: *Collector, name: []const u8, bytes: ?[]const u8) !void {
        if (!valid_name(name)) return error.InvalidPsarPath;
        const event = self.events;
        self.events += 1;
        const existing = self.outputs.getIndex(name);
        // mkdir is idempotent and does not truncate an existing file.
        if (existing != null and bytes == null) return;
        const index = existing orelse index: {
            const key = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(key);
            try self.outputs.put(self.allocator, key, .{ .event = event, .directory = true, .size = 0 });
            break :index self.outputs.count() - 1;
        };
        const output = &self.outputs.values()[index];
        if (output.contents) |old| {
            self.retained -= old.bytes.len;
            old.release();
        }
        output.* = .{ .event = event, .directory = bytes == null, .size = if (bytes) |value| value.len else 0 };
        if (bytes) |value| {
            if (self.replay) return;
            if (value.len > retention_limit - self.retained) {
                for (self.outputs.values()) |*previous| {
                    if (previous.contents) |view| view.release();
                    previous.contents = null;
                }
                self.retained = 0;
                self.replay = true;
                return;
            }
            output.contents = try memory.Owner.take_allocated(self.allocator, try self.allocator.dupe(u8, value));
            self.retained += value.len;
        }
    }

    fn receive(raw: ?*anyopaque, name: [*]const u8, name_size: usize, bytes: ?[*]const u8, size: usize, directory: c_int) callconv(.c) c_int {
        const self: *Collector = @ptrCast(@alignCast(raw.?));
        if (self.failure != null) return -1;
        const contents = native_contents(bytes, size, directory) catch |err| {
            self.failure = err;
            return -1;
        };
        self.collect(name[0..name_size], contents) catch |err| {
            self.failure = err;
            return -1;
        };
        return 0;
    }
};

/// Input is immutable and borrowed for this synchronous call; it may be unaligned.
/// No output is emitted before a complete successful native walk. Names and views
/// are borrowed until emit returns; retaining a view extends its backing lifetime.
pub fn walk(allocator: std.mem.Allocator, input: memory.View, context: anytype, comptime emit: anytype) !void {
    var collector: Collector = .{ .allocator = allocator };
    defer collector.deinit();
    const result = pspdb_psar_walk(input.bytes.ptr, input.bytes.len, &collector, Collector.receive);
    if (collector.failure) |err| return err;
    try native_status(result);
    if (!collector.replay) {
        for (collector.outputs.keys(), collector.outputs.values()) |name, output| {
            try emit(context, name, output.contents);
        }
        return;
    }
    const Replay = struct {
        collector: *const Collector,
        context: @TypeOf(context),
        events: usize = 0,
        emitted: usize = 0,
        failure: ?anyerror = null,

        fn output(self: *@This(), name: []const u8, bytes: ?[]const u8) !void {
            const expected = self.collector.outputs.get(name) orelse return error.PsarReplayMismatch;
            const event = self.events;
            self.events += 1;
            if (event != expected.event) return;
            if (expected.directory != (bytes == null) or expected.size != (if (bytes) |value| value.len else 0)) return error.PsarReplayMismatch;
            const view: ?memory.View = if (bytes) |value|
                try memory.Owner.take_allocated(self.collector.allocator, try self.collector.allocator.dupe(u8, value))
            else
                null;
            defer if (view) |owned| owned.release();
            try emit(self.context, name, view);
            self.emitted += 1;
        }

        fn receive(raw: ?*anyopaque, name: [*]const u8, name_size: usize, bytes: ?[*]const u8, size: usize, directory: c_int) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            if (self.failure != null) return -1;
            const contents = native_contents(bytes, size, directory) catch |err| {
                self.failure = err;
                return -1;
            };
            self.output(name[0..name_size], contents) catch |err| {
                self.failure = err;
                return -1;
            };
            return 0;
        }
    };
    var replay: Replay = .{ .collector = &collector, .context = context };
    const replay_result = pspdb_psar_walk(input.bytes.ptr, input.bytes.len, &replay, Replay.receive);
    if (replay.failure) |err| return err;
    try native_status(replay_result);
    if (replay.events != collector.events or replay.emitted != collector.outputs.count()) return error.PsarReplayMismatch;
}
