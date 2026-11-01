//! Pure-Zig port of `psar_native.cpp` (`pspdb_psar_walk`). The crypto cores it
//! compiles in from the pinned pspdecrypt (IPL1/IPL2/IPL3, DES table
//! decryption, stage 2/3 and kernel-key extraction, syscon keys) live in
//! Zig-PSP's `psar_crypto.zig`; this file keeps the walk, the sink and the
//! zlib/LZR glue.
//!
//! Event order, names, directory flags and return codes match the C:
//! 0 success; -1 malformed/transform; -2 allocation; -3 sink refused.
//! -4 (OpenSSL legacy provider missing) has no equivalent: DES-CBC is
//! implemented in the crypto module, so it is unreachable.
//!
//! Deliberate allocation differences: the two 1,000,000-byte stage buffers that
//! the C keeps on the stack live on the heap here (allocation failure -> -2).

const std = @import("std");
const c = @import("c_zlib");
const kirk = @import("kirk");
const decrypt = @import("zig_psp_decrypt");
const lzr = @import("../lzr.zig");
const kle = decrypt.kle;
const prx = decrypt.prx;
const crypto = decrypt.psar;

pub const Emit = *const fn (?*anyopaque, [*]const u8, usize, ?[*]const u8, usize, c_int) callconv(.c) c_int;

const data_size: usize = 3_000_000;
const out_dir = crypto.out_dir;

const Error = crypto.Error;

const Str = crypto.Str;

fn le32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn allDigits(s: []const u8) bool {
    for (s) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, s, prefix);
}

const Sink = struct {
    context: ?*anyopaque,
    emit: Emit,

    pub fn file(self: Sink, name: []const u8, bytes: []const u8) Error!void {
        if (self.emit(self.context, name.ptr, name.len, bytes.ptr, bytes.len, 0) != 0) return error.Sink;
    }

    fn directory(self: Sink, name: []const u8) Error!void {
        if (self.emit(self.context, name.ptr, name.len, null, 0, 1) != 0) return error.Sink;
    }

    /// gzip framing for `crypto.extractIplStages`.
    pub fn inflateGzip(self: Sink, input: []const u8, out: []u8, consumed: ?*u32) i32 {
        _ = self;
        return gunzip(input, out, consumed, false);
    }

    fn parents(self: Sink, name: []const u8) Error!void {
        for (name, 0..) |ch, i| {
            if (ch == '/') try self.directory(name[0..i]);
        }
    }
};

// zlib framing for PSAR records (raw=true, windowBits 15), gzip for payloads (31).
fn gunzip(input: []const u8, out: []u8, consumed: ?*u32, raw: bool) i32 {
    if (input.len < 2) return -1;
    var stream: c.z_stream = std.mem.zeroes(c.z_stream);
    if (c.inflateInit2_(&stream, @as(c_int, if (raw) 15 else 31), c.zlibVersion(), @sizeOf(c.z_stream)) != c.Z_OK) return -1;
    stream.next_in = @constCast(input.ptr);
    stream.avail_in = @intCast(input.len);
    stream.next_out = out.ptr;
    stream.avail_out = @intCast(out.len);
    const status = c.inflate(&stream, c.Z_FINISH);
    const written = stream.total_out;
    const used = stream.total_in;
    _ = c.inflateEnd(&stream);
    if (status != c.Z_STREAM_END or written > std.math.maxInt(i32)) return -1;
    if (consumed) |p| p.* = @truncate(used);
    return @intCast(written);
}

// ------------------------------------------------------------------ PSAR walk

fn compressed(p: []const u8) bool {
    return (p.len >= 2 and p[0] == 0x1f and p[1] == 0x8b) or
        (p.len >= 4 and (std.mem.eql(u8, p[0..4], "2RLZ") or std.mem.eql(u8, p[0..4], "KL4E") or std.mem.eql(u8, p[0..4], "KL3E")));
}

// `pspdb_psar_lzr`.
fn lzrMember(input: []const u8, output: []u8, consumed: *usize) i32 {
    consumed.* = 0;
    const member = lzr.decode_raw_member_into(input, output) catch return -1;
    if (member.written > std.math.maxInt(c_int)) return -1;
    consumed.* = member.consumed;
    return @intCast(member.written);
}

fn expand(input: []const u8, output: []u8, used: *usize) Error!usize {
    used.* = 0;
    if (input.len > std.math.maxInt(i32) or output.len > std.math.maxInt(i32)) return error.Psar;
    var result: i32 = -1;
    if (input.len >= 2 and input[0] == 0x1f and input[1] == 0x8b) {
        var count: u32 = 0;
        result = gunzip(input, output, &count, false);
        used.* = count;
    } else if (input.len >= 4 and std.mem.eql(u8, input[0..4], "2RLZ")) {
        result = lzrMember(input[4..], output, used);
        used.* += 4;
    } else if (input.len >= 4 and (std.mem.eql(u8, input[0..4], "KL4E") or std.mem.eql(u8, input[0..4], "KL3E"))) {
        result = kle.decompressKleBoundedMember(output, input[4..], input[2] == '4', used);
        used.* += 4;
    }
    if (result <= 0 or @as(usize, @intCast(result)) > output.len or used.* == 0 or used.* > input.len) return error.Psar;
    return @intCast(result);
}

fn decryptPrx(input: []const u8, output: []u8, size: usize) Error!usize {
    if (size < 0x150 or size > data_size) return error.Psar;
    const result = prx.decryptPrx(input, output, @intCast(size), null);
    if (result <= 0 or @as(usize, @intCast(result)) > size) return error.Psar;
    return @intCast(result);
}

const Context = struct {
    input: []const u8,
    sink: Sink,
    gpa: std.mem.Allocator,
    first: []u8,
    second: []u8,
    tables: [13][]u8 = @splat(@constCast("")),
    cursor: usize = 0,
    overhead: usize = 0,
    psar_version: u8 = 0,
    firmware: i32 = 0,
    table_mode: u8 = 0,
    plaintext: bool = false,

    fn create(gpa: std.mem.Allocator, input: []const u8, sink: Sink) Error!Context {
        const first = try gpa.alloc(u8, data_size);
        errdefer gpa.free(first);
        const second = try gpa.alloc(u8, data_size);
        @memset(first, 0);
        @memset(second, 0);
        return .{ .input = input, .sink = sink, .gpa = gpa, .first = first, .second = second };
    }

    fn deinit(self: *Context) void {
        for (self.tables) |t| self.gpa.free(t);
        self.gpa.free(self.first);
        self.gpa.free(self.second);
    }

    fn range(self: *const Context, offset: usize, length: usize) Error!void {
        if (offset > self.input.len or length > self.input.len - offset) return error.Psar;
    }

    fn block(self: *Context, offset: usize, length: usize, out: []u8) Error!i32 {
        if (length > data_size) return error.Psar;
        const aligned = if (self.plaintext) length else (length + 15) & ~@as(usize, 15);
        if (aligned > data_size) return error.Psar;
        try self.range(offset, aligned);
        if (self.plaintext) {
            @memcpy(out[0..length], self.input[offset..][0..length]);
            return @intCast(length);
        }
        if (aligned < 0x150) return -1;
        @memcpy(out[0..aligned], self.input[offset..][0..aligned]);
        if (self.psar_version != 1) {
            const k1 = [16]u8{ 0xD8, 0x69, 0xB8, 0x95, 0x33, 0x6B, 0x63, 0x34, 0x98, 0xB9, 0xFC, 0x3C, 0xB7, 0x26, 0x2B, 0xD7 };
            const k2 = [16]u8{ 0x0D, 0xA0, 0x90, 0x84, 0xAF, 0x9E, 0xB6, 0xE2, 0xD2, 0x94, 0xF2, 0xAA, 0xEF, 0x99, 0x68, 0x71 };
            var buffer: [20 + 0x130]u8 = @splat(0);
            @memcpy(buffer[20..], self.input[offset + 0x20 ..][0..0x130]);
            if (self.psar_version == 5) {
                for (0..0x130) |i| buffer[20 + i] ^= k1[i & 15];
            }
            std.mem.writeInt(u32, buffer[0..4], 5, .little);
            std.mem.writeInt(u32, buffer[12..16], 0x55, .little);
            std.mem.writeInt(u32, buffer[16..20], 0x130, .little);
            if (kirk.bufferCopyWithRange(&buffer, &buffer, 7) != 0) return -1;
            if (self.psar_version == 5) {
                for (0..0x130) |i| buffer[i] ^= k2[i & 15];
            }
            @memcpy(out[0x20..][0..0x130], buffer[0..0x130]);
        }
        return prx.decryptPrx(out[0..aligned], out[0..aligned], @intCast(aligned), null);
    }

    fn parseHeader(self: *Context) Error!void {
        const input = self.input;
        try self.range(0, 0x30);
        if (!std.mem.eql(u8, input[0..4], "PSAR")) return error.Psar;
        self.plaintext = le32(input, 0x20) == 0x2c333333;
        self.overhead = if (self.plaintext) 0 else 0x150;
        self.psar_version = input[4];
        if ((try self.block(0x10, self.overhead + 0x110, self.first)) != 0x110) return error.Psar;
        self.cursor = 0x10 + self.overhead + 0x110;
        var decoded: i32 = 0;
        if (self.plaintext) {
            decoded = try self.block(self.cursor, le32(self.first, 0x90), self.second);
            if (decoded <= 0) return error.Psar;
            try self.range(self.cursor, @intCast(decoded));
            self.cursor += @intCast(decoded);
        } else if (self.psar_version != 1) {
            decoded = try self.block(self.cursor, self.overhead + 100, self.second);
            if (decoded <= 0) decoded = try self.block(self.cursor, self.overhead + 144, self.second);
            if (decoded <= 0) decoded = try self.block(self.cursor, self.overhead + self.first[0x90] + (@as(usize, self.first[0x91]) << 8), self.second);
            if (decoded <= 0 or @as(usize, @intCast(decoded)) > data_size - 15) return error.Psar;
            const advance = self.overhead + ((@as(usize, @intCast(decoded)) + 15) & ~@as(usize, 15));
            try self.range(self.cursor, advance);
            self.cursor += advance;
        }
        const begin = self.first[0x10..][0..0x100];
        const end = std.mem.indexOfScalar(u8, begin, 0) orelse return error.Psar;
        const full = begin[0..end];
        const version = if (std.mem.lastIndexOfScalar(u8, full, ',')) |comma| full[comma + 1 ..] else "1.00";
        if (version.len != 4 or version[1] != '.' or version[0] < '0' or version[0] > '9' or
            version[2] < '0' or version[2] > '9' or version[3] < '0' or version[3] > '9') return error.Psar;
        const fw: i32 = @as(i32, version[0] - '0') * 100 + @as(i32, version[2] - '0') * 10 + (version[3] - '0');
        self.firmware = fw;
        if (fw >= 380 and fw < 400) {
            self.table_mode = 1;
        } else if (fw >= 400 and fw < 500) {
            self.table_mode = 2;
        } else if (fw >= 500 and fw < 600) {
            self.table_mode = 3;
        } else if (fw >= 610 and fw < 630 and self.psar_version == 5) {
            self.table_mode = 5;
        } else if (fw >= 600 and fw < 700) {
            self.table_mode = 4;
        }
    }

    fn next(self: *Context, name: *Str, expanded: *usize) Error!bool {
        try self.range(self.cursor, 0);
        if (self.input.len - self.cursor <= self.overhead) return false;
        if ((try self.block(self.cursor, self.overhead + 0x110, self.first)) != 0x110) return error.Psar;
        const field = self.first[4..][0..0xfc];
        const end = std.mem.indexOfScalar(u8, field, 0) orelse return error.Psar;
        if (end == 0 or end >= 128) return error.Psar;
        name.* = Str.from(&.{field[0..end]});
        if (le32(self.first, 0x100) != 0) return error.Psar;
        const chunk: usize = le32(self.first, 0x104);
        expanded.* = le32(self.first, 0x108);
        if (expanded.* > data_size) return error.Psar;
        self.cursor += self.overhead + 0x110;
        try self.range(self.cursor, chunk);
        if (expanded.* != 0) {
            const packed_size = try self.block(self.cursor, chunk, self.first);
            if (packed_size <= 10 or @as(usize, @intCast(packed_size)) > data_size or self.first[0] != 0x78 or self.first[1] != 0x9c) return error.Psar;
            const got = gunzip(self.first[0..@intCast(packed_size)], self.second[0..expanded.*], null, true);
            if (got < 0 or @as(usize, @intCast(got)) != expanded.*) return error.Psar;
        }
        self.cursor += chunk;
        return true;
    }

    fn tablePath(table: []const u8, number: []const u8, out: *Str) Error!bool {
        if (number.len < 5) return error.Psar;
        var i: usize = 0;
        while (i + 5 < table.len) : (i += 1) {
            if (!std.mem.eql(u8, table[i..][0..5], number[0..5])) continue;
            const start = i + 6;
            var end = start;
            while (end < table.len and table[end] >= 0x20) end += 1;
            if (end == table.len or end == start or end - start >= 128) return error.Psar;
            var path = Str.from(&.{table[start..end]});
            if (table[i + 5] == '|') {
                if (startsWith(path.slice(), "flash")) {
                    if (path.len < 7) return error.Psar;
                    path = Str.from(&.{ path.buf[0..6], ":/", path.buf[7..path.len] });
                } else if (startsWith(path.slice(), "ipl")) {
                    if (path.len < 4) return error.Psar;
                    path = Str.from(&.{ path.buf[0..3], ":/", path.buf[4..path.len] });
                }
            }
            if (path.len >= 128) return error.Psar;
            out.* = path;
            return true;
        }
        return false;
    }

    fn resolveName(self: *Context, name: *Str) Error!void {
        const s = name.slice();
        if (s.len == 5 and allDigits(s)) {
            const n = std.fmt.parseInt(u32, s, 10) catch unreachable;
            if (n >= 100 or (n >= 10 and self.firmware < 660)) {
                for (self.tables) |t| {
                    if (t.len != 0 and try tablePath(t, name.slice(), name)) return;
                }
                return error.Psar;
            }
        }
        const prefixes = [_][]const u8{ "com:", "01g:", "02g:" };
        for (prefixes, 0..) |p, i| {
            if (startsWith(name.slice(), p) and self.tables[i].len != 0) {
                if (!try tablePath(self.tables[i], name.slice()[4..], name)) return error.Psar;
                return;
            }
        }
    }

    fn outputPath(self: *Context, name: []const u8, expanded: *usize) Error!Str {
        if (startsWith(name, "flash0:/")) return Str.from(&.{ "F0/", name[8..] });
        if (startsWith(name, "flash1:/")) return Str.from(&.{ "F1/", name[8..] });
        const filenames = [_]struct { []const u8, u8 }{
            .{ "com:00000", 0 }, .{ "01g:00000", 1 }, .{ "02g:00000", 2 }, .{ "00001", 1 },
            .{ "00002", 2 },     .{ "00003", 3 },     .{ "00004", 4 },     .{ "00005", 5 },
            .{ "00006", 6 },     .{ "00007", 7 },     .{ "00008", 8 },     .{ "00009", 9 },
            .{ "00011", 11 },    .{ "00012", 12 },
        };
        for (filenames) |entry| {
            if (!startsWith(name, entry[0])) continue;
            const length = crypto.decryptTable(self.first, self.second, expanded.*, self.psar_version, self.table_mode);
            if (length <= 0 or @as(usize, @intCast(length)) > expanded.*) return error.Psar;
            expanded.* = @intCast(length);
            const copy = try self.gpa.dupe(u8, self.second[0..expanded.*]);
            self.gpa.free(self.tables[entry[1]]);
            self.tables[entry[1]] = copy;
            var model: [5]u8 = undefined;
            _ = std.fmt.bufPrint(&model, "{d:0>5}", .{entry[1]}) catch unreachable;
            return Str.from(&.{ out_dir, "/", if (entry[1] != 0) @as([]const u8, &model) else @as([]const u8, "common"), "_files_table.bin" });
        }
        const slash = std.mem.lastIndexOfScalar(u8, name, '/') orelse return error.Psar;
        if (slash + 1 == name.len) return error.Psar;
        return Str.from(&.{ out_dir, "/", name[slash + 1 ..] });
    }

    fn reboot(self: *Context, name: []const u8, bytes: []const u8) Error!void {
        var path: Str = undefined;
        if (std.mem.eql(u8, name, "flash0:/kd/loadexec.prx")) {
            path = Str.from(&.{out_dir ++ "/reboot.bin"});
        } else if (startsWith(name, "flash0:/kd/loadexec_")) {
            if (name.len != "flash0:/kd/loadexec_00g.prx".len) return error.Psar;
            path = Str.from(&.{ out_dir ++ "/reboot_", name["flash0:/kd/loadexec_".len..][0..2], "g.bin" });
        } else return;
        var i: usize = 0;
        while (i + 0x30 < bytes.len) : (i += 1) {
            if (!std.mem.eql(u8, bytes[i..][0..4], "~PSP")) continue;
            const embedded: usize = le32(bytes, i + 0x2c);
            if (embedded > bytes.len - i or embedded > data_size) return error.Psar;
            const decrypted = try self.gpa.alloc(u8, data_size);
            defer self.gpa.free(decrypted);
            const output = try self.gpa.alloc(u8, data_size);
            defer self.gpa.free(output);
            const n = try decryptPrx(bytes[i..], decrypted, embedded);
            var consumed: usize = 0;
            const actual = try expand(decrypted[0..n], output, &consumed);
            try self.sink.file(path.slice(), output[0..actual]);
            return;
        }
        return error.Psar;
    }

    fn run(self: *Context) Error!void {
        try self.parseHeader();
        try self.sink.directory("F0");
        try self.sink.directory("F1");
        try self.sink.directory(out_dir);
        var name: Str = .{};
        var expanded: usize = 0;
        while (try self.next(&name, &expanded)) {
            try self.resolveName(&name);
            var path = try self.outputPath(name.slice(), &expanded);
            const nm = name.slice();
            const flash = startsWith(nm, "flash0:/") or startsWith(nm, "flash1:/");
            if (flash and expanded == 0) {
                while (path.len > 0 and path.buf[path.len - 1] == '/') path.len -= 1;
            }
            if (flash) {
                try self.sink.parents(path.slice());
                if (expanded == 0) try self.sink.directory(path.slice());
            }
            if (expanded == 0) continue;
            const ipl = startsWith(nm, "ipl:");
            const first = self.first;
            const second = self.second;
            var is_prx = expanded >= 4 and std.mem.eql(u8, second[0..4], "~PSP");
            if (ipl and !is_prx) {
                if (expanded < 0x64) return error.Psar;
                const mode = le32(second, 0x60);
                if (mode != 1 and mode != 0x10001) {
                    expanded = try decryptPrx(second, first, expanded);
                    @memcpy(second[0..expanded], first[0..expanded]);
                }
                is_prx = expanded >= 4 and std.mem.eql(u8, second[0..4], "~PSP");
            }
            if (is_prx or startsWith(nm, "flash0:/kd/resource/me")) {
                const decrypted = try decryptPrx(second, first, expanded);
                var final_bytes: []const u8 = first[0..decrypted];
                var used: usize = decrypted;
                if (compressed(first[0..decrypted])) {
                    const n = try expand(first[0..decrypted], second, &used);
                    final_bytes = second[0..n];
                }
                try self.sink.file(path.slice(), final_bytes);
                try self.reboot(nm, final_bytes);
                if (used < decrypted) {
                    var used_second: usize = 0;
                    const length = try expand(first[used..decrypted], second, &used_second);
                    if (used_second != decrypted - used) return error.Psar;
                    const second_path = Str.from(&.{ path.slice(), ".2" });
                    try self.sink.file(second_path.slice(), second[0..length]);
                }
            } else {
                try self.sink.file(path.slice(), second[0..expanded]);
                try self.reboot(nm, second[0..expanded]);
                if (ipl) {
                    const blocks = crypto.decryptIpl1(second, first, expanded);
                    if (blocks <= 0 or @as(usize, @intCast(blocks)) != expanded) return error.Psar;
                    var address: u32 = 0;
                    const linear = crypto.linearizeIpl2(first, second, blocks, &address);
                    if (linear <= 0) return error.Psar;
                    const base = if (std.mem.lastIndexOfScalar(u8, nm, '/')) |s| nm[s + 1 ..] else nm;
                    const stage1 = Str.from(&.{ out_dir, "/stage1_", base });
                    try self.sink.file(stage1.slice(), second[0..@intCast(linear)]);
                    try crypto.extractIplStages(self.sink, self.gpa, second[0..@intCast(linear)], self.firmware, address, base);
                }
            }
        }
    }
};

/// `pspdb_psar_walk(input.ptr, input.len, context, emit)`.
pub fn walk(input: []const u8, context: ?*anyopaque, emit: Emit) i32 {
    if (input.len < 0x30 or !std.mem.eql(u8, input[0..4], "PSAR")) return -1;
    var ctx = Context.create(std.heap.page_allocator, input, .{ .context = context, .emit = emit }) catch return -2;
    defer ctx.deinit();
    ctx.run() catch |err| return switch (err) {
        error.OutOfMemory => -2,
        error.Sink => -3,
        error.Psar => -1,
    };
    return 0;
}
