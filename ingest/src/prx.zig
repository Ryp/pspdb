const std = @import("std");
const decoded_output = @import("decoded.zig");

const gzip_decoder = @import("gzip.zig");
const kle = @import("kle.zig");
const lzr_decoder = @import("lzr.zig");

const prx_encrypt = @import("zig_psp_prx_encrypt");
const kirk = @import("kirk");

extern fn pspdb_prx_decode(input: [*]const u8, input_len: usize, output: [*]u8, output_len: usize) c_int;

const max_decoded_size = 64 << 20;

const Decrypted = struct {
    bytes: []u8,
    elf_size: ?usize,
};

/// Decrypt a ~PSP module or PSPsysGP resource. The caller owns the exact
/// KIRK-declared payload; input may be unaligned and is never changed.
fn decrypt_plain(allocator: std.mem.Allocator, bytes: []const u8) !Decrypted {
    if (bytes.len < 0x150) return error.InvalidPrx;
    const module = std.mem.startsWith(u8, bytes, "~PSP");
    if (!module and !std.mem.startsWith(u8, bytes, "PSPsysGP")) return error.InvalidPrx;
    if (bytes.len > std.math.maxInt(c_int)) return error.InvalidPrxSize;
    const expected = std.mem.readInt(u32, bytes[0xb0..0xb4], .little);
    if (expected == 0 or expected > bytes.len) return error.InvalidPrxSize;
    const attributes = if (module) std.mem.readInt(u16, bytes[6..8], .little) else 0;
    const elf_size: ?usize = if (attributes & 1 != 0) @intCast(std.mem.readInt(u32, bytes[0x28..0x2c], .little)) else null;

    // Upstream reconstructs KIRK headers in this buffer before decrypting over
    // them. Keep its full workspace until it finishes; never shrink an intermediate.
    const output = try allocator.alloc(u8, bytes.len);
    errdefer allocator.free(output);
    const result = pspdb_prx_decode(bytes.ptr, bytes.len, output.ptr, output.len);
    switch (result) {
        -1 => return error.InvalidPrx,
        -2 => return error.InvalidPrxSize,
        -3 => return error.PrxDecryptionFailed,
        -4 => return error.PrxSizeMismatch,
        -5 => return error.PrxIntegrityFailed,
        else => if (result <= 0 or result != expected) return error.PrxSizeMismatch,
    }
    return .{ .bytes = try allocator.realloc(output, expected), .elf_size = elf_size };
}

const check_keys0 = [16]u8{ 0x71, 0xf6, 0xa8, 0x31, 0x1e, 0xe0, 0xff, 0x1e, 0x50, 0xba, 0x6c, 0xd2, 0x98, 0x2d, 0xd6, 0x2d };
const check_keys1 = [16]u8{ 0xaa, 0x85, 0x4d, 0xb0, 0xff, 0xca, 0x47, 0xeb, 0x38, 0x7f, 0xd7, 0xe4, 0x3d, 0x62, 0xb0, 0x10 };

fn decrypt(allocator: std.mem.Allocator, bytes: []const u8, console_key: ?*const kirk.Cmd8Key) !Decrypted {
    // Nonzero signcheck bytes are only a heuristic: ordinary signed PRX types
    // can use this region too. Never transform an envelope that already decodes.
    return decrypt_plain(allocator, bytes) catch |err| switch (err) {
        error.InvalidPrxSize, error.PrxDecryptionFailed, error.PrxSizeMismatch => blk: {
            if (bytes.len > std.math.maxInt(c_int) or !std.mem.startsWith(u8, bytes, "~PSP") or std.mem.allEqual(u8, bytes[0xd4..0x12c], 0)) return err;
            const key = console_key orelse return error.MissingNandFuseId;
            var command: [0x14 + 0xd0]u8 = @splat(0);
            std.mem.writeInt(u32, command[0..4], 5, .little);
            std.mem.writeInt(u32, command[0x0c..0x10], 0x100, .little);
            std.mem.writeInt(u32, command[0x10..0x14], 0xd0, .little);
            for (bytes[0x80..0x150], command[0x14..], 0..) |byte, *target, i| target.* = byte ^ check_keys1[i % 16];
            _ = try kirk.cmd8(key, &command, command[0x14..]);
            const plain = command[0x14..];
            for (plain, 0..) |*byte, i| byte.* ^= check_keys0[i % 16];
            // The native decoder requires separate contiguous input/workspace.
            // Keep the borrowed source and its CAS identity untouched.
            const normalized = try allocator.dupe(u8, bytes);
            defer allocator.free(normalized);
            @memcpy(normalized[0x80..0x110], plain[0x40..0xd0]);
            @memcpy(normalized[0x110..0x150], plain[0..0x40]);
            // CMD8 is not authenticated. Recheck sizes and run the ordinary
            // PRX integrity checks; never publish the normalized header alone.
            break :blk try decrypt_plain(allocator, normalized);
        },
        else => return err,
    };
}

fn expand(allocator: std.mem.Allocator, payload: Decrypted) ![]u8 {
    errdefer allocator.free(payload.bytes);
    if (try expand_payload(allocator, payload.bytes, payload.elf_size)) |expanded| {
        allocator.free(payload.bytes);
        return expanded;
    }
    // Uncompressed envelopes may include data beyond elf_size (e.g. update PRXs).
    // Preserve the complete KIRK-declared payload rather than truncating it.
    return payload.bytes;
}

/// Byte-only decoder used by tests and nested codec handling.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, console_key: ?*const kirk.Cmd8Key) ![]u8 {
    return expand(allocator, try decrypt(allocator, bytes, console_key));
}

fn preserveEncodedElf(allocator: std.mem.Allocator, payload: Decrypted) !?decoded_output.Output {
    const size = payload.elf_size orelse return null;
    const format: decoded_output.Format = if (std.mem.startsWith(u8, payload.bytes, "\x1f\x8b\x08"))
        .gzip
    else if (std.mem.startsWith(u8, payload.bytes, "KL3E"))
        .kl3e
    else if (std.mem.startsWith(u8, payload.bytes, "KL4E"))
        .kl4e
    else
        return null;
    if (size == 0 or size > max_decoded_size) return error.InvalidPrxSize;
    const probe = try allocator.alloc(u8, size);
    defer allocator.free(probe);
    const consumed = switch (format) {
        .gzip => blk: {
            const member = gzip_decoder.decode_member_info(payload.bytes, probe) catch |err| return switch (err) {
                error.GzipOutputTooSmall => error.PrxSizeMismatch,
                else => err,
            };
            if (member.written != size) return error.PrxSizeMismatch;
            break :blk member.consumed;
        },
        .kl3e, .kl4e => blk: {
            const written = kle.decodeInto(payload.bytes, probe) catch |err| return switch (err) {
                error.KleOutputTooSmall => error.PrxSizeMismatch,
                else => err,
            };
            if (written != size) return error.PrxSizeMismatch;
            break :blk payload.bytes.len;
        },
        else => unreachable,
    };
    if (!decoded_output.isPspElf(probe)) return error.UnexpectedPrxPayload;
    return .{
        .bytes = try allocator.realloc(payload.bytes, consumed),
        .format = format,
        .content_format = .elf,
    };
}

/// Preserve encoded ELF payloads so recursive codec extraction owns expansion.
pub fn extract(allocator: std.mem.Allocator, bytes: []const u8, console_key: ?*const kirk.Cmd8Key) !decoded_output.Output {
    const payload = try decrypt(allocator, bytes, console_key);
    if (preserveEncodedElf(allocator, payload) catch |err| {
        allocator.free(payload.bytes);
        return err;
    }) |output| return output;
    const output = try expand(allocator, payload);
    return .{ .bytes = output, .format = decoded_output.identify(output) };
}

fn expand_payload(allocator: std.mem.Allocator, payload: []const u8, declared_size: ?usize) !?[]u8 {
    const gzip = std.mem.startsWith(u8, payload, "\x1f\x8b");
    const kl = std.mem.startsWith(u8, payload, "KL3E") or std.mem.startsWith(u8, payload, "KL4E");
    const lzr = std.mem.startsWith(u8, payload, "2RLZ");
    if (!gzip and !kl and !lzr) return null;
    if (declared_size) |size| {
        if (size == 0 or size > max_decoded_size) return error.InvalidPrxSize;
        const output = try allocator.alloc(u8, size);
        errdefer allocator.free(output);
        const actual = (if (gzip)
            gzip_decoder.decode_member_into(payload, output)
        else if (kl)
            kle.decodeInto(payload, output)
        else
            lzr_decoder.decode_into(payload, output)) catch |err| return switch (err) {
            error.GzipOutputTooSmall, error.KleOutputTooSmall, error.LzrOutputTooSmall => error.PrxSizeMismatch,
            else => err,
        };
        if (actual != size) return error.PrxSizeMismatch;
        return output;
    }
    // Firmware resources can use an uncompressed ~PSP envelope around a
    // KL/LZR/gzip stream: elf_size then describes that stream, not its expanded
    // bytes. Firmware callers supply capacity (e.g. loadexec's 2 MiB reboot
    // buffer), not exact size. Keep the same bounded policy for every codec.
    return if (gzip)
        try gzip_decoder.decode_member_bounded(allocator, payload, max_decoded_size)
    else if (kl)
        try kle.decode(allocator, payload)
    else
        try lzr_decoder.decode(allocator, payload);
}

test "contextual KL enforces declared output only when the envelope declares compression" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "KL3E", "KL4E" }) |magic| {
        var payload = "KL3E\x80\x00\x00\x00\x03abc".*;
        @memcpy(payload[0..4], magic);
        const original = payload;
        var storage: [3]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&storage);
        const exact = (try expand_payload(fixed.allocator(), &payload, 3)).?;
        defer fixed.allocator().free(exact);
        try std.testing.expectEqualStrings("abc", exact);
        try std.testing.expectEqualSlices(u8, &original, &payload);
        try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, &payload, 2));
        try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, &payload, 4));
        try std.testing.expectError(error.InvalidKle, expand_payload(allocator, payload[0 .. payload.len - 1], 3));
        const resource = (try expand_payload(allocator, &payload, null)).?;
        defer allocator.free(resource);
        try std.testing.expectEqualStrings("abc", resource);
    }
    const coded = "KL4E\x07\x90\xcc\xe4\x56\xe6\x8a\x53\x77\x3b\x32\x9d\x00\x00\x00";
    const expanded = (try expand_payload(allocator, coded, 8)).?;
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("offsets!", expanded);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 7));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 9));
}

test "contextual LZR expands resource streams and enforces compressed envelope size" {
    const allocator = std.testing.allocator;
    const direct = "2RLZ\xff\x00\x00\x00\x03abc\xa5";
    var storage: [3]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    const exact = (try expand_payload(fixed.allocator(), direct, 3)).?;
    defer fixed.allocator().free(exact);
    try std.testing.expectEqualStrings("abc", exact);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, direct, 2));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, direct, 4));
    try std.testing.expectError(error.InvalidLzr, expand_payload(allocator, direct[0 .. direct.len - 1], 3));

    const coded = "2RLZ\x08\xc8\x63\x3d\xbe\x16\x38\x4a\xd2\x32\xf6\x60\x00\x00\x00";
    const resource = (try expand_payload(allocator, coded, null)).?;
    defer allocator.free(resource);
    try std.testing.expectEqualStrings("offsets!", resource);
    const expanded = (try expand_payload(allocator, coded, 8)).?;
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("offsets!", expanded);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 7));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, coded, 9));
    try std.testing.expectError(error.InvalidLzr, expand_payload(allocator, coded[0 .. coded.len - 1], 8));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, coded, max_decoded_size + 1));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, coded, 0));
}

test "contextual gzip checks declared length after a complete member" {
    const member = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x01\x03\x00\xfc\xffabc\xc2\x41\x24\x35\x03\x00\x00\x00";
    const allocator = std.testing.allocator;
    const output = (try expand_payload(allocator, member ++ "\x00envelope tail", 3)).?;
    defer allocator.free(output);
    try std.testing.expectEqualStrings("abc", output);
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, member, 2));
    try std.testing.expectError(error.PrxSizeMismatch, expand_payload(allocator, member, 4));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, member, max_decoded_size + 1));
    try std.testing.expectError(error.InvalidPrxSize, expand_payload(allocator, member, 0));
}

fn signed_fixture(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var input: std.Io.Reader = .fixed(payload);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try prx_encrypt.encrypt(allocator, &input, payload.len, &output.writer);
    return output.toOwnedSlice();
}

test "PRX extraction exposes a gzip-encoded ELF for recursive decoding" {
    const allocator = std.testing.allocator;
    var payload: [52]u8 = @splat(0);
    @memcpy(payload[0..7], "\x7fELF\x01\x01\x01");
    std.mem.writeInt(u16, payload[16..18], 0xffa0, .little);
    std.mem.writeInt(u16, payload[18..20], 8, .little);
    std.mem.writeInt(u32, payload[20..24], 1, .little);
    std.mem.writeInt(u16, payload[40..42], 52, .little);
    const fixture = try signed_fixture(allocator, &payload);
    defer allocator.free(fixture);
    const output = try extract(allocator, fixture, null);
    defer allocator.free(output.bytes);
    try std.testing.expectEqual(decoded_output.Format.gzip, output.format);
    try std.testing.expectEqual(decoded_output.Format.elf, output.content_format.?);
    try std.testing.expect(std.mem.startsWith(u8, output.bytes, "\x1f\x8b\x08"));
    const expanded = try gzip_decoder.decode(allocator, output.bytes);
    defer allocator.free(expanded);
    try std.testing.expectEqualSlices(u8, &payload, expanded[0..payload.len]);
}

test "PRX extraction preserves KL-encoded ELF for recursive decoding" {
    const allocator = std.testing.allocator;
    var elf: [52]u8 = @splat(0);
    @memcpy(elf[0..7], "\x7fELF\x01\x01\x01");
    std.mem.writeInt(u16, elf[16..18], 0xffa0, .little);
    std.mem.writeInt(u16, elf[18..20], 8, .little);
    std.mem.writeInt(u32, elf[20..24], 1, .little);
    std.mem.writeInt(u16, elf[40..42], 52, .little);
    var encoded: [4 + 5 + elf.len]u8 = undefined;
    @memcpy(encoded[0..4], "KL3E");
    encoded[4] = 0x80;
    std.mem.writeInt(u32, encoded[5..9], elf.len, .big);
    @memcpy(encoded[9..], &elf);
    const owned = try allocator.dupe(u8, &encoded);
    const output = (try preserveEncodedElf(allocator, .{ .bytes = owned, .elf_size = elf.len })).?;
    defer allocator.free(output.bytes);
    try std.testing.expectEqual(decoded_output.Format.kl3e, output.format);
    try std.testing.expectEqual(decoded_output.Format.elf, output.content_format.?);
    try std.testing.expectEqualSlices(u8, &encoded, output.bytes);
}

test "PRX rejects truncated headers and impossible declared sizes" {
    var bytes: [0x150]u8 = @splat(0);
    @memcpy(bytes[0..4], "~PSP");
    try std.testing.expectError(error.InvalidPrx, decode(std.testing.allocator, bytes[0..0x14f], null));
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes, null));
    std.mem.writeInt(u32, bytes[0xb0..0xb4], bytes.len + 1, .little);
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes, null));
    std.mem.writeInt(u32, bytes[0xb0..0xb4], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidPrxSize, decode(std.testing.allocator, &bytes, null));
}

test "PRX preserves unaligned input and rejects truncation or modified headers" {
    const allocator = std.testing.allocator;
    const payload = "\x7fELF native PRX immutable input";
    const fixture = try signed_fixture(allocator, payload);
    defer allocator.free(fixture);
    const storage = try allocator.alloc(u8, fixture.len + 1);
    defer allocator.free(storage);
    const unaligned = storage[1..];
    @memcpy(unaligned, fixture);
    const output = try decode(allocator, unaligned, null);
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, fixture, unaligned);
    try std.testing.expectEqual(std.mem.readInt(u32, fixture[0x28..0x2c], .little), output.len);
    // The signer pads the ELF before compression and forges a CMAC block after
    // the member. PRX consumes one complete member, not those envelope bytes.
    try std.testing.expectEqualSlices(u8, payload, output[0..payload.len]);
    try std.testing.expect(std.mem.allEqual(u8, output[payload.len..], 0));

    // Missing CBC padding previously let libkirk read a block beyond the file.
    try std.testing.expectError(error.PrxIntegrityFailed, decode(allocator, unaligned[0 .. unaligned.len - 1], null));
    unaligned[0x0a] ^= 1;
    try std.testing.expectError(error.PrxDecryptionFailed, decode(allocator, unaligned, null));
}

test "matched PRX integrity failures remain terminal with or without console context" {
    const allocator = std.testing.allocator;
    const fixture = try signed_fixture(allocator, "\x7fELF authenticated ciphertext");
    defer allocator.free(fixture);
    fixture[0x150] ^= 1;
    const original = try allocator.dupe(u8, fixture);
    defer allocator.free(original);
    var key = kirk.Cmd8Key.init(0x0000123456789abc);
    defer key.deinit();
    for ([_]?*const kirk.Cmd8Key{ null, &key }) |context| {
        try std.testing.expectError(error.PrxIntegrityFailed, decode(allocator, fixture, context));
        try std.testing.expectError(error.PrxIntegrityFailed, extract(allocator, fixture, context));
        try std.testing.expectEqualSlices(u8, original, fixture);
    }
}

// Sony updater PSAR members F0/vsh/etc/index_05g.dat (Go) and index_01g.dat
// (standard PSP). Expected text is the independent, same-PSAR version.txt.
// Each encrypted fixture is the complete 496-byte resource, not an executable.
const resource_fixtures = [_]struct { encrypted: []const u8, plaintext: []const u8 }{
    .{
        // 610go.PBP SHA-256: b378aef0bc8576f471c1e161766b1c021ab26d4547ef3358f4214d04885f3d73
        // Member SHA-256: c16e94dca11cf5bf3312ad939b52fdba50401c0a38ccf7ac9eee667ea52548a8
        // Tag 0B2B29F0: type 2, including the former type-6 fallback vulnerability.
        .encrypted = @embedFile("fixtures/prx/6.10-index_05g.dat"),
        .plaintext = "release:6.10:\n" ++
            "build:3745,0,3,1,0:builder@vsh-build6\n" ++
            "system:54865@release_610,0x06010010:\n" ++
            "vsh:p6501@release_610,v55286@release_610,20090918:\n" ++
            "target:1:WorldWide\n",
    },
    .{
        // 630go.PBP SHA-256: 7b3d4c5d3c77886d08878e3040959353d69912120177ba767a06f8063db748fe
        // Member SHA-256: 50033620dd30e9f4f64fd977931e5bfcb4e48cf9a5e77009d6fe511e2cb52d9a
        // Tag 0B2B83F0: type 6, with genuine Sony ECDSA signatures.
        .encrypted = @embedFile("fixtures/prx/6.30-index_05g.dat"),
        .plaintext = "release:6.30:\n" ++
            "build:4530,0,3,1,0:builder@vsh-build6\n" ++
            "system:56422@release_630,0x06030010:\n" ++
            "vsh:p6576@release_630,v57929@release_630,20100625:\n" ++
            "target:1:WorldWide\n",
    },
    .{
        // 661go.PBP SHA-256: 0c35c813afb1e56648ac3ff43cdb86aaebc05a05d9502bc2d35b1e409fcdbaba
        // Member SHA-256: 288b8e54366f5c67f64c5d9f1e9ac03f82b9224c1a5105a6a1629d4843f1741b
        // Tag 0B2B93F0: the third Go seed, type 2.
        .encrypted = @embedFile("fixtures/prx/6.61-index_05g.dat"),
        .plaintext = resource_661_plaintext,
    },
    .{
        // Standard 661.PBP SHA-256: dc23a6dabdaed40bbfaad811d1f170346b911ba9750478fe5928d9f10c94f552
        // Member SHA-256: b9cb1d601341f474fe0bed2d06ab834a670ac5e71a5e432b317f157d67c40711
        // Tag 0B2B90F0: retain the existing standard-resource type-2 mapping.
        .encrypted = @embedFile("fixtures/prx/6.61-index_01g.dat"),
        .plaintext = resource_661_plaintext,
    },
};

const resource_661_plaintext = "release:6.61:\n" ++
    "build:5553,0,3,1,0:builder@vsh-build6\n" ++
    "system:58401@release_661,0x06060110:\n" ++
    "vsh:p6621@release_661,v58692@release_661,20141113:\n" ++
    "target:1:WorldWide\n";

fn expect_resource_plaintext(encrypted: []const u8, plaintext: []const u8) !void {
    const allocator = std.testing.allocator;
    var storage: [497]u8 align(16) = undefined;
    const input = storage[1..];
    @memcpy(input, encrypted);
    const output = try decode(allocator, input, null);
    defer allocator.free(output);
    try std.testing.expectEqualStrings(plaintext, output);
    try std.testing.expectEqualSlices(u8, encrypted, input);

    const extracted = try extract(allocator, input, null);
    defer allocator.free(extracted.bytes);
    try std.testing.expectEqualStrings(plaintext, extracted.bytes);
    try std.testing.expectEqual(decoded_output.Format.unknown, extracted.format);
    try std.testing.expect(extracted.content_format != .elf);
    try std.testing.expectEqualSlices(u8, encrypted, input);
}

fn expect_resource_rejected(encrypted: []const u8) !void {
    var input: [496]u8 = undefined;
    @memcpy(&input, encrypted);
    if (decode(std.testing.allocator, &input, null)) |unexpected| {
        std.testing.allocator.free(unexpected);
        return error.AcceptedCorruptPrx;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, encrypted, &input);
    if (extract(std.testing.allocator, &input, null)) |unexpected| {
        std.testing.allocator.free(unexpected.bytes);
        return error.AcceptedCorruptPrx;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, encrypted, &input);
}

test "PSPsysGP Go and standard resources expose exact immutable version metadata" {
    for (resource_fixtures) |fixture| {
        try expect_resource_plaintext(fixture.encrypted, fixture.plaintext);
    }
}

test "PSPsysGP header and ciphertext integrity failures cannot fall back to another recipe" {
    for (resource_fixtures) |fixture| {
        // Independent controls: PRX header authentication, then payload authentication.
        // 6.10 byte 352 formerly passed type 6 after the correct type-2 CMAC failed.
        for ([_]usize{ 0x140, 352 }) |offset| {
            var corrupted: [496]u8 = undefined;
            @memcpy(&corrupted, fixture.encrypted);
            corrupted[offset] ^= 1;
            try expect_resource_rejected(&corrupted);
        }
    }
}

test "PSPsysGP type 6 requires a valid ECDSA signature beyond the outer header hash" {
    const fixture = resource_fixtures[1];
    try expect_resource_plaintext(fixture.encrypted, fixture.plaintext);
    var corrupted: [496]u8 = undefined;
    @memcpy(&corrupted, fixture.encrypted);
    corrupted[0x120] ^= 1;
    try expect_resource_rejected(&corrupted);

    // Derived from the genuine 6.30 member above: flip byte 0x120 (KIRK data
    // signature S +8), recompute the PRX type-6 SHA-1, and AES-CBC rewrap its
    // outer 0x60-byte header with KIRK slot 5C. Ciphertext and signed message
    // are unchanged. Unlike the raw flip, this reaches ECDSA verification.
    // Derived SHA-256: 99a749a8be4b176d7047991ded01f1cec529c4883b1b6548649cbdb09b7de031
    try expect_resource_rejected(@embedFile("fixtures/prx/6.30-index_05g-bad-signature.dat"));
    // A failed signature must not poison the native verifier's next valid job.
    try expect_resource_plaintext(fixture.encrypted, fixture.plaintext);
}

// Test-only CMD5 counterpart with independently derived, synthetic AES keys.
// Production owns only CMD8; no real console material belongs in fixtures.
fn signcheck_fixture(bytes: []u8, synthetic_key_hex: []const u8) !void {
    var aes_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&aes_key, synthetic_key_hex);
    const aes = std.crypto.core.aes.Aes128.initEnc(aes_key);
    var header: [0xd0]u8 = undefined;
    @memcpy(header[0..0x40], bytes[0x110..0x150]);
    @memcpy(header[0x40..], bytes[0x80..0x110]);
    for (&header, 0..) |*byte, i| byte.* ^= check_keys0[i % 16];
    var iv: [16]u8 = @splat(0);
    var offset: usize = 0;
    while (offset < header.len) : (offset += 16) {
        for (&iv, header[offset..][0..16]) |*byte, source| byte.* ^= source;
        aes.encrypt(&iv, &iv);
        for (iv, bytes[0x80 + offset ..][0..16], 0..) |byte, *target, i| target.* = byte ^ check_keys1[i];
    }
}

test "signchecked PRX needs context, preserves source and rejects the wrong console" {
    const allocator = std.testing.allocator;
    const fixture = try signed_fixture(allocator, "\x7fELF console-bound immutable input");
    defer allocator.free(fixture);
    const expected = try decode(allocator, fixture, null);
    defer allocator.free(expected);
    var key = kirk.Cmd8Key.init(0x0000123456789abc);
    defer key.deinit();
    // Supplying console context must not transform an ordinary signed module.
    const ordinary = try decode(allocator, fixture, &key);
    defer allocator.free(ordinary);
    try std.testing.expectEqualSlices(u8, expected, ordinary);
    try signcheck_fixture(fixture, "17023593ab51acb2490a119e31e9424f");
    const original = try allocator.dupe(u8, fixture);
    defer allocator.free(original);
    try std.testing.expectError(error.MissingNandFuseId, decode(allocator, fixture, null));
    var wrong = kirk.Cmd8Key.init(0x0000123456789abd);
    defer wrong.deinit();
    if (decode(allocator, fixture, &wrong)) |unexpected| {
        allocator.free(unexpected);
        return error.AcceptedWrongConsole;
    } else |err| switch (err) {
        error.InvalidPrxSize, error.PrxDecryptionFailed, error.PrxSizeMismatch => {},
        else => return err,
    }
    const output = try decode(allocator, fixture, &key);
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, expected, output);
    try std.testing.expectEqualSlices(u8, original, fixture);
}

test "concurrent PRX jobs retain independent KIRK state and owned results" {
    const allocator = std.testing.allocator;
    const first = try signed_fixture(allocator, "\x7fELF first concurrent PRX");
    defer allocator.free(first);
    const second = try signed_fixture(allocator, "\x7fELF second concurrent PRX");
    defer allocator.free(second);
    const first_plain = try decode(allocator, first, null);
    defer allocator.free(first_plain);
    const second_plain = try decode(allocator, second, null);
    defer allocator.free(second_plain);
    var first_key = kirk.Cmd8Key.init(0x0000123456789abc);
    defer first_key.deinit();
    var second_key = kirk.Cmd8Key.init(0x0000123456789abd);
    defer second_key.deinit();
    try signcheck_fixture(first, "17023593ab51acb2490a119e31e9424f");
    try signcheck_fixture(second, "27940573ab6a6c91d14a717fdb04e1b3");

    const Worker = struct {
        start: *std.atomic.Value(bool),
        input: []const u8,
        expected: []const u8,
        key: *const kirk.Cmd8Key,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
            self.check() catch |err| {
                self.failure = err;
            };
        }

        fn check(self: *@This()) !void {
            for (0..4) |_| {
                const decoded = try decode(std.heap.page_allocator, self.input, self.key);
                defer std.heap.page_allocator.free(decoded);
                if (!std.mem.eql(u8, self.expected, decoded)) return error.ConcurrentPrxMismatch;
            }
        }
    };
    var start: std.atomic.Value(bool) = .init(false);
    var workers: [4]Worker = undefined;
    {
        var threads: [workers.len]std.Thread = undefined;
        var spawned: usize = 0;
        defer {
            start.store(true, .release);
            for (threads[0..spawned]) |thread| thread.join();
        }
        for (&workers, 0..) |*worker, index| {
            worker.* = .{
                .start = &start,
                .input = if (index % 2 == 0) first else second,
                .expected = if (index % 2 == 0) first_plain else second_plain,
                .key = if (index % 2 == 0) &first_key else &second_key,
            };
            threads[index] = try std.Thread.spawn(.{}, Worker.run, .{worker});
            spawned += 1;
        }
        start.store(true, .release);
    }
    for (workers) |worker| if (worker.failure) |err| return err;
}
