const std = @import("std");
const processor = @import("processor.zig");

pub const revisions = @import("extractor_versions");
pub const State = @import("catalog_state.zig").State;
pub const Cache = struct { root: []const u8, state: *const State };

/// Only skip roots whose own result and reachable derived results are current.
pub fn contains(allocator: std.mem.Allocator, io: std.Io, cache: Cache, digest: [64]u8, size: u64, kind: []const u8) !bool {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-ingest.json", .{ cache.root, kind, if (std.mem.eql(u8, kind, "pkg")) revisions.pkg else revisions.iso, digest });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(bytes);
    const Identity = struct { kind: []const u8, schema_version: u32, sha256: []const u8, size_bytes: u64 };
    const parsed = std.json.parseFromSlice(Identity, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.CatalogConflict;
    defer parsed.deinit();
    const record = parsed.value;
    if (!std.mem.eql(u8, record.kind, kind) or record.schema_version != 1 or
        !std.mem.eql(u8, record.sha256, &digest) or record.size_bytes != size) return error.CatalogConflict;
    return if (std.mem.eql(u8, kind, "pkg")) cache.state.fresh_pkgs.map.contains(&digest) else cache.state.fresh_isos.map.contains(&digest);
}

/// One complete inventory per exact ISO. Neither the UID nor an inventory hash
/// participates in identity. No machine-local source/store paths are published.
pub fn publish(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: processor.Result) !void {
    const fields = result.metadata;
    if (result.kind == .pkg) {
        const record = .{
            .kind = "pkg",
            .schema_version = @as(u32, 1),
            .sha256 = @as([]const u8, &result.sha256),
            .sha1 = @as([]const u8, &result.sha1),
            .size_bytes = result.size_bytes,
            .metadata = .{ .content_id = result.content_id, .content_type = result.content_type, .title_id = result.content_id[7..16], .disc_id = fields.disc_id, .disc_version = fields.disc_version, .title = fields.title, .required_firmware = fields.required_firmware },
        };
        const tree = .{ .kind = "tree", .schema_version = @as(u32, 1), .sha256 = record.sha256, .size_bytes = record.size_bytes, .extractor = .{ .name = "pspdb-ingest", .version = revisions.pkg, .options = [0][]const u8{} }, .entries = result.entries };
        try writeRecord(allocator, io, root, "pkg", revisions.pkg, &result.sha256, "tree", tree);
        try writeRecord(allocator, io, root, "pkg", revisions.pkg, &result.sha256, "ingest", record);
        return;
    }
    const record = .{
        .kind = "iso",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &result.sha256),
        .sha1 = @as([]const u8, &result.sha1),
        .size_bytes = result.size_bytes,
        .metadata = .{
            .identifier = result.record.identifier,
            .umd_uid = result.record.uid,
            .type_code = result.record.type_code,
            .media_code = result.record.media_code,
            .disc_id = fields.disc_id,
            .disc_version = fields.disc_version,
            .title = fields.title,
            .required_firmware = fields.required_firmware,
        },
    };
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = record.sha256,
        .size_bytes = record.size_bytes,
        .extractor = .{ .name = "pspdb-ingest", .version = revisions.iso, .options = [0][]const u8{} },
        .entries = result.entries,
    };
    try writeRecord(allocator, io, root, "iso", revisions.iso, &result.sha256, "tree", tree);
    try writeRecord(allocator, io, root, "iso", revisions.iso, &result.sha256, "ingest", record);
}

fn writeRecord(allocator: std.mem.Allocator, io: std.Io, root: []const u8, directory: []const u8, version: []const u8, digest: []const u8, suffix: []const u8, record: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, record, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
    defer allocator.free(json);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-{s}.json", .{ root, directory, version, digest, suffix });
    defer allocator.free(path);
    var output = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .make_path = true });
    defer output.deinit(io);
    try output.file.writeStreamingAll(io, json);
    try output.file.writeStreamingAll(io, "\n");
    try output.file.sync(io);
    output.link(io) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
            defer allocator.free(existing);
            const old = try std.json.parseFromSlice(std.json.Value, allocator, existing, .{});
            defer old.deinit();
            const new = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
            defer new.deinit();
            if (!equal(old.value, new.value)) return error.CatalogConflict;
        },
        else => return err,
    };
}

// Compare parsed values so harmless indentation/key-order changes do not turn
// a repeated import into a conflict.
fn equal(a: std.json.Value, b: std.json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |v| v == b.bool,
        .integer => |v| v == b.integer,
        .float => |v| v == b.float,
        .number_string => |v| std.mem.eql(u8, v, b.number_string),
        .string => |v| std.mem.eql(u8, v, b.string),
        .array => |v| blk: {
            if (v.items.len != b.array.items.len) break :blk false;
            for (v.items, b.array.items) |x, y| if (!equal(x, y)) break :blk false;
            break :blk true;
        },
        .object => |v| blk: {
            if (v.count() != b.object.count()) break :blk false;
            var it = v.iterator();
            while (it.next()) |entry| {
                if (!equal(entry.value_ptr.*, b.object.get(entry.key_ptr.*) orelse break :blk false)) break :blk false;
            }
            break :blk true;
        },
    };
}

/// Publish external extractor metadata and the same inventory shape as ISO.
pub fn publishExtraction(allocator: std.mem.Allocator, io: std.Io, root: []const u8, hash: [64]u8, size: usize, entries: []processor.Entry, provenance: @import("extractor.zig").Provenance, kind: []const u8) !void {
    const name_rule: ?[]const u8 = if (std.mem.eql(u8, kind, "prx") or std.mem.eql(u8, kind, "sce") or std.mem.eql(u8, kind, "vmp")) "source_stem" else if (std.mem.eql(u8, kind, "gzip")) "decoded_suffix" else if (std.mem.eql(u8, kind, "kl3e") or std.mem.eql(u8, kind, "kl4e")) "strip_suffix" else null;
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
        .extractor = provenance,
        .name_rule = name_rule,
        .entries = entries,
    };
    try writeRecord(allocator, io, root, kind, provenance.version.?, &hash, "tree", tree);
    try writeRecord(allocator, io, root, kind, provenance.version.?, &hash, "ingest", .{
        .kind = kind,
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
    });
}
