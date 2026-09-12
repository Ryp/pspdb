const std = @import("std");
const processor = @import("processor.zig");

/// Validate the catalog identity only; an existing record skips file/store work.
pub fn contains(allocator: std.mem.Allocator, io: std.Io, root: []const u8, digest: [64]u8, size: u64) !bool {
    const path = try std.fmt.allocPrint(allocator, "{s}/iso/{s}.json", .{ root, digest });
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
    if (!std.mem.eql(u8, record.kind, "iso") or record.schema_version != 1 or
        !std.mem.eql(u8, record.sha256, &digest) or record.size_bytes != size) return error.CatalogConflict;
    // A metadata record alone must not suppress rebuilding a missing inventory.
    const tree_path = try std.fmt.allocPrint(allocator, "{s}/trees/{s}.json", .{ root, digest });
    defer allocator.free(tree_path);
    const tree_bytes = std.Io.Dir.cwd().readFileAlloc(io, tree_path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(tree_bytes);
    const tree = std.json.parseFromSlice(Identity, allocator, tree_bytes, .{ .ignore_unknown_fields = true }) catch return error.CatalogConflict;
    defer tree.deinit();
    if (!std.mem.eql(u8, tree.value.kind, "tree") or tree.value.schema_version != 1 or
        !std.mem.eql(u8, tree.value.sha256, &digest) or tree.value.size_bytes != size) return error.CatalogConflict;
    return true;
}

/// One complete inventory per exact ISO. Neither the UID nor an inventory hash
/// participates in identity. No machine-local source/store paths are published.
pub fn publish(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: processor.Result) !void {
    const fields = result.metadata;
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
        .sha256 = @as([]const u8, &result.sha256),
        .size_bytes = result.size_bytes,
        .extractor = .{ .name = "pspdb-ingest", .version = "iso-1", .options = [0][]const u8{} },
        .entries = result.entries,
    };
    // Publish the inventory before its metadata record makes it discoverable.
    try writeRecord(allocator, io, root, "trees", &result.sha256, tree);
    try writeRecord(allocator, io, root, "iso", &result.sha256, record);
}

fn writeRecord(allocator: std.mem.Allocator, io: std.Io, root: []const u8, directory: []const u8, digest: []const u8, record: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, record, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
    defer allocator.free(json);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}.json", .{ root, directory, digest });
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
    const name_rule: ?[]const u8 = if (std.mem.eql(u8, kind, "prx") or std.mem.eql(u8, kind, "sce")) "source_stem" else if (std.mem.eql(u8, kind, "gzip") or std.mem.eql(u8, kind, "kl3e") or std.mem.eql(u8, kind, "kl4e")) "strip_suffix" else null;
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
        .extractor = provenance,
        .name_rule = name_rule,
        .entries = entries,
    };
    try writeRecord(allocator, io, root, "trees", &hash, tree);
    try writeRecord(allocator, io, root, kind, &hash, .{
        .kind = kind,
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
    });
}
