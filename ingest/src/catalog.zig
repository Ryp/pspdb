const std = @import("std");
const inventory = @import("inventory.zig");

pub const revisions = @import("extractor_versions");
pub const State = @import("catalog_state.zig").State;
pub const Cache = struct { root: []const u8, state: *const State };

/// Only skip roots whose own result and reachable derived results are current.
pub fn contains(allocator: std.mem.Allocator, io: std.Io, cache: Cache, digest: [64]u8, size: u64, kind: inventory.RootKind) !bool {
    const revision = switch (kind) {
        .iso => revisions.iso,
        .pkg => revisions.pkg,
        .nand => revisions.nand,
        .update => revisions.update,
    };
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-ingest.json", .{ cache.root, @tagName(kind), revision, digest });
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
    if (!std.mem.eql(u8, record.kind, @tagName(kind)) or record.schema_version != 1 or
        !std.mem.eql(u8, record.sha256, &digest) or record.size_bytes != size) return error.CatalogConflict;
    return switch (kind) {
        .iso => cache.state.fresh_isos.map.contains(&digest),
        .pkg => cache.state.fresh_pkgs.map.contains(&digest),
        .nand => cache.state.fresh_nands.map.contains(&digest),
        .update => cache.state.fresh_updates.map.contains(&digest),
    };
}

pub fn nand_provenance() @import("extractor.zig").Provenance {
    return .{ .name = "pspdb-nand", .version = revisions.nand, .options = &.{} };
}

/// Publish one observation per exact source. No private source or key paths.
pub fn publish(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: inventory.Result) !void {
    switch (result.kind) {
        .iso => try publish_iso(allocator, io, root, result),
        .pkg => try publish_pkg(allocator, io, root, result),
        .nand => try publish_nand(allocator, io, root, result),
        .update => try publish_update(allocator, io, root, result),
    }
}

fn publish_update(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: inventory.Result) !void {
    const Metadata = struct {
        updater_version: ?[]const u8,
        updater_target: std.json.Value,
        title: ?[]const u8,
        disc_id: ?[]const u8,
    };
    const record = .{
        .kind = "update",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &result.sha256),
        .sha1 = @as([]const u8, &result.sha1),
        .size_bytes = result.size_bytes,
        .metadata = if (result.has_metadata) @as(?Metadata, .{
            .updater_version = result.updater_version,
            // Explicit null survives the catalog's omission of optional fields.
            .updater_target = if (result.updater_target) |target| .{ .string = @tagName(target) } else .null,
            .title = result.metadata.title,
            .disc_id = result.metadata.disc_id,
        }) else null,
    };
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = record.sha256,
        .size_bytes = record.size_bytes,
        .extractor = .{ .name = "pspdb-update", .version = revisions.update, .options = [0][]const u8{} },
        .entries = result.entries,
        .@"error" = result.@"error",
    };
    try write_record(allocator, io, root, "update", revisions.update, &result.sha256, "tree", tree);
    try write_record(allocator, io, root, "update", revisions.update, &result.sha256, "ingest", record);
}

fn publish_nand(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: inventory.Result) !void {
    const Geometry = struct { page_bytes: u32 = 512, spare_bytes: u32 = 16, pages_per_block: u32 = 32, blocks: u32 };
    const record = .{
        .kind = "nand",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &result.sha256),
        .sha1 = @as([]const u8, &result.sha1),
        .size_bytes = result.size_bytes,
        .metadata = if (result.nand_blocks) |blocks| @as(?Geometry, .{ .blocks = blocks }) else null,
    };
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = record.sha256,
        .size_bytes = record.size_bytes,
        .extractor = nand_provenance(),
        .entries = result.entries,
        .@"error" = result.@"error",
    };
    try write_record(allocator, io, root, "nand", revisions.nand, &result.sha256, "tree", tree);
    try write_record(allocator, io, root, "nand", revisions.nand, &result.sha256, "ingest", record);
}

fn publish_pkg(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: inventory.Result) !void {
    const fields = result.metadata;
    const Metadata = struct {
        content_id: []const u8,
        content_type: u32,
        package_flags: ?u32,
        title_id: []const u8,
        disc_id: ?[]const u8,
        disc_version: ?[]const u8,
        title: ?[]const u8,
        required_firmware: ?[]const u8,
    };
    const record = .{
        .kind = "pkg",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &result.sha256),
        .sha1 = @as([]const u8, &result.sha1),
        .size_bytes = result.size_bytes,
        .metadata = if (result.has_metadata) @as(?Metadata, .{ .content_id = result.content_id, .content_type = result.content_type, .package_flags = result.package_flags, .title_id = result.content_id[7..16], .disc_id = fields.disc_id, .disc_version = fields.disc_version, .title = fields.title, .required_firmware = fields.required_firmware }) else null,
    };
    const tree = .{ .kind = "tree", .schema_version = @as(u32, 1), .sha256 = record.sha256, .size_bytes = record.size_bytes, .extractor = .{ .name = "pspdb-ingest", .version = revisions.pkg, .options = [0][]const u8{} }, .entries = result.entries, .@"error" = result.@"error" };
    try write_record(allocator, io, root, "pkg", revisions.pkg, &result.sha256, "tree", tree);
    try write_record(allocator, io, root, "pkg", revisions.pkg, &result.sha256, "ingest", record);
}

fn publish_iso(allocator: std.mem.Allocator, io: std.Io, root: []const u8, result: inventory.Result) !void {
    const fields = result.metadata;
    const Metadata = struct {
        identifier: []const u8,
        umd_uid: []const u8,
        type_code: []const u8,
        media_code: []const u8,
        disc_id: ?[]const u8,
        disc_version: ?[]const u8,
        title: ?[]const u8,
        required_firmware: ?[]const u8,
        logical_image_path: ?[]const u8,
    };
    const record = .{
        .kind = "iso",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &result.sha256),
        .sha1 = @as([]const u8, &result.sha1),
        .size_bytes = result.size_bytes,
        .metadata = if (result.has_metadata) @as(?Metadata, .{
            .identifier = result.record.identifier,
            .umd_uid = result.record.uid,
            .type_code = result.record.type_code,
            .media_code = result.record.media_code,
            .disc_id = fields.disc_id,
            .disc_version = fields.disc_version,
            .title = fields.title,
            .required_firmware = fields.required_firmware,
            .logical_image_path = result.logical_image_path,
        }) else null,
    };
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = record.sha256,
        .size_bytes = record.size_bytes,
        .extractor = .{ .name = "pspdb-ingest", .version = revisions.iso, .options = [0][]const u8{} },
        .entries = result.entries,
        .@"error" = result.@"error",
    };
    try write_record(allocator, io, root, "iso", revisions.iso, &result.sha256, "tree", tree);
    try write_record(allocator, io, root, "iso", revisions.iso, &result.sha256, "ingest", record);
}

fn write_record(allocator: std.mem.Allocator, io: std.Io, root: []const u8, directory: []const u8, version: []const u8, digest: []const u8, suffix: []const u8, record: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, record, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
    defer allocator.free(json);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-{s}.json", .{ root, directory, version, digest, suffix });
    defer allocator.free(path);
    try std.Io.Dir.cwd().createDirPath(io, std.Io.Dir.path.dirname(path).?);
    // Lock the stable directory inode, not the result inode being replaced.
    // Every publisher takes this lock before checking or replacing an attempt.
    var lock_directory = try std.Io.Dir.cwd().openDir(io, std.Io.Dir.path.dirname(path).?, .{ .iterate = true });
    defer lock_directory.close(io);
    const lock: std.Io.File = .{ .handle = lock_directory.handle, .flags = .{ .nonblocking = false } };
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    const existing = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |bytes| {
        defer allocator.free(bytes);
        const old = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer old.deinit();
        const new = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
        defer new.deinit();
        if (equal(old.value, new.value)) return;
        if (!std.mem.eql(u8, suffix, "tree")) return error.CatalogConflict;
        for ([_][]const u8{ "kind", "schema_version", "sha256", "size_bytes" }) |field| {
            if (old.value != .object or new.value != .object or
                !equal(old.value.object.get(field) orelse return error.CatalogConflict, new.value.object.get(field) orelse return error.CatalogConflict)) return error.CatalogConflict;
        }
        const old_extractor = old.value.object.get("extractor") orelse return error.CatalogConflict;
        const new_extractor = new.value.object.get("extractor") orelse return error.CatalogConflict;
        if (old_extractor != .object or new_extractor != .object or
            !equal(old_extractor.object.get("version") orelse return error.CatalogConflict, new_extractor.object.get("version") orelse return error.CatalogConflict)) return error.CatalogConflict;
        // Never downgrade a successful tree, including a concurrent winner.
        if (!has_error(old.value)) {
            if (has_error(new.value)) return;
            return error.CatalogConflict;
        }
    }
    var output = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .replace = true });
    defer output.deinit(io);
    try output.file.writeStreamingAll(io, json);
    try output.file.writeStreamingAll(io, "\n");
    try output.file.sync(io);
    try output.replace(io);
}

fn has_error(value: std.json.Value) bool {
    if (value != .object) return false;
    if (value.object.get("error")) |message| {
        if (message == .string and message.string.len != 0) return true;
    }
    const entries = value.object.get("entries") orelse return false;
    if (entries != .array) return false;
    for (entries.array.items) |entry| {
        if (entry == .object) {
            if (entry.object.get("extraction")) |tree| {
                if (has_error(tree)) return true;
            }
        }
    }
    return false;
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
pub fn publish_extraction(allocator: std.mem.Allocator, io: std.Io, root: []const u8, hash: [64]u8, size: usize, entries: []inventory.Entry, provenance: @import("extractor.zig").Provenance, kind: []const u8, failure: ?[]const u8) !void {
    const name_rule: ?[]const u8 = if (std.mem.eql(u8, kind, "prx") or std.mem.eql(u8, kind, "sce") or std.mem.eql(u8, kind, "vmp") or std.mem.eql(u8, kind, "edat") or std.mem.eql(u8, kind, "pgd")) "source_stem" else if (std.mem.eql(u8, kind, "gzip") or std.mem.eql(u8, kind, "kl3e") or std.mem.eql(u8, kind, "kl4e")) "decoded_suffix" else null;
    const tree = .{
        .kind = "tree",
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
        .extractor = provenance,
        .name_rule = name_rule,
        .entries = entries,
        .@"error" = failure,
    };
    try write_record(allocator, io, root, kind, provenance.version.?, &hash, "tree", tree);
    try write_record(allocator, io, root, kind, provenance.version.?, &hash, "ingest", .{
        .kind = kind,
        .schema_version = @as(u32, 1),
        .sha256 = @as([]const u8, &hash),
        .size_bytes = size,
    });
}
