const std = @import("std");

const extractor = @import("extractor.zig");
const sfo = @import("sfo.zig");
const umd = @import("umd_data.zig");

pub const Dependency = struct {
    path: []const u8,
    sha256: []const u8,
    size_bytes: u64,

    fn deinit(self: Dependency, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.sha256);
    }
};

pub const InlineExtraction = struct {
    sha256: []const u8,
    size_bytes: u64,
    extractor: extractor.Provenance,
    name_rule: []const u8 = "source_stem",
    entries: []Entry,
    dependencies: []Dependency = &.{},
    @"error": ?[]const u8 = null,
    owned_provenance: ?std.json.Parsed(extractor.Provenance) = null,

    pub fn jsonStringify(self: InlineExtraction, json: *std.json.Stringify) !void {
        try json.beginObject();
        try json.objectField("sha256");
        try json.write(self.sha256);
        try json.objectField("size_bytes");
        try json.write(self.size_bytes);
        try json.objectField("extractor");
        try json.write(self.extractor);
        try json.objectField("name_rule");
        try json.write(self.name_rule);
        try json.objectField("entries");
        try json.write(self.entries);
        if (self.@"error") |message| {
            try json.objectField("error");
            try json.write(message);
        }
        if (self.dependencies.len != 0) {
            try json.objectField("dependencies");
            try json.write(self.dependencies);
        }
        try json.endObject();
    }
};

pub const Entry = struct {
    path: []const u8,
    type: enum { directory, file },
    size_bytes: ?u64 = null,
    sha256: ?[64]u8 = null,
    extraction: ?*InlineExtraction = null,

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.extraction) |tree| {
            for (tree.entries) |entry| entry.deinit(allocator);
            allocator.free(tree.entries);
            allocator.free(tree.sha256);
            if (tree.@"error") |message| allocator.free(message);
            for (tree.dependencies) |dependency| dependency.deinit(allocator);
            allocator.free(tree.dependencies);
            if (tree.owned_provenance) |provenance| provenance.deinit();
            allocator.destroy(tree);
        }
    }

    pub fn jsonStringify(self: Entry, json: *std.json.Stringify) !void {
        try json.beginObject();
        try json.objectField("path");
        try json.write(self.path);
        try json.objectField("type");
        try json.write(self.type);
        if (self.type == .file) {
            try json.objectField("size_bytes");
            try json.write(self.size_bytes.?);
            try json.objectField("sha256");
            try json.write(@as([]const u8, &self.sha256.?));
        }
        if (self.extraction) |tree| {
            try json.objectField("extraction");
            try json.write(tree);
        }
        try json.endObject();
    }
};

pub const RootKind = enum { iso, pkg, nand, update };

pub const Result = struct {
    size_bytes: u64,
    kind: RootKind = .iso,
    nand_blocks: ?u32 = null,
    updater_version: ?[]const u8 = null,
    updater_target: ?sfo.UpdateTarget = null,
    content_id: []u8 = &.{},
    content_type: u32 = 0,
    package_flags: ?u32 = null,
    pkg_sfo_bytes: []u8 = &.{},
    pkg_title: []u8 = &.{},
    pbp_title: []u8 = &.{},
    pbp_sfo_bytes: []u8 = &.{},
    boot_file: ?[]const u8 = null,
    boot_category: ?[]const u8 = null,
    umd_bytes: []u8 = &.{},
    record: umd.Record = undefined,
    game_sfo_bytes: []u8 = &.{},
    video_sfo_bytes: []u8 = &.{},
    updater_sfo_bytes: []u8 = &.{},
    iso_title: []u8 = &.{},
    logical_image_path: ?[]const u8 = null,
    metadata: sfo.Metadata = .{},
    has_metadata: bool = true,
    entries: []Entry = &.{},
    @"error": ?[]const u8 = null,
    sha256: [64]u8 = undefined,
    sha1: [40]u8 = undefined,
    stored: usize = 0,
    reused: usize = 0,
    extraction_errors: usize = 0,

    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        allocator.free(self.content_id);
        allocator.free(self.pkg_sfo_bytes);
        allocator.free(self.pkg_title);
        allocator.free(self.pbp_title);
        allocator.free(self.pbp_sfo_bytes);
        allocator.free(self.umd_bytes);
        allocator.free(self.game_sfo_bytes);
        allocator.free(self.video_sfo_bytes);
        allocator.free(self.updater_sfo_bytes);
        allocator.free(self.iso_title);
        if (self.@"error") |message| allocator.free(message);
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);
    }
};
