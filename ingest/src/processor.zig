const std = @import("std");

const containers = @import("containers.zig");
const decoded_output = @import("decoded.zig");
const gzip = @import("gzip.zig");
const prx = @import("prx.zig");
const pops = @import("pops.zig");
const kle = @import("kle.zig");
const npumdimg = @import("npumdimg.zig");
const edat = @import("edat.zig");
const pgd = @import("pgd.zig");
const psar = @import("psar.zig");
const rco = @import("rco.zig");
const catalog_io = @import("catalog.zig");
const pkg = @import("pkg.zig");
const data_psp = @import("data_psp.zig");
const revisions = @import("extractor_versions");
const licenses = @import("licenses.zig");
const memory = @import("bytes.zig");
const iso = @import("iso_reader.zig");
const nand = @import("zig_psp_nand");
const kirk = @import("kirk");
const nand_fuses = @import("nand_fuses.zig");
const extractor = @import("extractor.zig");
const external_extractor = @import("external_extractor.zig");
const CatalogState = @import("catalog_state.zig").State;
const StoreWriter = @import("store.zig").Writer;
const umd = @import("umd_data.zig");
const sfo = @import("sfo.zig");
const model = @import("inventory.zig");
const Entry = model.Entry;
const Result = model.Result;
const Dependency = model.Dependency;
const InlineExtraction = model.InlineExtraction;

/// Queue-owned extraction input. Native readers borrow subranges of input.
pub const Task = struct {
    name: []const u8,
    input: memory.View,
    hash: [64]u8,
    kind: extractor.Kind,

    pub fn deinit(self: Task, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.input.release();
    }
};

/// Shared by root and descendant jobs; only discovery deduplication needs this lock.
/// enqueue takes ownership of a task on success only.
pub const Dispatch = struct {
    context: *anyopaque,
    enqueue: *const fn (*anyopaque, Task) anyerror!void,
    store: ?[]const u8,
    catalog: []const u8,
    state: ?*const CatalogState = null,
    rap_directory: ?[]const u8 = null,
    // Initialized before the root queues descendants; immutable until the last
    // group job completes. Never copied into tasks or serialized as provenance.
    prx_key: ?kirk.Cmd8Key = null,
    mutex: std.Io.Mutex = .init,
    visited: std.AutoHashMap([64]u8, void),

    pub fn deinit(self: *Dispatch) void {
        if (self.prx_key) |*key| key.deinit();
        self.visited.deinit();
    }

    fn inspect(self: *Dispatch, allocator: std.mem.Allocator, io: std.Io, name: []const u8, input: memory.View, hash: [64]u8) !void {
        const kind = extractor.detect_named(name, input.bytes) orelse return;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const visited = try self.visited.getOrPut(hash);
        if (visited.found_existing) return;
        errdefer _ = self.visited.remove(hash);
        const task = Task{ .name = try allocator.dupe(u8, name), .input = input.retain(), .hash = hash, .kind = kind };
        errdefer task.deinit(allocator);
        try self.enqueue(self.context, task);
    }
};

pub const Counts = struct { stored: usize = 0, reused: usize = 0, extraction_errors: usize = 0 };

fn orchestrator(kind: extractor.Kind) extractor.Provenance {
    return .{ .name = "pspdb-ingest", .version = switch (kind) {
        inline else => |value| @field(revisions, @tagName(value)),
    } };
}

// Only memory-backed decoder/parser errors cross this boundary. I/O and queue
// callbacks mark their inventory fatal before unwinding through a parser.
fn extraction_error(inventory: *Inventory, err: anyerror) ![]const u8 {
    var failure: ?[]const u8 = null;
    try record_failure(inventory, &failure, err);
    return failure.?;
}

fn record_failure(inventory: *Inventory, failure: *?[]const u8, err: anyerror) !void {
    if (inventory.fatal or err == error.OutOfMemory or err == error.CryptoFailure) return err;
    inventory.counts.extraction_errors += 1;
    std.debug.print("Extraction error: {s}\n", .{@errorName(err)});
    if (failure.* == null) failure.* = try inventory.allocator.dupe(u8, @errorName(err));
}

const SourceHashes = struct { sha256: [64]u8, sha1: [40]u8 };

fn source_error(allocator: std.mem.Allocator, bytes: []const u8, hashes: SourceHashes, kind: @FieldType(Result, "kind"), err: anyerror) !Result {
    if (err == error.OutOfMemory or err == error.CryptoFailure) return err;
    std.debug.print("Extraction error: {s}\n", .{@errorName(err)});
    return .{ .kind = kind, .size_bytes = bytes.len, .sha256 = hashes.sha256, .sha1 = hashes.sha1, .has_metadata = false, .@"error" = try allocator.dupe(u8, @errorName(err)), .extraction_errors = 1 };
}

fn hash_source(bytes: []const u8) SourceHashes {
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    var sha1 = std.crypto.hash.Sha1.init(.{});
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = offset + @min(bytes.len - offset, 64 * 1024);
        sha256.update(bytes[offset..end]);
        sha1.update(bytes[offset..end]);
        offset = end;
    }
    return .{
        .sha256 = std.fmt.bytesToHex(sha256.finalResult(), .lower),
        .sha1 = std.fmt.bytesToHex(sha1.finalResult(), .lower),
    };
}

fn read_metadata(allocator: std.mem.Allocator, bytes: []const u8) !Result {
    if (bytes.len == 0) return error.EmptyFile;
    const umd_bytes = (try iso.read_file(allocator, bytes, "UMD_DATA.BIN")) orelse return error.MissingUmdData;
    var result: Result = .{ .size_bytes = bytes.len, .umd_bytes = umd_bytes, .record = undefined };
    errdefer result.deinit(allocator);
    result.record = try umd.parse(umd_bytes);
    result.game_sfo_bytes = (try iso.read_file(allocator, bytes, "PSP_GAME/PARAM.SFO")) orelse &.{};
    result.video_sfo_bytes = (try iso.read_file(allocator, bytes, "UMD_VIDEO/PARAM.SFO")) orelse &.{};
    const game = try sfo.parse(allocator, result.game_sfo_bytes);
    const video = try sfo.parse(allocator, result.video_sfo_bytes);
    // One disc-level metadata record: prefer the game SFO when both exist.
    result.metadata = if (result.game_sfo_bytes.len != 0) game else video;
    if (result.game_sfo_bytes.len == 0 and result.video_sfo_bytes.len == 0) {
        result.updater_sfo_bytes = (try iso.read_file(allocator, bytes, "PSP_GAME/SYSDIR/UPDATE/PARAM.SFO")) orelse &.{};
        // An updater-only disc takes its title here, but MSTKUPDATE is not its disc ID.
        const updater = try sfo.parse(allocator, result.updater_sfo_bytes);
        result.metadata.title = updater.title;
        result.metadata.disc_version = updater.disc_version;
    }
    return result;
}

/// Read and validate metadata first, then inventory, hash and store file contents.
/// Only libarchive's private descriptor view is patched; whole-ISO hashing uses
/// the unchanged input. The reader retains one file for the synchronous callback.
pub fn process_iso(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8) !Result {
    return (try process_iso_checked(allocator, io, bytes, store, null, null)).?;
}

pub fn process_iso_checked(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8, catalog: ?catalog_io.Cache, dispatch: ?*Dispatch) !?Result {
    const hashes = hash_source(bytes);
    if (catalog) |root| {
        if (try catalog_io.contains(allocator, io, root, hashes.sha256, bytes.len, .iso)) return null;
    }
    var result = read_metadata(allocator, bytes) catch |err| return try source_error(allocator, bytes, hashes, .iso, err);
    errdefer result.deinit(allocator);
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .pair_documents = true, .paths = .init(allocator) };
    defer inventory.deinit();
    iso.walk(allocator, bytes, &inventory, Inventory.emit_view) catch |err| {
        result.@"error" = try extraction_error(&inventory, err);
    };
    try inventory.extract_documents();
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    result.entries = try inventory.finish_result(&result.@"error");
    result.extraction_errors = inventory.counts.extraction_errors;
    result.sha256 = hashes.sha256;
    result.sha1 = hashes.sha1;
    return result;
}

/// PKGs are roots just like ISOs; decrypted entries retain their own backing
/// buffers so the existing extraction queue can outlive the package walk.
pub fn process_pkg_checked(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8, cache: ?catalog_io.Cache, dispatch: ?*Dispatch) !?Result {
    const hashes = hash_source(bytes);
    if (cache) |value| {
        if (try catalog_io.contains(allocator, io, value, hashes.sha256, bytes.len, .pkg)) return null;
    }
    if (bytes.len == 0) return try source_error(allocator, bytes, hashes, .pkg, error.EmptyFile);
    const package = pkg.Package.init(bytes) catch |err| return try source_error(allocator, bytes, hashes, .pkg, err);
    var result = read_pkg_metadata(allocator, package) catch |err| return try source_error(allocator, bytes, hashes, .pkg, err);
    errdefer result.deinit(allocator);
    result.sha256 = hashes.sha256;
    result.sha1 = hashes.sha1;
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .pair_documents = true, .paths = .init(allocator) };
    defer inventory.deinit();
    const PackageInventory = struct {
        inventory: *Inventory,
        result: *Result,

        fn emit(self: *@This(), name: []const u8, contents: ?memory.View) !void {
            try self.inventory.emit_view(name, contents);
            const view = contents orelse return;
            if (!std.mem.eql(u8, name, "USRDIR/CONTENT/EBOOT.PBP")) return;
            // Use the inventory's already-decrypted PBP rather than decrypting
            // its entire game payload a second time just to read PARAM.SFO.
            const parsed = containers.parse_pbp(view.bytes) catch return;
            self.result.pbp_sfo_bytes = try self.inventory.allocator.dupe(u8, parsed.get("PARAM.SFO").?);
            const inner = sfo.parsePkg(self.inventory.allocator, self.result.pbp_sfo_bytes, &self.result.pbp_title) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return,
            };
            self.result.metadata = .{ .title = inner.title orelse self.result.metadata.title, .disc_id = inner.disc_id, .disc_version = inner.disc_version, .required_firmware = inner.required_firmware };
        }
    };
    var context = PackageInventory{ .inventory = &inventory, .result = &result };
    package.walk(allocator, &context, PackageInventory.emit) catch |err| {
        result.@"error" = try extraction_error(&inventory, err);
    };
    try inventory.extract_documents();
    result.entries = try inventory.finish_result(&result.@"error");
    result.stored = inventory.counts.stored;
    result.extraction_errors = inventory.counts.extraction_errors;
    result.reused = inventory.counts.reused;
    return result;
}

fn read_pkg_metadata(allocator: std.mem.Allocator, package: pkg.Package) !Result {
    var result: Result = .{ .kind = .pkg, .size_bytes = package.bytes.len, .content_type = package.content_type, .package_flags = package.package_flags };
    errdefer result.deinit(allocator);
    result.content_id = try allocator.dupe(u8, package.content_id);
    if (try package.read_file(allocator, "PARAM.SFO")) |metadata| {
        result.pkg_sfo_bytes = metadata;
        if (metadata.len == 0) return error.InvalidSfo;
        result.metadata = try sfo.parsePkg(allocator, metadata, &result.pkg_title);
    } else if (package.content_type != 9) {
        return error.MissingPkgMetadata;
    }
    return result;
}

fn parse_update_pbp(bytes: []const u8) !@import("zig_psp_pbp").Pbp {
    const pbp = try containers.parse_pbp(bytes);
    if (!std.mem.startsWith(u8, pbp.get("DATA.BIN").?, "PSAR")) return error.InvalidUpdaterPsar;
    return pbp;
}

/// Recognition is intentionally cheaper than PSAR reconstruction. Malformed
/// probes are ignored; allocation failures must still abort discovery.
pub fn probe_update(allocator: std.mem.Allocator, bytes: []const u8) !bool {
    const pbp = parse_update_pbp(bytes) catch return false;
    _ = sfo.parseUpdate(allocator, pbp.get("PARAM.SFO").?) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return false,
    };
    return true;
}

fn read_update_metadata(allocator: std.mem.Allocator, pbp: @import("zig_psp_pbp").Pbp, size: usize) !Result {
    var result: Result = .{ .kind = .update, .size_bytes = size };
    errdefer result.deinit(allocator);
    // Summary and publication outlive the mapping, unlike queued section views.
    result.pbp_sfo_bytes = try allocator.dupe(u8, pbp.get("PARAM.SFO").?);
    const metadata = try sfo.parseUpdate(allocator, result.pbp_sfo_bytes);
    result.metadata = metadata.metadata;
    result.updater_version = metadata.updater_version;
    result.updater_target = metadata.updater_target;
    return result;
}

/// The original PBP is an observation, never a new CAS object. SDK section
/// slices share the retained source mapping through ordinary recursive tasks.
pub fn process_update_checked(allocator: std.mem.Allocator, io: std.Io, input: memory.View, store: ?[]const u8, cache: ?catalog_io.Cache, dispatch: ?*Dispatch) !?Result {
    const bytes = input.bytes;
    const hashes = hash_source(bytes);
    if (cache) |value| {
        if (try catalog_io.contains(allocator, io, value, hashes.sha256, bytes.len, .update)) return null;
    }
    const pbp = parse_update_pbp(bytes) catch |err| return try source_error(allocator, bytes, hashes, .update, err);
    var result = read_update_metadata(allocator, pbp, bytes.len) catch |err| return try source_error(allocator, bytes, hashes, .update, err);
    errdefer result.deinit(allocator);
    result.sha256 = hashes.sha256;
    result.sha1 = hashes.sha1;
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .owner = input.owner, .paths = .init(allocator) };
    defer inventory.deinit();
    // Parsing already validated every section. Walk failures can only come
    // from our consumer and must never become durable malformed-input errors.
    try pbp.walk(&inventory, Inventory.emit);
    result.entries = try inventory.finish_result(&result.@"error");
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    result.extraction_errors = inventory.counts.extraction_errors;
    return result;
}

/// A NAND is an immutable root observation. Native reconstructions are separate
/// attempts; only real extracted files, never the raw source, enter the CAS.
pub fn process_nand_checked(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8, cache: ?catalog_io.Cache, dispatch: ?*Dispatch, nand_fuse_directory: ?[]const u8) !?Result {
    const hashes = hash_source(bytes);
    if (cache) |value| {
        if (try catalog_io.contains(allocator, io, value, hashes.sha256, bytes.len, .nand)) return null;
    }
    const blocks = nand.asBlocks(bytes) catch |err| return try source_error(allocator, bytes, hashes, .nand, err);
    var result = Result{
        .kind = .nand,
        .size_bytes = bytes.len,
        .sha256 = hashes.sha256,
        .sha1 = hashes.sha1,
        .nand_blocks = @intCast(blocks.len),
    };
    errdefer result.deinit(allocator);
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .paths = .init(allocator) };
    defer inventory.deinit();
    var fuse_id: ?u64 = null;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&fuse_id));
    if (nand_fuse_directory) |directory| {
        fuse_id = nand_fuses.read_fuse(io, directory, hashes.sha256) catch |err| switch (err) {
            error.InvalidNandFuseId => blk: {
                try record_failure(&inventory, &result.@"error", err);
                break :blk null;
            },
            else => return err,
        };
    }
    if (dispatch) |queue| {
        std.debug.assert(queue.prx_key == null);
        if (fuse_id) |id| queue.prx_key = kirk.Cmd8Key.init(id);
    }
    var diagnostics: std.Io.Writer.Discarding = .init(&.{});
    ingest_nand_ipl(&inventory, blocks, &diagnostics.writer) catch |err| {
        try record_failure(&inventory, &result.@"error", err);
    };
    nand.idstorage.walk(allocator, blocks, fuse_id, &diagnostics.writer, &inventory, NandIdStorage.emit) catch |err| {
        try record_failure(&inventory, &result.@"error", err);
    };
    ingest_nand_lflash(&inventory, bytes, fuse_id, &diagnostics.writer) catch |err| {
        try record_failure(&inventory, &result.@"error", err);
    };
    result.entries = try inventory.finish_result(&result.@"error");
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    result.extraction_errors = inventory.counts.extraction_errors;
    return result;
}

fn nand_child(parent: *Inventory) Inventory {
    return .{ .allocator = parent.allocator, .io = parent.io, .store = parent.store, .dispatch = parent.dispatch, .paths = .init(parent.allocator) };
}

// Explicit native parents receive contextual trees, not a competing hash-only
// generic extraction. Suppression is scoped to this one emission.
fn emit_nand_parent(inventory: *Inventory, path: []const u8, input: memory.View) !usize {
    const previous = inventory.suppress_dispatch;
    inventory.suppress_dispatch = path;
    defer inventory.suppress_dispatch = previous;
    const index = inventory.entries.items.len;
    try inventory.emit_view(path, input);
    return index;
}

fn ingest_nand_ipl(inventory: *Inventory, blocks: []const nand.Block, writer: *std.Io.Writer) !void {
    const selected = try nand.findIpl(blocks);
    const bytes = try nand.reconstructIpl(inventory.allocator, blocks, selected, writer);
    // Reconstruction failures above are regional; everything below is either
    // explicitly caught on the real parent or an infrastructure failure.
    errdefer inventory.fatal = true;
    const input = try memory.Owner.take_allocated(inventory.allocator, bytes);
    defer input.release();
    const index = try emit_nand_parent(inventory, "ipl.bin", input);
    var child = nand_child(inventory);
    defer child.deinit();
    var failure: ?[]const u8 = null;
    defer if (failure) |message| inventory.allocator.free(message);
    var consumer = NandIpl{ .inventory = &child };
    defer consumer.deinit();
    nand.ipl.walk(inventory.allocator, input.bytes, writer, &consumer, NandIpl.emit) catch |err| {
        try record_failure(&child, &failure, err);
    };
    try consumer.finish_image();
    try inventory.attach_inline(&inventory.entries.items[index], &child, catalog_io.nand_provenance(), "identity", &failure);
}

const NandIpl = struct {
    inventory: *Inventory,
    pending: ?struct {
        image_index: usize,
        entry_index: usize,
        inventory: Inventory,
        failure: ?[]const u8 = null,
    } = null,

    fn deinit(self: *NandIpl) void {
        if (self.pending) |*pending| {
            pending.inventory.deinit();
            if (pending.failure) |message| self.inventory.allocator.free(message);
        }
    }

    fn finish_image(self: *NandIpl) !void {
        if (self.pending) |*pending| {
            try self.inventory.attach_inline(&self.inventory.entries.items[pending.entry_index], &pending.inventory, catalog_io.nand_provenance(), "identity", &pending.failure);
            pending.inventory.deinit();
            self.pending = null;
        }
    }

    fn emit(self: *NandIpl, event: nand.ipl.Event) anyerror!void {
        // Even callback errors named like format errors must escape the SDK and
        // the regional catch, never become an apparently durable partial root.
        errdefer self.inventory.fatal = true;
        switch (event) {
            .artifact => |artifact| {
                if (artifact.kind == .image) try self.finish_image();
                if (!artifact.publishable) return;
                const view = try memory.Owner.take_allocated(self.inventory.allocator, try self.inventory.allocator.dupe(u8, artifact.bytes));
                defer view.release();
                var path_buffer: [64]u8 = undefined;
                switch (artifact.kind) {
                    .record, .image => {
                        const directory = if (artifact.kind == .record) "records" else "images";
                        if (!self.inventory.paths.contains(directory)) try self.inventory.emit_view(directory, null);
                        const path = try std.fmt.bufPrint(&path_buffer, "{s}/{d:0>4}.bin", .{ directory, artifact.index });
                        if (artifact.kind == .image and !artifact.reset_write) {
                            const index = try emit_nand_parent(self.inventory, path, view);
                            self.pending = .{ .image_index = artifact.index, .entry_index = index, .inventory = nand_child(self.inventory) };
                        } else {
                            try self.inventory.emit_view(path, view);
                        }
                    },
                    .stage2, .stage3, .kernel_keys => {
                        const pending = if (self.pending) |*value| value else return error.InvalidNandIplEvent;
                        if (pending.image_index != artifact.index) return error.InvalidNandIplEvent;
                        const path = switch (artifact.kind) {
                            .stage2 => "stage2.bin",
                            .stage3 => "stage3.bin",
                            .kernel_keys => "kernel-keys.bin",
                            else => unreachable,
                        };
                        try pending.inventory.emit_view(path, view);
                    },
                }
            },
            .failure => |failure| {
                const pending = if (self.pending) |*value| value else return error.InvalidNandIplEvent;
                if (pending.image_index != failure.image_index) return error.InvalidNandIplEvent;
                try record_failure(&pending.inventory, &pending.failure, failure.reason);
            },
        }
    }
};

const NandIdStorage = struct {
    fn emit(inventory: *Inventory, region: nand.idstorage.Region) anyerror!void {
        errdefer inventory.fatal = true;
        // Region's fixed byte array has the same length and alignment as this
        // slice allocation. Adoption consumes it on success and failure.
        const input = try memory.Owner.take_allocated(inventory.allocator, region.data[0..]);
        defer input.release();
        if (!inventory.paths.contains("idstorage")) try inventory.emit_view("idstorage", null);
        var directory_buffer: [64]u8 = undefined;
        const directory = try std.fmt.bufPrint(&directory_buffer, "idstorage/index-{d:0>4}", .{region.index_block});
        try inventory.emit_view(directory, null);
        var path_buffer: [96]u8 = undefined;
        try inventory.emit_view(try std.fmt.bufPrint(&path_buffer, "{s}/index.bin", .{directory}), .{ .owner = input.owner, .bytes = region.index() });
        var leaves = region.leaves();
        while (leaves.next()) |leaf| {
            try inventory.emit_view(try std.fmt.bufPrint(&path_buffer, "{s}/{x:0>4}.bin", .{ directory, leaf.id }), .{ .owner = input.owner, .bytes = leaf.bytes });
        }
    }
};

fn ingest_nand_lflash(inventory: *Inventory, raw: []const u8, fuse_id: ?u64, writer: *std.Io.Writer) !void {
    const image = try nand.lflash.reconstruct(inventory.allocator, raw, fuse_id, writer);
    errdefer inventory.fatal = true;
    const partitions = image.partitions;
    const count = image.count;
    const input = try memory.Owner.take_allocated(inventory.allocator, image.bytes);
    defer input.release();
    try inventory.emit_view("lflash", null);
    for (partitions[0..count], 0..) |partition, index| {
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "lflash/flash{d}.img", .{index});
        const view = memory.View{ .owner = input.owner, .bytes = input.bytes[partition.first_sector * 512 ..][0 .. partition.sector_count * 512] };
        if (partition.formatted) {
            try ingest_nand_partition(inventory, path, view, writer);
        } else {
            try inventory.emit_view(path, view);
        }
    }
}

// The actual partition adapter also serves compact synthetic FAT regressions:
// never retain the SDK FileView or its temporary validated cluster-chain slice.
fn ingest_nand_partition(inventory: *Inventory, path: []const u8, input: memory.View, writer: *std.Io.Writer) !void {
    errdefer inventory.fatal = true;
    const index = try emit_nand_parent(inventory, path, input);
    var child = nand_child(inventory);
    child.pair_documents = true;
    child.owner = input.owner;
    defer child.deinit();
    var failure: ?[]const u8 = null;
    defer if (failure) |message| inventory.allocator.free(message);
    nand.fat.walk(inventory.allocator, input.bytes, writer, &child, NandFat.emit) catch |err| {
        try record_failure(&child, &failure, err);
    };
    try child.extract_documents();
    try inventory.attach_inline(&inventory.entries.items[index], &child, catalog_io.nand_provenance(), "identity", &failure);
}

const NandFat = struct {
    fn emit(inventory: *Inventory, path: []const u8, file: ?nand.fat.FileView) anyerror!void {
        errdefer inventory.fatal = true;
        const contents = file orelse return inventory.emit_view(path, null);
        if (contents.contiguous()) |bytes| {
            try inventory.emit_view(path, .{ .owner = inventory.owner.?, .bytes = bytes });
        } else {
            const view = try memory.Owner.take_allocated(inventory.allocator, try contents.copy(inventory.allocator));
            defer view.release();
            try inventory.emit_view(path, view);
        }
    }
};

/// Ingest owns names, inventory records, hashes and store writes. The reader
/// only lends paths and payloads for the duration of emit.
const Inventory = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: ?[]const u8,
    dispatch: ?*Dispatch,
    counts: Counts = .{},
    owner: ?*memory.Owner = null,
    suppress_dispatch: ?[]const u8 = null,
    pair_documents: bool = false,
    documents: std.ArrayList(usize) = .empty,
    document_inputs: std.AutoHashMapUnmanaged(usize, memory.View) = .empty,
    entries: std.ArrayList(Entry) = .empty,
    paths: std.StringHashMap(usize),
    fatal: bool = false,

    fn deinit(self: *Inventory) void {
        self.paths.deinit();
        var inputs = self.document_inputs.valueIterator();
        while (inputs.next()) |view| view.release();
        self.document_inputs.deinit(self.allocator);
        self.documents.deinit(self.allocator);
        for (self.entries.items) |entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    // Native readers emit slices borrowed from the task's backing owner.
    fn emit(self: *Inventory, name: []const u8, contents: ?[]const u8) anyerror!void {
        try self.emit_view(name, if (contents) |bytes| .{ .bytes = bytes, .owner = self.owner.? } else null);
    }

    fn emit_view(self: *Inventory, name: []const u8, contents: ?memory.View) !void {
        self.emit_entry(name, contents) catch |err| {
            switch (err) {
                error.InvalidIsoPath, error.DuplicateIsoPath => {},
                else => self.fatal = true,
            }
            return err;
        };
    }

    fn emit_entry(self: *Inventory, name: []const u8, contents: ?memory.View) !void {
        try validate_path(name);
        if (self.paths.contains(name)) return error.DuplicateIsoPath;
        var entry = Entry{ .path = try self.allocator.dupe(u8, name), .type = if (contents != null) .file else .directory };
        errdefer entry.deinit(self.allocator);
        if (contents) |view| {
            const payload = view.bytes;
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
            entry.sha256 = std.fmt.bytesToHex(hash, .lower);
            entry.size_bytes = payload.len;
            if (self.store) |root| {
                if (try StoreWriter.init(self.allocator, self.io, root, entry.sha256.?, payload.len)) |new_writer| {
                    var writer = new_writer;
                    defer writer.deinit();
                    try writer.write(payload);
                    if (try writer.finish(self.allocator, entry.sha256.?, payload.len)) self.counts.stored += 1 else self.counts.reused += 1;
                } else self.counts.reused += 1;
            }
        }
        const paired_document = self.pair_documents and self.dispatch != null and
            if (contents) |view|
                std.mem.eql(u8, std.Io.Dir.path.basename(name), "DOCUMENT.DAT") and extractor.paired_document_candidate(view.bytes)
            else
                false;
        if (paired_document) try self.documents.append(self.allocator, self.entries.items.len);
        if (contents) |view| {
            if (self.pair_documents and self.dispatch != null and
                (paired_document or std.mem.eql(u8, std.Io.Dir.path.basename(name), "DOCINFO.EDAT")))
            {
                try self.document_inputs.put(self.allocator, self.entries.items.len, view);
                _ = view.retain();
            }
        }
        if (contents) |view| {
            if (!paired_document and (self.suppress_dispatch == null or !std.mem.eql(u8, name, self.suppress_dispatch.?))) {
                if (self.dispatch) |dispatch| try dispatch.inspect(self.allocator, self.io, name, view, entry.sha256.?);
            }
        }
        try self.paths.put(entry.path, self.entries.items.len);
        try self.entries.append(self.allocator, entry);
    }

    // A manual's sibling context belongs to this inventory occurrence, never to
    // the hash-only extraction queue. Wait until both paths have been observed.
    fn extract_documents(self: *Inventory) !void {
        if (self.dispatch == null) return;
        for (self.documents.items) |index| {
            const entry = &self.entries.items[index];
            const prefix = entry.path[0 .. entry.path.len - "DOCUMENT.DAT".len];
            const companion_path = try std.fmt.allocPrint(self.allocator, "{s}DOCINFO.EDAT", .{prefix});
            defer self.allocator.free(companion_path);
            const companion_index = self.paths.get(companion_path) orelse continue;
            const companion = self.entries.items[companion_index];
            const source = self.document_inputs.get(index) orelse return error.InvalidDocument;
            const companion_input = self.document_inputs.get(companion_index);
            try self.attach(entry, .document, source.bytes, if (companion_input) |view| view.bytes else "", entry.sha256.?);
            if (companion.type == .file) {
                const dependencies = try self.allocator.alloc(Dependency, 1);
                errdefer self.allocator.free(dependencies);
                const path = try self.allocator.dupe(u8, companion.path);
                errdefer self.allocator.free(path);
                dependencies[0] = .{ .path = path, .sha256 = try self.allocator.dupe(u8, &companion.sha256.?), .size_bytes = companion.size_bytes.? };
                entry.extraction.?.dependencies = dependencies;
            }
        }
    }

    fn extract_external(self: *Inventory, hash: [64]u8, input: []const u8, kind: extractor.Kind, companion: ?[]const u8) !external_extractor.Output {
        return external_extractor.extract(self.allocator, self.io, hash, input, kind, companion) catch |err| {
            switch (err) {
                error.ExtractionFailed, error.ExtractorUnavailable, error.InvalidExtractorProvenance => {},
                else => self.fatal = true,
            }
            return err;
        };
    }

    fn walk_external(self: *Inventory, output: external_extractor.Output) !void {
        output.walk(self.allocator, self.io, self, Inventory.emit_view) catch |err| {
            switch (err) {
                error.EmptyExtraction, error.UnsupportedExtractedEntry, error.InvalidIsoPath, error.DuplicateIsoPath => {},
                else => self.fatal = true,
            }
            return err;
        };
    }

    fn decode_context(self: *Inventory, kind: extractor.Kind, input: []const u8, companion: []const u8, hash: [64]u8, output: *?external_extractor.Output) !extractor.Provenance {
        if (kind == .pops) {
            const output_value = try pops.extract(self.allocator, input, companion);
            const view = try memory.Owner.take_allocated(self.allocator, output_value.bytes);
            defer view.release();
            var name_buffer: [4096]u8 = undefined;
            try self.emit_view(try decodedOutputName(kind, output_value.format, output_value.content_format, &name_buffer), view);
            return .{ .name = "pspdb-pops", .version = revisions.pops, .options = &.{"in-memory"} };
        }
        if (kind == .document) {
            if (companion.len != 304) return error.InvalidDocinfo;
            if (input.len > 64 * 1024 * 1024) return error.InvalidDocument;
        }
        output.* = try self.extract_external(hash, input, kind, if (kind == .document) companion else null);
        try self.walk_external(output.*.?);
        return output.*.?.provenance.?.value;
    }

    fn attach(self: *Inventory, entry: *Entry, kind: extractor.Kind, input: []const u8, companion: []const u8, hash: [64]u8) !void {
        var child = Inventory{ .allocator = self.allocator, .io = self.io, .store = self.store, .dispatch = self.dispatch, .paths = .init(self.allocator) };
        defer child.deinit();
        var output: ?external_extractor.Output = null;
        defer if (output) |value| value.deinit(self.allocator, self.io);
        var failure: ?[]const u8 = null;
        errdefer if (failure) |message| self.allocator.free(message);
        const provenance = child.decode_context(kind, input, companion, hash, &output) catch |err| blk: {
            failure = extraction_error(&child, err) catch |fatal| {
                self.fatal = true;
                return fatal;
            };
            break :blk orchestrator(kind);
        };
        try self.attach_inline(entry, &child, provenance, if (kind == .pops) "source_stem" else "identity", &failure);
        if (output) |*value| entry.extraction.?.owned_provenance = value.take_provenance();
    }

    // Takes the finalized child entries and its first error only on success.
    fn attach_inline(self: *Inventory, entry: *Entry, child: *Inventory, provenance: extractor.Provenance, name_rule: []const u8, failure: *?[]const u8) !void {
        errdefer self.fatal = true;
        const tree = try self.allocator.create(InlineExtraction);
        errdefer self.allocator.destroy(tree);
        const source_hash = try self.allocator.dupe(u8, &entry.sha256.?);
        errdefer self.allocator.free(source_hash);
        tree.* = .{
            .sha256 = source_hash,
            .size_bytes = entry.size_bytes.?,
            .extractor = provenance,
            .name_rule = name_rule,
            .entries = try child.finish_result(failure),
            .@"error" = failure.*,
        };
        entry.extraction = tree;
        failure.* = null;
        self.counts.stored += child.counts.stored;
        self.counts.reused += child.counts.reused;
        self.counts.extraction_errors += child.counts.extraction_errors;
    }

    fn finish_result(self: *Inventory, failure: *?[]const u8) ![]Entry {
        return self.finish() catch |err| {
            if (failure.* == null) failure.* = try extraction_error(self, err);
            // Keep only paths whose directory ancestors actually survived.
            if (self.fatal or err == error.OutOfMemory or err == error.CryptoFailure) return err;
            var changed = true;
            while (changed) {
                changed = false;
                var index = self.entries.items.len;
                while (index != 0) {
                    index -= 1;
                    const entry = self.entries.items[index];
                    const slash = std.mem.lastIndexOfScalar(u8, entry.path, '/') orelse continue;
                    const valid = for (self.entries.items) |parent| {
                        if (parent.type == .directory and std.mem.eql(u8, parent.path, entry.path[0..slash])) break true;
                    } else false;
                    if (!valid) {
                        (self.entries.orderedRemove(index)).deinit(self.allocator);
                        changed = true;
                    }
                }
            }
            return self.sorted_entries();
        };
    }

    fn finish(self: *Inventory) ![]Entry {
        for (self.entries.items) |entry| {
            if (std.mem.lastIndexOfScalar(u8, entry.path, '/')) |slash| {
                const parent = self.paths.get(entry.path[0..slash]) orelse return error.MissingIsoDirectory;
                if (self.entries.items[parent].type != .directory) return error.InvalidIsoPath;
            }
        }
        return self.sorted_entries();
    }

    fn sorted_entries(self: *Inventory) ![]Entry {
        std.mem.sort(Entry, self.entries.items, {}, struct {
            fn less(_: void, a: Entry, b: Entry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.less);
        return self.entries.toOwnedSlice(self.allocator);
    }
};

/// Hash-keyed trees must not depend on the filename of the first occurrence.
/// The catalog's name_rule restores occurrence-specific names when rendered.
fn decodedOutputName(kind: extractor.Kind, format: decoded_output.Format, content_format: ?decoded_output.Format, buffer: []u8) ![]const u8 {
    if (kind == .gzip) return "payload.bin";
    if (kind == .prx and (format == .gzip or format == .kl3e or format == .kl4e)) {
        if (content_format) |content|
            return std.fmt.bufPrint(buffer, "payload.{s}.{s}", .{ content.extension(), format.extension() });
    }
    if (kind == .npumdimg) return "disc.iso";
    return switch (format) {
        .elf => "module.elf",
        .gzip => "payload.gz",
        .kl3e => "payload.kl3e",
        .kl4e => "payload.kl4e",
        .psp => "payload.psp",
        .unknown => "payload.bin",
        .iso => "disc.iso",
    };
}

test "KL extraction accepts absent mismatched and empty-stem suffixes" {
    const allocator = std.testing.allocator;
    const Queue = struct {
        fn enqueue(_: *anyopaque, _: Task) !void {
            return error.UnexpectedTask;
        }
    };
    var context: u8 = 0;
    var dispatch = Dispatch{
        .context = &context,
        .enqueue = Queue.enqueue,
        .store = null,
        .catalog = "unused",
        .visited = .init(allocator),
    };
    defer dispatch.deinit();
    for ([_]extractor.Kind{ .kl3e, .kl4e }) |kind| {
        var encoded = "KL3E\x80\x00\x00\x00\x03abc".*;
        if (kind == .kl4e) encoded[2] = '4';
        const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &encoded));
        defer input.release();
        const suffix_only = if (kind == .kl3e) ".kl3e" else ".kl4e";
        const mismatched = if (kind == .kl3e) "module.kl4e" else "module.kl3e";
        for ([_][]const u8{ "DATA", mismatched, suffix_only }) |name| {
            var inventory = Inventory{ .allocator = allocator, .io = std.testing.io, .store = null, .dispatch = null, .paths = .init(allocator) };
            defer inventory.deinit();
            var output: ?external_extractor.Output = null;
            _ = try execute_task(allocator, .{ .name = name, .input = input, .hash = hash_source(&encoded).sha256, .kind = kind }, &dispatch, &inventory, &output);
            try std.testing.expectEqual(@as(usize, 1), inventory.entries.items.len);
            const entry = inventory.entries.items[0];
            try std.testing.expectEqualStrings("payload.bin", entry.path);
            try std.testing.expectEqual(@as(u64, 3), entry.size_bytes.?);
            try std.testing.expectEqualStrings(&hash_source("abc").sha256, &entry.sha256.?);
        }
    }
}

pub fn process_task(allocator: std.mem.Allocator, io: std.Io, task: Task, dispatch: *Dispatch) !Counts {
    if (dispatch.state) |state| {
        if (state.fresh_trees.map.getPtr(@tagName(task.kind))) |fresh| {
            if (fresh.map.contains(&task.hash)) {
                if (try reuse_task(allocator, io, task, dispatch)) |counts| return counts;
            }
        }
    }

    var inventory = Inventory{
        .allocator = allocator,
        .io = io,
        .store = dispatch.store,
        .dispatch = dispatch,
        .owner = task.input.owner,
        .pair_documents = task.kind == .iso9660,
        .paths = .init(allocator),
    };
    defer inventory.deinit();
    var output: ?external_extractor.Output = null;
    defer if (output) |value| value.deinit(allocator, io);
    var failure: ?[]const u8 = null;
    defer if (failure) |message| allocator.free(message);
    const provenance = execute_task(allocator, task, dispatch, &inventory, &output) catch |err| blk: {
        failure = try extraction_error(&inventory, err);
        break :blk orchestrator(task.kind);
    };
    const entries = try inventory.finish_result(&failure);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    try catalog_io.publish_extraction(allocator, io, dispatch.catalog, task.hash, task.input.bytes.len, entries, provenance, @tagName(task.kind), failure);
    return inventory.counts;
}

fn execute_task(allocator: std.mem.Allocator, task: Task, dispatch: *Dispatch, inventory: *Inventory, output: *?external_extractor.Output) !extractor.Provenance {
    return switch (task.kind) {
        .edat => blk: {
            const bytes = edat.decode(allocator, task.input.bytes, null) catch |err| switch (err) {
                error.MissingEdatRap => retry: {
                    const directory = dispatch.rap_directory orelse return error.MissingEdatRap;
                    const content_id = try edat.content_id(task.input.bytes);
                    var rap = licenses.read_rap(inventory.io, directory, content_id) catch |key_error| {
                        switch (key_error) {
                            error.MissingEdatRap, error.InvalidEdatRap, error.InvalidEdatContentId => {},
                            else => inventory.fatal = true,
                        }
                        std.debug.print("EDAT {s}: {s} in {s}; configure PSPDB_RAP_DIR or import its RAP with tools/psn_acquire.py\n", .{ content_id, @errorName(key_error), directory });
                        return key_error;
                    };
                    defer std.crypto.secureZero(u8, &rap);
                    break :retry try edat.decode(allocator, task.input.bytes, rap);
                },
                else => return err,
            };
            const view = try memory.Owner.take_allocated(allocator, bytes);
            defer view.release();
            try inventory.emit_view("payload.dat", view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.edat };
        },
        .gzip, .prx, .kl3e, .kl4e, .pgd, .npumdimg => blk: {
            const output_value = try switch (task.kind) {
                .gzip => gzip.extract(allocator, task.input.bytes),
                .prx => prx.extract(allocator, task.input.bytes, if (dispatch.prx_key) |*key| key else null),
                .kl3e, .kl4e => kle.extract(allocator, task.input.bytes),
                .pgd => pgd.extract(allocator, task.input.bytes),
                .npumdimg => npumdimg.extract(allocator, task.input.bytes),
                else => unreachable,
            };
            const view = try memory.Owner.take_allocated(allocator, output_value.bytes);
            defer view.release();
            var name_buffer: [4096]u8 = undefined;
            const name = try decodedOutputName(task.kind, output_value.format, output_value.content_format, &name_buffer);
            try inventory.emit_view(name, view);
            const revision = switch (task.kind) {
                inline .gzip, .prx, .kl3e, .kl4e, .pgd, .npumdimg => |kind| @field(revisions, @tagName(kind)),
                else => unreachable,
            };
            break :blk .{ .name = "pspdb-ingest", .version = revision };
        },
        .psar => blk: {
            try psar.walk(allocator, task.input, inventory, Inventory.emit_view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.psar };
        },
        .rco => blk: {
            try rco.walk(allocator, task.input, inventory, Inventory.emit_view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.rco };
        },
        .iso9660 => blk: {
            try iso.walk(allocator, task.input.bytes, inventory, Inventory.emit_view);
            try inventory.extract_documents();
            break :blk .{ .name = "pspdb-ingest", .version = revisions.iso9660 };
        },
        .sce => blk: {
            try containers.walk_sce(task.input.bytes, inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.sce };
        },
        .vmp => blk: {
            try containers.walk_vmp(task.input.bytes, inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.vmp };
        },
        .elf => blk: {
            try containers.walk_elf(task.input.bytes, inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.elf };
        },
        .pbp => blk: {
            const pbp = try containers.parse_pbp(task.input.bytes);
            var title: []u8 = &.{};
            defer allocator.free(title);
            _ = try sfo.parsePkg(allocator, pbp.get("PARAM.SFO") orelse "", &title);
            if (pbp.get("DATA.BIN")) |psar_bytes| {
                if (extractor.detect(psar_bytes) == .npumdimg) {
                    const data = try data_psp.Header.parse(pbp.get("DATA.PSP") orelse return error.MissingDataPsp);
                    const param = pbp.get("PARAM.SFO") orelse return error.MissingPbpMetadata;
                    const valid = try data.verify(param);
                    if (!valid) return error.InvalidDataPspSignature;
                    if (data.opnssmp) |bytes| try inventory.emit("OPNSSMP.PGD", bytes);
                    if (data.startdat) |bytes| try inventory.emit("STARTDAT", bytes);
                }
            }
            const data_bin = pbp.get("DATA.BIN") orelse &.{};
            const is_pops = std.mem.startsWith(u8, data_bin, "PSISOIMG0000") or std.mem.startsWith(u8, data_bin, "PSTITLEIMG0000");
            if (is_pops) inventory.suppress_dispatch = "DATA.PSP";
            try pbp.walk(inventory, Inventory.emit);
            if (is_pops) {
                if (inventory.paths.get("DATA.PSP")) |index| {
                    try inventory.attach(&inventory.entries.items[index], .pops, pbp.get("DATA.PSP").?, data_bin, task.hash);
                }
                if (inventory.paths.get("DATA.BIN")) |index| {
                    try inventory.attach(&inventory.entries.items[index], .psx, task.input.bytes, "", task.hash);
                }
            }
            break :blk .{ .name = "Zig-PSP zPBPTool", .version = revisions.pbp, .options = &.{"in-memory"} };
        },
        else => blk: {
            output.* = try inventory.extract_external(task.hash, task.input.bytes, task.kind, null);
            try inventory.walk_external(output.*.?);
            break :blk output.*.?.provenance.?.value;
        },
    };
}

/// Reuse an unchanged immediate inventory, but still visit its derived children.
fn reuse_task(allocator: std.mem.Allocator, io: std.Io, task: Task, dispatch: *Dispatch) !?Counts {
    if (dispatch.store == null) return null;
    const revision = switch (task.kind) {
        inline else => |kind| @field(revisions, @tagName(kind)),
    };
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/v{s}/{s}-tree.json", .{ dispatch.catalog, @tagName(task.kind), revision, task.hash });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    const Saved = SavedTree;
    const parsed = try std.json.parseFromSlice(Saved, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.sha256, &task.hash) or parsed.value.size_bytes != task.input.bytes.len) return error.CatalogConflict;
    if (parsed.value.@"error" != null) return null;
    return reuse_entries(allocator, io, parsed.value.entries, dispatch, task.kind == .iso9660);
}

const SavedEntry = struct { path: []const u8, type: []const u8, sha256: ?[]const u8 = null, size_bytes: ?u64 = null, extraction: ?SavedTree = null };
const SavedTree = struct { sha256: []const u8, size_bytes: u64, entries: []SavedEntry, dependencies: []Dependency = &.{}, @"error": ?[]const u8 = null };

fn reuse_entries(allocator: std.mem.Allocator, io: std.Io, entries: []SavedEntry, dispatch: *Dispatch, pair_documents: bool) anyerror!?Counts {
    const store = dispatch.store orelse return null;
    var counts: Counts = .{};
    for (entries) |entry| {
        try validate_path(entry.path);
        if (std.mem.eql(u8, entry.type, "directory")) continue;
        const hash = entry.sha256 orelse return error.CatalogConflict;
        try validate_hash(hash);
        if (entry.extraction) |tree| {
            if (tree.@"error" != null) return null;
            const size = entry.size_bytes orelse return error.CatalogConflict;
            if (!std.mem.eql(u8, tree.sha256, hash) or tree.size_bytes != size) return error.CatalogConflict;
            const document = std.mem.eql(u8, std.Io.Dir.path.basename(entry.path), "DOCUMENT.DAT");
            if (document and size > 64 * 1024 * 1024) return error.CatalogConflict;
            var prefix: [24]u8 = undefined;
            if (!try verify_stored_input(allocator, io, store, hash, size, &prefix)) return null;
            if (document and extractor.paired_document_candidate(prefix[0..@intCast(@min(size, prefix.len))])) {
                if (tree.dependencies.len != 1 or tree.dependencies[0].size_bytes != 304 or
                    !std.mem.eql(u8, std.Io.Dir.path.basename(tree.dependencies[0].path), "DOCINFO.EDAT"))
                    return error.CatalogConflict;
                const parent = std.Io.Dir.path.dirname(entry.path) orelse "";
                const dependency_parent = std.Io.Dir.path.dirname(tree.dependencies[0].path) orelse "";
                if (!std.mem.eql(u8, parent, dependency_parent)) return error.CatalogConflict;
            }
            for (tree.dependencies, 0..) |dependency, dependency_index| {
                try validate_path(dependency.path);
                if (std.mem.eql(u8, dependency.path, entry.path)) return error.CatalogConflict;
                for (tree.dependencies[0..dependency_index]) |previous| {
                    if (std.mem.eql(u8, previous.path, dependency.path)) return error.CatalogConflict;
                }
                var sibling: ?SavedEntry = null;
                for (entries) |candidate| {
                    if (std.mem.eql(u8, candidate.path, dependency.path)) {
                        if (sibling != null) return error.CatalogConflict;
                        sibling = candidate;
                    }
                }
                const bound = sibling orelse return error.CatalogConflict;
                if (!std.mem.eql(u8, bound.type, "file") or bound.sha256 == null or bound.size_bytes == null or
                    !std.mem.eql(u8, bound.sha256.?, dependency.sha256) or bound.size_bytes.? != dependency.size_bytes)
                    return error.CatalogConflict;
                if (!try verify_stored_input(allocator, io, store, dependency.sha256, dependency.size_bytes, &.{})) return null;
            }
            // Contextual parents must not be redispatched without their sibling
            // inputs. Their verified children still visit the normal queue.
            const nested = (try reuse_entries(allocator, io, tree.entries, dispatch, false)) orelse return null;
            counts.reused += nested.reused;
        } else {
            const object_path = try std.fmt.allocPrint(allocator, "{s}/sha256/{s}/{s}/{s}", .{ store, hash[0..2], hash[2..4], hash });
            defer allocator.free(object_path);
            const object = std.Io.Dir.cwd().openFile(io, object_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => return null,
                else => return err,
            };
            defer object.close(io);
            const info = try object.stat(io);
            if (info.kind != .file or entry.size_bytes == null or info.size != entry.size_bytes.?) return error.CorruptObject;
            const payload = try allocator.alloc(u8, std.math.cast(usize, info.size) orelse return error.CorruptObject);
            const view = try memory.Owner.take_allocated(allocator, payload);
            defer view.release();
            if (try object.readPositionalAll(io, payload, 0) != payload.len) return error.CorruptObject;
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
            const actual = std.fmt.bytesToHex(digest, .lower);
            if (payload.len != entry.size_bytes.? or !std.mem.eql(u8, &actual, hash)) return error.CorruptObject;
            if (pair_documents and std.mem.eql(u8, std.Io.Dir.path.basename(entry.path), "DOCUMENT.DAT") and extractor.paired_document_candidate(payload)) {
                const parent = std.Io.Dir.path.dirname(entry.path) orelse "";
                for (entries) |sibling| {
                    if (std.mem.eql(u8, std.Io.Dir.path.basename(sibling.path), "DOCINFO.EDAT") and
                        std.mem.eql(u8, std.Io.Dir.path.dirname(sibling.path) orelse "", parent))
                        return null;
                }
                // An absent companion remains opaque, just like the initial walk.
            } else try dispatch.inspect(allocator, io, entry.path, view, actual);
        }
        counts.reused += 1;
    }
    return counts;
}

fn validate_hash(hash: []const u8) !void {
    if (hash.len != 64) return error.CatalogConflict;
    for (hash) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.CatalogConflict;
}

/// Recheck the exact CAS inputs before a contextual helper reads their paths.
/// Stream validation and an optional bounded prefix, without another payload copy.
fn verify_stored_input(allocator: std.mem.Allocator, io: std.Io, root: []const u8, hash: []const u8, size: u64, prefix: []u8) !bool {
    try validate_hash(hash);
    const path = try std.fmt.allocPrint(allocator, "{s}/sha256/{s}/{s}/{s}", .{ root, hash[0..2], hash[2..4], hash });
    defer allocator.free(path);
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const info = try file.stat(io);
    if (info.kind != .file or info.size != size) return error.CorruptObject;
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        if (n > size - total) return error.CorruptObject;
        if (total < prefix.len) {
            const start: usize = @intCast(total);
            const copied = @min(n, prefix.len - start);
            @memcpy(prefix[start..][0..copied], buffer[0..copied]);
        }
        total += n;
        digest.update(buffer[0..n]);
    }
    if (total != size or !std.mem.eql(u8, hash, &std.fmt.bytesToHex(digest.finalResult(), .lower))) return error.CorruptObject;
    return true;
}

fn validate_path(name: []const u8) !void {
    if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidIsoPath;
    for (name) |ch| if (ch < 32 or ch == '\\' or ch == ':') return error.InvalidIsoPath;
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidIsoPath;
}

/// Open and map one image read-only; optional outputs go only to the store.
/// V1 targets POSIX: direct mmap avoids an implicit whole-file heap fallback.
pub fn process_file(allocator: std.mem.Allocator, io: std.Io, path: []const u8, kind: model.RootKind, store: ?[]const u8, catalog: ?catalog_io.Cache, dispatch: ?*Dispatch, nand_fuse_directory: ?[]const u8) !?Result {
    // Recheck the opened descriptor without following symlinks or blocking on
    // a FIFO substituted after discovery.
    const descriptor = try std.posix.openat(std.Io.Dir.cwd().handle, path, .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0);
    const file: std.Io.File = .{ .handle = descriptor, .flags = .{ .nonblocking = true } };
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooLarge;

    const input = if (size == 0)
        try memory.Owner.take_allocated(allocator, try allocator.alloc(u8, 0))
    else blk: {
        const mapping = try std.posix.mmap(null, size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, file.handle, 0);
        break :blk try memory.Owner.take_mapped(allocator, mapping);
    };
    defer input.release();
    const result = switch (kind) {
        .iso => try process_iso_checked(allocator, io, input.bytes, store, catalog, dispatch),
        .pkg => try process_pkg_checked(allocator, io, input.bytes, store, catalog, dispatch),
        .nand => try process_nand_checked(allocator, io, input.bytes, store, catalog, dispatch, nand_fuse_directory),
        .update => try process_update_checked(allocator, io, input, store, catalog, dispatch),
    };
    errdefer if (result) |value| value.deinit(allocator);
    const after = try file.stat(io);
    if (stat.size != after.size or stat.mtime.nanoseconds != after.mtime.nanoseconds or stat.ctime.nanoseconds != after.ctime.nanoseconds) return error.SourceChanged;
    return result;
}

test "unparseable source publishes identity without invented metadata" {
    const allocator = std.testing.allocator;
    const result = try process_iso(allocator, std.testing.io, "not an ISO", null);
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("InvalidIso", result.@"error".?);
    try std.testing.expect(!result.has_metadata);
    try std.testing.expectEqual(@as(usize, 0), result.entries.len);
    try std.testing.expectEqualStrings(&hash_source("not an ISO").sha256, &result.sha256);
}

test "failed queue publication permits retry with input retained past its parent" {
    const allocator = std.testing.allocator;
    const Queue = struct {
        reject: bool = true,
        task: ?Task = null,
        fn enqueue(context: *anyopaque, task: Task) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.reject) return error.TestQueueFailure;
            if (self.task != null) return error.UnexpectedTask;
            self.task = task;
        }
    };
    var queue = Queue{};
    defer if (queue.task) |task| task.deinit(allocator);
    var dispatch = Dispatch{
        .context = &queue,
        .enqueue = Queue.enqueue,
        .store = "unused",
        .catalog = "unused",
        .visited = .init(allocator),
    };
    defer dispatch.deinit();
    {
        const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, "PSARinput"));
        defer input.release();
        try std.testing.expectError(error.TestQueueFailure, dispatch.inspect(allocator, std.testing.io, "test.psar", input, @splat('a')));
        queue.reject = false;
        try dispatch.inspect(allocator, std.testing.io, "test.psar", input, @splat('a'));
    }
    const task = queue.task orelse return error.MissingQueuedTask;
    try std.testing.expectEqualStrings("PSARinput", task.input.bytes);
}

test "native descendants outlive their parent and never reread their source from the store" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const Queue = struct {
        task: ?Task = null,
        fn enqueue(context: *anyopaque, task: Task) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.task != null) return error.UnexpectedTask;
            self.task = task;
        }
    };
    var queue = Queue{};
    defer if (queue.task) |task| task.deinit(allocator);
    var dispatch = Dispatch{
        .context = &queue,
        .enqueue = Queue.enqueue,
        .store = root,
        .catalog = root,
        .visited = .init(allocator),
    };
    defer dispatch.deinit();
    // Two native SCE wrappers: the second borrows a subrange of the first.
    const payload = "~SCE\x08\x00\x00\x00~SCE\x08\x00\x00\x00plain";
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, payload));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    {
        defer input.release();
        const counts = try process_task(allocator, io, .{ .name = "outer.sce", .input = input, .hash = hash, .kind = .sce }, &dispatch);
        try std.testing.expectEqual(@as(usize, 1), counts.stored);
    }
    // Remove the child's stored source; it must still decode from retained RAM.
    const child = queue.task.?;
    queue.task = null;
    defer child.deinit(allocator);
    const source = try std.fmt.allocPrint(allocator, "sha256/{s}/{s}/{s}", .{ child.hash[0..2], child.hash[2..4], child.hash });
    defer allocator.free(source);
    try tmp.dir.deleteFile(io, source);
    const counts = try process_task(allocator, io, child, &dispatch);
    try std.testing.expectEqual(@as(usize, 1), counts.stored);
    try std.testing.expectEqual(null, queue.task);
}

fn nand_test_pbp(title: []const u8) [640]u8 {
    var bytes: [640]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PBP");
    std.mem.writeInt(u32, bytes[4..8], 0x10000, .little);
    std.mem.writeInt(u32, bytes[8..12], 40, .little);
    for (1..8) |index| std.mem.writeInt(u32, bytes[8 + index * 4 ..][0..4], bytes.len, .little);
    const metadata = bytes[40..];
    @memcpy(metadata[0..4], "\x00PSF");
    std.mem.writeInt(u32, metadata[4..8], 0x101, .little);
    std.mem.writeInt(u32, metadata[8..12], 36, .little);
    // Put the actual title beyond the first FAT cluster, not just filler.
    std.mem.writeInt(u32, metadata[12..16], 560, .little);
    std.mem.writeInt(u32, metadata[16..20], 1, .little);
    std.mem.writeInt(u16, metadata[22..24], 0x204, .little);
    std.mem.writeInt(u32, metadata[24..28], @intCast(title.len + 1), .little);
    std.mem.writeInt(u32, metadata[28..32], @intCast(title.len + 1), .little);
    @memcpy(metadata[36..42], "TITLE\x00");
    @memcpy(metadata[560..][0..title.len], title);
    return bytes;
}

fn nand_test_fat_link(bytes: []u8, cluster: usize, value: u16) void {
    const pair = bytes[512 + cluster + cluster / 2 ..][0..2];
    const old = std.mem.readInt(u16, pair, .little);
    std.mem.writeInt(u16, pair, if (cluster & 1 == 0) (old & 0xf000) | value else (old & 0x000f) | (value << 4), .little);
}

fn nand_test_partition() [8192]u8 {
    var bytes: [8192]u8 = @splat(0);
    std.mem.writeInt(u16, bytes[11..13], 512, .little);
    bytes[13] = 1;
    std.mem.writeInt(u16, bytes[14..16], 1, .little);
    bytes[16] = 1;
    std.mem.writeInt(u16, bytes[17..19], 16, .little);
    std.mem.writeInt(u16, bytes[19..21], 16, .little);
    bytes[21] = 0xf8;
    std.mem.writeInt(u16, bytes[22..24], 1, .little);
    std.mem.writeInt(u16, bytes[510..512], 0xaa55, .little);
    @memcpy(bytes[512..515], &[_]u8{ 0xf8, 0xff, 0xff });
    for ([_]usize{ 2, 3, 4, 7 }, [_]u16{ 3, 0xfff, 7, 0xfff }) |cluster, link| nand_test_fat_link(&bytes, cluster, link);
    for ([_]*const [11]u8{ "CONTIG  PBP", "FRAG    PBP" }, [_]u16{ 2, 4 }, 0..) |name, cluster, index| {
        const record = bytes[1024 + index * 32 ..][0..32];
        @memcpy(record[0..11], name);
        record[11] = 0x20;
        std.mem.writeInt(u16, record[26..28], cluster, .little);
        std.mem.writeInt(u32, record[28..32], 640, .little);
    }
    const contiguous = nand_test_pbp("Contiguous");
    const fragmented = nand_test_pbp("Fragmented");
    @memcpy(bytes[1536..][0..640], &contiguous);
    @memcpy(bytes[2560..][0..512], fragmented[0..512]);
    @memcpy(bytes[4096..][0..128], fragmented[512..]);
    return bytes;
}

test "NAND FAT queued PBP children decode after their partition and walker are gone" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const Queue = struct {
        tasks: std.ArrayList(Task) = .empty,
        fn enqueue(context: *anyopaque, task: Task) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try self.tasks.append(std.testing.allocator, task);
        }
    };
    var queue: Queue = .{};
    defer {
        for (queue.tasks.items) |task| task.deinit(allocator);
        queue.tasks.deinit(allocator);
    }
    var dispatch = Dispatch{ .context = &queue, .enqueue = Queue.enqueue, .store = root, .catalog = root, .visited = .init(allocator) };
    defer dispatch.deinit();
    {
        const fixture = nand_test_partition();
        const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
        defer input.release();
        var inventory = Inventory{ .allocator = allocator, .io = io, .store = root, .dispatch = &dispatch, .paths = .init(allocator) };
        defer inventory.deinit();
        var writer: std.Io.Writer.Discarding = .init(&.{});
        try ingest_nand_partition(&inventory, "flash0.img", input, &writer.writer);
    }
    try std.testing.expectEqual(@as(usize, 2), queue.tasks.items.len);
    for (queue.tasks.items, [_][]const u8{ "Contiguous", "Fragmented" }) |task, title| {
        const counts = try process_task(allocator, io, task, &dispatch);
        try std.testing.expectEqual(@as(usize, 0), counts.extraction_errors);
        const path = try std.fmt.allocPrint(allocator, "pbp/v{s}/{s}-tree.json", .{ revisions.pbp, task.hash });
        defer allocator.free(path);
        const tree_bytes = try tmp.dir.readFileAlloc(io, path, allocator, .unlimited);
        defer allocator.free(tree_bytes);
        const tree = try std.json.parseFromSlice(SavedTree, allocator, tree_bytes, .{ .ignore_unknown_fields = true });
        defer tree.deinit();
        try std.testing.expectEqual(null, tree.value.@"error");
        const entry = for (tree.value.entries) |entry| {
            if (std.mem.eql(u8, entry.path, "PARAM.SFO")) break entry;
        } else return error.MissingSfo;
        const hash = entry.sha256.?;
        const object_path = try std.fmt.allocPrint(allocator, "sha256/{s}/{s}/{s}", .{ hash[0..2], hash[2..4], hash });
        defer allocator.free(object_path);
        const metadata = try tmp.dir.readFileAlloc(io, object_path, allocator, .unlimited);
        defer allocator.free(metadata);
        const expected = nand_test_pbp(title);
        try std.testing.expectEqualSlices(u8, expected[40..], metadata);
        try std.testing.expectEqualStrings(title, (try sfo.parse(allocator, metadata)).title.?);
    }
}

test "NAND late FAT failure stays inline and retains an earlier real file" {
    const allocator = std.testing.allocator;
    var fixture = nand_test_partition();
    nand_test_fat_link(&fixture, 7, 0xff7);
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
    defer input.release();
    var inventory = Inventory{ .allocator = allocator, .io = std.testing.io, .store = null, .dispatch = null, .paths = .init(allocator) };
    defer inventory.deinit();
    var writer: std.Io.Writer.Discarding = .init(&.{});
    try ingest_nand_partition(&inventory, "flash0.img", input, &writer.writer);
    const tree = inventory.entries.items[0].extraction.?;
    try std.testing.expectEqualStrings("FatBadCluster", tree.@"error".?);
    try std.testing.expectEqual(@as(usize, 1), inventory.counts.extraction_errors);
    try std.testing.expectEqual(@as(usize, 1), tree.entries.len);
    try std.testing.expectEqualStrings("CONTIG.PBP", tree.entries[0].path);
    const expected = nand_test_pbp("Contiguous");
    try std.testing.expectEqualStrings(&hash_source(&expected).sha256, &tree.entries[0].sha256.?);
    try std.testing.expectEqual(@as(?u64, expected.len), tree.entries[0].size_bytes);
}

test "NAND FAT callback errors escape even when named like parser errors" {
    const allocator = std.testing.allocator;
    const Queue = struct {
        fn enqueue(_: *anyopaque, _: Task) !void {
            return error.InvalidIsoPath;
        }
    };
    var context: u8 = 0;
    var dispatch = Dispatch{ .context = &context, .enqueue = Queue.enqueue, .store = null, .catalog = "unused", .visited = .init(allocator) };
    defer dispatch.deinit();
    const fixture = nand_test_partition();
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
    defer input.release();
    var inventory = Inventory{ .allocator = allocator, .io = std.testing.io, .store = null, .dispatch = &dispatch, .paths = .init(allocator) };
    defer inventory.deinit();
    var writer: std.Io.Writer.Discarding = .init(&.{});
    try std.testing.expectError(error.InvalidIsoPath, ingest_nand_partition(&inventory, "flash0.img", input, &writer.writer));
    try std.testing.expectEqual(null, inventory.entries.items[0].extraction);
}

test "NAND FAT corrupt CAS child aborts instead of attaching a format error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root);
    const expected = nand_test_pbp("Contiguous");
    const hash = hash_source(&expected).sha256;
    const directory = try std.fmt.allocPrint(allocator, "sha256/{s}/{s}", .{ hash[0..2], hash[2..4] });
    defer allocator.free(directory);
    try tmp.dir.createDirPath(io, directory);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ directory, hash });
    defer allocator.free(path);
    const corrupt = try tmp.dir.createFile(io, path, .{ .exclusive = true });
    defer corrupt.close(io);
    try corrupt.writeStreamingAll(io, "corrupt");
    const fixture = nand_test_partition();
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
    defer input.release();
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = root, .dispatch = null, .paths = .init(allocator) };
    defer inventory.deinit();
    var writer: std.Io.Writer.Discarding = .init(&.{});
    try std.testing.expectError(error.CorruptObject, ingest_nand_partition(&inventory, "flash0.img", input, &writer.writer));
    try std.testing.expectEqual(null, inventory.entries.items[0].extraction);
}

fn nand_test_allocation_failures(allocator: std.mem.Allocator) !void {
    const fixture = nand_test_partition();
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
    defer input.release();
    var inventory = Inventory{ .allocator = allocator, .io = std.testing.io, .store = null, .dispatch = null, .paths = .init(allocator) };
    defer inventory.deinit();
    var writer: std.Io.Writer.Discarding = .init(&.{});
    try ingest_nand_partition(&inventory, "flash0.img", input, &writer.writer);
    const tree = inventory.entries.items[0].extraction.?;
    try std.testing.expectEqual(null, tree.@"error");
    try std.testing.expectEqual(@as(usize, 2), tree.entries.len);
}

test "NAND partition ownership and inline publication unwind every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nand_test_allocation_failures, .{});
}

fn update_test_pbp() [97]u8 {
    var bytes: [97]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x00PBP");
    std.mem.writeInt(u32, bytes[4..8], 0x10000, .little);
    for (0..8) |i| std.mem.writeInt(u32, bytes[8 + i * 4 ..][0..4], if (i == 0) 40 else 93, .little);
    const param = bytes[40..93];
    @memcpy(param[0..4], "\x00PSF");
    std.mem.writeInt(u32, param[4..8], 0x101, .little);
    std.mem.writeInt(u32, param[8..12], 36, .little);
    std.mem.writeInt(u32, param[12..16], 48, .little);
    std.mem.writeInt(u32, param[16..20], 1, .little);
    std.mem.writeInt(u16, param[22..24], 0x204, .little);
    std.mem.writeInt(u32, param[24..28], 5, .little);
    std.mem.writeInt(u32, param[28..32], 5, .little);
    @memcpy(param[36..48], "UPDATER_VER\x00");
    @memcpy(param[48..53], "6.61\x00");
    @memcpy(bytes[93..97], "PSAR");
    return bytes;
}

test "recognized updater replaced before intake remains an update format error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var bytes = update_test_pbp();
    try std.testing.expect(try probe_update(allocator, &bytes));
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, probe_update(failing.allocator(), &bytes));
    // Discovery has already fixed the root role. The current input is hashed
    // and diagnosed as an updater, not ignored or retried as an ISO.
    bytes[0] = 1;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "changed.pbp", .{});
    try file.writeStreamingAll(io, &bytes);
    file.close(io);
    const path = try tmp.dir.realPathFileAlloc(io, "changed.pbp", allocator);
    defer allocator.free(path);
    const result = (try process_file(allocator, io, path, .update, null, null, null, null)).?;
    defer result.deinit(allocator);
    try std.testing.expectEqual(model.RootKind.update, result.kind);
    try std.testing.expectEqualStrings("InvalidPbp", result.@"error".?);
    try std.testing.expect(!result.has_metadata);
    try std.testing.expectEqualStrings(&hash_source(&bytes).sha256, &result.sha256);
}

test "updater queue callback failures remain fatal regardless of error name" {
    const allocator = std.testing.allocator;
    const Queue = struct {
        fn enqueue(_: *anyopaque, _: Task) !void {
            return error.InvalidIsoPath;
        }
    };
    var context: u8 = 0;
    var dispatch = Dispatch{ .context = &context, .enqueue = Queue.enqueue, .store = null, .catalog = "unused", .visited = .init(allocator) };
    defer dispatch.deinit();
    const fixture = update_test_pbp();
    const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
    defer input.release();
    try std.testing.expectError(error.InvalidIsoPath, process_update_checked(allocator, std.testing.io, input, null, null, &dispatch));
}

fn update_test_allocation_failures(allocator: std.mem.Allocator) !void {
    const fixture = update_test_pbp();
    const result = result: {
        const input = try memory.Owner.take_allocated(allocator, try allocator.dupe(u8, &fixture));
        defer input.release();
        break :result (try process_update_checked(allocator, std.testing.io, input, null, null, null)).?;
    };
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("6.61", result.updater_version.?);
    try std.testing.expectEqualStrings(&hash_source(&fixture).sha256, &result.sha256);
}

test "updater metadata survives source release and unwinds every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, update_test_allocation_failures, .{});
}

test {
    _ = umd;
    _ = sfo;
    _ = @import("iso_view.zig");
}
