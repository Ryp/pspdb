const std = @import("std");

const containers = @import("containers.zig");
const gzip = @import("gzip.zig");
const prx = @import("prx.zig");
const pops = @import("pops.zig");
const kle = @import("kle.zig");
const npumdimg = @import("npumdimg.zig");
const edat = @import("edat.zig");
const psar = @import("psar.zig");
const rco = @import("rco.zig");
const catalog_io = @import("catalog.zig");
const pkg = @import("pkg.zig");
const data_psp = @import("data_psp.zig");
const revisions = @import("extractor_versions");
const licenses = @import("licenses.zig");
const memory = @import("bytes.zig");
const iso = @import("iso_reader.zig");
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

/// Shared by one ISO's jobs; only discovery deduplication needs this lock.
/// enqueue takes ownership of a task on success only.
pub const Dispatch = struct {
    context: *anyopaque,
    enqueue: *const fn (*anyopaque, Task) anyerror!void,
    store: ?[]const u8,
    catalog: []const u8,
    state: ?*const CatalogState = null,
    rap_directory: ?[]const u8 = null,
    mutex: std.Io.Mutex = .init,
    visited: std.AutoHashMap([64]u8, void),

    fn inspect(self: *Dispatch, allocator: std.mem.Allocator, io: std.Io, name: []const u8, input: memory.View, hash: [64]u8) !void {
        const kind = extractor.detect(input.bytes) orelse return;
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

pub const Counts = struct { stored: usize = 0, reused: usize = 0 };

fn hash_source(bytes: []const u8) struct { sha256: [64]u8, sha1: [40]u8 } {
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
        if (try catalog_io.contains(allocator, io, root, hashes.sha256, bytes.len, "iso")) return null;
    }
    var result = try read_metadata(allocator, bytes);
    errdefer result.deinit(allocator);
    var inventory = Inventory{ .allocator = allocator, .io = io, .store = store, .dispatch = dispatch, .pair_documents = true, .paths = .init(allocator) };
    defer inventory.deinit();
    try iso.walk(allocator, bytes, &inventory, Inventory.emit_view);
    try inventory.extract_documents();
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    result.entries = try inventory.finish();
    result.sha256 = hashes.sha256;
    result.sha1 = hashes.sha1;
    return result;
}

/// PKGs are roots just like ISOs; decrypted entries retain their own backing
/// buffers so the existing extraction queue can outlive the package walk.
pub fn process_pkg_checked(allocator: std.mem.Allocator, io: std.Io, bytes: []const u8, store: ?[]const u8, cache: ?catalog_io.Cache, dispatch: ?*Dispatch) !?Result {
    const package = try pkg.Package.init(bytes);
    const hashes = hash_source(bytes);
    if (cache) |value| {
        if (try catalog_io.contains(allocator, io, value, hashes.sha256, bytes.len, "pkg")) return null;
    }
    var result: Result = .{
        .kind = .pkg,
        .size_bytes = bytes.len,
        .sha256 = hashes.sha256,
        .sha1 = hashes.sha1,
        .content_type = package.content_type,
        .package_flags = package.package_flags,
    };
    errdefer result.deinit(allocator);
    result.content_id = try allocator.dupe(u8, package.content_id);
    if (try package.read_file(allocator, "PARAM.SFO")) |metadata| {
        result.pkg_sfo_bytes = metadata;
        if (metadata.len == 0) return error.InvalidSfo;
        result.metadata = try sfo.parsePkg(allocator, metadata, &result.pkg_title);
    } else if (package.content_type != 9) {
        // PSP theme PKGs can contain only a theme payload, with no SFO or PBP.
        return error.MissingPkgMetadata;
    }
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
            const parsed = try containers.parse_pbp(view.bytes);
            self.result.pbp_sfo_bytes = try self.inventory.allocator.dupe(u8, parsed.get("PARAM.SFO").?);
            const inner = try sfo.parsePkg(self.inventory.allocator, self.result.pbp_sfo_bytes, &self.result.pbp_title);
            self.result.metadata = .{ .title = inner.title orelse self.result.metadata.title, .disc_id = inner.disc_id, .disc_version = inner.disc_version, .required_firmware = inner.required_firmware };
        }
    };
    var context = PackageInventory{ .inventory = &inventory, .result = &result };
    try package.walk(allocator, &context, PackageInventory.emit);
    try inventory.extract_documents();
    result.entries = try inventory.finish();
    result.stored = inventory.counts.stored;
    result.reused = inventory.counts.reused;
    return result;
}

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
        const dispatch = self.dispatch orelse return;
        for (self.documents.items) |index| {
            const entry = &self.entries.items[index];
            const prefix = entry.path[0 .. entry.path.len - "DOCUMENT.DAT".len];
            const companion_path = try std.fmt.allocPrint(self.allocator, "{s}DOCINFO.EDAT", .{prefix});
            var attached = false;
            defer if (!attached) self.allocator.free(companion_path);
            const companion_index = self.paths.get(companion_path) orelse continue;
            const companion = self.entries.items[companion_index];
            if (companion.type != .file or companion.size_bytes.? != 304) return error.InvalidDocinfo;
            if (entry.size_bytes.? > 64 * 1024 * 1024) return error.InvalidDocument;
            const source_input = self.document_inputs.get(index) orelse return error.InvalidDocument;
            const companion_input = self.document_inputs.get(companion_index) orelse return error.InvalidDocinfo;
            const output = try external_extractor.extract(self.allocator, self.io, entry.sha256.?, source_input.bytes, .document, companion_input.bytes);
            // The inline tree takes the parsed provenance; temporary output
            // files still disappear after their immediate inventory walk.
            defer {
                std.Io.Dir.cwd().deleteTree(self.io, output.path) catch {};
                self.allocator.free(output.path);
                if (!attached) output.provenance.deinit();
            }
            var child = Inventory{ .allocator = self.allocator, .io = self.io, .store = dispatch.store, .dispatch = dispatch, .paths = .init(self.allocator) };
            defer child.deinit();
            try output.walk(self.allocator, self.io, &child, Inventory.emit_view);
            const tree = try self.allocator.create(InlineExtraction);
            errdefer self.allocator.destroy(tree);
            const hash = try self.allocator.dupe(u8, &entry.sha256.?);
            errdefer self.allocator.free(hash);
            const dependencies = try self.allocator.alloc(Dependency, 1);
            errdefer self.allocator.free(dependencies);
            const companion_hash = try self.allocator.dupe(u8, &companion.sha256.?);
            errdefer self.allocator.free(companion_hash);
            dependencies[0] = .{ .path = companion_path, .sha256 = companion_hash, .size_bytes = companion.size_bytes.? };
            tree.* = .{
                .sha256 = hash,
                .size_bytes = entry.size_bytes.?,
                .extractor = output.provenance.value,
                .name_rule = "identity",
                .entries = try child.finish(),
                .dependencies = dependencies,
                .owned_provenance = output.provenance,
            };
            entry.extraction = tree;
            attached = true;
            self.counts.stored += child.counts.stored;
            self.counts.reused += child.counts.reused;
        }
    }

    fn finish(self: *Inventory) ![]Entry {
        for (self.entries.items) |entry| {
            if (std.mem.lastIndexOfScalar(u8, entry.path, '/')) |slash| {
                const parent = self.paths.get(entry.path[0..slash]) orelse return error.MissingIsoDirectory;
                if (self.entries.items[parent].type != .directory) return error.InvalidIsoPath;
            }
        }
        std.mem.sort(Entry, self.entries.items, {}, struct {
            fn less(_: void, a: Entry, b: Entry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.less);
        return self.entries.toOwnedSlice(self.allocator);
    }
};

/// Process only this extraction's immediate tree. Descendants go to Dispatch.
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
    const provenance: extractor.Provenance = switch (task.kind) {
        .edat => blk: {
            const bytes = edat.decode(allocator, task.input.bytes, null) catch |err| switch (err) {
                error.MissingEdatRap => retry: {
                    const directory = dispatch.rap_directory orelse return error.MissingEdatRap;
                    const content_id = try edat.content_id(task.input.bytes);
                    var rap = licenses.read_rap(io, directory, content_id) catch |key_error| {
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
            try inventory.emit_view("payload.DAT", view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.edat };
        },
        .gzip, .prx, .kl3e, .kl4e, .npumdimg => blk: {
            const bytes = try switch (task.kind) {
                .gzip => gzip.decode(allocator, task.input.bytes),
                .prx => prx.decode(allocator, task.input.bytes),
                .kl3e, .kl4e => kle.decode(allocator, task.input.bytes),
                .npumdimg => npumdimg.decode(allocator, task.input.bytes),
                else => unreachable,
            };
            const view = try memory.Owner.take_allocated(allocator, bytes);
            defer view.release();
            const name: []const u8 = if (task.kind == .npumdimg)
                "disc.iso"
            else if (std.mem.startsWith(u8, bytes, "\x7fELF"))
                "module.elf"
            else if (task.kind != .prx and std.mem.startsWith(u8, bytes, "\x1f\x8b\x08"))
                "payload.gz"
            else
                "payload.bin";
            try inventory.emit_view(name, view);
            const revision = switch (task.kind) {
                inline .gzip, .prx, .kl3e, .kl4e, .npumdimg => |kind| @field(revisions, @tagName(kind)),
                else => unreachable,
            };
            break :blk .{ .name = "pspdb-ingest", .version = revision };
        },
        .psar => blk: {
            try psar.walk(allocator, task.input, &inventory, Inventory.emit_view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.psar };
        },
        .rco => blk: {
            try rco.walk(allocator, task.input, &inventory, Inventory.emit_view);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.rco };
        },
        .iso9660 => blk: {
            try iso.walk(allocator, task.input.bytes, &inventory, Inventory.emit_view);
            try inventory.extract_documents();
            break :blk .{ .name = "pspdb-ingest", .version = revisions.iso9660 };
        },
        .sce => blk: {
            try containers.walk_sce(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.sce };
        },
        .vmp => blk: {
            try containers.walk_vmp(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.vmp };
        },
        .elf => blk: {
            try containers.walk_elf(task.input.bytes, &inventory, Inventory.emit);
            break :blk .{ .name = "pspdb-ingest", .version = revisions.elf };
        },
        .pbp => blk: {
            const pbp = try containers.parse_pbp(task.input.bytes);
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
            try containers.walk_pbp(task.input.bytes, &inventory, Inventory.emit);
            if (is_pops) inline for (.{ .{ extractor.Kind.pops, "DATA.PSP" }, .{ extractor.Kind.psx, "DATA.BIN" } }) |section| {
                // Sibling/container context stays attached to its source section.
                var child = Inventory{ .allocator = allocator, .io = io, .store = dispatch.store, .dispatch = dispatch, .paths = .init(allocator) };
                defer child.deinit();
                const section_provenance: extractor.Provenance = if (section[0] == .pops) native: {
                    const bytes = try pops.decode(allocator, pbp.get("DATA.PSP") orelse return error.MissingDataPsp, data_bin);
                    const view = try memory.Owner.take_allocated(allocator, bytes);
                    defer view.release();
                    const name: []const u8 = if (std.mem.startsWith(u8, bytes, "\x7fELF")) "module.elf" else "payload.gz";
                    try child.emit_view(name, view);
                    break :native .{ .name = "pspdb-pops", .version = revisions.pops, .options = &.{"in-memory"} };
                } else external: {
                    output = try external_extractor.extract(allocator, io, task.hash, task.input.bytes, .psx, null);
                    try output.?.walk(allocator, io, &child, Inventory.emit_view);
                    break :external output.?.provenance.value;
                };
                const index = inventory.paths.get(section[1]) orelse return error.MissingDataPsp;
                const entry = &inventory.entries.items[index];
                const tree = try allocator.create(InlineExtraction);
                errdefer allocator.destroy(tree);
                const hash = try allocator.dupe(u8, &entry.sha256.?);
                errdefer allocator.free(hash);
                tree.* = .{ .sha256 = hash, .size_bytes = entry.size_bytes.?, .extractor = section_provenance, .name_rule = if (section[0] == .psx) "identity" else "source_stem", .entries = try child.finish() };
                entry.extraction = tree;
                inventory.counts.stored += child.counts.stored;
                inventory.counts.reused += child.counts.reused;
            };
            break :blk .{ .name = "Zig-PSP zPBPTool", .version = revisions.pbp, .options = &.{"in-memory"} };
        },
        else => blk: {
            output = try external_extractor.extract(allocator, io, task.hash, task.input.bytes, task.kind, null);
            try output.?.walk(allocator, io, &inventory, Inventory.emit_view);
            break :blk output.?.provenance.value;
        },
    };
    const entries = try inventory.finish();
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    try catalog_io.publish_extraction(allocator, io, dispatch.catalog, task.hash, task.input.bytes.len, entries, provenance, @tagName(task.kind));
    return inventory.counts;
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
    return reuse_entries(allocator, io, parsed.value.entries, dispatch, task.kind == .iso9660);
}

const SavedEntry = struct { path: []const u8, type: []const u8, sha256: ?[]const u8 = null, size_bytes: ?u64 = null, extraction: ?SavedTree = null };
const SavedTree = struct { sha256: []const u8, size_bytes: u64, entries: []SavedEntry, dependencies: []Dependency = &.{} };

fn reuse_entries(allocator: std.mem.Allocator, io: std.Io, entries: []SavedEntry, dispatch: *Dispatch, pair_documents: bool) anyerror!?Counts {
    const store = dispatch.store orelse return null;
    var counts: Counts = .{};
    for (entries) |entry| {
        try validate_path(entry.path);
        if (std.mem.eql(u8, entry.type, "directory")) continue;
        const hash = entry.sha256 orelse return error.CatalogConflict;
        try validate_hash(hash);
        if (entry.extraction) |tree| {
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
pub fn process_file(allocator: std.mem.Allocator, io: std.Io, path: []const u8, store: ?[]const u8, catalog: ?catalog_io.Cache, dispatch: ?*Dispatch) !?Result {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    });
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    if (stat.size == 0) return error.EmptyFile;
    const size = std.math.cast(usize, stat.size) orelse return error.FileTooLarge;

    const mapping = try std.posix.mmap(null, size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, file.handle, 0);
    const input = try memory.Owner.take_mapped(allocator, mapping);
    defer input.release();
    const result = if (std.ascii.endsWithIgnoreCase(path, ".pkg"))
        try process_pkg_checked(allocator, io, mapping, store, catalog, dispatch)
    else
        try process_iso_checked(allocator, io, mapping, store, catalog, dispatch);
    errdefer if (result) |value| value.deinit(allocator);
    const after = try file.stat(io);
    if (stat.size != after.size or stat.mtime.nanoseconds != after.mtime.nanoseconds or stat.ctime.nanoseconds != after.ctime.nanoseconds) return error.SourceChanged;
    return result;
}

test "processor rejects non-ISO bytes" {
    try std.testing.expectError(error.EmptyFile, process_iso(std.testing.allocator, std.testing.io, "", null));
    try std.testing.expectError(error.InvalidIso, process_iso(std.testing.allocator, std.testing.io, "not an ISO", null));
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
    defer dispatch.visited.deinit();
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
    defer dispatch.visited.deinit();
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

test {
    _ = umd;
    _ = sfo;
    _ = @import("iso_view.zig");
}
