const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    module.addAnonymousImport("extractor_adapter", .{ .root_source_file = b.path("../tools/extract_external.py") });

    module.addAnonymousImport("catalog_status", .{ .root_source_file = b.path("../tools/catalog_status.py") });
    module.addAnonymousImport("extractor_versions_json", .{ .root_source_file = b.path("../tools/extractor_versions.json") });
    const revisions = b.addOptions();
    const revision_bytes = std.Io.Dir.cwd().readFileAlloc(b.graph.io, b.pathFromRoot("../tools/extractor_versions.json"), b.allocator, .unlimited) catch @panic("Cannot read extractor revisions");
    const parsed = std.json.parseFromSlice(std.json.Value, b.allocator, revision_bytes, .{}) catch @panic("Invalid extractor revisions");
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const revision = entry.value_ptr.string;
        const number = std.fmt.parseInt(u32, revision, 10) catch @panic("Extractor revisions must be positive integers");
        if (number == 0 or revision[0] == '0') @panic("Extractor revisions must be canonical positive integers");
        revisions.addOption([]const u8, entry.key_ptr.*, revision);
    }
    module.addOptions("extractor_versions", revisions);

    const archive = b.addTranslateC(.{
        .root_source_file = b.path("src/archive.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("archive", archive.createModule());
    module.linkSystemLibrary("archive", .{});
    module.link_libc = true;

    const exe = b.addExecutable(.{ .name = "pspdb-ingest", .root_module = module });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run.addArgs(args);
    }

    b.step("run", "Hash and store files from ISO and ZIP inputs").dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = module });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
