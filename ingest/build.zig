const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Patch an output copy; never mutate Zig's dependency cache.
    const sdk = b.dependency("zig_psp", .{ .target = target, .optimize = optimize });
    const patch_pbp = b.addSystemCommand(&.{ "patch", "--silent", "--output" });
    const pbp_source = patch_pbp.addOutputFileArg("pbp.zig");
    patch_pbp.addFileArg(sdk.path("tools/pbp/src/main.zig"));
    patch_pbp.addFileArg(b.path("../tools/patches/zig-psp-pbp-memory.patch"));
    module.addImport("zig_psp_pbp", b.createModule(.{
        .root_source_file = pbp_source,
        .target = target,
        .optimize = optimize,
    }));

    const patch_sfo = b.addSystemCommand(&.{ "patch", "--silent", "--output" });
    const sfo_source = patch_sfo.addOutputFileArg("sfo.zig");
    patch_sfo.addFileArg(sdk.path("tools/sfo/src/main.zig"));
    patch_sfo.addFileArg(b.path("../tools/patches/zig-psp-sfo-memory.patch"));
    module.addImport("zig_psp_sfo", b.createModule(.{
        .root_source_file = sfo_source,
        .target = target,
        .optimize = optimize,
    }));

    const decrypt = b.dependency("pspdecrypt", .{});
    const prepare = b.addSystemCommand(&.{"python3"});
    prepare.addFileArg(b.path("../tools/prepare_pspdecrypt.py"));
    prepare.addDirectoryArg(decrypt.path(""));
    const native_source = prepare.addOutputDirectoryArg("pspdecrypt");
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-update-xor.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-prx-native.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-prx-coverage.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-kle-native.patch"));
    module.addIncludePath(native_source);
    module.addCSourceFiles(.{
        .root = native_source,
        .files = &.{ "libkirk/kirk_engine.c", "libkirk/AES.c", "libkirk/SHA1.c", "libkirk/bn.c", "libkirk/ec.c", "kl4e.c" },
        .flags = &.{ "-std=c11", "-fno-strict-aliasing" },
    });
    module.addCSourceFile(.{ .file = native_source.path(b, "PrxDecrypter.cpp"), .flags = &.{ "-std=c++17", "-fno-strict-aliasing" } });
    module.addCSourceFile(.{ .file = b.path("src/prx_native.cpp"), .flags = &.{"-std=c++17"} });
    module.link_libcpp = true;
    module.addImport("zig_psp_prx_encrypt", b.createModule(.{
        .root_source_file = sdk.path("tools/prxencrypt/prx_encrypt.zig"),
        .target = target,
        .optimize = optimize,
    }));

    module.addAnonymousImport("extractor_adapter", .{ .root_source_file = b.path("../tools/extract_external.py") });
    module.addAnonymousImport("rap", .{ .root_source_file = b.path("../tools/rap.py") });

    module.addAnonymousImport("catalog_status", .{ .root_source_file = b.path("../tools/catalog_status.py") });
    module.addAnonymousImport("extractor_versions_json", .{ .root_source_file = b.path("../tools/extractor_versions.json") });
    module.addAnonymousImport("contextual_extractors_json", .{ .root_source_file = b.path("../website/pspdb/data/contextual_extractors.json") });
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
    module.linkSystemLibrary("crypto", .{});
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
