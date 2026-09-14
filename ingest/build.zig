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
    prepare.addFileArg(b.path("../tools/prepare_native.py"));
    prepare.addArgs(&.{ "--normalize", "libkirk/kirk_engine.c", "--normalize", "pspdecrypt_lib.cpp" });
    prepare.addDirectoryArg(decrypt.path(""));
    const native_source = prepare.addOutputDirectoryArg("pspdecrypt");
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-update-xor.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-prx-native.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-prx-coverage.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-kle-native.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-pops-native.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-table-length.patch"));
    prepare.addFileArg(b.path("../tools/patches/pspdecrypt-psar-memory.patch"));
    module.addIncludePath(native_source);
    module.addCSourceFiles(.{
        .root = native_source,
        .files = &.{ "libkirk/kirk_engine.c", "libkirk/amctrl.c", "libkirk/AES.c", "libkirk/SHA1.c", "libkirk/bn.c", "libkirk/ec.c", "kl4e.c", "syscon_ipl_keys.c" },
        .flags = &.{ "-std=c11", "-fno-strict-aliasing" },
    });
    module.addCSourceFile(.{ .file = native_source.path(b, "PrxDecrypter.cpp"), .flags = &.{ "-std=c++17", "-fno-strict-aliasing" } });
    module.addCSourceFile(.{ .file = b.path("src/prx_native.cpp"), .flags = &.{"-std=c++17"} });
    module.addCSourceFile(.{ .file = b.path("src/pops_native.cpp"), .flags = &.{"-std=c++17"} });
    module.addCSourceFile(.{ .file = b.path("src/psar_native.cpp"), .flags = &.{ "-std=c++17", "-fno-strict-aliasing" } });
    module.link_libcpp = true;
    module.addImport("zig_psp_prx_encrypt", b.createModule(.{
        .root_source_file = sdk.path("tools/prxencrypt/prx_encrypt.zig"),
        .target = target,
        .optimize = optimize,
    }));

    const npdata = b.dependency("make_npdata", .{});
    const prepare_edat = b.addSystemCommand(&.{"python3"});
    prepare_edat.addFileArg(b.path("../tools/prepare_native.py"));
    prepare_edat.addArgs(&.{ "--normalize", "Linux/make_npdata.c", "--normalize", "Linux/utils.c" });
    prepare_edat.addDirectoryArg(npdata.path(""));
    const edat_source = prepare_edat.addOutputDirectoryArg("make-npdata");
    prepare_edat.addFileArg(b.path("../tools/patches/make-npdata-safety.patch"));
    prepare_edat.addFileArg(b.path("../tools/patches/make-npdata-memory.patch"));
    module.addIncludePath(edat_source.path(b, "Linux"));
    // Read-only AES tables avoid upstream's unsynchronized first-use setup.
    // Both upstream AES implementations export these CMAC helper names.
    const edat_flags = &.{
        "-std=c11",
        "-fno-strict-aliasing",
        "-DPOLARSSL_AES_ROM_TABLES",
        "-Dxor_128=pspdb_edat_xor_128",
        "-Dleftshift_onebit=pspdb_edat_leftshift_onebit",
        "-Dgenerate_subkey=pspdb_edat_generate_subkey",
        "-Dpadding=pspdb_edat_padding",
    };
    module.addCSourceFiles(.{
        .root = edat_source,
        .files = &.{ "Linux/aes.c", "Linux/sha1.c", "Linux/utils.c" },
        .flags = edat_flags,
    });
    module.addCSourceFile(.{ .file = b.path("src/edat_native.c"), .flags = edat_flags });

    const pkg2zip = b.dependency("pkg2zip", .{});
    const prepare_npumdimg = b.addSystemCommand(&.{"python3"});
    prepare_npumdimg.addFileArg(b.path("../tools/prepare_native.py"));
    prepare_npumdimg.addDirectoryArg(pkg2zip.path(""));
    const npumdimg_source = prepare_npumdimg.addOutputDirectoryArg("pkg2zip");
    prepare_npumdimg.addFileArg(b.path("../tools/patches/pkg2zip-lzrc-safety.patch"));
    prepare_npumdimg.addFileArg(b.path("../tools/patches/pkg2zip-npumdimg-memory.patch"));
    module.addIncludePath(npumdimg_source);
    // Keep pkg2zip's AES symbols private to this codec's namespace, alongside
    // the independent KIRK and make-npdata implementations.
    const npumdimg_flags = &[_][]const u8{
        "-std=c11",
        "-fno-strict-aliasing",
        "-Daes128_init=pspdb_npumdimg_aes128_init",
        "-Daes128_init_dec=pspdb_npumdimg_aes128_init_dec",
        "-Daes128_ecb_encrypt=pspdb_npumdimg_aes128_ecb_encrypt",
        "-Daes128_ecb_decrypt=pspdb_npumdimg_aes128_ecb_decrypt",
        "-Daes128_ctr_xor=pspdb_npumdimg_aes128_ctr_xor",
        "-Daes128_cmac=pspdb_npumdimg_aes128_cmac",
        "-Daes128_psp_decrypt=pspdb_npumdimg_aes128_psp_decrypt",
        "-Daes128_init_x86=pspdb_npumdimg_aes128_init_x86",
        "-Daes128_init_dec_x86=pspdb_npumdimg_aes128_init_dec_x86",
        "-Daes128_ecb_encrypt_x86=pspdb_npumdimg_aes128_ecb_encrypt_x86",
        "-Daes128_ecb_decrypt_x86=pspdb_npumdimg_aes128_ecb_decrypt_x86",
        "-Daes128_ctr_xor_x86=pspdb_npumdimg_aes128_ctr_xor_x86",
        "-Daes128_cmac_process_x86=pspdb_npumdimg_aes128_cmac_process_x86",
        "-Daes128_psp_decrypt_x86=pspdb_npumdimg_aes128_psp_decrypt_x86",
    };
    module.addCSourceFile(.{ .file = npumdimg_source.path(b, "pkg2zip_aes.c"), .flags = npumdimg_flags });
    if (target.result.cpu.arch == .x86 or target.result.cpu.arch == .x86_64) {
        module.addCSourceFile(.{
            .file = npumdimg_source.path(b, "pkg2zip_aes_x86.c"),
            .flags = npumdimg_flags ++ &[_][]const u8{ "-maes", "-mssse3" },
        });
    }
    module.addCSourceFile(.{ .file = b.path("src/npumdimg_native.c"), .flags = npumdimg_flags });

    const rcomage = b.dependency("rcomage", .{});
    const rco_files = b.addWriteFiles();
    for ([_][]const u8{ "tagmap.ini", "miscmap.ini", "objattribdef-psp.ini", "objattribdef-ps3.ini", "animattribdef-psp.ini", "animattribdef-ps3.ini" }) |name| {
        _ = rco_files.addCopyFile(rcomage.path(b.fmt("data/{s}", .{name})), name);
    }
    const rco_config = rco_files.add("rco_config.zig",
        \\pub const tagmap = @embedFile("tagmap.ini");
        \\pub const miscmap = @embedFile("miscmap.ini");
        \\pub const objattribdef_psp = @embedFile("objattribdef-psp.ini");
        \\pub const objattribdef_ps3 = @embedFile("objattribdef-ps3.ini");
        \\pub const animattribdef_psp = @embedFile("animattribdef-psp.ini");
        \\pub const animattribdef_ps3 = @embedFile("animattribdef-ps3.ini");
        \\
    );
    module.addImport("rco_config", b.createModule(.{
        .root_source_file = rco_config,
        .target = target,
        .optimize = optimize,
    }));

    module.addAnonymousImport("extractor_adapter", .{ .root_source_file = b.path("../tools/extract_external.py") });

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
    module.linkSystemLibrary("z", .{});
    module.linkSystemLibrary("expat", .{ .use_pkg_config = .force });
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
