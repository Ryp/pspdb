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
