const std = @import("std");

const USE_LLVM = false;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const compiler_module = b.createModule(.{
        .root_source_file = b.path("../src/export_air.zig"),
        .target = target,
        .optimize = optimize,
    });

    const compiler_options = b.addOptions();
    compiler_module.addOptions("build_options", compiler_options);

    const air_module = b.createModule(.{
        .root_source_file = b.path("src/air.zig"),
        .target = target,
        .optimize = optimize,
    });
    air_module.addImport("compiler", compiler_module);

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("air", air_module);

    const exe = b.addExecutable(.{
        .name = "analyzer",
        .root_module = exe_module,
        .use_llvm = USE_LLVM,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // AIR static library to allow import AIR without directly depending on the full compiler code.
    const air_library = b.addLibrary(.{
        .linkage = .static,
        .name = "analyzer",
        .root_module = air_module,
        .use_llvm = USE_LLVM,
    });
    b.installArtifact(air_library);

    // Tests.
    const lib_unit_tests = b.addTest(.{
        .root_module = air_module,
        .use_llvm = USE_LLVM,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_module,
        .use_llvm = USE_LLVM,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
