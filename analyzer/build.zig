const std = @import("std");

const USE_LLVM = false;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const single_threaded = b.option(bool, "single-threaded", "Build artifacts that run in single threaded mode");

    // NOTE: compiler options required to create a fake Zcu compilation unit.
    const compiler_options = b.addOptions();
    compiler_options.addOption(bool, "have_llvm", USE_LLVM);
    compiler_options.addOption([:0]const u8, "version", "0.15.0");
    compiler_options.addOption(std.SemanticVersion, "semver", .{ .major = 0, .minor = 15, .patch = 0 });
    compiler_options.addOption(bool, "enable_tracy", false);
    compiler_options.addOption(bool, "enable_debug_extensions", true);
    compiler_options.addOption(bool, "enable_logging", true);
    const ValueInterpretMode = enum { direct, by_name };
    compiler_options.addOption(ValueInterpretMode, "value_interpret_mode", .by_name);

    const compiler_module = b.createModule(.{
        .root_source_file = b.path("../src/export_air.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
    });
    compiler_module.addOptions("build_options", compiler_options);

    const air_module = b.createModule(.{
        .root_source_file = b.path("src/air.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
    });
    air_module.addImport("compiler", compiler_module);

    // TODO(pwr): use air static library instead of module directly to make compilation faster (caching the static lib).
    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = single_threaded,
    });
    exe_module.addImport("air", air_module);

    const exe = b.addExecutable(.{
        .name = "analyzer",
        .root_module = exe_module,
        .use_llvm = USE_LLVM,
        .single_threaded = single_threaded,
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
        .single_threaded = single_threaded,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_module,
        .use_llvm = USE_LLVM,
        .single_threaded = single_threaded,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
