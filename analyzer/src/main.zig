// Simple PoC to demonstrate:
// * Importing the binary AIR representation emittted while compiling a program.
// * Using imported AIR to create the same debug output as --verbose-air provides within the compiler.
// * Detect division by zero as a simple PoC using symbolic execution.
// * TODO(pwr): maybe:
//   * Stable iterator over expanded AIR instructions to tagged unions -> type safe + stable over Zig versions.
//   * Integrate CLR to perform additional checks -> would be nice to know how fast it is.
//   * Allow -fincremental usage with analysis -> would be amazing for clangd style fast interaction on save.
//     * Experimental web interface for simple division by zero analysis.

const std = @import("std");

const air_lib = @import("air");
const Air = air_lib.Air;

pub fn main() !void {
    const stdout = std.io.getStdOut();
    const out = stdout.writer();

    var gpa = std.heap.GeneralPurposeAllocator(.{
        .safety = true,
        .verbose_log = false,
    }){};
    defer {
        const check = gpa.deinit();
        switch (check) {
            .ok => {},
            .leak => _ = gpa.detectLeaks(),
        }
    }

    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const air_file_path = "../" ++ air_lib.DEFAULT_BINARY_AIR_PATH;
    const air_file = try std.fs.cwd().openFile(air_file_path, .{});
    defer air_file.close();

    const ip_file_path = "../" ++ air_lib.DEFAULT_BINARY_INTERN_POOL_PATH;
    const ip_file = try std.fs.cwd().openFile(ip_file_path, .{});
    defer ip_file.close();

    // Iterate functions until the end of the stream is reached or the target function is found.
    const target_function = "test.main";
    const air_import = try air_lib.importAirFunction(target_function, arena_allocator, air_file.reader().any()) orelse {
        std.log.err("target function \"{s}\" not found in AIR file \"{s}\"", .{ target_function, air_file_path });
        return error.TargetFunctionNotFound;
    };

    // TODO(pwr): temporarily importing the full intern pool and overwriting the function local one.
    // This is required to have data about all compiled modules, not just the analyzed function.
    // => Not sure what the best approach is here yet.
    const intern_pool_import = try air_lib.importInternPool(arena_allocator, ip_file.reader().any());
    const intern_pool = &intern_pool_import.intern_pool;
    air_import.zcu_main_thread.zcu.intern_pool = intern_pool.*;

    // TODO(pwr): some of the internal functions are skipped due to missing exported data.
    if (false) {
        try out.print("InternPool dump:\n", .{});
        intern_pool.dump();
        try out.print("InternPool dumpGenericInstances:", .{});
        intern_pool.dumpGenericInstances(arena_allocator);
        try out.print("\n\n", .{});
    }

    const main_body = air_import.air.getMainBody();

    // TODO(pwr): some of the internal functions are skipped due to missing exported data.
    air_lib.print_air.dump(air_import.zcu_main_thread, air_import.air, air_import.liveness);

    std.log.info("Iteration:", .{});
    var iterator = air_lib.AirExpansion.init(&air_import.air, intern_pool, main_body[0]);
    var instruction = iterator.get();
    while (true) : (instruction = iterator.nextInstruction()) {
        std.log.info("{any}", .{instruction});

        switch (instruction.key) {
            .end_of_instructions => break,
            else => {},
        }
    }

    // Sybolic execution prototype.
    {
        // TODO(pwr): NYI.
    }
}
