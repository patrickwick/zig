const std = @import("std");

const air_lib = @import("air");
const Air = air_lib.Air;

/// Simple PoC to demonstrate:
/// * importing the binary AIR representation emittted while compiling a program.
/// * using imported AIR to create the same debug output as --verbose-air provides within the compiler.
/// * detect division by zero as a simple PoC using symbolic execution.
/// * TODO(pwr): maybe integrate CLR to perform additional checks -> would be nice to know how fast it is.
pub fn main() !void {
    air_lib.InternPool.ANALYZER = true; // FIXME(pwr): remove. Temporarirly disabled functions that are not yet supported.

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
    const air_optional = while (true) {
        // TODO: create a function to search a file -> peek the function names only without reading all functions.
        // TODO: return optional to indicate end of stream without an error.
        const air_function = air_lib.importAir(arena_allocator, air_file.reader().any()) catch |err| switch (err) {
            error.EndOfStream => break null,
            else => return err,
        };

        if (std.mem.eql(u8, air_function.function_name, target_function)) break air_function;
    };

    const air_import: air_lib.AirImported = air_optional orelse {
        std.log.err("target function \"{s}\" not found in AIR file \"{s}\"", .{ target_function, air_file_path });
        return error.TargetFunctionNotFound;
    };

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

    // TODO(pwr): some of the internal functions are skipped due to missing exported data.
    air_lib.print_air.dump(air_import.zcu_main_thread, air_import.air, air_import.liveness);

    // Sybolic execution prototype.
    {
        // TODO(pwr): NYI.
    }
}
