const std = @import("std");

const air_lib = @import("air");
const Air = air_lib.Air;

// pub const Options = struct {
//     version: i32,
//     have_llvm: bool,
// };
//
// pub const options = Options{
//     .version = 123,
//     .have_llvm = false,
// };

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

    var intern_pool: air_lib.InternPool = .empty;
    const thread_count = 1;
    try intern_pool.init(arena_allocator, thread_count);
    defer intern_pool.deinit(arena_allocator);

    const air_file_path = "../" ++ air_lib.DEFAULT_BINARY_AIR_PATH;
    const air_file = try std.fs.cwd().openFile(air_file_path, .{});
    defer air_file.close();

    // Iterate functions until the end of the stream is reached or the target function is found.
    const target_function = "test.main";
    const reader = air_file.reader().any();
    const air_optional = while (true) {
        // TODO: create a function to search a file -> peek the function names only without reading all functions.
        // TODO: return optional to indicate end of stream without an error.
        const air_function = air_lib.importAir(arena_allocator, reader) catch |err| switch (err) {
            error.EndOfStream => break null,
            else => return err,
        };

        if (std.mem.eql(u8, air_function.function_name, target_function)) break air_function;
    };

    const air_import: air_lib.AirImported = air_optional orelse {
        std.log.err("target function \"{s}\" not found in AIR file \"{s}\"", .{ target_function, air_file_path });
        return error.TargetFunctionNotFound;
    };

    // TODO(pwr): some of the internal functions are skipped due to missing exported data.
    {
        try out.print("InternPool dump:\n", .{});
        air_import.intern_pool.dump();
        try out.print("InternPool dumpGenericInstances:", .{});
        air_import.intern_pool.dumpGenericInstances(arena_allocator);
        try out.print("\n\n", .{});
    }

    air_lib.print_air.dump(air_import.zcu_main_thread, air_import.air, air_import.liveness);
}
