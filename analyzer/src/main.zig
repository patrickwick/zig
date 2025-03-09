const std = @import("std");

const air = @import("air");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .safety = true,
        .verbose_log = true,
        .enable_memory_limit = true,
    }){
        .requested_memory_limit = 10 * 4096,
    };
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

    const air_file_path = "../air_export.bair";
    const air_file = try std.fs.cwd().openFile(air_file_path, .{});
    defer air_file.close();

    const reader = air_file.reader().any();
    // TODO(pwr): iterate functions
    const air_function = try air.importAir(arena_allocator, reader);
    std.log.info("AIR \"{s}\":\n{any}", .{ air_function.function_name, air_function });

    // TODO(pwr): import AIR and perform some example static analysis as a PoC.

    // TODO(pwr): how can source locations be traced back? Using the `dbg_stmt` instructions?
    // * What is the meaning of the two integers?
    // * What additional information is required?
}
