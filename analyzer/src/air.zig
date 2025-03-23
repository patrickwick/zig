const std = @import("std");

const compiler = @import("compiler");

pub const DEFAULT_BINARY_AIR_PATH = compiler.DEFAULT_BINARY_AIR_PATH;
pub const DEFAULT_BINARY_INTERN_POOL_PATH = compiler.DEFAULT_BINARY_INTERN_POOL_PATH;

pub const Air = compiler.Air;
pub const AirImported = compiler.AirImported;
pub const FakeCompilationUnit = compiler.FakeCompilationUnit;
pub const InternPool = compiler.InternPool;
pub const Liveness = compiler.Liveness;
pub const print_air = compiler.print_air;
pub const Type = compiler.Type;
pub const Value = compiler.Value;
pub const Zcu = compiler.Zcu;

pub fn importAir(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported {
    InternPool.ANALYZER = true; // FIXME(pwr): Temporarirly disables compiler functions that are not fully supported yet.
    return try compiler.importAir(allocator, reader);
}

pub fn importAirFunction(target_function: []const u8, allocator: std.mem.Allocator, reader: std.io.AnyReader) !?compiler.AirImported {
    while (true) {
        var function = importAir(allocator, reader) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return err,
        };

        if (std.mem.eql(u8, function.function_name, target_function)) {
            return function;
        } else {
            function.deinit();
        }
    }
}

pub fn importInternPool(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported.InternPoolImported {
    InternPool.ANALYZER = true; // FIXME(pwr): Temporarirly disables compiler functions that are not fully supported yet.
    return try compiler.importInternPool(allocator, reader);
}

// TODO(pwr): add type safe and stable expanded AIR representation (like InternPool creates `Key` when accessing the data).
// => if the overhead of creating this tree is too high, the user can still use the raw data and compiler APIs directly.
pub const AirKey = union(enum) {};
