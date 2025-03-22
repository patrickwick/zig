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
    return try compiler.importAir(allocator, reader);
}

pub fn importInternPool(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported.InternPoolImported {
    return try compiler.importInternPool(allocator, reader);
}
