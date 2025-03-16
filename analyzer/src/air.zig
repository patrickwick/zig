const std = @import("std");

const compiler = @import("compiler");

pub const DEFAULT_BINARY_AIR_PATH = compiler.DEFAULT_BINARY_AIR_PATH;
pub const Air = compiler.Air;
pub const AirImported = compiler.AirImported;
pub const InternPool = compiler.InternPool;
pub const Liveness = compiler.Liveness;
pub const Value = compiler.Value;
pub const Type = compiler.Type;

pub fn importAir(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported {
    return try compiler.importAir(allocator, reader);
}
