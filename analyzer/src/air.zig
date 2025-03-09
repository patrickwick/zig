const std = @import("std");

const compiler = @import("compiler");

pub const DEFAULT_BINARY_AIR_PATH = compiler.DEFAULT_BINARY_AIR_PATH;

pub fn importAir(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported {
    return try compiler.importAir(allocator, reader);
}
