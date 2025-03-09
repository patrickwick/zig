const std = @import("std");

const compiler = @import("compiler");

pub fn importAir(allocator: std.mem.Allocator, reader: std.io.AnyReader) !compiler.AirImported {
    return try compiler.importAir(allocator, reader);
}
