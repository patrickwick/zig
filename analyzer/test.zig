const std = @import("std");

// Guess what happens when running `zig run ./test.zig`.
pub fn main() void {
    var a: usize = 5;
    a *= 2;
    const b = 1 / (a - a);
    std.log.info("1 / ({} - {}) = {}", .{ a, a, b });
}
