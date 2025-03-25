const std = @import("std");

const air_lib = @import("air");

pub fn symbolicExecution(air: *const air_lib.Air, intern_pool: *const air_lib.InternPool, main_body: []const air_lib.Air.Inst.Index) void {
    var execution = SymbolicExecution.init(air, intern_pool, main_body);
    execution.execute();
}

const SymbolicExecution = struct {
    air: *const air_lib.Air,
    intern_pool: *const air_lib.InternPool,
    body: []const air_lib.Air.Inst.Index,
    expansion: air_lib.AirExpansion,

    fn init(air: *const air_lib.Air, intern_pool: *const air_lib.InternPool, body: []const air_lib.Air.Inst.Index) @This() {
        std.debug.assert(body.len > 0);
        return .{
            .air = air,
            .intern_pool = intern_pool,
            .body = body,
            .expansion = .init(air, intern_pool, body[0]),
        };
    }

    fn execute(self: *@This()) void {
        var indentation: usize = 0;
        var instruction = self.expansion.nextInstruction();
        while (true) : (instruction = self.expansion.nextInstruction()) {
            // std.log.info("%{d} {s}: {any}", .{ instruction.index, @tagName(instruction.tag), instruction.key });

            indentation += 2;
            defer indentation -= 2;

            switch (instruction.key) {
                .binary_operation => |op| {
                    switch (op.operation) {
                        .store, .store_safe => {
                            // std.log.info("{any} = {any}", .{ op.left, op.right });
                        },
                        else => {},
                    }
                },
                .end_of_instructions => break,
                else => {},
            }
        }
    }
};
