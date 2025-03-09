const std = @import("std");

const air_lib = @import("air");

pub fn main() !void {
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

    const main_body_indexes = air_import.air.getMainBody();
    std.log.info(
        \\AIR function "{s}":
        \\main body indexes: {any}
        \\{any}
    , .{ air_import.function_name, main_body_indexes, air_import.air });

    // Detect division by zero as a simple PoC using symbolic execution.
    {
        // TODO(pwr): add store for variables.
        // TODO(pwr): how can identifiers be traced back? Using only the `dbg_x` instructions?
        // * Is any additional information required or does the fully qualified name, source code and AIR suffice?

        const tags = air_import.instructions_owned.items(.tag);
        const data = air_import.instructions_owned.items(.data);
        for (main_body_indexes) |instruction_index| {
            const i = @intFromEnum(instruction_index);
            const tag = tags[i];
            const variant = data[i];

            // TODO(pwr): dereference the `Air.Inst.Ref` from intern pool => not exported yet.
            // NOTE: see Air.Inst.Tag for documentation on the mapping.
            switch (tag) {
                .dbg_stmt => {
                    const debug_statement = variant.dbg_stmt;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, debug_statement });
                },
                .dbg_var_ptr => {
                    const payload_operand = variant.pl_op;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, payload_operand });
                },
                .dbg_var_val => {
                    const payload_operand = variant.pl_op;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, payload_operand });
                },
                .store, .store_safe => {
                    const binary_operation = variant.bin_op;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, binary_operation });
                },
                .load => {
                    const type_operand = variant.ty_op;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, type_operand });
                },
                .mul_with_overflow => {
                    const type_payload = variant.ty_pl;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, type_payload });
                },
                .sub_with_overflow => {
                    const type_payload = variant.ty_pl;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, type_payload });
                },
                .div_trunc => {
                    const binary_operation = variant.bin_op;
                    std.log.info("{} {}: {}", .{ instruction_index, tag, binary_operation });
                },
                // TODO(pwr): implement all instructions.
                else => std.log.info("{} {}", .{ instruction_index, tag }),
            }
        }
    }
}
