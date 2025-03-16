const std = @import("std");

const air_lib = @import("air");

/// Simple PoC to demonstrate:
/// * importing the binary AIR representation emittted while compiling a program.
/// * using imported AIR to create the same debug output as --verbose-air provides within the compiler.
/// * detect division by zero as a simple PoC using symbolic execution.
/// * TODO(pwr): maybe integrate CLR to perform additional checks -> would be nice to know how fast it is.
pub fn main() !void {
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

    const main_body_indexes = air_import.air.getMainBody();
    const liveness = air_import.liveness orelse @panic("Liveness is required");

    try out.print(
        \\# Begin Function AIR: {s}:
        \\# Total AIR+Liveness bytes: {d} bytes
        \\# AIR Instructions:         {d} entries
        \\# AIR Extra Data:           {d} entries
        \\# Liveness tomb_bits:       {d} entries
        \\# Liveness Extra Data:      {d} entries
        \\# Liveness special table:   not supported
        \\# Main body indexes: {any}
        \\
    , .{
        air_import.function_name,
        air_import.header.total_size_bytes,
        air_import.header.instruction_count,
        air_import.header.extra_data_count,
        liveness.tomb_bits.len,
        liveness.extra.len,
        main_body_indexes,
    });

    // Detect division by zero as a simple PoC using symbolic execution.
    //
    // # Begin Function AIR: test.main:
    // # Total AIR+Liveness bytes: 1012B
    // # AIR Instructions:         48 (432B)
    // # AIR Extra Data:           83 (332B)
    // # Liveness tomb_bits:       24B
    // # Liveness Extra Data:      18 (72B)
    // # Liveness special table:   6 (48B)
    // %0!= save_err_return_trace_index()
    // %1!= dbg_stmt(2:5)
    // %2 = alloc(*usize)
    // %3!= store_safe(%2, <usize, 5>)
    // %4!= dbg_var_ptr(%2, "a")
    // %5!= dbg_stmt(3:5)
    // %6 = load(usize, %2)
    // %7!= dbg_stmt(3:7)
    // %8 = mul_with_overflow(struct { usize, u1 }, %6!, <usize, 2>)
    // %9 = struct_field_val(%8, 1)
    // %10 = cmp_eq(%9!, <u1, 0>)
    // %13!= block(void, {
    //   %14!= cond_br(%10!, likely {
    //     %15!= br(%13, @Air.Inst.Ref.void_value)
    //   }, cold {
    //     %2! %8!
    //     %11!= call(<fn () noreturn, (function 'integerOverflow')>, [])
    //     %12!= unreach()
    //   })
    // } %10!)
    // %16 = struct_field_val(%8!, 0)
    // %17!= store_safe(%2, %16!)
    // %18!= dbg_stmt(4:5)
    // %19 = load(usize, %2)
    // %20 = load(usize, %2)
    // %21!= dbg_stmt(4:22)
    // %22 = sub_with_overflow(struct { usize, u1 }, %19!, %20!)
    // %23 = struct_field_val(%22, 1)
    // %24 = cmp_eq(%23!, <u1, 0>)
    // %27!= block(void, {
    //   %28!= cond_br(%24!, likely {
    //     %29!= br(%27, @Air.Inst.Ref.void_value)
    //   }, cold {
    //     %2! %22!
    //     %25!= call(<fn () noreturn, (function 'integerOverflow')>, [])
    //     %26!= unreach()
    //   })
    // } %24!)
    // %30 = struct_field_val(%22!, 0)
    // %31!= dbg_stmt(4:17)
    // %32 = cmp_neq(%30, @Air.Inst.Ref.zero_usize)
    // %35!= block(void, {
    //   %36!= cond_br(%32!, likely {
    //     %37!= br(%35, @Air.Inst.Ref.void_value)
    //   }, cold {
    //     %2! %30!
    //     %33!= call(<fn () noreturn, (function 'divideByZero')>, [])
    //     %34!= unreach()
    //   })
    // } %32!)
    // %38 = div_trunc(@Air.Inst.Ref.one_usize, %30!)
    // %39!= dbg_var_val(%38, "b")
    // %40!= dbg_stmt(5:17)
    // %41 = load(usize, %2)
    // %42 = load(usize, %2!)
    // %43 = aggregate_init(struct { usize, usize, usize }, [%41!, %42!, %38!])
    // %45!= dbg_stmt(5:17)
    // %46!= call(<fn (struct { usize, usize, usize }) void, (function 'info__anon_2904')>, [%43!])
    // %47!= ret_safe(@Air.Inst.Ref.void_value)
    // # End Function AIR: test.main
    {
        // TODO(pwr): add store for variables.
        // TODO(pwr): how can identifiers be traced back? Using only the `dbg_x` instructions?
        // * Is any additional information required or does the fully qualified name, source code and AIR suffice?

        const tag_format = "{}{c}= {s}(";

        // TODO(pwr): extract to air.zig
        const Helpers = struct {
            // Highest bit indicates if it's an AIR instruction index or intern pool reference.
            fn isInstructionReference(ref: air_lib.Air.Inst.Ref) bool {
                return @as(u1, @intCast(@intFromEnum(ref) >> 31)) == 1;
            }

            // Some instructions (e.g. dbg_var_ptr using pl_op) contain a payload index into extra data for variable length strings.
            fn derefStringPayload(air: *const air_lib.Air, index: usize) []const u8 {
                // TODO: use Air.extraData(air: Air, comptime T: type, index: usize) struct { data: T, end: usize }
                const name: air_lib.Air.NullTerminatedString = @enumFromInt(index);
                return name.toSlice(air.*); // TODO(pwr): format escapes.
            }

            // TODO(pwr): use a writer instead of log and split common header part from individual tags
            fn logPayloadOperand(writer: anytype, air: *const air_lib.Air, index: air_lib.Air.Inst.Index, unused: bool, tag: air_lib.Air.Inst.Tag, payload_operand: anytype) !void {
                const tag_name = @tagName(tag);
                const is_instruction_ref = @This().isInstructionReference(payload_operand.operand);
                const ref_display = if (is_instruction_ref) @as(u31, @truncate(@intFromEnum(payload_operand.operand))) else @intFromEnum(payload_operand.operand);
                const payload_display = @This().derefStringPayload(air, @intCast(payload_operand.payload));
                const unused_indicator: u8 = if (unused) '!' else ' ';

                try writer.print(tag_format ++ "{s}{}, \"{s}\")\n", .{
                    index,
                    unused_indicator,
                    tag_name,
                    if (is_instruction_ref) "%" else "",
                    ref_display,
                    payload_display,
                });
            }
        };

        const tags = air_import.instructions_owned.items(.tag);
        const data = air_import.instructions_owned.items(.data);
        for (main_body_indexes) |instruction_index| {
            const i = @intFromEnum(instruction_index);
            const tag = tags[i];
            const variant = data[i];
            const unused = liveness.isUnused(instruction_index);
            const unused_indicator: u8 = if (unused) '!' else ' ';

            const tag_name = @tagName(tag);

            // NOTE: see Air.Inst.Tag for documentation on the mapping.
            switch (tag) {
                .atomic_rmw,
                .call, // %33!= call(<fn () noreturn, (function 'divideByZero')>, [])
                .call_always_tail,
                .call_never_tail,
                .call_never_inline,
                .cond_br,
                .loop_switch_br,
                .select,
                .switch_br,
                .@"try",
                => try Helpers.logPayloadOperand(out, &air_import.air, instruction_index, unused, tag, variant.pl_op),

                .dbg_stmt => { // %40!= dbg_stmt(5:17)
                    const debug_statement = variant.dbg_stmt;
                    try out.print(tag_format ++ "{}:{})\n", .{
                        instruction_index,
                        unused_indicator,
                        tag_name,
                        debug_statement.line,
                        debug_statement.column,
                    });
                },

                .dbg_var_ptr, // %4!= dbg_var_ptr(%2, "a")
                .dbg_var_val, // %39!= dbg_var_val(%38, "b")
                .dbg_arg_inline,
                => try Helpers.logPayloadOperand(out, &air_import.air, instruction_index, unused, tag, variant.pl_op),

                .store, .store_safe => {
                    const binary_operation = variant.bin_op;
                    try out.print(tag_format ++ ") # {}\n", .{ instruction_index, unused_indicator, tag_name, binary_operation });
                },
                .load => {
                    const type_operand = variant.ty_op;
                    try out.print(tag_format ++ ") # {}\n", .{ instruction_index, unused_indicator, tag_name, type_operand });
                },
                .mul_with_overflow => {
                    const type_payload = variant.ty_pl;
                    try out.print(tag_format ++ ") # {}\n", .{ instruction_index, unused_indicator, tag_name, type_payload });
                },
                .sub_with_overflow => {
                    const type_payload = variant.ty_pl;
                    try out.print(tag_format ++ ") # {}\n", .{ instruction_index, unused_indicator, tag_name, type_payload });
                },
                .div_trunc => {
                    const binary_operation = variant.bin_op;
                    try out.print(tag_format ++ ") # {}\n", .{ instruction_index, unused_indicator, tag_name, binary_operation });
                },
                .ret_safe => {
                    const unary_operation = variant.un_op;

                    // TODO(pwr): extract function to air.zig
                    const value = if (unary_operation.toInterned()) |index| air_lib.Value.fromInterned(index) else value: {
                        const index = unary_operation.toIndex().?; // Can be unwrapped due to the above check.
                        const type_value = air_import.air.typeOfIndex(index, &intern_pool);
                        // TODO(pwr): reconstruct Type and Value without a Zcu.PerThread dependency.
                        // const value = try type_value.onePossibleValue(zcu_per_thread);
                        // break :value value;
                        break :value air_lib.Value{ .ip_index = type_value.ip_index };
                    };

                    try out.print(tag_format ++ "@{any} - {any})\n", .{ instruction_index, unused_indicator, tag_name, unary_operation, value.ip_index });
                },
                // TODO(pwr): implement all instructions.
                else => try out.print(tag_format ++ ")\n", .{ instruction_index, unused_indicator, tag_name }),
            }
        }
    }
}
