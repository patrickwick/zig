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

pub const Instruction = struct {
    pub const Index = @typeInfo(Air.Inst.Index).@"enum".tag_type;

    index: Index,
    key: AirKey,
};

pub const AirKey = union(enum) {
    /// Initial key.
    start: void,
    /// Key indicating that no more instructions are left.
    end_of_instructions: void,
    unsupported: void, // TODO(pwr): not yet implemented instructions.

    binary_operation: BinaryOperation,
    unary_operation: UnaryOperation,
    no_operation: NoOperation,
    allocation: Allocation,
    debug_statement: DebugStatement,
};

pub const BinaryOperation = struct {
    // NOTE: **not** using `Air.Inst.Tag` direclty to decouple enum values from compiler.
    pub const Tag = enum {
        invalid,

        add,
        add_optimized,
        add_safe,
        add_wrap,
        add_sat,
        sub,
        sub_optimized,
        sub_safe,
        sub_wrap,
        sub_sat,
        mul,
        mul_optimized,
        mul_safe,
        mul_wrap,
        mul_sat,
        div_float,
        div_trunc,
        div_floor,
        div_exact,
        rem,
        mod,
        bit_and,
        bit_or,
        xor,
        cmp_lt,
        cmp_lte,
        cmp_eq,
        cmp_gte,
        cmp_gt,
        cmp_neq,
        bool_and,
        bool_or,
        store,
        store_safe,
        array_elem_val,
        slice_elem_val,
        ptr_elem_val,
        shl,
        shl_exact,
        shl_sat,
        shr,
        shr_exact,
        set_union_tag,
        min,
        max,
        div_float_optimized,
        div_trunc_optimized,
        div_floor_optimized,
        div_exact_optimized,
        rem_optimized,
        mod_optimized,
        cmp_lt_optimized,
        cmp_lte_optimized,
        cmp_eq_optimized,
        cmp_gte_optimized,
        cmp_gt_optimized,
        cmp_neq_optimized,
        memcpy,
        memset,
        memset_safe,

        pub fn from(tag: Air.Inst.Tag) @This() {
            return switch (tag) {
                .add => .add,
                .add_optimized => .add_optimized,
                .add_safe => .add_safe,
                .add_wrap => .add_wrap,
                .add_sat => .add_sat,
                .sub => .sub,
                .sub_optimized => .sub_optimized,
                .sub_safe => .sub_safe,
                .sub_wrap => .sub_wrap,
                .sub_sat => .sub_sat,
                .mul => .mul,
                .mul_optimized => .mul_optimized,
                .mul_safe => .mul_safe,
                .mul_wrap => .mul_wrap,
                .mul_sat => .mul_sat,
                .div_float => .div_float,
                .div_trunc => .div_trunc,
                .div_floor => .div_floor,
                .div_exact => .div_exact,
                .rem => .rem,
                .mod => .mod,
                .bit_and => .bit_and,
                .bit_or => .bit_or,
                .xor => .xor,
                .cmp_lt => .cmp_lt,
                .cmp_lte => .cmp_lte,
                .cmp_eq => .cmp_eq,
                .cmp_gte => .cmp_gte,
                .cmp_gt => .cmp_gt,
                .cmp_neq => .cmp_neq,
                .bool_and => .bool_and,
                .bool_or => .bool_or,
                .store => .store,
                .store_safe => .store_safe,
                .array_elem_val => .array_elem_val,
                .slice_elem_val => .slice_elem_val,
                .ptr_elem_val => .ptr_elem_val,
                .shl => .shl,
                .shl_exact => .shl_exact,
                .shl_sat => .shl_sat,
                .shr => .shr,
                .shr_exact => .shr_exact,
                .set_union_tag => .set_union_tag,
                .min => .min,
                .max => .max,
                .div_float_optimized => .div_float_optimized,
                .div_trunc_optimized => .div_trunc_optimized,
                .div_floor_optimized => .div_floor_optimized,
                .div_exact_optimized => .div_exact_optimized,
                .rem_optimized => .rem_optimized,
                .mod_optimized => .mod_optimized,
                .cmp_lt_optimized => .cmp_lt_optimized,
                .cmp_lte_optimized => .cmp_lte_optimized,
                .cmp_eq_optimized => .cmp_eq_optimized,
                .cmp_gte_optimized => .cmp_gte_optimized,
                .cmp_gt_optimized => .cmp_gt_optimized,
                .cmp_neq_optimized => .cmp_neq_optimized,
                .memcpy => .memcpy,
                .memset => .memset,
                .memset_safe => .memset_safe,
                else => .invalid,
            };
        }
    };

    operation: Tag,
    left: Operand,
    right: Operand,
};

pub const UnaryOperation = struct {
    // NOTE: **not** using `Air.Inst.Tag` direclty to decouple enum values from compiler.
    pub const Tag = enum {
        invalid,

        is_null,
        is_non_null,
        is_null_ptr,
        is_non_null_ptr,
        is_err,
        is_non_err,
        is_err_ptr,
        is_non_err_ptr,
        ret,
        ret_safe,
        ret_load,
        is_named_enum_value,
        tag_name,
        error_name,
        sqrt,
        sin,
        cos,
        tan,
        exp,
        exp2,
        log,
        log2,
        log10,
        floor,
        ceil,
        round,
        trunc_float,
        neg,
        neg_optimized,
        cmp_lt_errors_len,
        set_err_return_trace,
        c_va_end,

        pub fn from(tag: Air.Inst.Tag) @This() {
            return switch (tag) {
                .is_null => .is_null,
                .is_non_null => .is_non_null,
                .is_null_ptr => .is_null_ptr,
                .is_non_null_ptr => .is_non_null_ptr,
                .is_err => .is_err,
                .is_non_err => .is_non_err,
                .is_err_ptr => .is_err_ptr,
                .is_non_err_ptr => .is_non_err_ptr,
                .ret => .ret,
                .ret_safe => .ret_safe,
                .ret_load => .ret_load,
                .is_named_enum_value => .is_named_enum_value,
                .tag_name => .tag_name,
                .error_name => .error_name,
                .sqrt => .sqrt,
                .sin => .sin,
                .cos => .cos,
                .tan => .tan,
                .exp => .exp,
                .exp2 => .exp2,
                .log => .log,
                .log2 => .log2,
                .log10 => .log10,
                .floor => .floor,
                .ceil => .ceil,
                .round => .round,
                .trunc_float => .trunc_float,
                .neg => .neg,
                .neg_optimized => .neg_optimized,
                .cmp_lt_errors_len => .cmp_lt_errors_len,
                .set_err_return_trace => .set_err_return_trace,
                .c_va_end => .c_va_end,
                else => .invalid,
            };
        }
    };

    operation: Tag,
    operand: Operand,
};

pub const NoOperation = void;

pub const DebugStatement = struct {
    line: u32,
    column: u32,
};

pub const Allocation = struct {
    allocated_type: Type,
};

/// Expand AIR incrementally based on the raw AIR and InternPool data like a tokenizer would.
/// This simplifies safe AIR usage over using the raw split tag and data arrays at a small runtime cost.
pub const AirExpansion = struct {
    air: *const Air,
    air_tags: []const Air.Inst.Tag,
    air_data: []const Air.Inst.Data,

    ip: *const InternPool,

    current_instruction_index: Instruction.Index,
    current: Instruction,

    pub fn init(air: *const Air, ip: *const InternPool, initial_instruction_index: Air.Inst.Index) @This() {
        return .{
            .air = air,
            .air_tags = air.instructions.items(.tag),
            .air_data = air.instructions.items(.data),
            .ip = ip,
            .current_instruction_index = @intFromEnum(initial_instruction_index),
            .current = .{
                .index = @intFromEnum(initial_instruction_index),
                .key = .start,
            },
        };
    }

    pub fn get(self: *@This()) Instruction {
        return self.current;
    }

    pub fn nextInstruction(self: *@This()) Instruction {
        if (self.current_instruction_index >= self.air_tags.len) return .{
            .index = self.current_instruction_index,
            .key = .end_of_instructions,
        };
        defer self.current_instruction_index += 1;

        const tag = self.air_tags[self.current_instruction_index];
        const data = self.air_data[self.current_instruction_index];

        const key: AirKey = switch (tag) {
            // Binary operations.
            .add,
            .add_optimized,
            .add_safe,
            .add_wrap,
            .add_sat,
            .sub,
            .sub_optimized,
            .sub_safe,
            .sub_wrap,
            .sub_sat,
            .mul,
            .mul_optimized,
            .mul_safe,
            .mul_wrap,
            .mul_sat,
            .div_float,
            .div_trunc,
            .div_floor,
            .div_exact,
            .rem,
            .mod,
            .bit_and,
            .bit_or,
            .xor,
            .cmp_lt,
            .cmp_lte,
            .cmp_eq,
            .cmp_gte,
            .cmp_gt,
            .cmp_neq,
            .bool_and,
            .bool_or,
            .store,
            .store_safe,
            .array_elem_val,
            .slice_elem_val,
            .ptr_elem_val,
            .shl,
            .shl_exact,
            .shl_sat,
            .shr,
            .shr_exact,
            .set_union_tag,
            .min,
            .max,
            .div_float_optimized,
            .div_trunc_optimized,
            .div_floor_optimized,
            .div_exact_optimized,
            .rem_optimized,
            .mod_optimized,
            .cmp_lt_optimized,
            .cmp_lte_optimized,
            .cmp_eq_optimized,
            .cmp_gte_optimized,
            .cmp_gt_optimized,
            .cmp_neq_optimized,
            .memcpy,
            .memset,
            .memset_safe,
            => .{
                .binary_operation = .{
                    .operation = .from(tag),
                    .left = derefOperand(self, data.bin_op.lhs),
                    .right = derefOperand(self, data.bin_op.rhs),
                },
            },

            // Unary operations.
            .is_null,
            .is_non_null,
            .is_null_ptr,
            .is_non_null_ptr,
            .is_err,
            .is_non_err,
            .is_err_ptr,
            .is_non_err_ptr,
            .ret,
            .ret_safe,
            .ret_load,
            .is_named_enum_value,
            .tag_name,
            .error_name,
            .sqrt,
            .sin,
            .cos,
            .tan,
            .exp,
            .exp2,
            .log,
            .log2,
            .log10,
            .floor,
            .ceil,
            .round,
            .trunc_float,
            .neg,
            .neg_optimized,
            .cmp_lt_errors_len,
            .set_err_return_trace,
            .c_va_end,
            => .{
                .unary_operation = .{
                    .operation = .from(tag),
                    .operand = derefOperand(self, data.un_op),
                },
            },

            // No operations.
            .trap,
            .breakpoint,
            .dbg_empty_stmt,
            .unreach,
            .ret_addr,
            .frame_addr,
            .save_err_return_trace_index,
            => AirKey.no_operation,

            .alloc => .{ .allocation = .{ .allocated_type = derefType(self, data.ty) } },
            .ret_ptr,
            .err_return_trace,
            .c_va_start,
            => .unsupported, // TODO(pwr): NYI.

            .arg,
            => .unsupported, // TODO(pwr): NYI.

            .not,
            .bitcast,
            .load,
            .fptrunc,
            .fpext,
            .intcast,
            .intcast_safe,
            .trunc,
            .optional_payload,
            .optional_payload_ptr,
            .optional_payload_ptr_set,
            .errunion_payload_ptr_set,
            .wrap_optional,
            .unwrap_errunion_payload,
            .unwrap_errunion_err,
            .unwrap_errunion_payload_ptr,
            .unwrap_errunion_err_ptr,
            .wrap_errunion_payload,
            .wrap_errunion_err,
            .slice_ptr,
            .slice_len,
            .ptr_slice_len_ptr,
            .ptr_slice_ptr_ptr,
            .struct_field_ptr_index_0,
            .struct_field_ptr_index_1,
            .struct_field_ptr_index_2,
            .struct_field_ptr_index_3,
            .array_to_slice,
            .float_from_int,
            .splat,
            .int_from_float,
            .int_from_float_optimized,
            .get_union_tag,
            .clz,
            .ctz,
            .popcount,
            .byte_swap,
            .bit_reverse,
            .abs,
            .error_set_has_value,
            .addrspace_cast,
            .c_va_arg,
            .c_va_copy,
            => .unsupported, // TODO(pwr): NYI.

            .block,
            .dbg_inline_block,
            => .unsupported, // TODO(pwr): NYI.

            .loop,
            => .unsupported, // TODO(pwr): NYI.

            .slice,
            .slice_elem_ptr,
            .ptr_elem_ptr,
            .ptr_add,
            .ptr_sub,
            .add_with_overflow,
            .sub_with_overflow,
            .mul_with_overflow,
            .shl_with_overflow,
            => .unsupported, // TODO(pwr): NYI.

            .call,
            .call_always_tail,
            .call_never_tail,
            .call_never_inline,
            => .unsupported, // TODO(pwr): NYI.

            .dbg_var_ptr,
            .dbg_var_val,
            .dbg_arg_inline,
            => .unsupported, // TODO(pwr): NYI.

            .dbg_stmt => .{ .debug_statement = .{ .line = data.dbg_stmt.line + 1, .column = data.dbg_stmt.column + 1 } },

            .struct_field_ptr => .unsupported, // TODO(pwr): NYI.
            .struct_field_val => .unsupported, // TODO(pwr): NYI.
            .inferred_alloc => .unsupported, // TODO(pwr): NYI.
            .inferred_alloc_comptime => .unsupported, // TODO(pwr): NYI.
            .assembly => .unsupported, // TODO(pwr): NYI.

            .aggregate_init => .unsupported, // TODO(pwr): NYI.
            .union_init => .unsupported, // TODO(pwr): NYI.
            .br => .unsupported, // TODO(pwr): NYI.
            .switch_dispatch => .unsupported, // TODO(pwr): NYI.
            .repeat => .unsupported, // TODO(pwr): NYI.
            .cond_br => .unsupported, // TODO(pwr): NYI.
            .@"try", .try_cold => .unsupported, // TODO(pwr): NYI.
            .try_ptr, .try_ptr_cold => .unsupported, // TODO(pwr): NYI.
            .loop_switch_br, .switch_br => .unsupported, // TODO(pwr): NYI.
            .cmpxchg_weak, .cmpxchg_strong => .unsupported, // TODO(pwr): NYI.
            .atomic_load => .unsupported, // TODO(pwr): NYI.
            .prefetch => .unsupported, // TODO(pwr): NYI.
            .atomic_store_unordered => .unsupported, // TODO(pwr): NYI.
            .atomic_store_monotonic => .unsupported, // TODO(pwr): NYI.
            .atomic_store_release => .unsupported, // TODO(pwr): NYI.
            .atomic_store_seq_cst => .unsupported, // TODO(pwr): NYI.
            .atomic_rmw => .unsupported, // TODO(pwr): NYI.
            .field_parent_ptr => .unsupported, // TODO(pwr): NYI.
            .wasm_memory_size => .unsupported, // TODO(pwr): NYI.
            .wasm_memory_grow => .unsupported, // TODO(pwr): NYI.
            .mul_add => .unsupported, // TODO(pwr): NYI.
            .select => .unsupported, // TODO(pwr): NYI.
            .shuffle => .unsupported, // TODO(pwr): NYI.
            .reduce, .reduce_optimized => .unsupported, // TODO(pwr): NYI.
            .cmp_vector, .cmp_vector_optimized => .unsupported, // TODO(pwr): NYI.
            .vector_store_elem => .unsupported, // TODO(pwr): NYI.

            .work_item_id,
            .work_group_size,
            .work_group_id,
            => .unsupported, // TODO(pwr): NYI.
        };
        self.current = .{ .index = self.current_instruction_index, .key = key };
        return self.get();
    }

    fn derefOperand(self: *const @This(), operand_ref: Air.Inst.Ref) Operand {
        if (operand_ref.toInterned()) |ip_index| return .{ .interned = self.ip.indexToKey(ip_index) };
        return .{ .instruction_ref = operand_ref.toIndex().? };
    }

    fn derefType(self: *const @This(), type_ref: compiler.Type) Type {
        const ip_index = type_ref.toIntern();
        return self.ip.indexToKey(ip_index);
    }
};

// TODO(pwr): create own decoupled type definitions for Key and Type, so compiler internal types can change.
// At a later point in time: direct InternPool indexToKey usage works very well for now.
pub const Key = InternPool.Key;
pub const Type = InternPool.Key;

pub const Operand = union(enum) {
    interned: Key,
    instruction_ref: Air.Inst.Index,
};

const t = std.testing;

test "ExpandAir" {}
