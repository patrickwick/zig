// This is an experiment in exporting the analyzed intermediate representation (AIR)
// in a minimal lossless form to be used in external static analysis tools.
const std = @import("std");
const builtin = @import("builtin");

const Air = @import("Air.zig");
const Compilation = @import("Compilation.zig");
const Liveness = @import("Liveness.zig");
const Package = @import("Package.zig");
const Zcu = @import("Zcu.zig");

/// Export AIR main body.
pub fn exportAir(zcu_per_thread: Zcu.PerThread, air: Air, liveness: ?Liveness) void {
    const body = air.getMainBody();
    std.log.err("Main body of size {}: {any}", .{ body.len, body }); // FIXME: remove
    for (body) |instruction_index| exportAirInst(instruction_index, zcu_per_thread, air, liveness);

    // TODO: dump InternPool: AIR instructions contain indexes to entries in Data.bin_op, Data.ty, etc.
    const intern_pool = zcu_per_thread.zcu.intern_pool;
    _ = intern_pool;

    // TODO: dump additional data on demand: Data.ty_pl contains a u32 index into additional data
    // => what data exactly?

    // TODO: dump extra data as well? Used by Data.arg.

    // TODO: dump liveness
    if (liveness) |l| {
        _ = l;
    }
}

/// Export AIR starting from a specific instruction index.
pub fn exportAirInst(instruction_index: Air.Inst.Index, zcu_per_thread: Zcu.PerThread, air: Air, liveness: ?Liveness) void {
    _ = zcu_per_thread;
    _ = liveness;

    const tags = air.instructions.items(.tag);
    const data = air.instructions.items(.data);

    const index = @intFromEnum(instruction_index);
    const tag = tags[index];
    const variant = data[index];

    // TODO: dump the instructions starting from the index
    // => no serialization needed, they all have an 8bit tag and 64bit variant
    std.log.err("Instruction {any}: {any}: {any}", .{ instruction_index, tag, variant }); // FIXME: remove
}

// Test code here on.
const t = std.testing;

// Create a test compilation unit for testing without source files. Zcu stores the InternPool which is used in AIR.
// A Zcu holds a pointer to Compilation, so it cannot be created on its own.
const TestCompilationUnit = struct {
    compilation: *Compilation,
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    thread_pool: *std.Thread.Pool,

    pub fn init(
        allocator: std.mem.Allocator,
    ) !@This() {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_allocator = arena.allocator();

        const thread_stack_size = 32 << 20;
        const thread_pool = try allocator.create(std.Thread.Pool);
        errdefer allocator.destroy(thread_pool);

        const thread_count = 1;
        try thread_pool.*.init(.{
            .allocator = allocator,
            .n_jobs = thread_count,
            .track_ids = true,
            .stack_size = thread_stack_size,
        });
        errdefer thread_pool.deinit();

        const resolved_target = Package.Module.ResolvedTarget{
            .result = try std.zig.system.resolveTargetQuery(.{}),
            .is_native_os = true,
            .is_native_abi = true,
            .llvm_cpu_features = null,
        };

        const root_module = try Package.Module.create(arena_allocator, .{
            .global_cache_directory = std.Build.Cache.Directory.cwd(),
            .paths = .{
                .root = .{
                    .root_dir = std.Build.Cache.Directory.cwd(),
                },
                .root_src_path = "src/main.zig",
            },
            .fully_qualified_name = "root",
            .cc_argv = &.{},
            .inherited = .{
                .resolved_target = resolved_target,
                .stack_check = false,
                .stack_protector = 0,
                .no_builtin = true,
            },
            .global = try Compilation.Config.resolve(.{
                .output_mode = .Exe,
                .resolved_target = resolved_target,
                .is_test = false,
                .have_zcu = true,
                .emit_bin = true,
            }),
            .parent = null,
            .builtin_mod = null, // NOTE: null will create a new builtin submodule on creation
            .builtin_modules = null,
        });

        const compilation = try Compilation.create(allocator, arena_allocator, .{
            .local_cache_directory = std.Build.Cache.Directory.cwd(),
            .global_cache_directory = std.Build.Cache.Directory.cwd(),
            .thread_pool = thread_pool,
            .zig_lib_directory = .{ .path = "./", .handle = std.fs.cwd() },
            .config = .{
                .have_zcu = true,
                .output_mode = .Exe,
                .link_mode = .static,
                .link_libc = false,
                .link_libcpp = false,
                .link_libunwind = false,
                .any_c_source_files = false,
                .any_unwind_tables = false,
                .any_non_single_threaded = false,
                .any_error_tracing = false,
                .any_sanitize_thread = false,
                .any_sanitize_c = false,
                .any_fuzz = false,
                .pie = true,
                .use_llvm = false,
                .use_lib_llvm = false,
                .use_lld = false,
                .c_frontend = .aro,
                .lto = .none,
                .wasi_exec_model = .command,
                .import_memory = false,
                .export_memory = false,
                .shared_memory = false,
                .is_test = false,
                .debug_format = .{ .dwarf = .@"64" },
                .root_optimize_mode = .Debug,
                .root_strip = false,
                .root_error_tracing = false,
                .dll_export_fns = false,
                .rdynamic = false,
                .san_cov_trace_pc_guard = false,
            },
            .root_mod = root_module,
            .root_name = "<root_name>",
            .emit_bin = null,
        });
        errdefer compilation.destroy();

        return .{
            .compilation = compilation,
            .allocator = allocator,
            .arena = arena,
            .thread_pool = thread_pool,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.compilation.destroy();
        self.thread_pool.*.deinit();
        self.allocator.destroy(self.thread_pool);
        self.arena.deinit();
    }
};

// Export minimal main function:
// pub fn main() void {}
//
// # Begin Function AIR: test.main:
// # Total AIR+Liveness bytes: 146B
// # AIR Instructions:         2 (18B)
// # AIR Extra Data:           4 (16B)
// # Liveness tomb_bits:       8B
// # Liveness Extra Data:      0 (0B)
// # Liveness special table:   0 (0B)
//   %0!= save_err_return_trace_index()
//   %1!= ret_safe(@Air.Inst.Ref.void_value)
// info: Air.Inst.Tag.save_err_return_trace_index
// info: Air.Inst.Tag.ret_safe
// # End Function AIR: test.main
test exportAir {
    const allocator = t.allocator;
    var test_unit = try TestCompilationUnit.init(allocator);
    defer test_unit.deinit();
    const zcu_per_thread = Zcu.PerThread{ .tid = .main, .zcu = test_unit.compilation.zcu.? };

    var instructions = std.MultiArrayList(Air.Inst){};
    defer instructions.deinit(allocator);
    {
        // %0!= save_err_return_trace_index()
        try instructions.append(allocator, Air.Inst{
            .tag = .save_err_return_trace_index,
            .data = .{ .ty_pl = .{ .ty = .void_value, .payload = 0 } }, // TODO: index to what in this case?
        });

        // %1!= ret_safe(@Air.Inst.Ref.void_value)
        try instructions.append(allocator, Air.Inst{
            .tag = .ret_safe,
            .data = .{ .un_op = .void_value },
        });
    }

    const extra = e: {
        const extra_max_size = 512;
        var extra = [1]u32{0} ** extra_max_size;
        std.debug.assert(instructions.len <= extra_max_size);

        // "main_block" points to a length followed by the main body instruction indexes (see Air.getMainBody()).
        const main_block_extra_index = @intFromEnum(Air.ExtraIndex.main_block);
        extra[main_block_extra_index] = main_block_extra_index + 1;
        extra[main_block_extra_index + 1] = @intCast(instructions.len);
        for (0..instructions.len) |i| extra[main_block_extra_index + 2 + i] = @intCast(i);

        break :e extra;
    };

    const air = Air{
        .instructions = instructions.slice(),
        .extra = &extra,
    };

    exportAir(zcu_per_thread, air, null);
}
