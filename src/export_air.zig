// This is an experiment in exporting the analyzed intermediate representation (AIR)
// in a minimal lossless form to be used in external static analysis tools.
const std = @import("std");
const builtin = @import("builtin");

pub const Air = @import("Air.zig");
const Compilation = @import("Compilation.zig");
pub const InternPool = @import("InternPool.zig");
pub const Liveness = @import("Liveness.zig");
const Package = @import("Package.zig");
pub const Type = @import("Type.zig");
pub const Value = @import("Value.zig");
const Zcu = @import("Zcu.zig");

pub const DEFAULT_BINARY_AIR_PATH = "air_export.air.bin";

const endianness = builtin.target.cpu.arch.endian();

/// Dumped AIR header with C ABI type for stability.
pub const AirHeader = extern struct {
    /// Each field is aligned.
    pub const TARGET_ALIGNMENT = 8;
    pub const MAGIC = 0x21504d5544524941; // "AIRDUMP!" in hex

    magic: u64 = MAGIC,
    total_size_bytes: u64,
    function_name_length: u64, // in bytes
    instruction_count: u64, // in entries, not bytes
    extra_data_count: u64, // in entries, not bytes

    liveness_tomb_bits_count: u64, // in entries, not bytes
    liveness_extra_count: u64, // in entries, not bytes

    intern_locals_shared_extra_count: u64, // in entries, not bytes

    pub fn init(air: Air, liveness: ?Liveness, zcu_per_thread: Zcu.PerThread, function_name: []const u8) @This() {
        const header_size = std.mem.alignForward(usize, @sizeOf(@This()), TARGET_ALIGNMENT);
        const tag_size = std.mem.alignForward(usize, air.instructions.len * @sizeOf(Air.Inst.Tag), TARGET_ALIGNMENT);
        const data_size = std.mem.alignForward(usize, air.instructions.len * @sizeOf(Air.Inst.Data), TARGET_ALIGNMENT);
        const name_size = std.mem.alignForward(usize, function_name.len, TARGET_ALIGNMENT);
        const extra_size = std.mem.alignForward(usize, air.extra.len * @sizeOf(@TypeOf(air.extra[0])), TARGET_ALIGNMENT);
        const liveness_tomb_bits_size = if (liveness) |l| std.mem.alignForward(usize, l.tomb_bits.len * @sizeOf(@TypeOf(l.tomb_bits[0])), TARGET_ALIGNMENT) else 0;

        // intern pool
        var intern_pool = zcu_per_thread.zcu.intern_pool;
        const ip_local_shared = intern_pool.getLocalShared(.main);
        const ip_local_shared_slice = ip_local_shared.items.acquire().view().slice();

        const ipls_tags = ip_local_shared_slice.items(.tag);
        const ipls_data = ip_local_shared_slice.items(.data);
        std.debug.assert(ipls_tags.len == ipls_data.len); // single length for MultiArrayList

        const ipls_extra_tag_size = std.mem.alignForward(usize, ipls_tags.len * @sizeOf(std.meta.FieldType(InternPool.Item, .tag)), TARGET_ALIGNMENT);
        const ipls_extra_inst_size = std.mem.alignForward(usize, ipls_data.len * @sizeOf(std.meta.FieldType(InternPool.Item, .data)), TARGET_ALIGNMENT);
        const intern_pool_size = ipls_extra_tag_size + ipls_extra_inst_size;

        const total_size = header_size + tag_size + data_size + name_size + extra_size + liveness_tomb_bits_size + intern_pool_size;

        return .{
            .total_size_bytes = total_size,
            .function_name_length = function_name.len,
            .instruction_count = @intCast(air.instructions.len),
            .extra_data_count = @intCast(air.extra.len),
            .liveness_tomb_bits_count = if (liveness) |l| l.tomb_bits.len else 0,
            .liveness_extra_count = if (liveness) |l| l.extra.len else 0,
            .intern_locals_shared_extra_count = ipls_tags.len,
        };
    }
};

/// Export AIR for all instructions. The main body can be filtered from the instruction indexes stored in extra data.
/// Native endianness only - assumed to be used on the same machine in a different process.
pub fn exportAir(writer: std.io.AnyWriter, zcu_per_thread: Zcu.PerThread, air: Air, liveness: ?Liveness, function_name: []const u8) void {
    const header = AirHeader.init(air, liveness, zcu_per_thread, function_name);

    errdefer @panic("exportAir writer failed"); // TODO: handle properly
    try writer.writeStruct(header);
    try writer.writeAll(function_name);
    try alignWriter(writer, function_name.len, AirHeader.TARGET_ALIGNMENT);

    try writer.writeAll(@ptrCast(air.instructions.items(.tag)));
    try alignWriter(writer, air.instructions.len * @sizeOf(Air.Inst.Tag), AirHeader.TARGET_ALIGNMENT);

    try writer.writeAll(@ptrCast(air.instructions.items(.data)));
    try alignWriter(writer, air.instructions.len * @sizeOf(Air.Inst.Data), AirHeader.TARGET_ALIGNMENT);

    try writer.writeAll(@ptrCast(air.extra));
    try alignWriter(writer, air.extra.len * @sizeOf(@TypeOf(air.extra[0])), AirHeader.TARGET_ALIGNMENT);

    if (liveness) |l| {
        try writer.writeAll(@ptrCast(l.tomb_bits));
        try alignWriter(writer, l.tomb_bits.len * @sizeOf(@TypeOf(l.tomb_bits[0])), AirHeader.TARGET_ALIGNMENT);

        try writer.writeAll(@ptrCast(l.extra));
        try alignWriter(writer, l.extra.len * @sizeOf(@TypeOf(l.extra[0])), AirHeader.TARGET_ALIGNMENT);

        // TODO(pwr): serialize hashmap or just drop special?
        // => how important is this data for analysis? Can the Liveness lookups handle missing special data?
        // try writer.writeAll(l.special);
        // try alignWriter(writer, l.special.len * @sizeOf(@TypeOf(l.special[0])), AirHeader.TARGET_ALIGNMENT);
    }

    // TODO(pwr): dump InternPool: AIR instructions contain indexes to entries in Data.bin_op, Data.ty, etc.
    // Store the entire pool or iterate the instructions to store dereferenced values? There are helpers like `Air.value` for it.
    {
        var intern_pool = zcu_per_thread.zcu.intern_pool;
        const ip_local = intern_pool.getLocal(.main);
        const ip_local_shared = intern_pool.getLocalShared(.main);
        _ = ip_local;

        const ip_local_shared_slice = ip_local_shared.items.acquire().view().slice();

        const ipls_tags = ip_local_shared_slice.items(.tag);
        try writer.writeAll(@ptrCast(ipls_tags));
        const intern_extra_tag_size = ipls_tags.len * @sizeOf(std.meta.FieldType(InternPool.Item, .tag));
        try alignWriter(writer, intern_extra_tag_size, AirHeader.TARGET_ALIGNMENT);

        const ipls_data = ip_local_shared_slice.items(.data);
        try writer.writeAll(@ptrCast(ipls_data));
        const intern_extra_inst_size = ipls_data.len * @sizeOf(std.meta.FieldType(InternPool.Item, .data));
        try alignWriter(writer, intern_extra_inst_size, AirHeader.TARGET_ALIGNMENT);
    }
}

/// Export AIR starting from a specific instruction index.
pub fn exportAirInst(writer: std.io.AnyWriter, instruction_index: Air.Inst.Index, zcu_per_thread: Zcu.PerThread, air: Air, liveness: ?Liveness) void {
    // TODO: not supported yet.
    // It's unclear how the multi array list would be written incrementally using the writer abstraction.
    // Also indexes stored in e.g. `Data.arg` would need to be adjusted accordingly.
    _ = writer;
    _ = instruction_index;
    _ = air;
    _ = zcu_per_thread;
    _ = liveness;
    @panic("exportAirInst is not supported yet");
}

fn alignWriter(writer: anytype, size: usize, comptime target_alignment: usize) !void {
    const aligned_length = std.mem.alignForward(usize, size, target_alignment);
    try writer.writeByteNTimes(0, aligned_length - size);
}

fn alignReader(reader: anytype, size: usize, comptime target_alignment: usize) !void {
    const aligned_length = std.mem.alignForward(usize, size, target_alignment);
    try reader.skipBytes(aligned_length - size, .{});
}

pub const AirImported = struct {
    header: AirHeader,
    function_name: []const u8,
    air: Air,
    intern_pool: InternPool,
    /// Instructions owned by the caller that needs to free it using the provided allocator.
    instructions_owned: std.MultiArrayList(Air.Inst),
    liveness: ?Liveness,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *@This()) void {
        self.instructions_owned.deinit(self.allocator);
        self.allocator.free(self.function_name);
        self.allocator.free(self.air.extra);
        if (self.liveness) |l| self.allocator.free(l.tomb_bits);
        if (self.liveness) |l| self.allocator.free(l.extra);
    }
};

// TODO: return optional to indicate end of stream without an error.
pub fn importAir(allocator: std.mem.Allocator, reader: std.io.AnyReader) !AirImported {
    const header = try reader.readStruct(AirHeader);

    var instructions = std.MultiArrayList(Air.Inst){};
    errdefer instructions.deinit(allocator);
    try instructions.resize(allocator, header.instruction_count);

    const function_name = try allocator.alloc(u8, header.function_name_length);
    errdefer allocator.free(function_name);
    const function_name_bytes_read = try reader.readAll(function_name);
    std.debug.assert(function_name_bytes_read == header.function_name_length * @sizeOf(u8));
    try alignReader(reader, function_name_bytes_read, AirHeader.TARGET_ALIGNMENT);

    const tag_bytes_read = try reader.readAll(@ptrCast(instructions.items(.tag)));
    std.debug.assert(tag_bytes_read == header.instruction_count * @sizeOf(Air.Inst.Tag));
    try alignReader(reader, tag_bytes_read, AirHeader.TARGET_ALIGNMENT);

    const data_bytes_read = try reader.readAll(@ptrCast(instructions.items(.data)));
    std.debug.assert(data_bytes_read == header.instruction_count * @sizeOf(Air.Inst.Data));
    try alignReader(reader, data_bytes_read, AirHeader.TARGET_ALIGNMENT);

    const Extra = u32;
    const extra = try allocator.alloc(Extra, header.extra_data_count);
    errdefer allocator.free(extra);
    const extra_bytes_read = try reader.readAll(@ptrCast(extra));
    std.debug.assert(extra_bytes_read == header.extra_data_count * @sizeOf(Extra));
    try alignReader(reader, extra_bytes_read, AirHeader.TARGET_ALIGNMENT);

    const liveness = l: {
        if (header.liveness_tomb_bits_count == 0 and header.liveness_extra_count == 0) break :l null;

        const tomb_bits = try allocator.alloc(usize, header.liveness_tomb_bits_count);
        errdefer allocator.free(tomb_bits);
        const liveness_tomb_bits_read = try reader.readAll(@ptrCast(tomb_bits));
        std.debug.assert(liveness_tomb_bits_read == header.liveness_tomb_bits_count * @sizeOf(usize));
        try alignReader(reader, liveness_tomb_bits_read, AirHeader.TARGET_ALIGNMENT);

        // TODO: extra
        const liveness_extra = try allocator.alloc(u32, header.liveness_extra_count);
        errdefer allocator.free(liveness_extra);
        const liveness_extra_read = try reader.readAll(@ptrCast(liveness_extra));
        std.debug.assert(liveness_extra_read == header.liveness_extra_count * @sizeOf(u32));
        try alignReader(reader, liveness_extra_read, AirHeader.TARGET_ALIGNMENT);

        // TODO: add special or leave it?

        break :l Liveness{
            .tomb_bits = tomb_bits,
            .extra = liveness_extra,
            .special = .{},
        };
    };

    const intern_pool = intern_pool: {
        const tags = try allocator.alloc(InternPool.Tag, header.intern_locals_shared_extra_count);
        errdefer allocator.free(tags);
        const ip_tag_bytes_read = try reader.readAll(@ptrCast(tags));
        std.debug.assert(ip_tag_bytes_read == header.intern_locals_shared_extra_count * @sizeOf(InternPool.Tag));
        try alignReader(reader, ip_tag_bytes_read, AirHeader.TARGET_ALIGNMENT);

        const IpDataType = std.meta.FieldType(InternPool.Item, .data);
        const data = try allocator.alloc(IpDataType, header.intern_locals_shared_extra_count);
        errdefer allocator.free(data);
        const ip_data_bytes_read = try reader.readAll(@ptrCast(data));
        std.debug.assert(ip_data_bytes_read == header.intern_locals_shared_extra_count * @sizeOf(IpDataType));
        try alignReader(reader, ip_data_bytes_read, AirHeader.TARGET_ALIGNMENT);

        // reconstruct
        const ip = InternPool.empty;

        // TODO(pwr): NYI
        // const ip.getLocalShared(.main).extra.view().setCapacity(allocator, header.extra_data_count)

        break :intern_pool ip;
    };

    return .{
        .header = header,
        .function_name = function_name,
        .air = .{
            .instructions = instructions.slice(),
            .extra = extra,
        },
        .intern_pool = intern_pool,
        .instructions_owned = instructions,
        .liveness = liveness,
        .allocator = allocator,
    };
}

// Test code here on.
const t = std.testing;

// Create a test compilation unit for testing without source files. Zcu stores the InternPool which is used in AIR.
// Zcu unit holds a pointer to Compilation, so it cannot be created on its own (without null pointer hacks).
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
        const extra_max_size = 32;
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

    var tomb_bits = [_]usize{ 1, 2 };
    const liveness = Liveness{
        .tomb_bits = &tomb_bits,
        .extra = &.{},
        .special = .{},
    };

    // Export, import and assert data.
    const buffer_size = 4096;
    var buffer = [1]u8{0} ** buffer_size;
    var stream = std.io.FixedBufferStream([]u8){ .buffer = &buffer, .pos = 0 };
    const function_name = "test.main";
    exportAir(stream.writer().any(), zcu_per_thread, air, liveness, function_name);
    const total_size_bytes = try stream.getPos();

    try stream.seekTo(0);
    var imported = try importAir(allocator, stream.reader().any());
    defer imported.deinit();

    try t.expectEqual(AirHeader.MAGIC, imported.header.magic);
    try t.expectEqual(total_size_bytes, imported.header.total_size_bytes);
    try t.expectEqual(function_name.len, imported.header.function_name_length);
    try t.expectEqualStrings(function_name, imported.function_name);
    try t.expectEqual(air.instructions.len, imported.air.instructions.len);
    try t.expectEqual(air.extra.len, imported.air.extra.len);
    try t.expectEqualSlices(usize, imported.liveness.?.tomb_bits, liveness.tomb_bits);
    try t.expectEqualSlices(u32, imported.liveness.?.extra, liveness.extra);
    try t.expectEqual(imported.liveness.?.special.count(), liveness.special.count());

    const tags = imported.air.instructions.items(.tag);
    const variants = imported.air.instructions.items(.data);
    for (tags, variants, air.instructions.items(.tag), air.instructions.items(.data)) |tag, variant, expected_tag, expected_variant| {
        try t.expectEqual(expected_tag, tag);
        const DataType = *align(1) const u64;
        try t.expectEqual(@as(DataType, @ptrCast(&expected_variant)).*, @as(DataType, @ptrCast(&variant)).*);
    }

    try t.expectEqualSlices(u32, air.extra, imported.air.extra);

    const main_body_indexes = imported.air.getMainBody();
    try t.expectEqual(air.instructions.len, main_body_indexes.len);
    for (0..air.instructions.len, main_body_indexes) |expected_i, actual_i| try t.expectEqual(expected_i, @intFromEnum(actual_i));

    // Assert that values that rely on the `InternPool` can be reconstructed from `Air.Inst.Ref` references.
    // TODO: Reconstruct inside import function.
    const ref = Air.Inst.Ref.one; // Arbitrary test reference.
    {
        var intern_pool: InternPool = .empty;
        const thread_count = 1;
        try intern_pool.init(allocator, thread_count);
        defer intern_pool.deinit(allocator);

        // TODO: try to find root cause of the Value and Zcu.PerThread dependency.
        // => can those be separated for our specific use case?
        // `Air.value` is inlined here and expanded:
        const value = if (ref.toInterned()) |index| Value.fromInterned(index) else value: {
            const index = ref.toIndex().?; // Can be unwrapped due to the above check.
            const type_value = air.typeOfIndex(index, &intern_pool);
            const value = try type_value.onePossibleValue(zcu_per_thread);
            break :value value;
        };
        _ = value; // TODO: NYI
    }
}

test "Pack AIR functions into one buffer" {
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
        const extra_max_size = 32;
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

    // Test that exporting / importing multiple functions in a continuous stream works.
    const buffer_size = 4096;
    var buffer = [1]u8{0} ** buffer_size;
    var stream = std.io.FixedBufferStream([]u8){ .buffer = &buffer, .pos = 0 };
    const liveness = null;
    const function_name = "test.main";
    const writer = stream.writer().any();

    const iterations = 3;

    // Export without resetting the writer position.
    for (0..iterations) |_| exportAir(writer, zcu_per_thread, air, liveness, function_name);
    const total_size_bytes = try stream.getPos();

    try stream.seekTo(0);
    for (0..iterations) |_| {
        var imported = try importAir(allocator, stream.reader().any());
        defer imported.deinit();

        try t.expectEqual(AirHeader.MAGIC, imported.header.magic);
        try t.expectEqual(function_name.len, imported.header.function_name_length);
        try t.expectEqualStrings(function_name, imported.function_name);
        try t.expectEqual(air.instructions.len, imported.air.instructions.len);
        try t.expectEqual(air.extra.len, imported.air.extra.len);
        try t.expectEqual(null, imported.liveness);

        const tags = imported.air.instructions.items(.tag);
        const variants = imported.air.instructions.items(.data);
        for (tags, variants, air.instructions.items(.tag), air.instructions.items(.data)) |tag, variant, expected_tag, expected_variant| {
            try t.expectEqual(expected_tag, tag);
            const DataType = *align(1) const u64;
            try t.expectEqual(@as(DataType, @ptrCast(&expected_variant)).*, @as(DataType, @ptrCast(&variant)).*);
        }

        try t.expectEqualSlices(u32, air.extra, imported.air.extra);

        const main_body_indexes = imported.air.getMainBody();
        try t.expectEqual(air.instructions.len, main_body_indexes.len);
        for (0..air.instructions.len, main_body_indexes) |expected_i, actual_i| try t.expectEqual(expected_i, @intFromEnum(actual_i));
    }

    const total_size_bytes_read = try stream.getPos();
    try t.expectEqual(total_size_bytes, total_size_bytes_read);
}
