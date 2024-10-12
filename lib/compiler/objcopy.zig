const builtin = @import("builtin");
const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const elf = std.elf;
const Allocator = std.mem.Allocator;
const File = std.fs.File;
const assert = std.debug.assert;

const fatal = std.zig.fatal;
const Server = std.zig.Server;

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var general_purpose_allocator: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const gpa = general_purpose_allocator.allocator();

    const args = try std.process.argsAlloc(arena);
    return cmdObjCopy(gpa, arena, args[1..]);
}

fn cmdObjCopy(
    gpa: Allocator,
    arena: Allocator,
    args: []const []const u8,
) !void {
    const options = parseCommandLine(args);
    if (options.print_usage) {
        try std.io.getStdOut().writeAll(usage);
        return;
    }

    const input = options.input;
    const output = options.output;

    var in_file = fs.cwd().openFile(input, .{}) catch |err|
        fatal("unable to open '{s}': {s}", .{ input, @errorName(err) });
    defer in_file.close();

    const add_section = if (options.add_section) |add| add_section_content: {
        var section_file = fs.cwd().openFile(add.file_path, .{}) catch |err| fatal("unable to open '{s}': {s}", .{ add.file_path, @errorName(err) });
        defer section_file.close();

        const content = try section_file.readToEndAlloc(arena, std.math.maxInt(usize));
        break :add_section_content AddSection{ .section_name = add.section_name, .content = content };
    } else null;
    defer if (add_section) |add| arena.free(add.content);

    const in_ofmt = .elf;

    const out_fmt: std.Target.ObjectFormat = options.opt_out_fmt orelse ofmt: {
        if (mem.endsWith(u8, output, ".hex") or std.mem.endsWith(u8, output, ".ihex")) {
            break :ofmt .hex;
        } else if (mem.endsWith(u8, output, ".bin")) {
            break :ofmt .raw;
        } else if (mem.endsWith(u8, output, ".elf")) {
            break :ofmt .elf;
        } else {
            break :ofmt in_ofmt;
        }
    };

    const mode = mode: {
        if (out_fmt != .elf or options.only_keep_debug)
            break :mode fs.File.default_mode;
        if (in_file.stat()) |stat|
            break :mode stat.mode
        else |_|
            break :mode fs.File.default_mode;
    };
    var out_file = try fs.cwd().createFile(output, .{ .mode = mode });
    defer out_file.close();

    switch (out_fmt) {
        .hex, .raw => {
            if (options.strip_debug or options.strip_all or options.only_keep_debug)
                fatal("zig objcopy: ELF to RAW or HEX copying does not support --strip", .{});
            if (options.opt_extract != null)
                fatal("zig objcopy: ELF to RAW or HEX copying does not support --extract-to", .{});
            if (options.add_section != null)
                fatal("zig objcopy: ELF to RAW or HEX copying does not support --add-section", .{});
            if (options.set_section_alignment != null)
                fatal("zig objcopy: ELF to RAW or HEX copying does not support --set_section_alignment", .{});
            if (options.set_section_flags != null)
                fatal("zig objcopy: ELF to RAW or HEX copying does not support --set_section_flags", .{});

            const elf_hdr = std.elf.Header.read(in_file) catch |err| switch (err) {
                error.InvalidElfMagic => fatal("not an ELF file: '{s}'", .{input}),
                else => fatal("unable to read '{s}': {s}", .{ input, @errorName(err) }),
            };

            // e_ident data is not stored in the parsed std.elf.Header struct but is required to emit the new header
            var e_ident: [elf.EI_NIDENT]u8 = undefined;
            const bytes_read = in_file.preadAll(&e_ident, 0) catch |err| fatal("unable to read '{s}': {s}", .{ input, @errorName(err) });
            if (bytes_read < elf.EI_NIDENT) fatal("not an ELF file: '{s}'", .{input});
            const elf_header = ElfHeader{ .e_ident = e_ident, .parsed = elf_hdr };

            try emitElf(arena, in_file, out_file, elf_header.parsed, .{
                .ofmt = out_fmt,
                .only_section = options.only_section,
                .pad_to = options.pad_to,
            });
        },
        .elf => {
            if (options.only_section) |_| fatal("zig objcopy: ELF to ELF copying does not support --only-section", .{});
            if (options.pad_to) |_| fatal("zig objcopy: ELF to ELF copying does not support --pad-to", .{});

            // * Parse: create a descriptor of the ELF input
            // * Apply: apply modifications on the descriptor
            // * Process: process descritpro for simple ELF output
            // * Write: write new ELF file according to the processed descriptor
            var input_descriptor = try parseElfDescriptor(arena, in_file);
            defer input_descriptor.deinit();
            try applyOptions(&input_descriptor, .{
                .strip_debug = options.strip_debug,
                .strip_all = options.strip_all,
                .only_keep_debug = options.only_keep_debug,
                .add_debuglink = options.opt_add_debuglink,
                .extract_to = options.opt_extract,
                .compress_debug = options.compress_debug_sections,
                .add_section = add_section,
                .set_section_alignment = options.set_section_alignment,
                .set_section_flags = options.set_section_flags,
            });
            const processed_descriptor = try processElfDescriptor(arena, input_descriptor);
            try writeElf(arena, processed_descriptor, in_file, out_file);

            return std.process.cleanExit();
        },
        else => fatal("unsupported output object format: {s}", .{@tagName(out_fmt)}),
    }

    if (options.listen) {
        var server = try Server.init(.{
            .gpa = gpa,
            .in = std.io.getStdIn(),
            .out = std.io.getStdOut(),
            .zig_version = builtin.zig_version_string,
        });
        defer server.deinit();

        var seen_update = false;
        while (true) {
            const hdr = try server.receiveMessage();
            switch (hdr.tag) {
                .exit => {
                    return std.process.cleanExit();
                },
                .update => {
                    if (seen_update) fatal("zig objcopy only supports 1 update for now", .{});
                    seen_update = true;

                    // The build system already knows what the output is at this point, we
                    // only need to communicate that the process has finished.
                    // Use the empty error bundle to indicate that the update is done.
                    try server.serveErrorBundle(std.zig.ErrorBundle.empty);
                },
                else => fatal("unsupported message: {s}", .{@tagName(hdr.tag)}),
            }
        }
    }
    return std.process.cleanExit();
}

const Options = struct {
    const AddSectionPath = struct {
        section_name: []const u8,
        file_path: []const u8,
    };

    print_usage: bool,
    input: []const u8,
    output: []const u8,
    opt_out_fmt: ?std.Target.ObjectFormat,
    opt_extract: ?[]const u8,
    opt_add_debuglink: ?[]const u8,
    only_section: ?[]const u8,
    pad_to: ?u64,
    strip_all: bool,
    strip_debug: bool,
    only_keep_debug: bool,
    compress_debug_sections: bool,
    listen: bool,
    add_section: ?AddSectionPath,
    set_section_alignment: ?SetSectionAlignment,
    set_section_flags: ?SetSectionFlags,
};

fn parseCommandLine(args: []const []const u8) Options {
    var print_usage = false;
    var input: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var opt_out_fmt: ?std.Target.ObjectFormat = null;
    var opt_extract: ?[]const u8 = null;
    var opt_add_debuglink: ?[]const u8 = null;
    var only_section: ?[]const u8 = null;
    var pad_to: ?u64 = null;
    var strip_all: bool = false;
    var strip_debug: bool = false;
    var only_keep_debug: bool = false;
    var compress_debug_sections: bool = false;
    var listen = false;
    var add_section: ?Options.AddSectionPath = null;
    var set_section_alignment: ?SetSectionAlignment = null;
    var set_section_flags: ?SetSectionFlags = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!mem.startsWith(u8, arg, "-")) {
            if (input == null) {
                input = arg;
            } else if (output == null) {
                output = arg;
            } else {
                fatal("unexpected positional argument: '{s}'", .{arg});
            }
        } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            print_usage = true;
        } else if (mem.eql(u8, arg, "-O") or mem.eql(u8, arg, "--output-target")) {
            i += 1;
            if (i >= args.len) fatal("expected another argument after '{s}'", .{arg});
            const next_arg = args[i];
            if (mem.eql(u8, next_arg, "binary")) {
                opt_out_fmt = .raw;
            } else {
                opt_out_fmt = std.meta.stringToEnum(std.Target.ObjectFormat, next_arg) orelse
                    fatal("invalid output format: '{s}'", .{next_arg});
            }
        } else if (mem.startsWith(u8, arg, "--output-target=")) {
            const next_arg = arg["--output-target=".len..];
            if (mem.eql(u8, next_arg, "binary")) {
                opt_out_fmt = .raw;
            } else {
                opt_out_fmt = std.meta.stringToEnum(std.Target.ObjectFormat, next_arg) orelse
                    fatal("invalid output format: '{s}'", .{next_arg});
            }
        } else if (mem.eql(u8, arg, "-j") or mem.eql(u8, arg, "--only-section")) {
            i += 1;
            if (i >= args.len) fatal("expected another argument after '{s}'", .{arg});
            only_section = args[i];
        } else if (mem.eql(u8, arg, "--listen=-")) {
            listen = true;
        } else if (mem.startsWith(u8, arg, "--only-section=")) {
            only_section = arg["--only-section=".len..];
        } else if (mem.eql(u8, arg, "--pad-to")) {
            i += 1;
            if (i >= args.len) fatal("expected another argument after '{s}'", .{arg});
            pad_to = std.fmt.parseInt(u64, args[i], 0) catch |err| {
                fatal("unable to parse: '{s}': {s}", .{ args[i], @errorName(err) });
            };
        } else if (mem.eql(u8, arg, "-g") or mem.eql(u8, arg, "--strip-debug")) {
            strip_debug = true;
        } else if (mem.eql(u8, arg, "-S") or mem.eql(u8, arg, "--strip-all")) {
            strip_all = true;
        } else if (mem.eql(u8, arg, "--only-keep-debug")) {
            only_keep_debug = true;
        } else if (mem.eql(u8, arg, "--compress-debug-sections")) {
            compress_debug_sections = true;
        } else if (mem.startsWith(u8, arg, "--add-gnu-debuglink=")) {
            opt_add_debuglink = arg["--add-gnu-debuglink=".len..];
        } else if (mem.eql(u8, arg, "--add-gnu-debuglink")) {
            i += 1;
            if (i >= args.len) fatal("expected another argument after '{s}'", .{arg});
            opt_add_debuglink = args[i];
        } else if (mem.startsWith(u8, arg, "--extract-to=")) {
            opt_extract = arg["--extract-to=".len..];
        } else if (mem.eql(u8, arg, "--extract-to")) {
            i += 1;
            if (i >= args.len) fatal("expected another argument after '{s}'", .{arg});
            opt_extract = args[i];
        } else if (mem.eql(u8, arg, "--set-section-alignment")) {
            i += 1;
            if (i >= args.len) fatal("expected section name and alignment arguments after '{s}'", .{arg});

            if (splitOption(args[i])) |split| {
                const alignment = std.fmt.parseInt(u32, split.second, 10) catch |err| {
                    fatal("unable to parse alignment number: '{s}': {s}", .{ split.second, @errorName(err) });
                };
                if (!std.math.isPowerOfTwo(alignment)) fatal("alignment must be a power of two", .{});
                set_section_alignment = .{ .section_name = split.first, .alignment = alignment };
            } else {
                fatal("unrecognized argument: '{s}', expecting <name>=<alignment>", .{args[i]});
            }
        } else if (mem.eql(u8, arg, "--set-section-flags")) {
            i += 1;
            if (i >= args.len) fatal("expected section name and filename arguments after '{s}'", .{arg});

            if (splitOption(args[i])) |split| {
                set_section_flags = .{ .section_name = split.first, .flags = parseSectionFlags(split.second) };
            } else {
                fatal("unrecognized argument: '{s}', expecting <name>=<flags>", .{args[i]});
            }
        } else if (mem.eql(u8, arg, "--add-section")) {
            i += 1;
            if (i >= args.len) fatal("expected section name and filename arguments after '{s}'", .{arg});

            if (splitOption(args[i])) |split| {
                add_section = .{ .section_name = split.first, .file_path = split.second };
            } else {
                fatal("unrecognized argument: '{s}', expecting <name>=<file>", .{args[i]});
            }
        } else {
            fatal("unrecognized argument: '{s}'", .{arg});
        }
    }

    // validate positional arguments
    if (input == null) fatal("expected input parameter", .{});
    if (output == null) fatal("expected output parameter", .{});
    if (std.mem.eql(u8, input.?, output.?)) fatal("input and output file paths must be different", .{});

    return .{
        .print_usage = print_usage,
        .input = input.?,
        .output = output.?,
        .opt_out_fmt = opt_out_fmt,
        .opt_extract = opt_extract,
        .opt_add_debuglink = opt_add_debuglink,
        .only_section = only_section,
        .pad_to = pad_to,
        .strip_all = strip_all,
        .strip_debug = strip_debug,
        .only_keep_debug = only_keep_debug,
        .compress_debug_sections = compress_debug_sections,
        .listen = listen,
        .add_section = add_section,
        .set_section_alignment = set_section_alignment,
        .set_section_flags = set_section_flags,
    };
}

const usage =
    \\Usage: zig objcopy [options] input output
    \\
    \\Options:
    \\  -h, --help                              Print this help and exit
    \\  --output-target=<value>                 Format of the output file
    \\  -O <value>                              Alias for --output-target
    \\  --only-section=<section>                Remove all but <section>
    \\  -j <value>                              Alias for --only-section
    \\  --pad-to <addr>                         Pad the last section up to address <addr>
    \\  --strip-debug, -g                       Remove all debug sections from the output.
    \\  --strip-all, -S                         Remove all debug sections and symbol table from the output.
    \\  --only-keep-debug                       Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact.
    \\  --add-gnu-debuglink=<file>              Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.
    \\  --extract-to <file>                     Extract the removed sections into <file>, and add a .gnu-debuglink section.
    \\  --compress-debug-sections               Compress DWARF debug sections with zlib
    \\  --set-section-alignment <name>=<align>  Set alignment of section <name> to <align> bytes. Must be a power of two.
    \\  --set-section-flags <name>=<file>       Set flags of section <name> to <flags> represented as a comma separated set of flags.
    \\  --add-section <name>=<file>             Add file content from <file> with the a new section named <name>.
    \\
;

pub const EmitRawElfOptions = struct {
    ofmt: std.Target.ObjectFormat,
    only_section: ?[]const u8 = null,
    pad_to: ?u64 = null,
    add_section: ?AddSection = null,
    set_section_alignment: ?SetSectionAlignment = null,
    set_section_flags: ?SetSectionFlags = null,
};

const AddSection = struct {
    section_name: []const u8,
    content: []const u8,
};

const SetSectionAlignment = struct {
    section_name: []const u8,
    alignment: u32,
};

const SetSectionFlags = struct {
    section_name: []const u8,
    flags: SectionFlags,
};

fn emitElf(
    arena: Allocator,
    in_file: File,
    out_file: File,
    elf_hdr: elf.Header,
    options: EmitRawElfOptions,
) !void {
    var binary_elf_output = try BinaryElfOutput.parse(arena, in_file, elf_hdr);
    defer binary_elf_output.deinit();

    if (options.ofmt == .elf) {
        fatal("zig objcopy: ELF to ELF copying is not implemented yet", .{});
    }

    if (options.only_section) |target_name| {
        switch (options.ofmt) {
            .hex => fatal("zig objcopy: hex format with sections is not implemented yet", .{}),
            .raw => {
                for (binary_elf_output.sections.items) |section| {
                    if (section.name) |curr_name| {
                        if (!std.mem.eql(u8, curr_name, target_name))
                            continue;
                    } else {
                        continue;
                    }

                    try writeBinaryElfSection(in_file, out_file, section);
                    try padFile(out_file, options.pad_to);
                    return;
                }
            },
            else => unreachable,
        }

        return error.SectionNotFound;
    }

    switch (options.ofmt) {
        .raw => {
            for (binary_elf_output.sections.items) |section| {
                try out_file.seekTo(section.binaryOffset);
                try writeBinaryElfSection(in_file, out_file, section);
            }
            try padFile(out_file, options.pad_to);
        },
        .hex => {
            if (binary_elf_output.segments.items.len == 0) return;
            if (!containsValidAddressRange(binary_elf_output.segments.items)) {
                return error.InvalidHexfileAddressRange;
            }

            var hex_writer = HexWriter{ .out_file = out_file };
            for (binary_elf_output.segments.items) |segment| {
                try hex_writer.writeSegment(segment, in_file);
            }
            if (options.pad_to) |_| {
                // Padding to a size in hex files isn't applicable
                return error.InvalidArgument;
            }
            try hex_writer.writeEOF();
        },
        else => unreachable,
    }
}

const BinaryElfSection = struct {
    elfOffset: u64,
    binaryOffset: u64,
    fileSize: usize,
    name: ?[]const u8,
    segment: ?*BinaryElfSegment,
};

const BinaryElfSegment = struct {
    physicalAddress: u64,
    virtualAddress: u64,
    elfOffset: u64,
    binaryOffset: u64,
    fileSize: u64,
    firstSection: ?*BinaryElfSection,
};

const BinaryElfOutput = struct {
    segments: std.ArrayListUnmanaged(*BinaryElfSegment),
    sections: std.ArrayListUnmanaged(*BinaryElfSection),
    allocator: Allocator,
    shstrtab: ?[]const u8,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.shstrtab) |shstrtab|
            self.allocator.free(shstrtab);
        self.sections.deinit(self.allocator);
        self.segments.deinit(self.allocator);
    }

    pub fn parse(allocator: Allocator, elf_file: File, elf_hdr: elf.Header) !Self {
        var self: Self = .{
            .segments = .{},
            .sections = .{},
            .allocator = allocator,
            .shstrtab = null,
        };
        errdefer self.sections.deinit(allocator);
        errdefer self.segments.deinit(allocator);

        self.shstrtab = blk: {
            if (elf_hdr.shstrndx >= elf_hdr.shnum) break :blk null;

            var section_headers = elf_hdr.section_header_iterator(&elf_file);

            var section_counter: usize = 0;
            while (section_counter < elf_hdr.shstrndx) : (section_counter += 1) {
                _ = (try section_headers.next()).?;
            }

            const shstrtab_shdr = (try section_headers.next()).?;

            const buffer = try allocator.alloc(u8, @intCast(shstrtab_shdr.sh_size));
            errdefer allocator.free(buffer);

            const num_read = try elf_file.preadAll(buffer, shstrtab_shdr.sh_offset);
            if (num_read != buffer.len) return error.EndOfStream;

            break :blk buffer;
        };

        errdefer if (self.shstrtab) |shstrtab| allocator.free(shstrtab);

        var section_headers = elf_hdr.section_header_iterator(&elf_file);
        while (try section_headers.next()) |section| {
            if (sectionValidForOutput(section)) {
                const newSection = try allocator.create(BinaryElfSection);

                newSection.binaryOffset = 0;
                newSection.elfOffset = section.sh_offset;
                newSection.fileSize = @intCast(section.sh_size);
                newSection.segment = null;

                newSection.name = if (self.shstrtab) |shstrtab|
                    std.mem.span(@as([*:0]const u8, @ptrCast(&shstrtab[section.sh_name])))
                else
                    null;

                try self.sections.append(allocator, newSection);
            }
        }

        var program_headers = elf_hdr.program_header_iterator(&elf_file);
        while (try program_headers.next()) |phdr| {
            if (phdr.p_type == elf.PT_LOAD) {
                const newSegment = try allocator.create(BinaryElfSegment);

                newSegment.physicalAddress = phdr.p_paddr;
                newSegment.virtualAddress = phdr.p_vaddr;
                newSegment.fileSize = @intCast(phdr.p_filesz);
                newSegment.elfOffset = phdr.p_offset;
                newSegment.binaryOffset = 0;
                newSegment.firstSection = null;

                for (self.sections.items) |section| {
                    if (sectionWithinSegment(section, phdr)) {
                        if (section.segment) |sectionSegment| {
                            if (sectionSegment.elfOffset > newSegment.elfOffset) {
                                section.segment = newSegment;
                            }
                        } else {
                            section.segment = newSegment;
                        }

                        if (newSegment.firstSection == null) {
                            newSegment.firstSection = section;
                        }
                    }
                }

                try self.segments.append(allocator, newSegment);
            }
        }

        mem.sort(*BinaryElfSegment, self.segments.items, {}, segmentSortCompare);

        for (self.segments.items, 0..) |firstSegment, i| {
            if (firstSegment.firstSection) |firstSection| {
                const diff = firstSection.elfOffset - firstSegment.elfOffset;

                firstSegment.elfOffset += diff;
                firstSegment.fileSize += diff;
                firstSegment.physicalAddress += diff;

                const basePhysicalAddress = firstSegment.physicalAddress;

                for (self.segments.items[i + 1 ..]) |segment| {
                    segment.binaryOffset = segment.physicalAddress - basePhysicalAddress;
                }
                break;
            }
        }

        for (self.sections.items) |section| {
            if (section.segment) |segment| {
                section.binaryOffset = segment.binaryOffset + (section.elfOffset - segment.elfOffset);
            }
        }

        mem.sort(*BinaryElfSection, self.sections.items, {}, sectionSortCompare);

        return self;
    }

    fn sectionWithinSegment(section: *BinaryElfSection, segment: elf.Elf64_Phdr) bool {
        return segment.p_offset <= section.elfOffset and (segment.p_offset + segment.p_filesz) >= (section.elfOffset + section.fileSize);
    }

    fn sectionValidForOutput(shdr: anytype) bool {
        return shdr.sh_type != elf.SHT_NOBITS and
            ((shdr.sh_flags & elf.SHF_ALLOC) == elf.SHF_ALLOC);
    }

    fn segmentSortCompare(context: void, left: *BinaryElfSegment, right: *BinaryElfSegment) bool {
        _ = context;
        if (left.physicalAddress < right.physicalAddress) {
            return true;
        }
        if (left.physicalAddress > right.physicalAddress) {
            return false;
        }
        return false;
    }

    fn sectionSortCompare(context: void, left: *BinaryElfSection, right: *BinaryElfSection) bool {
        _ = context;
        return left.binaryOffset < right.binaryOffset;
    }
};

fn writeBinaryElfSection(elf_file: File, out_file: File, section: *BinaryElfSection) !void {
    try out_file.writeFileAll(elf_file, .{
        .in_offset = section.elfOffset,
        .in_len = section.fileSize,
    });
}

const HexWriter = struct {
    prev_addr: ?u32 = null,
    out_file: File,

    /// Max data bytes per line of output
    const MAX_PAYLOAD_LEN: u8 = 16;

    fn addressParts(address: u16) [2]u8 {
        const msb: u8 = @truncate(address >> 8);
        const lsb: u8 = @truncate(address);
        return [2]u8{ msb, lsb };
    }

    const Record = struct {
        const Type = enum(u8) {
            Data = 0,
            EOF = 1,
            ExtendedSegmentAddress = 2,
            ExtendedLinearAddress = 4,
        };

        address: u16,
        payload: union(Type) {
            Data: []const u8,
            EOF: void,
            ExtendedSegmentAddress: [2]u8,
            ExtendedLinearAddress: [2]u8,
        },

        fn EOF() Record {
            return Record{
                .address = 0,
                .payload = .EOF,
            };
        }

        fn Data(address: u32, data: []const u8) Record {
            return Record{
                .address = @intCast(address % 0x10000),
                .payload = .{ .Data = data },
            };
        }

        fn Address(address: u32) Record {
            assert(address > 0xFFFF);
            const segment: u16 = @intCast(address / 0x10000);
            if (address > 0xFFFFF) {
                return Record{
                    .address = 0,
                    .payload = .{ .ExtendedLinearAddress = addressParts(segment) },
                };
            } else {
                return Record{
                    .address = 0,
                    .payload = .{ .ExtendedSegmentAddress = addressParts(segment << 12) },
                };
            }
        }

        fn getPayloadBytes(self: *const Record) []const u8 {
            return switch (self.payload) {
                .Data => |d| d,
                .EOF => @as([]const u8, &.{}),
                .ExtendedSegmentAddress, .ExtendedLinearAddress => |*seg| seg,
            };
        }

        fn checksum(self: Record) u8 {
            const payload_bytes = self.getPayloadBytes();

            var sum: u8 = @intCast(payload_bytes.len);
            const parts = addressParts(self.address);
            sum +%= parts[0];
            sum +%= parts[1];
            sum +%= @intFromEnum(self.payload);
            for (payload_bytes) |byte| {
                sum +%= byte;
            }
            return (sum ^ 0xFF) +% 1;
        }

        fn write(self: Record, file: File) File.WriteError!void {
            const linesep = "\r\n";
            // colon, (length, address, type, payload, checksum) as hex, CRLF
            const BUFSIZE = 1 + (1 + 2 + 1 + MAX_PAYLOAD_LEN + 1) * 2 + linesep.len;
            var outbuf: [BUFSIZE]u8 = undefined;
            const payload_bytes = self.getPayloadBytes();
            assert(payload_bytes.len <= MAX_PAYLOAD_LEN);

            const line = try std.fmt.bufPrint(&outbuf, ":{0X:0>2}{1X:0>4}{2X:0>2}{3s}{4X:0>2}" ++ linesep, .{
                @as(u8, @intCast(payload_bytes.len)),
                self.address,
                @intFromEnum(self.payload),
                std.fmt.fmtSliceHexUpper(payload_bytes),
                self.checksum(),
            });
            try file.writeAll(line);
        }
    };

    pub fn writeSegment(self: *HexWriter, segment: *const BinaryElfSegment, elf_file: File) !void {
        var buf: [MAX_PAYLOAD_LEN]u8 = undefined;
        var bytes_read: usize = 0;
        while (bytes_read < segment.fileSize) {
            const row_address: u32 = @intCast(segment.physicalAddress + bytes_read);

            const remaining = segment.fileSize - bytes_read;
            const to_read: usize = @intCast(@min(remaining, MAX_PAYLOAD_LEN));
            const did_read = try elf_file.preadAll(buf[0..to_read], segment.elfOffset + bytes_read);
            if (did_read < to_read) return error.UnexpectedEOF;

            try self.writeDataRow(row_address, buf[0..did_read]);

            bytes_read += did_read;
        }
    }

    fn writeDataRow(self: *HexWriter, address: u32, data: []const u8) File.WriteError!void {
        const record = Record.Data(address, data);
        if (address > 0xFFFF and (self.prev_addr == null or record.address != self.prev_addr.?)) {
            try Record.Address(address).write(self.out_file);
        }
        try record.write(self.out_file);
        self.prev_addr = @intCast(record.address + data.len);
    }

    fn writeEOF(self: HexWriter) File.WriteError!void {
        try Record.EOF().write(self.out_file);
    }
};

fn containsValidAddressRange(segments: []*BinaryElfSegment) bool {
    const max_address = std.math.maxInt(u32);
    for (segments) |segment| {
        if (segment.fileSize > max_address or
            segment.physicalAddress > max_address - segment.fileSize) return false;
    }
    return true;
}

fn padFile(f: File, opt_size: ?u64) !void {
    const size = opt_size orelse return;
    try f.setEndPos(size);
}

test "HexWriter.Record.Address has correct payload and checksum" {
    const record = HexWriter.Record.Address(0x0800_0000);
    const payload = record.getPayloadBytes();
    const sum = record.checksum();
    try std.testing.expect(sum == 0xF2);
    try std.testing.expect(payload.len == 2);
    try std.testing.expect(payload[0] == 8);
    try std.testing.expect(payload[1] == 0);
}

test "containsValidAddressRange" {
    var segment = BinaryElfSegment{
        .physicalAddress = 0,
        .virtualAddress = 0,
        .elfOffset = 0,
        .binaryOffset = 0,
        .fileSize = 0,
        .firstSection = null,
    };
    var buf: [1]*BinaryElfSegment = .{&segment};

    // segment too big
    segment.fileSize = std.math.maxInt(u32) + 1;
    try std.testing.expect(!containsValidAddressRange(&buf));

    // start address too big
    segment.physicalAddress = std.math.maxInt(u32) + 1;
    segment.fileSize = 2;
    try std.testing.expect(!containsValidAddressRange(&buf));

    // max address too big
    segment.physicalAddress = std.math.maxInt(u32) - 1;
    segment.fileSize = 2;
    try std.testing.expect(!containsValidAddressRange(&buf));

    // is ok
    segment.physicalAddress = std.math.maxInt(u32) - 1;
    segment.fileSize = 1;
    try std.testing.expect(containsValidAddressRange(&buf));
}

// -------------
// ELF to ELF stripping

const StripElfOptions = struct {
    extract_to: ?[]const u8 = null,
    add_debuglink: ?[]const u8 = null,
    strip_all: bool = false,
    strip_debug: bool = false,
    only_keep_debug: bool = false,
    compress_debug: bool = false,
    add_section: ?AddSection = null,
    set_section_alignment: ?SetSectionAlignment = null,
    set_section_flags: ?SetSectionFlags = null,
};

const Section = struct {
    // copy from the input file
    const InputFileRange = struct {
        offset: usize,
        size: usize,
    };

    // SHT_NOBITS section like .bss do not store content in the ELF file
    const NoBits = struct {
        offset: usize,
        size: usize,
    };

    // new data written into new sections that did not exist in the input
    const Data = []const u8;

    // section contents have different sources
    const ContentSource = union(enum) {
        input_file_range: InputFileRange,
        no_bits: NoBits,
        data: Data,

        fn fileSize(self: *const @This()) usize {
            return switch (self.*) {
                .input_file_range => |range| range.size,
                .no_bits => 0, // no size in ELF file, only at runtime
                .data => |data| data.len,
            };
        }
    };

    // Reduced section header that does not include fields that are computed from the content source.
    // Using std.elf.Shdr would make the code hard to understand since it's unclear what needs to be writen in what step.
    const SectionHeader = struct {
        // sh_name: Elf64_Word,
        sh_type: usize,
        sh_flags: usize,
        sh_addr: usize,
        // sh_offset: usize,
        // sh_size: usize,
        sh_link: usize,
        sh_info: usize,
        sh_addralign: usize,
        sh_entsize: usize,
    };

    // TODO: heap allocation could be avoided using a union type of a slice or the input file offset but probably not worth the effort
    name: []const u8, // head allocated copy
    // shdr: SectionHeader,
    shdr: std.elf.Shdr,
    content: ContentSource,

    // Create the section header in the input file endianess
    fn toShdr(self: *const @This(), target_endianess: std.builtin.Endian) std.elf.Shdr {
        _ = target_endianess;
        std.log.warn("TODO: apply endianess on copy if native does not match target", .{});
        // std.mem.byteSwapAllFields(comptime S: type, ptr: *S)
        _ = target_endianess;
        return self.shdr;
    }

    // User has to free read memory
    fn readContentAlloc(self: *const @This(), input: anytype, allocator: std.mem.Allocator) ![]const u8 {
        comptime assert(std.meta.hasMethod(@TypeOf(input), "seekableStream"));
        comptime assert(std.meta.hasMethod(@TypeOf(input), "reader"));

        switch (self.content) {
            .input_file_range => |range| {
                const data = try allocator.alloc(u8, range.size);
                errdefer allocator.free(data);

                try input.seekableStream().seekTo(range.offset);
                const bytes_read = try input.reader().readAll(data);
                if (bytes_read != data.len) return error.TruncatedElf;

                return data;
            },
            .no_bits => return "", // .bss, etc.
            .data => |data| {
                const copy = try allocator.alloc(u8, data.len);
                @memcpy(copy, data);
                return copy;
            },
        }
    }
};

const ProgramSegment = struct {
    phdr: std.elf.Phdr,

    // Create the section header in the input file endianess
    pub fn toPhdr(self: *const @This(), target_endianess: std.builtin.Endian) std.elf.Phdr {
        std.log.warn("TODO: apply endianess", .{});
        // std.mem.byteSwapAllFields(comptime S: type, ptr: *S)
        _ = target_endianess;
        return self.phdr;
    }
};

// Describes what the result of objcopy is supposed to look like.
const ElfDescriptor = struct {
    elf_header: ElfHeader,
    sections: std.ArrayList(Section),
    program_segments: std.ArrayList(ProgramSegment),
    // heap allocated section name table copy that section names hold slices to
    string_table_content: []const u8,
    string_table_content_allocator: Allocator,

    // TODO: clarify what data is kept across the stages and when it is freed
    // also add init function with capacities?
    fn deinit(self: *const @This()) void {
        self.sections.deinit();
        self.program_segments.deinit();
        self.string_table_content_allocator.free(self.string_table_content);
    }
};

inline fn isStringTable(shdr: std.elf.Shdr) bool {
    return shdr.sh_type == std.elf.SHT_STRTAB;
}

inline fn isSectionInFile(shdr: std.elf.Shdr) bool {
    return shdr.sh_type != std.elf.SHT_NOBITS and (shdr.sh_flags & std.elf.SHF_ALLOC) != 0;
}

fn parseElfDescriptor(allocator: Allocator, input: anytype) !ElfDescriptor {
    comptime assert(std.meta.hasMethod(@TypeOf(input), "seekableStream"));
    comptime assert(std.meta.hasMethod(@TypeOf(input), "reader"));

    // e_ident data is not stored in the parsed std.elf.Header struct but is required to emit the new header
    var e_ident: [elf.EI_NIDENT]u8 = undefined;
    try input.seekableStream().seekTo(0);
    const bytes_read = try input.reader().readAll(&e_ident);
    if (bytes_read < elf.EI_NIDENT) fatal("unable to read ELF input file", .{});

    const header = std.elf.Header.read(input) catch |err| switch (err) {
        error.InvalidElfMagic => fatal("input is not an ELF file", .{}),
        else => fatal("unable to read input: {s}", .{@errorName(err)}),
    };

    // TODO: document what needs to be done to remove this limitation
    if (header.endian != builtin.target.cpu.arch.endian()) fatal("zig objcopy: ELF to ELF copying only supports native endian", .{});
    if (header.phoff == 0) fatal("zig objcopy: ELF to ELF copying only supports programs", .{});

    // read shstrtab
    const string_table_section = strtab: {
        // NOTE: iterator accounts for endianess, so it's always native
        var section_it = header.section_header_iterator(input);
        var i: usize = 0;
        while (try section_it.next()) |section| : (i += 1) {
            if (i == header.shstrndx) {
                if (!isStringTable(section)) fatal(
                    "zig objcopy: section type of section name string table must be SHT_STRTAB 0x{x}, got 0x{x}",
                    .{ std.elf.SHT_STRTAB, section.sh_type },
                );

                break :strtab Section{
                    .name = ".strtab",
                    .shdr = section,
                    .content = .{ .input_file_range = .{ .offset = section.sh_offset, .size = section.sh_size } },
                };
            }
        }
        fatal("input ELF file does not contain a string table section (strtab)", .{});
    };
    const string_table_content = try string_table_section.readContentAlloc(input, allocator);

    var sections = try std.ArrayList(Section).initCapacity(allocator, header.shnum);
    {
        var section_it = header.section_header_iterator(input);
        while (try section_it.next()) |section| {
            if (section.sh_name >= string_table_content.len)
                fatal("invalid ELF input file: section name offset {d} exceeds strtab size {d}", .{ section.sh_name, string_table_content.len });

            const name = std.mem.span(@as([*:0]const u8, @ptrCast(&string_table_content[section.sh_name])));

            const content: Section.ContentSource = if (isSectionInFile(section))
                .{ .input_file_range = .{ .offset = section.sh_offset, .size = section.sh_size } }
            else
                .{ .no_bits = .{ .offset = section.sh_offset, .size = section.sh_size } };

            try sections.append(.{
                .name = name,
                .shdr = section,
                .content = content,
            });
        }
    }

    var program_segments = try std.ArrayList(ProgramSegment).initCapacity(allocator, header.phnum);
    var program_it = header.program_header_iterator(input);
    while (try program_it.next()) |program| {
        try program_segments.append(.{ .phdr = program });
    }

    return .{
        .elf_header = .{ .e_ident = e_ident, .parsed = header },
        .sections = sections,
        .program_segments = program_segments,
        .string_table_content = string_table_content,
        .string_table_content_allocator = allocator,
    };
}

// descriptor in out parameter to be modified
fn applyOptions(descriptor: *ElfDescriptor, options: StripElfOptions) !void {
    const no_flags = 0;
    const not_mapped = 0;
    const default_alignment = 8;
    const dynamic = 0;

    // TODO: make sure to shift the section name string table index when removing sections
    // or extract a function for that

    // TODO: options.extract_to
    // TODO: options.add_debuglink
    // TODO: options.strip_all
    // TODO: options.strip_debug
    // TODO: options.only_keep_debug
    // TODO: options.compress_debug

    if (options.add_section) |add| {
        try descriptor.sections.append(.{
            .name = add.section_name,
            .shdr = .{
                .sh_name = 0, // NOTE: filled after strtab was rebuilt
                .sh_type = std.elf.SHT_PROGBITS,
                .sh_flags = no_flags,
                .sh_addr = not_mapped,
                // FIXME: still needs to have the largest address to be appendended since the sections are sorted
                // => what's a simple approach here to achieve this?
                .sh_offset = 99999999999, // NOTE: filled after strtab was rebuilt
                .sh_size = add.content.len,
                .sh_link = std.elf.SHN_UNDEF,
                .sh_info = std.elf.SHN_UNDEF,
                .sh_addralign = default_alignment,
                .sh_entsize = dynamic,
            },
            .content = .{ .data = add.content },
        });
    }

    if (options.set_section_alignment) |alignment| {
        for (descriptor.sections.items) |*section| {
            if (std.mem.eql(u8, section.name, alignment.section_name)) {
                section.shdr.sh_addralign = alignment.alignment;
                break;
            }
        } else fatal("Section '{s}' to change alignment on does not exist", .{alignment.section_name});
    }

    if (options.set_section_flags) |set_flags| {
        for (descriptor.sections.items) |*section| {
            if (std.mem.eql(u8, section.name, set_flags.section_name)) {
                const f = set_flags.flags;
                const shdr = &section.shdr;
                shdr.sh_flags = std.elf.SHF_WRITE; // default is writable cleared by "readonly"

                // Supporting a subset of GNU and LLVM objcopy for ELF only
                // GNU:
                // alloc: add SHF_ALLOC
                // contents: if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing
                // load: if section is SHT_NOBITS, set SHT_PROGBITS, otherwise do nothing (same as contents)
                // noload: not ELF relevant
                // readonly: clear default SHF_WRITE flag
                // code: add SHF_EXECINSTR
                // data: not ELF relevant
                // rom: ignored
                // exclude: add SHF_EXCLUDE
                // share: not ELF relevant
                // debug: not ELF relevant
                // large: add SHF_X86_64_LARGE. Fatal error if target is not x86_64
                if (f.alloc) shdr.sh_flags |= std.elf.SHF_ALLOC;
                if (f.contents or f.load) {
                    if (shdr.sh_type == std.elf.SHT_NOBITS) shdr.sh_type = std.elf.SHT_PROGBITS;
                }
                if (f.readonly) shdr.sh_flags &= ~@as(@TypeOf(shdr.sh_type), std.elf.SHF_WRITE);
                if (f.code) shdr.sh_flags |= std.elf.SHF_EXECINSTR;
                if (f.exclude) shdr.sh_flags |= std.elf.SHF_EXCLUDE;
                if (f.large) {
                    if (descriptor.elf_header.parsed.machine != std.elf.EM.X86_64)
                        fatal("zig objcopy: 'large' section flag is only supported on x86_64 targets", .{});
                    shdr.sh_flags |= std.elf.SHF_X86_64_LARGE;
                }

                // LLVM:
                // merge: add SHF_MERGE
                // strings: add SHF_STRINGS
                if (f.merge) shdr.sh_flags |= std.elf.SHF_MERGE;
                if (f.strings) shdr.sh_flags |= std.elf.SHF_STRINGS;
                break;
            }
        } else fatal("Section '{s}' to change flags on does not exist", .{set_flags.section_name});
    }
}

const ProcessedElfDescriptor = struct {
    header: ElfHeader,
    ordered_sections: std.ArrayList(Section),
    program_segments: std.ArrayList(ProgramSegment),
};

// Process ELF objcopy descriptor to allow simple writing and testing by ensuring simplifying postconditions:
// * sections are ordered by their ascending file offsets
// * section file offsets and sizes are updated and account:
//   * resized sections
//   * deleted or new sections in between
//   * alignment changes
// * ELF header section and program header table offsets are updated
// * ELF header section name string table index is updated
fn processElfDescriptor(allocator: Allocator, descriptor: ElfDescriptor) !ProcessedElfDescriptor {
    // TODO: copy array lists or modify in place? More efficient but side effects are nasty for testing...
    const desc = descriptor;
    const elf_header = desc.elf_header.parsed;

    // rebuild string table section and update all sh_name offsets
    const section_string_table_index = elf_header.shstrndx;
    {
        var strtab_size: usize = 0;
        for (desc.sections.items) |section| strtab_size += section.name.len + 1; // + 1 for sentinel

        const strtab_content = try allocator.alloc(u8, strtab_size);
        @memset(strtab_content, 0);

        var offset: usize = 0;
        for (desc.sections.items) |*section| {
            defer offset += section.name.len + 1;
            @memcpy(strtab_content[offset .. offset + section.name.len], section.name);
            strtab_content[offset + section.name.len] = 0;
            section.shdr.sh_name = @intCast(offset);
        }
        assert(strtab_content[0] == 0); // expect 0 for null section with an empty name

        const section = &desc.sections.items[section_string_table_index];
        assert(isStringTable(section.shdr));
        section.content = .{ .data = strtab_content };
        section.shdr.sh_size = strtab_content.len; // NOTE: not necessary, will be update after ordering again
    }

    // sort sections by ascending file offsets
    const sorted_sections = try desc.sections.clone();
    const SortCommands = struct {
        fn lessThanFn(context: *@This(), lhs: Section, rhs: Section) bool {
            _ = context;
            return lhs.shdr.sh_offset < rhs.shdr.sh_offset;
        }
    };
    var sort = SortCommands{};
    // FIXME: shift the section name string table index when reordering and update the header
    std.mem.sort(Section, sorted_sections.items, &sort, SortCommands.lessThanFn);

    // recompute section sizes and offsets with correct alignment
    {
        var offset: usize = @sizeOf(std.elf.Ehdr) + desc.program_segments.items.len * @sizeOf(std.elf.Phdr) + desc.sections.items.len * @sizeOf(std.elf.Shdr);
        // start at index 1 to skip null section
        for (sorted_sections.items[1..]) |*section| {
            const default_alignment = 8; // FIXME: 8 byte alignment required?
            const alignment = @max(default_alignment, section.shdr.sh_addralign);
            const size = section.content.fileSize();
            const new_offset = std.mem.alignForward(usize, offset + size, alignment);
            defer offset = new_offset;

            section.shdr.sh_offset = offset;
            section.shdr.sh_size = size;
        }
    }

    // FIXME: always moves headers to the top even if there is no need for it
    // Is this a reasonable limitation for now?
    const new_program_header_offset = @sizeOf(std.elf.Ehdr);
    const new_section_header_offset = new_program_header_offset + desc.program_segments.items.len * @sizeOf(std.elf.Phdr);

    const new_header = ElfHeader{
        .e_ident = desc.elf_header.e_ident,
        .parsed = .{
            .is_64 = elf_header.is_64,
            .endian = elf_header.endian,
            .os_abi = elf_header.os_abi,
            .abi_version = elf_header.abi_version,
            .type = elf_header.type,
            .machine = elf_header.machine,
            .entry = elf_header.entry,
            .phoff = new_program_header_offset,
            .shoff = new_section_header_offset,
            .phentsize = elf_header.phentsize,
            .phnum = @intCast(desc.program_segments.items.len),
            .shentsize = elf_header.shentsize,
            .shnum = @intCast(desc.sections.items.len),
            .shstrndx = @intCast(section_string_table_index),
        },
    };

    return .{
        .header = new_header,
        .ordered_sections = sorted_sections,
        .program_segments = desc.program_segments,
    };
}

fn writeElf(allocator: Allocator, desc: ProcessedElfDescriptor, in_file: anytype, out_file: anytype) !void {
    comptime assert(std.meta.hasMethod(@TypeOf(in_file), "seekableStream"));
    comptime assert(std.meta.hasMethod(@TypeOf(in_file), "reader"));
    comptime assert(std.meta.hasMethod(@TypeOf(out_file), "seekableStream"));
    comptime assert(std.meta.hasMethod(@TypeOf(out_file), "writer"));

    const writer = out_file.writer();
    const out_stream = out_file.seekableStream();

    const header = &desc.header;
    const sections = &desc.ordered_sections;
    const program_segments = &desc.program_segments;
    const endianess = try header.getEndianess();

    // header
    try out_stream.seekTo(0);
    try writer.writeStruct(try header.toEhdr());

    // program segments
    try out_stream.seekTo(header.parsed.phoff);
    for (program_segments.items) |program| try writer.writeStruct(program.toPhdr(endianess));

    // section headers
    try out_stream.seekTo(header.parsed.shoff);
    for (sections.items) |section| try writer.writeStruct(section.toShdr(endianess));

    // section content
    // TODO: offsets are not adjusted yet, so some sections will overwrite parts of other sections / section headers
    for (sections.items) |section| {
        // TODO: fill gaps with 0
        const alignment = @max(1, section.shdr.sh_addralign);
        try out_stream.seekTo(std.mem.alignForward(usize, try out_stream.getPos(), alignment));

        switch (section.content) {
            .data => |data| {
                try out_stream.seekTo(section.shdr.sh_offset);
                try writer.writeAll(data);
            },
            .no_bits => {},
            .input_file_range => |range| {
                const data = section.readContentAlloc(in_file, allocator) catch |err| {
                    std.log.err("failed reading '{s}' section content at 0x{x} of size 0x{x} ({d}): {}", .{
                        section.name,
                        range.offset,
                        range.size,
                        range.size,
                        err,
                    });
                    return err;
                };

                try out_stream.seekTo(section.shdr.sh_offset);
                try writer.writeAll(data);
            },
        }
    }
}

// Stores the parsed header with e_ident from the input file ELF header that is only partially parsed by std.elf.Header.parse.
// TODO: does not support different target endianness than native endianness yet.
// Does not support non-zero e_flags.
const ElfHeader = struct {
    e_ident: [std.elf.EI_NIDENT]u8,
    parsed: std.elf.Header,

    // Create the ELF header in the input file endianess
    fn toEhdr(self: *const @This()) !std.elf.Ehdr {
        const e = std.elf;

        // validate that the parsed fields have not diverged from e_ident
        const endian = try self.getEndianess();
        assert(endian == self.parsed.endian);

        const e_ident_is_64 = switch (self.e_ident[e.EI_CLASS]) {
            e.ELFCLASS64 => true,
            e.ELFCLASS32 => false,
            else => return error.InvalidElfHeader,
        };
        assert(e_ident_is_64 == self.parsed.is_64);

        const e_version = self.e_ident[e.EI_VERSION];
        assert(e_version == e.EV_CURRENT);

        const os_abi: e.OSABI = @enumFromInt(self.e_ident[e.EI_OSABI]);
        assert(os_abi == self.parsed.os_abi);

        const abi_version = self.e_ident[e.EI_ABIVERSION];
        assert(abi_version == self.parsed.abi_version);

        // EI_PAD should be all zero
        assert(std.mem.eql(u8, self.e_ident[9..], &[_]u8{0} ** 7));

        const e_flags = 0; // no EF_... flags supported

        const header = e.Ehdr{
            .e_ident = self.e_ident,
            .e_type = self.parsed.type,
            .e_machine = self.parsed.machine,
            .e_version = e_version,
            .e_entry = self.parsed.entry,
            .e_phoff = self.parsed.phoff,
            .e_shoff = self.parsed.shoff,
            .e_flags = e_flags,
            .e_ehsize = @sizeOf(e.Ehdr),
            .e_phentsize = self.parsed.phentsize,
            .e_phnum = self.parsed.phnum,
            .e_shentsize = self.parsed.shentsize,
            .e_shnum = self.parsed.shnum,
            .e_shstrndx = self.parsed.shstrndx,
        };

        // TODO: swap bytes of all fields including e_ident if native endian does not match
        const native_endian = @import("builtin").target.cpu.arch.endian();
        if (endian != native_endian) {
            // TODO: can't use std.mem.byteSwapAllFields due to e_ident
            return error.InvalidElfEndian;
        }

        return header;
    }

    fn getEndianess(self: *const @This()) !std.builtin.Endian {
        return switch (self.e_ident[std.elf.EI_DATA]) {
            std.elf.ELFDATA2LSB => .little,
            std.elf.ELFDATA2MSB => .big,
            else => return error.InvalidElfEndian,
        };
    }
};

const SectionFlags = packed struct {
    alloc: bool = false,
    contents: bool = false,
    load: bool = false,
    noload: bool = false,
    readonly: bool = false,
    code: bool = false,
    data: bool = false,
    rom: bool = false,
    exclude: bool = false,
    shared: bool = false,
    debug: bool = false,
    large: bool = false,
    merge: bool = false,
    strings: bool = false,
};

fn parseSectionFlags(comma_separated_flags: []const u8) SectionFlags {
    const P = struct {
        fn parse(flags: *SectionFlags, string: []const u8) void {
            if (string.len == 0) return;

            if (std.mem.eql(u8, string, "alloc")) {
                flags.alloc = true;
            } else if (std.mem.eql(u8, string, "contents")) {
                flags.contents = true;
            } else if (std.mem.eql(u8, string, "load")) {
                flags.load = true;
            } else if (std.mem.eql(u8, string, "noload")) {
                flags.noload = true;
            } else if (std.mem.eql(u8, string, "readonly")) {
                flags.readonly = true;
            } else if (std.mem.eql(u8, string, "code")) {
                flags.code = true;
            } else if (std.mem.eql(u8, string, "data")) {
                flags.data = true;
            } else if (std.mem.eql(u8, string, "rom")) {
                flags.rom = true;
            } else if (std.mem.eql(u8, string, "exclude")) {
                flags.exclude = true;
            } else if (std.mem.eql(u8, string, "shared")) {
                flags.shared = true;
            } else if (std.mem.eql(u8, string, "debug")) {
                flags.debug = true;
            } else if (std.mem.eql(u8, string, "large")) {
                flags.large = true;
            } else if (std.mem.eql(u8, string, "merge")) {
                flags.merge = true;
            } else if (std.mem.eql(u8, string, "strings")) {
                flags.strings = true;
            } else {
                std.log.warn("Skipping unrecognized section flag '{s}'", .{string});
            }
        }
    };

    var flags = SectionFlags{};
    var offset: usize = 0;
    for (comma_separated_flags, 0..) |c, i| {
        if (c == ',') {
            defer offset = i + 1;
            const string = comma_separated_flags[offset..i];
            P.parse(&flags, string);
        }
    }
    P.parse(&flags, comma_separated_flags[offset..]);
    return flags;
}

const SplitResult = struct { first: []const u8, second: []const u8 };

fn splitOption(option: []const u8) ?SplitResult {
    const separator = '=';
    if (option.len < 3) return null; // minimum "a=b"
    for (1..option.len - 1) |i| {
        if (option[i] == separator) return .{
            .first = option[0..i],
            .second = option[i + 1 ..],
        };
    }
    return null;
}

const t = std.testing;

test "Parse section flags" {
    const F = SectionFlags;
    try t.expectEqual(F{}, parseSectionFlags(""));
    try t.expectEqual(F{}, parseSectionFlags(","));
    try t.expectEqual(F{}, parseSectionFlags("abc"));
    try t.expectEqual(F{ .alloc = true }, parseSectionFlags("alloc"));
    try t.expectEqual(F{ .data = true }, parseSectionFlags("data,"));
    try t.expectEqual(F{ .alloc = true, .code = true }, parseSectionFlags("alloc,code"));
    try t.expectEqual(F{ .alloc = true, .code = true }, parseSectionFlags("alloc,code,not_supported"));
}

test "Split option" {
    {
        const split = splitOption(".abc=123");
        try t.expect(split != null);
        try t.expectEqualStrings(".abc", split.?.first);
        try t.expectEqualStrings("123", split.?.second);
    }

    try t.expectEqual(null, splitOption(""));
    try t.expectEqual(null, splitOption("=abc"));
    try t.expectEqual(null, splitOption("abc="));
    try t.expectEqual(null, splitOption("abc"));
}

test parseCommandLine {
    {
        const options = parseCommandLine(&[_][]const u8{ "a", "b" });
        try t.expectEqualSlices(u8, "a", options.input);
        try t.expectEqualSlices(u8, "b", options.output);
    }

    {
        const options = parseCommandLine(&[_][]const u8{ "./123", "/home/pwr/abc" });
        try t.expectEqualSlices(u8, "./123", options.input);
        try t.expectEqualSlices(u8, "/home/pwr/abc", options.output);
    }

    {
        const options = parseCommandLine(&[_][]const u8{ "a", "b", "-h" });
        try t.expectEqualSlices(u8, "a", options.input);
        try t.expectEqualSlices(u8, "b", options.output);
    }

    {
        const options = parseCommandLine(&[_][]const u8{ "a", "b", "--add-section", ".new=c" });
        try t.expectEqualSlices(u8, "a", options.input);
        try t.expectEqualSlices(u8, "b", options.output);
        try t.expect(options.add_section != null);
        try t.expectEqualSlices(u8, ".new", options.add_section.?.section_name);
        try t.expectEqualSlices(u8, "c", options.add_section.?.file_path);
    }
}

// Minimal ELF file to test objcopy options on.
fn createTestElfFile() ![256]u8 {
    const section_header_table_offset = 64;
    const section_not_mapped = 0;
    const section_dynamic_size = 0;

    const e_ident = std.elf.MAGIC ++ [_]u8{std.elf.ELFCLASS64} ++ [_]u8{std.elf.ELFDATA2LSB} ++ [_]u8{std.elf.EV_CURRENT} ++ [_]u8{@intFromEnum(std.elf.OSABI.GNU)} ++ [_]u8{0} ++ [_]u8{0} ** 7;

    const elf_header = ElfHeader{
        .e_ident = e_ident.*,
        .parsed = .{
            .is_64 = true,
            .endian = .little,
            .os_abi = std.elf.OSABI.GNU,
            .abi_version = 0,
            .type = std.elf.ET.EXEC,
            .machine = .X86_64,
            .entry = 0,
            .phoff = @sizeOf(std.elf.Ehdr),
            .shoff = section_header_table_offset,
            .phentsize = @sizeOf(std.elf.Elf64_Phdr),
            .phnum = 0,
            .shentsize = @sizeOf(std.elf.Elf64_Shdr),
            .shnum = 2,
            .shstrndx = 1,
        },
    };

    const test_buffer_size = 256;
    var in_buffer = [_]u8{0} ** test_buffer_size;
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };
    const in_buffer_writer = in_buffer_stream.writer();

    // write input ELF
    {
        try in_buffer_writer.writeStruct(try elf_header.toEhdr());

        // section headers
        try t.expectEqual(section_header_table_offset, try in_buffer_stream.getPos());

        // null section
        const null_section_header = [_]u8{0} ** @sizeOf(std.elf.Shdr);
        try in_buffer_writer.writeAll(&null_section_header);

        // shstrtab
        const string_table_offset = 192;
        const string_table_size = 11;
        try in_buffer_writer.writeStruct(std.elf.Shdr{
            .sh_name = 1,
            .sh_type = std.elf.SHT_STRTAB,
            .sh_flags = std.elf.SHF_STRINGS,
            .sh_addr = section_not_mapped,
            .sh_offset = string_table_offset,
            .sh_size = string_table_size,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = section_dynamic_size,
        });

        // shstrtab content
        const string_table_section_offset = try in_buffer_stream.getPos();
        try in_buffer_writer.writeByte(0); // 0 for null section without a name
        try in_buffer_writer.writeAll(".shstrtab");
        try in_buffer_writer.writeByte(0);
        const string_table_section_end = try in_buffer_stream.getPos();

        try t.expectEqual(string_table_offset, string_table_section_offset);
        try t.expectEqual(string_table_size, string_table_section_end - string_table_section_offset);
    }

    return in_buffer;
}

// End to end test objcopy without any options on a minimal ELF file.
test "objcopy ELF no operation integration test" {
    const allocator = t.allocator;

    var in_buffer = try createTestElfFile();
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };

    var out_buffer align(8) = [_]u8{0} ** in_buffer.len;
    var out_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &out_buffer, .pos = 0 };

    var descriptor = try parseElfDescriptor(allocator, &in_buffer_stream);
    defer descriptor.deinit();
    try applyOptions(&descriptor, .{});
    const processed_descriptor = try processElfDescriptor(allocator, descriptor);
    try writeElf(allocator, processed_descriptor, &in_buffer_stream, &out_buffer_stream);

    try t.expectEqualSlices(u8, &in_buffer, &out_buffer);
}

test "objcopy --add-section --set-section-alignment" {
    const allocator = t.allocator;

    var in_buffer = try createTestElfFile();
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };

    var descriptor = try parseElfDescriptor(allocator, &in_buffer_stream);
    defer descriptor.deinit();

    try t.expectEqual(2, descriptor.sections.items.len);
    try applyOptions(&descriptor, .{
        .add_section = .{ .section_name = ".new", .content = "abc123" },
        .set_section_alignment = .{ .section_name = ".new", .alignment = 32 },
    });

    try t.expectEqual(3, descriptor.sections.items.len);
    try t.expectEqualStrings(".new", descriptor.sections.items[2].name);
    try t.expectEqualStrings("abc123", descriptor.sections.items[2].content.data);
    try t.expectEqual(32, descriptor.sections.items[2].shdr.sh_addralign);
}

// Test objcopy with section that are not ordered ascending wrt. their file offsets.
test "objcopy ELF unordered sections" {
    const allocator = t.allocator;

    const program_header_table_offset = @sizeOf(std.elf.Ehdr);
    const program_header_count = 0;
    const section_header_table_offset = 104;
    const section_header_count = 4; // null section + strtab + 2 test sections
    const section_name_string_table_index = 1;
    const section_alignment = 8;
    const section_not_mapped = 0;
    const section_dynamic_size = 0;

    const e_ident = std.elf.MAGIC ++ [_]u8{std.elf.ELFCLASS64} ++ [_]u8{std.elf.ELFDATA2LSB} ++ [_]u8{std.elf.EV_CURRENT} ++ [_]u8{@intFromEnum(std.elf.OSABI.GNU)} ++ [_]u8{0} ++ [_]u8{0} ** 7;

    const elf_header = ElfHeader{
        .e_ident = e_ident.*,
        .parsed = .{
            .is_64 = true,
            .endian = .little,
            .os_abi = std.elf.OSABI.GNU,
            .abi_version = 0,
            .type = std.elf.ET.EXEC,
            .machine = .X86_64,
            .entry = 0,
            .phoff = program_header_table_offset,
            .shoff = section_header_table_offset,
            .phentsize = @sizeOf(std.elf.Elf64_Phdr),
            .phnum = program_header_count,
            .shentsize = @sizeOf(std.elf.Elf64_Shdr),
            .shnum = section_header_count,
            .shstrndx = section_name_string_table_index,
        },
    };

    const test_section_size = 8;
    const test_buffer_size = 512;
    var in_buffer = [_]u8{0} ** test_buffer_size;
    var in_buffer_stream = std.io.FixedBufferStream([]u8){ .buffer = &in_buffer, .pos = 0 };

    // header
    const in_buffer_writer = in_buffer_stream.writer();
    try in_buffer_writer.writeStruct(try elf_header.toEhdr());

    // section name string table before section headers for simple offsets
    const string_table_section_offset = try in_buffer_stream.getPos();
    try in_buffer_writer.writeByte(0); // 0 for null section without a name

    const shstrtab_name = try in_buffer_stream.getPos();
    try in_buffer_writer.writeAll(".shstrtab");
    try in_buffer_writer.writeByte(0);

    const high_name = try in_buffer_stream.getPos();
    try in_buffer_writer.writeAll(".high");
    try in_buffer_writer.writeByte(0);

    const low_name = try in_buffer_stream.getPos();
    try in_buffer_writer.writeAll(".low");
    try in_buffer_writer.writeByte(0);
    const string_table_section_end = try in_buffer_stream.getPos();

    try in_buffer_stream.seekTo(std.mem.alignForward(usize, try in_buffer_stream.getPos(), section_alignment));
    const test_low_offset = try in_buffer_stream.getPos();
    try in_buffer_writer.writeByteNTimes(0, test_section_size);
    const test_high_offset = try in_buffer_stream.getPos();
    try in_buffer_writer.writeByteNTimes(0, test_section_size);

    // section headers
    try in_buffer_stream.seekTo(std.mem.alignForward(usize, try in_buffer_stream.getPos(), section_alignment));
    try std.testing.expectEqual(section_header_table_offset, try in_buffer_stream.getPos());

    const null_section_header = [_]u8{0} ** @sizeOf(std.elf.Shdr);
    try in_buffer_writer.writeAll(&null_section_header);

    // string section
    try in_buffer_writer.writeStruct(std.elf.Shdr{
        .sh_name = @intCast(shstrtab_name - string_table_section_offset),
        .sh_type = std.elf.SHT_STRTAB,
        .sh_flags = std.elf.SHF_STRINGS,
        .sh_addr = section_not_mapped,
        .sh_offset = string_table_section_offset,
        .sh_size = string_table_section_end - string_table_section_offset,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 1,
        .sh_entsize = section_dynamic_size,
    });

    // test section with high offset before low offset
    try in_buffer_writer.writeStruct(std.elf.Shdr{
        .sh_name = @intCast(high_name - string_table_section_offset),
        .sh_type = std.elf.SHT_PROGBITS,
        .sh_flags = std.elf.SHF_ALLOC,
        .sh_addr = section_not_mapped,
        .sh_offset = test_high_offset,
        .sh_size = test_section_size,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = section_alignment,
        .sh_entsize = section_dynamic_size,
    });

    try in_buffer_writer.writeStruct(std.elf.Shdr{
        .sh_name = @intCast(low_name - string_table_section_offset),
        .sh_type = std.elf.SHT_PROGBITS,
        .sh_flags = std.elf.SHF_ALLOC,
        .sh_addr = section_not_mapped,
        .sh_offset = test_low_offset,
        .sh_size = test_section_size,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = section_alignment,
        .sh_entsize = section_dynamic_size,
    });

    const out_descriptor = try parseElfDescriptor(allocator, &in_buffer_stream);
    defer out_descriptor.deinit();

    try t.expectEqual(program_header_count, out_descriptor.program_segments.items.len);
    try t.expectEqual(section_header_count, out_descriptor.sections.items.len);

    // null section
    try t.expectEqualStrings("", out_descriptor.sections.items[0].name);
    try t.expectEqual(std.mem.zeroes(std.elf.Shdr), out_descriptor.sections.items[0].shdr);

    // shstrtab
    try t.expectEqualStrings(".shstrtab", out_descriptor.sections.items[1].name);

    // high
    try t.expectEqualStrings(".high", out_descriptor.sections.items[2].name);
    try t.expectEqual(test_high_offset, out_descriptor.sections.items[2].content.input_file_range.offset);
    try t.expectEqual(test_section_size, out_descriptor.sections.items[2].content.input_file_range.size);

    // low
    try t.expectEqualStrings(".low", out_descriptor.sections.items[3].name);
    try t.expectEqual(test_low_offset, out_descriptor.sections.items[3].content.input_file_range.offset);
    try t.expectEqual(test_section_size, out_descriptor.sections.items[3].content.input_file_range.size);

    const processed = try processElfDescriptor(allocator, out_descriptor);
    // TODO: clarify what needs to be deleted and when. Use tagged union to distinguish copied sections?
    defer processed.ordered_sections.deinit(); // FIXME: temporary hack
    defer allocator.free(processed.ordered_sections.items[1].content.data); // FIXME: temporary hack

    const ordered = processed.ordered_sections;
    try t.expectEqualStrings("", ordered.items[0].name);
    try t.expectEqualStrings(".shstrtab", ordered.items[1].name);

    // test that the sections are reordered by their file offset
    try t.expectEqualStrings(".low", ordered.items[2].name);
    try t.expectEqualStrings(".high", ordered.items[3].name);

    try t.expectEqual(test_low_offset, ordered.items[2].content.input_file_range.offset);
    try t.expectEqual(test_high_offset, ordered.items[3].content.input_file_range.offset);
}

// Test adding a section which appends a section header entry and bytes but also increases the strtab sizes that
// pushes down all following sections that need to be realligned correctly.
test "objcopy ELF add section" {
    if (true) return; // FIXME: reenable

    const allocator = t.allocator;

    const section_alignment = 8;
    const section_not_mapped = 0;
    const section_dynamic_size = 0;
    const does_not_matter = 0;

    const e_ident = std.elf.MAGIC ++ [_]u8{std.elf.ELFCLASS64} ++ [_]u8{std.elf.ELFDATA2LSB} ++ [_]u8{std.elf.EV_CURRENT} ++ [_]u8{@intFromEnum(std.elf.OSABI.GNU)} ++ [_]u8{0} ++ [_]u8{0} ** 7;

    const string_table_content_raw = [1]u8{0} ++ ".shstrtab" ++ [1]u8{0} ++ ".test" ++ [1]u8{0};
    const string_table_content = try allocator.alloc(u8, string_table_content_raw.len);
    @memcpy(string_table_content, string_table_content_raw);

    var descriptor = ElfDescriptor{
        .elf_header = .{
            .e_ident = e_ident.*,
            .parsed = .{
                .is_64 = true,
                .endian = .little,
                .os_abi = std.elf.OSABI.GNU,
                .abi_version = 0,
                .type = std.elf.ET.EXEC,
                .machine = .X86_64,
                .entry = does_not_matter,
                .phoff = 1024, // somewhere after sections content
                .shoff = 2048,
                .phentsize = @sizeOf(std.elf.Elf64_Phdr),
                .phnum = 0,
                .shentsize = @sizeOf(std.elf.Elf64_Shdr),
                .shnum = 3, // null section + shstrtab + test section,
                .shstrndx = 1,
            },
        },
        .sections = std.ArrayList(Section).init(allocator),
        .program_segments = std.ArrayList(ProgramSegment).init(allocator),
        .string_table_content = string_table_content,
        .string_table_content_allocator = allocator,
    };
    defer descriptor.deinit();

    // null section
    try descriptor.sections.append(.{ .name = "", .content = .{ .no_bits = .{ .offset = 0, .size = 0 } }, .shdr = std.mem.zeroes(std.elf.Shdr) });

    try descriptor.sections.append(.{
        .name = ".shstrtab",
        .content = .{ .data = string_table_content },
        .shdr = .{
            .sh_name = does_not_matter,
            .sh_type = std.elf.SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = section_not_mapped,
            .sh_offset = @sizeOf(std.elf.Ehdr),
            .sh_size = string_table_content.len,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = section_alignment,
            .sh_entsize = section_dynamic_size,
        },
    });

    // offset with the new section name not added yet
    const test_offset = @sizeOf(std.elf.Ehdr) + std.mem.alignForward(usize, string_table_content.len, section_alignment);

    try descriptor.sections.append(.{
        .name = ".test",
        .content = .{ .data = "test123" },
        .shdr = .{
            .sh_name = does_not_matter,
            .sh_type = std.elf.SHT_PROGBITS,
            .sh_flags = std.elf.SHF_ALLOC,
            .sh_addr = section_not_mapped,
            .sh_offset = test_offset,
            .sh_size = 8,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = section_alignment,
            .sh_entsize = section_dynamic_size,
        },
    });

    try descriptor.sections.append(.{
        .name = ".new",
        .content = .{ .data = "abc" },
        .shdr = .{
            .sh_name = does_not_matter,
            .sh_type = std.elf.SHT_PROGBITS,
            .sh_flags = std.elf.SHF_ALLOC,
            .sh_addr = section_not_mapped,
            .sh_offset = test_offset + 30,
            .sh_size = 8,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = section_alignment,
            .sh_entsize = section_dynamic_size,
        },
    });

    const processed = try processElfDescriptor(allocator, descriptor);
    const ordered = processed.ordered_sections;
    try t.expectEqual(4, ordered.items.len);

    try t.expectEqualStrings("", ordered.items[0].name);
    try t.expectEqualStrings(".shstrtab", ordered.items[1].name);
    try t.expectEqualStrings(".test", ordered.items[2].name);
    try t.expectEqualStrings(".new", ordered.items[3].name);

    // shstrtab is larger due to new section name
    const new_section_name_length = 5;
    const expected_new_shstrtab_size = string_table_content.len + new_section_name_length;
    try t.expectEqual(expected_new_shstrtab_size, ordered.items[1].shdr.sh_size);

    // existing section is pushed down by the new section name
    try t.expectEqual(test_offset + section_alignment, ordered.items[2].shdr.sh_offset);

    // new section is added directly after the last section
    try t.expectEqual(ordered.items[2].shdr.sh_offset + section_alignment, ordered.items[3].shdr.sh_offset);
}
