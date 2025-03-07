// This is an experiment in exporting the analyzed intermediate representation (AIR)
// in a minimal lossless form to be used in external static analysis tools.
const std = @import("std");

const Air = @import("Air.zig");
const Compilation = @import("Compilation.zig");
const Liveness = @import("Liveness.zig");
const Zcu = @import("Zcu.zig");

/// Export AIR main body.
pub fn exportAir(pt: Zcu.PerThread, air: Air, liveness: ?Liveness) void {
    const body = air.getMainBody();
    for (body) |inst| exportAirInst(inst, pt, air, liveness);
}

pub fn exportAirInst(inst: Air.Inst.Index, pt: Zcu.PerThread, air: Air, liveness: ?Liveness) void {
    _ = inst;
    _ = pt;
    _ = liveness;

    const tags = air.instructions.items(.tag);
    const data = air.instructions.items(.data);

    for (tags, data) |tag, variant| {
        std.log.info("{any}: {any}", .{ tag, variant });
    }
}

// Tests from here on
const t = std.testing;

const TestCompilationUnit = struct {
    zcu: *Zcu,
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const zcu = try t.allocator.create(Zcu);
        errdefer t.allocator.free(zcu);

        const comp = try t.allocator.create(Compilation);
        errdefer t.allocator.free(comp);

        comp = Compilation{
            .gpa = allocator,
            .zcu = zcu,
            .arena = arena.allocator(),
        };

        zcu = Zcu{
            .gpa = t.allocator,
            .comp = comp,
        };

        return .{ .zcu = zcu, .allocator = allocator, .arena = arena };
    }

    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
        self.allocator.free(self.zcu.comp);
        self.allocator.free(self.zcu);
    }
};

test exportAir {
    const test_unit = try TestCompilationUnit.init(t.allocator);
    defer test_unit.deinit();

    const pt = Zcu.PerThread{ .tid = 0, .zcu = test_unit.zcu };
    const instructions = std.MultiArrayList(Air.Inst){};

    const air = Air{
        .instructions = instructions.slice(),
        .extra = &.{},
    };

    exportAir(pt, air, null);
}
