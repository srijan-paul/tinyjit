const std = @import("std");
const builtin = @import("builtin");
const interp = @import("interpreter.zig");

const CodeBlock = interp.CodeBlock;
const Interpreter = interp.Interpreter;
const Op = interp.Op;

fn runProgram(allocator: std.mem.Allocator, program: []const CodeBlock, jit: bool) !void {
    var interpreter = try Interpreter.init(allocator, program);
    interpreter.is_jit_enabled = jit;

    defer {
        interpreter.deinit();
        allocator.destroy(interpreter);
    }

    try interpreter.run();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // 0 is x, 1 is i
    const b0 = CodeBlock{
        .instructions = &[_]u8{
            Op(.push), 0, // x = 0
            Op(.push), 0, // i = 0
            Op(.jump), 1, // jump to while loop (block 1
        },

        .constants = &[_]i64{0},
    };

    const b1 = CodeBlock{
        .instructions = &[_]u8{
            // while i < 1_000_000
            Op(.load_var), 1, // load i
            Op(.push), 0, // load 1_000_000
            Op(.eq),
            Op(.jump_nz), 2, // jump to exit if i == 1_000_000

            // x = x + 1
            Op(.load_var), 0, // load x
            Op(.load_var), 1, // load i
            Op(.add),
            Op(.store_var), 0, // x = x + i

            // i += 1
            Op(.load_var), 1, // load i
            Op(.push), 1, // load 1
            Op(.add),
            Op(.store_var), 1, // i = i + 1
            Op(.jump), 1, // jump to start
        },
        .constants = &[_]i64{ 5_000_000, 1 },
    };

    const b2 = CodeBlock{
        .instructions = &[_]u8{
            Op(.load_var), 0, // load x
        },
        .constants = &[_]i64{0},
    };

    const program = [_]CodeBlock{ b0, b1, b2 };

    var is_jit_enabled = false;
    if (std.os.argv.len > 0) {
        const arg = std.os.argv[std.os.argv.len - 1];
        var len: usize = 0;
        while (arg[len] != 0) len += 1;

        const jit_flag = "--jit";
        is_jit_enabled = std.mem.eql(u8, arg[0..len], jit_flag);
    }

    const n_runs = 100;
    const before = std.time.milliTimestamp();
    for (0..n_runs) |_| {
        try runProgram(allocator, &program, is_jit_enabled);
    }
    const after = std.time.milliTimestamp();

    const dt: f64 = @floatFromInt(after - before);
    const avg_time = dt / @as(f64, @floatFromInt(n_runs));

    const msg = try std.fmt.allocPrintZ(
        allocator,
        "Time per run (JIT = {s}): {d} ms\n",
        .{ if (is_jit_enabled) "ON" else "OFF", avg_time },
    );
    defer allocator.free(msg);

    const stdout = std.io.getStdOut();
    defer stdout.close();

    _ = try stdout.write(msg);
}
