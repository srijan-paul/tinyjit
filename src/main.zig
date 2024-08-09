const std = @import("std");
const builtin = @import("builtin");
const interp = @import("interpreter.zig");

const CodeBlock = interp.CodeBlock;
const Interpreter = interp.Interpreter;
const Op = interp.Op;

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
        .constants = &[_]i64{ 5, 1 },
    };

    const b2 = CodeBlock{
        .instructions = &[_]u8{
            Op(.load_var), 0, // load x
            Op(.print),
        },
        .constants = &[_]i64{0},
    };

    const program = [_]CodeBlock{ b0, b1, b2 };

    var interpreter = try Interpreter.init(allocator, &program);
    interpreter.is_jit_enabled = true;
    defer {
        interpreter.deinit();
        allocator.destroy(interpreter);
    }

    try interpreter.run();
}
