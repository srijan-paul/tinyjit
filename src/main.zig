const std = @import("std");

const Opcode = enum(u8) {
    load_const,
    add,
    print,
    exit,
};

const Interpreter = struct {
    stack: [32_000]i64 = undefined,
    stack_pos: u64 = 0,

    instructions: []const u8,
    pc: usize = 0,

    constants: []const i64,

    inline fn loadConst(self: *Interpreter) i64 {
        const index = self.instructions[self.pc];
        const constant = self.constants[index];

        self.pc += 1;
        return constant;
    }

    inline fn pop(self: *Interpreter) i64 {
        self.stack_pos -= 1;
        return self.stack[self.stack_pos];
    }

    inline fn push(self: *Interpreter, value: i64) void {
        self.stack[self.stack_pos] = value;
        self.stack_pos += 1;
    }

    pub fn run(self: *Interpreter) !void {
        while (self.pc < self.instructions.len) {
            const instr: Opcode = @enumFromInt(self.instructions[self.pc]);
            self.pc += 1;

            switch (instr) {
                .load_const => self.push(self.loadConst()),
                .add => {
                    const a = self.pop();
                    const b = self.pop();
                    self.push(a + b);
                },
                .print => std.debug.print("{d}\n", .{self.pop()}),
                .exit => {
                    const exit_code: u8 = @intCast(self.pop());
                    std.process.exit(exit_code);
                },
            }
        }
    }
};

pub inline fn Op(o: Opcode) u8 {
    return @intFromEnum(o);
}

pub fn main() !void {
    var interpreter = Interpreter{
        .instructions = &[_]u8{
            Op(.load_const), 0, // load 42
            Op(.load_const), 1, // load 24
            Op(.add), // 42 + 24 = 66
            Op(.print), // print(66)
            Op(.load_const), 2, // load 0
            Op(.exit), // exit()
        },
        .constants = &[_]i64{ 42, 24, 0 },
    };

    try interpreter.run();
}
