const std = @import("std");

const Opcode = enum(u8) {
    load_const,
    add,
    print,
    exit,
    eq, // pushes 1 if stack[-1] == stack[-2], 0 otherwise
    jumpif_1,
    jump,
};

const CodeBlock = struct {
    instructions: []const u8,
    constants: []const i64,
};

const Interpreter = struct {
    stack: [32_000]i64 = undefined,
    stack_pos: u64 = 0,

    blocks: []const CodeBlock,
    current_block: *const CodeBlock = undefined,

    pc: usize = 0,

    pub fn init(blocks: []const CodeBlock) Interpreter {
        return .{
            .blocks = blocks,
            .current_block = &blocks[0],
        };
    }

    inline fn loadConst(self: *Interpreter) i64 {
        const index = self.current_block.instructions[self.pc];
        const constant = self.current_block.constants[index];

        self.pc += 1;
        return constant;
    }

    inline fn top(self: *Interpreter) i64 {
        return self.stack[self.stack_pos - 1];
    }

    inline fn pop(self: *Interpreter) i64 {
        self.stack_pos -= 1;
        return self.stack[self.stack_pos];
    }

    inline fn push(self: *Interpreter, value: i64) void {
        self.stack[self.stack_pos] = value;
        self.stack_pos += 1;
    }

    inline fn nextOp(self: *Interpreter) u8 {
        const op = self.current_block.instructions[self.pc];
        self.pc += 1;
        return op;
    }

    pub fn run(self: *Interpreter) !void {
        while (self.pc < self.current_block.instructions.len) {
            const instr: Opcode = @enumFromInt(self.nextOp());

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
                .eq => {
                    const a = self.pop();
                    const b = self.pop();
                    self.push(if (a == b) 1 else 0);
                },

                .jump => self.jump(),
                .jumpif_1 => {
                    if (self.pop() == 1) {
                        self.jump();
                    } else {
                        self.pc += 1;
                    }
                },
            }
        }
    }

    fn jump(self: *Interpreter) void {
        const block_idx = self.nextOp();

        self.current_block = &self.blocks[block_idx];
        self.pc = 0;
    }
};

pub inline fn Op(o: Opcode) u8 {
    return @intFromEnum(o);
}

pub fn main() !void {
    const b0 = CodeBlock{
        .instructions = &[_]u8{
            Op(.load_const), 0, // load 5
            Op(.load_const), 1, // load 5
            Op(.add), // 11
            Op(.load_const), 2, // load 10
            Op(.eq),
            Op(.jumpif_1), 1, // jump to b1 if eq
            Op(.load_const), 3, // load 1
            Op(.exit),
        },
        .constants = &[_]i64{ 5, 5, 10, 1 },
    };

    const b1 = CodeBlock{
        .instructions = &[_]u8{
            Op(.load_const), 0, // load 0
            Op(.exit),
        },
        .constants = &[_]i64{0},
    };

    const program = [_]CodeBlock{ b0, b1 };

    var interpreter = Interpreter.init(&program);
    try interpreter.run();
}
