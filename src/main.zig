const std = @import("std");
const builtin = @import("builtin");
const mman = @cImport(@cInclude("sys/mman.h"));
const pthread = @cImport(@cInclude("pthread.h"));

const Opcode = enum(u8) {
    push,
    add,
    print,
    exit,
    eq,
    jumpif_1,
    jump,
    load_var,
    store_var,
};

const CodeBlock = struct {
    instructions: []const u8,
    constants: []const i64,
};

const Armv8a = struct {
    const Ret: u32 = 0xd65f03c0;
    const Mov42X0: u32 = 0xd2800540;
};

const IntFn = *fn () callconv(.C) u32;

const JITCompiler = struct {
    allocator: std.mem.Allocator,

    interpreter: *const Interpreter,
    codeBuf: std.ArrayList(u32),
    current_block: *const CodeBlock = undefined,

    pub fn init(allocator: std.mem.Allocator, interpreter: *Interpreter) JITCompiler {
        return .{
            .allocator = allocator,
            .interpreter = interpreter,
            .codeBuf = std.ArrayList(u32).init(allocator),
        };
    }

    pub fn deinit(self: *JITCompiler) void {
        self.codeBuf.deinit();
    }

    fn allocJitBuf(size: usize) [*]u32 {
        const buf: *anyopaque = mman.mmap(
            null,
            size,
            mman.PROT_WRITE | mman.PROT_EXEC,
            mman.MAP_PRIVATE | mman.MAP_ANONYMOUS | mman.MAP_JIT,
            -1,
            0,
        ) orelse unreachable; // TODO: return error

        if (buf == mman.MAP_FAILED) {
            std.debug.panic("mmap failed\n", .{}); // return error
        }

        return @ptrCast(@alignCast(buf));
    }

    fn deallocJitBuf(buf: *i32, size: usize) void {
        if (mman.munmap(buf, size) != 0) {
            std.debug.panic("munmap failed\n", .{});
        }
    }

    pub fn compileBlock(self: *JITCompiler, block: *const CodeBlock) void {
        self.current_block = block;

        var jitbuf = allocJitBuf(2);
        defer deallocJitBuf(jitbuf, 2);

        pthread.pthread_jit_write_protect_np(0);
        jitbuf[0] = Armv8a.Mov42X0;
        jitbuf[1] = Armv8a.Ret;
        pthread.pthread_jit_write_protect_np(1);

        const func: IntFn = @ptrCast(jitbuf);
        const ec = func();

        std.process.exit(@truncate(ec));

        // for (block.instructions) |instr| {
        //     const op: Opcode = @enumFromInt(instr);
        //     switch (op) {
        //         .push => self.compilePush(),
        //         else => std.debug.panic("Not implemented\n", .{}),
        //     }
        // }
    }

    // X0 = pointer to the stack (*i64)
    // X1 = pointer to the stack_pos (*u64)
    // X2 = pointer to the instructions (*u8)
    // X3 = pointer to the constants (*i64)
    // X4 = pointer to the pc (*usize)
    fn compileLoadConst(self: *JITCompiler) void {
        _ = self;
    }

    fn compilePush(self: *JITCompiler) void {
        _ = self;
    }
};

const Interpreter = struct {
    stack: [32_000]i64 = undefined,
    stack_pos: u64 = 0,

    blocks: []const CodeBlock,
    current_block: *const CodeBlock = undefined,

    jit_compiler: JITCompiler,

    pc: usize = 0,

    pub fn init(allocator: std.mem.Allocator, blocks: []const CodeBlock) !*Interpreter {
        const self = try allocator.create(Interpreter);
        self.* = Interpreter{
            .blocks = blocks,
            .current_block = &blocks[0],
            .jit_compiler = JITCompiler.init(allocator, self),
        };

        return self;
    }

    fn deinit(self: *Interpreter) void {
        self.jit_compiler.deinit();
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
        self.jit_compiler.compileBlock(&self.blocks[1]);

        while (self.pc < self.current_block.instructions.len) {
            const instr: Opcode = @enumFromInt(self.nextOp());

            switch (instr) {
                .push => self.push(self.loadConst()),
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

                .load_var => {
                    const index = self.nextOp();
                    self.push(self.stack[index]);
                },

                .store_var => {
                    // [value, index]
                    const index = self.nextOp();
                    self.stack[index] = self.pop();
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
            Op(.jumpif_1), 2, // jump to exit if i == 1_000_000

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
        .constants = &[_]i64{ 1_00_0001, 1 },
    };

    const b2 = CodeBlock{
        .instructions = &[_]u8{
            Op(.load_var), 0, // load x
            Op(.print),
            Op(.push), 0, // load 0
            Op(.exit),
        },
        .constants = &[_]i64{0},
    };

    const program = [_]CodeBlock{ b0, b1, b2 };

    var interpreter = try Interpreter.init(allocator, &program);
    defer {
        interpreter.deinit();
        allocator.destroy(interpreter);
    }

    try interpreter.run();
}
