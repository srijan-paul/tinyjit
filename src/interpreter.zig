const std = @import("std");
const jit = @import("jit.zig");

pub const Opcode = enum(u8) {
    push,
    add,
    eq,
    jump_nz,
    jump,
    load_var,
    store_var,
};

/// Shorthand to convert an Opcode to a u8
pub inline fn Op(op: Opcode) u8 {
    return @intFromEnum(op);
}

pub const CodeBlock = struct {
    /// A list of `Opcode`s cast to u8
    instructions: []const u8,
    /// Constants used within this block
    constants: []const i64,
};

pub const Interpreter = struct {
    stack: [32_000]i64 = undefined,
    stack_pos: u64 = 0,

    allocator: std.mem.Allocator,

    blocks: []const CodeBlock,
    jit_blocks: []?jit.CompiledFunction,

    current_block: *const CodeBlock = undefined,
    pc: usize = 0,

    jit_compiler: jit.JITCompiler,
    is_jit_enabled: bool = false,

    pub fn init(allocator: std.mem.Allocator, blocks: []const CodeBlock) !*Interpreter {
        const self = try allocator.create(Interpreter);
        self.* = Interpreter{
            .blocks = blocks,
            .current_block = &blocks[0],
            .jit_compiler = jit.JITCompiler.init(allocator, self),
            .jit_blocks = try allocator.alloc(?jit.CompiledFunction, blocks.len),
            .allocator = allocator,
        };

        for (self.jit_blocks) |*jit_block| {
            jit_block.* = null;
        }

        return self;
    }

    pub fn deinit(self: *const Interpreter) void {
        self.jit_compiler.deinit();

        // unmap all the JIT functions
        for (self.jit_blocks) |maybe_jit_block| {
            if (maybe_jit_block) |*jit_block| {
                jit_block.deinit();
            }
        }

        self.allocator.free(self.jit_blocks);
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
                .push => self.push(self.loadConst()),
                .add => {
                    const a = self.pop();
                    const b = self.pop();
                    self.push(a + b);
                },
                .eq => {
                    const a = self.pop();
                    const b = self.pop();
                    self.push(if (a == b) 1 else 0);
                },

                .jump => try self.jump(),
                .jump_nz => {
                    if (self.pop() != 0) {
                        try self.jump();
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

    /// Call a JIT compiled function
    inline fn callJit(self: *Interpreter, compiled: *const jit.CompiledFunction) void {
        var next_block_idx: usize = 0; // inout parameter for JITted function
        compiled.func(
            (&self.stack).ptr,
            self.current_block.instructions.ptr,
            &self.stack_pos,
            &self.pc,
            &next_block_idx,
            self.current_block.constants.ptr,
        );

        self.current_block = &self.blocks[next_block_idx];
        // self.pc = 0;
    }

    fn doJit(self: *Interpreter, block_index: usize) !void {
        const block = &self.blocks[block_index];
        const compiled = try self.jit_compiler.compileBlock(block);

        self.jit_blocks[block_index] = compiled;
        self.callJit(&compiled);
    }

    fn jump(self: *Interpreter) !void {
        // block index is the next "instruction".
        const block_idx = self.nextOp();
        self.pc = 0; // start from first instr in the next block
        const dst_block = &self.blocks[block_idx];

        if (!self.is_jit_enabled) {
            self.current_block = dst_block;
            return;
        }

        // check if the block has been JIT compiled before.
        if (self.jit_blocks[block_idx]) |*compiled| {
            self.callJit(compiled);
            return;
        }

        if (self.current_block == dst_block) {
            // self-referencing block. potentially a loop.
            // JIT compile this.
            try self.doJit(block_idx);
            return;
        }

        // Not a self-referencing block, so do regular execution.
        self.current_block = dst_block;
    }
};
