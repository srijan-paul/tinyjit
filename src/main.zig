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
    pub const ret: u32 = 0xd65f03c0;

    // GPRs in AArch64
    const Reg = enum(u32) { x0 = 0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12 };

    // TOOD: accept registers and then cast them to u32s.

    pub inline fn ldrReg(dst_reg: Reg, src_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        const src = @intFromEnum(src_reg);
        return (0x3E5000 << 10) | (src << 5) | dst;
    }

    pub inline fn ldrRegScaled(dst_reg: Reg, base_reg: Reg, offset_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        const base = @intFromEnum(base_reg);
        const offset = @intFromEnum(offset_reg);
        return 0xF8607800 | (offset << 16) | (base << 5) | dst;
    }

    pub inline fn ldrRegUnscaled(dst_reg: Reg, base_reg: Reg, offset_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        const base = @intFromEnum(base_reg);
        const off = @intFromEnum(offset_reg);
        return 0xF8606800 | (off << 16) | (base << 5) | dst;
    }

    pub inline fn subRegImm(dst_reg: Reg, src_reg: Reg, imm: u32) u32 {
        std.debug.assert(imm <= 0b111111_111111);
        const src = @intFromEnum(src_reg);
        const dst = @intFromEnum(dst_reg);

        return 0xD1000000 | (imm << 10) | (src << 5) | dst;
    }

    pub inline fn addRegImm(dst_reg: Reg, src_reg: Reg, imm: u32) u32 {
        const dst = @intFromEnum(dst_reg);
        const src = @intFromEnum(src_reg);
        std.debug.assert(imm <= 0b111111_111111);
        return 0x91000400 | (imm << 10) | (src << 5) | dst;
    }

    pub inline fn addRegs(dst_reg: Reg, reg_a: Reg, reg_b: Reg) u32 {
        const a = @intFromEnum(reg_a);
        const b = @intFromEnum(reg_b);
        const dst = @intFromEnum(dst_reg);

        return 0x8b000000 | (b << 16) | (a << 5) | dst;
    }

    pub inline fn strReg(src_reg: Reg, dst_reg: Reg, offset: u32) u32 {
        const dst = @intFromEnum(src_reg);
        const src = @intFromEnum(dst_reg);
        std.debug.assert(offset <= 0b111111_111111);
        return 0xF9000000 | (offset << 10) | (src << 5) | dst;
    }

    pub inline fn strRegScaled(src_reg: Reg, base_reg: Reg, offset_reg: Reg) u32 {
        const src = @intFromEnum(src_reg);
        const base = @intFromEnum(base_reg);
        const offset = @intFromEnum(offset_reg);

        return 0xF8207800 | (offset << 16) | (base << 5) | src;
    }

    pub inline fn mult8(dst_reg: Reg, src_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        const src = @intFromEnum(src_reg);

        return 0xD37DF000 | (src << 5) | dst;
    }
};

test "ARMv8a code generation" {
    const ldr_x8_x2 = Armv8a.ldrReg(.x8, .x2);
    try std.testing.expectEqual(0xf9400048, ldr_x8_x2);
    // ldr x9, [x0, x8, lsl #3]
    const ldr_scaled_offset = Armv8a.ldrRegScaled(.x9, .x0, .x8);
    try std.testing.expectEqual(0xf8687809, ldr_scaled_offset);
    // ldr x11, [x0, x10]
    const ldr_unscaled_offset = Armv8a.ldrRegUnscaled(.x11, .x0, .x10);
    try std.testing.expectEqual(0xf86a680b, ldr_unscaled_offset);
    // add x12, x12, #1
    try std.testing.expectEqual(0x9100058c, Armv8a.addRegImm(.x12, .x12, 1));
    // sub x8, x8, #1
    try std.testing.expectEqual(0xd1000508, Armv8a.subRegImm(.x8, .x8, 1));
    // str x8, [x2]
    try std.testing.expectEqual(0xf9000048, Armv8a.strReg(.x8, .x2, 0));
    // lsl x10, x8, #3
    try std.testing.expectEqual(0xd37df10a, Armv8a.mult8(.x10, .x8));
    // add x9, x11, x9
    try std.testing.expectEqual(0x8b090169, Armv8a.addRegs(.x9, .x11, .x9));
    // str x8, [x9, x10, lsl #3]
    try std.testing.expectEqual(0xf82a7928, Armv8a.strRegScaled(.x8, .x9, .x10));
}

const JitFunction = *fn (
    stack: [*]i64,
    instructions: [*]const u8,
    stack_ptr: *usize,
    instr_ptr: *usize,
    blocks: [*]const CodeBlock,
    current_block: *const CodeBlock,
) callconv(.C) void;

const CompiledFunction = struct {
    func: JitFunction, // both func and buf point to the same data.
    buf: [*]u32,
    size: usize,

    pub fn init(func: JitFunction, buf: [*]u32, size: usize) CompiledFunction {
        return .{ .func = func, .buf = buf, .size = size };
    }

    pub fn deinit(self: *CompiledFunction) void {
        if (mman.munmap(self.buf, self.size) != 0) {
            std.debug.panic("munmap failed\n", .{});
        }
    }
};

const JITCompiler = struct {
    allocator: std.mem.Allocator,

    interpreter: *const Interpreter,
    machine_code: std.ArrayList(u32),
    current_block: *const CodeBlock = undefined,

    const ArgReg = struct {
        const stackAddr = .x0;
        const instructionsAddr = .x1;
        const stackPtr = .x2;
        const instrPtr = .x3;
        const blocks = .x4;
        const currentBlock = .x5;
    };

    const VarReg = struct {
        const stackPtr = .x8;
        const instrPtr = .x12;
        const tempA = .x9;
        const tempB = .x10;
        const tempC = .x11;
    };

    pub fn init(allocator: std.mem.Allocator, interpreter: *Interpreter) JITCompiler {
        return .{
            .allocator = allocator,
            .interpreter = interpreter,
            .machine_code = std.ArrayList(u32).init(allocator),
        };
    }

    pub fn deinit(self: *JITCompiler) void {
        self.machine_code.deinit();
    }

    fn allocJitBuf(nbytes: usize) [*]u32 {
        const buf: *anyopaque = mman.mmap(
            null,
            nbytes,
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

    fn deallocJitBuf(buf: [*]u32, size: usize) void {
        if (mman.munmap(buf, size) != 0) {
            std.debug.panic("munmap failed\n", .{});
        }
    }

    /// Take all the machine code instructions emitted so far,
    /// compile them into a function, then return the function.
    fn getCompiledFunction(self: *JITCompiler) CompiledFunction {
        const num_instructions = self.machine_code.items.len;
        const bufsize = num_instructions;
        const buf = allocJitBuf(bufsize);

        pthread.pthread_jit_write_protect_np(0);
        @memcpy(buf, self.machine_code.items);
        pthread.pthread_jit_write_protect_np(1);

        const func: JitFunction = @ptrCast(buf);
        return CompiledFunction.init(func, buf, bufsize);
    }

    inline fn emit(self: *JITCompiler, instr: u32) !void {
        try self.machine_code.append(instr);
    }

    fn emitPrelude(self: *JITCompiler) !void {
        // deref the stack pointer, store it in a local var
        try self.emit(Armv8a.ldrReg(VarReg.stackPtr, ArgReg.stackPtr));
        // deref the instruction pointer, store it in a local var
        try self.emit(Armv8a.ldrReg(VarReg.instrPtr, ArgReg.instrPtr));
    }

    fn emitEpilogue(self: *JITCompiler) !void {
        // Restore the stack and instruction pointers
        try self.emit(Armv8a.strReg(VarReg.stackPtr, ArgReg.stackPtr, 0));
        try self.emit(Armv8a.strReg(VarReg.instrPtr, ArgReg.instrPtr, 0));
    }

    fn emitPop(self: *JITCompiler) !void {
        try self.emit(Armv8a.subRegImm(
            VarReg.stackPtr,
            VarReg.stackPtr,
            1,
        ));
    }

    fn emitPushReg(self: *JITCompiler, reg: Armv8a.Reg) !void {
        try self.emit(Armv8a.strRegScaled(
            reg,
            ArgReg.stackAddr,
            VarReg.stackPtr,
        ));

        try self.emit(Armv8a.addRegImm(
            VarReg.stackPtr,
            VarReg.stackPtr,
            1,
        ));
    }

    fn emitReturn(self: *JITCompiler) !void {
        try self.emitEpilogue();
        try self.emit(Armv8a.ret);
    }

    pub fn compileBlock(self: *JITCompiler, block: *const CodeBlock) !CompiledFunction {
        self.current_block = block;

        try self.emitPrelude();
        for (block.instructions) |instruction| {
            const op: Opcode = @enumFromInt(instruction);

            // ip += 1; // TODO: increment instr pointer just once, for all instrs.
            try self.emit(Armv8a.addRegImm(
                ArgReg.instrPtr,
                ArgReg.instrPtr,
                1,
            ));

            switch (op) {
                .push => {},
                .add => {
                    // A = pop()
                    try self.emitPop();
                    try self.emit(Armv8a.ldrRegScaled(
                        VarReg.tempA,
                        ArgReg.stackAddr,
                        VarReg.stackPtr,
                    ));

                    // B = pop()
                    try self.emitPop();
                    try self.emit(Armv8a.ldrRegScaled(
                        VarReg.tempB,
                        ArgReg.stackAddr,
                        VarReg.stackPtr,
                    ));

                    try self.emit(Armv8a.addRegs(
                        VarReg.tempA,
                        VarReg.tempA,
                        VarReg.tempB,
                    )); // a = a + b

                    try self.emitPushReg(VarReg.tempA);
                },
                else => try self.emitReturn(),
            }
        }

        try self.emitReturn();
        return self.getCompiledFunction();
    }
};

test "JITCompiler" {
    const allocator = std.testing.allocator;
    const program = [_]CodeBlock{.{
        .constants = &[_]i64{0},
        .instructions = &[_]u8{ Op(.add), Op(.exit) },
    }};

    var interpreter = try Interpreter.init(allocator, &program);
    defer {
        interpreter.deinit();
        allocator.destroy(interpreter);
    }

    const compiled = try interpreter.jit_compiler.compileBlock(&program[0]);

    var stack = [_]i64{ 2, 3 };
    var s_ptr: usize = 2;
    var i_ptr: usize = 0;
    var instructions = program[0].instructions;
    const blocks = &program;
    const current_block: *const CodeBlock = &program[0];

    compiled.func(
        (&stack).ptr,
        (&instructions).ptr,
        &s_ptr,
        &i_ptr,
        blocks.ptr,
        current_block,
    );

    try std.testing.expectEqual(1, s_ptr);
    try std.testing.expectEqual(5, stack[s_ptr - 1]);
}

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

        // if the block is compiled, call compiledBlock().

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
