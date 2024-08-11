const std = @import("std");
const interp = @import("interpreter.zig");
const mman = @cImport(@cInclude("sys/mman.h"));
const pthread = @cImport(@cInclude("pthread.h"));

const CodeBlock = interp.CodeBlock;
const Interpreter = interp.Interpreter;
const Opcode = interp.Opcode;
const Op = interp.Op;

const Armv8a = struct {
    pub const ret: u32 = 0xd65f03c0;

    // GPRs in AArch64. We only ever use 12 of them.
    const Reg = enum(u32) { x0 = 0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12 };

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

    pub inline fn ldrByteReg(dst_reg: Reg, base_reg: Reg, offset_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        const base = @intFromEnum(base_reg);
        const offset = @intFromEnum(offset_reg);

        return 0x38606800 | (offset << 16) | (base << 5) | dst;
    }

    pub inline fn cmpRegs(a_reg: Reg, b_reg: Reg) u32 {
        const a = @intFromEnum(a_reg);
        const b = @intFromEnum(b_reg);
        return 0xEB00001F | (b << 16) | (a << 5);
    }

    /// Same as the `cset [reg] eq` instruction in ARM
    pub inline fn setIfStatusEq(dst_reg: Reg) u32 {
        const dst = @intFromEnum(dst_reg);
        return 0x9A9F17E0 | dst;
    }

    pub inline fn movRegImm(dst_reg: Reg, imm: u32) u32 {
        const dst = @intFromEnum(dst_reg);
        return 0xD2800000 | (imm << 5) | dst;
    }

    pub inline fn cmpImmediate(reg: Reg, value: u32) u32 {
        const r = @intFromEnum(reg);
        return 0xF100001F | (value << 10) | (r << 5);
    }

    pub inline fn branchIfEq(branch_offset: u32) u32 {
        return 0x54000000 | (branch_offset << 5);
    }
};

pub const JitFunction = *fn (
    stack: [*]i64, // x0
    instructions: [*]const u8, // x1
    stack_ptr: *usize, // x2
    instr_ptr: *usize, // x3
    current_block_index: *usize, // x5
    constants: [*]const i64, // x6
) callconv(.C) void;

pub const CompiledFunction = struct {
    func: JitFunction, // both func and buf point to the same data.
    buf: [*]u32,
    size: usize,

    pub fn init(func: JitFunction, buf: [*]u32, size: usize) CompiledFunction {
        return .{ .func = func, .buf = buf, .size = size };
    }

    pub fn deinit(self: *const CompiledFunction) void {
        if (mman.munmap(self.buf, self.size) != 0) {
            std.debug.panic("munmap failed\n", .{});
        }
    }
};

pub const JITCompiler = struct {
    allocator: std.mem.Allocator,

    interpreter: *const Interpreter,
    machine_code: std.ArrayList(u32),

    const ArgReg = struct {
        const stackAddr = .x0;
        const instructionsAddr = .x1;
        const stackIndexPtr = .x2;
        const instrIndexPtr = .x3;
        const currentBlockNumber = .x4;
        const constantsAddr = .x5;
    };

    const VarReg = struct {
        const stackIndex = .x8;
        const instrIndex = .x12;
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

    pub fn deinit(self: *const JITCompiler) void {
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
        try self.emit(Armv8a.ldrReg(VarReg.stackIndex, ArgReg.stackIndexPtr));
        // deref the instruction pointer, store it in a local var
        try self.emit(Armv8a.ldrReg(VarReg.instrIndex, ArgReg.instrIndexPtr));
    }

    fn emitEpilogue(self: *JITCompiler) !void {
        // Restore the stack and instruction pointers
        try self.emit(Armv8a.strReg(VarReg.stackIndex, ArgReg.stackIndexPtr, 0));
        try self.emit(Armv8a.strReg(VarReg.instrIndex, ArgReg.instrIndexPtr, 0));
    }

    fn emitPop(self: *JITCompiler) !void {
        try self.emit(Armv8a.subRegImm(
            VarReg.stackIndex,
            VarReg.stackIndex,
            1,
        ));
    }

    fn emitPushReg(self: *JITCompiler, reg: Armv8a.Reg) !void {
        try self.emit(Armv8a.strRegScaled(
            reg,
            ArgReg.stackAddr,
            VarReg.stackIndex,
        ));

        try self.emit(Armv8a.addRegImm(
            VarReg.stackIndex,
            VarReg.stackIndex,
            1,
        ));
    }

    inline fn emitReturn(self: *JITCompiler) !void {
        try self.emitEpilogue();
        try self.emit(Armv8a.ret);
    }

    inline fn emitAdvanceIp(self: *JITCompiler) !void {
        try self.emit(Armv8a.addRegImm(
            VarReg.instrIndex,
            VarReg.instrIndex,
            1,
        ));
    }

    inline fn readInstruction(self: *JITCompiler, dst_reg: Armv8a.Reg) !void {
        try self.emit(Armv8a.ldrByteReg(
            dst_reg,
            ArgReg.instructionsAddr,
            VarReg.instrIndex,
        ));

        try self.emitAdvanceIp();
    }

    inline fn readStackTop(self: *JITCompiler, dst_reg: Armv8a.Reg) !void {
        try self.emit(Armv8a.ldrRegScaled(
            dst_reg,
            ArgReg.stackAddr,
            VarReg.stackIndex,
        ));
    }

    pub fn compileBlock(self: *JITCompiler, block: *const CodeBlock) !CompiledFunction {
        try self.emitPrelude();

        var i: usize = 0;
        while (i < block.instructions.len) {
            const instruction = block.instructions[i];
            const op: Opcode = @enumFromInt(instruction);

            // ip += 1;
            try self.emit(Armv8a.addRegImm(
                VarReg.instrIndex,
                VarReg.instrIndex,
                1,
            ));

            i += 1;

            switch (op) {
                .load_var => {
                    // a = instructions[ip]; ip++;
                    try self.readInstruction(VarReg.tempA);
                    i += 1;

                    try self.emit(Armv8a.ldrRegScaled(
                        VarReg.tempB,
                        ArgReg.stackAddr,
                        VarReg.tempA,
                    )); // b = stack[a]
                    try self.emitPushReg(VarReg.tempB); // push(stack[a]);
                },

                .eq => {
                    try self.emitPop();
                    try self.readStackTop(VarReg.tempA);

                    try self.emitPop();
                    try self.readStackTop(VarReg.tempB);

                    try self.emit(Armv8a.cmpRegs(VarReg.tempA, VarReg.tempB));
                    try self.emit(Armv8a.setIfStatusEq(VarReg.tempC));
                    try self.emitPushReg(VarReg.tempC);
                },

                .store_var => {
                    // a = instructions[ip]; ip++;
                    try self.readInstruction(VarReg.tempA);
                    i += 1;

                    // b = pop();
                    try self.emitPop();
                    try self.emit(Armv8a.ldrRegScaled(
                        VarReg.tempB,
                        ArgReg.stackAddr,
                        VarReg.stackIndex,
                    ));

                    try self.emit(Armv8a.strRegScaled(
                        VarReg.tempB,
                        ArgReg.stackAddr,
                        VarReg.tempA,
                    )); // stack[a] = b;
                },

                .push => {
                    try self.readInstruction(VarReg.tempA);
                    i += 1;

                    try self.emit(Armv8a.ldrRegScaled(
                        VarReg.tempB,
                        ArgReg.constantsAddr,
                        VarReg.tempA,
                    )); // b = constants[a]

                    try self.emitPushReg(VarReg.tempB); // push(p)
                },

                .jump => {
                    try self.readInstruction(VarReg.tempA);
                    i += 1;

                    try self.emit(Armv8a.strReg(
                        VarReg.tempA,
                        ArgReg.currentBlockNumber,
                        0,
                    ));

                    // TODO: if the jump destination is the same block,
                    // set ip to zero, and jump backwards to the start of the block.

                    try self.emit(Armv8a.movRegImm(VarReg.instrIndex, 0)); // ip = 0
                    try self.emitReturn();
                },

                .jump_nz => {
                    // a = pop();
                    try self.emitPop();
                    try self.readStackTop(VarReg.tempA);

                    const dst_block = VarReg.tempB;

                    // block_index = instructions[ip]; ip++;
                    try self.readInstruction(dst_block);
                    i += 1;

                    // if (a == 0)
                    try self.emit(Armv8a.cmpImmediate(VarReg.tempA, 0));
                    try self.emit(Armv8a.setIfStatusEq(VarReg.tempC));

                    try self.emit(0); // dummy instr, this will be patched below
                    const jmp_instr_index = self.machine_code.items.len - 1;

                    // current_block = block_index;
                    try self.emit(Armv8a.strReg(dst_block, ArgReg.currentBlockNumber, 0));
                    try self.emit(Armv8a.movRegImm(VarReg.instrIndex, 0)); // ip = 0
                    try self.emitReturn();

                    // patch the dummy jump instruction we emitted above
                    const offset = self.machine_code.items.len - jmp_instr_index;
                    self.machine_code.items[jmp_instr_index] =
                        Armv8a.branchIfEq(@intCast(offset));
                },

                .add => {
                    // A = pop()
                    try self.emitPop();
                    try self.readStackTop(VarReg.tempA);

                    // B = pop()
                    try self.emitPop();
                    try self.readStackTop(VarReg.tempB);

                    try self.emit(Armv8a.addRegs(
                        VarReg.tempA,
                        VarReg.tempA,
                        VarReg.tempB,
                    )); // a = a + b

                    try self.emitPushReg(VarReg.tempA);
                },
            }
        }

        try self.emitReturn();
        return self.getCompiledFunction();
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
    // ldrb w8, [x1, x8]
    try std.testing.expectEqual(0x38686828, Armv8a.ldrByteReg(.x8, .x1, .x8));
    // cmp x1, x2
    try std.testing.expectEqual(0xeb02003f, Armv8a.cmpRegs(.x1, .x2));
    // cset x3, eq
    try std.testing.expectEqual(0x9A9F17E3, Armv8a.setIfStatusEq(.x3));
    // mov x1, #9
    try std.testing.expectEqual(0xd2800121, Armv8a.movRegImm(.x1, 9));
    // cmp x1, #1
    try std.testing.expectEqual(0xf100043f, Armv8a.cmpImmediate(.x1, 1));
    // b.eq (ip + 2)
    try std.testing.expectEqual(0x54000040, Armv8a.branchIfEq(2));
}

test "JITCompiler" {
    const allocator = std.testing.allocator;
    const program = [_]CodeBlock{.{
        .constants = &[_]i64{ 30, 12 },
        .instructions = &[_]u8{
            Op(.add),
            Op(.push), // x = 30
            0,
            Op(.load_var), // push(x)
            0,
            Op(.push),
            1,
            Op(.store_var),
            0,

            Op(.push),
            1,
            Op(.push),
            0,
            Op(.eq),

            Op(.jump_nz),
            33,

            Op(.push),
            1,
            Op(.push),
            0,
            Op(.eq),

            Op(.push),
            1,
            Op(.push),
            1,
            Op(.eq),

            Op(.jump_nz),
            22,
        },
    }};

    var interpreter = try Interpreter.init(allocator, &program);
    defer {
        interpreter.deinit();
        allocator.destroy(interpreter);
    }

    const compiled = try interpreter.jit_compiler.compileBlock(&program[0]);

    var stack = [_]i64{ 2, 3, 0, 0, 0, 0, 0, 0 };
    var s_ptr: usize = 2;
    var i_ptr: usize = 0;
    var instructions = program[0].instructions;
    var current_block_index: usize = 0;

    compiled.func(
        (&stack).ptr,
        (&instructions).ptr,
        &s_ptr,
        &i_ptr,
        &current_block_index,
        program[0].constants.ptr,
    );

    try std.testing.expectEqual(4, s_ptr);
    try std.testing.expectEqual(0, i_ptr);
    try std.testing.expectEqualSlices(i64, &[_]i64{ 12, 30, 5, 0 }, stack[0..s_ptr]);
    try std.testing.expectEqual(22, current_block_index);
}
