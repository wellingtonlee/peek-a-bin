import { describe, expect, it } from "vitest";
import {
  buildCallSummaries,
  isCoveredMnemonic,
  resolveBranchTargetAddr,
  writtenRegs,
  writtenRegsOfInsn,
  X64_ABI_FALLBACK,
} from "../callSummary";
import type { Instruction } from "../types";

function insn(mnemonic: string, opStr = "", address = 0x1000, size = 5): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

function fn(...list: Instruction[]): Instruction[] {
  return list;
}

describe("writtenRegsOfInsn", () => {
  it("writes the first operand when it is a register", () => {
    expect(writtenRegsOfInsn(insn("mov", "rcx, rdx"))).toEqual(["rcx"]);
    expect(writtenRegsOfInsn(insn("lea", "r8, [rax + 8]"))).toEqual(["r8"]);
    expect(writtenRegsOfInsn(insn("add", "r11d, 1"))).toEqual(["r11"]);
  });

  it("writes nothing when the destination is memory", () => {
    expect(writtenRegsOfInsn(insn("mov", "qword ptr [rcx + 8], rdx"))).toEqual([]);
    expect(writtenRegsOfInsn(insn("and", "byte ptr [rax + rcx*1 + 8], 0xfe"))).toEqual([]);
  });

  it("canonicalises a sub-register write to its 64-bit parent", () => {
    // `mov cl, 2` is one byte of RCX, and the identity SSA keys on is RCX.
    expect(writtenRegsOfInsn(insn("mov", "cl, 2"))).toEqual(["rcx"]);
    expect(writtenRegsOfInsn(insn("xor", "eax, eax"))).toEqual(["rax"]);
    expect(writtenRegsOfInsn(insn("movzx", "r9d, byte ptr [rdx]"))).toEqual(["r9"]);
  });

  it("reads a comparison and writes nothing", () => {
    expect(writtenRegsOfInsn(insn("cmp", "rax, rcx"))).toEqual([]);
    expect(writtenRegsOfInsn(insn("test", "al, al"))).toEqual([]);
    // `bt` tests a bit; only `bts`/`btr`/`btc` write one back.
    expect(writtenRegsOfInsn(insn("bt", "rax, 3"))).toEqual([]);
    expect(writtenRegsOfInsn(insn("bts", "rax, 3"))).toEqual(["rax"]);
  });

  it("gives a call its result register and nothing else", () => {
    // The callee's own writes are the call graph's business, not this scan's.
    expect(writtenRegsOfInsn(insn("call", "0x140001000"))).toEqual(["rax"]);
  });

  it("splits imul by operand count", () => {
    expect(writtenRegsOfInsn(insn("imul", "rcx"))).toEqual(["rax", "rdx"]);
    expect(writtenRegsOfInsn(insn("imul", "rcx, rdx"))).toEqual(["rcx"]);
    expect(writtenRegsOfInsn(insn("imul", "rcx, rdx, 0x58"))).toEqual(["rcx"]);
  });

  it("knows the implicit RDX:RAX pair", () => {
    expect(writtenRegsOfInsn(insn("mul", "rcx")).sort()).toEqual(["rax", "rdx"]);
    expect(writtenRegsOfInsn(insn("div", "rcx")).sort()).toEqual(["rax", "rdx"]);
    expect(writtenRegsOfInsn(insn("cdq"))).toEqual(["rdx"]);
    expect(writtenRegsOfInsn(insn("cdqe"))).toEqual(["rax"]);
  });

  it("writes both operands of an exchange", () => {
    expect(writtenRegsOfInsn(insn("xchg", "rax, rcx")).sort()).toEqual(["rax", "rcx"]);
  });

  it("writes the accumulator as well as the destination of a cmpxchg", () => {
    expect(writtenRegsOfInsn(insn("cmpxchg", "rcx, rdx")).sort()).toEqual(["rax", "rcx"]);
  });

  it("reads a lock or rep prefix off the front of the mnemonic", () => {
    // Capstone puts the prefix in the mnemonic; the base mnemonic is the last word.
    expect(writtenRegsOfInsn(insn("lock inc", "dword ptr [rax]"))).toEqual([]);
    expect(writtenRegsOfInsn(insn("lock add", "qword ptr [rax], rcx"))).toEqual([]);
    // A repeated string primitive leaves its counter at zero.
    expect(writtenRegsOfInsn(insn("rep movsd")).sort()).toEqual(["rcx", "rdi", "rsi"]);
    expect(writtenRegsOfInsn(insn("repne scasw")).sort()).toEqual(["rcx", "rdi"]);
    expect(writtenRegsOfInsn(insn("stosd")).sort()).toEqual(["rdi"]);
  });

  it("writes the destination of a setcc or cmovcc", () => {
    expect(writtenRegsOfInsn(insn("setne", "al"))).toEqual(["rax"]);
    expect(writtenRegsOfInsn(insn("cmove", "rcx, rdx"))).toEqual(["rcx"]);
  });

  it("writes nothing for an unrecognised mnemonic", () => {
    // The under-approximating direction: a missed write costs a clobber, an
    // invented one is the harm this module exists to avoid.
    expect(writtenRegsOfInsn(insn("vfmadd132ps", "xmm0, xmm1, xmm2"))).toEqual([]);
    expect(isCoveredMnemonic("vfmadd132ps")).toBe(false);
    expect(isCoveredMnemonic("cmovbe")).toBe(true);
    expect(isCoveredMnemonic("jbe")).toBe(true);
    expect(isCoveredMnemonic("rep stosd")).toBe(true);
  });
});

describe("writtenRegs", () => {
  it("does not count a pop matched by a push of the same register", () => {
    // A save/restore pair returns the caller's value; 32-bit `_chkstk` preserves
    // ECX exactly this way while destroying EAX.
    const body = fn(
      insn("push", "rcx"),
      insn("mov", "rax, 0x1000"),
      insn("pop", "rcx"),
      insn("ret"),
    );
    expect([...writtenRegs(body)].sort()).toEqual(["rax"]);
  });

  it("counts a pop with no matching push — push imm / pop reg is a mov", () => {
    // `push 7 / pop ecx` is a pervasive MSVC size idiom for `mov ecx, 7`.
    const body = fn(insn("push", "7"), insn("pop", "rcx"), insn("ret"));
    expect([...writtenRegs(body)].sort()).toEqual(["rcx"]);
  });

  it("counts a register another instruction writes, whatever the pops do", () => {
    const body = fn(insn("push", "rbx"), insn("mov", "rbx, rcx"), insn("pop", "rbx"), insn("ret"));
    expect([...writtenRegs(body)].sort()).toEqual(["rbx"]);
  });
});

describe("resolveBranchTargetAddr", () => {
  it("resolves a direct call to a code address", () => {
    expect(resolveBranchTargetAddr(insn("call", "0x140001000"))).toEqual({
      kind: "direct",
      addr: 0x140001000,
    });
  });

  it("resolves a RIP-relative call to the pointer's address", () => {
    const i = insn("call", "qword ptr [rip + 0x10]", 0x140002000, 6);
    expect(resolveBranchTargetAddr(i)).toEqual({ kind: "indirectMem", addr: 0x140002016 });
  });

  it("resolves an absolute bracketed call to the pointer's address", () => {
    expect(resolveBranchTargetAddr(insn("call", "dword ptr [0x40b000]"))).toEqual({
      kind: "indirectMem",
      addr: 0x40b000,
    });
  });

  it("returns null for an indirect call through a register", () => {
    expect(resolveBranchTargetAddr(insn("call", "rax"))).toBeNull();
  });
});

describe("buildCallSummaries", () => {
  const iat = new Map([[0x140009000, { lib: "kernel32.dll", func: "Sleep" }]]);

  it("reports only the volatile registers, so a restored callee-saved one is not a clobber", () => {
    const map = new Map([
      [0x1000, fn(insn("mov", "rbx, rcx"), insn("mov", "r10, 1"), insn("ret"))],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000],
      funcInsnMap: map,
      iatMap: iat,
    });
    expect(s.get(0x1000)).toEqual(["r10"]);
  });

  it("closes over a direct call to another local function", () => {
    const map = new Map([
      [0x1000, fn(insn("call", "0x2000", 0x1000), insn("ret", "", 0x1005))],
      [0x2000, fn(insn("mov", "r11, 1", 0x2000), insn("ret", "", 0x2003))],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000, 0x2000],
      funcInsnMap: map,
      iatMap: iat,
    });
    // RAX because a call defines its result; R11 through the callee.
    expect(s.get(0x1000)).toEqual(["rax", "r11"]);
    expect(s.get(0x2000)).toEqual(["r11"]);
  });

  it("closes over a tail jmp, which returns to this function's caller", () => {
    const map = new Map([
      [0x1000, fn(insn("jmp", "0x2000", 0x1000))],
      [0x2000, fn(insn("mov", "r10, 1", 0x2000), insn("ret", "", 0x2003))],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000, 0x2000],
      funcInsnMap: map,
      iatMap: iat,
    });
    expect(s.get(0x1000)).toEqual(["r10"]);
  });

  it("reaches a fixpoint on a recursive cycle rather than assuming the ABI set", () => {
    // A cycle's least fixpoint is the union of its members' own writes, which is
    // the correct may-write answer for entering it anywhere. Collapsing the
    // component to the ABI set instead would report writes no member performs.
    const map = new Map([
      [0x1000, fn(insn("mov", "rcx, 1", 0x1000), insn("jmp", "0x2000", 0x1003))],
      [0x2000, fn(insn("mov", "r9, 1", 0x2000), insn("jmp", "0x1000", 0x2003))],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000, 0x2000],
      funcInsnMap: map,
      iatMap: iat,
    });
    expect(s.get(0x1000)).toEqual(["rcx", "r9"]);
    expect(s.get(0x2000)).toEqual(["rcx", "r9"]);
  });

  it("keeps an unanalysable callee out of the answer by default", () => {
    const map = new Map([
      [
        0x1000,
        fn(
          insn("mov", "r10, 1", 0x1000),
          insn("call", "qword ptr [rip + 0x1ff5]", 0x1004, 6),
          insn("ret", "", 0x100a),
        ),
      ],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000],
      funcInsnMap: map,
      iatMap: new Map([[0x2fff, { lib: "kernel32.dll", func: "Sleep" }]]),
    });
    expect(s.get(0x1000)).toEqual(["rax", "r10"]);
  });

  it("gives an unanalysable callee the ABI set when asked to", () => {
    const map = new Map([
      [
        0x1000,
        fn(
          insn("mov", "r10, 1", 0x1000),
          insn("call", "qword ptr [rip + 0x1ff5]", 0x1004, 6),
          insn("ret", "", 0x100a),
        ),
      ],
    ]);
    const s = buildCallSummaries({
      functionAddresses: [0x1000],
      funcInsnMap: map,
      iatMap: new Map([[0x2fff, { lib: "kernel32.dll", func: "Sleep" }]]),
      unresolved: X64_ABI_FALLBACK,
    });
    expect(s.get(0x1000)).toEqual([...X64_ABI_FALLBACK]);
  });

  it("treats an indirect call as unanalysable and an intra-function jmp as nothing", () => {
    const map = new Map([
      [0x1000, fn(insn("call", "rax", 0x1000), insn("jmp", "0x1000", 0x1002), insn("ret"))],
    ]);
    const bare = buildCallSummaries({
      functionAddresses: [0x1000],
      funcInsnMap: map,
      iatMap: iat,
    });
    expect(bare.get(0x1000)).toEqual(["rax"]);
    const abi = buildCallSummaries({
      functionAddresses: [0x1000],
      funcInsnMap: map,
      iatMap: iat,
      unresolved: X64_ABI_FALLBACK,
    });
    expect(abi.get(0x1000)).toEqual([...X64_ABI_FALLBACK]);
  });
});
