/**
 * `parseBranchTarget` used to exist twice: once in `shared.tsx` and once as a
 * private copy inside `JumpArrows.tsx`. The copies are collapsed onto the
 * `shared.tsx` implementation; these tests pin its contract, including the
 * inputs that used to reach the JumpArrows copy's dead second `jmp` branch.
 */
import { describe, it, expect } from "vitest";
import { parseBranchTarget } from "../shared";

describe("parseBranchTarget", () => {
  it("resolves a direct jmp immediate", () => {
    expect(parseBranchTarget("jmp", "0x401000")).toBe(0x401000);
  });

  it("resolves conditional jumps", () => {
    for (const mn of ["je", "jne", "jz", "jnz", "jle", "jbe", "jecxz", "jrcxz"]) {
      expect(parseBranchTarget(mn, "0x140001234")).toBe(0x140001234);
    }
  });

  it("resolves a call immediate", () => {
    expect(parseBranchTarget("call", "0x401000")).toBe(0x401000);
  });

  it("accepts upper-case hex digits", () => {
    expect(parseBranchTarget("jmp", "0xDEADBEEF")).toBe(0xdeadbeef);
  });

  it("returns null for non-branch mnemonics", () => {
    for (const mn of ["mov", "push", "ret", "nop", "int3", "lea"]) {
      expect(parseBranchTarget(mn, "0x401000")).toBeNull();
    }
  });

  // The JumpArrows copy tested `mnemonic === "jmp"` a second time and re-ran the
  // identical regex on the identical operand. Every input below entered that
  // second block, and the regex necessarily failed there exactly as it had the
  // first time — so the branch could never return. These pin that the single
  // shared implementation yields null for all of them.
  it("returns null for indirect jmp operands that entered the dead branch", () => {
    expect(parseBranchTarget("jmp", "rax")).toBeNull();
    expect(parseBranchTarget("jmp", "eax")).toBeNull();
    expect(parseBranchTarget("jmp", "qword ptr [rip + 0x1234]")).toBeNull();
    expect(parseBranchTarget("jmp", "dword ptr [eax*4 + 0x402000]")).toBeNull();
    expect(parseBranchTarget("jmp", "")).toBeNull();
  });

  it("requires the whole operand to be the immediate", () => {
    expect(parseBranchTarget("jmp", "0x401000 ")).toBeNull();
    expect(parseBranchTarget("jmp", "short 0x401000")).toBeNull();
    expect(parseBranchTarget("jmp", "0x401000, 0x401004")).toBeNull();
    expect(parseBranchTarget("jmp", "401000")).toBeNull();
    expect(parseBranchTarget("jmp", "0x")).toBeNull();
  });
});
