/**
 * `parseBranchTarget` used to exist twice: once in `shared.tsx` and once as a
 * private copy inside `JumpArrows.tsx`. The copies are collapsed onto the
 * `shared.tsx` implementation; these tests pin its contract, including the
 * inputs that used to reach the JumpArrows copy's dead second `jmp` branch.
 */
import { describe, expect, it } from "vitest";
import { isJumpMnemonic, parseBranchTarget } from "../shared";

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

/**
 * peek-a-bin-8bj — the A64 half.
 *
 * `parseBranchTarget` matched `^0x…$` and gated on `mnemonic.startsWith("j")`,
 * both x86 spellings, so on an ARM64 image it resolved nothing: 0 of 27428
 * instructions on t64-arm.exe, and consequently no jump arrows and no
 * "follow branch" navigation. The operand strings here are Capstone's output on
 * that file.
 *
 * There is no React renderer in this project, so `JumpArrows` itself is not
 * mounted by any test. What IS testable is the pair of pure functions it calls,
 * and the guard it applies between them — that is what these pin.
 */
describe("parseBranchTarget — ARM64", () => {
  it("resolves the A64 direct branches", () => {
    expect(parseBranchTarget("b", "#0x140001210")).toBe(0x140001210);
    expect(parseBranchTarget("bl", "#0x140003160")).toBe(0x140003160);
    expect(parseBranchTarget("b.eq", "#0x1400011d4")).toBe(0x1400011d4);
    expect(parseBranchTarget("cbz", "x3, #0x140001164")).toBe(0x140001164);
    expect(parseBranchTarget("cbnz", "w2, #0x140001500")).toBe(0x140001500);
    expect(parseBranchTarget("tbz", "w2, #2, #0x14000114c")).toBe(0x14000114c);
    expect(parseBranchTarget("tbnz", "w0, #0x1f, #0x1400025b8")).toBe(0x1400025b8);
  });

  it("returns null for indirect A64 transfers rather than a guess", () => {
    expect(parseBranchTarget("br", "x8")).toBeNull();
    expect(parseBranchTarget("blr", "x2")).toBeNull();
    expect(parseBranchTarget("ret", "")).toBeNull();
  });

  it("returns null for A64 non-branches, including the brk that looks like br", () => {
    for (const [mn, ops] of [
      ["brk", "#1"],
      ["adrp", "x16, #0x140027000"],
      ["add", "x16, x16, #0"],
      ["ldr", "x16, [x16]"],
      ["stp", "x19, x20, [sp, #-0x30]!"],
    ]) {
      expect(parseBranchTarget(mn, ops), `${mn} ${ops}`).toBeNull();
    }
  });

  it("does not accept a bare 0x target on an A64 mnemonic", () => {
    // A64 writes `#0x…`. Accepting the x86 spelling here would mean the parser
    // had stopped checking which grammar it was reading.
    expect(parseBranchTarget("b", "0x140001210")).toBeNull();
  });
});

describe("isJumpMnemonic — the JumpArrows guard", () => {
  it("keeps drawing for every x86 jump it used to", () => {
    for (const mn of ["jmp", "je", "jne", "jz", "jnz", "jle", "jbe", "jecxz", "jrcxz"]) {
      expect(isJumpMnemonic(mn)).toBe(true);
    }
  });

  it("still excludes x86 call, which is the whole point of the guard", () => {
    expect(isJumpMnemonic("call")).toBe(false);
    for (const mn of ["mov", "push", "ret", "nop", "lea"]) {
      expect(isJumpMnemonic(mn)).toBe(false);
    }
  });

  it("now draws for A64 jumps and conditional branches", () => {
    for (const mn of ["b", "b.eq", "b.ne", "cbz", "cbnz", "tbz", "tbnz"]) {
      expect(isJumpMnemonic(mn)).toBe(true);
    }
  });

  it("excludes bl and blr, which are A64 calls", () => {
    expect(isJumpMnemonic("bl")).toBe(false);
    expect(isJumpMnemonic("blr")).toBe(false);
  });
});
