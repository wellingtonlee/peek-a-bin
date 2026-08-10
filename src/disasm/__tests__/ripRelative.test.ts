import { describe, it, expect } from "vitest";
import {
  matchRipOperand,
  matchRipMemExpr,
  resolveRipTarget,
  resolveRipMemExpr,
} from "../ripRelative";

const insn = (address: number, opStr: string, size: number) => ({ address, size, opStr });

describe("matchRipOperand", () => {
  it("parses a positive displacement", () => {
    expect(matchRipOperand("rax, qword ptr [rip + 0x2000]")).toMatchObject({ disp: 0x2000 });
  });

  it("parses a negative displacement as a negative number", () => {
    expect(matchRipOperand("rcx, [rip - 0x1000]")).toMatchObject({ disp: -0x1000 });
  });

  it("parses a zero displacement", () => {
    expect(matchRipOperand("[rip + 0x0]")).toMatchObject({ disp: 0 });
  });

  it("accepts upper-case hex digits", () => {
    expect(matchRipOperand("[rip + 0xDEADBEEF]")?.disp).toBe(0xdeadbeef);
  });

  it("accepts upper-case RIP", () => {
    // Capstone emits lower case, but two of the nine former copies matched
    // case-insensitively and seven did not; the shared helper is permissive.
    expect(matchRipOperand("[RIP + 0x10]")?.disp).toBe(0x10);
    expect(matchRipOperand("[Rip - 0x10]")?.disp).toBe(-0x10);
  });

  it("tolerates extra whitespace around the operator and brackets", () => {
    expect(matchRipOperand("[  rip   +   0x40  ]")?.disp).toBe(0x40);
    expect(matchRipOperand("[rip-0x40]")?.disp).toBe(-0x40);
  });

  it("reports the matched span so a later hex scan can skip it", () => {
    const m = matchRipOperand("dword ptr [rip + 0x100], 0x3000");
    expect(m).not.toBeNull();
    expect("dword ptr [rip + 0x100], 0x3000".slice(m!.index, m!.index + m!.length)).toBe(
      "[rip + 0x100]",
    );
  });

  it("returns null for a non-RIP memory operand", () => {
    expect(matchRipOperand("rax, qword ptr [rbp - 0x10]")).toBeNull();
    expect(matchRipOperand("rax, qword ptr [rax + rcx*4 + 0x10]")).toBeNull();
    expect(matchRipOperand("dword ptr [0x407120]")).toBeNull();
  });

  it("returns null for malformed operands", () => {
    expect(matchRipOperand("")).toBeNull();
    expect(matchRipOperand("[rip]")).toBeNull();
    expect(matchRipOperand("[rip + ]")).toBeNull();
    expect(matchRipOperand("[rip + 0x]")).toBeNull();
    expect(matchRipOperand("[rip + 100]")).toBeNull();
    expect(matchRipOperand("[rip * 0x10]")).toBeNull();
    expect(matchRipOperand("[rip + 0x10")).toBeNull();
    // `ripple` must not be mistaken for `rip`.
    expect(matchRipOperand("[ripx + 0x10]")).toBeNull();
  });
});

describe("matchRipMemExpr", () => {
  it("parses a bare bracket body in both directions", () => {
    expect(matchRipMemExpr("rip + 0x100")?.disp).toBe(0x100);
    expect(matchRipMemExpr("rip - 0x100")?.disp).toBe(-0x100);
    expect(matchRipMemExpr(" RIP  +  0xAB ")?.disp).toBe(0xab);
  });

  it("is anchored — a RIP term mixed with other terms does not match", () => {
    expect(matchRipMemExpr("rax + rip + 0x10")).toBeNull();
    expect(matchRipMemExpr("rip + 0x10 + rax")).toBeNull();
    expect(matchRipMemExpr("[rip + 0x10]")).toBeNull();
    expect(matchRipMemExpr("rbp - 0x10")).toBeNull();
    expect(matchRipMemExpr("rip")).toBeNull();
  });
});

describe("resolveRipTarget", () => {
  // RIP points at the NEXT instruction, so the base is address + size.
  it("resolves forwards against the end of the instruction", () => {
    expect(resolveRipTarget(insn(0x140001000, "rax, qword ptr [rip + 0x2000]", 7))).toBe(
      0x140003007,
    );
  });

  it("resolves backwards against the end of the instruction", () => {
    expect(resolveRipTarget(insn(0x140005000, "rcx, [rip - 0x1000]", 7))).toBe(0x140004007);
  });

  it("resolves a zero displacement to the next instruction", () => {
    expect(resolveRipTarget(insn(0x1000, "[rip + 0x0]", 6))).toBe(0x1006);
  });

  it("returns null — not 0 — when there is no RIP operand", () => {
    expect(resolveRipTarget(insn(0x1000, "rax, qword ptr [rbp - 0x10]", 4))).toBeNull();
    expect(resolveRipTarget(insn(0x1000, "", 1))).toBeNull();
  });

  it("resolveRipMemExpr agrees with resolveRipTarget on the same displacement", () => {
    const i = insn(0x140001000, "qword ptr [rip + 0x8ff2]", 6);
    expect(resolveRipMemExpr("rip + 0x8ff2", i)).toBe(resolveRipTarget(i));
    expect(resolveRipMemExpr("rbp - 0x10", i)).toBeNull();
  });
});
