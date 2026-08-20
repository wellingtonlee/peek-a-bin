import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { Instruction } from "../../types";
import {
  blockFlagOwner,
  CARRY_IN_WRITERS,
  canSpellCondition,
  flagEffect,
  flagOwnerBefore,
  IMPLICIT_REG_WRITERS,
  isFlagReadingJump,
  NO_FLAG_WRITE,
  PARTIAL_FLAG_WRITERS,
  RESULT_OWNERS,
  SHIFTS,
  UNDEFINED_RESULT_FLAGS,
} from "../flagModel";
import { flagResultSetter } from "../flagResult";

/**
 * These tests were written before `flagModel.ts` existed, against the API the
 * two eventual consumers need (`structure.ts`'s `extractCondition` and
 * `flagResult.ts`'s `flagResultSetter`). The forward model is the half of
 * peek-a-bin-c33 most likely to go wrong silently: a wrong owner produces a
 * guard that is valid, plausible C stating something the machine does not do,
 * which CLAUDE.md records as invisible to every stage-level gate in this repo.
 * So the clear-on-unknown default gets a test per mnemonic class, and the
 * single most important assertion in the file is that an *unrecognised*
 * mnemonic clears the current owner.
 */

const BASE = 0x401000;

function insn(mnemonic: string, opStr = "", address = BASE): Instruction {
  return { address, mnemonic, opStr, size: 4, bytes: new Uint8Array(4) };
}

/**
 * A block from one instruction per string, `"<mnemonic> <operands>"`, 4 bytes
 * apart. A `lock`/`rep` prefix would be swallowed into the mnemonic here, so
 * those forms are tested through `flagEffect` directly.
 */
function block(...code: string[]): BasicBlock {
  const insns = code.map((line, i) => {
    const space = line.indexOf(" ");
    const mn = space < 0 ? line : line.slice(0, space);
    return insn(mn, space < 0 ? "" : line.slice(space + 1), BASE + i * 4);
  });
  return {
    id: 0,
    startAddr: BASE,
    endAddr: BASE + insns.length * 4,
    insns,
    succs: [],
    preds: [],
  };
}

/** The owner of a block that ends in a conditional jump. */
function owner(...code: string[]) {
  const answer = blockFlagOwner(block(...code));
  if (!answer) throw new Error("block does not end in a flag-reading jump");
  return answer.owner;
}

describe("flagEffect — the transfer function", () => {
  it("recognises the instructions that provably write no flag", () => {
    for (const mn of NO_FLAG_WRITE) {
      expect(flagEffect(insn(mn, "eax, ecx")), mn).toEqual({ kind: "none" });
    }
  });

  it("claims the flags for cmp and test", () => {
    expect(flagEffect(insn("cmp", "eax, 5"))).toEqual({ kind: "compare", mnemonic: "cmp" });
    expect(flagEffect(insn("test", "eax, eax"))).toEqual({ kind: "compare", mnemonic: "test" });
  });

  it("claims ZF/SF for every single-destination arithmetic and logical form", () => {
    for (const mn of RESULT_OWNERS) {
      // Shifts need a non-zero immediate count to have written anything.
      const ops = SHIFTS.has(mn) ? "ecx, 1" : "ecx, edx";
      expect(flagEffect(insn(mn, ops)), mn).toEqual({ kind: "result", destText: "ecx" });
    }
  });

  it("reads the destination exactly as written, memory included", () => {
    expect(flagEffect(insn("dec", "dword ptr [rcx]"))).toEqual({
      kind: "result",
      destText: "dword ptr [rcx]",
    });
  });

  // ── The clear-on-unknown default, one test per class ──

  it("CLEARS on an unrecognised mnemonic — the default that makes this model safe", () => {
    for (const mn of ["frobnicate", "vpcmpeqb", "xchg", "setne", "cmovne", "leave", "andn"]) {
      expect(flagEffect(insn(mn, "eax, ecx")), mn).toEqual({
        kind: "clobber",
        why: "unrecognised",
      });
    }
  });

  it("clears on imul/mul/div/idiv — Intel documents ZF and SF undefined", () => {
    for (const mn of UNDEFINED_RESULT_FLAGS) {
      expect(flagEffect(insn(mn, "ecx")), mn).toEqual({
        kind: "clobber",
        why: "undefined-result",
      });
    }
  });

  it("clears on the CF/OF-only writers, which leave ZF and SF to something older", () => {
    expect(PARTIAL_FLAG_WRITERS.has("rol")).toBe(true);
    expect(PARTIAL_FLAG_WRITERS.has("bt")).toBe(true);
    for (const mn of PARTIAL_FLAG_WRITERS) {
      expect(flagEffect(insn(mn, "eax, 1")), mn).toEqual({ kind: "clobber", why: "partial-write" });
    }
  });

  it("clears on adc/sbb/xadd, whose result the lifter does not name", () => {
    for (const mn of CARRY_IN_WRITERS) {
      expect(flagEffect(insn(mn, "eax, ecx")), mn).toEqual({ kind: "clobber", why: "carry-in" });
    }
  });

  it("clears on a lock-prefixed read-modify-write", () => {
    expect(flagEffect(insn("lock dec", "dword ptr [rcx]"))).toEqual({
      kind: "clobber",
      why: "locked",
    });
    expect(flagEffect(insn("lock cmpxchg", "[rcx], edx"))).toEqual({
      kind: "clobber",
      why: "locked",
    });
  });

  it("clears on string operations, prefixed or not", () => {
    for (const mn of ["movsb", "stosd", "lodsb", "scasb", "cmpsb", "rep movsb", "repne scasb"]) {
      expect(flagEffect(insn(mn)), mn).toEqual({ kind: "clobber", why: "string-op" });
    }
  });

  it("clears on a call — a callee's flags are unknown", () => {
    expect(flagEffect(insn("call", "0x401500"))).toEqual({ kind: "clobber", why: "call" });
    expect(flagEffect(insn("call", "qword ptr [rip + 0x1234]"))).toEqual({
      kind: "clobber",
      why: "call",
    });
  });

  // ── Shifts: the count decides whether anything was written at all ──

  it("claims a shift with a non-zero immediate count", () => {
    expect(flagEffect(insn("shl", "eax, 1"))).toEqual({ kind: "result", destText: "eax" });
    expect(flagEffect(insn("sar", "eax, 0x1f"))).toEqual({ kind: "result", destText: "eax" });
  });

  it("NEVER claims a shift with a register count — cl may be 0, which writes no flag", () => {
    expect(flagEffect(insn("shl", "eax, cl"))).toEqual({ kind: "clobber", why: "variable-count" });
    expect(flagEffect(insn("shr", "rax, cl"))).toEqual({ kind: "clobber", why: "variable-count" });
  });

  it("does not claim a shift by a literal zero", () => {
    expect(flagEffect(insn("shl", "eax, 0"))).toEqual({ kind: "clobber", why: "variable-count" });
    expect(flagEffect(insn("shl", "eax, 0x0"))).toEqual({ kind: "clobber", why: "variable-count" });
  });

  it("does not claim a shift whose count masks to zero at the destination's width", () => {
    // x86 masks the count to 5 bits (6 with REX.W), so `shl eax, 0x20` shifts
    // by 0 and leaves the flags alone, while `shl rax, 0x20` really shifts.
    expect(flagEffect(insn("shl", "eax, 0x20"))).toEqual({
      kind: "clobber",
      why: "variable-count",
    });
    expect(flagEffect(insn("shl", "rax, 0x20"))).toEqual({ kind: "result", destText: "rax" });
  });

  it("is case-insensitive about the mnemonic", () => {
    expect(flagEffect(insn("CMP", "eax, 5"))).toEqual({ kind: "compare", mnemonic: "cmp" });
    expect(flagEffect(insn("DEC", "ECX"))).toEqual({ kind: "result", destText: "ecx" });
  });
});

describe("isFlagReadingJump", () => {
  it("accepts the conditional jumps", () => {
    for (const mn of ["je", "jne", "js", "jns", "jg", "jbe", "jo", "jc"]) {
      expect(isFlagReadingJump(mn), mn).toBe(true);
    }
  });

  it("rejects jmp and the register-counting jumps, which read no flag", () => {
    for (const mn of ["jmp", "jecxz", "jrcxz", "jcxz"]) {
      expect(isFlagReadingJump(mn), mn).toBe(false);
    }
  });
});

describe("blockFlagOwner", () => {
  it("declines a block that does not end in a flag-reading jump", () => {
    expect(blockFlagOwner(block())).toBeNull();
    expect(blockFlagOwner(block("cmp eax, 5", "jmp 0x401800"))).toBeNull();
    expect(blockFlagOwner(block("dec ecx", "jecxz 0x401800"))).toBeNull();
    expect(blockFlagOwner(block("mov eax, 1", "ret"))).toBeNull();
  });

  it("reports the trailing jump alongside the owner", () => {
    const answer = blockFlagOwner(block("cmp eax, 5", "jne 0x401800"));
    expect(answer?.jcc).toBe("jne");
    expect(answer?.owner.kind).toBe("compare");
  });

  it("answers nothing-known for a block whose flags nothing in it set", () => {
    const o = owner("mov eax, 1", "je 0x401800");
    expect(o).toEqual({ kind: "none", reason: "no-owner" });
  });

  it("attributes to a cmp", () => {
    const o = owner("cmp eax, 5", "je 0x401800");
    expect(o.kind).toBe("compare");
    if (o.kind !== "compare") return;
    expect(o.mnemonic).toBe("cmp");
    expect(o.address).toBe(BASE);
    expect(o.defines).toBe("all");
    expect(o.spoiled).toBe(false);
  });

  it("attributes to an arithmetic result and names its destination", () => {
    const o = owner("mov ecx, edx", "dec ecx", "jne 0x401800");
    expect(o.kind).toBe("result");
    if (o.kind !== "result") return;
    expect(o.mnemonic).toBe("dec");
    expect(o.address).toBe(BASE + 4);
    expect(o.destText).toBe("ecx");
    expect(o.destReg).toBe("rcx");
    expect(o.defines).toBe("zf-sf");
    expect(canSpellCondition(o)).toBe(true);
  });

  it("keeps the owner across a flag-transparent instruction", () => {
    const o = owner("dec ecx", "mov edx, eax", "jne 0x401800");
    expect(o.kind).toBe("result");
    expect(o.kind === "result" && o.address).toBe(BASE);
  });

  // ── The behaviour that distinguishes this from the backward walk ──

  it("attributes to the LATER flag-writer when a cmp precedes one (peek-a-bin-jitf)", () => {
    // `cmp eax, 5 / sub ecx, edx / jne` branches on `ecx - edx != 0`. Reading
    // the condition off the cmp gives the right operator over wrong operands.
    const o = owner("cmp eax, 5", "sub ecx, edx", "jne 0x401800");
    expect(o.kind).toBe("result");
    if (o.kind !== "result") return;
    expect(o.mnemonic).toBe("sub");
    expect(o.destText).toBe("ecx");
  });

  it("attributes to the later of two results", () => {
    const o = owner("dec ecx", "add eax, 1", "jne 0x401800");
    expect(o.kind === "result" && o.destText).toBe("eax");
  });

  it("attributes to a cmp that follows a result", () => {
    const o = owner("sub eax, ebx", "cmp ecx, 1", "je 0x401800");
    expect(o.kind).toBe("compare");
    expect(o.kind === "compare" && o.address).toBe(BASE + 4);
  });

  it("attributes to the last of several compares", () => {
    const o = owner("cmp eax, 5", "cmp ecx, 1", "je 0x401800");
    expect(o.kind === "compare" && o.address).toBe(BASE + 4);
  });

  // ── Clear-on-unknown, at block level ──

  it("CLEARS a standing owner when an unrecognised instruction intervenes", () => {
    const o = owner("dec ecx", "frobnicate eax", "jne 0x401800");
    expect(o.kind).toBe("none");
    expect(o.kind === "none" && o.reason).toBe("cleared");
    expect(o.kind === "none" && o.clearedBy?.mnemonic).toBe("frobnicate");
  });

  it("clears a standing compare when a call intervenes", () => {
    const o = owner("cmp eax, 5", "call 0x401500", "jne 0x401800");
    expect(o).toMatchObject({ kind: "none", reason: "cleared" });
  });

  it("clears rather than falling back to an older owner after a partial write", () => {
    // ZF and SF really do survive a `rol`, so the *machine's* answer here is
    // the cmp — but ownership in this model is whole-flags, and answering
    // "cmp" would be wrong for a `jc` reading rol's own CF. Clearing costs a
    // recovery; per-flag ownership is what it would take to do better.
    const o = owner("cmp eax, 5", "rol edx, 1", "je 0x401800");
    expect(o).toMatchObject({ kind: "none", reason: "cleared" });
  });

  it("clears after a shift by a register count", () => {
    const o = owner("cmp eax, 5", "shl edx, cl", "je 0x401800");
    expect(o).toMatchObject({ kind: "none", reason: "cleared" });
  });

  // ── Spoiling: the flags are still that instruction's, but the name is not ──

  it("marks a result spoiled when a later instruction overwrites its destination", () => {
    // `dec ecx / mov ecx, edx / jne` leaves ECX holding EDX where the guard
    // would read it, so naming ECX states a different test entirely.
    const o = owner("dec ecx", "mov ecx, edx", "jne 0x401800");
    expect(o.kind).toBe("result");
    expect(o.kind === "result" && o.spoiled).toBe(true);
    expect(canSpellCondition(o)).toBe(false);
  });

  it("sees a sub-register overwrite of the same canonical register", () => {
    const o = owner("dec rcx", "mov cl, 3", "jne 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(true);
  });

  it("does not treat push as an overwrite — it only reads its operand", () => {
    const o = owner("dec ecx", "push ecx", "jne 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(false);
  });

  it("spoils on an implicit register writer, whose destination the text omits", () => {
    // Conservative and deliberately so: `cdq` writes EDX, not EAX, but the
    // destination is in the mnemonic rather than the operands and this model
    // does not carry a second table of implicit destinations.
    expect(IMPLICIT_REG_WRITERS.has("cdq")).toBe(true);
    const o = owner("dec eax", "cdq", "jne 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(true);
  });

  it("owns the flags of a memory-destination result but cannot name it", () => {
    const o = owner("dec dword ptr [rcx]", "jne 0x401800");
    expect(o.kind).toBe("result");
    if (o.kind !== "result") return;
    expect(o.destReg).toBeNull();
    expect(canSpellCondition(o)).toBe(false);
  });

  it("marks a compare spoiled when a later instruction overwrites an operand", () => {
    // The same argument `flagResult.ts` makes for a result's destination, made
    // for a compare's operands: the block's statements are emitted before the
    // `if`, so `eax = edx; if (eax != 5)` reads the new value.
    const o = owner("cmp eax, 5", "mov eax, edx", "je 0x401800");
    expect(o.kind).toBe("compare");
    expect(o.kind === "compare" && o.spoiled).toBe(true);
    expect(canSpellCondition(o)).toBe(false);
  });

  it("marks a compare over memory spoiled by a store", () => {
    const o = owner("cmp byte ptr [rcx], 0x30", "mov dword ptr [rdx], eax", "je 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(true);
  });

  it("does not spoil a compare on an unrelated register", () => {
    const o = owner("cmp eax, 5", "mov edx, 1", "je 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(false);
  });

  it("sees the base register of a memory operand", () => {
    const o = owner("cmp byte ptr [rcx], 0x30", "mov rcx, rdx", "je 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(true);
  });
});

describe("flagOwnerBefore", () => {
  it("answers for an arbitrary program point, not just a trailing jump", () => {
    const insns = block("cmp eax, 5", "dec ecx", "jne 0x401800").insns;
    expect(flagOwnerBefore(insns, 1).kind).toBe("compare");
    expect(flagOwnerBefore(insns, 2).kind).toBe("result");
  });

  it("answers nothing-known at the top of a block", () => {
    const insns = block("cmp eax, 5", "je 0x401800").insns;
    expect(flagOwnerBefore(insns, 0)).toEqual({ kind: "none", reason: "no-owner" });
  });

  it("does not read past the end of the instruction list", () => {
    const insns = block("cmp eax, 5").insns;
    expect(flagOwnerBefore(insns, 99).kind).toBe("compare");
    expect(flagOwnerBefore([], 3)).toEqual({ kind: "none", reason: "no-owner" });
  });
});

/**
 * The backward walk in `flagResult.ts` and this forward model answer different
 * questions — it declines any block containing a `cmp`/`test` and any Jcc
 * outside its ZF/SF set, both of which are gates on the *caller's* behalf
 * rather than facts about the flags. So the agreement that must hold is
 * one-directional: wherever it commits to an answer, this model must commit to
 * the same one. Any block where it answers and this model does not, or answers
 * differently, is a defect in one of the two.
 */
describe("agreement with the backward walk in flagResult.ts", () => {
  const cases: [string, string[]][] = [
    ["plain dec", ["dec ecx", "jne 0x401800"]],
    ["sub then je", ["sub eax, ebx", "je 0x401800"]],
    ["and then jz", ["and eax, 3", "jz 0x401800"]],
    ["or self then jne", ["or rax, rax", "jne 0x401800"]],
    ["neg then js", ["neg eax", "js 0x401800"]],
    ["shift by immediate", ["shl eax, 1", "jne 0x401800"]],
    ["transparent after", ["dec ecx", "mov edx, eax", "jnz 0x401800"]],
    ["transparent before", ["mov ecx, edx", "dec ecx", "jne 0x401800"]],
    ["lea between", ["dec ecx", "lea eax, [ebx + 4]", "jne 0x401800"]],
    ["result overwritten", ["dec ecx", "mov ecx, edx", "jne 0x401800"]],
    ["memory destination", ["dec dword ptr [rcx]", "jne 0x401800"]],
    ["shift by register", ["shl eax, cl", "jne 0x401800"]],
    ["call between", ["dec ecx", "call 0x401500", "jne 0x401800"]],
    ["unrecognised between", ["dec ecx", "xchg eax, edx", "jne 0x401800"]],
    ["implicit writer after", ["dec eax", "cdq", "jne 0x401800"]],
    ["nothing sets flags", ["mov eax, 1", "je 0x401800"]],
    ["adc", ["adc eax, ecx", "je 0x401800"]],
    ["imul", ["imul eax, ecx", "je 0x401800"]],
    ["rol", ["rol eax, 1", "je 0x401800"]],
  ];

  it("commits to the same instruction wherever the backward walk commits", () => {
    let agreed = 0;
    for (const [name, code] of cases) {
      const b = block(...code);
      const backward = flagResultSetter(b);
      if (!backward) continue;
      agreed++;
      const o = blockFlagOwner(b)?.owner;
      expect(o?.kind, name).toBe("result");
      if (o?.kind !== "result") continue;
      expect(o.address, name).toBe(backward.address);
      expect(o.mnemonic, name).toBe(backward.mnemonic);
      expect(o.destText, name).toBe(backward.destText);
      expect(o.destReg, name).toBe(backward.destReg);
      expect(o.spoiled, name).toBe(false);
      expect(canSpellCondition(o), name).toBe(true);
    }
    // Guards the guard: a table that stopped exercising the backward walk at
    // all would otherwise pass this vacuously.
    expect(agreed).toBeGreaterThanOrEqual(8);
  });

  it("declines wherever the backward walk declines for a reason about the flags", () => {
    const declines: [string, string[]][] = [
      ["call between", ["dec ecx", "call 0x401500", "jne 0x401800"]],
      ["unrecognised between", ["dec ecx", "xchg eax, edx", "jne 0x401800"]],
      ["shift by register", ["shl eax, cl", "jne 0x401800"]],
      ["adc", ["adc eax, ecx", "je 0x401800"]],
      ["imul", ["imul eax, ecx", "je 0x401800"]],
      ["rol", ["rol eax, 1", "je 0x401800"]],
      ["nothing sets flags", ["mov eax, 1", "je 0x401800"]],
    ];
    for (const [name, code] of declines) {
      const b = block(...code);
      expect(flagResultSetter(b), name).toBeNull();
      const o = blockFlagOwner(b)?.owner;
      expect(o && canSpellCondition(o), name).toBeFalsy();
    }
  });

  it("declines to *name* what the backward walk declines to name", () => {
    // Both models own these flags; neither can spell a condition from them.
    for (const [name, code] of [
      ["result overwritten", ["dec ecx", "mov ecx, edx", "jne 0x401800"]],
      ["memory destination", ["dec dword ptr [rcx]", "jne 0x401800"]],
      ["implicit writer after", ["dec eax", "cdq", "jne 0x401800"]],
    ] as [string, string[]][]) {
      const b = block(...code);
      expect(flagResultSetter(b), name).toBeNull();
      const o = blockFlagOwner(b)?.owner;
      expect(o?.kind, name).toBe("result");
      expect(o && canSpellCondition(o), name).toBe(false);
    }
  });

  /**
   * The enumerated cases above are the shapes that were reasoned about; this is
   * the one that goes looking. Every block of one or two instructions drawn
   * from an alphabet spanning each effect class, under four Jccs, checked
   * against the same one-directional property. It is what would catch a
   * disagreement nobody thought to write down.
   *
   * It cannot catch a *missing clear*, and that is worth knowing: the backward
   * walk declines on precisely the instructions this model must clear on, so
   * those blocks never enter the comparison. The per-class tests above carry
   * that load alone.
   */
  it("commits to the same instruction on every block over an instruction alphabet", () => {
    const alphabet = [
      "mov ecx, edx",
      "mov eax, 1",
      "mov dword ptr [rdx], eax",
      "push ecx",
      "pop eax",
      "lea eax, [ebx + 4]",
      "cdq",
      "nop",
      "not eax",
      "dec ecx",
      "add eax, 1",
      "sub ecx, edx",
      "shl eax, 1",
      // `shl eax, 0x20` is deliberately absent: the two models genuinely
      // disagree there, and that divergence has its own test below.
      "shl eax, cl",
      "cmp eax, 5",
      "test eax, eax",
      "call 0x401500",
      "xchg eax, edx",
      "imul eax, ecx",
      "rol eax, 1",
      "adc eax, ecx",
      "dec dword ptr [rcx]",
      "movsb",
    ];
    const jccs = ["je", "jne", "js", "jns"];

    let committed = 0;
    const disagreements: string[] = [];
    for (const jcc of jccs) {
      for (const a of alphabet) {
        for (const rest of [[], ...alphabet.map((b) => [b])]) {
          const code = [a, ...rest, `${jcc} 0x401800`];
          const b = block(...code);
          const backward = flagResultSetter(b);
          if (!backward) continue;
          committed++;
          const o = blockFlagOwner(b)?.owner;
          const agrees =
            o?.kind === "result" &&
            o.address === backward.address &&
            o.mnemonic === backward.mnemonic &&
            o.destText === backward.destText &&
            o.destReg === backward.destReg &&
            !o.spoiled;
          if (!agrees) disagreements.push(`${code.join(" ; ")} -> ${o?.kind}`);
        }
      }
    }

    expect(disagreements).toEqual([]);
    expect(committed).toBeGreaterThan(100);
  });

  it("diverges on a shift count that masks to zero, and is the correct one", () => {
    // `shl eax, 0x20` shifts a 32-bit destination by 0x20 & 0x1f == 0, so it
    // writes no flag and the Jcc is reading an older test. The backward walk
    // asks only whether the count is a non-zero immediate and attributes the
    // condition to the shift. This is a defect in `flagResult.ts` rather than a
    // difference of policy — see the report on this task.
    const masked = block("cmp eax, 5", "shl eax, 0x20", "jne 0x401800");
    const wide = block("shl rax, 0x20", "jne 0x401800");

    expect(flagResultSetter(block("shl eax, 0x20", "jne 0x401800"))).not.toBeNull();
    expect(blockFlagOwner(masked)?.owner).toMatchObject({ kind: "none", reason: "cleared" });
    // The 64-bit form really does shift, and both models claim it.
    expect(flagResultSetter(wide)).not.toBeNull();
    expect(blockFlagOwner(wide)?.owner).toMatchObject({ kind: "result", mnemonic: "shl" });
  });

  /**
   * The deliberate divergences, enumerated rather than tuned away. Each is a
   * block the backward walk declines and this model answers, and in every one
   * the reason it declines is a gate on a caller's behalf.
   */
  it("answers three shapes the backward walk declines by construction", () => {
    // 1. A `cmp` in the block. `flagResultSetter` returns null on sight of one
    //    so that the two recovery paths stay disjoint; the forward model has
    //    no such split, and this is the peek-a-bin-jitf shape.
    const jitf = block("cmp eax, 5", "sub ecx, edx", "jne 0x401800");
    expect(flagResultSetter(jitf)).toBeNull();
    expect(blockFlagOwner(jitf)?.owner).toMatchObject({ kind: "result", mnemonic: "sub" });

    // 2. A Jcc outside ZF/SF. Which conditions a result can answer is a
    //    property of the *Jcc*, so it belongs to the caller, not here.
    const carry = block("sub eax, ebx", "jb 0x401800");
    expect(flagResultSetter(carry)).toBeNull();
    expect(blockFlagOwner(carry)?.owner).toMatchObject({ kind: "result", defines: "zf-sf" });

    // 3. An ordinary compare, which the backward walk exists to sidestep.
    const plain = block("cmp eax, 5", "je 0x401800");
    expect(flagResultSetter(plain)).toBeNull();
    expect(blockFlagOwner(plain)?.owner).toMatchObject({ kind: "compare", mnemonic: "cmp" });
  });
});

/**
 * A drift guard of the kind CLAUDE.md documents — it scrapes `flagResult.ts`
 * rather than calling it, because the tables there are module-private and this
 * task may not add an `export`. Written so a reformat cannot break it: it
 * matches the declaration by name and pulls the quoted strings out of the
 * literal.
 */
describe("mnemonic tables agree with flagResult.ts", () => {
  const source = fs.readFileSync(
    path.join(process.cwd(), "src/disasm/decompile/flagResult.ts"),
    "utf8",
  );

  function setLiteral(name: string): Set<string> {
    const decl = new RegExp(`${name}\\s*=\\s*new Set\\(\\s*\\[([\\s\\S]*?)\\]`).exec(source);
    if (!decl) throw new Error(`${name} is no longer declared as a Set literal in flagResult.ts`);
    return new Set(Array.from(decl[1].matchAll(/"([^"]+)"/g), (m) => m[1]));
  }

  it("has the same flag-transparent set", () => {
    // Identical membership, deliberately. "Provably writes no flag" is
    // direction-free; only the consequence differs.
    expect([...NO_FLAG_WRITE].sort()).toEqual([...setLiteral("FLAG_TRANSPARENT")].sort());
  });

  it("has the same result-owner set", () => {
    expect([...RESULT_OWNERS].sort()).toEqual([...setLiteral("RESULT_FLAG_SETTERS")].sort());
  });

  it("has the same shift and implicit-writer sets", () => {
    expect([...SHIFTS].sort()).toEqual([...setLiteral("SHIFTS")].sort());
    expect([...IMPLICIT_REG_WRITERS].sort()).toEqual(
      [...setLiteral("IMPLICIT_REG_WRITERS")].sort(),
    );
  });

  it("keeps the two classifications disjoint", () => {
    for (const mn of RESULT_OWNERS) expect(NO_FLAG_WRITE.has(mn), mn).toBe(false);
    for (const mn of SHIFTS) expect(RESULT_OWNERS.has(mn), mn).toBe(true);
    for (const mn of IMPLICIT_REG_WRITERS) expect(NO_FLAG_WRITE.has(mn), mn).toBe(true);
    for (const set of [UNDEFINED_RESULT_FLAGS, PARTIAL_FLAG_WRITERS, CARRY_IN_WRITERS]) {
      for (const mn of set) {
        expect(RESULT_OWNERS.has(mn), mn).toBe(false);
        expect(NO_FLAG_WRITE.has(mn), mn).toBe(false);
      }
    }
  });
});
