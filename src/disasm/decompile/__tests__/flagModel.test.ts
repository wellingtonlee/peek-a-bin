import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { Instruction } from "../../types";
import {
  blockFlagOwner,
  CARRY_IN_WRITERS,
  canSpellCondition,
  clobberedAfter,
  flagEffect,
  flagOwnerBefore,
  IMPLICIT_REG_WRITERS,
  isFlagReadingJump,
  isFlagTransparent,
  NO_FLAG_WRITE,
  PARTIAL_FLAG_WRITERS,
  RESULT_OWNERS,
  SHIFTS,
  UNDEFINED_RESULT_FLAGS,
} from "../flagModel";

/**
 * These tests were written before anything called `flagModel.ts`, against the
 * API its eventual consumer would need. `lifter.ts` is that consumer now: it
 * asks `blockFlagOwner` which instruction a block's Jcc reads and builds the
 * `IRBranch` from the answer. The forward model is the half of peek-a-bin-c33
 * most likely to go wrong silently: a wrong owner produces a
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
    // The same argument made for a result's destination, made for a compare's
    // operands: the block's statements are emitted before the
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
 * The shapes the deleted backward walk in `flagResult.ts` used to answer, and
 * the ones it used to decline.
 *
 * These were an *agreement* suite: the backward walk committed to an
 * instruction and this model had to commit to the same one. It is gone — a
 * result-derived guard is an `IRBranch` built from this model now
 * (peek-a-bin-c33 stage 4) — so what is left is the half that was ever a claim
 * about x86 rather than about the two implementations matching. Every case
 * below is now the *only* statement of what the lifter will do with the block.
 */
describe("which instruction a result-derived guard is answered from", () => {
  const answers: [string, string[], string][] = [
    ["plain dec", ["dec ecx", "jne 0x401800"], "dec"],
    ["sub then je", ["sub eax, ebx", "je 0x401800"], "sub"],
    ["and then jz", ["and eax, 3", "jz 0x401800"], "and"],
    ["or self then jne", ["or rax, rax", "jne 0x401800"], "or"],
    ["neg then js", ["neg eax", "js 0x401800"], "neg"],
    ["shift by immediate", ["shl eax, 1", "jne 0x401800"], "shl"],
    ["transparent after", ["dec ecx", "mov edx, eax", "jnz 0x401800"], "dec"],
    ["transparent before", ["mov ecx, edx", "dec ecx", "jne 0x401800"], "dec"],
    ["lea between", ["dec ecx", "lea eax, [ebx + 4]", "jne 0x401800"], "dec"],
  ];

  it("names the arithmetic instruction and can spell its result", () => {
    for (const [name, code, mnemonic] of answers) {
      const o = blockFlagOwner(block(...code))?.owner;
      expect(o?.kind, name).toBe("result");
      if (o?.kind !== "result") continue;
      expect(o.mnemonic, name).toBe(mnemonic);
      expect(canSpellCondition(o), name).toBe(true);
    }
  });

  it("declines when something between the setter and the Jcc took the flags", () => {
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
      const o = blockFlagOwner(block(...code))?.owner;
      expect(o && canSpellCondition(o), name).toBeFalsy();
    }
  });

  it("owns the flags but declines to NAME the result", () => {
    // Ownership and nameability are different facts, and this is the pair that
    // separates them: each of these really does leave the flags to the
    // arithmetic, and in none of them does a register still hold its result.
    for (const [name, code] of [
      ["result overwritten", ["dec ecx", "mov ecx, edx", "jne 0x401800"]],
      ["memory destination", ["dec dword ptr [rcx]", "jne 0x401800"]],
      ["implicit writer after", ["dec eax", "cdq", "jne 0x401800"]],
    ] as [string, string[]][]) {
      const o = blockFlagOwner(block(...code))?.owner;
      expect(o?.kind, name).toBe("result");
      expect(o && canSpellCondition(o), name).toBe(false);
    }
  });

  it("clears on a shift count that masks to zero", () => {
    // `shl eax, 0x20` shifts a 32-bit destination by 0x20 & 0x1f == 0, so it
    // writes no flag and the Jcc is reading an older test. The deleted backward
    // walk asked only whether the count was a non-zero immediate and attributed
    // the condition to the shift; that was a defect, and removing it removed
    // the one place the two models disagreed.
    const masked = block("cmp eax, 5", "shl eax, 0x20", "jne 0x401800");
    expect(blockFlagOwner(masked)?.owner).toMatchObject({ kind: "none", reason: "cleared" });
    // The 64-bit form really does shift.
    const wide = block("shl rax, 0x20", "jne 0x401800");
    expect(blockFlagOwner(wide)?.owner).toMatchObject({ kind: "result", mnemonic: "shl" });
  });

  /**
   * Three shapes the backward walk declined by construction and this model
   * answers. Two of the three are consumed; the first is deliberately NOT, and
   * the refusal lives in `lifter.ts`'s `branchFor` rather than here, because it
   * is a decision about an audit rather than a fact about the flags.
   */
  it("answers three shapes the backward walk declined by construction", () => {
    // 1. A `cmp` in the block. The backward walk returned null on sight of one
    //    so the two recovery paths stayed disjoint. This is peek-a-bin-jitf's
    //    shape, and `corpus/staleGuards.ts` counts any condition emitted at
    //    such a jcc as the stale reading — so `branchFor` still declines it.
    const jitf = block("cmp eax, 5", "sub ecx, edx", "jne 0x401800");
    expect(blockFlagOwner(jitf)?.owner).toMatchObject({ kind: "result", mnemonic: "sub" });

    // 2. A Jcc outside ZF/SF. Which conditions a result can answer is a
    //    property of the *Jcc*, so it belongs to the caller — `getCondition`
    //    returns `unknown` and `branchFor` builds nothing.
    const carry = block("sub eax, ebx", "jb 0x401800");
    expect(blockFlagOwner(carry)?.owner).toMatchObject({ kind: "result", defines: "zf-sf" });

    // 3. An ordinary compare, which the backward walk existed to sidestep.
    const plain = block("cmp eax, 5", "je 0x401800");
    expect(blockFlagOwner(plain)?.owner).toMatchObject({ kind: "compare", mnemonic: "cmp" });
  });
});

/**
 * A drift guard of the kind CLAUDE.md documents, inverted.
 *
 * It used to scrape `flagResult.ts` and fail if that module's private copies of
 * these tables stopped matching this one's. There is no second copy any more —
 * `flagResult.ts` is gone and its two survivors live at the bottom of
 * `flagModel.ts` — so the thing to guard is that nobody starts a third. It
 * scans every module that could plausibly want one and fails on a `Set` literal
 * carrying a distinctive slice of either table's membership. Written so a
 * reformat cannot break it: it matches quoted strings inside a `new Set([...])`
 * and never the surrounding layout.
 */
describe("nothing re-declares the flag tables", () => {
  const roots = ["src/disasm/decompile", "corpus"];
  const files: string[] = [];
  for (const root of roots) {
    const dir = path.join(process.cwd(), root);
    for (const name of fs.readdirSync(dir)) {
      if (!name.endsWith(".ts") || name === "flagModel.ts") continue;
      files.push(path.join(dir, name));
    }
  }

  // Three members apiece, chosen because no unrelated table would carry them
  // together. `bswap` and `movsxd` do not co-occur outside a flag-transparency
  // list; `sal` and `neg` do not co-occur outside a result-setter list.
  const signatures: [string, string[]][] = [
    ["NO_FLAG_WRITE", ["movsxd", "bswap", "cqo"]],
    ["RESULT_OWNERS", ["sal", "neg", "sar"]],
  ];

  it("finds no second copy of NO_FLAG_WRITE or RESULT_OWNERS", () => {
    expect(files.length).toBeGreaterThan(10);
    const offenders: string[] = [];
    for (const file of files) {
      const text = fs.readFileSync(file, "utf8");
      for (const literal of text.matchAll(/new Set\(\s*\[([\s\S]*?)\]/g)) {
        const members = new Set(Array.from(literal[1].matchAll(/"([^"]+)"/g), (m) => m[1]));
        for (const [table, signature] of signatures) {
          if (signature.every((mn) => members.has(mn))) {
            offenders.push(`${path.basename(file)} re-declares ${table}`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("keeps the classifications disjoint", () => {
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

  it("still exports the two survivors of flagResult.ts", () => {
    expect(isFlagTransparent("mov")).toBe(true);
    expect(isFlagTransparent("dec")).toBe(false);
    const scan = clobberedAfter(block("dec ecx", "mov ecx, edx", "jne 0x401800"), 0x401000);
    expect(scan.regs.has("rcx")).toBe(true);
    expect(scan.opaque).toBe(false);
  });
});
