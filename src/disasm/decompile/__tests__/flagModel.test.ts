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
  flagPredecessor,
  flagScanStream,
  IMPLICIT_REG_WRITERS,
  isFlagReadingJump,
  isFlagTransparent,
  NO_FLAG_WRITE,
  PARTIAL_FLAG_WRITERS,
  parseBitTest,
  RESULT_OWNERS,
  SHIFTS,
  UNDEFINED_RESULT_FLAGS,
  withoutLockPrefix,
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
    // `bt` is still a member — it really does write CF alone — but CF alone is
    // the entire question a `jb`/`jae` after it asks, so `flagEffect` claims the
    // forms `parseBitTest` admits before it reaches the set. Every OTHER member
    // clears, `bts`/`btr`/`btc` included: their CF is the bit's value *before*
    // the write, so nothing readable afterwards names it (peek-a-bin-frt8).
    expect(PARTIAL_FLAG_WRITERS.has("bt")).toBe(true);
    for (const mn of PARTIAL_FLAG_WRITERS) {
      if (mn === "bt") continue;
      expect(flagEffect(insn(mn, "eax, 1")), mn).toEqual({ kind: "clobber", why: "partial-write" });
    }
  });

  it("claims CF for a bt with a register bit base and an immediate offset", () => {
    // The shape all 30 admissible corpus sites have: `bt r11d, 0xa / jb`.
    expect(flagEffect(insn("bt", "r11d, 0xa"))).toEqual({
      kind: "bittest",
      destText: "r11d",
      bitIndex: 10,
    });
    // Intel reduces the offset modulo the operand size for a register bit base,
    // and applying it here is what keeps the emitted shift within the width.
    expect(flagEffect(insn("bt", "eax, 0x21"))).toEqual({
      kind: "bittest",
      destText: "eax",
      bitIndex: 1,
    });
    expect(flagEffect(insn("bt", "rax, 0x41"))).toEqual({
      kind: "bittest",
      destText: "rax",
      bitIndex: 1,
    });
  });

  it("refuses the bt forms it cannot name soundly, and they stay partial-write", () => {
    // A MEMORY bit base is the unsound one, not merely the unmeasured one: the
    // offset addresses a bit string, so `bt DWORD PTR [esp], eax` can select a
    // bit outside the dword the operand names. This is the real corpus shape on
    // both PE32 binaries (t32 0x40B678, w32 0x40A3A8), which is why bucket 1
    // recovers nothing there.
    for (const ops of ["dword ptr [esp], eax", "dword ptr [esp], 3", "eax, ecx", "al, 3"]) {
      expect(flagEffect(insn("bt", ops)), ops).toEqual({
        kind: "clobber",
        why: "partial-write",
      });
      expect(parseBitTest(insn("bt", ops)), ops).toBeNull();
    }
  });

  it("owns the flags of a bt and can spell its condition", () => {
    const o = owner("bt eax, 3", "jb 0x401800");
    expect(o.kind).toBe("bittest");
    if (o.kind !== "bittest") return;
    expect(o.destReg).toBe("rax");
    expect(o.bitIndex).toBe(3);
    expect(o.defines).toBe("cf");
    expect(canSpellCondition(o)).toBe(true);
  });

  it("spoils a bt whose bit base a later instruction overwrote", () => {
    // `bt` writes nothing, so the bits tested are the ones the register held on
    // both sides of it — and either way, an overwrite before the Jcc means the
    // name no longer denotes them.
    const o = owner("bt eax, 3", "mov eax, edx", "jb 0x401800");
    expect(o.kind === "bittest" && o.spoiled).toBe(true);
    expect(canSpellCondition(o)).toBe(false);
  });

  it("clears on adc/sbb/xadd, whose result the lifter does not name", () => {
    for (const mn of CARRY_IN_WRITERS) {
      expect(flagEffect(insn(mn, "eax, ecx")), mn).toEqual({ kind: "clobber", why: "carry-in" });
    }
  });

  it("classifies a lock-prefixed form by its BASE mnemonic", () => {
    // Both of these asserted `{clobber, "locked"}` until peek-a-bin-3qrl, and
    // that was the suite pinning a blanket refusal as a fact about the machine.
    // The `lock` prefix makes the read-modify-write atomic and changes no flag
    // effect whatever, so `lock dec dword ptr [rcx]` sets ZF from what it wrote
    // exactly as `dec dword ptr [rcx]` does — an ordinary memory-destination
    // result owner, spellable since peek-a-bin-ie0j.
    expect(flagEffect(insn("lock dec", "dword ptr [rcx]"))).toEqual({
      kind: "result",
      destText: "dword ptr [rcx]",
    });
    expect(flagEffect(insn("lock inc", "dword ptr [rax]"))).toEqual({
      kind: "result",
      destText: "dword ptr [rax]",
    });
    expect(flagEffect(insn("lock add", "dword ptr [rcx], r9d"))).toEqual({
      kind: "result",
      destText: "dword ptr [rcx]",
    });
  });

  it("keeps refusing the locked forms their own mnemonic refuses, with the real reason", () => {
    // The other half of dropping the blanket: each of these is still a clobber,
    // and now says *why* rather than only that a prefix was present. Every one
    // is a form `liftBlock` has no handler for, so it stays on the `raw`
    // fallback and there is no value for a condition to name either.
    expect(flagEffect(insn("lock cmpxchg", "[rcx], edx"))).toEqual({
      kind: "clobber",
      why: "unrecognised",
    });
    expect(flagEffect(insn("lock xadd", "[rcx], edx"))).toEqual({
      kind: "clobber",
      why: "carry-in",
    });
    expect(flagEffect(insn("lock bts", "dword ptr [rcx], 0xf"))).toEqual({
      kind: "clobber",
      why: "partial-write",
    });
  });

  it("strips only a lock prefix, and only for the dispatch key", () => {
    // `withoutLockPrefix` is what `liftBlock` dispatches on. A `rep` prefix must
    // survive it: Capstone spells the string primitives sometimes into the
    // mnemonic and sometimes into `opStr`, and `liftBlock` has its own case for
    // both spellings, which stripping generally would route into plain `movsd`.
    expect(withoutLockPrefix("lock dec")).toBe("dec");
    expect(withoutLockPrefix("LOCK DEC")).toBe("dec");
    expect(withoutLockPrefix("rep movsd")).toBe("rep movsd");
    expect(withoutLockPrefix("dec")).toBe("dec");
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

  it("owns AND can name a memory-destination result", () => {
    // This asserted `canSpellCondition === false` until peek-a-bin-ie0j, and
    // that was the suite pinning a limit on the spelling as a rule about the
    // machine: `dec dword ptr [rcx]` lifts to a store, so the deref read after
    // it IS the decremented value. `destReg` is still null — it answers "which
    // register do I watch for an overwrite", and the answer is none — so
    // `destForm` is what spellability has to be asked of.
    const o = owner("dec dword ptr [rcx]", "jne 0x401800");
    expect(o.kind).toBe("result");
    if (o.kind !== "result") return;
    expect(o.destReg).toBeNull();
    expect(o.destForm).toBe("mem");
    expect(canSpellCondition(o)).toBe(true);
  });

  it("refuses a destination that is neither a register nor memory", () => {
    // The `"none"` arm of `destForm`, which is what keeps the relaxation from
    // being "anything that is not a register". No well-formed x86 result owner
    // reaches it — every `RESULT_OWNERS` destination is a register or a memory
    // operand — so it is pinned against a synthetic operand rather than left an
    // unexercised default a later edit could quietly widen.
    const o = owner("dec whatever", "jne 0x401800");
    expect(o.kind).toBe("result");
    if (o.kind !== "result") return;
    expect(o.destReg).toBeNull();
    expect(o.destForm).toBe("none");
    expect(canSpellCondition(o)).toBe(false);
  });

  it("spoils a memory result on any store, without proving the addresses alias", () => {
    const o = owner("dec dword ptr [ebp + 0x10]", "mov dword ptr [eax], ecx", "je 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(true);
    expect(canSpellCondition(o)).toBe(false);
  });

  it("spoils a memory result on a push, which writes memory its text does not name", () => {
    // `writesMemory` exempts `push` because it only READS its operand, which is
    // the right reading for a compare over memory. For a memory *result* the
    // question is whether anything wrote the bytes the guard will read, and
    // `push` writes `[rsp - N]`. Refusing makes the claim sound by construction
    // rather than by the observation that no corpus binary has the shape.
    const o = owner("dec dword ptr [ebp + 0x10]", "push eax", "je 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(true);
  });

  it("does not spoil a memory result on a register-only write", () => {
    // The real corpus shape: `dec DWORD PTR [ebp+0x10] / movzx eax, ax / je` at
    // t32.exe 0x402125. `movzx` cannot touch the slot, so the guard stands.
    const o = owner("dec dword ptr [ebp + 0x10]", "movzx eax, ax", "je 0x401800");
    expect(o.kind === "result" && o.spoiled).toBe(false);
    expect(canSpellCondition(o)).toBe(true);
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

/**
 * TWO QUESTIONS ABOUT THE SAME INSTRUCTION, and `push`/`pop` is where they come
 * apart. Membership in `NO_FLAG_WRITE` says the standing owner survives;
 * `spoils` says whether the value can still be named. A `pop` answers *yes* to
 * the first and *no* to the second whenever it writes a register the compare
 * named, and both answers have to hold at once or the model is wrong in one of
 * two opposite directions — a guard needlessly refused, or a guard that reads
 * the restored callee-saved value in place of the tested one.
 *
 * These are here because peek-a-bin-thsj proposed adding `push`/`pop` to
 * `NO_FLAG_WRITE` — where they have been since `b35a786` — on the reasoning
 * that a Jcc behind an epilogue restore is needlessly unrecovered. The
 * adjudication was that the model already answers both questions correctly and
 * that the refusal is right; nothing pinned that, so a later change could have
 * "fixed" it by exempting a `pop` from `spoils` and emitted a wrong test at 4
 * corpus sites with every gate green. See the `NO_FLAG_WRITE` and `spoils`
 * docstrings for the measured populations.
 */
describe("push and pop: flag-transparent AND a spoiler", () => {
  it("keeps the standing owner across an epilogue restore", () => {
    // t32 sub_40E1D8 0x40e275, verified against objdump -d -M intel. The three
    // pops write no flag, so the `test` is still what the `jne` reads.
    const o = owner("test edi, edi", "pop edi", "pop esi", "pop ebx", "jne 0x40e283");
    expect(o.kind).toBe("compare");
    expect(o.kind === "compare" && o.mnemonic).toBe("test");
  });

  it("…and still refuses it, because the pop overwrote the compared register", () => {
    const o = owner("test edi, edi", "pop edi", "pop esi", "pop ebx", "jne 0x40e283");
    expect(o.kind === "compare" && o.spoiled).toBe(true);
    expect(canSpellCondition(o)).toBe(false);
  });

  it("recovers the guard when the pops touch neither operand", () => {
    // The majority shape: 26 of 34 such compare owners on t32 and 20 of 27 on
    // w32 are recovered today, and they are recovered BECAUSE push and pop are
    // members of NO_FLAG_WRITE.
    const o = owner("test eax, eax", "pop edi", "pop esi", "pop ebx", "jne 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(false);
    expect(canSpellCondition(o)).toBe(true);
  });

  it("does not let a push spoil a register it only reads", () => {
    const o = owner("cmp edi, esi", "push edi", "jne 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(false);
  });

  it("spoils a compare over memory on a pop whose destination IS memory", () => {
    // `pop dword ptr [ebp - 0x210]` is the form the CRT uses after `pushfd`.
    const o = owner("cmp dword ptr [ebp - 4], 0", "pop dword ptr [ebp - 0x210]", "je 0x401800");
    expect(o.kind === "compare" && o.spoiled).toBe(true);
  });

  it("MATCHES BY EXACT MNEMONIC: popf restores every flag and is not transparent", () => {
    // Hazard 1. A prefix test would admit `popf` as a `pop` and let a Jcc read a
    // condition off a compare the restored flags superseded. `pushfd` is not
    // hypothetical — it occurs twice in each 32-bit corpus binary.
    for (const mn of ["pushf", "pushfd", "pushfq", "popf", "popfd", "popfq", "pusha", "popa"]) {
      expect(isFlagTransparent(mn), mn).toBe(false);
      expect(flagEffect(insn(mn, "")), mn).toEqual({ kind: "clobber", why: "unrecognised" });
    }
    expect(isFlagTransparent("push")).toBe(true);
    expect(isFlagTransparent("pop")).toBe(true);
  });

  it("clears a compare owner when a pushfd sits between it and the jump", () => {
    const o = owner("cmp eax, 5", "pushfd", "je 0x401800");
    expect(o.kind).toBe("none");
    expect(o.kind === "none" && o.reason).toBe("cleared");
    expect(o.kind === "none" && o.clearedBy?.mnemonic).toBe("pushfd");
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
    // Memory destinations. Spellable since peek-a-bin-ie0j, and the last two
    // are the shapes the corpus actually has: a `dec` on a stack slot and an
    // `add` of a negative immediate to a field.
    ["dec on memory", ["dec dword ptr [rcx]", "jne 0x401800"], "dec"],
    ["dec on a stack slot", ["dec dword ptr [ebp + 0x10]", "je 0x401800"], "dec"],
    ["add to a field", ["add dword ptr [esi + 4], 0xfffffffe", "js 0x401800"], "add"],
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
    // arithmetic, and in none of them does anything still hold its result.
    //
    // `["memory destination", ["dec dword ptr [rcx]", …]]` used to be a row
    // here. It was the wrong list for it: the flags are the `dec`'s AND the
    // deref names its result, so it is now in `answers` above (peek-a-bin-ie0j).
    // What replaces it is the case where a store really did take the value.
    for (const [name, code] of [
      ["result overwritten", ["dec ecx", "mov ecx, edx", "jne 0x401800"]],
      ["memory result stored over", ["dec dword ptr [rcx]", "mov [rdx], eax", "jne 0x401800"]],
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

/**
 * The cross-block reading (peek-a-bin-suql). A block whose own instructions
 * write no flag was entered with its predecessor's, and where exactly one block
 * can have set them the owner is knowable — which is the difference between a
 * real guard and `__unrecovered_N` for 69 guards across the four corpus
 * binaries.
 *
 * The load-bearing assertion in here is the terminator skip. `jmp`, `ret` and
 * every Jcc are absent from `NO_FLAG_WRITE` — deliberately, since the set is
 * narrow on purpose — so `flagEffect` classes them `{clobber, unrecognised}`,
 * and a walk that reads the predecessor's last instruction clears the very owner
 * it went there for. Measured over the corpus: without the skip the recovery is
 * **0 on all four binaries**, which is exactly the false negative the first
 * measurement pass produced.
 */
describe("flagScanStream — flags carried across one edge", () => {
  /** Two blocks, `pred` falling into `succ`, wired as each other's edge. */
  function pair(predCode: string[], succCode: string[]): [BasicBlock, BasicBlock] {
    const pred = block(...predCode);
    const succ = block(...succCode);
    succ.id = 1;
    succ.startAddr = pred.endAddr;
    succ.endAddr = succ.startAddr + succ.insns.length * 4;
    succ.insns.forEach((i, n) => {
      i.address = succ.startAddr + n * 4;
    });
    pred.succs = [1];
    succ.preds = [0];
    return [pred, succ];
  }

  it("reads the block alone when the block sets its own flags", () => {
    const [pred, succ] = pair(["cmp eax, 5", "jg 0x401800"], ["cmp ecx, 7", "je 0x401800"]);
    const scan = flagScanStream(succ, pred);
    expect(scan.fromPredecessor).toBe(false);
    expect(scan.insns.map((i) => i.mnemonic)).toEqual(["cmp"]);
  });

  it("reads the predecessor when the block writes no flag at all", () => {
    const [pred, succ] = pair(["cmp eax, 5", "jg 0x401800"], ["je 0x401800"]);
    const scan = flagScanStream(succ, pred);
    expect(scan.fromPredecessor).toBe(true);
    expect(scan.insns.map((i) => i.mnemonic)).toEqual(["cmp"]);
  });

  // THE test in this describe. The predecessor's `jg` must not be walked: it is
  // unrecognised, so it clobbers, and the owner this whole path exists to find
  // is gone. 0 recovered on all four corpus binaries without it.
  it("does not walk the predecessor's own terminator", () => {
    const [pred, succ] = pair(["cmp eax, 5", "jg 0x401800"], ["je 0x401800"]);
    expect(flagScanStream(succ, pred).insns.map((i) => i.mnemonic)).not.toContain("jg");
    expect(blockFlagOwner(succ, pred)?.owner).toMatchObject({ kind: "compare", mnemonic: "cmp" });
  });

  it("does not walk a predecessor ending in jmp either", () => {
    const [pred, succ] = pair(["test ecx, ecx", "jmp 0x401800"], ["jne 0x401800"]);
    expect(blockFlagOwner(succ, pred)?.owner).toMatchObject({ kind: "compare", mnemonic: "test" });
  });

  // The predecessor's tail still spoils, because the walk continues rather than
  // stopping at the block boundary — and so does the reading block's own tail.
  it("spoils a predecessor's compare its own tail overwrote", () => {
    const [pred, succ] = pair(["cmp eax, 5", "mov eax, edx", "jg 0x401800"], ["je 0x401800"]);
    const owner = blockFlagOwner(succ, pred)?.owner;
    expect(owner).toMatchObject({ kind: "compare", spoiled: true });
    expect(owner && canSpellCondition(owner)).toBe(false);
  });

  it("spoils a predecessor's compare the reading block overwrote", () => {
    const [pred, succ] = pair(["cmp eax, 5", "jg 0x401800"], ["mov eax, edx", "je 0x401800"]);
    const owner = blockFlagOwner(succ, pred)?.owner;
    expect(owner).toMatchObject({ kind: "compare", spoiled: true });
    expect(owner && canSpellCondition(owner)).toBe(false);
  });

  it("reports no owner when the predecessor cleared the flags", () => {
    const [pred, succ] = pair(["sub esi, eax", "sbb edi, edx", "js 0x401800"], ["jg 0x401800"]);
    expect(blockFlagOwner(succ, pred)?.owner).toMatchObject({ kind: "none", reason: "cleared" });
  });

  it("is the pre-existing answer with no predecessor given", () => {
    const [, succ] = pair(["cmp eax, 5", "jg 0x401800"], ["je 0x401800"]);
    expect(blockFlagOwner(succ)?.owner).toEqual({ kind: "none", reason: "no-owner" });
    expect(blockFlagOwner(succ)?.fromPredecessor).toBe(false);
  });
});

describe("flagPredecessor", () => {
  function bare(id: number, preds: number[]): BasicBlock {
    return { id, startAddr: 0, endAddr: 0, insns: [], succs: [], preds };
  }

  /**
   * `n` predecessors, each with its own instruction list, falling into one
   * successor whose code is `succCode`. Addresses are laid out so no two blocks
   * share one, which matters: `flagPredecessor` compares operand TEXT, and a
   * rule that accidentally compared addresses would pass every test here.
   */
  function join(
    succCode: string[],
    ...predCode: string[][]
  ): [BasicBlock, Map<number, BasicBlock>] {
    const blocks: BasicBlock[] = [];
    let at = BASE;
    predCode.forEach((code, n) => {
      const b = block(...code);
      b.id = n;
      b.startAddr = at;
      b.insns.forEach((i, k) => {
        i.address = at + k * 4;
      });
      b.endAddr = at + b.insns.length * 4;
      at = b.endAddr;
      b.succs = [predCode.length];
      blocks.push(b);
    });
    const succ = block(...succCode);
    succ.id = predCode.length;
    succ.startAddr = at;
    succ.insns.forEach((i, k) => {
      i.address = at + k * 4;
    });
    succ.endAddr = at + succ.insns.length * 4;
    succ.preds = predCode.map((_, n) => n);
    blocks.push(succ);
    return [succ, new Map(blocks.map((b) => [b.id, b]))];
  }

  it("answers with the only predecessor", () => {
    const a = bare(0, []);
    const b = bare(1, [0]);
    const map = new Map([a, b].map((x) => [x.id, x]));
    expect(flagPredecessor(b, map)).toBe(a);
    expect(flagPredecessor(a, map)).toBeUndefined();
  });

  it("declines a self-loop, which is the question rather than an answer to it", () => {
    const s = bare(0, [0]);
    expect(flagPredecessor(s, new Map([[0, s]]))).toBeUndefined();
  });

  it("declines a predecessor id no block answers to", () => {
    const b = bare(1, [99]);
    expect(flagPredecessor(b, new Map([[1, b]]))).toBeUndefined();
  });

  // A block that sets its own flags needs no predecessor, and answering with one
  // would be a claim about a stream `flagScanStream` will not read anyway.
  it("declines a block whose own instructions own the flags", () => {
    const [succ, map] = join(["cmp ecx, 7", "je 0x401800"], ["cmp eax, 5", "jg 0x401800"]);
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // The generalisation (peek-a-bin-xdxt). Both edges leave the flags set by the
  // SAME test, so the block is entered with those flags however it was reached
  // and one block-local condition states the machine. 2 corpus sites, both
  // MSVC's `_stricmp` tail: `cmp ah, al / jne` on one edge and
  // `xor ecx, ecx / cmp ah, al / je` on the other, joining at `mov ecx, -1 / jb`.
  it("answers when every predecessor sets the flags from the same test", () => {
    const [succ, map] = join(
      ["mov ecx, 0xffffffff", "jb 0x401800"],
      ["cmp ah, al", "jne 0x401800"],
      ["xor ecx, ecx", "cmp ah, al", "je 0x401800"],
    );
    const answer = flagPredecessor(succ, map);
    expect(answer).toBe(map.get(0));
    expect(blockFlagOwner(succ, answer)?.owner).toMatchObject({
      kind: "compare",
      mnemonic: "cmp",
      spoiled: false,
    });
  });

  // A phi of conditions, and the 12 of the corpus's 14 multi-predecessor blocks
  // that are one: `test rbx, rbx` against `test rbp, rbp` is not a test a single
  // block-local `if` can state, and naming either would be a guard the machine
  // does not always make.
  it("declines predecessors whose owners are different tests", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["test ebx, ebx", "jne 0x401800"],
      ["test ebp, ebp", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // Same operator, same left operand, different right one — the t32 0x404641
  // shape (`cmp byte ptr [ebp-0x44c], bl` against `cmp … , 0`). A phi over the
  // VALUE could state this; one condition cannot, so it is refused too.
  it("declines predecessors that compare the same place against different things", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["cmp byte ptr [ebp - 0x10], bl", "jne 0x401800"],
      ["cmp byte ptr [ebp - 0x10], 0", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // Unanimous text is not enough if one edge overwrote what names the value: the
  // walk runs over each edge's whole path, so `spoiled` states it and
  // `canSpellCondition` refuses. This is why `structure.ts` can ask
  // `conditionSpoiled` of the returned predecessor alone.
  it("declines when one predecessor's tail spoiled its own compare", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["cmp eax, 5", "jne 0x401800"],
      ["cmp eax, 5", "mov eax, edx", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // A result owner is refused rather than given a second equality rule: 0 corpus
  // occurrences, and its condition is a function of the destination as well as
  // of the operand text.
  it("declines a unanimous result owner", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["dec ecx", "jne 0x401800"],
      ["dec ecx", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // `parseOperand` resolves a rip-relative operand against the instruction's own
  // address, so identical text at two addresses is two different expressions.
  it("declines a unanimous rip-relative compare", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["cmp dword ptr [rip + 0x10], 0", "jne 0x401800"],
      ["cmp dword ptr [rip + 0x10], 0", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });

  // `spoils` and `clobberedAfter` read `push`/`pop` differently about the stack
  // pointer, and only the returned predecessor gets the second scan. Refusing a
  // stack-relative compare makes that irrelevant by construction.
  it("declines a unanimous compare spelled relative to the stack pointer", () => {
    const [succ, map] = join(
      ["je 0x401800"],
      ["cmp dword ptr [esp + 4], 0", "jne 0x401800"],
      ["cmp dword ptr [esp + 4], 0", "jmp 0x401800"],
    );
    expect(flagPredecessor(succ, map)).toBeUndefined();
  });
});
