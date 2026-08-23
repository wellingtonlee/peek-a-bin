/**
 * Negative controls for `corpus/frameRepurpose.ts`.
 *
 * The corpus run can demonstrate exactly one thing about this audit: that it
 * finds the two MSVC `longjmp` reloads (`repurposings` 1/0/0/1, asserted in
 * `corpus.audit.ts`). It cannot demonstrate that the gate FIRES, because
 * `after` is 0 on all four binaries — the class is latent, which is why
 * `peek-a-bin-633s` refused the repair — and it cannot demonstrate that three of
 * the classifier's four arms discriminate, because `push <imm>` / `pop <fp>`,
 * `popa`/`popad` and `enter` have 0 occurrences in this corpus. Asserting a gate
 * that has never been shown to fire is asserting nothing, so the controls are
 * here, against the audit's own functions.
 *
 * BOTH DIRECTIONS ARE ASKED OF EVERY RULE. A test that only checks the red
 * direction passes against an audit that has stopped looking, and this one is
 * unusually exposed to that: the whole hazard the audit is built around is a
 * classifier that either refuses everything (0 rows because every write reads as
 * a repurposing — no, that is the loud direction) or admits everything (0 rows
 * because every write reads as a restore, which is the silent one). So each
 * mnemonic is asked over a function that DOES have a frame-relative operand
 * after it, and the expected answer is stated for both classifications.
 *
 * It lives in `build/` for `corpusPreflight.test.ts`'s reason: `frameRepurpose.ts`
 * imports `callSummary.ts`, `ir.ts` and `stackIdiom.ts` and nothing that loads
 * Capstone, so it runs in the ordinary suite while the audit it belongs to
 * cannot.
 *
 * EVERY RULE WAS CONTROLLED BY DISABLING IT, and the count of failures is
 * recorded here so that a later reader can tell a targeted control from a
 * global one:
 *
 *   implicit restores (`leave`/`popa`/`popad` -> repurpose)   3 (one rule, three
 *                                                                parameters)
 *   `enter` moved into the restore set                        1
 *   `pushedImmediate` ignored (`pop` always a restore)        1
 *   the bare `[<fp>]` arm dropped from the grammar            1
 *   the grammar widened to indexed operands                   2 (one rule, two
 *                                                                parameters)
 *   the `frameDelta` gate removed                             1
 *   nearest-preceding attribution -> first                    1
 *   the helper-framed arm removed                             1
 *   the `establishedAt` window removed                       16
 *   the `writtenRegsOfInsn` `none` arm removed               17
 *
 * The last two are loud rather than targeted, and deliberately so: both are the
 * frame of the harness rather than a rule inside it — every fixture here has a
 * prologue and most have an instruction that writes no frame register — so
 * breaking either breaks nearly every case. There is still a case that names
 * each ("does not count the establishing instruction", and the `none` table
 * below), it simply does not fail alone.
 */
import { describe, expect, it } from "vitest";
import {
  auditFrameRepurpose,
  classifyFrameWrite,
  emptyFrameRepurpose,
} from "../corpus/frameRepurpose";
import type { Instruction } from "../src/disasm/types";

function insn(address: number, mnemonic: string, opStr: string): Instruction {
  return { address, mnemonic, opStr, bytes: new Uint8Array(), size: 2 } as Instruction;
}

/**
 * A canonical 32-bit prologue, then whatever `body` says, then one read of
 * argument 0. `establishedAt` is the `mov ebp, esp` at 0x1002, as `stack.ts`
 * would report it.
 */
function run(body: Instruction[], is64 = false, establishedAt: number | null = 0x1002) {
  const fp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";
  const out = emptyFrameRepurpose();
  const insns = [
    insn(0x1000, "push", fp),
    insn(0x1002, "mov", `${fp}, ${sp}`),
    ...body,
    insn(0x2000, "mov", `eax, dword ptr [${fp} + 8]`),
    insn(0x2010, "ret", ""),
  ];
  auditFrameRepurpose(out, "bin", "f", insns, is64 ? 8 : 4, establishedAt, is64);
  return out;
}

const kind = (insns: Instruction[], index: number, fpCanon = "rbp") =>
  classifyFrameWrite(insns, index, fpCanon);

describe("frameRepurpose: which writes of the frame register are epilogue restores", () => {
  /**
   * THE TRAP, and the reason the row classifies rather than merely finds. A
   * `pop ebp` and a `leave` are writes of the frame register, and MSVC lays a
   * mid-function epilogue BEFORE code that executes later — so reading either
   * as a repurposing puts 264/81/79/264 operands over 168/18/16/167 functions
   * into a gate that is supposed to read 0 (measured as a control at cc70fe6,
   * `npm run corpus` exit 1).
   */
  it.each([
    ["pop", "ebp"],
    ["leave", ""],
    ["popad", ""],
    ["popa", ""],
  ])("reads %s %s as an epilogue restore", (mn, ops) => {
    expect(kind([insn(0x1100, mn, ops)], 0)).toBe("restore");
    const out = run([insn(0x1100, mn, ops)]);
    expect(out.restores).toBe(1);
    expect(out.repurposings).toBe(0);
    expect(out.after).toBe(0);
    // …and the operand is still SEEN, or the zero above would be the scan
    // failing to match rather than the classifier working.
    expect(out.operands).toBe(1);
  });

  /**
   * `enter` is the one implicit form that is NOT a restore: it establishes a
   * SECOND frame, which is not the frame `stack.ts` measured, so `[ebp + 8]`
   * below it means something else. 0 occurrences in the corpus.
   */
  it("reads enter as a repurposing, not a restore", () => {
    expect(kind([insn(0x1100, "enter", "0x10, 0")], 0)).toBe("repurpose");
    const out = run([insn(0x1100, "enter", "0x10, 0")]);
    expect(out.repurposings).toBe(1);
    expect(out.after).toBe(1);
  });

  /**
   * MSVC's `push <imm>` / `pop <reg>` size idiom is `mov <reg>, <imm>` wearing a
   * stack instruction's clothes, so such a `pop` restores nothing. The pairing
   * is `stackIdiom.ts`'s `pushedImmediate`, shared with `lifter.ts` and
   * `functionDetect.ts` so the three cannot disagree about what the idiom is.
   * 0 occurrences in this corpus: a bound on the rule, pinned here or nowhere.
   */
  it("reads push <imm> / pop <fp> as a repurposing", () => {
    const body = [insn(0x1100, "push", "0x10"), insn(0x1102, "pop", "ebp")];
    expect(kind(body, 1)).toBe("repurpose");
    const out = run(body);
    expect(out.repurposings).toBe(1);
    expect(out.restores).toBe(0);
    expect(out.after).toBe(1);
  });

  /** …and the same `pop` after a register push is the ordinary restore again. */
  it("reads push <reg> / pop <fp> as a restore", () => {
    const body = [insn(0x1100, "push", "esi"), insn(0x1102, "pop", "ebp")];
    expect(kind(body, 1)).toBe("restore");
    expect(run(body).repurposings).toBe(0);
  });

  /**
   * THE WITNESS, in the shape `t32!sub_40A810` 0x40a851 has it: MSVC `longjmp`
   * reloading the caller's EBP out of a `jmp_buf`.
   */
  it("reads a load into the frame register as a repurposing", () => {
    const body = [insn(0x1100, "mov", "ebp, dword ptr [eax + 0x10]")];
    expect(kind(body, 0)).toBe("repurpose");
    const out = run(body);
    expect(out.repurposings).toBe(1);
    expect(out.after).toBe(1);
    expect(out.rows[0].addr).toBe(0x2000);
    expect(out.rows[0].repurposedAt).toBe(0x1100);
  });

  it.each([
    ["mov", "ebp, esp"],
    ["lea", "ebp, [esp + 4]"],
    ["xor", "ebp, ebp"],
    ["add", "ebp, 8"],
    ["xchg", "ebp, eax"],
    ["mov", "bpl, 1"],
  ])("reads %s %s as a repurposing", (mn, ops) => {
    expect(kind([insn(0x1100, mn, ops)], 0)).toBe("repurpose");
    expect(run([insn(0x1100, mn, ops)]).after).toBe(1);
  });

  /**
   * `xchg` writes BOTH operands, so the frame register in the SOURCE position is
   * still a write. `writtenRegsOfInsn` is what gets this right, which is why the
   * write model is imported rather than re-spelled.
   */
  it("reads xchg eax, ebp as a repurposing", () => {
    expect(kind([insn(0x1100, "xchg", "eax, ebp")], 0)).toBe("repurpose");
  });

  it.each([
    ["mov", "eax, dword ptr [ebp + 8]"],
    ["push", "ebp"],
    ["cmp", "ebp, eax"],
    ["mov", "dword ptr [ebp - 4], ebp"],
    ["call", "0x401000"],
  ])("does not read %s %s as a write of the frame register", (mn, ops) => {
    expect(kind([insn(0x1100, mn, ops)], 0)).toBe("none");
    const out = run([insn(0x1100, mn, ops)]);
    expect(out.writes).toBe(0);
    expect(out.after).toBe(0);
  });
});

describe("frameRepurpose: the population and the window", () => {
  it("examines nothing when no frame displacement was recovered", () => {
    const out = emptyFrameRepurpose();
    auditFrameRepurpose(
      out,
      "bin",
      "f",
      [insn(0x1000, "mov", "ebp, ecx"), insn(0x1004, "mov", "eax, dword ptr [ebp + 8]")],
      null,
      null,
      false,
    );
    // The whole record, so an audit that started reporting an unframed function
    // fails here rather than moving a corpus number nobody re-reads.
    expect([out.framed, out.writes, out.operands, out.after]).toEqual([0, 0, 0, 0]);
  });

  /**
   * THE PROLOGUE'S OWN `mov ebp, esp` IS NOT A REPURPOSING OF ITSELF. The window
   * opens strictly after `establishedAt`, and without that every canonically
   * framed function in the corpus is a row.
   */
  it("does not count the establishing instruction", () => {
    const out = run([]);
    expect(out.framed).toBe(1);
    expect([out.writes, out.repurposings, out.after]).toEqual([0, 0, 0]);
  });

  /**
   * A HELPER-FRAMED FUNCTION IS SCANNED WHOLE. `__SEH_prolog4` establishes the
   * frame inside the helper, so `frameEstablishedAt` is null for all 31 t32 and
   * 29 w32 of them; scanning from the entry is sound because the caller's own
   * prologue is `push <imm>; push <imm>; call` and writes the frame register
   * nowhere. Without this arm those 60 functions are examined not at all.
   */
  it("scans a helper-framed function from its entry", () => {
    const out = emptyFrameRepurpose();
    auditFrameRepurpose(
      out,
      "bin",
      "f",
      [
        insn(0x1000, "push", "0x20"),
        insn(0x1002, "push", "0x411228"),
        insn(0x1007, "call", "0x404170"),
        insn(0x100c, "mov", "ebp, dword ptr [eax + 0x10]"),
        insn(0x1010, "mov", "eax, dword ptr [ebp + 8]"),
      ],
      4,
      null,
      false,
    );
    expect([out.framed, out.helperFramed, out.repurposings, out.after]).toEqual([1, 1, 1, 1]);
  });

  /**
   * ADDRESS ORDER, stated as a limitation rather than left implicit: an operand
   * laid out BEFORE the repurposing is not a row even though the machine may
   * reach it afterwards. Both corpus witnesses are of exactly this shape — one
   * `push dword ptr [ebp + 8]` before the reload and nothing after — so if this
   * ever changes, those two go red.
   */
  it("does not count an operand laid out before the repurposing", () => {
    const out = emptyFrameRepurpose();
    auditFrameRepurpose(
      out,
      "bin",
      "f",
      [
        insn(0x1000, "push", "ebp"),
        insn(0x1002, "mov", "ebp, esp"),
        insn(0x1004, "push", "dword ptr [ebp + 8]"),
        insn(0x1008, "mov", "ebp, dword ptr [eax + 0x10]"),
        insn(0x100c, "ret", ""),
      ],
      4,
      0x1002,
      false,
    );
    expect([out.repurposings, out.operands, out.after]).toEqual([1, 1, 0]);
  });

  /** A row names the NEAREST preceding repurposing, not the function's first. */
  it("attributes an operand to the nearest preceding repurposing", () => {
    const out = run([
      insn(0x1100, "mov", "ebp, dword ptr [eax + 0x10]"),
      insn(0x1200, "mov", "ebp, dword ptr [ecx + 0x20]"),
    ]);
    expect(out.repurposings).toBe(2);
    expect(out.funcsRepurposed).toBe(1);
    expect(out.rows[0].repurposedAt).toBe(0x1200);
  });
});

describe("frameRepurpose: the operand grammar", () => {
  /**
   * The three shapes `promote.ts`'s `matchStackAccess` resolves to a slot name.
   * Capstone prints a displacement `0x`-prefixed from 0xA up and bare below, and
   * `stack.ts`'s own docstring records that matching `0x` alone silently dropped
   * every slot in the first ten bytes of the frame — which on x86 is argument 0.
   */
  it.each([
    "mov eax, dword ptr [ebp + 8]",
    "mov eax, dword ptr [ebp + 0x10]",
    "mov eax, dword ptr [ebp - 4]",
    "mov eax, dword ptr [ebp - 0x2c]",
    "mov eax, dword ptr [ebp]",
    "mov dword ptr [ebp+8], eax",
  ])("counts %s as a frame-relative operand", (text) => {
    const [mn, ...rest] = text.split(" ");
    const out = emptyFrameRepurpose();
    auditFrameRepurpose(
      out,
      "bin",
      "f",
      [
        insn(0x1000, "push", "ebp"),
        insn(0x1002, "mov", "ebp, esp"),
        insn(0x1008, "mov", "ebp, dword ptr [eax + 0x10]"),
        insn(0x2000, mn, rest.join(" ")),
      ],
      4,
      0x1002,
      false,
    );
    expect([out.operands, out.after]).toEqual([1, 1]);
  });

  /**
   * An INDEXED operand is not one: `matchStackAccess` requires a constant on the
   * right of the `+` and refuses these too, so counting them would report a name
   * the emitter never produces.
   */
  it.each([
    "mov eax, dword ptr [ebp + eax]",
    "mov eax, dword ptr [ebp + eax*4 - 0x10]",
    "mov eax, dword ptr [esp + 8]",
    "mov eax, dword ptr [ebx + 8]",
  ])("does not count %s", (text) => {
    const [mn, ...rest] = text.split(" ");
    const out = run([insn(0x1100, "mov", "ebp, dword ptr [eax + 0x10]"), insn(0x1200, mn, rest.join(" "))]);
    // The `[ebp + 8]` the harness appends is the only operand expected.
    expect([out.operands, out.after]).toEqual([1, 1]);
  });

  /** On x64 the frame register is RBP, and EBP-shaped text must not match. */
  it("reads rbp and not ebp in a 64-bit image", () => {
    const out = emptyFrameRepurpose();
    auditFrameRepurpose(
      out,
      "bin",
      "f",
      [
        insn(0x1000, "push", "rbp"),
        insn(0x1002, "mov", "rbp, rsp"),
        insn(0x1008, "mov", "rbp, qword ptr [rax + 0x10]"),
        insn(0x2000, "mov", "eax, dword ptr [ebp + 8]"),
        insn(0x2008, "mov", "rax, qword ptr [rbp + 0x10]"),
      ],
      8,
      0x1002,
      true,
    );
    expect([out.operands, out.after]).toEqual([1, 1]);
    expect(out.rows[0].addr).toBe(0x2008);
  });
});
