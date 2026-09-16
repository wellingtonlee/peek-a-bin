/**
 * WHAT `stripFrameScaffolding` DID, AND WHICH READ REFUSED IT — the pass's own
 * account, taken off the `frameTap` `decompileFunction` offers and summed per
 * binary. `src/disasm/decompile/prologue.ts` is the pass.
 *
 * THIS IS THE INSTRUMENT, NOT THE GATE. The gate is `emitAudits.ts`'s
 * `stackPointerScaffolding.writeNoRead`, which reads the EMITTED TEXT and knows
 * nothing about this pass: a function whose C writes the stack pointer and
 * never reads it is one dead definition the pass failed to delete, and that row
 * gates at 0 from peek-a-bin-5b6q.1 on. What this file adds is the WHY on the
 * other side of the gate — `spReadsKept` splits the functions still mentioning
 * the register by the reason the pass kept them (the /GS cookie mix, an
 * unnamed slot, an `alloca`), so a rise in `mentioning` can be read as a rise
 * in refusals of one kind rather than as noise.
 *
 * LIVENESS: `framed > 0` per binary (the pass saw frames), `gs-xor > 0` on the
 * x64 pair (the /GS population is 15/13 functions at 6299113 and the xor's read
 * of RSP must survive, by CLAUDE.md's `/GS` entry). A pass that deleted the
 * cookie xor would read 0 there and go red before `staleGuards` could notice.
 */
import type { FrameStripReport, KeptReason, StripShape } from "../src/disasm/decompile/prologue";

export interface PrologueStripResult {
  /** Functions the pass ran over. */
  funcs: number;
  /** Of those, with a recovered frame-register displacement. Liveness. */
  framed: number;
  /** Candidate statements by shape, summed. */
  candidates: Record<StripShape, number>;
  /** Deleted statements by shape, summed. */
  deleted: Record<StripShape, number>;
  /** Functions in which at least one stack-pointer candidate was kept. */
  spRefused: number;
  /** Functions in which the frame establishment was kept. */
  fpRefused: number;
  /** Functions per surviving stack-pointer-read reason (a function may count under several). */
  spReadsKept: Record<KeptReason, number>;
  /** Functions per surviving frame-register-read reason. */
  fpReadsKept: Record<KeptReason, number>;
  /**
   * Functions whose x64 `UNWIND_INFO` and `stack.ts` prologue disagreed, so
   * the pass was refused outright — `pipeline.ts`'s `prologueAgrees`.
   */
  prologueDisagree: number;
  /** A sample of refused functions with their reasons, for the report. */
  rows: string[];
}

const zeroShapes = (): Record<StripShape, number> => ({
  "fp-establish": 0,
  "sp-alloc": 0,
  "sp-restore": 0,
  "sp-reload": 0,
  leave: 0,
  "cdecl-cleanup": 0,
});

const zeroReasons = (): Record<KeptReason, number> => ({
  "gs-xor": 0,
  "unnamed-slot": 0,
  alloca: 0,
  "sp-copy": 0,
  unlifted: 0,
  "fp-kept": 0,
  "sp-kept": 0,
  other: 0,
});

export const emptyPrologueStrip = (): PrologueStripResult => ({
  funcs: 0,
  framed: 0,
  candidates: zeroShapes(),
  deleted: zeroShapes(),
  spRefused: 0,
  fpRefused: 0,
  spReadsKept: zeroReasons(),
  fpReadsKept: zeroReasons(),
  prologueDisagree: 0,
  rows: [],
});

/** One function's report, summed in. */
export function recordFrameStrip(
  res: PrologueStripResult,
  funcName: string,
  r: FrameStripReport,
): void {
  res.funcs++;
  if (r.framed) res.framed++;
  for (const k of Object.keys(r.candidates) as StripShape[]) {
    res.candidates[k] += r.candidates[k];
    res.deleted[k] += r.deleted[k];
  }
  const spCands =
    r.candidates["sp-alloc"] +
    r.candidates["sp-restore"] +
    r.candidates["sp-reload"] +
    r.candidates["cdecl-cleanup"];
  const spDeleted =
    r.deleted["sp-alloc"] +
    r.deleted["sp-restore"] +
    r.deleted["sp-reload"] +
    r.deleted["cdecl-cleanup"];
  if (spCands > spDeleted) res.spRefused++;
  if (r.candidates["fp-establish"] > r.deleted["fp-establish"]) res.fpRefused++;
  for (const reason of r.spReadsKept) res.spReadsKept[reason]++;
  for (const reason of r.fpReadsKept) res.fpReadsKept[reason]++;
  if (
    (spCands > spDeleted || r.candidates["fp-establish"] > r.deleted["fp-establish"]) &&
    res.rows.length < 16
  ) {
    res.rows.push(
      `${funcName}: sp kept [${r.spReadsKept.join(",")}] fp kept [${r.fpReadsKept.join(",")}]`,
    );
  }
}

/** The by-shape record as `a/b/c/d/e`, for one report line. */
export const shapeLine = (m: Record<StripShape, number>): string =>
  `fp ${m["fp-establish"]}, alloc ${m["sp-alloc"]}, restore ${m["sp-restore"]}, reload ${m["sp-reload"]}, leave ${m.leave}, cdecl ${m["cdecl-cleanup"]}`;

export const reasonLine = (m: Record<KeptReason, number>): string =>
  `gs-xor ${m["gs-xor"]}, unnamed-slot ${m["unnamed-slot"]}, alloca ${m.alloca}, sp-copy ${m["sp-copy"]}, unlifted ${m.unlifted}, fp-kept ${m["fp-kept"]}, sp-kept ${m["sp-kept"]}, other ${m.other}`;
