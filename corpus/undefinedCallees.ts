/**
 * A CALL IN THE EMITTED C WHOSE CALLEE HAS NO DEFINITION ANYWHERE IN THE OUTPUT.
 *
 * `resolveCallTarget` spells a direct `call 0x4038f7` as the detected
 * function's name when one starts there and as the fallback `sub_4038F7`
 * otherwise. The fallback is honest about the transfer — the machine really does
 * call that address — but the identifier it mints is declared nowhere, so the
 * reader has a call they cannot follow. This counts them, and the whole point of
 * the audit is the SPLIT, because the two halves have nothing to do with each
 * other:
 *
 *   - **INTERNAL** — the target is inside the calling function's own extent.
 *     The callee's body IS in the output, in this same function, usually under a
 *     `loc_` label further down; the two halves are simply not connected. In
 *     this corpus every one of them is an MSVC x86 `__finally` funclet the
 *     detector folded into its parent (`peek-a-bin-qe8z`, `peek-a-bin-d827`):
 *     the parent's own `call` names the funclet body, the withdrawal took that
 *     body's start out of the function set, and the fallback name is what is
 *     left. **This is the class `peek-a-bin-pf5g` is about.**
 *
 *   - **EXTERNAL** — the target is outside it. Two shapes in this corpus, both
 *     detection's or the IAT's business rather than the emitter's: a tail `jmp`
 *     to a code address function detection never produced (lifted as a call, per
 *     `resolveNamedTarget`), and an indirect `call dword ptr ds:0x414738`
 *     through a data-section function pointer with no IAT entry, where the name
 *     is the POINTER's address and not the callee's at all.
 *
 * **REPORT-ONLY IN BOTH DIRECTIONS, AND NOT GATEABLE AT 0.** Every other gate
 * here can say of each row that it is provably a false statement about the
 * machine. This one cannot: `sub_4038F7();` is an INCOMPLETENESS, not a
 * falsehood — the machine does make that call, the name is derived from the
 * address it makes it to, and nothing in the line is wrong. That is
 * `offsetNamedArgs`' character rather than `unencodableNames`'. The external
 * half is doubly ungateable, since a call to a function detection did not
 * produce is not something the emitter could repair at all. If a future change
 * ever drives the INTERNAL count to 0 by connecting the two halves, gating that
 * half becomes worth re-arguing; today it is 25/0/0/23 and a gate is
 * unavailable on the count alone.
 *
 * **`internalLabelled` IS THE ROW THAT DECIDES WHAT A REPAIR CAN SAY**, which is
 * why it is reported rather than left to be re-derived. A comment at the call
 * site naming the label the body sits under is only available where the target
 * IS a block leader that `structureCFG` labelled — 8 of 25 on t32 and 6 of 23 on
 * w32 at `d8d2d02`. At the other 17 each the block leader is the *unwinder's*
 * own entry three to six bytes earlier (MSVC emits the register reloads only the
 * unwinder needs, and the parent's `call` names the body past them), so naming
 * that label would claim the call executes a reload it does not; at one site per
 * binary (t32 0x4063b8, w32 0x40224b) the funclet body is a fallthrough
 * continuation of the parent's own code and carries no label at all.
 *
 * **NOTHING ELSE HERE CAN SEE THE CLASS, AND `gcc` IS BLIND STRUCTURALLY RATHER
 * THAN INCIDENTALLY.** `ccSyntaxCheck` compiles one function per file with no
 * prototypes at all, so EVERY callee in the corpus is an implicit declaration
 * and `-std=gnu89` accepts one; `-w` then suppresses the warning before
 * `preludeFor` is ever consulted, so this leaves no invented prelude
 * declaration either and `peek-a-bin-k8i`'s instrument is blind too. Separating
 * a folded funclet from an ordinary cross-function call would need a
 * whole-program link, which the harness does not do. `distinct callees lost`
 * asks whether the emitted C still NAMES the callee the disassembly found, and
 * the name is on the page — CLAUDE.md records that camouflage already, in the
 * `__SEH_epilog4` control. The statement-drop audit counts drops, not
 * disconnections; polarity judges guards; `wildBranches` judges targets outside
 * the IMAGE and these are all inside it.
 *
 * **WHAT IT DOES NOT CLAIM.** "Internal" is an address relation and not a
 * funclet test. A call to an address inside the caller's own extent could be a
 * mid-function entry point of another kind, or fiction a misaligned decode
 * produced. All 48 internal rows in this corpus were read against
 * `objdump -d -M intel` and every one is a funclet with exactly one direct
 * caller, which is that caller's own parent — but that is a measurement, not a
 * property of the row.
 */

import type { FuncRec } from "./sweep";

/** One emitted call whose callee is defined nowhere in the output. */
export interface UndefinedCalleeRec {
  fn: string;
  /** The calling function's extent, as function detection reported it. */
  fnAddr: number;
  fnEnd: number;
  /** The identifier as the emitted C spells it. */
  callee: string;
  target: number;
  /** Whether `target` lies inside `[fnAddr, fnEnd)`. See the header. */
  internal: boolean;
  /**
   * For an internal row: whether the calling function emits a `loc_<target>:`
   * label, i.e. whether the target is a block leader a comment could name.
   */
  labelled: boolean;
  /** 1-based line within the function's emitted text, for adjudication. */
  line: number;
  text: string;
}

export interface UndefinedCalleeResult {
  /** Rows whose target is inside the caller's own extent — pf5g's class. */
  internal: number;
  /** Of those, how many have a `loc_<target>:` label to name. */
  internalLabelled: number;
  /** Distinct internal targets, so one funclet called twice is not two. */
  internalDistinct: number;
  internalFuncs: number;
  /** Rows whose target is outside it — detection's or the IAT's business. */
  external: number;
  externalDistinct: number;
  externalFuncs: number;
  /**
   * Every `sub_<hex>(` call site read, resolved or not. The liveness half: a
   * text-scraping audit fails by silently matching nothing, and a 0 here means
   * the emitted spelling moved rather than that the output is connected.
   */
  calls: number;
  /** Functions read. The other liveness half. */
  funcs: number;
  rows: UndefinedCalleeRec[];
}

/**
 * The fallback spelling `resolveNamedTarget` mints, in a call position.
 *
 * Written from the emitted text rather than imported from `lifter.ts`, so the
 * audit does not agree with the code under test by construction. `sub_<hex>` is
 * the ONLY name that form produces which is also an address (`structs.ts` says
 * the same of its own reader), so parsing the hex back out is exact.
 */
const SUB_CALL = /\b(sub_([0-9A-Fa-f]+))\s*\(/g;

const LOC_LABEL = /^\s*loc_([0-9A-Fa-f]+):$/gm;

/**
 * The function's own definition header, which is not a call site.
 *
 * `emit.ts` writes the signature at column 0 and indents every statement, so a
 * line that starts non-blank and ends `) {` is a definition and cannot be a
 * statement. `sweep.ts`'s `emittedCallees` skips the same line with a
 * line-number bound instead; this form is written to survive a reformat, since
 * CLAUDE.md's standing warning about text-scraping guards is that they encode
 * formatting by accident. Skipping it cannot hide a row either way: a function's
 * own address is in `defined` by construction, so its signature — and a genuine
 * self-recursive call — never produces one. What it keeps honest is `calls`, the
 * liveness denominator.
 */
const DEF_HEADER = /^\S.*\)\s*\{\s*$/;

export const emptyUndefinedCallees = (): UndefinedCalleeResult => ({
  internal: 0,
  internalLabelled: 0,
  internalDistinct: 0,
  internalFuncs: 0,
  external: 0,
  externalDistinct: 0,
  externalFuncs: 0,
  calls: 0,
  funcs: 0,
  rows: [],
});

export function auditUndefinedCallees(sets: { funcs: FuncRec[] }[]): UndefinedCalleeResult {
  const out = emptyUndefinedCallees();
  for (const { funcs } of sets) {
    // The set of addresses this binary's output actually DEFINES a function at.
    // Taken from the emitted set rather than from the detector's, because the
    // question is whether the reader can find a body — a function detection
    // found but that threw would still leave a call they cannot follow.
    const defined = new Set(funcs.map((f) => f.addr));
    const internalTargets = new Set<number>();
    const externalTargets = new Set<number>();
    const internalFns = new Set<number>();
    const externalFns = new Set<number>();
    for (const f of funcs) {
      out.funcs++;
      const code = f.code ?? "";
      const lines = code.split("\n");
      let labels: Set<number> | null = null;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        // A commented-out call is not a call. `emittedCallees` in `sweep.ts`
        // skips these for the same reason.
        if (l.trim().startsWith("//")) continue;
        if (DEF_HEADER.test(l)) continue;
        SUB_CALL.lastIndex = 0;
        let m: RegExpExecArray | null = SUB_CALL.exec(l);
        while (m !== null) {
          out.calls++;
          const target = Number.parseInt(m[2], 16);
          if (!defined.has(target)) {
            const internal = target >= f.addr && target < f.addr + f.size;
            if (labels === null) {
              LOC_LABEL.lastIndex = 0;
              labels = new Set([...code.matchAll(LOC_LABEL)].map((x) => Number.parseInt(x[1], 16)));
            }
            const labelled = internal && labels.has(target);
            out.rows.push({
              fn: f.name,
              fnAddr: f.addr,
              fnEnd: f.addr + f.size,
              callee: m[1],
              target,
              internal,
              labelled,
              line: i + 1,
              text: l.trim(),
            });
            if (internal) {
              out.internal++;
              if (labelled) out.internalLabelled++;
              internalTargets.add(target);
              internalFns.add(f.addr);
            } else {
              out.external++;
              externalTargets.add(target);
              externalFns.add(f.addr);
            }
          }
          m = SUB_CALL.exec(l);
        }
      }
    }
    out.internalDistinct += internalTargets.size;
    out.internalFuncs += internalFns.size;
    out.externalDistinct += externalTargets.size;
    out.externalFuncs += externalFns.size;
  }
  return out;
}
