/**
 * CALL ARITY AGAINST THE CALLEE'S OWN RECOVERED SIGNATURE — the 800+ `sub_`
 * call sites `corpus/arity.ts` is structurally blind to.
 *
 * `arity.ts` judges the emitted argument list against `apitypes.ts`, which is
 * the only oracle in this repo that can see call arity at all — and it can only
 * see a callee the TABLE declares. Every call to a function of the image itself
 * is invisible to it, and on x86 that is where the whole of `peek-a-bin-s1f6.2`
 * acts: an API call goes through an IAT slot, which is not a detected function,
 * so no API call site has a `ret N` ceiling and `arity.ts` could not move if the
 * ceiling deleted every argument in the corpus. This audit is the differential
 * that can see it.
 *
 * THE ORACLE IS THE CALLEE'S OWN BODY, and it is a different KIND of oracle from
 * `apitypes.ts` — weaker, and weaker in a way that decides which rows may ever
 * gate. `FuncRec.sigParams` is `inferSignature`'s count for the callee, and what
 * it is worth depends entirely on which arm produced it:
 *
 *   x86 `stdcall` (`sigConvention === "stdcall"`) is the `ret N` arm, and it is
 *   EXACT — the argument area's size in bytes, written by the compiler that had
 *   the prototype, and since `peek-a-bin-s1f6.2` it is refused unless every
 *   `ret` in the extent agrees. So `emitted > declared` is an INVENTED
 *   ARGUMENT, `arity.ts`'s OVER verdict on a population that oracle cannot
 *   reach, and it is the one row here with a claim to a gate.
 *
 *   x86 `cdecl`/`thiscall`/`fastcall` came from `framedParamCount`, which is
 *   `max index + 1` over the argument slots the callee's body happens to touch.
 *   A trailing untouched argument is invisible to it, so it is a LOWER bound and
 *   `emitted > declared` is not a defect. Only `emitted < declared` says
 *   anything, and it says the caller passed fewer than the callee provably
 *   reads.
 *
 *   x64 `fastcall` came from `inferSignature64`, which counts the fastcall
 *   registers the first 20 instructions read before writing. A callee that
 *   spills nothing and reads R9 late reads as 1, and the count is capped at 4.
 *   LOWER bound again, and a tight one: `emitted > declared` is reported as
 *   `x64AboveScan` and is explicitly NOT A DEFECT — a call site passing five
 *   arguments to a callee the scan read as taking one is the normal case.
 *
 * WHAT IT IS NOT. It reads the emitted TEXT, like `arity.ts`, so it judges what
 * a reader is handed. It says nothing about whether an argument NAMES the right
 * value (`corpus/staleReads.ts`'s dimension). And it cannot see a callee with no
 * recovered signature at all: `inferSignature32` answers `null` wherever the
 * body offers no evidence, which on x86 is most import thunks and every function
 * whose frame was not recovered. `withSignature` beside `callSites` is what
 * keeps that residue visible rather than silently shrinking the denominator.
 *
 * LIVENESS. `compared > 0` per PE32 binary is the half that stops the gate going
 * green by no longer looking — a text-scraping audit fails by matching nothing,
 * and this one resolves callees through a NAME map, so a change to how the
 * emitter spells a callee would empty it silently.
 */

import { isIdent, maskLiteralsAndComments, splitArgs } from "./arity";
import type { FuncRec } from "./sweep";

/** How a row was judged, which is decided by the callee's convention and width. */
export type CalleeArityClass =
  | "exact"
  /** x86 `ret N` callee, emitted MORE. An invented argument — the gate candidate. */
  | "stdcall-over"
  /** x86 `ret N` callee, emitted FEWER. A recovery the lifter did not make. */
  | "stdcall-under"
  /** x86 frame-counted callee, emitted FEWER than the body provably reads. */
  | "cdecl-under"
  /** x64 register-scan callee, emitted FEWER than the callee reads. */
  | "x64-under"
  /** x64, emitted MORE than the scan saw. NOT a defect: the scan is a lower bound. */
  | "x64-above-scan"
  /**
   * x86 frame-counted callee, emitted MORE than the frame accounts for. NOT a
   * defect either, and kept apart from `exact` deliberately: folding it in
   * would be a false green on a row the audit has no oracle for.
   */
  | "cdecl-above-frame";

export interface CalleeArityRec {
  fn: number;
  fname: string;
  /** The identifier the emitted C spells in callee position. */
  callee: string;
  /** The callee's entry address, from the `FuncRec` the name resolved to. */
  calleeAddr: number;
  /** `FuncRec.sigConvention` — which arm of `inferSignature` produced the count. */
  convention: string;
  /** `FuncRec.sigParams`. Exact for x86 stdcall; a lower bound otherwise. */
  declared: number;
  /** Arguments the emitted C passes, by top-level commas. */
  emitted: number;
  klass: CalleeArityClass;
  /** The emitted argument texts, so a row can be judged without re-running. */
  args: string[];
  /** 1-based line within the calling function's emitted text. */
  line: number;
  text: string;
}

export interface CalleeArityResult {
  /** Functions read. Liveness. */
  funcs: number;
  /** Emitted calls to an identifier this binary defines a function for. Liveness. */
  callSites: number;
  /** Of those, how many had a recovered signature to judge against. Liveness. */
  compared: number;
  /** Distinct callee functions carrying a signature, over the whole binary. */
  withSignature: number;
  /**
   * Compared sites whose callee's count came from the `ret N` arm — the
   * population the ONE gated row is drawn from, in every direction.
   *
   * THE GATE'S OWN LIVENESS HALF, and it is separate from `compared` for a
   * reason this repo keeps rediscovering: `compared` is dominated on x86 by
   * frame-counted callees, whose over-direction cannot be a defect, so a run in
   * which no `ret N` callee was resolved at all would report `stdcallOver 0`
   * over an EMPTY population and read as the healthiest row in the file.
   */
  stdcallSites: number;
  /** Names two or more functions share, which are resolved to neither. */
  ambiguousNames: number;
  exact: number;
  /** THE GATE CANDIDATE: an argument invented at a `ret N` callee. */
  stdcallOver: number;
  stdcallUnder: number;
  cdeclUnder: number;
  x64Under: number;
  /** NOT a defect — the x64 register scan is a lower bound. Reported. */
  x64AboveScan: number;
  /** NOT a defect — the x86 frame count is a lower bound. Reported. */
  cdeclAboveFrame: number;
  rows: CalleeArityRec[];
}

export const emptyCalleeArity = (): CalleeArityResult => ({
  funcs: 0,
  callSites: 0,
  compared: 0,
  withSignature: 0,
  stdcallSites: 0,
  ambiguousNames: 0,
  exact: 0,
  stdcallOver: 0,
  stdcallUnder: 0,
  cdeclUnder: 0,
  x64Under: 0,
  x64AboveScan: 0,
  cdeclAboveFrame: 0,
  rows: [],
});

/**
 * The function's own definition header, which is not a call to itself.
 *
 * The same rule `undefinedCallees.ts` uses and for the same reason: `emit.ts`
 * writes the signature at column 0 and indents every statement, so a line that
 * starts non-blank and ends `) {` is a definition. Written this way rather than
 * as `callee !== f.name` so a genuine self-recursive call is still a row.
 */
const DEF_HEADER = /^\S.*\)\s*\{\s*$/;

/** A call in the emitted C: an identifier applied to an argument list. */
const CALL = /([A-Za-z_]\w*)\s*\(/g;

/**
 * Every emitted call to a function of this image, judged against the callee's
 * own recovered signature.
 *
 * `is64` is the image's width, from the PE, because it decides which of the
 * three oracles above is in play — not the register names in the output.
 */
export function auditCalleeArity(funcs: FuncRec[], is64: boolean): CalleeArityResult {
  const out = emptyCalleeArity();

  // Callees are resolved by NAME, because the name is what the emitted text
  // carries: `resolveCallTarget` spells a detected function by its own name and
  // mints `sub_<hex>` only where detection produced none. A name two functions
  // share is resolved to NEITHER — a wrong callee is a wrong oracle — and the
  // count of them is reported so the refusal cannot hide a shrinking population.
  const byName = new Map<string, FuncRec | null>();
  for (const f of funcs) {
    if (byName.has(f.name)) {
      if (byName.get(f.name) !== null) {
        byName.set(f.name, null);
        out.ambiguousNames++;
      }
      continue;
    }
    byName.set(f.name, f);
  }
  for (const f of funcs) if (f.sigParams !== null) out.withSignature++;

  for (const f of funcs) {
    out.funcs++;
    const code = f.code ?? "";
    if (code === "") continue;
    const masked = maskLiteralsAndComments(code);
    const lines = code.split("\n");
    // Line starts, so a match index maps to a 1-based line without re-splitting
    // the masked text (an index into `masked` is an index into `code` — the
    // masking is length-preserving, which is the property `arity.ts` relies on).
    const lineStarts: number[] = [];
    {
      let at = 0;
      for (const l of lines) {
        lineStarts.push(at);
        at += l.length + 1;
      }
    }
    const lineOf = (idx: number): number => {
      let lo = 0;
      let hi = lineStarts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (lineStarts[mid] <= idx) lo = mid;
        else hi = mid - 1;
      }
      return lo;
    };

    CALL.lastIndex = 0;
    let m: RegExpExecArray | null = CALL.exec(masked);
    while (m !== null) {
      const name = m[1];
      const before = m.index === 0 ? undefined : masked[m.index - 1];
      // `p->f(` is a field and `xf(` is another name entirely. Neither occurs
      // today; both would be a wrong row.
      const standalone = !isIdent(before) && before !== "." && before !== ">";
      const li = lineOf(m.index);
      const callee = standalone && !DEF_HEADER.test(lines[li]) ? (byName.get(name) ?? null) : null;
      if (callee !== null) {
        out.callSites++;
        const argSpans =
          callee.sigParams === null ? null : splitArgs(masked, m.index + m[0].length - 1);
        if (callee.sigParams !== null && argSpans !== null) {
          const declared = callee.sigParams;
          const emitted = argSpans.length;
          const convention = callee.sigConvention ?? "";
          const klass = classify(is64, convention, declared, emitted);
          out.compared++;
          out[COUNTER[klass]]++;
          if (!is64 && convention === "stdcall") out.stdcallSites++;
          if (klass !== "exact") {
            out.rows.push({
              fn: f.addr,
              fname: f.name,
              callee: name,
              calleeAddr: callee.addr,
              convention,
              declared,
              emitted,
              klass,
              args: argSpans.map(([a, b]) => code.slice(a, b).trim()),
              line: li + 1,
              text: lines[li].trim(),
            });
          }
        }
      }
      // Resume just past the name, so a nested call inside this argument list is
      // found on its own match rather than skipped with the outer one.
      CALL.lastIndex = m.index + name.length;
      m = CALL.exec(masked);
    }
  }
  return out;
}

type CountKey =
  | "exact"
  | "stdcallOver"
  | "stdcallUnder"
  | "cdeclUnder"
  | "x64Under"
  | "x64AboveScan"
  | "cdeclAboveFrame";

const COUNTER: Record<CalleeArityClass, CountKey> = {
  exact: "exact",
  "stdcall-over": "stdcallOver",
  "stdcall-under": "stdcallUnder",
  "cdecl-under": "cdeclUnder",
  "x64-under": "x64Under",
  "x64-above-scan": "x64AboveScan",
  "cdecl-above-frame": "cdeclAboveFrame",
};

/**
 * Which row this site is, from the width and the arm that produced the count.
 *
 * The asymmetry is the whole audit: on x86 a `stdcall` count is EXACT in both
 * directions, every other count is a LOWER bound, and a lower bound can only be
 * violated downwards.
 */
function classify(
  is64: boolean,
  convention: string,
  declared: number,
  emitted: number,
): CalleeArityClass {
  if (emitted === declared) return "exact";
  if (is64) return emitted < declared ? "x64-under" : "x64-above-scan";
  if (convention === "stdcall") return emitted < declared ? "stdcall-under" : "stdcall-over";
  // A frame-counted x86 callee: only the UNDER direction is a statement. An
  // over-count against a LOWER bound is the bound being low, which is not a
  // defect — but it is not `exact` either, and folding it in would be a false
  // green. It gets its own reported row, exactly as `x64AboveScan` does.
  return emitted < declared ? "cdecl-under" : "cdecl-above-frame";
}
