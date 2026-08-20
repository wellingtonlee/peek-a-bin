/**
 * CALL ARITY AGAINST `apitypes.ts`'s DECLARED SIGNATURES.
 *
 * The one dimension of the emitted C that has an oracle *outside* the emitted
 * text, and the one nothing else here can see. `gcc -std=gnu89` accepts an
 * implicit declaration at ANY arity, the emitter deliberately writes no callee
 * prototypes, and `emitAudits.ts`'s `preludeFor` declares each undeclared
 * identifier as its own `long` — so the compiler gate is INSENSITIVE TO CALL
 * ARITY BY CONSTRUCTION. It could not have caught `peek-a-bin-qb2x` (x64
 * arguments set up through a 32-bit sub-register, so `ExitProcess()` was
 * emitted with no argument while the machine passed one) and it cannot certify
 * the fix. `src/disasm/decompile/apitypes.ts` is the only arity oracle in the
 * repo: **209** declared Win32/NT signatures at `e22ba6e` (14 of them taking no
 * parameter at all), none variadic, so a declared count is exact rather than a
 * minimum. CLAUDE.md's "~130" for that table is stale; `declaredNames` in the
 * result is the live count and the run asserts a floor on it.
 *
 * WHY THIS FILE EXISTS AT ALL. `peek-a-bin-qb2x` was verified against an
 * instrument that lived in a scratch worktree and was deleted with it: the diff
 * carried the fix, not the measurement, and the headline claim became
 * unrepeatable (`peek-a-bin-02fa`). `corpus/` exists precisely so that cannot
 * happen — when an agent builds an oracle to verify a change, landing the
 * oracle is part of the change.
 *
 * WHAT A ROW MEANS, and the two directions are not symmetric:
 *
 *   OVER  — the emitted call passes MORE arguments than the API takes. There is
 *           no reading of the machine on which that is right: the argument was
 *           invented. `GetLastError(rcx)` is the shape, and it compiles clean.
 *   UNDER — the emitted call passes FEWER. Usually a recovery the lifter did not
 *           make, and on x64 often one it CANNOT make: `collectArgs64` reads the
 *           four fastcall registers and nothing else, so an API declaring five
 *           or more parameters is short by construction. That subset is counted
 *           apart as `underAtCeiling`, because it is a property of the ABI
 *           evidence rather than a defect that could be fixed by lifting better.
 *
 * WHAT IT IS NOT. It reads the emitted TEXT, so it judges what a reader is
 * actually handed rather than what the IR held. It says nothing about whether an
 * argument NAMES the right value — `SearchPathW(0, rcx, rax, 0x400)` has exactly
 * the right arity and a wrong second argument, which is `corpus/staleReads.ts`'s
 * dimension, not this one (see README.md, "What the standing set does NOT
 * catch"). And it is only as good as the table: an OVER row is either an
 * invented argument or a wrong entry in `apitypes.ts`, so the rows are written
 * out per site for a human to adjudicate.
 */
import { API_TYPES } from "../src/disasm/decompile/apitypes";
import type { FuncRec } from "./sweep";

/** One emitted call whose callee `apitypes.ts` declares. */
export interface ArityRec {
  fn: number;
  fname: string;
  callee: string;
  /** Parameters `apitypes.ts` declares. Exact, not a minimum: no entry is variadic. */
  declared: number;
  /** Arguments the emitted C passes, by top-level commas in the argument list. */
  emitted: number;
  verdict: "exact" | "under" | "over";
  /**
   * An UNDER row the lifter's argument evidence cannot reach past: the emitted
   * count is exactly the ABI ceiling (`collectArgs64`'s four fastcall
   * registers, or `collectArgs32`'s eight-push scan) and the API declares more.
   */
  atCeiling: boolean;
  /** The emitted argument texts, so a row can be judged without re-running. */
  args: string[];
  /** The emitted line, trimmed. */
  line: string;
}

export interface ArityResult {
  /** Call sites whose callee the table declares — the denominator. */
  sites: number;
  exact: number;
  under: number;
  over: number;
  /** UNDER rows sitting exactly at the ABI ceiling. Not reachable by lifting better. */
  underAtCeiling: number;
  /** UNDER rows below it. These are arguments the evidence was there to recover. */
  underBelowCeiling: number;
  /** Distinct declared callees the emitted C calls. */
  distinctCallees: number;
  /** INSTRUMENT LIVENESS: names in the table this scan was willing to match. */
  declaredNames: number;
  /** INSTRUMENT LIVENESS: functions of emitted C the scan actually read. */
  scannedFuncs: number;
  /** Sites per callee, worst-verdict first, for the report. */
  byCallee: { callee: string; sites: number; exact: number; under: number; over: number }[];
  rows: ArityRec[];
}

export function emptyArity(): ArityResult {
  return {
    sites: 0,
    exact: 0,
    under: 0,
    over: 0,
    underAtCeiling: 0,
    underBelowCeiling: 0,
    distinctCallees: 0,
    declaredNames: Object.keys(API_TYPES).length,
    scannedFuncs: 0,
    byCallee: [],
    rows: [],
  };
}

/**
 * The emitted code with every comment and string/char literal body replaced by
 * spaces, LENGTH PRESERVED so an index into it is an index into the original.
 *
 * Both are necessary and neither is hypothetical. `annotateIOCTLArg` writes
 * `0x22 /* IOCTL: … *\/` INSIDE an argument list, and a recovered string
 * argument — `GetProcAddress(rax, "CorExitProcess")` — can contain a comma, a
 * parenthesis or an escaped quote. Counting commas over the raw text would
 * mis-split both. Neither hazard occurs in today's corpus, which is exactly why
 * it has to be handled here rather than noticed later.
 */
function maskLiteralsAndComments(code: string): string {
  const out = code.split("");
  let i = 0;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < out.length; k++) if (out[k] !== "\n") out[k] = " ";
  };
  while (i < code.length) {
    const c = code[i];
    const two = code.slice(i, i + 2);
    if (two === "//") {
      const end = code.indexOf("\n", i);
      blank(i, end === -1 ? code.length : end);
      i = end === -1 ? code.length : end;
    } else if (two === "/*") {
      const end = code.indexOf("*/", i + 2);
      const stop = end === -1 ? code.length : end + 2;
      blank(i, stop);
      i = stop;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < code.length && code[j] !== c && code[j] !== "\n") {
        if (code[j] === "\\") j++;
        j++;
      }
      blank(i, Math.min(j + 1, code.length));
      i = Math.min(j + 1, code.length);
    } else {
      i++;
    }
  }
  return out.join("");
}

/**
 * The argument list of a call whose `(` is at `open`, split at TOP-LEVEL commas.
 *
 * Returns null when the parentheses do not close in the masked text, which is
 * the honest answer for a call the scan cannot read rather than a guess at its
 * arity. Nesting is counted, so `f(g(a, b), c)` is two arguments and the inner
 * call is found on its own pass over the line.
 */
function splitArgs(masked: string, open: number): [number, number][] | null {
  let depth = 0;
  let start = open + 1;
  const args: [number, number][] = [];
  for (let i = open; i < masked.length; i++) {
    const c = masked[i];
    if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") {
      depth--;
      if (depth === 0) {
        if (masked.slice(start, i).trim() !== "" || args.length > 0) args.push([start, i]);
        return args;
      }
    } else if (c === "," && depth === 1) {
      args.push([start, i]);
      start = i + 1;
    }
  }
  return null;
}

/** An identifier character, for rejecting a match inside a longer name. */
const isIdent = (c: string | undefined) => c !== undefined && /[A-Za-z0-9_]/.test(c);

/**
 * Every emitted call to a declared API, judged against the declared arity.
 *
 * `is64` selects the ABI ceiling the UNDER split uses — four fastcall registers
 * against eight scanned pushes — and is the image's width, taken from the PE
 * rather than guessed from the register names in the output.
 */
export function auditApiArity(funcs: FuncRec[], is64: boolean): ArityResult {
  const res = emptyArity();
  const ceiling = is64 ? 4 : 8;
  const perCallee = new Map<
    string,
    { sites: number; exact: number; under: number; over: number }
  >();

  for (const f of funcs) {
    const code = f.code ?? "";
    if (code === "") continue;
    res.scannedFuncs++;
    const masked = maskLiteralsAndComments(code);
    const nameRe = /([A-Za-z_]\w*)\s*\(/g;
    let m: RegExpExecArray | null = nameRe.exec(masked);
    while (m !== null) {
      const callee = m[1];
      const sig = API_TYPES[callee] as (typeof API_TYPES)[string] | undefined;
      const declared = sig === undefined ? null : sig.params.length;
      const before = m.index === 0 ? undefined : masked[m.index - 1];
      // `p->GetLastError(` is a field, not this API; `xGetLastError(` is another
      // name entirely. Neither occurs today; both would be a wrong row.
      const standalone = !isIdent(before) && before !== "." && before !== ">";
      // The function's own definition header is not a call to itself.
      const notOwnHeader = callee !== f.name;
      if (declared !== null && standalone && notOwnHeader) {
        const open = m.index + m[0].length - 1;
        const argSpans = splitArgs(masked, open);
        if (argSpans !== null) {
          const emitted = argSpans.length;
          const verdict = emitted === declared ? "exact" : emitted < declared ? "under" : "over";
          const atCeiling = verdict === "under" && emitted === ceiling;
          const lineStart = code.lastIndexOf("\n", m.index) + 1;
          const lineEnd = code.indexOf("\n", m.index);
          res.rows.push({
            fn: f.addr,
            fname: f.name,
            callee,
            declared,
            emitted,
            verdict,
            atCeiling,
            args: argSpans.map(([a, b]) => code.slice(a, b).trim()),
            line: code.slice(lineStart, lineEnd === -1 ? code.length : lineEnd).trim(),
          });
          res.sites++;
          res[verdict]++;
          if (verdict === "under") {
            if (atCeiling) res.underAtCeiling++;
            else res.underBelowCeiling++;
          }
          const pc = perCallee.get(callee) ?? { sites: 0, exact: 0, under: 0, over: 0 };
          pc.sites++;
          pc[verdict]++;
          perCallee.set(callee, pc);
        }
      }
      // Resume just past the name, so a nested call inside this argument list is
      // found on its own match rather than skipped with the outer one.
      nameRe.lastIndex = m.index + m[1].length;
      m = nameRe.exec(masked);
    }
  }

  res.distinctCallees = perCallee.size;
  res.byCallee = [...perCallee]
    .map(([callee, v]) => ({ callee, ...v }))
    .sort((a, b) => b.over - a.over || b.under - a.under || b.sites - a.sites);
  return res;
}
