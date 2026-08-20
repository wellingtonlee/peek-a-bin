/**
 * ONE load + decompile pass per binary, feeding every audit that needs the
 * repo's own code.
 *
 * The single pass is not an optimisation, it is a correctness requirement.
 * `StructRegistry` is cross-function state shared for the lifetime of a loaded
 * file (see CLAUDE.md, "Struct synthesis"), so the emitted C for a function
 * depends on which functions were decompiled before it. An audit that runs its
 * own pass over a *subset* — only the functions with a jcc, say, or only those
 * with a call — is measuring a different program than the one production emits.
 * Every audit here therefore reads the results of the same pass, taken over
 * every detected function in address order, which is what the worker does.
 *
 * The audits computed here are the ones that need instructions, a CFG or a line
 * map. The ones that need only the emitted text — gcc, offsetof, goto
 * resolution — live in `emitAudits.ts` and run off `BinResult.funcs`.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isCoveredMnemonic, X64_VOLATILE } from "../src/disasm/callSummary";
import { buildCFG, detectLoops } from "../src/disasm/cfg";
import type { IRStmt } from "../src/disasm/decompile/ir";
import { decompileFunction, type StructuringTap } from "../src/disasm/decompile/pipeline";
import { buildFuncInsnMap } from "../src/disasm/funcInsns";
import { inferSignature } from "../src/disasm/signatures";
import { analyzeStackFrame } from "../src/disasm/stack";
import type { Instruction } from "../src/disasm/types";
import { FileSession } from "../src/mcp/session";
import { type BinKey, binPath, substitutedTablesDir } from "./preflight";
import { auditStaleGuards, emptyStaleGuards, type StaleGuardResult } from "./staleGuards";
import { auditStaleV0Reads, emptyStaleV0, type StaleV0Result } from "./staleReads";

// ── Condition polarity ─────────────────────────────────────────────────────
//
// Lifted from the scratchpad harness the standing "0 inverted" number was
// measured with. Two things in it are load-bearing and must not be simplified
// away:
//
// 1. ANCHORING THROUGH UNCONDITIONAL JUMPS. The guard for an emitted body is
//    found by asking which jcc reaches the body's first machine address. When a
//    `jmp`-only block sits between them — `jne exit / jmp top` is an ordinary
//    MSVC loop entry — the real guard is one edge further back, and the jcc a
//    naive match picks belongs to a different test. That produced a false
//    INVERTED on t32's sub_4045B1, where `if ((al & 0xC) == 0)` is correct
//    against `test al,0xc / jne …` and only looks wrong against the `je` two
//    blocks later. So candidate edges are resolved through `jmp` chains, and a
//    body address that two different jccs can reach is AMBIGUOUS and skipped
//    rather than judged against a guess. Skipping is the safe direction; a
//    guessed anchor yields a wrong verdict, which is worse than no verdict.
//
// 2. THE ANCHOR IS THE BODY, NOT THE CONDITION TEXT. The body's first statement
//    identifies the machine block that runs when the guard holds, so the
//    emitted comparison must be the jcc's taken-sense operator when that block
//    is the jump target and its negation when it is the fallthrough. This is
//    what makes the audit immune to the structurer legitimately swapping an
//    if/else round: `if (x != 0) A else B` and `if (x == 0) B else A` both pass,
//    because each is judged against the arm it actually guards.
//
// `extractCondition` returns the condition under which the jump is TAKEN — see
// the gotcha of that name in CLAUDE.md. TAKEN below is that same mapping,
// written independently so the audit does not agree with the code under test by
// construction.

const TAKEN: Record<string, string> = {
  je: "==",
  jz: "==",
  jne: "!=",
  jnz: "!=",
  jg: ">",
  jnle: ">",
  jge: ">=",
  jnl: ">=",
  jl: "<",
  jnge: "<",
  jle: "<=",
  jng: "<=",
  ja: ">",
  jnbe: ">",
  jae: ">=",
  jnb: ">=",
  jnc: ">=",
  jb: "<",
  jnae: "<",
  jc: "<",
  jbe: "<=",
  jna: "<=",
  js: "<",
  jns: ">=",
};
const NEG: Record<string, string> = {
  "==": "!=",
  "!=": "==",
  "<": ">=",
  ">=": "<",
  ">": "<=",
  "<=": ">",
};

const OPENER = /^\s*(\}\s*else\b|if\s*\(|while\s*\(|do\s*\{|for\s*\(|switch\s*\(|__try|\{)/;
const LABEL_LINE = /^(loc_([0-9A-Fa-f]+)):\s*$/;

/** The single top-level comparison operator of `cond`, or null if not exactly one. */
function topOp(cond: string): string | null {
  let depth = 0;
  const ops: string[] = [];
  for (let i = 0; i < cond.length; i++) {
    const c = cond[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0) {
      const two = cond.slice(i, i + 2);
      if (two === "&&" || two === "||") return null;
      if (two === "==" || two === "!=" || two === "<=" || two === ">=") {
        ops.push(two);
        i++;
      } else if (c === "<" || c === ">") ops.push(c);
    }
  }
  return ops.length === 1 ? ops[0] : null;
}

/** Split a `for` header's three clauses at top-level `;`. */
function splitFor(header: string): [string, string, string] | null {
  let depth = 0;
  const cuts: number[] = [];
  for (let i = 0; i < header.length; i++) {
    const c = header[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === ";" && depth === 0) cuts.push(i);
  }
  if (cuts.length !== 2) return null;
  return [header.slice(0, cuts[0]), header.slice(cuts[0] + 1, cuts[1]), header.slice(cuts[1] + 1)];
}

/**
 * One audited guard. `jcc` is the address of the conditional jump it was
 * anchored to, and is the key a base-vs-change comparison joins on — function
 * names move when detection changes, instruction addresses do not.
 */
export interface GuardRec {
  jcc: number;
  mnem: string;
  kind: string;
  cond: string;
  expect: string;
  emitted: string;
  verdict: "OK" | "INVERTED" | "MISMATCH";
  sense: string;
  /**
   * The machine address the guard was anchored BY — the first address of the
   * arm it governs. Recorded for debugging a failure by hand; deliberately not
   * part of what `compare.mjs` joins or diffs on, since an arm's first address
   * can move for reasons that are not a polarity change.
   */
  bodyAddr: number;
  /**
   * "A"  — the body's first line carried a block start address by itself.
   * "A2" — that line had to be normalised to its CFG block. Sound whenever the
   *        line really is in the arm's first block; counted apart so the
   *        headline number rests only on addresses that identify a block alone.
   * "B"  — the statement after a loop, which is the loop test's other side only
   *        when the loop has no other exit. A heuristic; reported separately
   *        and never part of the headline.
   */
  anchor: "A" | "A2" | "B";
  fn: number;
  fname: string;
}

/** An emitted loop offering fewer ways out than the machine loop it matches. */
export interface LoopShortRec {
  fn: number;
  fname: string;
  line: number;
  kind: string;
  machineExits: number;
  emittedExits: number;
  exits: string[];
}

/**
 * One statement `liftBlock` produced that `structureCFG` did not put anywhere
 * in its output, identified BY OBJECT IDENTITY.
 *
 * `addr` is the machine address the statement carries, which most lifted
 * statements do; `blockAddr` is its CFG block's start address, which every one
 * of them has. Between the two and `kind` there is enough to find the thing in
 * the disassembly and decide whether its absence is a defect.
 */
export interface StmtDropRec {
  fn: number;
  fname: string;
  blockId: number;
  blockAddr: number;
  /** The statement's own machine address, or null for one that carries none. */
  addr: number | null;
  kind: string;
  /** Where it sat in its block's lifted list, and how long that list was. */
  index: number;
  of: number;
  /** The assignment's destination, when it is a plain register or variable. */
  dest: string | null;
}

/**
 * One `__unrecovered_N` in the emitted C — one machine fact the emitter names
 * instead of guessing at.
 *
 * `jcc` is a LOCATOR — the conditional jump guarding the arm this value's
 * condition governs — and it is null far more often than it is set. That is
 * deliberate rather than a gap to close: the `if (…)` header line carries no
 * line-map address (`emit.ts` pushes it without one), so the only route to an
 * address is the same body-anchoring the polarity audit does, and that fails on
 * roughly two thirds of all guards. `jccFrom` says which happened.
 *
 * `note` is the authority on WHICH branch was unrecovered; `jcc` is not.
 * Anchoring names the jump that guards the arm, and in a short-circuited
 * condition — `if (!__unrecovered_1 /* jle *\/ && edi <= 0x7FFFFFF0)` — that is
 * the LAST test in the chain, while the unrecovered value came from the first.
 * Measured over the corpus, the note and the anchored jump name the same
 * mnemonic 123 times in 125, and both exceptions are exactly that shape.
 */
export interface UnrecoveredRec {
  fn: number;
  fname: string;
  /** `__unrecovered_7`. Unique within its function, not across the binary. */
  name: string;
  /** The text the emitter could not recover: a jcc mnemonic, or an operand. */
  note: string;
  /** "branch" when `note` names a conditional jump, else "value". */
  cause: "branch" | "value";
  /** Where the value is USED, from the emitted line it appears on. */
  site: string;
  /** The originating jcc, when the polarity anchoring named one. */
  jcc: number | null;
  /** That jcc's mnemonic, as the disassembly spells it. */
  mnem: string | null;
  /** How `jcc` was determined, or why it could not be. */
  jccFrom: string;
}

/** One decompiled function, as the emitted-text audits consume it. */
export interface FuncRec {
  addr: number;
  name: string;
  size: number;
  insns: number;
  threw: string | null;
  code: string;
}

export interface BinResult {
  key: BinKey;
  path: string;
  is64: boolean;
  functions: number;
  instructions: number;
  jumpTables: number;
  /** The recovered tables themselves, so another commit's run can be given them. */
  jumpTablesJson: string;
  /** Set when THESE tables came from another run's artifact, naming the file. */
  tablesFrom: string | null;
  /** decompileFunction (or its prep) raising. The standing expectation is 0. */
  throws: number;
  throwDetail: string[];
  polarity: {
    checked: number;
    ok: number;
    inverted: number;
    mismatch: number;
    skipped: number;
    a2Checked: number;
    a2Ok: number;
    weakChecked: number;
    weakOk: number;
    agreeAB: number;
    disagreeAB: number;
    onlyB: number;
  };
  skipReasons: Record<string, number>;
  guards: GuardRec[];
  loops: { seen: number; audited: number; short: number; skipped: number };
  loopSkip: Record<string, number>;
  loopShort: LoopShortRec[];
  /**
   * LINE MAP COVERAGE. Read the name literally: it measures whether an
   * instruction's address appears in the emitted line map, and NOTHING MORE.
   *
   * Lost coverage does NOT mean the statement is absent from the output. It has
   * three quite different causes and this metric cannot tell them apart:
   *
   *   1. FOLDED into a use — the value survives inside a later expression;
   *   2. RELOCATED — the statement is emitted, but carrying a different
   *      address, or moved relative to its neighbours;
   *   3. GENUINELY DROPPED — nothing in the output corresponds to it.
   *
   * Only (3) is a defect, and separating it from (1) and (2) requires reading
   * the emitted C beside the machine text, function by function. This has bitten
   * already: a report of this metric called three statements at t32
   * `sub_4045B1` 0x404e10 absent, and two of them (`edi = edx`, `ebx = eax`)
   * were in fact still emitted, having only lost their address mapping — one of
   * them relocated below its neighbour. Only the third was really gone.
   *
   * NEVER ZERO, and not expected to be: alignment padding and blocks that lift
   * to no statements land here legitimately. It is a baseline to compare
   * against, never a gate.
   */
  lineMapCoverage: {
    /** Instructions whose address appears in the line map. Per-instruction. */
    insnsCovered: number;
    insnsTotal: number;
    /** CFG blocks not one of whose instructions is covered. Per-block. */
    blocksUncovered: number;
    blocksTotal: number;
    funcsWithUncoveredBlock: number;
    detail: string[];
  };
  /** A callee the disassembly names that the emitted C never applies. Expect 0. */
  callees: { pairs: number; lost: number; funcsAffected: number; detail: string[] };
  /**
   * STATEMENT DROPS ACROSS `structureCFG`, BY OBJECT IDENTITY.
   *
   * The complement of line map coverage, and a strictly sharper question. That
   * metric asks whether an *address* reached the emitted line map, and cannot
   * tell "folded into a use" from "relocated" from "genuinely gone". This one
   * asks whether the *statement object* the front end built is anywhere in the
   * tree the structurer returned, so folding and relocation cannot register:
   * folding happens in `foldBlock`, before the snapshot, and a relocated
   * statement is still the same object somewhere in the tree.
   *
   * A drop here means nothing downstream can know the statement existed. It
   * never enters the tree, so there is no dangling reference, no comment and no
   * missing label — the reader simply concludes the code does not exist. That
   * is the class `peek-a-bin-cb2` was (6% of every statement, from the leftover
   * pass requiring reachability) and the class `peek-a-bin-hu7` is.
   *
   * NOT A GATE, and deliberately so: the count at the commit this was built on
   * is not zero, and a threshold nobody has justified is worse than a number
   * that moves. Read `drops` and `corpus/README.md` before acting on a change.
   *
   * WHAT IT DOES NOT COVER: everything after `structureCFG`. `cleanupStructured`,
   * `wrapExceptionRegions`, `inferTypes`, `promoteVars`, `synthesizeStructs` and
   * `emitFunction` all run afterwards, and a statement any of them discards is
   * counted as kept here.
   */
  stmtDrops: {
    /** Lifted statements examined — the denominator. */
    tracked: number;
    dropped: number;
    byKind: Record<string, number>;
    funcsAffected: number;
    detail: string[];
  };
  /** Every drop, per site. Written out as `drops_<key>.jsonl`. */
  drops: StmtDropRec[];
  /**
   * BRANCH AND VALUE RECOVERY, counted from the emitted C.
   *
   * `__unrecovered_N` is what the emitter prints when it cannot name a value —
   * most often the condition of a Jcc whose flags nothing in the IR explains.
   * It is the honest spelling and it is why so much of the corpus compiles
   * clean, but it is also an admitted gap, and until this existed NOTHING
   * COUNTED THEM.
   *
   * WHY THIS IS NOT COVERED BY THE POLARITY AUDIT, which is the trap it was
   * built for. `judge` needs `topOp(cond)` to name exactly one comparison
   * operator, and `__unrecovered_7 /* jne *\/` has none — so an unrecovered
   * guard is not a failing polarity row, IT IS NOT A ROW AT ALL. It leaves the
   * audited set silently. `polarity.ok / polarity.checked` then stays at 1.00
   * while `checked` falls, and a change that turned 400 recovered guards into
   * `__unrecovered_N` moved no number in a bad direction anywhere in this
   * harness (`peek-a-bin-rl01`). Both directions cross that boundary in
   * silence: recovery getting worse, and conditions getting richer.
   *
   * NOT A GATE, for the same reason the statement-drop count is not: the value
   * today is not zero and no threshold on it has been established. A RISE
   * between two pinned runs is judged in `compare.mjs`, which is also where
   * `polarity.checked` falling is now judged.
   */
  unrecovered: {
    /** Occurrences of the token in emitted C, declaration and use. Greppable. */
    occurrences: number;
    /** Distinct names, i.e. distinct machine facts given up on. */
    values: number;
    /** Values whose note names a conditional jump — an unrecovered GUARD. */
    branches: number;
    /** Of those, the ones whose originating jcc address could be named. */
    branchesWithJcc: number;
    funcsAffected: number;
    /** Functions of emitted C the scan actually read. Instrument liveness. */
    scannedFuncs: number;
    /** Declaration lines parsed, i.e. notes read from the header. Liveness. */
    declsParsed: number;
    bySite: Record<string, number>;
    byMnemonic: Record<string, number>;
    detail: string[];
  };
  /** Every unrecovered value, per site. Written as `unrecovered_<key>.jsonl`. */
  unrecoveredSites: UnrecoveredRec[];
  /**
   * WHAT A CALL DESTROYS, counted from the emitted C — the measurement
   * `peek-a-bin-hj1` lives or dies by.
   *
   * `clobbered_<reg>_<version>` is what the emitter prints for a read of a
   * register version a *call* handed out: no statement defines it, so the value
   * is indeterminate and naming it after the register would put the reader back
   * where they started (C's `rcx` still holds whatever the last `rcx = …` line
   * put there). Every occurrence in the emitted body is a READ — the `long
   * clobbered_rcx_4;` line in the `.c` file is `emitAudits.ts`'s prelude, added
   * after this runs — and `values` counts the distinct names behind them.
   *
   * IT IS NOT A GATE IN EITHER DIRECTION, and that is the point of recording
   * it. A rise is not automatically a defect — a call that really does destroy
   * a register *should* say so, and the whole of hj1 is about widening this
   * honestly. A fall is not automatically an improvement either: the narrow
   * model falls to zero by saying nothing at all. What makes a change here
   * judgeable is reading it beside `ifs` below, which is where the harmful
   * direction shows up: modelling a call as clobbering the full ABI volatile
   * set deleted a guard outright in `t64!sub_140004A9C`.
   *
   * `summaryFuncs`/`summaryNonEmpty`/`summaryFull` are instrument liveness for
   * `callSummary.ts` — a summary pass that quietly stopped resolving callees
   * would report the healthiest possible numbers. `uncoveredMnemonics` counts
   * instructions whose mnemonic that module's table does not classify: each one
   * is a write it cannot see, so a rise means the summary is quietly
   * under-approximating more than it was.
   */
  clobbered: {
    occurrences: number;
    values: number;
    reads: number;
    funcsAffected: number;
    byRegister: Record<string, number>;
    /** Emitted `if (`, `while (` and `for (` — the guard-deletion tell. */
    ifs: number;
    whiles: number;
    fors: number;
    summaryFuncs: number;
    summaryNonEmpty: number;
    summaryFull: number;
    uncoveredMnemonics: number;
  };
  /**
   * A REGISTER NAMED IN THE EMITTED C THAT NO LONGER HOLDS WHAT THE SSA SAID.
   *
   * A GATE at 0, unlike the two audits above it, and `corpus/staleReads.ts`
   * says why: every row is a *provably* wrong name, which is the polarity
   * audit's character rather than the drop count's. `wrong` is the bare
   * register a dominating write has already changed; `copiesCorrupted` is the
   * repair spoiled, which is worse because the output looks recovered.
   */
  staleV0: StaleV0Result;
  /**
   * A GUARD THAT NAMES THE RIGHT OPERATOR OVER THE WRONG OPERANDS.
   *
   * A GATE at 0 on `named`, for the same reason `staleV0` is one: every row is
   * an emitted `if` stating a test the machine does not make. `shapes` is the
   * population the machine code presents and does NOT move with a decompiler
   * fix — it is the liveness number. See `corpus/staleGuards.ts`.
   */
  staleGuards: StaleGuardResult;
  funcs: FuncRec[];
}

// ── Callee loss ────────────────────────────────────────────────────────────

const CALL_RE = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
const CALL_KEYWORDS = new Set([
  "if",
  "while",
  "for",
  "switch",
  "return",
  "sizeof",
  "do",
  "else",
  "__try",
  "__except",
]);

/** Identifiers the emitted C applies as a function. */
function emittedCallees(code: string): Set<string> {
  const s = new Set<string>();
  const lines = code.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim().startsWith("//")) continue;
    // The function's own signature line: `type name(params)` with no `;`.
    if (i < 6 && /^\w[\w *]*\(/.test(l) && !/;\s*$/.test(l)) continue;
    CALL_RE.lastIndex = 0;
    let m: RegExpExecArray | null = CALL_RE.exec(l);
    while (m !== null) {
      if (!CALL_KEYWORDS.has(m[1])) s.add(m[1]);
      m = CALL_RE.exec(l);
    }
  }
  return s;
}

function readArrayBuffer(path: string): ArrayBuffer {
  const b = readFileSync(path);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

type Jcc = { insn: Instruction; target: number; fall: number };
type Anchored =
  | { jc: Jcc; expect: string; addr: number; sense: string; exact: boolean }
  | { why: string };

/** The jump tables recovered for one binary, as a cross-substitution artifact. */
export function serializeJumpTables(tables: Map<number, number[]>): string {
  return JSON.stringify([...tables].sort((a, b) => a[0] - b[0]));
}

/** Load one binary and run every pass that needs more than the emitted text. */
export async function sweepBinary(key: BinKey): Promise<BinResult> {
  const path = binPath(key);
  const af = await new FileSession().loadFile("corpus", `${key}.exe`, readArrayBuffer(path));

  // Cross-substitution: run THIS commit's decompiler over ANOTHER commit's
  // recovered tables. See `substitutedTablesDir` for what that does and does
  // not isolate. Everything downstream — buildCFG here and in the audits, and
  // decompileFunction — reads `jumpTables` rather than `af.jumpTables`, so the
  // substitution is total rather than partial.
  const subDir = substitutedTablesDir();
  let jumpTables = af.jumpTables;
  let tablesFrom: string | null = null;
  if (subDir !== null) {
    const file = join(subDir, `jumpTables_${key}.json`);
    const raw = JSON.parse(readFileSync(file, "utf8")) as [number, number[]][];
    jumpTables = new Map(raw);
    tablesFrom = file;
  }

  const funcInsnMap = buildFuncInsnMap(af.functions, af.instructions);
  const funcMap = new Map(
    af.functions.map((f) => [f.address, { name: f.name, address: f.address }]),
  );

  const res: BinResult = {
    key,
    path,
    is64: af.pe.is64,
    functions: af.functions.length,
    instructions: af.instructions.length,
    jumpTables: jumpTables.size,
    jumpTablesJson: serializeJumpTables(jumpTables),
    tablesFrom,
    throws: 0,
    throwDetail: [],
    polarity: {
      checked: 0,
      ok: 0,
      inverted: 0,
      mismatch: 0,
      skipped: 0,
      a2Checked: 0,
      a2Ok: 0,
      weakChecked: 0,
      weakOk: 0,
      agreeAB: 0,
      disagreeAB: 0,
      onlyB: 0,
    },
    skipReasons: {},
    guards: [],
    loops: { seen: 0, audited: 0, short: 0, skipped: 0 },
    loopSkip: {},
    loopShort: [],
    lineMapCoverage: {
      insnsCovered: 0,
      insnsTotal: 0,
      blocksUncovered: 0,
      blocksTotal: 0,
      funcsWithUncoveredBlock: 0,
      detail: [],
    },
    callees: { pairs: 0, lost: 0, funcsAffected: 0, detail: [] },
    stmtDrops: { tracked: 0, dropped: 0, byKind: {}, funcsAffected: 0, detail: [] },
    drops: [],
    unrecovered: {
      occurrences: 0,
      values: 0,
      branches: 0,
      branchesWithJcc: 0,
      funcsAffected: 0,
      scannedFuncs: 0,
      declsParsed: 0,
      bySite: {},
      byMnemonic: {},
      detail: [],
    },
    unrecoveredSites: [],
    clobbered: {
      occurrences: 0,
      values: 0,
      reads: 0,
      funcsAffected: 0,
      byRegister: {},
      ifs: 0,
      whiles: 0,
      fors: 0,
      summaryFuncs: af.calleeClobbers.byAddress.size,
      summaryNonEmpty: [...af.calleeClobbers.byAddress.values()].filter((v) => v.length > 0).length,
      summaryFull: [...af.calleeClobbers.byAddress.values()].filter(
        (v) => v.length === X64_VOLATILE.length,
      ).length,
      uncoveredMnemonics: af.instructions.filter((i) => !isCoveredMnemonic(i.mnemonic)).length,
    },
    staleV0: emptyStaleV0(),
    staleGuards: emptyStaleGuards(),
    funcs: [],
  };

  for (const func of af.functions) {
    const insns = funcInsnMap.get(func.address) ?? [];
    if (insns.length === 0) {
      res.funcs.push({
        addr: func.address,
        name: func.name,
        size: func.size,
        insns: 0,
        threw: null,
        code: "",
      });
      continue;
    }

    let stackFrame = null;
    let signature = null;
    try {
      stackFrame = analyzeStackFrame(func, af.instructions, af.pe.is64, funcInsnMap);
      signature = inferSignature(func, af.instructions, af.pe.is64, funcInsnMap);
    } catch (e) {
      res.throws++;
      res.throwDetail.push(`prep 0x${func.address.toString(16)}: ${String(e)}`);
    }

    let code = "";
    let lineMap: [number, number][] = [];
    let threw: string | null = null;
    // The structuring step's two sides, for the statement-drop audit. An array
    // rather than a nullable, because a `let` assigned only inside a callback
    // is not narrowed by the typechecker afterwards. Empty when the pipeline
    // returned before structuring (no blocks, or an internal throw), which is
    // the honest reading: nothing was structured, so nothing was dropped.
    const tapped: StructuringTap[] = [];
    try {
      const r = decompileFunction(
        func,
        insns,
        af.xrefMap,
        stackFrame,
        signature,
        af.pe.is64,
        jumpTables,
        af.iatMap,
        af.stringMap,
        funcMap,
        af.structRegistry,
        af.pe.runtimeFunctions,
        (ev) => tapped.push(ev),
        // Whole-image, closed over the call graph, and built by the session
        // rather than here: the measurement must be of the same code the MCP
        // decompile path runs, not of a summary the harness computed for itself.
        af.calleeClobbers,
      );
      code = r.code;
      lineMap = r.lineMap;
    } catch (e) {
      threw = String(e instanceof Error ? (e.stack ?? e.message) : e);
      res.throws++;
      res.throwDetail.push(`decompile 0x${func.address.toString(16)}: ${String(e)}`);
    }

    res.funcs.push({
      addr: func.address,
      name: func.name,
      size: func.size,
      insns: insns.length,
      threw,
      code,
    });
    if (threw !== null) continue;

    if (tapped.length > 0) {
      auditStatementDrops(res, func, insns, tapped[0], jumpTables, af);
    }
    auditLineMapCoverage(res, func, insns, lineMap, jumpTables, af);
    auditCallees(res, func, insns, code, funcMap);
    // The guard pass is what can name a jcc for an unrecovered condition — it
    // is the only thing here that anchors an emitted arm to a machine block —
    // so it runs first and hands over what it resolved.
    const guardsBefore = res.guards.length;
    const jccOf = auditGuardsAndLoops(res, func, insns, code, lineMap, jumpTables, af);
    auditUnrecovered(res, func, code, jccOf);
    // A GUARD THAT NAMES THE RIGHT OPERATOR OVER THE WRONG OPERANDS. Runs after
    // the guard pass because it needs what that pass anchored: an emitted
    // condition at a jcc address is how "the wrong reading reached the page" is
    // distinguished from "the wrong reading was refused". See staleGuards.ts.
    const emittedAt = new Map<number, string>();
    for (let gi = guardsBefore; gi < res.guards.length; gi++) {
      const g = res.guards[gi];
      if (!emittedAt.has(g.jcc)) emittedAt.set(g.jcc, g.cond);
    }
    auditStaleGuards(
      res.staleGuards,
      key,
      func.name,
      func.address,
      buildCFG(func, insns, af.xrefMap, jumpTables),
      emittedAt,
    );
    // Runs AFTER `decompileFunction`, so the shared `StructRegistry` has
    // already evolved exactly as production's pass evolves it. This one drives
    // its own replica of pipeline stages 1-3 — see `staleReads.ts` on why
    // neither side of the question is recoverable from the return value.
    auditStaleV0Reads(
      res.staleV0,
      key,
      func,
      insns,
      af.xrefMap,
      jumpTables,
      af.pe.is64,
      af.iatMap,
      af.stringMap,
      funcMap,
      af.calleeClobbers,
    );
  }

  auditClobbered(res);
  return res;
}

/**
 * Count what the emitter admitted a call destroyed, plus the three construct
 * counts that say whether a guard went missing while it did so.
 *
 * Read off the emitted text rather than the IR for the same reason
 * `auditUnrecovered` is: what matters is the name that reached the page.
 */
function auditClobbered(res: BinResult): void {
  const NAME = /\bclobbered_([a-z0-9]+)_(\d+)\b/g;
  for (const f of res.funcs) {
    if (f.code === "") continue;
    res.clobbered.ifs += f.code.match(/\bif \(/g)?.length ?? 0;
    res.clobbered.whiles += f.code.match(/\bwhile \(/g)?.length ?? 0;
    res.clobbered.fors += f.code.match(/\bfor \(/g)?.length ?? 0;
    const hits = [...f.code.matchAll(NAME)];
    if (hits.length === 0) continue;
    res.clobbered.funcsAffected++;
    res.clobbered.occurrences += hits.length;
    // Every occurrence in the emitted *body* is a read: the declaration is not
    // the emitter's, it is `emitAudits.ts`'s prelude, which is added later and
    // is not part of `code`. Distinct names are counted per function, since the
    // name is scoped to one.
    const distinct = new Set<string>();
    for (const h of hits) {
      distinct.add(h[0]);
      res.clobbered.byRegister[h[1]] = (res.clobbered.byRegister[h[1]] ?? 0) + 1;
    }
    res.clobbered.values += distinct.size;
  }
  res.clobbered.reads = res.clobbered.occurrences;
}

type Af = Awaited<ReturnType<FileSession["loadFile"]>>;
type Func = Af["functions"][number];

/**
 * How much of the machine text carries an address into the emitted line map,
 * counted BOTH per instruction and per CFG block.
 *
 * Per-instruction is the finer instrument and it is the one that located the
 * defects behind `peek-a-bin-qzrl`: a block can be "covered" because one of its
 * five instructions mapped, while the other four did not. Per-block is the
 * coarser view kept for continuity with earlier measurements.
 *
 * Neither is a gate, and neither says a statement is missing — see the long
 * comment on `BinResult.lineMapCoverage` for the three things lost coverage can
 * mean and why only one of them is a defect.
 */
function auditLineMapCoverage(
  res: BinResult,
  func: Func,
  insns: Instruction[],
  lineMap: [number, number][],
  jumpTables: Map<number, number[]>,
  af: Af,
): void {
  const seen = new Set(lineMap.map(([, a]) => a));
  const cov = res.lineMapCoverage;
  for (const i of insns) {
    cov.insnsTotal++;
    if (seen.has(i.address)) cov.insnsCovered++;
  }
  const cfg = buildCFG(func, insns, af.xrefMap, jumpTables);
  let d = 0;
  for (const b of cfg) {
    cov.blocksTotal++;
    const bIns = insns.filter((i) => i.address >= b.startAddr && i.address <= b.endAddr);
    if (bIns.length > 0 && !bIns.some((i) => seen.has(i.address))) d++;
  }
  if (d > 0) {
    cov.blocksUncovered += d;
    cov.funcsWithUncoveredBlock++;
    if (cov.detail.length < 40) {
      cov.detail.push(`0x${func.address.toString(16)} ${func.name} uncoveredBlocks=${d}`);
    }
  }
}

/**
 * Every statement object reachable in a structured tree.
 *
 * The switch is exhaustive against `IRStmt` on purpose. A new statement kind
 * that carries a nested body and is not listed here would make this audit
 * under-count silently — it would report the body's statements as dropped when
 * they are merely nested inside something the walker does not descend into —
 * and a *quiet wrong answer from the instrument* is worse than no instrument.
 * The `never` binding makes `npm run typecheck` fail instead. CLAUDE.md's
 * "Adding new IRExpr / IRStmt kinds" table lists the compiler-caught switches;
 * this is one more.
 */
function collectStmtIdentities(stmts: IRStmt[], into: Set<IRStmt>): void {
  for (const s of stmts) {
    into.add(s);
    switch (s.kind) {
      case "if":
        collectStmtIdentities(s.thenBody, into);
        if (s.elseBody) collectStmtIdentities(s.elseBody, into);
        break;
      case "while":
      case "do_while":
        collectStmtIdentities(s.body, into);
        break;
      case "for":
        collectStmtIdentities([s.init, s.update], into);
        collectStmtIdentities(s.body, into);
        break;
      case "switch":
        for (const c of s.cases) collectStmtIdentities(c.body, into);
        if (s.defaultBody) collectStmtIdentities(s.defaultBody, into);
        break;
      case "try":
        collectStmtIdentities(s.body, into);
        collectStmtIdentities(s.handler, into);
        break;
      case "assign":
      case "store":
      case "call_stmt":
      case "return":
      case "goto":
      case "label":
      case "comment":
      case "raw":
      case "break":
      case "continue":
      case "phi":
      // A branch carries no nested body, and it is extracted before structuring
      // in any case — so one appearing on either side of this audit is itself
      // the finding, which `emit.ts` turns into a counted throw.
      case "branch":
        break;
      default: {
        const _exhaustive: never = s;
        throw new Error(`unhandled IRStmt kind: ${JSON.stringify(_exhaustive)}`);
      }
    }
  }
}

/** The destination of an assignment, when it has a name worth printing. */
function destName(s: IRStmt): string | null {
  if (s.kind !== "assign") return null;
  if (s.dest.kind === "reg" || s.dest.kind === "var") return s.dest.name;
  return null;
}

/**
 * STATEMENT DROPS ACROSS THE STRUCTURER, BY OBJECT IDENTITY.
 *
 * `liftBlock` builds a statement; `structureCFG` either puts that same object
 * somewhere in the tree it returns, or it does not. There is no third outcome
 * and no ambiguity to interpret, which is what makes this a sharper instrument
 * than line map coverage: the two other things lost coverage can mean —
 * folded into a use, relocated — cannot register here. Folding happened in
 * `foldBlock`, before the snapshot the tap takes, and a relocated statement is
 * the same object at another place in the same tree.
 *
 * WHY IT NEEDED A TAP IN `pipeline.ts`. Neither side is recoverable from
 * `decompileFunction`'s return value, and re-running the front half here
 * instead would be a second copy of the pipeline prefix that drifts the moment
 * a stage is inserted between `foldBlock` and `structureCFG` — measuring a
 * different program while looking like it measures this one.
 *
 * This is NOT a gate. See `BinResult.stmtDrops` and README.md.
 */
function auditStatementDrops(
  res: BinResult,
  func: Func,
  insns: Instruction[],
  ev: StructuringTap,
  jumpTables: Map<number, number[]>,
  af: Af,
): void {
  const kept = new Set<IRStmt>();
  collectStmtIdentities(ev.structured, kept);

  const here: { blockId: number; index: number; of: number; stmt: IRStmt }[] = [];
  for (const [blockId, stmts] of ev.lifted) {
    res.stmtDrops.tracked += stmts.length;
    for (let i = 0; i < stmts.length; i++) {
      if (kept.has(stmts[i])) continue;
      here.push({ blockId, index: i, of: stmts.length, stmt: stmts[i] });
    }
  }
  if (here.length === 0) return;

  // Only now is a CFG worth building: the block start address is what makes a
  // drop findable in the disassembly, and the overwhelmingly common case is
  // that there is nothing to find.
  const startOf = new Map(
    buildCFG(func, insns, af.xrefMap, jumpTables).map((b) => [b.id, b.startAddr]),
  );

  res.stmtDrops.dropped += here.length;
  res.stmtDrops.funcsAffected++;
  for (const d of here) {
    const k = d.stmt.kind;
    res.stmtDrops.byKind[k] = (res.stmtDrops.byKind[k] ?? 0) + 1;
    res.drops.push({
      fn: func.address,
      fname: func.name,
      blockId: d.blockId,
      blockAddr: startOf.get(d.blockId) ?? 0,
      addr: "addr" in d.stmt && d.stmt.addr !== undefined ? d.stmt.addr : null,
      kind: k,
      index: d.index,
      of: d.of,
      dest: destName(d.stmt),
    });
  }
  if (res.stmtDrops.detail.length < 40) {
    const kinds = here.map((d) => d.stmt.kind).join(",");
    res.stmtDrops.detail.push(
      `0x${func.address.toString(16)} ${func.name}: ${here.length} dropped (${kinds})`,
    );
  }
}

/**
 * The callees the DISASSEMBLY names — direct `call <imm>` through the function
 * map, indirect `call [mem]` through the IAT — against the identifiers the
 * emitted C applies. A name in the first set and not the second is a call the
 * reader is told does not happen. Expect 0.
 */
function auditCallees(
  res: BinResult,
  func: Func,
  insns: Instruction[],
  code: string,
  funcMap: Map<number, { name: string; address: number }>,
): void {
  const expect = new Set<string>();
  for (const ins of insns) {
    if (ins.mnemonic.toLowerCase() !== "call") continue;
    const op = (ins.opStr ?? "").trim();
    const imm = op.match(/^0x([0-9a-f]+)$/i);
    if (imm) {
      // A call to something that is not a detected function has no name the
      // emitted C could be expected to use.
      const f = funcMap.get(Number.parseInt(imm[1], 16));
      if (f) expect.add(f.name);
      continue;
    }
    const named = ins.comment?.match(/!([A-Za-z_][A-Za-z0-9_@?$]*)\s*$/);
    if (named && op.includes("[")) expect.add(named[1]);
  }
  if (expect.size === 0) return;

  const got = emittedCallees(code);
  const missing = [...expect].filter((n) => !got.has(n));
  res.callees.pairs += expect.size;
  if (missing.length > 0) {
    res.callees.lost += missing.length;
    res.callees.funcsAffected++;
    res.callees.detail.push(`0x${func.address.toString(16)} ${func.name}: ${missing.join(", ")}`);
  }
}

// ── Branch and value recovery ──────────────────────────────────────────────
//
// See `BinResult.unrecovered`. The short version: `__unrecovered_N` is an
// admitted gap in the output, there are hundreds of them, and every gate in
// this harness was structurally blind to all of them — the polarity audit
// because `topOp` finds no operator in one, gcc because the emitter declares it
// and the C is therefore valid.

/** The declaration the emitter puts in the function header for each one. */
const UNREC_DECL = /^\s*\w+\s+(__unrecovered_\d+)\s*;\s*\/\*\s*not recovered(?::\s*(.*?))?\s*\*\//;
/**
 * A use, with the note the emitter attaches to it inline. The comment group is
 * optional and must be ADJACENT: a value whose note was empty is emitted as a
 * bare name, and an unrelated comment later on the same line is not its note.
 */
const UNREC_USE = /(__unrecovered_\d+)(?:\s\/\*\s*(.*?)\s*\*\/)?/g;

/**
 * What an emitted line uses the value FOR.
 *
 * The buckets are descriptive, not load-bearing: `values`, `branches` and the
 * mnemonic breakdown are all derived from the note rather than from this, so a
 * re-spelling in the emitter moves sites between buckets without changing any
 * gated number. "call-target" is the one bucket that encodes a spelling — the
 * function-pointer cast around an indirect call whose target has no name — and
 * it degrades into "other" rather than disappearing.
 */
function siteOf(trimmed: string): string {
  if (/^(?:\}\s*else\s+)?if\s*\(/.test(trimmed)) return "if";
  if (/^(?:\}\s*else\s+)?while\s*\(/.test(trimmed)) return "while";
  if (/^for\s*\(/.test(trimmed)) return "for";
  if (/^\}\s*while\s*\(/.test(trimmed)) return "do_while";
  if (/^switch\s*\(/.test(trimmed)) return "switch";
  if (/^return\b/.test(trimmed)) return "return";
  if (/\(\*\)\s*\(\s*\)\s*\)\s*__unrecovered_/.test(trimmed)) return "call-target";
  return "other";
}

/**
 * EVERY `__unrecovered_N` IN ONE FUNCTION'S EMITTED C, and what it stood for.
 *
 * Counted from the text because that is where the fact lives: the value exists
 * precisely when the IR had nothing to give, so there is no expression, no
 * statement kind and no line-map entry to count instead. The note the emitter
 * writes beside it — the Jcc mnemonic, or the operand it could not read — is
 * the only record of what was lost, and `TAKEN` (this file's own, independently
 * written Jcc table) is what decides whether that note names a branch.
 *
 * `jccOf` comes from the guard pass and is the only route to a machine address:
 * the emitted `if (…)` line carries none of its own. Most entries end up null,
 * and null is recorded rather than omitted.
 */
function auditUnrecovered(
  res: BinResult,
  func: Func,
  code: string,
  jccOf: Map<string, UnrecAnchor>,
): void {
  if (code === "") return;
  const u = res.unrecovered;
  u.scannedFuncs++;
  if (!code.includes("__unrecovered_")) return;

  // Keyed by name, in declaration order — the header is written after the body
  // but printed before it, so the declarations come first in the text.
  const seen = new Map<string, { note: string; site: string | null }>();
  for (const line of code.split("\n")) {
    const decl = UNREC_DECL.exec(line);
    if (decl !== null) {
      u.occurrences++;
      u.declsParsed++;
      const rec = seen.get(decl[1]) ?? { note: "", site: null };
      if (rec.note === "") rec.note = decl[2] ?? "";
      seen.set(decl[1], rec);
      continue;
    }
    const trimmed = line.trim();
    UNREC_USE.lastIndex = 0;
    let m = UNREC_USE.exec(line);
    while (m !== null) {
      u.occurrences++;
      const rec = seen.get(m[1]) ?? { note: "", site: null };
      if (rec.note === "") rec.note = m[2] ?? "";
      if (rec.site === null) rec.site = siteOf(trimmed);
      seen.set(m[1], rec);
      m = UNREC_USE.exec(line);
    }
  }
  if (seen.size === 0) return;

  u.funcsAffected++;
  const branchesHere: string[] = [];
  for (const [name, rec] of seen) {
    const mnem = rec.note.split(/\s/)[0];
    // A branch is one this file's own Jcc table recognises, not anything that
    // merely looks like a mnemonic.
    const isBranch = TAKEN[mnem] !== undefined;
    const at = jccOf.get(name) ?? { jcc: null, mnem: null, jccFrom: "not-in-an-audited-guard" };
    u.values++;
    const site = rec.site ?? "unused";
    u.bySite[site] = (u.bySite[site] ?? 0) + 1;
    if (isBranch) {
      u.branches++;
      u.byMnemonic[mnem] = (u.byMnemonic[mnem] ?? 0) + 1;
      if (at.jcc !== null) u.branchesWithJcc++;
      branchesHere.push(mnem);
    }
    res.unrecoveredSites.push({
      fn: func.address,
      fname: func.name,
      name,
      note: rec.note,
      cause: isBranch ? "branch" : "value",
      site,
      jcc: at.jcc,
      mnem: at.mnem,
      jccFrom: at.jccFrom,
    });
  }
  if (u.detail.length < 40) {
    const b =
      branchesHere.length > 0 ? ` (${branchesHere.length} branch: ${branchesHere.join(",")})` : "";
    u.detail.push(`0x${func.address.toString(16)} ${func.name}: ${seen.size} unrecovered${b}`);
  }
}

/** What the guard pass could resolve about one `__unrecovered_N` in a condition. */
type UnrecAnchor = { jcc: number | null; mnem: string | null; jccFrom: string };

/**
 * Condition polarity over if/while/for/do-while, plus loop exit coverage.
 *
 * Returns, per `__unrecovered_N` name appearing in an audited guard's
 * condition, the jcc that guard was anchored to — the one channel through
 * which an unrecovered condition can be given a machine address, since the
 * emitted `if (…)` line carries none of its own.
 */
function auditGuardsAndLoops(
  res: BinResult,
  func: Func,
  insns: Instruction[],
  code: string,
  lineMap: [number, number][],
  jumpTables: Map<number, number[]>,
  af: Af,
): Map<string, UnrecAnchor> {
  const unrecAnchors = new Map<string, UnrecAnchor>();
  const jccs: Jcc[] = [];
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (!/^j/.test(ins.mnemonic) || ins.mnemonic === "jmp") continue;
    const m = (ins.opStr ?? "").match(/^0x([0-9a-f]+)$/i);
    if (!m || !TAKEN[ins.mnemonic]) continue;
    const fall = insns[i + 1]?.address;
    if (fall === undefined) continue;
    jccs.push({ insn: ins, target: Number.parseInt(m[1], 16), fall });
  }
  if (jccs.length === 0) return unrecAnchors;

  // The same CFG the pipeline builds. An emitted line carries the address of
  // the *instruction* it came from, which is the block's start address only
  // when nothing before it in the block folded away; normalising to the block
  // is what makes "which machine block is this arm" answerable otherwise.
  const cfgBlocks = buildCFG(func, af.instructions, af.xrefMap, jumpTables);
  const blockStartOf = new Map<number, number>();
  for (const b of cfgBlocks) for (const ins of b.insns) blockStartOf.set(ins.address, b.startAddr);
  const machineLoops = detectLoops(cfgBlocks);

  // A block that is nothing but `jmp <imm>` forwards an edge without being a
  // decision, so every arm address is normalised through such blocks first.
  const jmpForward = new Map<number, number>();
  for (const b of cfgBlocks) {
    if (b.insns.length !== 1) continue;
    const only = b.insns[0];
    if (only.mnemonic !== "jmp") continue;
    const m = (only.opStr ?? "").match(/^0x([0-9a-f]+)$/i);
    if (m) jmpForward.set(b.startAddr, Number.parseInt(m[1], 16));
  }
  const landing = (addr: number): number => {
    let a = addr;
    for (let n = 0; n < 8; n++) {
      const nxt = jmpForward.get(a);
      if (nxt === undefined || nxt === a) break;
      a = nxt;
    }
    return a;
  };
  /** Every jcc whose taken or fallthrough edge lands on `addr`, jmps followed. */
  const reaching = (addr: number) =>
    jccs.filter((x) => landing(x.target) === addr || landing(x.fall) === addr);

  const lineAddr = new Map(lineMap);
  const lines = code.split("\n");
  const indentOf = (s: string) => (s.match(/^ */) ?? [""])[0].length;

  const bodyAddrAt = (
    j0: number,
    d: number,
  ): { addr: number; exact: boolean } | { why: string } => {
    let j = j0;
    while (j < lines.length && !lines[j].trim()) j++;
    if (j >= lines.length) return { why: "no-body" };
    const lm = LABEL_LINE.exec(lines[j].trim());
    // A label is *better* evidence than the line map: it is the block's start
    // address by construction.
    if (lm) return { addr: Number.parseInt(lm[2], 16), exact: true };
    if (indentOf(lines[j]) <= d) return { why: "body-outdented" };
    if (OPENER.test(lines[j])) return { why: "body-is-nested-guard" };
    const a = lineAddr.get(j);
    if (a === undefined) return { why: "body-has-no-address" };
    const start = blockStartOf.get(a);
    if (start === undefined || start === a) return { addr: a, exact: true };
    return { addr: start, exact: false };
  };

  const afterLoopAddr = (
    closeLine: number,
    d: number,
  ): { addr: number; exact: boolean } | { why: string } => {
    let j = closeLine + 1;
    while (j < lines.length && !lines[j].trim()) j++;
    if (j >= lines.length) return { why: "nothing-after-loop" };
    const lm = LABEL_LINE.exec(lines[j].trim());
    if (lm) return { addr: Number.parseInt(lm[2], 16), exact: true };
    if (indentOf(lines[j]) !== d) return { why: "after-loop-not-sibling" };
    if (OPENER.test(lines[j])) return { why: "after-loop-is-guard" };
    const a = lineAddr.get(j);
    if (a === undefined) return { why: "after-loop-has-no-address" };
    const start = blockStartOf.get(a);
    if (start === undefined || start === a) return { addr: a, exact: true };
    return { addr: start, exact: false };
  };

  const closingBrace = (openLine: number, d: number): number => {
    const re = new RegExp(`^ {${d}}\\}`);
    for (let j = openLine + 1; j < lines.length; j++) if (re.test(lines[j])) return j;
    return -1;
  };

  const skip = (k: string, why: string) => {
    res.polarity.skipped++;
    const kk = `${k}:${why}`;
    res.skipReasons[kk] = (res.skipReasons[kk] ?? 0) + 1;
  };

  const judge = (
    kind: string,
    cond: string,
    expect: string,
    jc: Jcc,
    bodyAddr: number,
    sense: string,
    anchor: "A" | "A2" | "B",
  ) => {
    const emitted = topOp(cond);
    if (emitted === null) {
      skip(kind, "cond-not-single-comparison");
      return;
    }
    const verdict = emitted === expect ? "OK" : emitted === NEG[expect] ? "INVERTED" : "MISMATCH";
    if (anchor === "A2") {
      res.polarity.a2Checked++;
      if (verdict === "OK") res.polarity.a2Ok++;
    } else if (anchor === "B") {
      res.polarity.weakChecked++;
      if (verdict === "OK") res.polarity.weakOk++;
    } else {
      res.polarity.checked++;
      if (verdict === "OK") res.polarity.ok++;
      else if (verdict === "INVERTED") res.polarity.inverted++;
      else res.polarity.mismatch++;
    }
    res.guards.push({
      jcc: jc.insn.address,
      mnem: jc.insn.mnemonic,
      kind,
      cond: cond.trim(),
      expect,
      emitted,
      verdict,
      sense,
      bodyAddr,
      anchor,
      fn: func.address,
      fname: func.name,
    });
  };

  /** Anchor A: the guard's body identifies the block that runs when it holds. */
  const resolveBody = (i: number, d: number): Anchored => {
    const b = bodyAddrAt(i + 1, d);
    if ("why" in b) return b;
    const cands = reaching(b.addr);
    if (cands.length !== 1) {
      return { why: cands.length === 0 ? "no-jcc-for-body-addr" : "ambiguous-jcc" };
    }
    const jc = cands[0];
    const taken = TAKEN[jc.insn.mnemonic];
    const isTarget = landing(jc.target) === b.addr;
    return {
      jc,
      expect: isTarget ? taken : NEG[taken],
      addr: b.addr,
      sense: isTarget ? "TARGET" : "FALL",
      exact: b.exact,
    };
  };

  /** Anchor B, loops only: the statement after a top-tested loop. */
  const resolveAfterLoop = (closeLine: number, d: number): Anchored => {
    const e = afterLoopAddr(closeLine, d);
    if ("why" in e) return e;
    const cands = reaching(e.addr);
    if (cands.length !== 1) {
      return { why: cands.length === 0 ? "no-jcc-for-exit-addr" : "ambiguous-exit-jcc" };
    }
    const jc = cands[0];
    const taken = TAKEN[jc.insn.mnemonic];
    const isTarget = landing(jc.target) === e.addr;
    // Reaching the exit is the negation of continuing into the loop.
    return {
      jc,
      expect: isTarget ? NEG[taken] : taken,
      addr: e.addr,
      sense: isTarget ? "EXIT=TARGET" : "EXIT=FALL",
      exact: e.exact,
    };
  };

  /**
   * Hand an unrecovered condition the jcc this guard was anchored to.
   *
   * Every top-tested guard and every `do/while` funnels through `reconcile`,
   * whether or not it goes on to be judged — and an unrecovered one never is,
   * because `topOp` finds no operator in it. That is the whole point: this
   * records the address on the way past, so a guard invisible to the polarity
   * audit is still locatable in the disassembly.
   *
   * A guard neither anchor could resolve is recorded with a null address and
   * the reason. Recording it as absent would be the mistake the audit exists to
   * prevent — "not measured" reading as "nothing there".
   */
  const noteUnrecovered = (cond: string, a: Anchored, b: Anchored) => {
    const names = cond.match(/__unrecovered_\d+/g);
    if (names === null) return;
    const src = !("why" in a) ? a : !("why" in b) ? b : null;
    const at: UnrecAnchor =
      src === null
        ? {
            jcc: null,
            mnem: null,
            jccFrom: `unanchored:${(a as { why: string }).why}`,
          }
        : { jcc: src.jc.insn.address, mnem: src.jc.insn.mnemonic, jccFrom: `anchor:${src.sense}` };
    for (const n of names) unrecAnchors.set(n, at);
  };

  const reconcile = (kind: string, cond: string, a: Anchored, b: Anchored) => {
    noteUnrecovered(cond, a, b);
    const aOk = !("why" in a);
    const bOk = !("why" in b);
    if (aOk && bOk) {
      if (a.jc.insn.address === b.jc.insn.address && a.expect === b.expect) res.polarity.agreeAB++;
      else res.polarity.disagreeAB++;
      judge(kind, cond, a.expect, a.jc, a.addr, a.sense, a.exact ? "A" : "A2");
      return;
    }
    if (aOk) {
      judge(kind, cond, a.expect, a.jc, a.addr, a.sense, a.exact ? "A" : "A2");
      return;
    }
    if (bOk) {
      res.polarity.onlyB++;
      judge(kind, cond, b.expect, b.jc, b.addr, b.sense, "B");
      return;
    }
    skip(kind, `${(a as { why: string }).why}|${(b as { why: string }).why}`);
  };

  const auditTopTested = (kind: string, cond: string, i: number, d: number) => {
    const a = resolveBody(i, d);
    let b: Anchored = { why: "no-anchorB-for-if" };
    if (kind !== "if") {
      const close = closingBrace(i, d);
      b = close < 0 ? { why: "no-closing-brace" } : resolveAfterLoop(close, d);
    }
    reconcile(kind, cond, a, b);
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const mIf = line.match(/^(\s*)(?:\}\s*else\s+)?(if|while)\s*\((.*)\)\s*\{\s*$/);
    if (mIf) {
      auditTopTested(mIf[2], mIf[3], i, mIf[1].length);
      continue;
    }

    const mFor = line.match(/^(\s*)for\s*\((.*)\)\s*\{\s*$/);
    if (mFor) {
      const parts = splitFor(mFor[2]);
      if (!parts) {
        skip("for", "unsplittable-header");
        continue;
      }
      auditTopTested("for", parts[1].trim(), i, mFor[1].length);
      continue;
    }

    // do { … } while (c); — the condition governs the BACK EDGE: the loop
    // repeats when control returns to the loop top, so `c` must be the
    // taken-sense operator of the unique conditional jump that targets the
    // loop-top address from inside the loop.
    const mDo = line.match(/^(\s*)\}\s*while\s*\((.*)\)\s*;\s*$/);
    if (!mDo) continue;
    const d = mDo[1].length;
    const cond = mDo[2];
    let openLine = -1;
    for (let k = i - 1; k >= 0; k--) {
      if (new RegExp(`^ {${d}}do\\s*\\{\\s*$`).test(lines[k])) {
        openLine = k;
        break;
      }
    }
    if (openLine < 0) {
      skip("do_while", "no-matching-do");
      continue;
    }
    let a: Anchored;
    const top = bodyAddrAt(openLine + 1, d);
    if ("why" in top) a = top;
    else {
      // A jcc whose *fallthrough* is the top is an entry, not a back edge.
      const cands = jccs.filter((x) => x.target === top.addr && x.insn.address >= top.addr);
      if (cands.length !== 1) {
        a = { why: cands.length === 0 ? "no-back-edge-jcc" : "ambiguous-back-edge" };
      } else {
        a = {
          jc: cands[0],
          expect: TAKEN[cands[0].insn.mnemonic],
          addr: top.addr,
          sense: "BACKEDGE",
          exact: top.exact,
        };
      }
    }
    let b: Anchored;
    const e = afterLoopAddr(i, d);
    if ("why" in e) b = e;
    else {
      const cands = jccs.filter((x) => x.fall === e.addr && x.target <= x.insn.address);
      if (cands.length !== 1) {
        b = { why: cands.length === 0 ? "no-jcc-falls-to-exit" : "ambiguous-exit-jcc" };
      } else {
        b = {
          jc: cands[0],
          expect: TAKEN[cands[0].insn.mnemonic],
          addr: e.addr,
          sense: "BACKEDGE-EXIT",
          exact: e.exact,
        };
      }
    }
    reconcile("do_while", cond, a, b);
  }

  auditLoopExits(res, func, lines, lineAddr, jccs, machineLoops, landing, closingBrace);
  return unrecAnchors;
}

/**
 * EXIT-TEST COVERAGE. A guard that states one of the machine's two tests and
 * drops the other passes the polarity audit perfectly, because the operator it
 * does state matches its own jcc. What that cannot hide is the *count* of ways
 * out: every conditional jump inside a machine loop whose target leaves the
 * loop is an exit, and the emitted loop has to offer at least as many — its own
 * header/back-edge test, plus every `break`, `return` and `goto` out of it.
 *
 * Only innermost loops are audited. A nested loop's exit can leave the outer
 * loop too, so attributing exits in a loop containing another one would need
 * the auditor to decide which loop each exit belongs to, and a wrong
 * attribution is a wrong verdict rather than a missing one.
 */
function auditLoopExits(
  res: BinResult,
  func: Func,
  lines: string[],
  lineAddr: Map<number, number>,
  jccs: Jcc[],
  machineLoops: ReturnType<typeof detectLoops>,
  landing: (a: number) => number,
  closingBrace: (openLine: number, d: number) => number,
): void {
  const loopOpen = /^(\s*)(?:\}\s*else\s+)?(while|for)\s*\((.*)\)\s*\{\s*$/;
  const isInner = (L: { bodyAddrs: Set<number> }) =>
    !machineLoops.some(
      (o) =>
        o !== L &&
        o.bodyAddrs.size < L.bodyAddrs.size &&
        [...o.bodyAddrs].every((x) => L.bodyAddrs.has(x)),
    );

  for (let i = 0; i < lines.length; i++) {
    const m = loopOpen.exec(lines[i]);
    const mDoOpen = /^(\s*)do\s*\{\s*$/.exec(lines[i]);
    if (!m && !mDoOpen) continue;
    res.loops.seen++;
    const d = (m ? m[1] : (mDoOpen as RegExpExecArray)[1]).length;
    const bump = (k: string) => {
      res.loopSkip[k] = (res.loopSkip[k] ?? 0) + 1;
      res.loops.skipped++;
    };

    const close = closingBrace(i, d);
    if (close < 0) {
      bump("no-closing-brace");
      continue;
    }

    // Every machine address the emitted body carries: line addresses plus the
    // addresses `loc_` labels name, which are exact by construction.
    const bodyAddrs: number[] = [];
    for (let j = i + 1; j < close; j++) {
      const lm = LABEL_LINE.exec(lines[j].trim());
      if (lm) bodyAddrs.push(Number.parseInt(lm[2], 16));
      const a2 = lineAddr.get(j);
      if (a2 !== undefined) bodyAddrs.push(a2);
    }
    if (bodyAddrs.length === 0) {
      bump("body-has-no-address");
      continue;
    }

    // The machine loop this is: the innermost one containing EVERY address the
    // emitted body carries. Anything less than full containment is a guess.
    const cands = machineLoops.filter(
      (L) => isInner(L) && bodyAddrs.every((x) => L.bodyAddrs.has(x)),
    );
    if (cands.length === 0) {
      bump("no-containing-inner-loop");
      continue;
    }
    const L = cands.reduce((x, y) => (x.bodyAddrs.size <= y.bodyAddrs.size ? x : y));

    const exits = jccs.filter(
      (x) => L.bodyAddrs.has(x.insn.address) && !L.bodyAddrs.has(landing(x.target)),
    );
    if (exits.length === 0) {
      bump("no-exit-jcc");
      continue;
    }

    // Emitted ways out. The loop's own test is one; a `goto` counts only when
    // the label it names is outside the loop.
    let emitted = 1;
    for (let j = i + 1; j < close; j++) {
      const t = lines[j].trim();
      if (/^break\s*;/.test(t) || /^return\b/.test(t)) emitted++;
      const g = /^goto\s+loc_([0-9A-Fa-f]+)\s*;/.exec(t);
      if (g && !L.bodyAddrs.has(Number.parseInt(g[1], 16))) emitted++;
    }

    res.loops.audited++;
    if (emitted < exits.length) {
      res.loops.short++;
      res.loopShort.push({
        fn: func.address,
        fname: func.name,
        line: i + 1,
        kind: m ? m[2] : "do_while",
        machineExits: exits.length,
        emittedExits: emitted,
        exits: exits.map((e) => `${e.insn.mnemonic}@0x${e.insn.address.toString(16)}`),
      });
    }
  }
}
