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
import { buildCFG, detectLoops } from "../src/disasm/cfg";
import { decompileFunction } from "../src/disasm/decompile/pipeline";
import { buildFuncInsnMap } from "../src/disasm/funcInsns";
import { inferSignature } from "../src/disasm/signatures";
import { analyzeStackFrame } from "../src/disasm/stack";
import type { Instruction } from "../src/disasm/types";
import { FileSession } from "../src/mcp/session";
import { type BinKey, binPath, substitutedTablesDir } from "./preflight";

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

    auditLineMapCoverage(res, func, insns, lineMap, jumpTables, af);
    auditCallees(res, func, insns, code, funcMap);
    auditGuardsAndLoops(res, func, insns, code, lineMap, jumpTables, af);
  }

  return res;
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

/** Condition polarity over if/while/for/do-while, plus loop exit coverage. */
function auditGuardsAndLoops(
  res: BinResult,
  func: Func,
  insns: Instruction[],
  code: string,
  lineMap: [number, number][],
  jumpTables: Map<number, number[]>,
  af: Af,
): void {
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
  if (jccs.length === 0) return;

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

  const reconcile = (kind: string, cond: string, a: Anchored, b: Anchored) => {
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
