/**
 * PROLOGUE / EPILOGUE NORMALISATION: delete the stack-pointer and frame-pointer
 * scaffolding nothing in the emitted C reads — and never move any of it.
 *
 * `rbp = rsp`, `rsp -= 0x28`, `esp += 0xC` after a cdecl call and `/* unlifted:
 * leave *\/` are true statements about the machine and no reader wants them.
 * They survive every earlier pass for one of two reasons: the frame-pointer copy
 * is read (through `[rbp - N]` derefs promotion could not name, or the /GS
 * `x ^ rbp` cookie mix), or the stack-pointer writes form a chain that reads
 * itself — a loop's `add esp, 0xC` after a cdecl call is a phi cycle SSA's
 * dead-code elimination cannot see through. Measured at 6299113, 181/99/96/180
 * of the corpus's 260/279/275/258 functions mention the stack pointer
 * (`corpus/emitAudits.ts`'s `stackPointerScaffolding`).
 *
 * ── WHY DELETION IS SOUND WHERE MOVING IS NOT ──────────────────────────────
 *
 * The standing rule (`ssaopt.ts`'s `isCopyStmt`, `fold.ts`'s single-use
 * inlining, CLAUDE.md) is that NO READ OF RSP MAY BE MOVED TO ANOTHER PROGRAM
 * POINT: the stack pointer has no faithful definition chain in this IR —
 * `push`, `pop` and `call` move it with no statement saying so — so `rsp` at one
 * point and `rsp` at another are different machine values wearing one name, and
 * relocating a read changes what it denotes. That rule forbids *relocation*. It
 * says nothing against deleting a WRITE whose value is read nowhere: with zero
 * surviving reads there is no denotation left to change, and nothing else in
 * the IR observes RSP — a `call` does not read it, a `store` through a named
 * slot does not, a `return` does not. So the pass asks one question of the
 * whole function, "does any read of the stack pointer survive outside the
 * statements about to be deleted?", and deletes only on NO. The same question
 * is asked of the frame register before its establishment goes: a surviving
 * `[rbp - N]` is a slot the frame could not name, and deleting `rbp = rsp`
 * above it would leave a read of an undefined register (it prints anyway, but
 * the C would no longer say where the value came from).
 *
 * ── THE REFUSALS, EACH OF WHICH IS THE WHOLE SOUNDNESS ARGUMENT ────────────
 *
 *  1. **A frame-register read survives** (the register itself or any
 *     `frameRegisterAliases` variable, anywhere in the body, at any nesting
 *     depth) → the establishing statement stays. The /GS `__security_cookie ^
 *     ebp` mix is the common survivor on x86 and is reported as `gs-xor`.
 *  2. **A stack-pointer read survives** (the register at any width, a variable
 *     `destroySSA` split off one of the candidate statements, or an `unlifted`
 *     line whose text names the register) → every stack-pointer candidate
 *     stays. Function-wide, because a surviving read observes the allocation.
 *     The x64 `__security_cookie ^ rsp` mix is the common survivor and is
 *     reported as `gs-xor`; an unnamed `*(T*)(rsp + N)` as `unnamed-slot`.
 *  3. **The address test.** A stack-pointer write is a candidate only where the
 *     instruction stream places it: inside `stack.ts`'s prologue extent
 *     (`StackFrame.spWritesAt`), in an epilogue shape (`add <sp>, imm` /
 *     `lea <sp>, [<fp> ± N]` / `mov <sp>, <fp>` / `leave`, then only `pop`s,
 *     then `ret` or a tail `jmp`), or — x86 only — an `add esp, imm`
 *     after a `call`, the cdecl caller cleanup, or the SEH continuation's
 *     `mov esp, [ebp - N]` reload. A mid-body
 *     `sub rsp, rax` (`alloca`, `__chkstk`) or `sub esp, 8` fails the test, is
 *     itself a read of the register, and so keeps every other candidate too
 *     (refusal 2). Reported as `alloca`.
 *  4. **`leave`** is deleted only in an epilogue shape and only where
 *     `frameDelta !== null` — the register it restores was a frame pointer.
 *     Its own writes are dead by construction (only `ret` follows), so it does
 *     not take part in refusal 2.
 *  5. **The two families are decided together, to a fixpoint.** `ebp = esp`
 *     reads the stack pointer and the epilogue's `esp = ebp` reads the frame
 *     register, so a kept statement in either family can be the read that
 *     refuses the other. Candidates start deletable and lose that standing as
 *     reads are found among the statements that will remain; two rounds settle
 *     it.
 *
 * ── PLACEMENT ──────────────────────────────────────────────────────────────
 *
 * After `synthesizeStructs` and immediately before `emitFunction`, and both
 * halves of that are load-bearing. Not in the lifter, which must keep emitting
 * what the machine does — `firstCalleeSavedWrites`, `matchedStackSlots`,
 * `spoils` and `flagPredecessor` all read the instruction stream. Not before
 * struct synthesis, whose `stackDerivedBases` follows the `rbp = rsp` copy
 * chain to REFUSE a struct over `[rbp + N]`: delete the copy first and every
 * remaining frame deref is fabricated into a struct.
 *
 * ── WHAT IT DOES NOT DO ────────────────────────────────────────────────────
 *
 * It does not delete a `push`/`pop` pair (`matchedStackSlots` already erases
 * those in SSA), a home-slot spill (`dropParameterIdentities` drops the ones
 * promotion named), or a `mov`-based callee-saved save/restore pair — measured
 * and left, see peek-a-bin-5b6q.1's report. It never rewrites an expression:
 * a statement is deleted whole or kept whole. The line map loses the deleted
 * instructions, so `insns covered` falls by exactly what was deleted.
 */
import { loneImmediate, STACK_TRAFFIC } from "../stackIdiom";
import type { DisasmFunction, Instruction, StackFrame } from "../types";
import type { IRExpr, IRFunction, IRStmt } from "./ir";
import { bodiesOf, canonReg, rewriteBodies } from "./ir";
import { frameRegisterAliases } from "./promote";

/** The shapes this pass deletes. */
export type StripShape =
  | "fp-establish"
  | "sp-alloc"
  | "sp-restore"
  | "sp-reload"
  | "leave"
  | "cdecl-cleanup";

/**
 * Why a stack-pointer (or frame-pointer) read survived and refused a deletion.
 *
 *  - `gs-xor` — the /GS cookie mix, `x ^ rsp` / `x ^ ebp`, at the check or the
 *    store. Named and kept on purpose (CLAUDE.md's `/GS` entry).
 *  - `unnamed-slot` — a `*(T*)(sp ± N)` promotion could not name.
 *  - `alloca` — a stack-pointer write the address test refused (a mid-body
 *    `sub rsp, rax` or `sub esp, 8`): it reads the register itself.
 *  - `sp-copy` — a bare copy into another register, `rax = rsp`.
 *  - `unlifted` — an `/* unlifted: … *\/` line whose text names the register.
 *  - `fp-kept` — the read is the kept frame establishment's own `= rsp`
 *    (refusal 1 fired, and `rbp = rsp` reads the stack pointer).
 *  - `sp-kept` — the read is a kept epilogue restore's own `= rbp` (refusal 2
 *    fired, and `rsp = rbp` reads the frame register).
 *  - `other` — anything else (a comparison, an argument, arithmetic).
 */
export type KeptReason =
  | "gs-xor"
  | "unnamed-slot"
  | "alloca"
  | "sp-copy"
  | "unlifted"
  | "fp-kept"
  | "sp-kept"
  | "other";

/** One function's account of the pass, for `corpus/sweep.ts`. */
export interface FrameStripReport {
  /** `stack.ts` recovered a frame-register displacement. */
  framed: boolean;
  /** Candidate statements found, by shape. */
  candidates: Record<StripShape, number>;
  /** Of those, deleted. */
  deleted: Record<StripShape, number>;
  /** Reasons a stack-pointer read survived; empty when none did. */
  spReadsKept: KeptReason[];
  /** Reasons a frame-register read survived; empty when none did. */
  fpReadsKept: KeptReason[];
}

function zeroShapes(): Record<StripShape, number> {
  return {
    "fp-establish": 0,
    "sp-alloc": 0,
    "sp-restore": 0,
    "sp-reload": 0,
    leave: 0,
    "cdecl-cleanup": 0,
  };
}

/**
 * x86 SEH: `mov esp, dword ptr [ebp - N]` — an `__except` continuation
 * re-establishing the stack pointer out of the frame's EH registration record
 * (MSVC's `mov esp, [ebp-18h]` at the head of every handler block). A load of
 * the stack pointer from a frame slot, x86 only; the block it heads has no
 * predecessor in the recovered CFG, since the unwinder enters it. No C
 * statement stands for it, and it is a candidate under the same rule as the
 * rest: deleted only when no read of the stack pointer survives.
 */
function sehReloads(insns: readonly Instruction[], is64: boolean): Set<number> {
  const out = new Set<number>();
  if (is64) return out;
  const re = new RegExp(`^esp,\\s*dword ptr \\[ebp\\s*-\\s*${DISP}\\]$`, "i");
  for (const insn of insns) {
    if (insn.mnemonic.toLowerCase() === "mov" && re.test(insn.opStr.trim())) out.add(insn.address);
  }
  return out;
}

/** Mnemonics that leave the function. A tail `jmp` is judged by its target below. */
const RETURNS = new Set(["ret", "retn", "retf"]);

/** Capstone prints a displacement `0x`-prefixed from 0xA up and bare below. */
const DISP = "(?:0[xX][0-9a-fA-F]+|\\d+)";

/**
 * The epilogue's stack-pointer restore(s), from the instruction stream.
 *
 * ABI grammar, read backwards from each exit: `ret` or a `jmp` out of the
 * function; before it only `pop <reg>`; before those exactly one restore —
 * `leave`, `add <sp>, imm`, `mov <sp>, <fp>` or `lea <sp>, [<fp> ± N]`. This is
 * the same fact `corpus/frameRepurpose.ts` classifies as `restore`, spelled
 * here for the stack pointer rather than the frame register. Anything else
 * before the pops is not an epilogue and marks nothing.
 */
function epilogueRestores(
  insns: readonly Instruction[],
  func: DisasmFunction,
  is64: boolean,
): { restores: Set<number>; leaves: Set<number> } {
  const sp = is64 ? "rsp" : "esp";
  const fp = is64 ? "rbp" : "ebp";
  const restores = new Set<number>();
  const leaves = new Set<number>();
  const restoreRe = new RegExp(`^${sp},\\s*${fp}$`, "i");
  const leaRe = new RegExp(`^${sp},\\s*\\[${fp}\\s*[+-]\\s*${DISP}\\]$`, "i");
  const addRe = new RegExp(`^${sp},\\s*${DISP}$`, "i");
  const lo = func.address;
  const hi = func.address + func.size;

  const exits = (insn: Instruction): boolean => {
    const mn = insn.mnemonic.toLowerCase();
    if (RETURNS.has(mn)) return true;
    if (mn !== "jmp") return false;
    const m = /^0x([0-9a-fA-F]+)$/.exec(insn.opStr.trim());
    if (!m) return true; // `jmp [slot]` / `jmp reg`: an indirect tail transfer
    const target = parseInt(m[1], 16);
    return target < lo || target >= hi;
  };

  for (let i = 0; i < insns.length; i++) {
    if (!exits(insns[i])) continue;
    let j = i - 1;
    while (j >= 0 && insns[j].mnemonic.toLowerCase() === "pop") j--;
    if (j < 0) continue;
    const r = insns[j];
    const mn = r.mnemonic.toLowerCase();
    const ops = r.opStr.trim();
    if (mn === "leave") leaves.add(r.address);
    else if (mn === "add" && addRe.test(ops)) restores.add(r.address);
    else if (mn === "mov" && restoreRe.test(ops)) restores.add(r.address);
    else if (mn === "lea" && leaRe.test(ops)) restores.add(r.address);
  }
  return { restores, leaves };
}

/**
 * The instruction an unlifted `raw` statement carries, with the lifter's
 * `__asm { … }` wrapper taken off — the same reading `emit.ts` gives it.
 */
function unliftedText(text: string): string {
  return (/^__asm \{(.*)\}$/.exec(text)?.[1] ?? text).trim().toLowerCase();
}

/** How far back from an `add esp, imm` the `call` it cleans up after may sit. */
const CDECL_LOOKBACK = 8;

/**
 * x86 cdecl caller cleanup: `add esp, imm` after a `call`, with nothing that
 * touches the stack or transfers control between the two. The callee has
 * returned and the pushed arguments are being discarded; no C statement stands
 * for it. MSVC routinely interleaves — `call f / add [ebp-8], edi / add esp,
 * 0x10` (t32 0x4027c3) — so "the instruction after the call" is not the
 * grammar; a bounded walk back over instructions that neither name ESP nor
 * push, pop, call or jump is. x86 only — the x64 ABI has no caller cleanup, so
 * on x64 the same shape would be a claim this pass has no evidence for.
 */
function cdeclCleanups(insns: readonly Instruction[], is64: boolean): Set<number> {
  const out = new Set<number>();
  if (is64) return out;
  for (let i = 1; i < insns.length; i++) {
    const insn = insns[i];
    if (insn.mnemonic.toLowerCase() !== "add") continue;
    const parts = insn.opStr.split(",").map((p) => p.trim().toLowerCase());
    if (parts[0] !== "esp" || loneImmediate(parts[1] ?? "") === null) continue;
    for (let j = i - 1, steps = 0; j >= 0 && steps < CDECL_LOOKBACK; j--, steps++) {
      const mn = insns[j].mnemonic.toLowerCase();
      if (mn === "call") {
        out.add(insn.address);
        break;
      }
      if (
        STACK_TRAFFIC.has(mn) ||
        mn.startsWith("j") ||
        RETURNS.has(mn) ||
        mn === "leave" ||
        /\besp\b/i.test(insns[j].opStr)
      )
        break;
    }
  }
  return out;
}

const isCanon = (e: IRExpr, canon: string): boolean =>
  e.kind === "reg" && canonReg(e.name) === canon;

/**
 * The expressions a statement READS — its destination, when a register or a
 * variable, is not one. Nested statement lists are the caller's business
 * (`bodiesOf`); a `for`'s `init`/`update` are single statements and are visited
 * here. A `comment` reads nothing (an x86 SEH trylevel note is prose, not a
 * register mention); a `raw` is handled by the caller from its text.
 */
function forEachRead(stmt: IRStmt, visit: (e: IRExpr, ancestors: IRExpr[]) => void): void {
  const walk = (root: IRExpr): void => {
    const rec = (e: IRExpr, ancestors: IRExpr[]): void => {
      visit(e, ancestors);
      const inner = [e, ...ancestors];
      switch (e.kind) {
        case "binary":
          rec(e.left, inner);
          rec(e.right, inner);
          break;
        case "unary":
        case "cast":
          rec(e.operand, inner);
          break;
        case "deref":
          rec(e.address, inner);
          break;
        case "call":
          // The target is evaluated BEFORE the arguments, so it is a read like
          // any other: `call [ebp + 8]` reads the frame register, and a walk
          // that missed it would let this pass delete the frame copy out from
          // under the transfer (peek-a-bin-s1f6.1).
          if (e.targetExpr) rec(e.targetExpr, inner);
          for (const a of e.args) rec(a, inner);
          break;
        case "ternary":
          rec(e.condition, inner);
          rec(e.then, inner);
          rec(e.else, inner);
          break;
        case "field_access":
          rec(e.base, inner);
          break;
        case "array_access":
          rec(e.base, inner);
          rec(e.index, inner);
          break;
        default:
          break;
      }
    };
    rec(root, []);
  };
  switch (stmt.kind) {
    case "assign":
      if (stmt.dest.kind !== "reg" && stmt.dest.kind !== "var") walk(stmt.dest);
      walk(stmt.src);
      break;
    case "store":
      // The address is a dereference for the reader's purposes, so a bare
      // `*(T*)(esp) = v` classifies as an unnamed slot like any other.
      walk({ kind: "deref", address: stmt.address, size: stmt.size });
      walk(stmt.value);
      break;
    case "call_stmt":
      walk(stmt.call);
      if (stmt.resultDest && stmt.resultDest.kind !== "reg" && stmt.resultDest.kind !== "var")
        walk(stmt.resultDest);
      break;
    case "return":
      if (stmt.value) walk(stmt.value);
      break;
    case "if":
    case "while":
    case "do_while":
      walk(stmt.condition);
      break;
    case "for":
      forEachRead(stmt.init, visit);
      walk(stmt.condition);
      forEachRead(stmt.update, visit);
      break;
    case "switch":
      walk(stmt.expr);
      break;
    case "try":
      if (stmt.filterExpr) walk(stmt.filterExpr);
      break;
    case "phi":
      for (const op of stmt.operands) walk(op.value);
      break;
    case "branch":
      walk(stmt.condition);
      break;
    case "raw":
    case "comment":
    case "goto":
    case "label":
    case "break":
    case "continue":
      break;
    default: {
      // Compile error if a new IRStmt kind is added without handling it here.
      const _exhaustive: never = stmt;
      throw new Error(`unhandled statement kind: ${String(_exhaustive)}`);
    }
  }
}

/** Every statement in the tree, at any depth (`bodiesOf` is the one declaration of nesting). */
function forEachStmt(list: readonly IRStmt[], visit: (s: IRStmt) => void): void {
  for (const s of list) {
    visit(s);
    for (const nested of bodiesOf(s)) forEachStmt(nested, visit);
  }
}

/**
 * What a surviving read of the register looks like, for the report. `ancestors`
 * is the expression chain above the read, nearest first; `insn` the machine
 * instruction the statement carries the address of, which is what tells a
 * `sub esp, 8` (alloca) from a `lea eax, [esp + 8]` (an unnamed slot) after
 * `destroySSA` has swapped either's destination for a variable.
 */
function classify(
  stmt: IRStmt,
  ancestors: readonly IRExpr[],
  canon: string,
  insn: Instruction | undefined,
): KeptReason {
  const parent = ancestors[0];
  if (parent?.kind === "binary" && parent.op === "^") return "gs-xor";
  // Inside an address: a slot promotion could not name, indexed or not.
  if (ancestors.some((a) => a.kind === "deref")) return "unnamed-slot";
  if (insn !== undefined && stmt.kind === "assign") {
    const mn = insn.mnemonic.toLowerCase();
    const dest = insn.opStr.split(",")[0]?.trim().toLowerCase() ?? "";
    const destIsReg = dest !== "" && canonReg(dest) === canon;
    if ((mn === "sub" || mn === "add" || mn === "lea") && destIsReg) return "alloca";
    if (mn === "lea") return "unnamed-slot";
    if (mn === "mov" && parent === undefined) return "sp-copy";
  }
  if (
    parent?.kind === "binary" &&
    (parent.op === "+" || parent.op === "-") &&
    (parent.left.kind === "const" || parent.right.kind === "const")
  ) {
    // `rsp + 0x30` as a lea promotion could not spell — a slot without a name.
    return "unnamed-slot";
  }
  if (stmt.kind === "assign" && stmt.dest.kind === "reg") {
    if (canonReg(stmt.dest.name) === canon) return "alloca";
    if (parent === undefined) return "sp-copy";
  }
  return "other";
}

/**
 * Delete the frame scaffolding the emitted C does not read. See the module
 * docstring for the rule, its refusals and the soundness argument.
 *
 * `insns` is the function's own instruction stream in address order — the
 * epilogue grammar and the cdecl-cleanup shape are read off it, never off the
 * IR. `frame` is `stack.ts`'s record, `null` when it had nothing to say; the
 * `?? null` / `?? []` reads below are the worker-boundary rule every consumer
 * of `StackFrame` follows.
 */
export function stripFrameScaffolding(
  func: IRFunction,
  insns: readonly Instruction[],
  extent: DisasmFunction,
  frame: StackFrame | null,
  is64: boolean,
  report?: (r: FrameStripReport) => void,
): IRFunction {
  const spCanon = "rsp";
  const fpCanon = "rbp";
  const frameDelta = frame?.frameDelta ?? null;
  const establishedAt = frame?.frameEstablishedAt ?? null;
  const spWritesAt = new Set<number>(frame?.spWritesAt ?? []);
  const { restores, leaves } = epilogueRestores(insns, extent, is64);
  const cleanups = cdeclCleanups(insns, is64);
  const reloads = sehReloads(insns, is64);
  const insnAt = new Map(insns.map((i) => [i.address, i]));
  const insnOf = (s: IRStmt): Instruction | undefined =>
    s.kind === "assign" && s.addr !== undefined ? insnAt.get(s.addr) : undefined;

  // ── 1. Candidates, by the address each statement carries ──
  const shapeOf = new Map<IRStmt, StripShape>();
  const candidates = zeroShapes();
  /** Variables `destroySSA` split off a candidate's destination: `rsp_1` in `rsp_1 = rsp - 0x30`. */
  const spVars = new Set<string>();
  const fpVars = frameRegisterAliases(func.body, is64, frameDelta, establishedAt);

  forEachStmt(func.body, (s) => {
    if (s.kind === "raw") {
      if (s.addr !== undefined && leaves.has(s.addr) && unliftedText(s.text) === "leave") {
        shapeOf.set(s, "leave");
        candidates.leave++;
      }
      return;
    }
    if (s.kind !== "assign" || s.addr === undefined) return;
    const dest = s.dest;
    const destIsSp = isCanon(dest, spCanon) || (dest.kind === "var" && spWritesAt.has(s.addr));
    const destIsFp = isCanon(dest, fpCanon) || (dest.kind === "var" && fpVars.has(dest.name));
    let shape: StripShape | null = null;
    if (establishedAt !== null && s.addr === establishedAt && (destIsFp || dest.kind === "var")) {
      shape = "fp-establish";
    } else if (spWritesAt.has(s.addr) && (destIsSp || dest.kind === "var")) {
      shape = "sp-alloc";
    } else if (restores.has(s.addr) && (destIsSp || dest.kind === "var")) {
      shape = "sp-restore";
    } else if (cleanups.has(s.addr) && (destIsSp || dest.kind === "var")) {
      shape = "cdecl-cleanup";
    } else if (reloads.has(s.addr) && (destIsSp || dest.kind === "var")) {
      shape = "sp-reload";
    }
    if (shape === null) return;
    shapeOf.set(s, shape);
    candidates[shape]++;
    if (shape !== "fp-establish" && dest.kind === "var") spVars.add(dest.name);
  });

  const isSpRead = (e: IRExpr): boolean =>
    isCanon(e, spCanon) || (e.kind === "var" && spVars.has(e.name));
  const isFpRead = (e: IRExpr): boolean =>
    isCanon(e, fpCanon) || (e.kind === "var" && fpVars.has(e.name));
  const spText = is64 ? /\brsp\b|\besp\b|\bsp\b/i : /\besp\b|\bsp\b/i;
  const fpText = is64 ? /\brbp\b|\bebp\b|\bbp\b/i : /\bebp\b|\bbp\b/i;

  // ── 2. The fixpoint: a kept statement in one family can refuse the other ──
  let fpOn = candidates["fp-establish"] > 0;
  let spOn =
    candidates["sp-alloc"] +
      candidates["sp-restore"] +
      candidates["sp-reload"] +
      candidates["cdecl-cleanup"] >
    0;
  const leaveOn = candidates.leave > 0 && frameDelta !== null;
  const spKept = new Set<KeptReason>();
  const fpKept = new Set<KeptReason>();

  const deletable = (s: IRStmt): boolean => {
    const shape = shapeOf.get(s);
    if (shape === undefined) return false;
    if (shape === "fp-establish") return fpOn;
    if (shape === "leave") return leaveOn;
    return spOn;
  };

  for (let round = 0; round < 3; round++) {
    spKept.clear();
    fpKept.clear();
    forEachStmt(func.body, (s) => {
      if (deletable(s)) return;
      const shape = shapeOf.get(s);
      if (s.kind === "raw") {
        if (shape === "leave") return; // a kept `leave` names no register in the IR
        if (spText.test(s.text)) spKept.add("unlifted");
        if (fpText.test(s.text)) fpKept.add("unlifted");
        return;
      }
      forEachRead(s, (e, ancestors) => {
        // A kept candidate's own reads: the frame establishment reads the stack
        // pointer and an epilogue restore reads the frame register, so each
        // family's refusal is reported as the other's reason. A kept
        // stack-pointer candidate reading the stack pointer itself
        // (`rsp -= 0x30`) is the candidate, not a reason.
        if (isSpRead(e)) {
          if (shape === undefined) spKept.add(classify(s, ancestors, spCanon, insnOf(s)));
          else if (shape === "fp-establish") spKept.add("fp-kept");
        }
        if (isFpRead(e)) {
          if (shape === undefined) fpKept.add(classify(s, ancestors, fpCanon, insnOf(s)));
          else if (shape !== "fp-establish") fpKept.add("sp-kept");
        }
      });
    });
    let changed = false;
    if (fpOn && fpKept.size > 0) {
      fpOn = false;
      changed = true;
    }
    if (spOn && spKept.size > 0) {
      spOn = false;
      changed = true;
    }
    if (!changed) break;
  }

  // ── 3. Delete, whole statements only ──
  const deleted = zeroShapes();
  const prune = (list: IRStmt[]): IRStmt[] =>
    list
      .filter((s) => {
        if (!deletable(s)) return true;
        deleted[shapeOf.get(s) as StripShape]++;
        return false;
      })
      .map((s) => rewriteBodies(s, prune));
  const body = prune(func.body);

  report?.({
    framed: frameDelta !== null,
    candidates,
    deleted,
    spReadsKept: [...spKept].sort(),
    fpReadsKept: [...fpKept].sort(),
  });

  return body === func.body ? func : { ...func, body };
}
