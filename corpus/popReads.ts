/**
 * A REGISTER A `pop` WROTE, READ IN THE EMITTED C UNDER ITS PREVIOUS VALUE.
 *
 * `liftBlock` skips `push` and `pop` — RSP moves with nothing in the IR
 * recording it, so there is no faithful definition chain over the stack slot
 * (CLAUDE.md, "No read of RSP may be moved to another program point"). The one
 * exception is MSVC's two-byte `mov reg, imm`, spelled `push <imm>` /
 * `pop <reg>`, which `stackIdiom.ts` pairs and the lifter turns into an
 * assignment — block-locally since peek-a-bin-3axd, and across a branch since
 * peek-a-bin-6ilz, where the definition lands in each PREDECESSOR and
 * `buildSSA` builds the phi. Every other `pop <reg>` is therefore **not a
 * definition in SSA**, so a later read of that register binds to the value it
 * held BEFORE the pop, and the emitted C names something the machine no longer
 * has there.
 *
 * WHAT THIS AUDIT ASKS, and the one thing it must not get wrong: for each
 * `pop <reg>`, walk forward over the CFG to the first instruction that WRITES
 * that register **on the machine**, and report every read of it in the
 * post-fold IR on the way. The write test has to be the machine's, not the
 * IR's. Asking the IR instead attributes other classes' defects to the pop:
 * t32!sub_40D99A does `pop ecx` (cdecl cleanup) and then `mov ecx, [ebp+8]`,
 * whose IR definition `foldBlock` inlines into its single in-block use while
 * ECX is live out of the block — so the reads two blocks later name an ECX
 * nothing assigns, and against an IR-level write test they read as the pop's
 * fault. They are not: the pop's value is dead there. Measured, the difference
 * is 54 reported against 7 real on t32 (peek-a-bin-4ynk, measured at 6952d53).
 *
 * TWO VERDICTS, and only one is a defect:
 *
 *   `wrong`   — the machine reads the popped value and the C names the
 *               pre-pop one. A store through the wrong pointer, a loop
 *               counter read after it was restored.
 *   `benign`  — the paired push pushed the SAME register and nothing wrote it
 *               in between, so the pop restores a value the C never
 *               reassigned. Emitting nothing for the pop is CORRECT here, and
 *               that is why refusing every pop (lifting it as
 *               `reg = <unknown>`) is not free: it would trade these for an
 *               `__unrecovered_N`.
 *
 * The `benign` split is decided from the instruction stream by a balanced-depth
 * backward scan in ADDRESS order, which is an approximation of path order: it
 * can only move a row from `wrong` to `benign`, so the defect count it reports
 * is a LOWER bound. Everything else — which reads exist at all, and what the
 * emitted IR says — is read off the program the pipeline builds.
 */

import type { CalleeClobbers } from "../src/disasm/callSummary";
import { buildCFG } from "../src/disasm/cfg";
import { solePredecessor } from "../src/disasm/decompile/flagModel";
import { blockLiveOut, foldBlock } from "../src/disasm/decompile/fold";
import type { IRExpr, IRReg, IRStmt } from "../src/disasm/decompile/ir";
import { canonReg } from "../src/disasm/decompile/ir";
import {
  firstCalleeSavedWrites,
  liftBlock,
  liftCrossBlockPops,
} from "../src/disasm/decompile/lifter";
import { RegState } from "../src/disasm/decompile/regstate";
import type { SSAContext } from "../src/disasm/decompile/ssa";
import { buildSSA, detectNaturalLoops } from "../src/disasm/decompile/ssa";
import { destroySSA } from "../src/disasm/decompile/ssadestroy";
import { ssaOptimize } from "../src/disasm/decompile/ssaopt";
import { STACK_TRAFFIC } from "../src/disasm/stackIdiom";
import type { DisasmFunction, Instruction, Xref } from "../src/disasm/types";

/** One read of a register whose value a `pop` had already replaced. */
export interface PopReadRec {
  bin: string;
  func: string;
  funcAddr: number;
  /** The `pop` whose value the machine has here. */
  popAddr: number;
  reg: string;
  canon: string;
  /** The instruction that reads it, and its text. */
  readAddr: number;
  insn: string;
  /** How the emitted IR spells the register at that instruction. */
  readName: string;
  /** What the paired push pushed: `push-same-reg`, `push-imm`, … */
  pushKind: string;
  pushAddr: number | undefined;
  /** `wrong`, `ret-wrong` or `ret-benign` — see the module docstring. */
  verdict: string;
}

export interface PopReadResult {
  /** Functions the replica got through. Instrument liveness. */
  functionsScanned: number;
  /** Pops with a register destination, RSP excluded. Instrument liveness. */
  pops: number;
  /** Of those, the ones the lifter DOES define (peek-a-bin-3axd's rule). */
  popsLifted: number;
  /** Reads of a popped register bound to its pre-pop value. GATE candidate. */
  wrong: number;
  /** Pops accounted for by the `wrong` reads. */
  popsWrong: number;
  funcsWrong: number;
  /** Reads where the pop restores an unchanged value: correct output today. */
  benign: number;
  /**
   * A `ret` is an implicit read of the return register, and it is counted
   * apart from the two above rather than folded into them. `liftBlock` gives
   * EVERY `ret` a `return <retReg>`, including in functions that return
   * nothing, so a `pop eax` before one is only sometimes a claim about a
   * value. `retWrong` is a `return` of a value the machine popped and the C
   * names from before the pop; `retBenign` is a same-register restore, where
   * emitting nothing for the pop is what makes the `return` CORRECT — it is
   * the population a blanket refusal of every pop would destroy, and it is
   * NOT zero (t32!sub_40A925 is `push eax` / `pop eax` / `ret 4`).
   */
  retWrong: number;
  retBenign: number;
  rows: PopReadRec[];
}

export function emptyPopReads(): PopReadResult {
  return {
    functionsScanned: 0,
    pops: 0,
    popsLifted: 0,
    wrong: 0,
    popsWrong: 0,
    funcsWrong: 0,
    benign: 0,
    retWrong: 0,
    retBenign: 0,
    rows: [],
  };
}

// ── Reading the IR, written out here rather than imported ──────────────────
//
// Same reasoning as `staleReads.ts`: borrowing `ssadestroy.ts`'s notion of a
// read would make the audit share a blind spot with the code under test. The
// `default:` arms are safe because a new expression kind can only make this see
// fewer reads, never invent one.

function regsIn(e: IRExpr, out: IRReg[]): void {
  switch (e.kind) {
    case "reg":
      out.push(e);
      return;
    case "binary":
      regsIn(e.left, out);
      regsIn(e.right, out);
      return;
    case "unary":
    case "cast":
      regsIn(e.operand, out);
      return;
    case "deref":
      regsIn(e.address, out);
      return;
    case "call":
      for (const a of e.args) regsIn(a, out);
      return;
    case "ternary":
      regsIn(e.condition, out);
      regsIn(e.then, out);
      regsIn(e.else, out);
      return;
    case "field_access":
      regsIn(e.base, out);
      return;
    case "array_access":
      regsIn(e.base, out);
      regsIn(e.index, out);
      return;
    default:
      return;
  }
}

function readsOf(stmt: IRStmt): IRReg[] {
  const out: IRReg[] = [];
  switch (stmt.kind) {
    case "assign":
      // A `deref` destination is an address computation, so its registers are
      // read even though the statement is a write.
      if (stmt.dest.kind === "deref") regsIn(stmt.dest, out);
      regsIn(stmt.src, out);
      break;
    case "store":
      regsIn(stmt.address, out);
      regsIn(stmt.value, out);
      break;
    case "call_stmt":
      for (const a of stmt.call.args) regsIn(a, out);
      break;
    case "return":
      if (stmt.value) regsIn(stmt.value, out);
      break;
    // A guard's registers are reads like any other.
    case "branch":
      regsIn(stmt.condition, out);
      break;
  }
  return out;
}

function addrOf(stmt: IRStmt): number | undefined {
  return (stmt as { addr?: number }).addr;
}

// ── The machine model: which registers an instruction reads and writes ──────
//
// Independent of `ir.ts`'s tables on purpose — this asks about the MACHINE, and
// the whole point of the audit is to compare the machine against the IR. It is
// deliberately crude in the safe direction: an unrecognised mnemonic with a
// register first operand counts as a WRITE, which ends the walk early and
// reports fewer rows rather than more.

const ALIASES: Record<string, string[]> = {
  rax: ["rax", "eax", "ax", "al", "ah"],
  rbx: ["rbx", "ebx", "bx", "bl", "bh"],
  rcx: ["rcx", "ecx", "cx", "cl", "ch"],
  rdx: ["rdx", "edx", "dx", "dl", "dh"],
  rsi: ["rsi", "esi", "si", "sil"],
  rdi: ["rdi", "edi", "di", "dil"],
  rbp: ["rbp", "ebp", "bp", "bpl"],
  rsp: ["rsp", "esp", "sp", "spl"],
  r8: ["r8", "r8d", "r8w", "r8b"],
  r9: ["r9", "r9d", "r9w", "r9b"],
  r10: ["r10", "r10d", "r10w", "r10b"],
  r11: ["r11", "r11d", "r11w", "r11b"],
  r12: ["r12", "r12d", "r12w", "r12b"],
  r13: ["r13", "r13d", "r13w", "r13b"],
  r14: ["r14", "r14d", "r14w", "r14b"],
  r15: ["r15", "r15d", "r15w", "r15b"],
};
const ALIAS_RE = new Map<string, RegExp>(
  Object.entries(ALIASES).map(([c, names]) => [c, new RegExp(`\\b(${names.join("|")})\\b`, "i")]),
);
const CANON_OF = new Map<string, string>();
for (const [c, names] of Object.entries(ALIASES)) for (const n of names) CANON_OF.set(n, c);

/** Mnemonics whose register first operand is written without being read. */
const PURE_WRITE = new Set([
  "mov",
  "movabs",
  "movzx",
  "movsx",
  "movsxd",
  "lea",
  "pop",
  "sete",
  "setne",
  "setz",
  "setnz",
  "seta",
  "setae",
  "setb",
  "setbe",
  "setg",
  "setge",
  "setl",
  "setle",
  "sets",
  "setns",
]);
/** Mnemonics that write no register at all. */
const NO_DEST = new Set([
  "push",
  "cmp",
  "test",
  "jmp",
  "call",
  "ret",
  "retn",
  "nop",
  "int",
  "int3",
  "ud2",
  "leave",
  "hlt",
]);
/** Caller-saved: a call destroys these whatever the callee turns out to do. */
const VOLATILE32 = new Set(["rax", "rcx", "rdx"]);
const VOLATILE64 = new Set(["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]);
/** Implicit register users, keyed by which canonical registers they touch. */
const STRING_OP = /^(movs|stos|scas|lods|cmps)[bwdq]?$/;
const STRING_REGS = new Set(["rsi", "rdi", "rcx", "rax"]);

function canonOf(text: string): string | null {
  return CANON_OF.get(text.trim().toLowerCase()) ?? null;
}

function baseMnemonic(insn: Instruction): string {
  return insn.mnemonic.toLowerCase().replace(/^(rep|repe|repz|repne|repnz|lock)\s+/, "");
}

function machineWrites(insn: Instruction, canon: string, is64: boolean): boolean {
  const mn = baseMnemonic(insn);
  if (mn === "call") return (is64 ? VOLATILE64 : VOLATILE32).has(canon);
  if (mn.startsWith("j")) return false;
  if (STRING_OP.test(mn)) return STRING_REGS.has(canon);
  const ops = insn.opStr.split(",");
  if (["mul", "imul", "div", "idiv"].includes(mn) && ops.length === 1)
    return canon === "rax" || canon === "rdx";
  if (mn === "cdq" || mn === "cqo") return canon === "rdx";
  if (mn === "cpuid") return ["rax", "rbx", "rcx", "rdx"].includes(canon);
  if (mn === "xchg") return ops.some((op) => !op.includes("[") && canonOf(op) === canon);
  if (NO_DEST.has(mn)) return false;
  const first = ops[0]?.trim().toLowerCase() ?? "";
  if (first.includes("[")) return false;
  return canonOf(first) === canon;
}

function machineReads(insn: Instruction, canon: string): boolean {
  const mn = baseMnemonic(insn);
  const re = ALIAS_RE.get(canon);
  if (!re) return false;
  if (STRING_OP.test(mn)) return STRING_REGS.has(canon);
  const ops = insn.opStr.split(",");
  for (let i = 0; i < ops.length; i++) {
    const op = ops[i].trim().toLowerCase();
    if (!re.test(op)) continue;
    // A register-only first operand of a pure write is written, not read.
    if (i === 0 && !op.includes("[") && PURE_WRITE.has(mn) && canonOf(op) === canon) continue;
    return true;
  }
  return false;
}

/**
 * What the `pop` at `popIndex` takes off the stack, classified.
 *
 * A balanced-depth backward scan over the function's instructions in ADDRESS
 * order. Address order is not path order, so this is evidence for the `benign`
 * split and for nothing else; see the module docstring on why that direction is
 * the safe one.
 */
function pairedPush(
  insns: Instruction[],
  popIndex: number,
  canon: string,
  is64: boolean,
): { kind: string; addr: number | undefined; benign: boolean } {
  let depth = 1;
  for (let i = popIndex - 1; i >= 0; i--) {
    const p = insns[i];
    const mn = p.mnemonic.toLowerCase();
    if (mn === "push") {
      depth--;
      if (depth > 0) continue;
      const op = p.opStr.trim().toLowerCase();
      const pushed = canonOf(op);
      if (pushed !== canon)
        return {
          kind: pushed !== null ? "push-other-reg" : /^[-0]/.test(op) ? "push-imm" : "push-mem",
          addr: p.address,
          benign: false,
        };
      // The pushed value IS this register's. Benign only while nothing between
      // the two instructions has changed it — that is the whole discriminator
      // between a save/restore the emitted C already reads correctly and a
      // restore of a value the C has since overwritten.
      let written = false;
      for (let j = i + 1; j < popIndex; j++)
        if (machineWrites(insns[j], canon, is64)) written = true;
      return { kind: "push-same-reg", addr: p.address, benign: !written };
    }
    if (mn === "pop") {
      depth++;
      continue;
    }
    if (mn === "call") return { kind: "call-boundary", addr: undefined, benign: false };
    if (STACK_TRAFFIC.has(mn)) return { kind: `traffic-${mn}`, addr: undefined, benign: false };
    if (/\b[er]?sp\b/i.test(p.opStr)) return { kind: "sp-touched", addr: undefined, benign: false };
  }
  return { kind: "unpaired", addr: undefined, benign: false };
}

/**
 * One function's worth of the audit, over a replica of `pipeline.ts` stages
 * 1-3 plus `foldBlock`.
 *
 * The replica is the same one `staleReads.ts` runs and for the same reason:
 * neither side of the question is recoverable from `decompileFunction`'s
 * return value — the reads have to be read off the lowered, folded statement
 * list, and `foldBlock` is what decides whether a read reaches the page at all.
 */
export function auditPopReads(
  res: PopReadResult,
  bin: string,
  func: DisasmFunction,
  insns: Instruction[],
  xrefMap: Map<number, Xref[]>,
  jumpTables: Map<number, number[]>,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
  calleeClobbers: CalleeClobbers | undefined,
): void {
  let ctx: SSAContext;
  /** Pop addresses the LIFTER emitted a register definition for. */
  const liftedPops = new Set<number>();
  try {
    const blocks = buildCFG(func, insns, xrefMap, jumpTables);
    if (blocks.length === 0) return;
    const lifted = new Map<number, IRStmt[]>();
    const calleeSavedFirstWrite = is64 ? undefined : firstCalleeSavedWrites(blocks);
    const blockById0 = new Map(blocks.map((b) => [b.id, b]));
    for (const b of blocks)
      lifted.set(
        b.id,
        liftBlock(
          b,
          new RegState(),
          is64,
          iatMap,
          stringMap,
          funcMap,
          calleeSavedFirstWrite,
          calleeClobbers,
          solePredecessor(b, blockById0),
        ),
      );
    // `pipeline.ts` step 2b, and it must run BEFORE `liftedPops` is collected:
    // a cross-block `push imm` / `pop reg` is defined in the predecessors, and
    // the assignment carries the POP's address precisely so the scan below sees
    // it (peek-a-bin-6ilz).
    liftCrossBlockPops(blocks, lifted);
    // Asked of the LIFT, not of the lowered program: `push 0x1a / pop eax /
    // ret` really is lifted (peek-a-bin-3axd's rule), copy propagation folds
    // the constant into the `return`, and DCE then deletes the assignment — so
    // nothing survives at the pop's address and a post-fold test calls the pop
    // unlifted. That reported four false `ret-wrong` rows per x86 binary, each
    // a function returning a constant the emitted C states correctly.
    for (const [, stmts] of lifted)
      for (const st of stmts) {
        if (st.kind !== "assign" || st.dest.kind !== "reg") continue;
        const a = addrOf(st);
        if (a !== undefined) liftedPops.add(a);
      }
    ctx = buildSSA(blocks, lifted);
    const natural = detectNaturalLoops(blocks, ctx.idom, ctx.domTree);
    ssaOptimize(ctx, natural.size > 0 ? natural : undefined);
    destroySSA(ctx);
    // The live-out sets are `pipeline.ts`'s argument to `foldBlock` and not an
    // extra of this replica's own: without them the fold deletes definitions
    // that escape their block, which is a different program from the one the
    // emitter sees (peek-a-bin-7eyn).
    const liveOut = blockLiveOut(ctx.blocks, ctx.liftedBlocks);
    for (const [id, stmts] of ctx.liftedBlocks)
      ctx.liftedBlocks.set(id, foldBlock(stmts, liveOut.get(id)));
  } catch {
    // Same reading as `sweep.ts`: a function the pipeline cannot get through is
    // counted by the throw gate, not here.
    return;
  }
  res.functionsScanned++;

  const blockById = new Map(ctx.blocks.map((b) => [b.id, b]));
  /** Every lowered statement, by the machine address it came from. */
  const stmtsAt = new Map<number, IRStmt[]>();
  for (const [, stmts] of ctx.liftedBlocks)
    for (const st of stmts) {
      const a = addrOf(st);
      if (a === undefined) continue;
      const list = stmtsAt.get(a);
      if (list) list.push(st);
      else stmtsAt.set(a, [st]);
    }

  let wrongHere = 0;
  for (const block of ctx.blocks) {
    for (const pop of block.insns) {
      if (pop.mnemonic.toLowerCase() !== "pop") continue;
      const canon = canonOf(pop.opStr);
      // A `pop` into memory writes no register, and RSP is the one register no
      // stage here models.
      if (canon === null || canon === "rsp") continue;
      res.pops++;
      // A pop the lifter DOES define is peek-a-bin-3axd's rule working, not
      // this defect. Counting them is also this audit's liveness check on that
      // rule: if the pairing stops firing, `popsLifted` goes to zero. The
      // question is asked of the LIFT — see `liftedPops`.
      if (liftedPops.has(pop.address)) {
        res.popsLifted++;
        continue;
      }

      // ── Forward-propagate this one register to the first MACHINE write ──
      //
      // Single register, no fixpoint: a block is entered once from outside and
      // the walk stops at the first write, so a loop is followed exactly once.
      const found: { addr: number; insn: Instruction; name: string }[] = [];
      /** `ret` sites that read this register implicitly, counted separately. */
      const retSites: Instruction[] = [];
      const visited = new Set<number>();
      const stack: { block: number; after: number | null }[] = [
        { block: block.id, after: pop.address },
      ];
      while (stack.length > 0) {
        const item = stack.pop() as { block: number; after: number | null };
        if (item.after === null) {
          if (visited.has(item.block)) continue;
          visited.add(item.block);
        }
        const blk = blockById.get(item.block);
        if (!blk) continue;
        let killed = false;
        for (const insn of blk.insns) {
          if (item.after !== null && insn.address <= item.after) continue;
          if (machineReads(insn, canon))
            // Version-stripped: this runs after `destroySSA`, so a read
            // still carrying a version is not something the emitter prints.
            for (const st of stmtsAt.get(insn.address) ?? [])
              for (const r of readsOf(st))
                if (r.version === undefined && canonReg(r.name) === canon)
                  found.push({ addr: insn.address, insn, name: r.name });
          // The return register is read by `ret` itself, and no operand text
          // says so. Counted apart — see `retWrong` / `retBenign`.
          if (/^retn?$/.test(baseMnemonic(insn)) && canon === "rax") retSites.push(insn);
          if (machineWrites(insn, canon, is64)) {
            killed = true;
            break;
          }
        }
        if (killed) continue;
        for (const sid of blk.succs)
          if (blockById.has(sid)) stack.push({ block: sid, after: null });
      }
      if (found.length === 0 && retSites.length === 0) continue;

      const pp = pairedPush(
        insns,
        insns.findIndex((x) => x.address === pop.address),
        canon,
        is64,
      );
      const noteRow = (addr: number, insn: string, name: string, verdict: string): void => {
        if (res.rows.length < 400)
          res.rows.push({
            bin,
            func: func.name,
            funcAddr: func.address,
            popAddr: pop.address,
            reg: pop.opStr.trim().toLowerCase(),
            canon,
            readAddr: addr,
            insn,
            readName: name,
            pushKind: pp.kind,
            pushAddr: pp.addr,
            verdict,
          });
      };
      if (pp.benign) {
        res.benign += found.length;
        res.retBenign += retSites.length;
        // A benign row is not a defect and is recorded anyway: it is what a
        // blanket refusal of every pop would cost, and the count alone does not
        // say where.
        for (const r of retSites) noteRow(r.address, r.mnemonic, "<return value>", "ret-benign");
        continue;
      }
      res.retWrong += retSites.length;
      for (const r of retSites) noteRow(r.address, r.mnemonic, "<return value>", "ret-wrong");
      if (found.length === 0) continue;
      res.wrong += found.length;
      res.popsWrong++;
      wrongHere += found.length;
      for (const f of found)
        noteRow(f.addr, `${f.insn.mnemonic} ${f.insn.opStr}`.trim(), f.name, "wrong");
    }
  }
  if (wrongHere > 0) res.funcsWrong++;
}
