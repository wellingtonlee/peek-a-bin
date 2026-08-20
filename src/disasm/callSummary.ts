/**
 * What a call actually destroys: a per-function written-register summary,
 * closed over the call graph.
 *
 * THE PROBLEM THIS ANSWERS. `clobberedByCall` (`decompile/ssa.ts`) has to decide
 * which registers stop holding their value at a `call`. Two answers were tried
 * before this one and both are documented on `peek-a-bin-hj1`:
 *
 * - The **ABI volatile set** — RAX/RCX/RDX/R8-R11 on Windows x64 — is what a
 *   conforming callee is *allowed* to destroy, and it is not what compiled code
 *   does. `__chkstk` preserves everything but RAX/R10/R11 by documented
 *   contract and is called in the prologue of every large-frame function, so
 *   clobbering renamed 17 reads of `t64!sub_14000D8C4`'s own parameters; MSVC
 *   parks live values in R10 across calls to helpers it has analysed, and
 *   clobbering deleted a guard outright in `t64!sub_140004A9C`. 79 renamed reads
 *   over three binaries, against 10 for the narrow answer.
 * - The **narrow** answer that shipped: only the argument registers the
 *   decompiler already said the call was given. Supported by the decompiler's
 *   own reading, and silent about everything else.
 *
 * This module is the third: ask what the callee *writes*. The evidence is the
 * disassembly, so it is available before any lifting or SSA, and it is a
 * property of the callee rather than of the call site.
 *
 * THE ANSWER IS ONLY EVER ADDED TO THE NARROW ONE, never substituted for it —
 * see `clobberedByCall`. That is what makes the failure mode the good one: a
 * write this scan **misses** costs a clobber, which is exactly today's
 * behaviour, while a write it **invents** reintroduces the harm already
 * measured. Every rule below is therefore written to under-approximate when it
 * is unsure, and an unrecognised mnemonic contributes nothing.
 *
 * SCOPE: x64 only, and deliberately. On x86 nothing is passed in a register, so
 * `clobberedByCall` reports nothing at all today and every register this could
 * add would be new. The 32-bit CRT helpers are also the wrong shape for it —
 * `_chkstk` preserves ECX across a `push ecx` / `pop ecx` pair, and the
 * push/pop rule below is the only thing standing between that and an invented
 * write. Confining the wiring to x64 keeps the two PE32 binaries as a control:
 * their emitted C must not move.
 */

import { canonReg, isKnownRegister } from "./decompile/ir";
import { resolveRipTarget } from "./ripRelative";
import type { Instruction } from "./types";

/**
 * The Windows x64 caller-saved integer registers, canonically named.
 *
 * Same set as `regstate.ts`'s `CALLER_SAVED`, and it is the *ceiling* on
 * everything this module reports: a callee-saved register the callee writes and
 * restores is not a clobber, and intersecting here is what keeps a `mov rbx,
 * rcx` inside a helper from being read as one.
 */
export const X64_VOLATILE: readonly string[] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

/** What an unresolved callee contributes, when the caller wants the ABI answer. */
export const X64_ABI_FALLBACK: readonly string[] = X64_VOLATILE;

/**
 * The clobber evidence a lift needs: a summary per callee address, plus the
 * answer for a target that has none.
 *
 * `unresolved` is a policy, not a measurement — an import, an indirect call and
 * a tail jump into unrecovered code are all targets whose body this analysis
 * never saw. Empty keeps the narrow model at those sites; {@link X64_ABI_FALLBACK}
 * is the ABI reading. The two are measured separately in `corpus/`.
 */
export interface CalleeClobbers {
  /** Callee entry address → the volatile registers it may leave modified. */
  byAddress: Map<number, string[]>;
  /** Contribution of a callee this analysis could not identify. */
  unresolved: readonly string[];
}

// ── The branch-target grammar, by address ──────────────────────────────────

/**
 * Where a `call`/`jmp` operand points, or null when it points nowhere nameable.
 *
 * `direct` is a code address — `call 0x140001000`. `indirectMem` is the address
 * of a *pointer*: `call qword ptr [rip + 0x…]` and `call dword ptr [0x…]` are
 * how both an import thunk and an ordinary indirect call through a global are
 * spelled, and telling them apart is the caller's job (look the address up in
 * the IAT first, as `lifter.ts` does).
 *
 * Deliberately the same grammar `resolveNamedTarget` reads, and RIP
 * displacements go through `ripRelative.ts` rather than a tenth private copy —
 * see the `parseOperand` gotcha in CLAUDE.md.
 */
export type BranchTargetAddr =
  | { kind: "direct"; addr: number }
  | { kind: "indirectMem"; addr: number };

export function resolveBranchTargetAddr(insn: Instruction): BranchTargetAddr | null {
  const opStr = insn.opStr.trim();

  const directM = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (directM) return { kind: "direct", addr: parseInt(directM[1], 16) };

  const rip = resolveRipTarget(insn);
  if (rip !== null) return { kind: "indirectMem", addr: rip };

  const addrM = opStr.match(/\[\s*0x([0-9a-fA-F]+)\s*\]/);
  if (addrM) return { kind: "indirectMem", addr: parseInt(addrM[1], 16) };

  return null;
}

// ── Which registers one instruction writes ─────────────────────────────────

/** Mnemonics whose first operand is the destination, when it is a register. */
const WRITES_OP0 = new Set([
  "mov",
  "movabs",
  "movzx",
  "movsx",
  "movsxd",
  "movbe",
  "lea",
  "add",
  "sub",
  "adc",
  "sbb",
  "and",
  "or",
  "xor",
  "inc",
  "dec",
  "neg",
  "not",
  "shl",
  "sal",
  "shr",
  "sar",
  "rol",
  "ror",
  "rcl",
  "rcr",
  "shld",
  "shrd",
  "bts",
  "btr",
  "btc",
  "bsf",
  "bsr",
  "bswap",
  "popcnt",
  "lzcnt",
  "tzcnt",
  "xadd",
  "pop",
]);

/** Mnemonics that write a fixed set of registers whatever their operands say. */
const IMPLICIT_WRITES: Record<string, string[]> = {
  // Widening multiply and divide land in the RDX:RAX pair. `imul` is the
  // exception and is handled by arity below: two- and three-operand forms write
  // only their destination.
  mul: ["rax", "rdx"],
  div: ["rax", "rdx"],
  idiv: ["rax", "rdx"],
  cdq: ["rdx"],
  cqo: ["rdx"],
  cwd: ["rdx"],
  cdqe: ["rax"],
  cwde: ["rax"],
  cbw: ["rax"],
  cpuid: ["rax", "rbx", "rcx", "rdx"],
  rdtsc: ["rax", "rdx"],
  rdtscp: ["rax", "rcx", "rdx"],
  xgetbv: ["rax", "rdx"],
  lahf: ["rax"],
  syscall: ["rax", "rcx", "r11"],
  sysenter: ["rax", "rcx", "rdx"],
  // A port read lands in the accumulator; a port write reads it.
  in: ["rax"],
  // The string primitives step their pointers whether or not they are repeated.
  movsb: ["rsi", "rdi"],
  movsw: ["rsi", "rdi"],
  movsd: ["rsi", "rdi"],
  movsq: ["rsi", "rdi"],
  stosb: ["rdi"],
  stosw: ["rdi"],
  stosd: ["rdi"],
  stosq: ["rdi"],
  lodsb: ["rax", "rsi"],
  lodsw: ["rax", "rsi"],
  lodsd: ["rax", "rsi"],
  lodsq: ["rax", "rsi"],
  scasb: ["rdi"],
  scasw: ["rdi"],
  scasd: ["rdi"],
  scasq: ["rdi"],
  cmpsb: ["rsi", "rdi"],
  cmpsw: ["rsi", "rdi"],
  cmpsd: ["rsi", "rdi"],
  cmpsq: ["rsi", "rdi"],
  loop: ["rcx"],
  loope: ["rcx"],
  loopne: ["rcx"],
  loopz: ["rcx"],
  loopnz: ["rcx"],
};

/**
 * Mnemonics known to write nothing this analysis models — flags, memory, the
 * stack pointer, or an XMM register.
 *
 * Listed rather than defaulted so the coverage test below can tell "known to
 * write nothing" from "not recognised". RSP is deliberately absent from
 * everything here: `push`/`pop`/`call`/`ret`/`leave` all move it, no volatile
 * register is affected by that, and modelling it would only add a name the
 * intersection throws away.
 */
const WRITES_NOTHING = new Set([
  "cmp",
  "test",
  "bt",
  "push",
  "pushf",
  "pushfd",
  "pushfq",
  "popf",
  "popfd",
  "popfq",
  "ret",
  "retn",
  "iret",
  "jmp",
  "nop",
  "int3",
  "int",
  "int1",
  "ud2",
  "hlt",
  "cld",
  "std",
  "clc",
  "stc",
  "cmc",
  "cli",
  "sti",
  "sahf",
  "leave",
  "enter",
  "out",
  "prefetch",
  "prefetchnta",
  "prefetcht0",
  "prefetcht1",
  "prefetcht2",
  "pause",
  "lfence",
  "mfence",
  "sfence",
  "movdqa",
  "movdqu",
  "movaps",
  "movups",
  "movq",
  "movd",
  "movntdq",
  "movnti",
  "movntps",
  "pxor",
  "xorps",
  "xorpd",
  "fnstsw",
  "wait",
  "fwait",
]);

/** `jcc`, `setcc`, `cmovcc` — matched by exact prefix plus a known condition. */
const CC =
  /^(a|ae|b|be|c|e|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)$/;

/**
 * Split an Intel-syntax operand list. Safe on a plain comma split because an
 * x86 memory operand never contains one — `[rax + rcx*8 + 0x10]`, not a tuple.
 */
function operands(opStr: string): string[] {
  const s = opStr.trim();
  return s === "" ? [] : s.split(",").map((o) => o.trim());
}

function canonIfRegister(op: string): string | null {
  const name = op.toLowerCase();
  return isKnownRegister(name) ? canonReg(name) : null;
}

/**
 * Is this mnemonic one the table above understands?
 *
 * Exposed for the coverage test, which walks a real corpus and fails on a
 * mnemonic nothing here classifies — a silent gap is exactly the shape that
 * makes an under-approximation drift without anyone noticing.
 */
export function isCoveredMnemonic(mnemonic: string): boolean {
  const mn = stripPrefixes(mnemonic);
  if (mn === "") return false;
  if (WRITES_OP0.has(mn) || WRITES_NOTHING.has(mn)) return true;
  if (mn in IMPLICIT_WRITES) return true;
  if (mn === "call" || mn === "imul" || mn === "xchg" || mn === "cmpxchg") return true;
  if (mn.startsWith("j") && CC.test(mn.slice(1))) return true;
  if (mn.startsWith("set") && CC.test(mn.slice(3))) return true;
  if (mn.startsWith("cmov") && CC.test(mn.slice(4))) return true;
  return false;
}

/**
 * Capstone puts a `lock`/`rep` prefix in the mnemonic — `lock inc`,
 * `rep movsd`, `repne scasw` — so the base mnemonic is the last word.
 *
 * A `rep` prefix also makes RCX a written register, which {@link writtenRegs}
 * adds separately: it is the counter, and a repeated string primitive leaves it
 * at zero.
 */
function stripPrefixes(mnemonic: string): string {
  const parts = mnemonic.trim().toLowerCase().split(/\s+/);
  return parts[parts.length - 1] ?? "";
}

function hasRepPrefix(mnemonic: string): boolean {
  return /^(rep|repe|repz|repne|repnz)\s/.test(mnemonic.trim().toLowerCase());
}

/**
 * The canonical registers this instruction writes, ignoring what a `call`'s
 * callee does — {@link buildCallSummaries} closes over that separately.
 *
 * An unrecognised mnemonic writes nothing, which is the under-approximating
 * direction; see the module docstring.
 */
export function writtenRegsOfInsn(insn: Instruction): string[] {
  const mn = stripPrefixes(insn.mnemonic);
  const out: string[] = [];

  if (hasRepPrefix(insn.mnemonic)) out.push("rcx");

  const implicit = IMPLICIT_WRITES[mn];
  if (implicit) {
    out.push(...implicit);
    return out;
  }

  // A call's own definition is the return value; the callee's writes are the
  // call graph's business.
  if (mn === "call") {
    out.push("rax");
    return out;
  }

  const ops = operands(insn.opStr);

  // One-operand `imul`/`mul` widen into RDX:RAX; the two- and three-operand
  // forms write only their destination.
  if (mn === "imul") {
    if (ops.length <= 1) {
      out.push("rax", "rdx");
    } else {
      const d = canonIfRegister(ops[0]);
      if (d) out.push(d);
    }
    return out;
  }

  // Both operands of an exchange are written.
  if (mn === "xchg") {
    for (const op of ops) {
      const d = canonIfRegister(op);
      if (d) out.push(d);
    }
    return out;
  }

  // `cmpxchg` writes its destination on success and RAX on failure.
  if (mn === "cmpxchg") {
    out.push("rax");
    const d = ops.length > 0 ? canonIfRegister(ops[0]) : null;
    if (d) out.push(d);
    return out;
  }

  if (
    WRITES_OP0.has(mn) ||
    (mn.startsWith("set") && CC.test(mn.slice(3))) ||
    (mn.startsWith("cmov") && CC.test(mn.slice(4)))
  ) {
    const d = ops.length > 0 ? canonIfRegister(ops[0]) : null;
    if (d) out.push(d);
    // `xadd` writes both.
    if (mn === "xadd" && ops.length > 1) {
      const s = canonIfRegister(ops[1]);
      if (s) out.push(s);
    }
    return out;
  }

  return out;
}

/**
 * Every canonical register the *body* of this function writes — its own
 * instructions only, with nothing said about what it calls.
 *
 * ONE REFINEMENT, and it is the difference between a summary and a guess: a
 * `pop r` is not a write of `r` when the same function contains a `push r` and
 * nothing else writes `r`. That is a save/restore pair, and the value the
 * caller had is the value it gets back. Without it every hand-written CRT
 * helper that preserves a volatile register the ABI would let it destroy —
 * 32-bit `_chkstk` around ECX is the canonical one — reads as destroying it.
 *
 * The narrow shape is deliberate. `push imm8 / pop reg` is a pervasive MSVC
 * size idiom for `mov reg, imm` (see `corpus/README.md` on `peek-a-bin-6lmh`),
 * and there the push names an immediate rather than the register, so the pop
 * still counts. And when some *other* instruction writes `r`, `r` is written
 * whatever the pops do, so the pair cannot mask anything.
 */
export function writtenRegs(insns: Instruction[]): Set<string> {
  const nonPop = new Set<string>();
  const popped = new Set<string>();
  const pushed = new Set<string>();

  for (const insn of insns) {
    const mn = stripPrefixes(insn.mnemonic);
    if (mn === "push") {
      const r = canonIfRegister(operands(insn.opStr)[0] ?? "");
      if (r) pushed.add(r);
      continue;
    }
    if (mn === "pop") {
      const r = canonIfRegister(operands(insn.opStr)[0] ?? "");
      if (r) popped.add(r);
      continue;
    }
    for (const r of writtenRegsOfInsn(insn)) nonPop.add(r);
  }

  const out = new Set(nonPop);
  for (const r of popped) if (!pushed.has(r)) out.add(r);
  return out;
}

// ── The call graph, closed ─────────────────────────────────────────────────

export interface BuildCallSummariesArgs {
  /** Detected function entry addresses, in any order. */
  functionAddresses: Iterable<number>;
  /** Entry address → that function's instructions (`buildFuncInsnMap`). */
  funcInsnMap: Map<number, Instruction[]>;
  /** Import thunk pointers, so an import is told apart from a local callee. */
  iatMap: Map<number, { lib: string; func: string }>;
  /**
   * What a target this analysis cannot identify contributes to its caller's
   * summary — an import, an indirect call, or a jump into unrecovered code.
   * Empty (the default) keeps the narrow model at those sites.
   */
  unresolved?: readonly string[];
}

/**
 * The summary for every detected function, closed over the call graph.
 *
 * RECURSION NEEDS NO SPECIAL CASE, and inventing one would be the *less*
 * conservative choice. `summary(f) = writes(f) ∪ ⋃ summary(callees)` is a union
 * over a finite lattice, so it has a least fixpoint and the obvious worklist
 * reaches it; for a cycle that fixpoint is exactly the union of every member's
 * own writes, which is the correct may-write answer for entering the cycle
 * anywhere. Collapsing a strongly-connected component to the ABI set instead
 * would report writes no member performs — the one direction this module is
 * built not to take. The iteration is bounded regardless, because these
 * functions come from disassembling untrusted bytes.
 *
 * Values are intersected with {@link X64_VOLATILE} on the way out: a
 * callee-saved register the callee writes is restored before it returns, and
 * reporting it would clobber a register the caller can rely on.
 */
export function buildCallSummaries(args: BuildCallSummariesArgs): Map<number, string[]> {
  const { funcInsnMap, iatMap } = args;
  const unresolved = args.unresolved ?? [];
  const addresses = [...args.functionAddresses];
  const known = new Set(addresses);

  /** Own writes, before the closure. */
  const own = new Map<number, Set<string>>();
  /** Local callees, and whether any callee could not be identified. */
  const edges = new Map<number, Set<number>>();
  const opaque = new Set<number>();

  for (const addr of addresses) {
    const insns = funcInsnMap.get(addr) ?? [];
    own.set(addr, writtenRegs(insns));
    const succ = new Set<number>();
    for (const insn of insns) {
      const mn = stripPrefixes(insn.mnemonic);
      // A tail `jmp` transfers to a callee that returns to *this* function's
      // caller, so whatever it writes is visible to that caller exactly as a
      // call's writes are. `lifter.ts` lifts one as a call for the same reason.
      if (mn !== "call" && mn !== "jmp") continue;
      const target = resolveBranchTargetAddr(insn);
      if (!target) {
        // A `jmp` with no nameable target is overwhelmingly an intra-function
        // branch through a register or a jump table, not a tail call, so it is
        // not evidence of anything opaque. A `call` with none is an indirect
        // call and is.
        if (mn === "call") opaque.add(addr);
        continue;
      }
      if (target.kind === "indirectMem" && iatMap.has(target.addr)) {
        opaque.add(addr);
        continue;
      }
      if (known.has(target.addr)) {
        // An intra-function `jmp` names an address inside this function, which
        // is only a callee when it is the entry of another one.
        if (target.addr !== addr) succ.add(target.addr);
        continue;
      }
      if (mn === "call") opaque.add(addr);
    }
    edges.set(addr, succ);
  }

  /** The working set, unintersected so the closure stays monotone. */
  const summary = new Map<number, Set<string>>();
  for (const addr of addresses) {
    const s = new Set(own.get(addr));
    if (opaque.has(addr)) for (const r of unresolved) s.add(r);
    summary.set(addr, s);
  }

  // Worklist to a fixpoint. The bound is belt-and-braces: each round can only
  // grow sets over a 16-element universe, so `addresses.length + 2` rounds is
  // already generous, but these blocks come from untrusted bytes.
  for (let round = 0; round <= addresses.length + 2; round++) {
    let changed = false;
    for (const addr of addresses) {
      const s = summary.get(addr);
      if (!s) continue;
      for (const callee of edges.get(addr) ?? []) {
        for (const r of summary.get(callee) ?? []) {
          if (!s.has(r)) {
            s.add(r);
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  const out = new Map<number, string[]>();
  for (const addr of addresses) {
    const s = summary.get(addr) ?? new Set<string>();
    out.set(
      addr,
      X64_VOLATILE.filter((r) => s.has(r)),
    );
  }
  return out;
}
