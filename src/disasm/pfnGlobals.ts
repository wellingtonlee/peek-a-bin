/**
 * `GetProcAddress` results stored into globals, recognised image-wide, so the
 * emitter can spell the GLOBAL `pfn_<Name>`.
 *
 * THE DEFECT THIS EXISTS FOR. MSVC's CRT and the launcher stubs resolve a few
 * APIs at run time — `MessageBoxW`, `GetActiveWindow`, `MessageBoxTimeoutW` —
 * and park each result in a `.data` slot, wrapped in `EncodePointer` in the
 * newer CRTs. After peek-a-bin-5b6q.4 the slot is `g_1400163D0`: grounded (it
 * is a dereferenced data-section address) and unreadable, because the one fact
 * the reader wants about it — which function it holds — is stated by the STORE
 * a few lines above, or in another function entirely, or in a function the
 * browser never decompiles at all. That last case is why this is a PRE-PASS
 * over the whole instruction stream, keyed on the same token as the clobber
 * summaries and riding in `CalleeClobbers` beside the CRT idiom map: the
 * writer may be decompiled later or never, and the reader of the slot has to
 * see the name on its first request.
 *
 * THE SHAPE, read off the corpus (`objdump -d -M intel` at b613025;
 * `t64!sub_14000D3C8`, `w64!sub_140001000`, `w32!sub_401000`):
 *
 *   x64:  lea rdx, [rip + str]            ; str ∈ stringMap
 *         mov rcx, <handle>
 *         call [__imp_GetProcAddress]
 *         (test rax, rax ; je …)           ; a straight-line check is admitted
 *         (mov rcx, rax ; call [__imp_EncodePointer])*
 *         (lea rdx, [rip + next] ; mov rcx, rsi)   ; the NEXT lookup's setup
 *         mov [rip + G], rax
 *   x86:  push <str> ; push <handle> ; call [__imp_GetProcAddress]
 *         (push eax ; call [__imp_EncodePointer])*
 *         mov [G], eax
 *
 * THE CLAIM AND ITS GROUNDING. `pfn_MessageBoxW` claims exactly one thing:
 * every absolute store the image spells into G is the result of
 * `GetProcAddress(<something>, "MessageBoxW")`, possibly through
 * `EncodePointer`. It does NOT claim the module handle (`h` is not read — the
 * string names the function, the handle the module, and a wrong module gives
 * NULL, not another function), and it does NOT claim that a call through the
 * slot IS `MessageBoxW`: a pointer variable can be rewritten by a store this
 * pass cannot see (through a register, from another module, by the loader), so
 * the emitter names the VARIABLE and leaves the call site to the existing
 * indirect spelling — `((intptr_t (*)())rax)(…)` with `rax = DecodePointer(
 * pfn_MessageBoxW)` above it. NO call-site rewrite, and no typed
 * function-pointer cast: a real prototype would turn every admitted arity
 * under-count into a gcc error, reddening `cc clean` on refusals the record
 * accepts (`corpus/arity.ts`, which reads the text, is untouched either way —
 * `pfn_X` never stands in callee position).
 *
 * REFUSALS, each a fixture in `pfnGlobals.test.ts`, each carried out as a
 * {@link PfnRefusal} so `corpus/globals.ts` can report them by reason:
 *
 *  - `other-store`: ANY other instruction in the image writes G at an absolute
 *    address — `mov [G], rcx`, `and [G], 0`, `xchg`, a locked RMW. The name
 *    describes every writer or it describes none.
 *  - `disagree`: two shapes store into one G under different strings, or one
 *    encoded and one not.
 *  - `string-unknown`: the name operand is an address the string map does not
 *    hold. Refused rather than read from the bytes: the map is the one
 *    declaration of what the image's strings are, and a second reader would
 *    disagree with it at the edges (length caps, encodings).
 *  - `no-string-operand`: the name argument is not a string address at all —
 *    an ordinal (`mov edx, 0x10`), a register, a stack slot.
 *  - `unencodable-name`: the string is not a C identifier suffix.
 *  - `result-redefined`: every register holding the result is overwritten
 *    before a store — the value stored is something else.
 *  - `intervening-call`: a call other than `EncodePointer` between the lookup
 *    and the store; whatever it returns is what gets stored.
 *  - `encode-arg`: `EncodePointer` is called with something other than the
 *    result (x64: RCX does not hold it; x86: the last push was not of it).
 *  - `joined`: a branch target or a function start falls inside the window
 *    between the call and the store — another path reaches the store with a
 *    value this straight-line reading never saw.
 *  - `no-store`: the window ends (`jmp`, `ret`, an unmodelled instruction, the
 *    length bound) without a store. `t32!sub_40614A`'s `CorExitProcess` lookup
 *    is this: the result is called and never kept.
 *
 * WHAT IT CANNOT SEE, stated so nobody reads a name as more than it is: a
 * store through a register (`lea rcx, [G] … mov [rcx], rax`), a store from
 * another image, and a slot written by anything but an instruction in
 * `.text`. All three are exactly why the call site is not rewritten.
 *
 * THE MATCH IS STRAIGHT-LINE AND THE WRITE MODEL IS A WHITELIST. Between the
 * lookup and the store only the instruction shapes named in
 * {@link followResult} are admitted; anything else ends the window as
 * `no-store`. Refusal is the default, as in `crtIdioms.ts`: an unmodelled
 * mnemonic contributes a refusal, never an admission.
 *
 * A LEAF below `callSummary.ts`, like `crtIdioms.ts`: `CallSummaryCache.forToken`
 * runs it in the same pass, so it may import nothing from there.
 */

import { type BranchTargetInsn, resolveBranchTargetAddr } from "./branchTarget";
import { canonReg, isKnownRegister } from "./decompile/ir";
import type { FuncExtent } from "./funcInsns";

/** The least an instruction has to carry to be matched here. */
export interface PfnInsn extends BranchTargetInsn {
  mnemonic: string;
}

/** One global the emitted C may spell `pfn_<proc>`. */
export interface PfnGlobal {
  /** `pfn_` + the procedure name — see {@link pfnName}. */
  name: string;
  /** The string handed to `GetProcAddress`, exactly as the string map holds it. */
  proc: string;
  /** Whether the stored value went through `EncodePointer` (so a reader must `DecodePointer` it). */
  encoded: boolean;
}

export type PfnRefusalReason =
  | "other-store"
  | "disagree"
  | "string-unknown"
  | "no-string-operand"
  | "unencodable-name"
  | "result-redefined"
  | "intervening-call"
  | "encode-arg"
  | "joined"
  | "no-store";

export interface PfnRefusal {
  reason: PfnRefusalReason;
  /** The `call GetProcAddress` the refused shape started at. */
  at: number;
  /** The global the shape stored into, where the walk got that far. */
  global?: number;
  /** The procedure name, where the string was read. */
  proc?: string;
}

/** What the pre-pass found: the globals it names, and every shape it declined. */
export interface PfnPrepass {
  globals: Map<number, PfnGlobal>;
  refusals: PfnRefusal[];
  /** `call GetProcAddress` sites seen — the liveness denominator. */
  lookups: number;
}

export const PFN_PREFIX = "pfn_";

/** THE ONE DECLARATION of the spelling. `corpus/globals.ts` writes the pattern out rather than importing this. */
export function pfnName(proc: string): string {
  return `${PFN_PREFIX}${proc}`;
}

/** A procedure name that can follow `pfn_` in a C identifier. */
const IDENTIFIER_SUFFIX = /^[A-Za-z0-9_]+$/;

/**
 * How far past the lookup a store is looked for. The longest corpus window is
 * eight instructions (`t64!0x14000d429` → `0x14000d44b`, with the next
 * lookup's `lea`/`mov` interleaved); the bound exists for untrusted bytes.
 */
const MAX_WINDOW = 24;

/** `rep ret`/`lock inc` → the base mnemonic; Capstone puts the prefix in the mnemonic. */
function baseMnemonic(mnemonic: string): string {
  const parts = mnemonic.trim().toLowerCase().split(/\s+/);
  return parts[parts.length - 1] ?? "";
}

function operands(opStr: string): string[] {
  const s = opStr.trim();
  return s === "" ? [] : s.split(",").map((o) => o.trim().toLowerCase());
}

type Operand =
  | { kind: "reg"; name: string; canon: string; full: boolean }
  | { kind: "imm"; value: number }
  | { kind: "mem"; abs: number | null }
  | { kind: "other" };

const FULL_64 = /^r(ax|bx|cx|dx|si|di|bp|sp|\d+)$/;
const FULL_32 = /^e(ax|bx|cx|dx|si|di|bp|sp)$/;

function classify(op: string, insn: PfnInsn, is64: boolean): Operand {
  if (isKnownRegister(op)) {
    return {
      kind: "reg",
      name: op,
      canon: canonReg(op),
      full: (is64 ? FULL_64 : FULL_32).test(op),
    };
  }
  if (/^0x[0-9a-f]+$/.test(op)) return { kind: "imm", value: parseInt(op, 16) };
  if (/^\d+$/.test(op)) return { kind: "imm", value: parseInt(op, 10) };
  if (op.includes("[")) {
    // The memory operand alone, through the one branch/memory address grammar
    // (`cookieCompare` in `crtIdioms.ts` does the same): a `[rip + d]` or a
    // `[0x…]` resolves; anything based on a register does not.
    const t = resolveBranchTargetAddr({ address: insn.address, size: insn.size, opStr: op });
    return { kind: "mem", abs: t?.kind === "indirectMem" ? t.addr : null };
  }
  return { kind: "other" };
}

/** Op-0-is-memory mnemonics that only READ it; every other one is taken as a writer. */
const READS_MEM_OP0 = new Set(["cmp", "test", "bt", "push", "call", "jmp", "nop", "prefetch"]);

/**
 * Register-destination mnemonics whose op0 write is modelled inside a window.
 * A `mov reg, reg` from a holder is the one that ADDS a holder; every other
 * member overwrites op0. Anything not listed here or in {@link NEUTRAL} ends
 * the window.
 */
const WRITES_OP0 = new Set([
  "mov",
  "movzx",
  "movsx",
  "movsxd",
  "lea",
  "add",
  "sub",
  "and",
  "or",
  "xor",
  "inc",
  "dec",
  "neg",
  "not",
  "shl",
  "shr",
  "sar",
  "imul",
]);

/** Writes no general register: flags, the stack, nothing. */
const NEUTRAL = new Set(["test", "cmp", "nop", "push"]);

function isJcc(mn: string): boolean {
  return mn.length > 1 && mn.startsWith("j") && mn !== "jmp";
}

interface ImageIndex {
  byAddress: Map<number, number>;
  /** Every direct branch/call target plus every function start — where paths join. */
  joins: Set<number>;
  /** Absolute address → the instructions that write it. */
  writers: Map<number, number[]>;
}

function indexImage(
  insns: readonly PfnInsn[],
  funcExtents: readonly FuncExtent[],
  is64: boolean,
): ImageIndex {
  const byAddress = new Map<number, number>();
  const joins = new Set<number>(funcExtents.map((f) => f.address));
  const writers = new Map<number, number[]>();
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    byAddress.set(insn.address, i);
    const mn = baseMnemonic(insn.mnemonic);
    if (mn === "call" || mn === "jmp" || isJcc(mn)) {
      const t = resolveBranchTargetAddr(insn);
      if (t?.kind === "direct") joins.add(t.addr);
    }
    const ops = operands(insn.opStr);
    if (ops.length > 0 && !READS_MEM_OP0.has(mn)) {
      const op0 = classify(ops[0], insn, is64);
      if (op0.kind === "mem" && op0.abs !== null) {
        const list = writers.get(op0.abs);
        if (list) list.push(insn.address);
        else writers.set(op0.abs, [insn.address]);
      }
    }
  }
  return { byAddress, joins, writers };
}

/**
 * The import a `call` reaches, by the IAT: `call [slot]` directly, or `call
 * thunk` where the thunk is a `jmp [slot]` (the `/INCREMENTAL` shape). Null
 * for a local callee or an indirect call through a register.
 */
function importCalled(
  insn: PfnInsn,
  insns: readonly PfnInsn[],
  index: ImageIndex,
  iatMap: ReadonlyMap<number, { lib: string; func: string }>,
): string | null {
  const t = resolveBranchTargetAddr(insn);
  if (!t) return null;
  if (t.kind === "indirectMem") return iatMap.get(t.addr)?.func ?? null;
  const at = index.byAddress.get(t.addr);
  if (at === undefined) return null;
  const thunk = insns[at];
  if (baseMnemonic(thunk.mnemonic) !== "jmp") return null;
  const tt = resolveBranchTargetAddr(thunk);
  return tt?.kind === "indirectMem" ? (iatMap.get(tt.addr)?.func ?? null) : null;
}

interface Shape {
  callAt: number;
  storeAt: number;
  global: number;
  proc: string;
  encoded: boolean;
}

type Walk = { ok: true; shape: Shape } | { ok: false; reason: PfnRefusalReason };

/**
 * Follow the lookup's result from the instruction after the call to the first
 * absolute store of it. See the module docstring for the admitted shapes.
 */
function followResult(
  insns: readonly PfnInsn[],
  from: number,
  proc: string,
  is64: boolean,
  index: ImageIndex,
  iatMap: ReadonlyMap<number, { lib: string; func: string }>,
): Walk {
  const acc = "rax";
  const holders = new Set<string>([acc]);
  let encoded = false;
  /** x86: the last `push` pushed a holder, with no push since. */
  let lastPushHolder = false;
  const callAt = insns[from - 1].address;

  for (let j = from; j < insns.length && j - from < MAX_WINDOW; j++) {
    const insn = insns[j];
    if (index.joins.has(insn.address)) return { ok: false, reason: "joined" };
    const mn = baseMnemonic(insn.mnemonic);
    const ops = operands(insn.opStr).map((o) => classify(o, insn, is64));

    if (mn === "call") {
      if (importCalled(insn, insns, index, iatMap) !== "EncodePointer") {
        return { ok: false, reason: "intervening-call" };
      }
      const argHeld = is64 ? holders.has("rcx") : lastPushHolder;
      if (!argHeld) return { ok: false, reason: "encode-arg" };
      holders.clear();
      holders.add(acc);
      encoded = true;
      lastPushHolder = false;
      continue;
    }

    if (isJcc(mn)) continue;

    if (NEUTRAL.has(mn)) {
      if (mn === "push") {
        const p = ops[0];
        lastPushHolder = p?.kind === "reg" && p.full && holders.has(p.canon);
      }
      continue;
    }

    if (WRITES_OP0.has(mn) && ops.length >= 1) {
      const [d, s] = ops;
      if (d.kind === "mem") {
        // A store. Of the result, to an absolute address: the shape's end.
        if (mn === "mov" && d.abs !== null && s?.kind === "reg" && s.full && holders.has(s.canon)) {
          return {
            ok: true,
            shape: { callAt, storeAt: insn.address, global: d.abs, proc, encoded },
          };
        }
        // A store of something else, or through a register: no register moves.
        continue;
      }
      if (d.kind === "reg") {
        if (mn === "mov" && s?.kind === "reg" && d.full && s.full && holders.has(s.canon)) {
          holders.add(d.canon);
        } else {
          holders.delete(d.canon);
          if (holders.size === 0) return { ok: false, reason: "result-redefined" };
        }
        continue;
      }
      return { ok: false, reason: "no-store" };
    }

    // `jmp`, `ret`, a string primitive, anything unmodelled: the straight line
    // ends here without a store of the result.
    return { ok: false, reason: "no-store" };
  }
  return { ok: false, reason: "no-store" };
}

/** What the lookup's name argument was, as the instructions before the call set it up. */
type NameArg = { kind: "string"; va: number } | { kind: "none" };

export interface RecognisePfnArgs {
  /** The whole image's instructions, in address order. */
  instructions: readonly PfnInsn[];
  /** Function extents — their starts are join points, like branch targets. */
  funcExtents: readonly FuncExtent[];
  iatMap: ReadonlyMap<number, { lib: string; func: string }>;
  /** Address → string, the one declaration of what the image's strings are. */
  stringMap: ReadonlyMap<number, string>;
  is64: boolean;
}

/**
 * Every `GetProcAddress` result the image stores into a global it writes
 * nowhere else, keyed on the global's address. See the module docstring.
 *
 * One forward pass tracking the name argument (x64: what RDX holds, x86: the
 * pushes since the last call), one bounded forward walk per lookup, then a
 * per-global reconciliation against every writer in the image. Linear in the
 * instruction count plus {@link MAX_WINDOW} per lookup.
 */
export function recognisePfnGlobals(args: RecognisePfnArgs): PfnPrepass {
  const { instructions: insns, iatMap, stringMap, is64 } = args;
  const index = indexImage(insns, args.funcExtents, is64);
  const shapes: Shape[] = [];
  const refusals: PfnRefusal[] = [];
  let lookups = 0;

  // x64: the string RDX was last loaded with, or null once anything else
  // touched RDX or the straight line broke. x86: the operands pushed since
  // the last call, in order.
  let rdxString: NameArg = { kind: "none" };
  let pushes: Operand[] = [];
  const reset = () => {
    rdxString = { kind: "none" };
    pushes = [];
  };

  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    if (index.joins.has(insn.address)) reset();
    const mn = baseMnemonic(insn.mnemonic);
    const ops = operands(insn.opStr).map((o) => classify(o, insn, is64));

    if (mn === "call") {
      if (importCalled(insn, insns, index, iatMap) === "GetProcAddress") {
        lookups++;
        const nameArg: NameArg = is64
          ? rdxString
          : pushes.length >= 2 && pushes[pushes.length - 2].kind === "imm"
            ? { kind: "string", va: (pushes[pushes.length - 2] as { value: number }).value }
            : { kind: "none" };
        if (nameArg.kind === "none") {
          refusals.push({ reason: "no-string-operand", at: insn.address });
        } else {
          const proc = stringMap.get(nameArg.va);
          if (proc === undefined) {
            refusals.push({ reason: "string-unknown", at: insn.address });
          } else if (!IDENTIFIER_SUFFIX.test(proc)) {
            refusals.push({ reason: "unencodable-name", at: insn.address, proc });
          } else {
            const walk = followResult(insns, i + 1, proc, is64, index, iatMap);
            if (walk.ok) shapes.push(walk.shape);
            else refusals.push({ reason: walk.reason, at: insn.address, proc });
          }
        }
      }
      // Any call consumes the pushed arguments and clobbers RDX.
      reset();
      continue;
    }

    if (isJcc(mn) || mn === "test" || mn === "cmp" || mn === "nop") continue;

    if (mn === "push") {
      if (!is64) pushes.push(ops[0] ?? { kind: "other" });
      continue;
    }

    if (mn === "lea" && is64 && ops[0]?.kind === "reg" && ops[0].canon === "rdx") {
      const src = ops[1];
      rdxString =
        ops[0].full && src?.kind === "mem" && src.abs !== null
          ? { kind: "string", va: src.abs }
          : { kind: "none" };
      continue;
    }

    if (WRITES_OP0.has(mn) && ops.length >= 1) {
      const d = ops[0];
      if (d.kind === "reg" && is64 && d.canon === "rdx") rdxString = { kind: "none" };
      continue;
    }

    // `jmp`, `ret`, `pop`, a string primitive, anything unmodelled: the
    // straight line to the next lookup is broken.
    reset();
  }

  // Reconcile per global: one claim, and no writer outside the shapes.
  const byGlobal = new Map<number, Shape[]>();
  for (const s of shapes) {
    const list = byGlobal.get(s.global);
    if (list) list.push(s);
    else byGlobal.set(s.global, [s]);
  }
  const globals = new Map<number, PfnGlobal>();
  for (const [global, list] of byGlobal) {
    const claims = new Set(list.map((s) => `${s.proc} ${s.encoded}`));
    if (claims.size > 1) {
      for (const s of list) {
        refusals.push({ reason: "disagree", at: s.callAt, global, proc: s.proc });
      }
      continue;
    }
    const own = new Set(list.map((s) => s.storeAt));
    const others = (index.writers.get(global) ?? []).filter((w) => !own.has(w));
    if (others.length > 0) {
      for (const s of list) {
        refusals.push({ reason: "other-store", at: s.callAt, global, proc: s.proc });
      }
      continue;
    }
    const { proc, encoded } = list[0];
    globals.set(global, { name: pfnName(proc), proc, encoded });
  }

  refusals.sort((a, b) => a.at - b.at);
  return { globals, refusals, lookups };
}
