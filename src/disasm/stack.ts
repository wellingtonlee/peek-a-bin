import { canonReg, isKnownRegister, regSize } from "./decompile/ir";
import { collectFuncInsns, getFuncInsns } from "./funcInsns";
import { loneImmediate, STACK_TRAFFIC } from "./stackIdiom";
import type { DisasmFunction, Instruction, StackFrame, StackVar } from "./types";

/**
 * Stack-operand patterns, one pair per width. They depend only on `is64`, so
 * they are built once here rather than recompiled for every instruction.
 * None carry the `g` flag, so there is no shared `lastIndex` to reset.
 *
 * The displacement alternates hex and decimal because Capstone prints it both
 * ways: `0x` only from 0xA up, and a bare digit below that. Matching `0x` alone
 * silently dropped every slot in the first ten bytes of the frame — which on
 * x86 is *argument 0* (`[ebp + 8]`) and the first locals (`[ebp - 4]`,
 * `[ebp - 8]`). A function whose only parameter was reached through
 * `push dword ptr [ebp + 8]` came back with no parameters at all.
 */
const DISP = "(0[xX][0-9a-fA-F]+|\\d+)";
const BP_LOCAL_RE = {
  64: new RegExp(`\\[rbp\\s*-\\s*${DISP}\\]`, "i"),
  32: new RegExp(`\\[ebp\\s*-\\s*${DISP}\\]`, "i"),
};
const SP_RE = {
  64: new RegExp(`\\[rsp\\s*\\+\\s*${DISP}\\]`, "i"),
  32: new RegExp(`\\[esp\\s*\\+\\s*${DISP}\\]`, "i"),
};
const BP_PARAM_RE = {
  64: new RegExp(`\\[rbp\\s*\\+\\s*${DISP}\\]`, "i"),
  32: new RegExp(`\\[ebp\\s*\\+\\s*${DISP}\\]`, "i"),
};

/** A displacement as Capstone printed it: `0x`-prefixed hex, or bare decimal. */
function parseDisp(text: string): number {
  return /^0[xX]/.test(text) ? parseInt(text.slice(2), 16) : parseInt(text, 10);
}

/**
 * Geometry of the incoming-argument area, measured from the stack pointer on
 * **entry**. Call that `E`: `[E]` holds the return address, `[E + slot]` is
 * argument 0 and `[E + slot + N*slot]` is argument N. Every positional name in
 * this file is that arithmetic plus `D` — see `inlineFrameGeometry`.
 *
 * `homeRegs` is the part of the area the caller does **not** write, and it is
 * why an index alone is not enough to name a slot. The Microsoft x64 ABI has
 * the caller reserve four slots — the *home space* — for the arguments that
 * arrive in RCX, RDX, R8 and R9, and hands them to the callee as scratch: the
 * caller never stores anything there, so a home slot holds argument N only if
 * the callee spilled that register into it itself. The numbering still runs
 * continuously across the register/stack boundary, which is what makes the
 * index comparable with the caller-side one (`collectArgs64` counts argument
 * registers), so argument 4 — the first with no register — is at `[E + 0x28]`.
 * `homeRegs[N]` is therefore both *which* register carries argument N and, by
 * its length, *how many* leading slots are callee scratch.
 *
 * On x86 nothing arrives in a register: every argument is pushed by the caller,
 * so there is no home space and `homeRegs` is empty. That is not a shortcut for
 * "x86 is simpler" — it is the fact that makes every x86 slot nameable from `D`
 * alone, and it is why both PE32 binaries are the untouched control for any
 * change to the home-space rule.
 *
 * (The argument-register order is spelled in five other places in `src/` —
 * `signatures.ts`, `decompile/{lifter,ssa,structs}.ts` — each deliberately
 * local to a file that must not import the others. This one is a *field of the
 * geometry table* rather than a sixth free-standing copy, because its length
 * is the geometry: it is read here only to answer "whose home slot is this".)
 */
const ARG_AREA = {
  64: { slotSize: 8, homeRegs: ["rcx", "rdx", "r8", "r9"] as readonly string[] },
  32: { slotSize: 4, homeRegs: [] as readonly string[] },
};

/** `nop`, or a register moved onto itself (MSVC's `mov edi, edi` hot-patch pad). */
function isProloguePadding(insn: Instruction): boolean {
  if (insn.mnemonic === "nop") return true;
  if (insn.mnemonic !== "mov") return false;
  const m = /^(\w+),\s*(\w+)$/.exec(insn.opStr.trim());
  return m !== null && m[1].toLowerCase() === m[2].toLowerCase();
}

/**
 * How far into a function the frame-pointer search reads. A frame established
 * further in than this is *refused*, never guessed at.
 */
const FRAME_MAX_INSNS = 32;

/**
 * The value an operand denotes, as an offset from the stack pointer on entry, or
 * null when it is not derived from the stack pointer at all.
 *
 * `withDisplacement` distinguishes the two forms that can establish a frame
 * pointer: a bare register source (`mov <fp>, <sp>`, or a copy of it) and a
 * memory *address* (`lea <fp>, [<sp> - N]`). An index register, a scale or a
 * second base all return null, since the displacement would then not be the
 * whole offset.
 *
 * `spAlias` maps a canonical register to the `<sp> - E` it holds, so a frame
 * established from a copy of the stack pointer reads exactly as one established
 * from the stack pointer itself. There is one grammar for this in this file —
 * `fpFromSp` asks it with an empty alias map, which is the prologue-helper
 * path's own question.
 */
function entryRelative(
  operand: string,
  sp: string,
  spDelta: number,
  spAlias: ReadonlyMap<string, number>,
  withDisplacement: boolean,
): number | null {
  const t = operand.trim().toLowerCase();
  const deltaOf = (reg: string): number | undefined =>
    reg === sp ? spDelta : spAlias.get(canonReg(reg));

  if (!withDisplacement) return isKnownRegister(t) ? (deltaOf(t) ?? null) : null;

  const m = new RegExp(`^\\[\\s*([a-z][a-z0-9]*)\\s*(?:([+-])\\s*${DISP}\\s*)?\\]$`, "i").exec(t);
  if (!m) return null;
  const base = deltaOf(m[1]);
  if (base === undefined) return null;
  if (m[2] === undefined) return base;
  const v = parseDisp(m[3]);
  return m[2] === "-" ? base - v : base + v;
}

/** What `[<fp> + off]` means in one function — see `inlineFrameGeometry`. */
interface FrameGeometry {
  /**
   * `E - V` for the frame register, where `E` is the stack pointer on entry and
   * `V` the value the function establishes in it — or null when it never
   * establishes one *from the stack pointer* at all.
   */
  delta: number | null;
  /**
   * Argument indices inside the home space (`[0, homeRegs.length)`) whose home
   * slot the prologue provably fills with that argument's own register. Always
   * empty on x86, which has no home space, and never consulted when `delta` is
   * null.
   */
  homed: ReadonlySet<number>;
}

/** No home slot was shown to hold its argument. */
const NO_HOMED: ReadonlySet<number> = new Set<number>();

/** The frame register is not derived from the stack pointer in this function. */
const REFUSED: FrameGeometry = { delta: null, homed: NO_HOMED };

/**
 * A memory operand as Capstone spells it, with the size prefix removed:
 * `qword ptr [rsp + 8]` → `[rsp + 8]`. `entryRelative` anchors on the brackets,
 * so the prefix has to come off before it will read the operand at all — and a
 * segment override (`dword ptr fs:[0]`, the second instruction of
 * `__SEH_prolog4`) still fails to match, which is the right answer.
 */
const MEM_SIZE_PREFIX = /^(?:byte|word|dword|qword|fword|tbyte|[xyz]mmword)\s+ptr\s+/i;

/**
 * The argument index whose home slot this store fills, or null.
 *
 * `target` is the address written, as an offset from `E`, so argument N's home
 * slot is at `slot * (N + 1)`. The store counts only when its source is
 * argument N's **own** register: `mov [rsp + 8], rbx` writes argument 0's home
 * slot too, and it is a callee-saved register being parked in space the ABI
 * gave the callee for scratch — the same instruction shape stating the opposite
 * fact. Getting that backwards is not a cosmetic error, because
 * `paramIndexByBase` in `decompile/structs.ts` lets a home slot's `arg_<N>`
 * *displace* the argument register's own provenance claim, so a saved register
 * would then be linked to whatever the callers pass as argument N.
 *
 * A narrower source is admitted — `mov word ptr [rsp + 8], cx` spills the low
 * half of argument 0 and the slot does hold it, with the width coming from the
 * reads — but a store at an address *inside* a slot rather than at its base is
 * not that argument and is refused.
 */
function homedSlot(
  target: number | null,
  src: string,
  slotSize: number,
  homeRegs: readonly string[],
): number | null {
  if (target === null || target <= 0 || target % slotSize !== 0) return null;
  const index = target / slotSize - 1;
  if (index >= homeRegs.length) return null;
  if (!isKnownRegister(src)) return null;
  return canonReg(src) === canonReg(homeRegs[index]) ? index : null;
}

/**
 * `E - V` for the frame register, where `E` is the stack pointer on entry and
 * `V` the value the function establishes in the frame register — or null when it
 * never establishes one *from the stack pointer* at all.
 *
 * This is the one quantity the argument area's geometry needs, and it is a
 * quantity rather than a yes/no because a frame pointer does not have to point
 * at the saved frame pointer. `E` is where the return address is, so argument 0
 * is at `[E + slot]` and argument N at `[E + slot + N*slot]`; therefore
 * `[<fp> + off]` is argument `(off - D - slot) / slot`, and an `off` below
 * `D + slot` is *below the return address* — a local of this frame, not an
 * argument. The canonical `push <fp>; mov <fp>, <sp>` gives `D = slot`; every
 * other shape MSVC emits gives some other `D`, and reading the canonical
 * geometry as if `D` were `slot` anyway is what numbered a large frame's
 * locals — a GS cookie at `[rbp + 0x1A20]` — as incoming arguments
 * (peek-a-bin-ikd).
 *
 * Note `D` is measured from the stack pointer on **entry** and not from the
 * saved frame pointer, which is why it does not matter *what* the function
 * pushed before establishing the frame: `push rbx; mov rbp, rsp` is `D = slot`
 * and `[rbp + 2*slot]` really is argument 0 there too.
 *
 * The walk is a small abstract interpretation of the prologue holding the stack
 * pointer's offset from `E`, plus the registers standing in for an earlier value
 * of it — MSVC's large-frame prologue opens `mov rax, rsp` and establishes the
 * frame with `lea rbp, [rax - N]`, so the copy has to be tracked or that whole
 * shape is unreadable. Everything not understood is a **refusal**, because a `D`
 * that is wrong by a slot is an argument index that is wrong by one, and on the
 * naming side that is a parameter identity `structs.ts` links across functions.
 * In particular a write to the frame register from anything that is not a
 * tracked stack value returns null and does not fall through: `mov rbp, rcx`
 * makes RBP an object pointer, `mov rbp, rdx` is how an MSVC funclet receives
 * its parent's frame, and `xor ebp, ebp` makes it a constant — in none of those
 * is `[rbp + off]` an argument of this function at all.
 *
 * THE SECOND ANSWER, `homed`, is the home space's own question, and it is asked
 * in the same walk because it needs the same stack model: whether the *callee*
 * stored argument N's register into argument N's home slot — see `homedSlot`
 * and `ARG_AREA`. `D` says which offsets are arguments; on x64 it cannot say
 * whether the first four of them hold one, because the ABI gives those slots to
 * the callee as scratch and MSVC spends them on saved registers and byte locals
 * about as often as on spills (15 of this corpus's 20 such slots).
 *
 * `argsPristine` is the whole soundness argument for that half, and it is
 * deliberately blunt: a store counts as a spill only while *no* instruction in
 * the window has written any register but the stack pointer and the frame
 * register, so every argument register still provably holds its incoming value
 * and no liveness reasoning is needed. Pushes and the modelled `<sp>`
 * arithmetic keep it, since they are exactly what the walk already tracks and
 * neither touches an argument register. It costs nothing measurable — every
 * spill in this corpus is in the entry store block, before any register write —
 * and it is what makes the claim structural instead of empirical. The
 * alternative, tracking which argument registers are still live, would need a
 * second register-write grammar here and would have to be right about `cdq`,
 * `mul` and `xchg` to be worth anything.
 */
function inlineFrameGeometry(insns: Instruction[], is64: boolean): FrameGeometry {
  const fp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";
  const { slotSize, homeRegs } = ARG_AREA[is64 ? 64 : 32];
  const fpCanon = canonReg(fp);
  const spCanon = canonReg(sp);

  /** `<sp> - E` as the walk stands. */
  let spDelta = 0;
  /**
   * Registers holding an earlier `<sp>` value, keyed canonically, as `<sp> - E`.
   * The frame register joins them the moment it is established, which is what
   * lets a spill addressed `[<fp> + N]` resolve through the same grammar as one
   * addressed `[<sp> + N]`.
   */
  const spAlias = new Map<string, number>();
  /** Set once the frame register is established; `delta` never moves after. */
  let delta: number | null = null;
  /** No register but `<sp>` and `<fp>` has been written — see the docstring. */
  let argsPristine = true;
  const homed = new Set<number>();

  for (let i = 0; i < insns.length && i < FRAME_MAX_INSNS; i++) {
    const insn = insns[i];
    if (isProloguePadding(insn)) continue;
    const mn = insn.mnemonic.toLowerCase();
    const ops = insn.opStr.split(",").map((p) => p.trim().toLowerCase());
    const dest = ops[0] ?? "";
    // A memory destination writes no register, and the prologue is full of them:
    // `mov [rsp + 8], rbx` and `mov [rax + 0x10], rbx` are argument spills.
    const memDest = dest.includes("[");

    if (mn === "push") {
      if (!pushesWholeSlot(dest, slotSize)) return stop(delta, homed);
      spDelta -= slotSize;
      continue;
    }

    if (!memDest && isKnownRegister(dest) && canonReg(dest) === fpCanon) {
      // The frame register is being written. Either this establishes the frame
      // from a stack value, or the register is not a frame pointer here.
      //
      // Once it IS established the walk carries on, for `homed` only: a second
      // write means `[<fp> + N]` no longer addresses the frame, so the spill
      // scan ends there while `delta` — already fixed, and what every caller
      // before this bead received at exactly this point — is handed back
      // untouched.
      if (delta !== null) return { delta, homed };
      if (dest !== fp) return REFUSED; // a narrower write is not a frame pointer
      if (mn === "mov" || mn === "lea") {
        const v = entryRelative(ops[1] ?? "", sp, spDelta, spAlias, mn === "lea");
        if (v !== null) {
          delta = -v;
          spAlias.set(fpCanon, v);
          continue;
        }
      }
      return REFUSED;
    }

    if (!memDest && isKnownRegister(dest) && canonReg(dest) === spCanon) {
      // `sub <sp>, imm` and `add <sp>, imm` are the frame arithmetic; anything
      // else that moves the stack pointer ends the model.
      const imm = dest === sp ? loneImmediate(ops[1] ?? "") : null;
      if (imm === null) return stop(delta, homed);
      if (mn === "sub") spDelta -= imm;
      else if (mn === "add") spDelta += imm;
      else return stop(delta, homed);
      continue;
    }

    // `xchg` writes BOTH of its operands, so it is not enough to look at the
    // destination — the same reason `fpSurvivesToReturn` special-cases it.
    if (mn === "xchg" && ops.some((o) => isKnownRegister(o) && canonReg(o) === fpCanon)) {
      return stop(delta, homed);
    }

    if (STACK_TRAFFIC.has(mn) || mn.startsWith("j")) return stop(delta, homed);

    if (memDest) {
      // A store: it writes memory and no register, so it neither advances the
      // stack model nor ends it — the prologue is full of them. `mov` is the
      // only form that can be an argument spill, and it is also the only one
      // that provably writes no register: `xchg`, `xadd` and `cmpxchg` through
      // a memory operand write theirs, which `argsPristine` cannot survive.
      if (mn !== "mov") argsPristine = false;
      else if (argsPristine) {
        const target = entryRelative(dest.replace(MEM_SIZE_PREFIX, ""), sp, spDelta, spAlias, true);
        const slot = homedSlot(target, ops[1] ?? "", slotSize, homeRegs);
        if (slot !== null) homed.add(slot);
      }
      continue;
    }

    if (isKnownRegister(dest)) {
      // Any write ends whatever this register was standing in for; a full-width
      // copy of the stack pointer then makes it stand in for this point.
      spAlias.delete(canonReg(dest));
      if (mn === "mov" && ops[1] === sp && regSize(dest) === slotSize) {
        spAlias.set(canonReg(dest), spDelta);
      }
      argsPristine = false;
    } else {
      // An instruction whose written registers this walk cannot name — `cdq`
      // writes EDX, `mul` writes RDX:RAX — so nothing after it is a spill.
      argsPristine = false;
    }
  }
  return stop(delta, homed);
}

/**
 * The answer when the walk stops without establishing a frame, or stops after
 * having established one. Both are the same statement — this is everything that
 * was shown — and the pre-`sx57` code expressed the first half as a bare `null`.
 */
function stop(delta: number | null, homed: ReadonlySet<number>): FrameGeometry {
  return delta === null ? REFUSED : { delta, homed };
}

/**
 * Bounds on the prologue-helper search below. Neither is part of the rule — the
 * rule is the stack arithmetic in `hasHelperFramePointerPrologue` the
 * search from decoding an arbitrary distance into the image. A helper that
 * establishes the frame further in than this is *refused*, never guessed at.
 */
const HELPER_MAX_CALLER_PUSHES = 4;
const HELPER_WINDOW_BYTES = 128;
const HELPER_MAX_INSNS = 32;

/** Mnemonics that end a helper by returning to the caller. */
const HELPER_RETURNS = new Set(["ret", "retn", "retf"]);

/** No register stands in for an earlier stack-pointer value — see `entryRelative`. */
const NO_SP_ALIAS: ReadonlyMap<string, number> = new Map<string, number>();

/**
 * `N` where this instruction sets `<fp>` to `<sp> + N`, or null when it does not
 * establish the frame pointer from the stack pointer at all. `mov <fp>, <sp>` is
 * N = 0; `lea <fp>, [<sp> + N]` is N.
 */
function fpFromSp(insn: Instruction, fp: string, sp: string): number | null {
  const comma = insn.opStr.indexOf(",");
  if (comma < 0) return null;
  if (insn.opStr.slice(0, comma).trim().toLowerCase() !== fp) return null;
  const rhs = insn.opStr.slice(comma + 1);
  const mn = insn.mnemonic.toLowerCase();
  if (mn !== "mov" && mn !== "lea") return null;
  return entryRelative(rhs, sp, 0, NO_SP_ALIAS, mn === "lea");
}

/**
 * Does this `push` move the stack pointer by exactly one slot?
 *
 * An allowlist, not a blacklist: a narrower push moves the stack pointer by its
 * own width, and the depth arithmetic below would then be wrong by the
 * difference — which is a whole argument index, in the direction that invents
 * one. `matchedStackSlots` in `decompile/lifter.ts` refuses a narrow push for
 * the same reason.
 */
function pushesWholeSlot(op: string, slotSize: number): boolean {
  if (loneImmediate(op) !== null) return true;
  if (isKnownRegister(op)) return regSize(op) === slotSize;
  // A memory operand, which Capstone always spells with its size: MSVC's
  // `push dword ptr fs:[0]` is the second instruction of `__SEH_prolog4`.
  return slotSize === 8 ? /\bqword ptr\b/.test(op) : /\bdword ptr\b/.test(op);
}

/**
 * Does `<fp>` still hold what the establishing instruction put in it when the
 * helper returns?
 *
 * The arithmetic below computes `<fp>` at the moment it is established; that
 * says nothing about the value the *caller* sees unless the helper leaves it
 * alone from there to its `ret`. Refusing on anything not understood — a branch,
 * a nested call, `leave`, or any write naming `<fp>` as its destination — is the
 * safe direction, and so is refusing when the window runs out before a `ret`:
 * a helper whose return was never seen has not been shown to preserve anything.
 */
function fpSurvivesToReturn(window: Instruction[], from: number, fp: string): boolean {
  for (let k = from; k < window.length && k - from < HELPER_MAX_INSNS; k++) {
    const insn = window[k];
    const mn = insn.mnemonic.toLowerCase();
    if (HELPER_RETURNS.has(mn)) return true;
    // A `push` writes memory, not its operand, so it cannot disturb <fp>.
    if (mn === "push") continue;
    if (mn.startsWith("j") || mn === "call") return false;
    const ops = insn.opStr.split(",").map((p) => p.trim().toLowerCase());
    // `xchg` writes both of its operands, so neither may name <fp>.
    if (mn === "xchg" ? ops.includes(fp) : ops[0] === fp) return false;
    if (STACK_TRAFFIC.has(mn)) return false;
  }
  return false;
}

/**
 * Does the function called at the head of this one establish the caller's frame
 * pointer, exactly as an inline `push <fp>; mov <fp>, <sp>` would?
 *
 * This is MSVC's `__SEH_prolog4`, and it is not a byte pattern — it is stack
 * arithmetic, checked. Let `E` be the caller's stack pointer on entry, so `[E]`
 * is the return address and `[E + slot]` is argument 0. The canonical prologue
 * leaves `<fp> = E - slot`, pointing at the saved frame pointer, which is what
 * makes `[<fp> + 2 * slot]` argument 0. So the helper has
 * established the caller's frame exactly when the `<fp>` it computes equals
 * `E - slot`, and the offset of the stack pointer from `E` is known all the way
 * there: `-slot` for each of the caller's pushes, `-slot` for the return address
 * the `call` pushed, and `-slot` for each push the helper makes before it
 * establishes `<fp>`. Writing that offset `delta`, `lea <fp>, [<sp> + N]`
 * establishes the caller's frame precisely when `N + delta === -slot`.
 *
 * `__SEH_prolog4` satisfies it: the caller pushes the frame size and the scope
 * table (2), the `call` pushes the return address (1), the helper pushes the
 * handler and the old `fs:[0]` (2), and `lea ebp, [esp + 0x10]` has N = 16 —
 * `16 + (-5 * 4) === -4`. It saves the caller's EBP with
 * `mov [esp + 0x10], ebp`, into the slot the frame size arrived in, so `[ebp]`
 * is the saved frame pointer and `[ebp + 8]` is argument 0, verbatim as the
 * inline prologue.
 *
 * Three refusals carry the soundness and none is decoration:
 *
 *  - **The caller may only `push` immediates before the `call`.** The
 *    arithmetic works for any push, but `push <anything>; call` is what an
 *    ordinary two-argument call looks like, and the frame size and the scope
 *    table are immediates. This is what keeps the search off ordinary calls
 *    rather than relying on the arithmetic to decline them.
 *  - **The helper may not `push <fp>`.** That is a callee-saved save with a
 *    `pop <fp>` to come, so whatever the helper computes is undone before the
 *    caller sees it — and the arithmetic alone does *not* refuse it
 *    (`push ebp; lea ebp, [esp + 4]` satisfies `N + delta === -slot`).
 *  - **`<fp>` must survive to the helper's `ret`** — see `fpSurvivesToReturn`.
 *
 * Note this is deliberately NOT the shape ikd/x64 warns about. There the frame
 * is established by an in-function `lea rbp, [rsp - N]` after several pushes,
 * and `[rbp + N]` is a *local* in a large frame; teaching the detector that
 * shape would number locals as arguments. Requiring a `call` excludes it, and
 * the arithmetic would refuse it anyway.
 */
function hasHelperFramePointerPrologue(
  insns: Instruction[],
  instructions: Instruction[],
  is64: boolean,
): boolean {
  const fp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";
  const slotSize = ARG_AREA[is64 ? 64 : 32].slotSize;

  let i = 0;
  while (i < insns.length && isProloguePadding(insns[i])) i++;

  let pushes = 0;
  while (
    pushes < HELPER_MAX_CALLER_PUSHES &&
    insns[i]?.mnemonic.toLowerCase() === "push" &&
    loneImmediate(insns[i].opStr) !== null
  ) {
    pushes++;
    i++;
  }

  const call = insns[i];
  if (call?.mnemonic.toLowerCase() !== "call") return false;
  const target = call.opStr.trim().match(/^0x([0-9a-fA-F]+)$/);
  if (!target) return false;
  const targetAddr = parseInt(target[1], 16);

  // A bounded window of the callee, taken through the same cached binary search
  // every other reader of the global instruction array uses. A window rather
  // than the callee's real extent because the extent is not known here — and it
  // does not need to be: everything this asks is answered before the first
  // `ret`.
  const window = collectFuncInsns({ address: targetAddr, size: HELPER_WINDOW_BYTES }, instructions);
  if (window.length === 0 || window[0].address !== targetAddr) return false;

  // `-slotSize` per caller push, and `-slotSize` for the return address.
  let delta = -(pushes + 1) * slotSize;

  for (let k = 0; k < window.length && k < HELPER_MAX_INSNS; k++) {
    const insn = window[k];
    if (isProloguePadding(insn)) continue;

    const n = fpFromSp(insn, fp, sp);
    if (n !== null) {
      return n + delta === -slotSize && fpSurvivesToReturn(window, k + 1, fp);
    }

    const mn = insn.mnemonic.toLowerCase();
    if (mn === "push") {
      const op = insn.opStr.trim().toLowerCase();
      if (op === fp) return false;
      if (!pushesWholeSlot(op, slotSize)) return false;
      delta -= slotSize;
      continue;
    }
    // Anything else that moves the stack pointer, or that writes either of the
    // two registers this is reasoning about, ends the model. Note the helper
    // legitimately *stores through* the stack pointer before establishing the
    // frame — `mov [esp + 0x10], ebp` is how `__SEH_prolog4` saves the caller's
    // EBP — and that changes neither register's value, so only a destination
    // naming the register itself is a refusal.
    if (STACK_TRAFFIC.has(mn)) return false;
    const ops = insn.opStr.split(",").map((p) => p.trim().toLowerCase());
    if (mn === "xchg" ? ops.includes(fp) || ops.includes(sp) : ops[0] === fp || ops[0] === sp) {
      return false;
    }
  }
  return false;
}

/**
 * What `[<fp> + off]` means in this function — see `inlineFrameGeometry` — for a
 * frame established either inline or by a prologue helper the function calls.
 *
 * The helper path is deliberately still a yes/no question underneath: it admits
 * a helper only when the frame it establishes is `E - slot`, i.e. exactly the
 * canonical geometry, so its displacement is `slotSize` by construction. A
 * helper leaving some other displacement is *refused* rather than measured,
 * because the arithmetic in `hasHelperFramePointerPrologue` is what keeps the
 * search off ordinary calls and relaxing it has not been measured against
 * anything (peek-a-bin-emlv).
 *
 * It reports **no** homed slots, which is the conservative reading and costs
 * nothing measured: `__SEH_prolog4` is a 32-bit form, where there is no home
 * space to report on, and the helper search is measured to fire 0 times on both
 * x64 binaries. A helper-framed x64 function would keep its home slots
 * offset-named rather than have them guessed at.
 */
function frameGeometry(
  insns: Instruction[],
  is64: boolean,
  instructions: Instruction[],
): FrameGeometry {
  const inline = inlineFrameGeometry(insns, is64);
  if (inline.delta !== null) return inline;
  return hasHelperFramePointerPrologue(insns, instructions, is64)
    ? { delta: ARG_AREA[is64 ? 64 : 32].slotSize, homed: NO_HOMED }
    : REFUSED;
}

/**
 * `arg_<index>` when the slot's argument position is both derivable and a
 * statement about this function's interface, and `arg_0x<offset>` when it is
 * not. The name is the only channel to `decompile/structs.ts`, which keys
 * cross-function parameter provenance off `^arg_(\d+)$`, so the two spellings
 * are what keep a slot that is an argument apart from a slot that merely sits
 * where one would (CLAUDE.md's stack-frame gotcha).
 *
 * Three ways to fall back, and only the first is about the frame:
 *
 *  - **No `delta`.** Nothing says where the argument area is; the caller does
 *    not record such a slot as a parameter at all, so this is defence in depth.
 *  - **A sub-slot offset.** `[ebp+0xA]` is the third byte of argument 0 and
 *    divides into no index, so it is named after its offset rather than
 *    silently rounded into a neighbour's.
 *  - **A home slot the callee never filled** — `inUnfilledHomeSpace`. On x64
 *    `[E + slot]` through `[E + 4*slot]` is space the ABI gives the callee for
 *    scratch, so naming one `arg_0` states something false about the interface
 *    and, worse, hands `paramIndexByBase` a claim that *displaces* the argument
 *    register's own. Since peek-a-bin-g186 the caller does not record such a
 *    slot as a parameter at all, so this arm is defence in depth exactly as the
 *    first one is — the same predicate decides both, which is what keeps them
 *    from disagreeing.
 */
function argSlotName(
  offset: number,
  delta: number | null,
  slotSize: number,
  homeRegs: readonly string[],
  homed: ReadonlySet<number>,
): string {
  const byOffset = `arg_0x${offset.toString(16).toUpperCase()}`;
  if (delta === null) return byOffset;
  if (inUnfilledHomeSpace(offset, delta, slotSize, homeRegs, homed)) return byOffset;
  const above = offset - delta - slotSize;
  if (above < 0 || above % slotSize !== 0) return byOffset;
  return `arg_${above / slotSize}`;
}

/**
 * Whether `[<fp> + offset]` lands in home space the callee did **not** fill with
 * the argument that owns it — i.e. in storage that is inside the incoming
 * argument area and is nevertheless not an argument of this function.
 *
 * This is the one place the home-space judgement is made, and it has two
 * callers asking two different questions of it. `analyzeStackFrame` asks whether
 * to record a parameter at all; `argSlotName` asks whether an index it can
 * derive is a statement about the interface. Splitting the rule between them is
 * how a saved register came to be *named* after its offset — `argSlotName`
 * already refused it — while still being *emitted as a parameter*, which is the
 * defect this predicate closes (peek-a-bin-g186).
 *
 * Three properties are deliberate:
 *
 *  - **It is empty on x86 by construction, not by a special case.** `homeRegs`
 *    is `[]` there, so the length test returns false before any arithmetic
 *    runs; every x86 argument is pushed by the caller and `D` alone names it.
 *    That is what makes both PE32 binaries the untouched control.
 *  - **Containment, not slot alignment.** `[<fp> + D + slot + 2]` is the third
 *    byte of argument 0's home slot; if the callee never filled that slot, that
 *    byte is not part of an argument either. `argSlotName` still needs exact
 *    alignment to *spell* an index, which is a different question and stays
 *    separate. No such offset occurs in this corpus, so the two readings are
 *    measurably indistinguishable here and the containment one is the honest
 *    reading of the ABI fact.
 *  - **It cannot withdraw a positional name.** Everything it answers true for
 *    is exactly what `argSlotName`'s home-space fallback already spelled by
 *    offset, so no slot that reaches `arg_<N>` can be refused by it —
 *    peek-a-bin-sx57's five spilled home slots keep their indices as a property
 *    of the two rules being the same rule, not as a measurement.
 */
function inUnfilledHomeSpace(
  offset: number,
  delta: number,
  slotSize: number,
  homeRegs: readonly string[],
  homed: ReadonlySet<number>,
): boolean {
  if (homeRegs.length === 0) return false;
  const above = offset - delta - slotSize;
  if (above < 0 || above >= homeRegs.length * slotSize) return false;
  return !homed.has(Math.floor(above / slotSize));
}

export function analyzeStackFrame(
  func: DisasmFunction,
  instructions: Instruction[],
  is64: boolean,
  funcInsnMap?: Map<number, Instruction[]>,
): StackFrame | null {
  // Find instructions within this function
  const funcInsns = getFuncInsns(func, instructions, funcInsnMap);

  if (funcInsns.length === 0) return null;

  // Detect frame size from prologue: sub rsp, N / sub esp, N
  let frameSize = 0;
  for (const insn of funcInsns.slice(0, 10)) {
    if (insn.mnemonic === "sub") {
      const m = is64
        ? insn.opStr.match(/^rsp,\s*0x([0-9a-fA-F]+)$/i)
        : insn.opStr.match(/^esp,\s*0x([0-9a-fA-F]+)$/i);
      if (m) {
        frameSize = parseInt(m[1], 16);
        break;
      }
      // Decimal immediate
      const md = is64 ? insn.opStr.match(/^rsp,\s*(\d+)$/i) : insn.opStr.match(/^esp,\s*(\d+)$/i);
      if (md) {
        frameSize = parseInt(md[1], 10);
        break;
      }
    }
  }

  // Scan for stack variable accesses.
  // Keyed by "<base>:<signedOffset>" — `[rbp-0x10]` and `[rsp+0x10]` are
  // different memory locations, so keying on the bare numeric offset merged
  // them into one entry with a combined size, a combined access count, and
  // whichever isParam flag happened to be written first.
  interface VarEntry {
    base: "bp" | "sp";
    offset: number; // as written in the operand (always positive)
    signedOffset: number; // negative for [rbp - N]
    size: number;
    accessCount: number;
    isParam: boolean;
  }
  const varMap = new Map<string, VarEntry>();

  function record(
    base: "bp" | "sp",
    offset: number,
    signedOffset: number,
    size: number,
    isParam: boolean,
  ) {
    const key = stackVarKey(base, signedOffset);
    const existing = varMap.get(key);
    if (existing) {
      existing.accessCount++;
      if (size > existing.size) existing.size = size;
    } else {
      varMap.set(key, { base, offset, signedOffset, size, accessCount: 1, isParam });
    }
  }

  const width = is64 ? 64 : 32;
  const bpLocalRe = BP_LOCAL_RE[width];
  const spRe = SP_RE[width];
  const bpParamRe = BP_PARAM_RE[width];

  // The frame register's displacement from the stack pointer on entry, which is
  // what decides where the incoming-argument area begins — see
  // `inlineFrameDisplacement`. Computed before the scan because the scan needs
  // it: `[<fp> + off]` is an argument only at or above `delta + slot`, and only
  // when a delta exists at all.
  //
  // `null` is the case worth understanding. It means the frame register is not
  // derived from the stack pointer anywhere in this function's prologue, so it
  // is not a frame pointer and `[<fp> + off]` is not an argument of this
  // function under any reading — it is a field of whatever object the register
  // holds (`mov rbp, rcx`), a local of a *parent* frame handed to an MSVC
  // funclet (`mov rbp, rdx`), or address arithmetic over a constant
  // (`xor ebp, ebp`). Recording one as a parameter put a phantom argument in the
  // emitted signature and took the deref out of struct synthesis's reach
  // (peek-a-bin-ikd).
  const geometry = frameGeometry(funcInsns, is64, instructions);
  const frameDelta = geometry.delta;
  const { slotSize, homeRegs } = ARG_AREA[width];

  /**
   * Whether `[<fp> + offset]` is an argument of *this* function, which is two
   * questions and not one.
   *
   * The lowest offset that can be one is a slot past the return address, which
   * sits at `[<fp> + delta]`; below that is a local of this frame, and with no
   * `delta` at all nothing says where the area is. And on x64 being inside the
   * area is still not sufficient — see `inUnfilledHomeSpace`.
   */
  const isArgumentSlot = (offset: number): boolean =>
    frameDelta !== null &&
    offset >= frameDelta + slotSize &&
    !inUnfilledHomeSpace(offset, frameDelta, slotSize, homeRegs, geometry.homed);

  // Size heuristic from operand prefix
  function inferSize(opStr: string): number {
    if (opStr.includes("byte")) return 1;
    if (opStr.includes("word") && !opStr.includes("dword") && !opStr.includes("qword")) return 2;
    if (opStr.includes("dword")) return 4;
    if (opStr.includes("qword")) return 8;
    // Default based on architecture
    return is64 ? 8 : 4;
  }

  for (const insn of funcInsns) {
    const op = insn.opStr;

    // [rbp - 0xN] → local variable
    const bpLocalMatch = op.match(bpLocalRe);
    if (bpLocalMatch) {
      const offset = parseDisp(bpLocalMatch[1]);
      record("bp", offset, -offset, inferSize(op), false);
    }

    // [rsp + 0xN] → could be local or param depending on offset vs frameSize
    const spMatch = op.match(spRe);
    if (spMatch) {
      const offset = parseDisp(spMatch[1]);
      record("sp", offset, offset, inferSize(op), false);
    }

    // [rbp + 0xN] → parameter (above saved rbp + return addr)
    const bpParamMatch = op.match(bpParamRe);
    if (bpParamMatch) {
      const offset = parseDisp(bpParamMatch[1]);
      // The argument area starts one slot past the return address, which is at
      // `[<fp> + frameDelta]`. For the canonical prologue that is [ebp+0x8] in
      // 32-bit and [rbp+0x10] in 64-bit — on x64 the home slot the ABI reserves
      // for the argument passed in RCX, not the first argument that lacks a
      // register. See ARG_AREA and `inlineFrameGeometry`.
      //
      // Anything below it, or any offset at all when there is no frame pointer
      // to measure from, is recorded as nothing and left as a plain deref —
      // which is what `[<fp> + off]` below the threshold has always been. That
      // is the refusal, not a gap: naming it a local would claim a stack slot
      // just as falsely as naming it an argument did, and leaving it alone is
      // what lets struct synthesis see an object field for what it is.
      //
      // `inUnfilledHomeSpace` is the second refusal and it is the same
      // statement one storey up: on x64 an offset inside the argument area is
      // an argument of this function only if the callee spilled the register
      // that carries it, because the home space is four slots the *caller*
      // reserves and the *callee* may use for anything. 16 slots per x64 binary
      // are a saved register, a byte local or an out-param buffer sitting
      // there, and recording one put it in the emitted signature —
      // `void sub_1400027C8(int64_t arg_0x30, …) { arg_0x30 = rbx; }`
      // (peek-a-bin-g186). Not recording is again the *only* honest option
      // rather than the cautious one: it is not a local either — the caller
      // owns the storage — and `promote.ts`'s `matchStackAccess` classifies
      // every `[<fp> + N]` as a parameter from the offset alone, so a local
      // name recorded here would have no site to be promoted at.
      if (isArgumentSlot(offset)) {
        record("bp", offset, offset, inferSize(op), true);
      }
    }
  }

  if (varMap.size === 0 && frameSize === 0) return null;

  // Build sorted variable list. Sorted by the operand offset as before; entries
  // that now stay distinct (same offset, different base) are ordered bp first.
  const vars: StackVar[] = [];
  const entries = Array.from(varMap.values()).sort(
    (a, b) => a.offset - b.offset || a.base.localeCompare(b.base),
  );

  // The N in `arg_N` is derived from the slot's offset, never from the order
  // the slots were seen in. A counter over observed slots made N the order the
  // function happened to touch its arguments in, so a function that never reads
  // its first argument called its second one `arg_0` — misleading in the
  // emitted pseudocode, and unusable as an argument index by anything else.
  //
  // Assumptions, in the order they can fail:
  //
  //  1. The frame pointer is a frame pointer. Only checked, never assumed: a
  //     slot in a function whose frame register is not derived from the stack
  //     pointer is named after its offset (`arg_0x10`) instead, since no index
  //     can be derived from it. `arg_<N>` therefore means "`D` was recovered",
  //     which is what `decompile/structs.ts` reads it as.
  //  2. Each argument occupies exactly one slot, so N is really a *slot* index.
  //     An argument wider than one slot (an int64 on x86, a by-value struct)
  //     consumes several, and the arguments after it are then numbered past
  //     their source-level position. This is the same convention the call sites
  //     are counted in — 32-bit arguments by push, x64 by argument register —
  //     so the two indices still agree with each other, which is what matters
  //     for pairing a caller's argument against a callee's parameter.
  //  3. An untouched argument leaves a gap in the numbering rather than
  //     shifting everything after it down. That gap is the point.
  //
  // The index is `(offset - D - slot) / slot`, so it follows the recovered
  // geometry rather than the canonical one: a `push`-heavy MSVC prologue shifts
  // every offset by however many slots it pushed, and reading those offsets
  // against `D = slot` anyway is what left 83 genuine slots per x64 binary
  // offset-named (peek-a-bin-sx57). `argSlotName` holds the three reasons an
  // index is still not spellable, of which the x64 home space is the one that
  // is not about the frame at all.
  //
  // `framed` — the *canonical* geometry — no longer takes part in naming. It is
  // published for `promote.ts`, which uses it for a different question: whether
  // a copy of the frame register may be followed to the same slot.
  const framed = frameDelta === slotSize;

  const usedNames = new Set<string>();
  for (const v of entries) {
    let name: string;
    if (v.isParam) {
      name = argSlotName(v.offset, frameDelta, slotSize, homeRegs, geometry.homed);
    } else {
      // Two locals can now share an operand offset (e.g. [rbp-0x10] and
      // [rsp+0x10]); suffix the base so their names stay distinct. Names are
      // unchanged whenever there is no collision.
      name = `var_${v.offset.toString(16).toUpperCase()}`;
      if (usedNames.has(name)) name = `${name}_${v.base}`;
    }
    usedNames.add(name);
    vars.push({
      offset: v.offset,
      signedOffset: v.signedOffset,
      size: v.size,
      accessCount: v.accessCount,
      name,
      key: stackVarKey(v.base, v.signedOffset),
    });
  }

  return { frameSize, vars, framed };
}

/** Stable identity for a stack slot: base register + signed operand offset. */
export function stackVarKey(base: "bp" | "sp", signedOffset: number): string {
  return `${base}:${signedOffset}`;
}
