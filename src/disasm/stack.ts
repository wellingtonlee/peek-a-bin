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
 * Geometry of the incoming-argument area, relative to the frame pointer, for a
 * function that opens with `push <fp>; mov <fp>, <sp>`. The frame pointer then
 * points at the saved frame pointer, the return address is one slot above it,
 * and the arguments start one slot after that.
 *
 * On x64 that first slot is the home slot the Microsoft x64 ABI reserves for
 * the *first* argument — the one that arrives in RCX — so the numbering runs
 * continuously across the register/stack boundary: `[rbp+0x10]` is argument 0
 * (RCX's home) and the fifth argument, the first that has no register, lands at
 * `[rbp+0x30]` as argument 4. That is what makes the index comparable with the
 * caller-side index, which counts argument registers on x64.
 */
const ARG_AREA = {
  64: { firstOffset: 0x10, slotSize: 8 },
  32: { firstOffset: 0x08, slotSize: 4 },
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
 * argument. The canonical `push <fp>; mov <fp>, <sp>` gives `D = slot`, which is
 * where `ARG_AREA.firstOffset` (`2 * slot`) comes from; every other shape MSVC
 * emits gives some other `D`, and reading `firstOffset` as if `D` were `slot`
 * anyway is what numbered a large frame's locals — a GS cookie at
 * `[rbp + 0x1A20]` — as incoming arguments (peek-a-bin-ikd).
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
 */
function inlineFrameDisplacement(insns: Instruction[], is64: boolean): number | null {
  const fp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";
  const slotSize = ARG_AREA[is64 ? 64 : 32].slotSize;
  const fpCanon = canonReg(fp);
  const spCanon = canonReg(sp);

  /** `<sp> - E` as the walk stands. */
  let spDelta = 0;
  /** Registers holding an earlier `<sp>` value, keyed canonically, as `<sp> - E`. */
  const spAlias = new Map<string, number>();

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
      if (!pushesWholeSlot(dest, slotSize)) return null;
      spDelta -= slotSize;
      continue;
    }

    if (!memDest && isKnownRegister(dest) && canonReg(dest) === fpCanon) {
      // The frame register is being written. Either this establishes the frame
      // from a stack value, or the register is not a frame pointer here.
      if (dest !== fp) return null; // a narrower write is not a frame pointer
      if (mn === "mov" || mn === "lea") {
        const v = entryRelative(ops[1] ?? "", sp, spDelta, spAlias, mn === "lea");
        if (v !== null) return -v;
      }
      return null;
    }

    if (!memDest && isKnownRegister(dest) && canonReg(dest) === spCanon) {
      // `sub <sp>, imm` and `add <sp>, imm` are the frame arithmetic; anything
      // else that moves the stack pointer ends the model.
      const imm = dest === sp ? loneImmediate(ops[1] ?? "") : null;
      if (imm === null) return null;
      if (mn === "sub") spDelta -= imm;
      else if (mn === "add") spDelta += imm;
      else return null;
      continue;
    }

    // `xchg` writes BOTH of its operands, so it is not enough to look at the
    // destination — the same reason `fpSurvivesToReturn` special-cases it.
    if (mn === "xchg" && ops.some((o) => isKnownRegister(o) && canonReg(o) === fpCanon)) {
      return null;
    }

    if (STACK_TRAFFIC.has(mn) || mn.startsWith("j")) return null;

    if (!memDest && isKnownRegister(dest)) {
      // Any write ends whatever this register was standing in for; a full-width
      // copy of the stack pointer then makes it stand in for this point.
      spAlias.delete(canonReg(dest));
      if (mn === "mov" && ops[1] === sp && regSize(dest) === slotSize) {
        spAlias.set(canonReg(dest), spDelta);
      }
    }
  }
  return null;
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
 * makes `ARG_AREA.firstOffset` (`2 * slot`) argument 0. So the helper has
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
 * `E - V` for the frame register — see `inlineFrameDisplacement` — established
 * either inline or by a prologue helper the function calls, or null when the
 * frame register is not derived from the stack pointer at all.
 *
 * The helper path is deliberately still a yes/no question underneath: it admits
 * a helper only when the frame it establishes is `E - slot`, i.e. exactly the
 * canonical geometry, so its displacement is `slotSize` by construction. A
 * helper leaving some other displacement is *refused* rather than measured,
 * because the arithmetic in `hasHelperFramePointerPrologue` is what keeps the
 * search off ordinary calls and relaxing it has not been measured against
 * anything (peek-a-bin-emlv).
 */
function frameDisplacement(
  insns: Instruction[],
  is64: boolean,
  instructions: Instruction[],
): number | null {
  const inline = inlineFrameDisplacement(insns, is64);
  if (inline !== null) return inline;
  return hasHelperFramePointerPrologue(insns, instructions, is64)
    ? ARG_AREA[is64 ? 64 : 32].slotSize
    : null;
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
  const frameDelta = frameDisplacement(funcInsns, is64, instructions);
  // The lowest `[<fp> + off]` that can be an argument: one slot past the return
  // address, which sits at `[<fp> + delta]`.
  const minParamOffset = frameDelta === null ? null : frameDelta + ARG_AREA[width].slotSize;

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
      // register. See ARG_AREA and `inlineFrameDisplacement`.
      //
      // Anything below it, or any offset at all when there is no frame pointer
      // to measure from, is recorded as nothing and left as a plain deref —
      // which is what `[<fp> + off]` below the threshold has always been. That
      // is the refusal, not a gap: naming it a local would claim a stack slot
      // just as falsely as naming it an argument did, and leaving it alone is
      // what lets struct synthesis see an object field for what it is.
      if (minParamOffset !== null && offset >= minParamOffset) {
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
  //     slot in a function without the canonical prologue is named after its
  //     offset (`arg_0x10`) instead, since no index can be derived from it.
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
  // A sub-slot access ([ebp+0xA], the third byte of argument 0) does not
  // divide evenly and is offset-named too, rather than silently rounded into a
  // neighbour's index.
  // `framed` is the *canonical* geometry specifically, because that is what
  // `ARG_AREA.firstOffset` encodes and therefore what makes `arg_<index>`
  // spellable. A recovered delta of any other value still says which offsets
  // are arguments — that is `minParamOffset` above — but turning it into an
  // index would put `arg_<N>` names on 83 more slots per x64 binary, and
  // `structs.ts` keys cross-function parameter provenance off `^arg_(\d+)$`, so
  // that is a change to struct *identity* and needs its own measurement. Left
  // offset-named deliberately (peek-a-bin-ikd; peek-a-bin-sx57 carries the
  // census of what is left and why it is not a follow-on hunk).
  const framed = frameDelta === ARG_AREA[width].slotSize;
  const { firstOffset, slotSize } = ARG_AREA[width];

  const usedNames = new Set<string>();
  for (const v of entries) {
    let name: string;
    if (v.isParam) {
      const delta = v.offset - firstOffset;
      name =
        framed && delta % slotSize === 0
          ? `arg_${delta / slotSize}`
          : `arg_0x${v.offset.toString(16).toUpperCase()}`;
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
