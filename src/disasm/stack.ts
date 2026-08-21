import { isKnownRegister, regSize } from "./decompile/ir";
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
 * True when the function opens with the canonical frame-pointer prologue *in
 * line*, so a `[<fp> + N]` operand really does address the caller's argument
 * area and N can be turned into an argument index.
 *
 * Deliberately strict: `push <fp>` must be the first instruction (bar
 * hot-patch padding) and `mov <fp>, <sp>` the one after it. Anything pushed in
 * between shifts every argument offset by a slot, and `lea <fp>, [<sp> + N]` —
 * MSVC's other way of establishing a frame — shifts them by N.
 *
 * Outside that exact shape the offset carries no argument index at all. On x64
 * especially, RBP is far more often a plain callee-saved pointer than a frame
 * pointer, so `[rbp + 0x10]` in a function that never established a frame is a
 * field of whatever object RBP happens to hold.
 *
 * A frame the function delegates to a *helper* is the other true case and is
 * `hasHelperFramePointerPrologue`'s question, not this one's.
 */
function hasInlineFramePointerPrologue(insns: Instruction[], is64: boolean): boolean {
  const fp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";

  let i = 0;
  while (i < insns.length && isProloguePadding(insns[i])) i++;

  const push = insns[i];
  const setFp = insns[i + 1];
  if (!push || !setFp) return false;
  if (push.mnemonic !== "push" || push.opStr.trim().toLowerCase() !== fp) return false;
  if (setFp.mnemonic !== "mov") return false;

  const [dst, src] = setFp.opStr.split(",");
  return dst?.trim().toLowerCase() === fp && src?.trim().toLowerCase() === sp;
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

/**
 * The displacement of `[<sp>]` / `[<sp> + N]` / `[<sp> - N]`, signed, or null
 * for any other memory operand. An index register, a scale, or a second base
 * all return null: the displacement would then not be the whole offset.
 */
function spDisplacement(rhs: string, sp: string): number | null {
  const m = new RegExp(`^\\[\\s*${sp}\\s*(?:([+-])\\s*${DISP}\\s*)?\\]$`, "i").exec(rhs.trim());
  if (!m) return null;
  if (m[1] === undefined) return 0;
  const v = parseDisp(m[2]);
  return m[1] === "-" ? -v : v;
}

/**
 * `N` where this instruction sets `<fp>` to `<sp> + N`, or null when it does not
 * establish the frame pointer from the stack pointer at all. `mov <fp>, <sp>` is
 * N = 0; `lea <fp>, [<sp> + N]` is N.
 */
function fpFromSp(insn: Instruction, fp: string, sp: string): number | null {
  const comma = insn.opStr.indexOf(",");
  if (comma < 0) return null;
  if (insn.opStr.slice(0, comma).trim().toLowerCase() !== fp) return null;
  const rhs = insn.opStr
    .slice(comma + 1)
    .trim()
    .toLowerCase();
  const mn = insn.mnemonic.toLowerCase();
  if (mn === "mov") return rhs === sp ? 0 : null;
  if (mn === "lea") return spDisplacement(rhs, sp);
  return null;
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
 * True when the function's frame pointer really is one, so `[<fp> + N]`
 * addresses the caller's argument area and N carries an argument index.
 *
 * Either established inline, or by a prologue helper the function calls — see
 * the two functions above for which shapes each admits and why.
 */
function hasFramePointerPrologue(
  insns: Instruction[],
  is64: boolean,
  instructions: Instruction[],
): boolean {
  return (
    hasInlineFramePointerPrologue(insns, is64) ||
    hasHelperFramePointerPrologue(insns, instructions, is64)
  );
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
      // The argument area starts one slot past the return address: [ebp+0x8]
      // in 32-bit, [rbp+0x10] in 64-bit — which on x64 is the home slot the
      // ABI reserves for the argument passed in RCX, not the first argument
      // that lacks a register. See ARG_AREA.
      const minParamOffset = is64 ? 0x10 : 0x8;
      if (offset >= minParamOffset) {
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
  const framed = hasFramePointerPrologue(funcInsns, is64, instructions);
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
