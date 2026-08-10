import type { Instruction, DisasmFunction, StackFrame, StackVar } from './types';
import { getFuncInsns } from './funcInsns';

/**
 * Stack-operand patterns, one pair per width. They depend only on `is64`, so
 * they are built once here rather than recompiled for every instruction.
 * None carry the `g` flag, so there is no shared `lastIndex` to reset.
 */
const BP_LOCAL_RE = {
  64: /\[rbp\s*-\s*0x([0-9a-fA-F]+)\]/i,
  32: /\[ebp\s*-\s*0x([0-9a-fA-F]+)\]/i,
};
const SP_RE = {
  64: /\[rsp\s*\+\s*0x([0-9a-fA-F]+)\]/i,
  32: /\[esp\s*\+\s*0x([0-9a-fA-F]+)\]/i,
};
const BP_PARAM_RE = {
  64: /\[rbp\s*\+\s*0x([0-9a-fA-F]+)\]/i,
  32: /\[ebp\s*\+\s*0x([0-9a-fA-F]+)\]/i,
};

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
  if (insn.mnemonic === 'nop') return true;
  if (insn.mnemonic !== 'mov') return false;
  const m = /^(\w+),\s*(\w+)$/.exec(insn.opStr.trim());
  return m !== null && m[1].toLowerCase() === m[2].toLowerCase();
}

/**
 * True when the function opens with the canonical frame-pointer prologue, so a
 * `[<fp> + N]` operand really does address the caller's argument area and N can
 * be turned into an argument index.
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
 */
function hasFramePointerPrologue(insns: Instruction[], is64: boolean): boolean {
  const fp = is64 ? 'rbp' : 'ebp';
  const sp = is64 ? 'rsp' : 'esp';

  let i = 0;
  while (i < insns.length && isProloguePadding(insns[i])) i++;

  const push = insns[i];
  const setFp = insns[i + 1];
  if (!push || !setFp) return false;
  if (push.mnemonic !== 'push' || push.opStr.trim().toLowerCase() !== fp) return false;
  if (setFp.mnemonic !== 'mov') return false;

  const [dst, src] = setFp.opStr.split(',');
  return dst?.trim().toLowerCase() === fp && src?.trim().toLowerCase() === sp;
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
    if (insn.mnemonic === 'sub') {
      const m = is64
        ? insn.opStr.match(/^rsp,\s*0x([0-9a-fA-F]+)$/i)
        : insn.opStr.match(/^esp,\s*0x([0-9a-fA-F]+)$/i);
      if (m) {
        frameSize = parseInt(m[1], 16);
        break;
      }
      // Decimal immediate
      const md = is64
        ? insn.opStr.match(/^rsp,\s*(\d+)$/i)
        : insn.opStr.match(/^esp,\s*(\d+)$/i);
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
    base: 'bp' | 'sp';
    offset: number;        // as written in the operand (always positive)
    signedOffset: number;  // negative for [rbp - N]
    size: number;
    accessCount: number;
    isParam: boolean;
  }
  const varMap = new Map<string, VarEntry>();

  function record(base: 'bp' | 'sp', offset: number, signedOffset: number, size: number, isParam: boolean) {
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
    if (opStr.includes('byte')) return 1;
    if (opStr.includes('word') && !opStr.includes('dword') && !opStr.includes('qword')) return 2;
    if (opStr.includes('dword')) return 4;
    if (opStr.includes('qword')) return 8;
    // Default based on architecture
    return is64 ? 8 : 4;
  }

  for (const insn of funcInsns) {
    const op = insn.opStr;

    // [rbp - 0xN] → local variable
    const bpLocalMatch = op.match(bpLocalRe);
    if (bpLocalMatch) {
      const offset = parseInt(bpLocalMatch[1], 16);
      record('bp', offset, -offset, inferSize(op), false);
    }

    // [rsp + 0xN] → could be local or param depending on offset vs frameSize
    const spMatch = op.match(spRe);
    if (spMatch) {
      const offset = parseInt(spMatch[1], 16);
      record('sp', offset, offset, inferSize(op), false);
    }

    // [rbp + 0xN] → parameter (above saved rbp + return addr)
    const bpParamMatch = op.match(bpParamRe);
    if (bpParamMatch) {
      const offset = parseInt(bpParamMatch[1], 16);
      // The argument area starts one slot past the return address: [ebp+0x8]
      // in 32-bit, [rbp+0x10] in 64-bit — which on x64 is the home slot the
      // ABI reserves for the argument passed in RCX, not the first argument
      // that lacks a register. See ARG_AREA.
      const minParamOffset = is64 ? 0x10 : 0x8;
      if (offset >= minParamOffset) {
        record('bp', offset, offset, inferSize(op), true);
      }
    }
  }

  if (varMap.size === 0 && frameSize === 0) return null;

  // Build sorted variable list. Sorted by the operand offset as before; entries
  // that now stay distinct (same offset, different base) are ordered bp first.
  const vars: StackVar[] = [];
  const entries = Array.from(varMap.values())
    .sort((a, b) => a.offset - b.offset || a.base.localeCompare(b.base));

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
  const framed = hasFramePointerPrologue(funcInsns, is64);
  const { firstOffset, slotSize } = ARG_AREA[width];

  const usedNames = new Set<string>();
  for (const v of entries) {
    let name: string;
    if (v.isParam) {
      const delta = v.offset - firstOffset;
      name = framed && delta % slotSize === 0
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

  return { frameSize, vars };
}

/** Stable identity for a stack slot: base register + signed operand offset. */
export function stackVarKey(base: 'bp' | 'sp', signedOffset: number): string {
  return `${base}:${signedOffset}`;
}
