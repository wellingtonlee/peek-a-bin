import type { DisasmFunction, Instruction } from "./types";

/**
 * "Collect the instructions belonging to a function" — previously duplicated
 * byte-for-byte in cfg.ts, stack.ts and signatures.ts, each scanning from index
 * 0 of the *global* instruction array. Analysing every function was therefore
 * O(functions x instructions).
 *
 * The global array is address-ascending (`hybridDisassemble` sorts it, and the
 * duplicated scans already relied on that: they `break` on the first address
 * past the function), so the range is a contiguous slice and can be found by
 * binary search. The address index is cached per array so the O(n) build
 * happens once no matter how many functions are analysed.
 *
 * Unsorted input still falls back to the original linear scan, `break`
 * included, so the result is identical for any input rather than only for
 * well-formed input.
 */

interface AddrIndex {
  /** Array length the index was built from; a different length invalidates it. */
  length: number;
  /**
   * Identity of the first and last elements when the index was built. Length
   * alone is not enough: sorting an array in place preserves its length, and a
   * stale index would then silently return the wrong instructions for a
   * function rather than failing. These two checks are O(1) and catch a
   * reorder or a wholesale content replacement.
   */
  first: Instruction | undefined;
  last: Instruction | undefined;
  ascending: boolean;
  addresses: Float64Array;
}

const indexCache = new WeakMap<Instruction[], AddrIndex>();

function isStale(cached: AddrIndex, instructions: Instruction[]): boolean {
  return (
    cached.length !== instructions.length ||
    cached.first !== instructions[0] ||
    cached.last !== instructions[instructions.length - 1]
  );
}

function getAddrIndex(instructions: Instruction[]): AddrIndex {
  const cached = indexCache.get(instructions);
  if (cached && !isStale(cached, instructions)) return cached;

  const addresses = new Float64Array(instructions.length);
  let ascending = true;
  for (let i = 0; i < instructions.length; i++) {
    addresses[i] = instructions[i].address;
    if (i > 0 && addresses[i] < addresses[i - 1]) ascending = false;
  }

  const index: AddrIndex = {
    length: instructions.length,
    first: instructions[0],
    last: instructions[instructions.length - 1],
    ascending,
    addresses,
  };
  indexCache.set(instructions, index);
  return index;
}

/** Index of the first instruction with `address >= addr`, or `length` if none. */
function lowerBound(addresses: Float64Array, addr: number): number {
  let lo = 0;
  let hi = addresses.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (addresses[mid] < addr) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Instructions inside `[func.address, func.address + func.size)`, in array
 * order. Returns a fresh array; callers may keep it.
 */
export function collectFuncInsns(func: DisasmFunction, instructions: Instruction[]): Instruction[] {
  const endAddr = func.address + func.size;
  const index = getAddrIndex(instructions);

  if (!index.ascending) {
    const out: Instruction[] = [];
    for (const insn of instructions) {
      if (insn.address >= func.address && insn.address < endAddr) out.push(insn);
      if (insn.address >= endAddr) break;
    }
    return out;
  }

  const out: Instruction[] = [];
  for (let i = lowerBound(index.addresses, func.address); i < instructions.length; i++) {
    if (index.addresses[i] >= endAddr) break;
    out.push(instructions[i]);
  }
  return out;
}

/**
 * Group instructions by owning function, keyed by `func.address`. Pass the
 * result to `buildCFG` / `analyzeStackFrame` / `inferSignature` when analysing
 * many functions over the same instruction array.
 */
export function buildFuncInsnMap(
  functions: DisasmFunction[],
  instructions: Instruction[],
): Map<number, Instruction[]> {
  const map = new Map<number, Instruction[]>();
  for (const func of functions) {
    map.set(func.address, collectFuncInsns(func, instructions));
  }
  return map;
}

/**
 * `funcInsnMap` lookup with a computed fallback: an address the map does not
 * cover is collected on the spot, so a partial map is never wrong, only slower.
 */
export function getFuncInsns(
  func: DisasmFunction,
  instructions: Instruction[],
  funcInsnMap?: Map<number, Instruction[]>,
): Instruction[] {
  const cached = funcInsnMap?.get(func.address);
  if (cached) return cached;
  return collectFuncInsns(func, instructions);
}
