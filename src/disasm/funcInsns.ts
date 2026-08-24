import type { RuntimeFunction } from "../pe/types";
import type { DisasmFunction, Instruction, Xref } from "./types";

/**
 * All either function below reads of a function: where it starts and how long
 * it is. Widened from {@link DisasmFunction} so a caller holding nothing but
 * extents — the worker's decompile RPC, which is sent `[address, size]` pairs
 * rather than whole records — can group instructions without synthesising a
 * name and a set of flags it does not have. `DisasmFunction` satisfies it.
 */
export interface FuncExtent {
  address: number;
  size: number;
}

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
export function collectFuncInsns(func: FuncExtent, instructions: Instruction[]): Instruction[] {
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
  functions: readonly FuncExtent[],
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

/**
 * The xref rows a function's own decompilation can consult.
 *
 * The same predicate as {@link collectFuncInsns} over a different collection,
 * and it lives beside it so "belongs to this function" has one declaration
 * rather than two that can drift — the shape `sections.ts`, `ripRelative.ts`
 * and `stackIdiom.ts` each exist to end.
 *
 * WHY THIS IS EXACT RATHER THAN AN APPROXIMATION. `decompileFunction` hands the
 * map to `buildCFG` and to nothing else, and `buildCFG` reads it at exactly one
 * place: `xrefMap.get(insn.address)` for each `insn` of `getFuncInsns(func, …)`
 * — every one of which lies in `[func.address, func.address + func.size)` by
 * that function's own filter. So a row outside the window cannot be consulted,
 * and dropping it cannot change an answer. That is a property of `buildCFG`,
 * not of any image, and `__tests__/funcInsns.test.ts` pins it by recording
 * which keys the map is actually asked for.
 *
 * It is what lets the decompile RPC stop shipping the whole section's xref map
 * on every request — 7-14% of one, against a mean of 7-9 rows per function on
 * five real images (peek-a-bin-9gc9). Entries are returned in map order, which
 * is the order `Array.from(map.entries())` produced before this existed, so a
 * `new Map(rows)` on the far side iterates identically.
 */
export function funcXrefEntries(
  func: FuncExtent,
  xrefMap: Map<number, Xref[]>,
): [number, Xref[]][] {
  const endAddr = func.address + func.size;
  const rows: [number, Xref[]][] = [];
  for (const [addr, xrefs] of xrefMap) {
    if (addr >= func.address && addr < endAddr) rows.push([addr, xrefs]);
  }
  return rows;
}

/**
 * The `.pdata` record a function's own decompilation can consult — at most one,
 * and `undefined` where the image's whole table has nothing to say about it.
 *
 * The third member of this file's family, and the one whose predicate is NOT
 * {@link collectFuncInsns}' window. `collectFuncInsns` and
 * {@link funcXrefEntries} both ask whether an address lies inside
 * `[func.address, func.address + func.size)`; a `RuntimeFunction` carries its
 * own extent, so an *intersection* test looks like the natural reading here. It
 * is not the one the consumer makes. `wrapExceptionRegions` matches a record's
 * **begin address** against the function's, and the extent is consulted only as
 * a tie-break between records that already begin at the same place modulo the
 * image base. So the rule below is an equality, not a containment and not an
 * overlap, and a record covering the function without beginning at it is
 * deliberately not returned — it describes some other function's frame.
 *
 * **Units, and why the image base is recovered rather than passed.**
 * `DisasmFunction.address` is a virtual address — the image base is already in
 * it. `RuntimeFunction.beginAddress` is an RVA, exactly as parsed out of
 * `.pdata`; nothing normalises the array on the way here (the worker, the MCP
 * server and `corpus/sweep.ts` all forward `pe.runtimeFunctions` untouched).
 * Comparing the two directly matched nothing at all: on t64.exe all 240 entries
 * match `beginAddress + imageBase` and none match the raw RVA, so `__try` was
 * emitted zero times across 1475 real functions despite 50 handlers being
 * present (peek-a-bin-yrh). The base is therefore recovered from the pair — a
 * VA and its RVA differ by the image base, which the PE spec requires to be a
 * multiple of 64K. That is not by itself a unique test, since two functions
 * exactly 64K apart are congruent, so an **ambiguous match is discarded** rather
 * than guessed at. A missing `__try` is a gap; a `__try` attributed to the wrong
 * function is a lie about what the code does.
 *
 * WHY IT IS HERE AND NOT IN `pipeline.ts`, where it used to be. It is the whole
 * of what one decompile request needs out of an array that is linear in the
 * image — 1641 rows on a 669 KiB-`.text` `go` build, 240 and 235 on t64/w64 —
 * so the client applies it and sends the survivor instead of the table
 * (peek-a-bin-qmlz). `disasmClient` cannot import the pipeline (that would pull
 * the emitter, the structurer and struct synthesis onto the main thread), so the
 * rule has to live in a leaf, and this is the leaf the other two members of the
 * family already live in.
 *
 * IT IS THE SAME RULE ON BOTH SIDES, AND THAT IS WHAT MAKES THE SLICE EXACT.
 * The worker still applies it to whatever it is given, so a caller that sends
 * the whole table (the MCP server, `corpus/sweep.ts`, an older client) gets
 * exactly the answer it got before. A caller that sends the survivor gets the
 * same answer because this function is **idempotent**: handed `[rf]` it returns
 * `rf`, whichever of the two branches selected it — an equal begin address
 * re-matches the first, and a congruent one is the sole survivor of the second,
 * with or without the extent tie-break. `__tests__/funcInsns.test.ts` pins that
 * directly, over the full table and over its own output.
 */
export function funcExceptionRecord(
  func: FuncExtent,
  runtimeFunctions: readonly RuntimeFunction[] | undefined,
): RuntimeFunction | undefined {
  if (!runtimeFunctions || runtimeFunctions.length === 0) return undefined;

  const withHandler = runtimeFunctions.filter(
    (rf) => rf.handlerAddress !== undefined && (rf.handlerFlags ?? 0) & 0x3, // EHANDLER or UHANDLER
  );

  // Same unit on both sides: either the caller normalised the array to VAs, or
  // the image is based at 0.
  const sameAddress = withHandler.filter((rf) => rf.beginAddress === func.address);
  if (sameAddress.length > 0) return sameAddress[0];

  const IMAGE_BASE_ALIGNMENT = 0x10000;
  const congruent = withHandler.filter((rf) => {
    const imageBase = func.address - rf.beginAddress;
    return imageBase > 0 && imageBase % IMAGE_BASE_ALIGNMENT === 0;
  });
  // Prefer an entry whose extent is the function's own; only an unambiguous
  // survivor is used.
  const exact = congruent.filter((rf) => rf.endAddress - rf.beginAddress === func.size);
  const candidates = exact.length > 0 ? exact : congruent;
  return candidates.length === 1 ? candidates[0] : undefined;
}
