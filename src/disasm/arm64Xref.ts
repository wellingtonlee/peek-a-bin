/**
 * Cross-references for an ARM64 image (peek-a-bin-erb).
 *
 * `buildAllXrefs` in `functionDetect.ts` is an x86 operand grammar end to end:
 * it resolves `[rip ± 0x..]`, scans operand strings for bare `0x…` literals and
 * reads `call 0x…` for the call graph. Run over A64 bytes it does not fail — it
 * reports references that do not exist — so the worker and the MCP server
 * currently return empty maps for ARM64 instead of calling it. The cost of that
 * honesty is that an ARM64 image has no string xrefs, no import xrefs, no call
 * graph and no data xrefs at all.
 *
 * This is the A64 replacement, and it differs from the x86 one in two ways that
 * matter:
 *
 *  * It takes DECODED INSTRUCTIONS, not bytes. A64 is fixed-width, so the
 *    linear sweep in `arm64.ts` has already produced every instruction there is
 *    to produce; re-decoding the section a second time would find nothing new
 *    and cost another pass through Capstone.
 *  * A reference is a PAIR of instructions (`adrp` + `add`/`ldr`), not a literal
 *    inside one operand — see `findArm64AddressRefs`. There is no `0x…` in
 *    either half that naming the referenced address, which is exactly why the
 *    x86 scan finds nothing here.
 *
 * A reference is attributed to the instruction that COMPLETES the pair, which
 * is the one a reader would put the cursor on.
 */

import { classifyArm64Branch, findArm64AddressRefs } from "./arm64Operands";
import type { Instruction } from "./types";

/** Same shape `buildAllXrefs` returns, so the two are interchangeable. */
export interface Arm64XrefResult {
  stringXrefs: [number, number[]][];
  importXrefs: [number, number[]][];
  callGraph: [number, number[]][];
  dataXrefs: [number, number[]][];
}

/** Append `from` to the list keyed by `target`. */
function push(map: Map<number, number[]>, target: number, from: number): void {
  const arr = map.get(target);
  if (arr) arr.push(from);
  else map.set(target, [from]);
}

/**
 * String, import, data and call-graph references for ARM64 instructions.
 *
 * `funcEntries` is `[address, size]` per function; without it there is no call
 * graph, because a caller cannot be attributed to a function. `dataSections`
 * bounds what counts as a data xref — an address materialised into `.text` is
 * a code pointer, not data.
 */
export function buildArm64Xrefs(
  instructions: readonly Instruction[],
  stringAddrs: number[],
  iatAddrs: number[],
  funcEntries?: [number, number][],
  dataSections?: { va: number; size: number }[],
): Arm64XrefResult {
  const stringSet = new Set(stringAddrs);
  const iatSet = new Set(iatAddrs);
  const strXrefs = new Map<number, number[]>();
  const impXrefs = new Map<number, number[]>();
  const dataXrefs = new Map<number, number[]>();

  const funcAddrSet = new Set<number>();
  const funcBounds: [number, number][] = [];
  if (funcEntries && funcEntries.length > 0) {
    for (const [addr] of funcEntries) funcAddrSet.add(addr);
    const sorted = [...funcEntries].sort((a, b) => a[0] - b[0]);
    for (const [addr, size] of sorted) funcBounds.push([addr, addr + size]);
  }

  const hasDataSections = dataSections !== undefined && dataSections.length > 0;
  const isInDataSection = (addr: number): boolean => {
    if (!hasDataSections) return false;
    for (const ds of dataSections) {
      if (addr >= ds.va && addr < ds.va + ds.size) return true;
    }
    return false;
  };

  /** Binary search for the function containing `addr`, or -1. */
  const findContainingFunc = (addr: number): number => {
    let lo = 0;
    let hi = funcBounds.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (addr < funcBounds[mid][0]) hi = mid - 1;
      else if (addr >= funcBounds[mid][1]) lo = mid + 1;
      else return funcBounds[mid][0];
    }
    return -1;
  };

  for (const ref of findArm64AddressRefs(instructions)) {
    if (stringSet.has(ref.target)) push(strXrefs, ref.target, ref.from);
    if (iatSet.has(ref.target)) push(impXrefs, ref.target, ref.from);
    if (
      hasDataSections &&
      !stringSet.has(ref.target) &&
      !iatSet.has(ref.target) &&
      isInDataSection(ref.target)
    ) {
      push(dataXrefs, ref.target, ref.from);
    }
  }

  // Call graph. `bl #0x…` is the only call whose target is known statically;
  // `blr x2` goes through a register and contributes no edge rather than a
  // guessed one — t64-arm.exe has 1725 of the former and 262 of the latter.
  const callGraphMap = new Map<number, Set<number>>();
  if (funcBounds.length > 0) {
    for (const insn of instructions) {
      const branch = classifyArm64Branch(insn.mnemonic, insn.opStr);
      if (branch?.kind !== "call" || branch.target === null) continue;
      if (!funcAddrSet.has(branch.target)) continue;
      const caller = findContainingFunc(insn.address);
      if (caller < 0) continue;
      let callees = callGraphMap.get(caller);
      if (!callees) {
        callees = new Set();
        callGraphMap.set(caller, callees);
      }
      callees.add(branch.target);
    }
  }

  return {
    stringXrefs: Array.from(strXrefs.entries()),
    importXrefs: Array.from(impXrefs.entries()),
    callGraph: Array.from(callGraphMap, ([addr, callees]) => [addr, Array.from(callees)]),
    dataXrefs: Array.from(dataXrefs.entries()),
  };
}
