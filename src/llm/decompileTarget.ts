/**
 * Pure helpers behind `decompileForLLM`.
 *
 * Split out from `decompileForLLM.ts` because that module imports
 * `workers/disasmClient`, which constructs a real `Worker` at module scope and
 * therefore cannot be imported under vitest. Keep this file free of heavy
 * imports so the arithmetic below stays testable.
 */
import type { DisasmFunction } from "../disasm/types";
import type { SectionHeader } from "../pe/types";

/**
 * Byte range of `fn` within `section`'s raw data, or `null` when the function
 * does not lie wholly inside it.
 *
 * The bound is `sizeOfRawData`, not `virtualSize`: the bytes actually exist on
 * disk only up to the raw size, and a function reported past that end would
 * slice into the following section's data.
 */
export function functionByteRange(
  fn: DisasmFunction,
  section: SectionHeader,
  imageBase: number,
): { start: number; end: number } | null {
  const baseAddr = imageBase + section.virtualAddress;
  const offset = fn.address - baseAddr;
  if (offset < 0 || offset + fn.size > section.sizeOfRawData) return null;
  return { start: offset, end: offset + fn.size };
}

/**
 * Cap decompiled output at `maxLines`. `undefined` means no cap — the vuln
 * scanner sends whole functions because a truncated body can hide the very sink
 * it is looking for.
 */
export function truncateCode(code: string, maxLines?: number): string {
  if (maxLines === undefined) return code;
  return code.split("\n").slice(0, maxLines).join("\n");
}
