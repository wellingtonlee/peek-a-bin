/**
 * The readable-data spans `detectFunctions` needs, and their wire format.
 *
 * ## Why they exist
 *
 * `detectFunctions` is handed the code section and nothing else. That is enough
 * for the x86 jump-table layout — MSVC drops the table into `.text`, right
 * after the function that dispatches through it — but not for the x64 one: the
 * RVA tables x64 MSVC, GCC and clang emit live in `.rdata`, outside the
 * disassembly window, so the detector could see the `lea`/`movsxd`/`add`/`jmp`
 * chain and still not read a single entry. `options.dataWindows` takes those
 * bytes; this module is what produces them.
 *
 * ## Which sections, and why not all of them
 *
 * {@link buildDataWindows} takes the initialized, non-executable, readable
 * sections — `isDataSection` in `../pe/sections.ts`, the shared predicate —
 * minus two kinds that are pure payload:
 *
 *  * **discardable** sections (`.reloc`, debug data). The loader is free to
 *    drop them; nothing addresses them with a `lea`.
 *  * **`.rsrc`**. Resources are icons, manifests and bitmaps, they are parsed
 *    by `pe/resources.ts` for their own sake, and they are routinely the
 *    largest section in a GUI binary. No compiler emits a jump table there.
 *
 * `.data` is kept even though const tables are read-only in every mainstream
 * x64 compiler: it is small next to `.rdata`, and a window that is never read
 * costs a memcpy, while a missing one costs a whole switch statement.
 *
 * The result is bounded by the file — every window is a view onto the loaded
 * buffer, clamped to it — so the added payload is at most "the file minus
 * `.text` and `.rsrc`", and on the distlib binaries it is 15-23 KiB against a
 * 55-110 KiB code section.
 *
 * ## Why the wire format is flat
 *
 * `workers/transfer.ts` transfers only *top-level* binary arguments, and
 * deliberately so: a deep walk would build a transfer list with one entry per
 * `Instruction.bytes`, which measured 80.6 s against 1.6 s to clone. So a
 * `{ base, bytes }[]` posted inside `options` would not be transferred — and
 * every `bytes` here is a view onto the **whole loaded file**, whose structured
 * clone copies the entire backing buffer, once per window. That is the exact
 * regression the transfer module exists to prevent.
 *
 * {@link packDataWindows} therefore flattens the windows into one byte array
 * plus plain-number spans, so the RPC carries a single top-level buffer that
 * gets sliced and transferred like any other, and {@link unpackDataWindows}
 * rebuilds the views on the far side with `subarray` (no second copy).
 */

import { isDataSection } from "../pe/sections";
import { IMAGE_SCN_MEM_DISCARDABLE } from "../pe/constants";
import type { SectionHeader } from "../pe/types";
import type { DataWindow } from "./functionDetect";

export type { DataWindow };

/** Resources: parsed elsewhere, never hold code or a jump table, often huge. */
const EXCLUDED_SECTIONS = new Set([".rsrc"]);

/** `name` as written in the section table, NUL-stripped and lowercased. */
function normalizeName(name: string): string {
  return name.replace(/\0/g, "").trim().toLowerCase();
}

/**
 * Readable data spans of a loaded image, keyed by virtual address.
 *
 * The `bytes` are **views onto `buffer`**, not copies: nothing is duplicated
 * until an RPC call packs them. A section whose file pointer or size does not
 * fit the buffer is clamped, and skipped entirely if nothing is left — a
 * malformed section table must not throw here, since this runs on every load.
 */
export function buildDataWindows(
  buffer: ArrayBuffer,
  sections: readonly SectionHeader[],
  imageBase: number,
): DataWindow[] {
  const windows: DataWindow[] = [];
  for (const section of sections) {
    if (!isDataSection(section)) continue;
    if ((section.characteristics & IMAGE_SCN_MEM_DISCARDABLE) !== 0) continue;
    if (EXCLUDED_SECTIONS.has(normalizeName(section.name))) continue;

    const start = section.pointerToRawData;
    if (!Number.isFinite(start) || start <= 0 || start >= buffer.byteLength) continue;
    const size = Math.min(section.sizeOfRawData, buffer.byteLength - start);
    if (!Number.isFinite(size) || size <= 0) continue;

    windows.push({
      base: imageBase + section.virtualAddress,
      bytes: new Uint8Array(buffer, start, size),
    });
  }
  return windows;
}

/** One window's place in a packed byte array. Plain numbers, clone-cheap. */
export interface DataWindowSpan {
  base: number;
  offset: number;
  length: number;
}

/** A packed set of windows: one buffer plus where each window sits in it. */
export interface PackedDataWindows {
  dataBytes: Uint8Array;
  dataSpans: DataWindowSpan[];
}

/**
 * Flatten windows into one transferable buffer.
 *
 * Returns `undefined` for an empty set so callers can spread the result into
 * an args object without adding empty keys. See the module docstring for why
 * this cannot just be posted as an array of views.
 */
export function packDataWindows(
  windows: readonly DataWindow[] | undefined,
): PackedDataWindows | undefined {
  if (!windows || windows.length === 0) return undefined;
  let total = 0;
  for (const w of windows) total += w.bytes.length;
  if (total === 0) return undefined;

  const dataBytes = new Uint8Array(total);
  const dataSpans: DataWindowSpan[] = [];
  let offset = 0;
  for (const w of windows) {
    dataBytes.set(w.bytes, offset);
    dataSpans.push({ base: w.base, offset, length: w.bytes.length });
    offset += w.bytes.length;
  }
  return { dataBytes, dataSpans };
}

/**
 * Rebuild windows from the packed form. Views, not copies.
 *
 * Returns `undefined` when either half is missing, so a caller that sent no
 * windows leaves `options.dataWindows` unset rather than empty — the two are
 * equivalent to the detector, but only the first says "nobody sent any".
 * Spans that do not fit the received bytes are dropped rather than trusted; a
 * worker message is not a place to throw on arithmetic that cannot happen.
 */
export function unpackDataWindows(
  dataBytes: Uint8Array | undefined,
  dataSpans: readonly DataWindowSpan[] | undefined,
): DataWindow[] | undefined {
  if (!dataBytes || !dataSpans || dataSpans.length === 0) return undefined;
  const windows: DataWindow[] = [];
  for (const span of dataSpans) {
    const end = span.offset + span.length;
    if (span.offset < 0 || span.length <= 0 || end > dataBytes.length) continue;
    windows.push({ base: span.base, bytes: dataBytes.subarray(span.offset, end) });
  }
  return windows.length > 0 ? windows : undefined;
}
