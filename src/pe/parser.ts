/**
 * PE Parser
 * Parses Windows Portable Executable files from ArrayBuffer
 */

import { parseSecurityDirectory } from "./authenticode";
import {
  IMAGE_DIRECTORY_ENTRY_BASERELOC,
  IMAGE_DIRECTORY_ENTRY_EXCEPTION,
  IMAGE_DIRECTORY_ENTRY_EXPORT,
  IMAGE_DIRECTORY_ENTRY_IMPORT,
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
  IMAGE_DIRECTORY_ENTRY_RESOURCE,
  IMAGE_DIRECTORY_ENTRY_TLS,
  IMAGE_DOS_SIGNATURE,
  IMAGE_NT_OPTIONAL_HDR32_MAGIC,
  IMAGE_NT_OPTIONAL_HDR64_MAGIC,
  IMAGE_NT_SIGNATURE,
  IMAGE_ORDINAL_FLAG32,
  IMAGE_ORDINAL_FLAG64,
} from "./constants";
import { formatOrdinalImport } from "./ordinalTables";
import { parsePdata } from "./pdata";
import { parseResourceDirectory } from "./resources";
import { findCodeSection } from "./sections";
import type {
  COFFHeader,
  DataDirectory,
  DOSHeader,
  ExportEntry,
  ImportEntry,
  LoadConfigDirectory,
  OptionalHeader32,
  OptionalHeader64,
  PEFile,
  RelocationBlock,
  RelocationEntry,
  SectionHeader,
  TLSDirectory,
} from "./types";
import { normalizeOptionalHeader } from "./types";

const textDecoder = new TextDecoder();

/**
 * The admission appended to a name `readCString` could not read whole.
 *
 * It is the shape `peek-a-bin-nygv` settled on for the PDB path
 * (`PDB_PATH_TRUNCATION_MARKER`), for the same reason: a narrower answer must
 * not wear a complete one's shape, and the *value* is the only channel that
 * reaches a reader — the render sites print these strings verbatim and the app
 * has no toast mechanism.
 *
 * `…` and `<`/`>` are bytes no name this parser reads can contain: a PE import,
 * export or library name is an ASCII C string emitted by a linker, so the
 * marker cannot be confused with one, and it cannot survive a round trip
 * through anything that resolves a name (no API matches it, no ordinal table
 * holds it, no symbol is called it).
 */
export const NAME_TRUNCATION_MARKER = "… <truncated>";

/** Whether `readCString` had to cut this string short. One declaration. */
export function isNameTruncated(name: string): boolean {
  return name.endsWith(NAME_TRUNCATION_MARKER);
}

/**
 * Read a NUL-terminated ASCII string, bounded by `maxLength` and by the buffer.
 *
 * **A CUT-SHORT READ SAYS SO**, by appending {@link NAME_TRUNCATION_MARKER}.
 * The 1024-byte cap has been here since long before the marker and it is the
 * right bound — no linker emits a name near it — but it used to truncate
 * SILENTLY, so a crafted `.rdata` holding 1024 non-NUL bytes where a name
 * should be produced a 1024-character library or function name that read as the
 * file's own (`peek-a-bin-tmo9`, measured: exactly 1024 characters, tail
 * `"AAAAAAAA"`, nothing marking it).
 *
 * THE MARKER IS NOT ENOUGH ON ITS OWN, and that asymmetry is the finding.
 * A PDB path is read *out* of the tool by a human; these names are also read by
 * `computeImphash`, `matchesApi`, `resolveOrdinal` and the IAT map. A marker
 * there changes a hash rather than merely labelling a string, which is the
 * `Ordinal_<n>` trap again. So `parseImports` additionally treats a truncated
 * name as evidence that the entry is **not whole** (`ImportEntry.truncated`),
 * which propagates to `PEFile.importsTruncated`, which makes `computeImphash`
 * refuse outright — so a marked name can never reach a digest.
 *
 * Truncation is decided exactly: the read stopped at the bound *and* there is
 * no NUL sitting at it. A name of exactly `maxLength` bytes plus its terminator
 * is whole and is not marked.
 */
function readCString(view: DataView, offset: number, maxLength = 1024): string {
  let end = offset;
  const limit = Math.min(offset + maxLength, view.byteLength);
  while (end < limit && view.getUint8(end) !== 0) end++;
  const text = textDecoder.decode(
    new Uint8Array(view.buffer, view.byteOffset + offset, end - offset),
  );
  const terminated = end < view.byteLength && view.getUint8(end) === 0;
  return terminated ? text : text + NAME_TRUNCATION_MARKER;
}

/**
 * Convert RVA (Relative Virtual Address) to file offset.
 *
 * O(sections) per lookup. This is the reference implementation and defines the
 * semantics every other path must reproduce: the *first* section in table order
 * whose virtual range contains the RVA wins, and an RVA that lands past that
 * section's raw data resolves to -1 rather than falling through to a later
 * section. Fine for one-off lookups; anything resolving many RVAs (import
 * thunks, `.pdata` entries) should build a `SectionIndex` once with
 * `buildSectionIndex()` and call `rvaToFileOffsetIndexed()` instead.
 */
export function rvaToFileOffset(rva: number, sections: readonly SectionHeader[]): number {
  return offsetInSection(scanSectionForRva(rva, sections), rva);
}

/**
 * The first section in table order whose *virtual* range contains `rva`, or
 * null. The containment half of `rvaToFileOffset`'s semantics, factored out so
 * that "which section holds this RVA" has one declaration — `sectionForRva`
 * (the searchable form) and `sectionRawLimitForRva` (how far a walk may go
 * without leaving it) both answer from it rather than restating the rule.
 */
function scanSectionForRva(rva: number, sections: readonly SectionHeader[]): SectionHeader | null {
  for (const section of sections) {
    if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
      return section;
    }
  }
  return null;
}

/**
 * `rva`'s file offset inside a section already known to contain it virtually,
 * or -1 when it lands past that section's raw data. Deliberately does NOT fall
 * through to a later section: see `rvaToFileOffset`'s docstring.
 */
function offsetInSection(section: SectionHeader | null, rva: number): number {
  if (section === null) return -1;
  const offset = rva - section.virtualAddress;
  if (offset >= section.sizeOfRawData) return -1;
  return section.pointerToRawData + offset;
}

/** The searchable form of a section table: sections by ascending RVA. */
interface SortedSections {
  readonly sections: readonly SectionHeader[];
  readonly starts: Float64Array;
}

/**
 * Below this many sections the index declines to build a searchable form and
 * lookups just scan.
 *
 * The scan is not the disaster it looks like. It walks contiguous objects and
 * stops at the containing section, and RVAs resolved in bulk — import thunks,
 * `.pdata` unwind info — nearly all land in the same early section, so it exits
 * after a couple of iterations. A binary search mispredicts at every step
 * instead.
 *
 * Which one wins is a function of the section count *and* of where the lookups
 * land — not of the count alone. Re-measured 2026-08-11 (node 18, i7-10710U, 2
 * cores, 200k lookups per figure, median of 7, scan and search verified to
 * agree on every RVA): with hits spread uniformly across the table, scan/search
 * came in at 4.35/9.18 ms at 16 sections, 5.37/12.11 ms at 24, and the search
 * was ahead by 1.28x at 32. With hits confined to the first two sections the
 * scan won at every count measured, up to 20000. The threshold is also
 * insensitive — anywhere in 16–64 is defensible, because below 64 sections the
 * absolute gap either way is under ~25 ms per 200k lookups.
 *
 * So 32 sits above any table a linker emits, leaving real files on the scan
 * they already took: 1.04x end to end, i.e. noise. Its whole value is bounding
 * the hostile case, since section count is a uint16 bounded only by the file
 * size. Measured old-vs-new in one process, the same 200k lookups over a
 * 1006-section table went 405 ms → 30 ms, and over a 20006-section table
 * 9.08 s → 57 ms, both on the main thread.
 */
const MIN_SECTIONS_TO_SEARCH = 32;

/**
 * A section table prepared for repeated RVA lookups. Build once per parse with
 * `buildSectionIndex()`; see `rvaToFileOffsetIndexed()`.
 */
export interface SectionIndex {
  /** The table in file order — both the fallback and the reference semantics. */
  readonly sections: readonly SectionHeader[];
  /**
   * The same sections by ascending virtual address, or `null` when lookups
   * should just scan: either the table is short enough that scanning is
   * cheaper, or its sections overlap and only the scan resolves them correctly.
   *
   * Binary search answers "which section holds this RVA"; the scan answers
   * "which is the *first* section in table order that holds it". Those agree
   * exactly when no two sections overlap, since then at most one can hold any
   * RVA and file order stops mattering — which is why an out-of-order table can
   * simply be sorted, but an overlapping one cannot, and goes back to the scan
   * rather than silently resolving to a different section's bytes.
   */
  readonly sorted: SortedSections | null;
}

/**
 * Prepare a section table for repeated RVA lookups. O(sections) for the
 * ordinary already-sorted table, O(sections log sections) otherwise, once.
 */
export function buildSectionIndex(sections: readonly SectionHeader[]): SectionIndex {
  const count = sections.length;
  if (count < MIN_SECTIONS_TO_SEARCH) return { sections, sorted: null };

  // A linker-produced table is already ascending and disjoint, so it is its own
  // index. `>=` keeps zero-sized and exactly abutting sections on this path.
  let ascending = true;
  let prevEnd = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < count; i++) {
    if (!(sections[i].virtualAddress >= prevEnd)) {
      ascending = false;
      break;
    }
    prevEnd = sections[i].virtualAddress + sections[i].virtualSize;
  }

  if (ascending) {
    const starts = new Float64Array(count);
    for (let i = 0; i < count; i++) starts[i] = sections[i].virtualAddress;
    return { sections, sorted: { sections, starts } };
  }

  // Out of order. Sort a copy and re-check: disjoint ranges in ascending order
  // are all the search needs. A NaN address or size survives neither the sort
  // nor this check, and lands on the scan.
  const ordered = sections.slice().sort((a, b) => a.virtualAddress - b.virtualAddress);
  const starts = new Float64Array(count);
  prevEnd = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < count; i++) {
    if (!(ordered[i].virtualAddress >= prevEnd)) return { sections, sorted: null };
    starts[i] = ordered[i].virtualAddress;
    prevEnd = ordered[i].virtualAddress + ordered[i].virtualSize;
  }

  return { sections, sorted: { sections: ordered, starts } };
}

/**
 * Convert an RVA to a file offset using a prebuilt index. O(log sections)
 * unless the section table overlaps, where it falls back to
 * `rvaToFileOffset`'s scan. Returns exactly what
 * `rvaToFileOffset(rva, index.sections)` would.
 */
export function rvaToFileOffsetIndexed(rva: number, index: SectionIndex): number {
  return offsetInSection(sectionForRva(rva, index), rva);
}

/**
 * The section `rvaToFileOffsetIndexed` resolves `rva` into, or null. Exactly
 * what `scanSectionForRva(rva, index.sections)` answers, in O(log sections).
 */
function sectionForRva(rva: number, index: SectionIndex): SectionHeader | null {
  const sorted = index.sorted;
  if (sorted === null) return scanSectionForRva(rva, index.sections);

  // Upper bound: how many section starts are <= rva. The sections being sorted
  // and disjoint, the one before that boundary is the only possible container.
  // A NaN rva compares false against everything, so it collapses to 0 and
  // leaves as null instead of looping.
  const starts = sorted.starts;
  let lo = 0;
  let hi = starts.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= rva) lo = mid + 1;
    else hi = mid;
  }
  if (lo === 0) return null;

  const section = sorted.sections[lo - 1];
  return rva - section.virtualAddress < section.virtualSize ? section : null;
}

/**
 * File offset one past the last byte of raw data in the section holding `rva`,
 * or -1 when `rva` is in no section.
 *
 * This is the bound for a walk that starts at a resolved RVA and steps forward:
 * an array the file places inside a section does not continue past it, so the
 * section end is a limit **the file itself declares** and one no attacker can
 * inflate beyond the image. `min(virtualSize, sizeOfRawData)` because
 * `offsetInSection` refuses both, so a byte past either is a byte the rest of
 * this parser will not resolve.
 *
 * **Exported because it is the ONE DECLARATION of that bound**, and five walks
 * outside `parseImports` now want it — the two export tables, the relocation
 * blocks, the debug directory (`metadata.ts`) and `.pdata` (`pdata.ts`). Every
 * one of those was bounded by the end of the FILE, which is exactly the shape
 * `peek-a-bin-nygv` and `peek-a-bin-tmo9` both turned out to be. See the
 * attacker-controlled-bound census in `docs/gotchas.md`.
 *
 * Returns -1 for an unmapped RVA; a caller wanting "no opinion" must spell that
 * as `Number.POSITIVE_INFINITY` itself rather than passing -1 into a `Math.min`.
 */
export function sectionRawLimitForRva(rva: number, index: SectionIndex): number {
  const section = sectionForRva(rva, index);
  if (section === null) return -1;
  return section.pointerToRawData + Math.min(section.virtualSize, section.sizeOfRawData);
}

/**
 * File offset of `rva`, but only if the whole of `[rva, rva + length)` lands in
 * one section's raw data. `-1` otherwise.
 *
 * `rvaToFileOffsetIndexed` answers for a single byte, which is the wrong
 * question for a fixed-size structure: a directory that begins 8 bytes before
 * the end of `.rdata` resolves perfectly well and then reads its remaining
 * fields out of whatever follows in the file. Resolving the last byte too is the
 * cheapest way to ask the section table the question that matters, and it reuses
 * the containment rules rather than restating them.
 */
function rvaRangeToFileOffset(rva: number, length: number, index: SectionIndex): number {
  if (length <= 0) return -1;
  const start = rvaToFileOffsetIndexed(rva, index);
  if (start < 0) return -1;
  const last = rvaToFileOffsetIndexed(rva + length - 1, index);
  return last === start + length - 1 ? start : -1;
}

/**
 * Read DOS Header
 */
function parseDOSHeader(view: DataView): DOSHeader {
  // The DOS header is 64 bytes; without this, a short file throws a bare
  // RangeError from getUint16/getUint32 instead of a usable parse error.
  if (view.byteLength < 64) {
    throw new Error(`File too small to be a PE (${view.byteLength} bytes, need at least 64)`);
  }

  const e_magic = view.getUint16(0, true);

  if (e_magic !== IMAGE_DOS_SIGNATURE) {
    throw new Error(`Invalid DOS signature: 0x${e_magic.toString(16)} (expected 0x5A4D)`);
  }

  const e_lfanew = view.getUint32(60, true);

  return { e_magic, e_lfanew };
}

/**
 * Read COFF Header
 */
function parseCOFFHeader(view: DataView, offset: number): COFFHeader {
  return {
    machine: view.getUint16(offset, true),
    numberOfSections: view.getUint16(offset + 2, true),
    timeDateStamp: view.getUint32(offset + 4, true),
    pointerToSymbolTable: view.getUint32(offset + 8, true),
    numberOfSymbols: view.getUint32(offset + 12, true),
    sizeOfOptionalHeader: view.getUint16(offset + 16, true),
    characteristics: view.getUint16(offset + 18, true),
  };
}

/**
 * Read Optional Header (PE32)
 */
function parseOptionalHeader32(view: DataView, offset: number): OptionalHeader32 {
  return {
    magic: view.getUint16(offset, true),
    majorLinkerVersion: view.getUint8(offset + 2),
    minorLinkerVersion: view.getUint8(offset + 3),
    sizeOfCode: view.getUint32(offset + 4, true),
    sizeOfInitializedData: view.getUint32(offset + 8, true),
    sizeOfUninitializedData: view.getUint32(offset + 12, true),
    addressOfEntryPoint: view.getUint32(offset + 16, true),
    baseOfCode: view.getUint32(offset + 20, true),
    baseOfData: view.getUint32(offset + 24, true),
    imageBase: view.getUint32(offset + 28, true),
    sectionAlignment: view.getUint32(offset + 32, true),
    fileAlignment: view.getUint32(offset + 36, true),
    majorOperatingSystemVersion: view.getUint16(offset + 40, true),
    minorOperatingSystemVersion: view.getUint16(offset + 42, true),
    majorImageVersion: view.getUint16(offset + 44, true),
    minorImageVersion: view.getUint16(offset + 46, true),
    majorSubsystemVersion: view.getUint16(offset + 48, true),
    minorSubsystemVersion: view.getUint16(offset + 50, true),
    win32VersionValue: view.getUint32(offset + 52, true),
    sizeOfImage: view.getUint32(offset + 56, true),
    sizeOfHeaders: view.getUint32(offset + 60, true),
    checkSum: view.getUint32(offset + 64, true),
    subsystem: view.getUint16(offset + 68, true),
    dllCharacteristics: view.getUint16(offset + 70, true),
    sizeOfStackReserve: view.getUint32(offset + 72, true),
    sizeOfStackCommit: view.getUint32(offset + 76, true),
    sizeOfHeapReserve: view.getUint32(offset + 80, true),
    sizeOfHeapCommit: view.getUint32(offset + 84, true),
    loaderFlags: view.getUint32(offset + 88, true),
    numberOfRvaAndSizes: view.getUint32(offset + 92, true),
  };
}

/**
 * Read Optional Header (PE32+)
 */
function parseOptionalHeader64(view: DataView, offset: number): OptionalHeader64 {
  return {
    magic: view.getUint16(offset, true),
    majorLinkerVersion: view.getUint8(offset + 2),
    minorLinkerVersion: view.getUint8(offset + 3),
    sizeOfCode: view.getUint32(offset + 4, true),
    sizeOfInitializedData: view.getUint32(offset + 8, true),
    sizeOfUninitializedData: view.getUint32(offset + 12, true),
    addressOfEntryPoint: view.getUint32(offset + 16, true),
    baseOfCode: view.getUint32(offset + 20, true),
    imageBase: view.getBigUint64(offset + 24, true),
    sectionAlignment: view.getUint32(offset + 32, true),
    fileAlignment: view.getUint32(offset + 36, true),
    majorOperatingSystemVersion: view.getUint16(offset + 40, true),
    minorOperatingSystemVersion: view.getUint16(offset + 42, true),
    majorImageVersion: view.getUint16(offset + 44, true),
    minorImageVersion: view.getUint16(offset + 46, true),
    majorSubsystemVersion: view.getUint16(offset + 48, true),
    minorSubsystemVersion: view.getUint16(offset + 50, true),
    win32VersionValue: view.getUint32(offset + 52, true),
    sizeOfImage: view.getUint32(offset + 56, true),
    sizeOfHeaders: view.getUint32(offset + 60, true),
    checkSum: view.getUint32(offset + 64, true),
    subsystem: view.getUint16(offset + 68, true),
    dllCharacteristics: view.getUint16(offset + 70, true),
    sizeOfStackReserve: view.getBigUint64(offset + 72, true),
    sizeOfStackCommit: view.getBigUint64(offset + 80, true),
    sizeOfHeapReserve: view.getBigUint64(offset + 88, true),
    sizeOfHeapCommit: view.getBigUint64(offset + 96, true),
    loaderFlags: view.getUint32(offset + 104, true),
    numberOfRvaAndSizes: view.getUint32(offset + 108, true),
  };
}

/**
 * Read Data Directories
 */
function parseDataDirectories(view: DataView, offset: number, count: number): DataDirectory[] {
  const directories: DataDirectory[] = [];

  // numberOfRvaAndSizes is attacker-controlled. The PE spec caps it at 16, and
  // entries must fit in the buffer; without this a crafted value allocates
  // millions of objects before the first out-of-range read throws.
  const safeCount = Math.min(count, 16, Math.max(0, Math.floor((view.byteLength - offset) / 8)));

  for (let i = 0; i < safeCount; i++) {
    const dirOffset = offset + i * 8;
    directories.push({
      virtualAddress: view.getUint32(dirOffset, true),
      size: view.getUint32(dirOffset + 4, true),
    });
  }

  return directories;
}

/**
 * Read Section Headers
 */
function parseSectionHeaders(view: DataView, offset: number, count: number): SectionHeader[] {
  const sections: SectionHeader[] = [];

  // numberOfSections is a uint16 (up to 65535) read straight off the file. Each
  // header is 40 bytes, so anything that cannot fit in the buffer is bogus —
  // clamp rather than let getUint8 throw partway through.
  const safeCount = Math.min(count, Math.max(0, Math.floor((view.byteLength - offset) / 40)));

  for (let i = 0; i < safeCount; i++) {
    const sectionOffset = offset + i * 40;

    // Read section name (8 bytes, null-padded)
    const nameBytes: number[] = [];
    for (let j = 0; j < 8; j++) {
      const byte = view.getUint8(sectionOffset + j);
      if (byte !== 0) nameBytes.push(byte);
    }
    const name = String.fromCharCode(...nameBytes);

    sections.push({
      name,
      virtualSize: view.getUint32(sectionOffset + 8, true),
      virtualAddress: view.getUint32(sectionOffset + 12, true),
      sizeOfRawData: view.getUint32(sectionOffset + 16, true),
      pointerToRawData: view.getUint32(sectionOffset + 20, true),
      pointerToRelocations: view.getUint32(sectionOffset + 24, true),
      pointerToLinenumbers: view.getUint32(sectionOffset + 28, true),
      numberOfRelocations: view.getUint16(sectionOffset + 32, true),
      numberOfLinenumbers: view.getUint16(sectionOffset + 34, true),
      characteristics: view.getUint32(sectionOffset + 36, true),
    });
  }

  return sections;
}

/**
 * The most import descriptors — i.e. imported libraries — that will be read.
 *
 * A descriptor is not free: it resolves an RVA and decodes a name of up to
 * `readCString`'s 1024 bytes. Real images import from a handful of libraries
 * (2-3 across every binary in the corpus; a heavily linked application reaches
 * the low hundreds), so 4096 is more than an order of magnitude above anything
 * a linker emits and still bounds the walk at a few megabytes of decoding.
 */
export const MAX_IMPORT_DESCRIPTORS = 4096;

/**
 * The most imported functions that will be read **across the whole table**.
 *
 * Deliberately one global budget rather than a per-library cap, because the
 * cost that matters is the PRODUCT: a crafted file supplies both the descriptor
 * count and the thunk count, and capping each separately still multiplies out.
 * Measured at 5baec33 on a 1 MiB fixture (52,416 descriptors all naming one
 * unterminated thunk array), the old walk did not merely hang — node died with
 * `FATAL ERROR: Ineffective mark-compacts near heap limit`, i.e. 4 GB of import
 * entries out of a one-megabyte file. In a browser that is the tab.
 *
 * 65536 is the same budget `parseResourceDirectory` gives its own tree walk,
 * and is far above any real total (94 functions is the corpus maximum; a large
 * C++ application reaches a few thousand). A DLL cannot export more than 65535
 * symbols, so this is also above what any single library could legitimately
 * contribute.
 */
export const MAX_IMPORT_FUNCTIONS = 65536;

/**
 * Parse Import Table.
 *
 * TWO ATTACKER-CONTROLLED WALKS, EACH BOUNDED FOUR WAYS, SMALLEST WINNING, AND
 * A CUT-SHORT ONE SAYS SO (`peek-a-bin-tmo9`, the list-shaped sibling of
 * `peek-a-bin-nygv`'s PDB path).
 *
 * The descriptor walk stops at the null descriptor and the thunk walk stops at
 * the null thunk, but a file need not supply either. Before this, the thunk
 * walk's only other bound was the end of the FILE, so an unterminated array
 * pushed one import entry per pointer-width slot all the way to EOF — inside
 * `parsePE`, on the main thread, before anything renders.
 *
 * The bounds:
 *
 *  - **the containing section's raw extent** (`sectionRawLimitForRva`). An
 *    import array the file places inside a section does not continue past it,
 *    so this is evidence the file itself provides and cannot inflate beyond the
 *    image. It is also the bound that improves the ANSWER rather than merely
 *    the cost: without it a missing terminator at the end of `.rdata` reads the
 *    next section's bytes — or the overlay's — as thunks.
 *  - **the directory's declared size**, for descriptors, as before.
 *  - **a count cap**, which is the bound that actually stops the hostile case,
 *    since a section's declared size is attacker-controlled too.
 *  - **the buffer**.
 *
 * WHY THE ADMISSION IS NOT A MARKER. `nygv` spelled its truncation into the
 * value because the value was a string and the render site printed it verbatim.
 * Here the value is a LIST, and there is no honest place to put a marker in
 * one: an invented `<truncated>` entry would be a lie inside a list that feeds
 * `computeImphash`, the Imports tab, the IAT map and the MCP tools — the
 * `Ordinal_<n>` trap with a new spelling. So the admission takes the two forms
 * a list can carry it in:
 *
 *  - `ImportEntry.truncated` / `PEFile.importsTruncated`, the machine-readable
 *    half, on the model of `ResourceTree.truncated`; and
 *  - a REFUSAL from `computeImphash`, which is the strongest form of "a
 *    narrower answer must not wear a complete one's shape". An imphash over a
 *    short list is a well-formed digest of something the file does not contain,
 *    and it is only ever compared with another tool's answer, so it fails by
 *    matching nothing while looking entirely correct.
 *
 * The reader-facing half is the Imports tab's own counts, which say the list is
 * incomplete rather than quietly describing a smaller file.
 */
function parseImports(
  view: DataView,
  importDir: DataDirectory,
  sectionIndex: SectionIndex,
  is64: boolean,
  imageBase: number,
): { imports: ImportEntry[]; truncated: boolean } {
  if (!importDir.virtualAddress || !importDir.size) {
    return { imports: [], truncated: false };
  }

  const imports: ImportEntry[] = [];
  const importTableOffset = rvaToFileOffsetIndexed(importDir.virtualAddress, sectionIndex);

  if (importTableOffset < 0 || importTableOffset >= view.byteLength) {
    return { imports, truncated: false };
  }

  let descriptorOffset = importTableOffset;
  const descriptorSize = 20;
  /** Whether any walk below stopped at a bound instead of at its terminator. */
  let tableTruncated = false;
  /** Functions left in the whole-table budget. See MAX_IMPORT_FUNCTIONS. */
  let functionBudget = MAX_IMPORT_FUNCTIONS;

  const descriptorSectionLimit = sectionRawLimitForRva(importDir.virtualAddress, sectionIndex);
  const descriptorLimit = Math.min(
    view.byteLength,
    importTableOffset + Math.max(0, importDir.size),
    descriptorSectionLimit >= 0 ? descriptorSectionLimit : Number.POSITIVE_INFINITY,
    importTableOffset + MAX_IMPORT_DESCRIPTORS * descriptorSize,
  );

  // Walk import descriptors until the null entry — or until a bound, which is
  // the case that has to say so.
  for (;;) {
    if (descriptorOffset + descriptorSize > descriptorLimit) {
      tableTruncated = true;
      break;
    }
    const originalFirstThunk = view.getUint32(descriptorOffset, true);
    const nameRVA = view.getUint32(descriptorOffset + 12, true);
    const firstThunk = view.getUint32(descriptorOffset + 16, true);

    // Null descriptor marks end
    if (!originalFirstThunk && !nameRVA && !firstThunk) {
      break;
    }

    // Read library name. An RVA the section table does not map drops the whole
    // library — the descriptor is real, the file declared it, and we cannot name
    // it — so the table is NOT whole and must say so. Without this a crafted (or
    // simply damaged) file renders a shorter Imports tab that reads as complete
    // and hands `computeImphash` a confident digest over a list missing a DLL.
    const nameOffset = rvaToFileOffsetIndexed(nameRVA, sectionIndex);
    if (nameOffset < 0 || nameOffset >= view.byteLength) {
      tableTruncated = true;
      descriptorOffset += descriptorSize;
      continue;
    }

    const libraryName = readCString(view, nameOffset);
    const functions: string[] = [];
    const iatAddresses: number[] = [];
    // A name that could not be read whole does not describe this library, so
    // the entry is not whole either — see `readCString`'s docstring for why the
    // marker alone is not the answer where the value reaches a digest.
    let entryTruncated = isNameTruncated(libraryName);

    // Read import names from INT (Import Name Table)
    const thunkRVA = originalFirstThunk || firstThunk;
    const thunkSize = is64 ? 8 : 4;
    // A thunk RVA outside every section yields -1; without this guard the loop
    // below is entered with a negative offset and getBigUint64 throws, failing
    // the whole file load. Every other rvaToFileOffset call site checks this.
    let thunkOffset = thunkRVA ? rvaToFileOffsetIndexed(thunkRVA, sectionIndex) : -1;
    // A descriptor that names a thunk array we cannot resolve is not a library
    // that imports nothing: `KERNEL32.dll (0)` is a statement about the file,
    // and the two are indistinguishable without this. `!thunkRVA` really does
    // mean "no thunk array declared" and is left unmarked.
    if (thunkRVA && thunkOffset < 0) entryTruncated = true;
    if (thunkRVA && thunkOffset >= 0) {
      let funcIndex = 0;
      const thunkSectionLimit = sectionRawLimitForRva(thunkRVA, sectionIndex);
      const thunkLimit = Math.min(
        view.byteLength,
        thunkSectionLimit >= 0 ? thunkSectionLimit : Number.POSITIVE_INFINITY,
      );

      for (;;) {
        if (thunkOffset + thunkSize > thunkLimit) {
          entryTruncated = true;
          break;
        }
        if (functionBudget <= 0) {
          entryTruncated = true;
          break;
        }
        const thunkValue = is64
          ? view.getBigUint64(thunkOffset, true)
          : BigInt(view.getUint32(thunkOffset, true));

        if (thunkValue === 0n) break;
        functionBudget--;

        // WHAT THIS SLOT IMPORTS, or null when the file does not let us say.
        //
        // **`functions` AND `iatAddresses` ARE PARALLEL ARRAYS PAIRED BY INDEX
        // BY FOUR CONSUMERS** — `disasm/operands.ts`'s `buildIATLookup`
        // (`iatAddresses[i]` -> `functions[i]`, which is what labels a call site
        // in the disassembly), `ImportsView`, `useVulnScanner` and
        // `mcp/resources.ts`. The IAT address used to be pushed
        // unconditionally while the name was pushed only if its hint/name
        // record resolved, so ONE unresolvable name RVA shifted every later
        // name up one slot and **mislabelled every remaining call site in that
        // library, on real instructions, with another import's name**. That is
        // a wrong value, not a missing one, and no flag repairs it.
        //
        // So a slot contributes to BOTH arrays or to NEITHER, which is what
        // keeps the pairing an invariant rather than a convention. `funcIndex`
        // still counts every thunk, so the IAT VAs that do get pushed stay the
        // addresses the loader will use. Inventing a placeholder name to keep
        // the arrays the same length was the other option and is the
        // `Ordinal_<n>` trap: it would put a fabricated symbol into a list that
        // feeds `computeImphash` and `matchesApi`.
        //
        // The structural fix is one array of `{ name, iatAddress }` pairs, so
        // the desync is unrepresentable. Not taken here: it changes a `PEFile`
        // shape read by four modules in three directories, and the invariant
        // this loop now keeps is testable directly.
        let funcName: string | null = null;

        // Check if import by ordinal
        const ordinalFlag = is64 ? IMAGE_ORDINAL_FLAG64 : BigInt(IMAGE_ORDINAL_FLAG32);
        if (thunkValue & ordinalFlag) {
          const ordinal = Number(thunkValue & 0xffffn);
          funcName = formatOrdinalImport(ordinal);
        } else {
          // Import by name
          const nameTableRVA = Number(thunkValue);
          const nameTableOffset = rvaToFileOffsetIndexed(nameTableRVA, sectionIndex);

          if (nameTableOffset >= 0 && nameTableOffset + 2 < view.byteLength) {
            // Skip hint (2 bytes)
            funcName = readCString(view, nameTableOffset + 2);
            if (isNameTruncated(funcName)) entryTruncated = true;
          } else {
            // A declared import we cannot name: the entry is not whole.
            entryTruncated = true;
          }
        }

        if (funcName !== null) {
          functions.push(funcName);
          iatAddresses.push(imageBase + firstThunk + funcIndex * thunkSize);
        }

        thunkOffset += thunkSize;
        funcIndex++;
      }
    }

    imports.push(
      entryTruncated
        ? { libraryName, functions, iatAddresses, truncated: true }
        : { libraryName, functions, iatAddresses },
    );
    if (entryTruncated) tableTruncated = true;
    descriptorOffset += descriptorSize;
  }

  return { imports, truncated: tableTruncated };
}

/**
 * The most export names, and the most address-table slots, that will be read.
 *
 * **NOT AN INVENTED NUMBER — it is the format's own ceiling.** The export
 * ordinal table is an array of `uint16` holding the unbiased index into the
 * address table, so a PE cannot bind more than 65536 slots to names at all, and
 * the loader's ordinal space is a `uint16` too. That is the same reasoning, and
 * the same value, `MAX_IMPORT_FUNCTIONS` already records above ("A DLL cannot
 * export more than 65535 symbols"), and it means a well-formed file cannot be
 * cut short by it.
 *
 * Real tables sit three orders of magnitude below: `ntdll.dll` exports ~2400.
 * **That figure is documentation, not measurement — no binary in this corpus
 * exports anything at all** (all six are EXEs, and `corpus:parserdiff`'s two
 * export gates are VACUOUS), so nothing here can demonstrate the cap is above
 * a real table. The format argument is the whole of the evidence.
 */
export const MAX_EXPORT_ENTRIES = 65536;

/**
 * Parse Export Table.
 *
 * **THREE ATTACKER-CONTROLLED COUNTS, AND UNTIL NOW THE ONLY BOUND ON ANY OF
 * THEM WAS THE END OF THE FILE** — the `peek-a-bin-tmo9` shape, in the reader
 * the census went looking at first because `NumberOfNames` and
 * `NumberOfFunctions` are a classic multiplying pair.
 *
 * They do not in fact multiply: the two walks are sequential, and the alias
 * loop (`for (const name of names)`) is bounded by the *total* number of names
 * because `namesByIndex` partitions them. What was there instead is a plain
 * hundredfold amplification, and it was measured rather than reasoned: at
 * `d8d8a6d`, a **1,049,088-byte** fixture declaring `0xFFFFFFFF` for both
 * counts and a name-pointer table of slots all aimed at one unterminated run
 * yielded **524,093 export entries carrying 104,696,157 characters of name**,
 * inside `parsePE`, on the main thread, before anything renders.
 *
 * Every walk is now bounded four ways, smallest winning, exactly as
 * `parseImports` is:
 *
 *  - **the containing section's raw extent** (`sectionRawLimitForRva`), which
 *    is the bound that improves the ANSWER and not merely the cost: a name
 *    pointer table that runs off the end of `.rdata` was reading the next
 *    section's bytes — or the overlay's — as name RVAs;
 *  - **the declared count**, as before;
 *  - **`MAX_EXPORT_ENTRIES`**, the count cap, which is what actually stops the
 *    hostile case since a section's declared size is attacker-controlled too;
 *  - **the buffer**.
 *
 * A list cannot carry a truncation marker (an invented entry would be a lie
 * inside a list that feeds the Exports tab, function detection and the MCP
 * tools), so the admission is the flag `PEFile.exportsTruncated` and the
 * Exports tab's own heading count — the same two forms `parseImports` uses.
 * There is no export-side `computeImphash` to refuse, which is why this needs
 * no third form.
 */
function parseExports(
  view: DataView,
  exportDir: DataDirectory,
  sectionIndex: SectionIndex,
): { exports: ExportEntry[]; truncated: boolean } {
  if (!exportDir.virtualAddress || !exportDir.size) {
    return { exports: [], truncated: false };
  }

  const exports: ExportEntry[] = [];
  const exportTableOffset = rvaToFileOffsetIndexed(exportDir.virtualAddress, sectionIndex);

  if (exportTableOffset < 0 || exportTableOffset + 40 > view.byteLength) {
    return { exports, truncated: false };
  }

  // Read Export Directory Table
  const ordinalBase = view.getUint32(exportTableOffset + 16, true);
  const numberOfFunctions = view.getUint32(exportTableOffset + 20, true);
  const numberOfNames = view.getUint32(exportTableOffset + 24, true);
  const addressTableRVA = view.getUint32(exportTableOffset + 28, true);
  const namePointerRVA = view.getUint32(exportTableOffset + 32, true);
  const ordinalTableRVA = view.getUint32(exportTableOffset + 36, true);

  const addressTableOffset = rvaToFileOffsetIndexed(addressTableRVA, sectionIndex);
  const namePointerOffset = rvaToFileOffsetIndexed(namePointerRVA, sectionIndex);
  const ordinalTableOffset = rvaToFileOffsetIndexed(ordinalTableRVA, sectionIndex);

  // Every export ultimately comes out of the address table; without it there is
  // nothing to report. The name tables are optional — a DLL may export purely
  // by ordinal — so an unmapped name table only costs the names.
  if (addressTableOffset < 0) {
    return { exports, truncated: false };
  }

  /** Whether any walk below stopped at a bound instead of at its declared count. */
  let tableTruncated = false;

  /**
   * How far a table starting at `offset` may be read: its own section's raw
   * extent where the section table places it, and the buffer otherwise. One
   * helper because the three tables ask the identical question and a fourth
   * hand-written copy is how these bounds drift apart.
   */
  const limitFor = (rva: number, offset: number): number => {
    const sectionLimit = sectionRawLimitForRva(rva, sectionIndex);
    return Math.max(
      0,
      Math.min(view.byteLength, sectionLimit >= 0 ? sectionLimit : Number.POSITIVE_INFINITY) -
        offset,
    );
  };

  // Address-table index -> the names bound to it. Multiple names may resolve to
  // the same slot (aliases), and dumpbin lists each, so keep them all.
  const namesByIndex = new Map<number, string[]>();

  if (namePointerOffset >= 0 && ordinalTableOffset >= 0) {
    // numberOfNames comes straight off the file as a uint32, so it bounds
    // nothing on its own. Four bounds, smallest winning — see the docstring.
    const maxNames = Math.min(
      numberOfNames,
      MAX_EXPORT_ENTRIES,
      Math.floor(limitFor(namePointerRVA, namePointerOffset) / 4),
      Math.floor(limitFor(ordinalTableRVA, ordinalTableOffset) / 2),
    );
    if (maxNames < numberOfNames) tableTruncated = true;

    // Walk name pointer table
    for (let i = 0; i < maxNames; i++) {
      const namePointerPos = namePointerOffset + i * 4;
      const ordinalPos = ordinalTableOffset + i * 2;

      // Past the end of the buffer — every later index is too, so stop rather than
      // spin to numberOfNames.
      if (namePointerPos + 4 > view.byteLength || ordinalPos + 2 > view.byteLength) {
        break;
      }

      const nameRVA = view.getUint32(namePointerPos, true);
      // The ordinal table holds the *unbiased* index into the address table,
      // not the ordinal the loader reports.
      const addressIndex = view.getUint16(ordinalPos, true);

      const nameOffset = rvaToFileOffsetIndexed(nameRVA, sectionIndex);
      if (nameOffset < 0 || nameOffset >= view.byteLength) continue;

      const name = readCString(view, nameOffset);
      // A name `readCString` could not read whole does not name this export, so
      // the table is not whole either — the same reading `parseImports` takes.
      if (isNameTruncated(name)) tableTruncated = true;

      const existing = namesByIndex.get(addressIndex);
      if (existing) existing.push(name);
      else namesByIndex.set(addressIndex, [name]);
    }
  }

  // An address inside the export directory's own range is not code: it is the
  // RVA of a "OTHERDLL.Func" forwarder string.
  const forwarderStart = exportDir.virtualAddress;
  const forwarderEnd = exportDir.virtualAddress + exportDir.size;

  // Same four bounds as the name walk: numberOfFunctions is attacker-controlled
  // and the address table is 4 bytes per entry.
  const maxFunctions = Math.min(
    numberOfFunctions,
    MAX_EXPORT_ENTRIES,
    Math.floor(limitFor(addressTableRVA, addressTableOffset) / 4),
  );
  if (maxFunctions < numberOfFunctions) tableTruncated = true;

  // Walk the address table, which is the only table that covers ordinal-only
  // exports. Index i is ordinal `ordinalBase + i` per the PE spec.
  for (let i = 0; i < maxFunctions; i++) {
    const addressPos = addressTableOffset + i * 4;
    if (addressPos + 4 > view.byteLength) break;

    const address = view.getUint32(addressPos, true);
    const names = namesByIndex.get(i);

    // A zero address marks an unused ordinal slot. Keep it only if a name
    // somehow points at it, so a malformed file still shows its named exports.
    if (address === 0 && !names) continue;

    const ordinal = ordinalBase + i;

    let forwarder: string | undefined;
    if (address >= forwarderStart && address < forwarderEnd) {
      const forwarderOffset = rvaToFileOffsetIndexed(address, sectionIndex);
      if (forwarderOffset >= 0 && forwarderOffset < view.byteLength) {
        forwarder = readCString(view, forwarderOffset) || undefined;
        if (forwarder && isNameTruncated(forwarder)) tableTruncated = true;
      }
    }

    if (names) {
      for (const name of names) {
        exports.push({ name, ordinal, address, ...(forwarder ? { forwarder } : {}) });
      }
    } else {
      exports.push({
        name: `Ordinal#${ordinal}`,
        ordinal,
        address,
        byOrdinal: true,
        ...(forwarder ? { forwarder } : {}),
      });
    }
  }

  return { exports, truncated: tableTruncated };
}

/** The per-section scan ceiling, unchanged: 1 MiB of any one section's bytes. */
const SECTION_SCAN_LIMIT = 1024 * 1024;

/**
 * The most bytes `extractStrings` will scan **across a whole image**.
 *
 * The per-section 1 MiB ceiling bounded each scan and nothing bounded their
 * PRODUCT with the section count — which is a `uint16` read off the file and
 * clamped only by `buffer / 40`. Every section named `.rdata` is scanned, and
 * `pointerToRawData` may be 0 for all of them, so N sections each scan the same
 * megabyte: measured at `d8d8a6d`, a 221,184-byte fixture with 400 such
 * sections produced **166,784 strings in 752 ms**, and the shape is linear in
 * the section count, so a 1 MiB file declaring its buffer-full ~26,000 sections
 * asks for ~26 GiB of scanning and a Map to match. `peek-a-bin-tmo9`'s lesson
 * exactly: per-iteration safety says nothing about the total.
 *
 * 64 MiB is above any real image's data sections (the whole corpus is under
 * 200 KiB; a 253 MiB image's `.rdata`/`.data` are a few MiB) and it is the
 * budget for the *scan*, not for the file — a large binary loses nothing.
 *
 * This is a **worker-side** walk (`extractStrings` is the disasm RPC whose
 * argument is the whole image), so the cost is a dead worker and an unbounded
 * Map crossing `postMessage`, not a frozen render. Second tier, therefore, but
 * the largest amplification in the census.
 */
export const MAX_STRING_SCAN_BYTES = 64 * 1024 * 1024;

/** Bytes left in one `extractStrings` call's whole-image scan budget. */
interface ScanBudget {
  remaining: number;
}

/**
 * How far into `section` a scan may read, given what is left of the budget.
 * Decrements the budget by what it hands out, so the three passes below share
 * one total rather than each getting their own.
 */
function scanEndFor(view: DataView, section: SectionHeader, budget: ScanBudget): number {
  const start = section.pointerToRawData;
  const end = Math.min(
    start + Math.min(section.sizeOfRawData, SECTION_SCAN_LIMIT),
    view.byteLength,
  );
  const allowed = Math.max(0, Math.min(end - start, budget.remaining));
  budget.remaining -= allowed;
  return start + allowed;
}

/**
 * Scan a section for ASCII strings
 */
function extractASCIIStrings(
  view: DataView,
  section: SectionHeader,
  imageBase: number,
  budget: ScanBudget,
  minLength = 4,
): Map<number, string> {
  const strings = new Map<number, string>();

  const start = section.pointerToRawData;
  const end = scanEndFor(view, section, budget);

  const buf = new Uint8Array(view.buffer, view.byteOffset);
  let i = start;
  while (i < end) {
    const byte = buf[i];

    // Skip leading whitespace/control chars before printable ASCII
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      let skip = i;
      while (skip < end && (buf[skip] === 0x09 || buf[skip] === 0x0a || buf[skip] === 0x0d)) skip++;
      if (skip < end && buf[skip] >= 0x20 && buf[skip] <= 0x7e) {
        i = skip;
        continue;
      }
    }

    if (byte >= 0x20 && byte <= 0x7e) {
      const strStart = i;
      while (i < end) {
        const b = buf[i];
        if (b === 0 || b < 0x20 || b > 0x7e) break;
        i++;
      }

      const len = i - strStart;
      if (len >= minLength) {
        const str = textDecoder.decode(buf.subarray(strStart, i));
        const rva = section.virtualAddress + (strStart - section.pointerToRawData);
        strings.set(imageBase + rva, str);
        // Also map preceding whitespace addresses to this string
        let ws = strStart - 1;
        while (ws >= start && (buf[ws] === 0x09 || buf[ws] === 0x0a || buf[ws] === 0x0d)) {
          const wsRva = section.virtualAddress + (ws - section.pointerToRawData);
          strings.set(imageBase + wsRva, str);
          ws--;
        }
      }
    }

    i++;
  }

  return strings;
}

/**
 * Scan a section for UTF-16LE strings
 */
function extractUTF16Strings(
  view: DataView,
  section: SectionHeader,
  imageBase: number,
  budget: ScanBudget,
  minLength = 4,
): Map<number, string> {
  const strings = new Map<number, string>();

  const start = section.pointerToRawData;
  const end = scanEndFor(view, section, budget);

  const utf16Decoder = new TextDecoder("utf-16le");
  const buf = new Uint8Array(view.buffer, view.byteOffset);
  let i = start;
  while (i + 1 < end) {
    const lo = buf[i];
    const hi = buf[i + 1];

    // Skip leading whitespace/control char pairs before printable UTF-16LE
    if (hi === 0 && (lo === 0x09 || lo === 0x0a || lo === 0x0d)) {
      let skip = i;
      while (
        skip + 1 < end &&
        buf[skip + 1] === 0 &&
        (buf[skip] === 0x09 || buf[skip] === 0x0a || buf[skip] === 0x0d)
      )
        skip += 2;
      if (skip + 1 < end && buf[skip + 1] === 0 && buf[skip] >= 0x20 && buf[skip] <= 0x7e) {
        i = skip;
        continue;
      }
    }

    // Check for [printable, 0x00] pattern
    if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
      const strStart = i;
      let charCount = 0;

      while (i + 1 < end) {
        const clo = buf[i];
        const chi = buf[i + 1];
        if (chi === 0 && clo >= 0x20 && clo <= 0x7e) {
          charCount++;
          i += 2;
        } else {
          break;
        }
      }

      if (charCount >= minLength) {
        const str = utf16Decoder.decode(buf.subarray(strStart, strStart + charCount * 2));
        const rva = section.virtualAddress + (strStart - section.pointerToRawData);
        strings.set(imageBase + rva, str);
        // Also map preceding whitespace UTF-16 pairs to this string
        let ws = strStart - 2;
        while (
          ws >= start &&
          ws + 1 < end &&
          buf[ws + 1] === 0 &&
          (buf[ws] === 0x09 || buf[ws] === 0x0a || buf[ws] === 0x0d)
        ) {
          const wsRva = section.virtualAddress + (ws - section.pointerToRawData);
          strings.set(imageBase + wsRva, str);
          ws -= 2;
        }
      }
    } else {
      i += 2;
    }
  }

  return strings;
}

/**
 * Parse TLS Directory
 */
function parseTLSDirectory(
  view: DataView,
  tlsDir: DataDirectory,
  sectionIndex: SectionIndex,
  is64: boolean,
  imageBase: number,
): TLSDirectory | undefined {
  if (!tlsDir.virtualAddress || !tlsDir.size) return undefined;

  const offset = rvaToFileOffsetIndexed(tlsDir.virtualAddress, sectionIndex);
  if (offset < 0) return undefined;

  const ptrSize = is64 ? 8 : 4;
  const structSize = is64 ? 40 : 24;
  if (offset + structSize > view.byteLength) return undefined;

  const readPtr = (o: number): number =>
    is64 ? Number(view.getBigUint64(o, true)) : view.getUint32(o, true);

  const startAddressOfRawData = readPtr(offset);
  const endAddressOfRawData = readPtr(offset + ptrSize);
  const addressOfIndex = readPtr(offset + ptrSize * 2);
  const addressOfCallBacks = readPtr(offset + ptrSize * 3);
  const sizeOfZeroFill = view.getUint32(offset + ptrSize * 4, true);
  const characteristics = view.getUint32(offset + ptrSize * 4 + 4, true);

  // Walk callback array (null-terminated VA pointers)
  const callbacks: number[] = [];
  if (addressOfCallBacks) {
    const cbRVA = addressOfCallBacks - imageBase;
    const cbOffset = rvaToFileOffsetIndexed(cbRVA, sectionIndex);
    if (cbOffset >= 0) {
      let pos = cbOffset;
      for (let i = 0; i < 256; i++) {
        // safety limit
        if (pos + ptrSize > view.byteLength) break;
        const cbAddr = readPtr(pos);
        if (cbAddr === 0) break;
        callbacks.push(cbAddr);
        pos += ptrSize;
      }
    }
  }

  return {
    startAddressOfRawData,
    endAddressOfRawData,
    addressOfIndex,
    addressOfCallBacks,
    callbacks,
    sizeOfZeroFill,
    characteristics,
  };
}

/**
 * Byte offset of `CHPEMetadataPointer` within `IMAGE_LOAD_CONFIG_DIRECTORY`, and
 * the width of the field, per optional-header magic.
 *
 * The two layouts are not one structure with wider pointers — the 32-bit form
 * swaps `ProcessHeapFlags` and `ProcessAffinityMask` relative to the 64-bit one —
 * so each offset is counted against its own definition rather than derived from
 * the other. 0xC8/8 is the PE32+ slot, which is the one ARM64EC and ARM64X use.
 * 0x7C/4 is the PE32 slot, which belongs to the older x86-on-ARM64 CHPE images.
 */
const CHPE_METADATA_POINTER = {
  pe32: { offset: 0x7c, size: 4 },
  pe32plus: { offset: 0xc8, size: 8 },
} as const;

/**
 * Read data directory 10 far enough to answer whether the image declares CHPE
 * metadata. See `LoadConfigDirectory` for what the answer means.
 *
 * Three separate claims bound the read and the smallest wins: the data
 * directory's `Size`, the structure's own `Size` field, and what the section
 * table actually maps.
 *
 * They disagree routinely rather than exceptionally: `CHPEMetadataPointer` sits
 * near the end of a structure linkers have been growing for two decades, and the
 * two PE32 binaries measured here declare 0x48 bytes against a 0x40-byte
 * directory entry where the 32-bit field alone needs 0x80. Reading at the offset
 * without checking all three claims is a read of whatever `.rdata` holds next,
 * reported as a pointer — and a non-zero value there says "hybrid image" about a
 * file that is nothing of the sort. Every failure here returns `undefined` for
 * the field, never a value.
 */
function parseLoadConfig(
  view: DataView,
  loadConfigDir: DataDirectory,
  sectionIndex: SectionIndex,
  is64: boolean,
): LoadConfigDirectory | undefined {
  if (!loadConfigDir.virtualAddress || !loadConfigDir.size) return undefined;

  // The `Size` field itself has to be inside the image before it can bound
  // anything, so it goes through the same range check as the field below.
  const headerOffset = rvaRangeToFileOffset(loadConfigDir.virtualAddress, 4, sectionIndex);
  if (headerOffset < 0 || headerOffset + 4 > view.byteLength) return undefined;
  const declaredSize = view.getUint32(headerOffset, true);

  const { offset, size } = is64 ? CHPE_METADATA_POINTER.pe32plus : CHPE_METADATA_POINTER.pe32;
  const needed = offset + size;

  let chpeMetadataPointer: number | undefined;
  // Both sizes have to cover the field. `declaredSize` is the one that is
  // usually short; `loadConfigDir.size` is the one a crafted file inflates.
  if (declaredSize >= needed && loadConfigDir.size >= needed) {
    const fieldOffset = rvaRangeToFileOffset(loadConfigDir.virtualAddress, needed, sectionIndex);
    if (fieldOffset >= 0 && fieldOffset + needed <= view.byteLength) {
      chpeMetadataPointer = is64
        ? Number(view.getBigUint64(fieldOffset + offset, true))
        : view.getUint32(fieldOffset + offset, true);
    }
  }

  return {
    virtualAddress: loadConfigDir.virtualAddress,
    directorySize: loadConfigDir.size,
    declaredSize,
    chpeMetadataPointer,
  };
}

/**
 * Parse Base Relocations.
 *
 * **THE BLOCK WALK HONOURED THE DIRECTORY'S DECLARED SIZE AND THE ENTRY WALK
 * INSIDE IT DID NOT.** `entryCount` came from the block's own `SizeOfBlock`,
 * whose only backstop was the end of the FILE, so a directory declaring **8
 * bytes** — one block header — whose `SizeOfBlock` read `0xFFFFFFFF` produced
 * **524,284 relocation entries** out of a 1,049,088-byte fixture (measured at
 * `d8d8a6d`; the pre-existing test asserted only `< buf.byteLength`, which that
 * number satisfies). That is `peek-a-bin-tmo9`'s shape once more: the declared
 * size bounded the outer walk and was then ignored by the inner one.
 *
 * `blockLimit` is now the smallest of the block's own claim, the directory's,
 * the containing section's raw extent and the buffer. `Math.floor` on the entry
 * count is the other half — `(sizeOfBlock - 8) / 2` for an odd `SizeOfBlock`
 * gave a fractional count, so `i < entryCount` read half an entry's worth of
 * loop.
 *
 * **What is deliberately NOT capped is the entry TOTAL.** A relocation table is
 * legitimately O(image): one block per 4 KiB page, up to 2044 entries in each,
 * so a 253 MiB image really does carry millions. There is no count above which
 * a table is provably bogus, and the section extent *is* the file's own
 * statement about how far the array goes — so that, and not an invented number,
 * is the bound. See `docs/gotchas.md`.
 */
function parseBaseRelocations(
  view: DataView,
  relocDir: DataDirectory,
  sectionIndex: SectionIndex,
): RelocationBlock[] | undefined {
  if (!relocDir.virtualAddress || !relocDir.size) return undefined;

  const baseOffset = rvaToFileOffsetIndexed(relocDir.virtualAddress, sectionIndex);
  if (baseOffset < 0) return undefined;

  const blocks: RelocationBlock[] = [];
  let pos = baseOffset;
  const sectionLimit = sectionRawLimitForRva(relocDir.virtualAddress, sectionIndex);
  const dirLimit = Math.min(
    view.byteLength,
    baseOffset + Math.max(0, relocDir.size),
    sectionLimit >= 0 ? sectionLimit : Number.POSITIVE_INFINITY,
  );

  while (pos + 8 <= dirLimit) {
    const virtualAddress = view.getUint32(pos, true);
    const sizeOfBlock = view.getUint32(pos + 4, true);

    if (virtualAddress === 0 || sizeOfBlock < 8) break;

    // The block may not claim more than the directory, the section or the file
    // leaves it, whatever its header says.
    const blockLimit = Math.min(dirLimit, pos + sizeOfBlock);
    const entryCount = Math.max(0, Math.floor((blockLimit - pos - 8) / 2));
    const entries: RelocationEntry[] = [];

    for (let i = 0; i < entryCount; i++) {
      const value = view.getUint16(pos + 8 + i * 2, true);
      const type = (value >> 12) & 0xf;
      const entryOffset = value & 0xfff;
      entries.push({ type, offset: entryOffset });
    }

    blocks.push({ virtualAddress, entries });
    pos += sizeOfBlock;
  }

  return blocks.length > 0 ? blocks : undefined;
}

/**
 * Main PE Parser
 */
export function parsePE(buffer: ArrayBuffer): PEFile {
  const view = new DataView(buffer);

  // 1. Parse DOS Header
  const dosHeader = parseDOSHeader(view);

  // 2. Validate PE Signature
  const peOffset = dosHeader.e_lfanew;
  if (peOffset + 4 > view.byteLength) {
    throw new Error("Invalid PE offset");
  }

  const peSignature = view.getUint32(peOffset, true);
  if (peSignature !== IMAGE_NT_SIGNATURE) {
    throw new Error(`Invalid PE signature: 0x${peSignature.toString(16)} (expected 0x4550)`);
  }

  // 3. Parse COFF Header (20 bytes) followed by the optional header magic (2).
  const coffOffset = peOffset + 4;
  if (coffOffset + 22 > view.byteLength) {
    throw new Error("Truncated PE: COFF header runs past end of file");
  }
  const coffHeader = parseCOFFHeader(view, coffOffset);

  // 4. Parse Optional Header
  const optionalHeaderOffset = coffOffset + 20;
  const magic = view.getUint16(optionalHeaderOffset, true);
  const is64 = magic === IMAGE_NT_OPTIONAL_HDR64_MAGIC;

  let optionalHeader: OptionalHeader32 | OptionalHeader64;
  let dataDirectoriesOffset: number;

  if (is64) {
    optionalHeader = parseOptionalHeader64(view, optionalHeaderOffset);
    dataDirectoriesOffset = optionalHeaderOffset + 112;
  } else if (magic === IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    optionalHeader = parseOptionalHeader32(view, optionalHeaderOffset);
    dataDirectoriesOffset = optionalHeaderOffset + 96;
  } else {
    throw new Error(`Invalid optional header magic: 0x${magic.toString(16)}`);
  }

  // 5. Parse Data Directories
  const dataDirectories = parseDataDirectories(
    view,
    dataDirectoriesOffset,
    optionalHeader.numberOfRvaAndSizes,
  );

  // 6. Parse Section Headers
  const sectionHeadersOffset = optionalHeaderOffset + coffHeader.sizeOfOptionalHeader;
  const sections = parseSectionHeaders(view, sectionHeadersOffset, coffHeader.numberOfSections);

  // Every directory below resolves RVAs against the section table — import
  // thunks and .pdata entries in the hundreds of thousands on a large image.
  // Build the lookup structure once here and hand it down.
  const sectionIndex = buildSectionIndex(sections);

  // 7. Parse Imports
  const imageBase =
    typeof optionalHeader.imageBase === "bigint"
      ? Number(optionalHeader.imageBase)
      : optionalHeader.imageBase;

  const { imports, truncated: importsTruncated } = parseImports(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT] || { virtualAddress: 0, size: 0 },
    sectionIndex,
    is64,
    imageBase,
  );

  // 8. Parse Exports
  const { exports, truncated: exportsTruncated } = parseExports(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT] || { virtualAddress: 0, size: 0 },
    sectionIndex,
  );

  // 9. Parse TLS Directory
  const tlsDirectory = parseTLSDirectory(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS] || { virtualAddress: 0, size: 0 },
    sectionIndex,
    is64,
    imageBase,
  );

  // 9b. Parse the Load Config Directory (CHPE metadata only, for now)
  const loadConfig = parseLoadConfig(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] || { virtualAddress: 0, size: 0 },
    sectionIndex,
    is64,
  );

  // 10. Parse Base Relocations
  const relocations = parseBaseRelocations(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC] || { virtualAddress: 0, size: 0 },
    sectionIndex,
  );

  // 11. Parse Resource Directory
  let resources: import("./types").ResourceTree | undefined;
  const resourceDir = dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resourceDir && resourceDir.virtualAddress > 0 && resourceDir.size > 0) {
    try {
      resources = parseResourceDirectory(buffer, resourceDir, sections);
    } catch {
      // silently ignore malformed resources
    }
  }

  // 12. Parse .pdata (Exception Directory) — PE32+ only, decoded per machine type
  const runtimeFunctions = is64
    ? parsePdata(
        buffer,
        dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION] || { virtualAddress: 0, size: 0 },
        sections,
        coffHeader.machine,
        sectionIndex,
      )
    : undefined;

  // 13. Parse Authenticode / Security Directory
  let certificate: import("./authenticode").CertificateInfo | undefined;
  try {
    certificate = parseSecurityDirectory(buffer, dataDirectories) ?? undefined;
  } catch {
    // silently ignore malformed certificates
  }

  return {
    buffer,
    is64,
    dosHeader,
    coffHeader,
    optionalHeader: normalizeOptionalHeader(optionalHeader),
    rawOptionalHeader: optionalHeader,
    dataDirectories,
    sections,
    imports,
    // Omitted rather than set false when the table is whole, so that a
    // `PEFile` built anywhere else cannot claim completeness by accident.
    ...(importsTruncated ? { importsTruncated: true } : {}),
    exports,
    // Same rule as `importsTruncated`: omitted rather than false, so a `PEFile`
    // built anywhere else cannot claim completeness by accident.
    ...(exportsTruncated ? { exportsTruncated: true } : {}),
    tlsDirectory,
    loadConfig,
    relocations,
    runtimeFunctions,
    resources,
    strings: new Map(),
    stringTypes: new Map(),
    certificate,
  };
}

/**
 * Extract strings from PE sections (run separately from parsePE to avoid blocking UI)
 */
export function extractStrings(
  buffer: ArrayBuffer,
  sections: SectionHeader[],
  imageBase: number,
  is64?: boolean,
): { strings: Map<number, string>; stringTypes: Map<number, "ascii" | "utf16le"> } {
  const view = new DataView(buffer);
  const strings = new Map<number, string>();
  const stringTypes = new Map<number, "ascii" | "utf16le">();
  const dataSectionNames = new Set([".rdata", ".data", ".rodata"]);
  // ONE budget for the whole call, shared by all four passes below — see
  // MAX_STRING_SCAN_BYTES. A per-pass budget would multiply by four, and a
  // per-section one is what was already there and is what the section count
  // multiplies out.
  const budget: ScanBudget = { remaining: MAX_STRING_SCAN_BYTES };

  for (const sec of sections) {
    if (dataSectionNames.has(sec.name)) {
      const asciiStrings = extractASCIIStrings(view, sec, imageBase, budget, 4);
      asciiStrings.forEach((v, k) => {
        strings.set(k, v);
        stringTypes.set(k, "ascii");
      });
    }
  }

  const textSection = findCodeSection(sections);
  if (textSection) {
    const textAscii = extractASCIIStrings(view, textSection, imageBase, budget, 8);
    textAscii.forEach((v, k) => {
      if (!strings.has(k)) {
        strings.set(k, v);
        stringTypes.set(k, "ascii");
      }
    });
  }

  for (const sec of sections) {
    if (dataSectionNames.has(sec.name)) {
      const utf16Strings = extractUTF16Strings(view, sec, imageBase, budget, 4);
      utf16Strings.forEach((v, k) => {
        if (!strings.has(k)) {
          strings.set(k, v);
          stringTypes.set(k, "utf16le");
        }
      });
    }
  }

  // Pointer indirection pass: scan .rdata/.data for pointers to known string VAs
  const ptrSize = is64 ? 8 : 4;
  // `Math.max(...)` over the section table: `numberOfSections` is a `uint16`, so
  // the spread is at most 65535 arguments. Checked rather than assumed —
  // measured at `d8d8a6d`, V8 accepts 65535 and throws `RangeError: Maximum
  // call stack size exceeded` at 125000, so this is safe *only* because of the
  // `uint16`. Anything that ever lets the section count past 65535 must replace
  // this with a reduce.
  const imageEnd = imageBase + Math.max(...sections.map((s) => s.virtualAddress + s.virtualSize));

  for (const sec of sections) {
    if (!dataSectionNames.has(sec.name)) continue;
    const start = sec.pointerToRawData;
    const end = scanEndFor(view, sec, budget);

    for (let off = start; off + ptrSize <= end; off += ptrSize) {
      let ptr: number;
      if (ptrSize === 8) {
        const lo = view.getUint32(off, true);
        const hi = view.getUint32(off + 4, true);
        ptr = hi * 0x100000000 + lo;
      } else {
        ptr = view.getUint32(off, true);
      }
      if (ptr >= imageBase && ptr < imageEnd && strings.has(ptr)) {
        const pointerVA = imageBase + sec.virtualAddress + (off - sec.pointerToRawData);
        if (!strings.has(pointerVA)) {
          strings.set(pointerVA, strings.get(ptr)!);
          const t = stringTypes.get(ptr);
          if (t) stringTypes.set(pointerVA, t);
        }
      }
    }
  }

  return { strings, stringTypes };
}
