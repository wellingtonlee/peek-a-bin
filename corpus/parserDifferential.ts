/**
 * The PE parser, judged against a second reader written from the specification.
 *
 * WHY THIS FILE EXISTS. CLAUDE.md's Verification section opened its list of
 * audits-with-an-oracle with this claim:
 *
 *   "The PE parser holds, differentially against an independently written
 *    from-spec reader — sections, imports, exports, imphash, resources,
 *    checksum and `.pdata` agree on every file."
 *
 * Measured on 2026-08-25: **that instrument was not in the tree.** Six files
 * under `corpus/` called `parsePE`; five parsed only to have something to time,
 * and the sixth — `corpus/arm64.ts` — compared the parser with the sweep on the
 * ARM64 `.pdata` rows alone. Six of the seven named subjects had no standing
 * differential of any kind. The claim was a past measurement whose instrument
 * had been lost with a scratch directory, which is this repo's own recurring
 * failure (`corpus/README.md`: rebuilt from scratch twice in one day) and the
 * reason `corpus/` exists at all. This is the repair: the oracle, landed.
 *
 * INDEPENDENCE, AND EXACTLY HOW FAR IT GOES. Everything between the "the
 * reference reader" banner and the "the subjects" banner is the reference, and
 * it **uses nothing from `src/`** — not a constant, not a helper, not
 * `rvaToFileOffset`. It reads a `DataView` against the PE/COFF specification,
 * plus `node:crypto` for MD5. Below the second banner is the comparison, which
 * necessarily uses the code under test. TypeScript puts every import at the top
 * of the file, so that separation cannot be expressed by import placement and
 * is instead a property of the two regions — and it is guarded rather than
 * asserted: `build/parserIndependence.test.ts` splits this file at the banners
 * and fails if any name imported from `src/` appears in the reference half. If
 * the reference ever reads the parser, this stops being an oracle and becomes a
 * differential test between one implementation and itself, which is the trap
 * this repo's handbook already names.
 *
 * Three places where the independence is genuinely weaker, stated rather than
 * glossed:
 *
 *  - **The RVA→file-offset rule is the same rule in both readers**, because the
 *    specification only permits one: the section whose virtual range contains
 *    the RVA, at `pointerToRawData + (rva - virtualAddress)`, and nothing when
 *    that lands past the section's raw data. So this cannot catch an error in
 *    the *rule*. What it does catch independently is the parser's `SectionIndex`
 *    — a sorted binary search with a scan fallback — disagreeing with a plain
 *    table-order scan, which is a real optimisation with a real failure mode.
 *  - **imphash is a second reading of the ALGORITHM, not of pefile's output.**
 *    pefile is not installed on this machine and cannot be consulted. The
 *    reference builds the `dll.func` string from pefile's documented rules and
 *    hashes it with `node:crypto`, which is a genuine oracle over this repo's
 *    hand-rolled MD5 and over the parser's import list — but if pefile's *rules*
 *    were misread, both readers here are wrong together. It also declines the
 *    `ordlookup` table (see `imphashSubject`).
 *  - **`.pdata` on ARM64 is not asked here.** `npm run corpus:arm64` already
 *    gates every ARM64 record against the sweep, `.xdata` codes included, and
 *    duplicating it would put the same question in two places. The x64 records
 *    on t64/w64 are asked here and are asked nowhere else.
 *
 * WHAT THE CORPUS CAN AND CANNOT EXERCISE. Measured, not assumed — every one of
 * the six binaries is an EXE built by MSVC, and:
 *
 *  - **exports: 0 on all six**, forwarders included. There is no DLL in the
 *    corpus and `find / -xdev -iname '*.dll'` finds none on this machine. The
 *    export reader below is written and correct as far as reading goes, and its
 *    row is printed **VACUOUS**: a green row over an empty population says
 *    nothing, which is this directory's standing rule. `build/parserDifferential.test.ts`
 *    is where that reader is actually exercised, over a hand-built image.
 *  - **ordinal imports: 0 on all six.** Same treatment. `Ordinal_<n>` is a wire
 *    format the parser writes and `computeImphash` reads back, so the reference
 *    produces ordinals as *numbers* and the comparison spells the expected
 *    string here, literally, on purpose — respell it in `pe/ordinalTables.ts`
 *    and this row goes red rather than silently changing every imphash.
 *  - **checksum has an oracle outside BOTH readers on four of six**: the value
 *    the linker stored in the header. t32/t64/w32/w64 carry one and it matches;
 *    both ARM64 launchers store 0, so there the row is reader-vs-reader only.
 *
 * NOT AUDITED HERE, and deliberately: TLS, load config, debug directory, rich
 * header, authenticode, and the string extraction. Each is a subject of its own
 * and adding a half-read of one is worse than not claiming it.
 *
 * Run with `npm run corpus:parserdiff`. Missing binaries skip cleanly and exit
 * 0, naming what was looked for and where. Extra arguments are extra images:
 * `npm run corpus:parserdiff -- /path/to/some.dll` audits that file too, which
 * is how the export rows stop being vacuous the day a DLL is available.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { checksumFile, computeImphash } from "../src/pe/metadata";
import { parsePE } from "../src/pe/parser";
import type { PEFile } from "../src/pe/types";
import { ALL_BINS, resolveArmCorpus, resolveCorpus } from "./preflight";

// ════════════════════════════════════════════════════════════════════════════
// THE REFERENCE READER.  Nothing between this banner and the "THE SUBJECTS"
// banner may use anything imported from `src/`.  Guarded by
// `build/parserIndependence.test.ts`, which splits this file on these two
// comment lines — do not reword them without updating it.
// ════════════════════════════════════════════════════════════════════════════

const DOS_MAGIC = 0x5a4d; // "MZ"
const PE_MAGIC = 0x00004550; // "PE\0\0"
const PE32_MAGIC = 0x10b;
const PE32PLUS_MAGIC = 0x20b;

/** Data directory indices this reader uses. */
const DIR_EXPORT = 0;
const DIR_IMPORT = 1;
const DIR_RESOURCE = 2;
const DIR_EXCEPTION = 3;
const DIR_BASERELOC = 5;

export interface RefSection {
  name: string;
  /** True when the 8-byte field held a byte >= 0x80 or an interior NUL. */
  oddName: boolean;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  pointerToRelocations: number;
  pointerToLinenumbers: number;
  numberOfRelocations: number;
  numberOfLinenumbers: number;
  characteristics: number;
}

export interface RefDirectory {
  virtualAddress: number;
  size: number;
}

/** One imported function: a name, or an ordinal. Never a formatted string. */
export type RefImportFunc =
  | { kind: "name"; name: string; hint: number; nonAscii: boolean }
  | { kind: "ordinal"; ordinal: number };

export interface RefImport {
  dll: string;
  dllNonAscii: boolean;
  funcs: RefImportFunc[];
  /** VA of each IAT slot, in the same order as `funcs`. */
  iat: number[];
}

export interface RefExport {
  /** null for an address-table slot no name points at. */
  name: string | null;
  /** Base + index into the address table. */
  ordinal: number;
  /** The address table's value: a code RVA, or the forwarder string's RVA. */
  rva: number;
  /** "OTHER.Func" when the value falls inside the export directory. */
  forwarder: string | null;
}

export interface RefResourceEntry {
  type: number | string;
  name: number | string;
  lang: number;
  rva: number;
  size: number;
}

export interface RefPdata {
  begin: number;
  end: number;
  unwind: number;
  /** Undefined where the record's UNWIND_INFO version is not 1 or 2. */
  handlerFlags?: number;
  handlerAddress?: number;
}

export interface RefRelocBlock {
  virtualAddress: number;
  entries: { type: number; offset: number }[];
}

export interface RefImage {
  eLfanew: number;
  machine: number;
  numberOfSections: number;
  timeDateStamp: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
  magic: number;
  is64: boolean;
  addressOfEntryPoint: number;
  baseOfCode: number;
  sizeOfCode: number;
  imageBase: number;
  sectionAlignment: number;
  fileAlignment: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  storedChecksum: number;
  subsystem: number;
  dllCharacteristics: number;
  numberOfRvaAndSizes: number;
  directories: RefDirectory[];
  sections: RefSection[];
  imports: RefImport[];
  exports: RefExport[];
  /** Present only when the image has an export directory at all. */
  hasExportDir: boolean;
  resources: RefResourceEntry[];
  /** Top-level node ids, in directory order — the shape half of the walk. */
  resourceRootIds: (number | string)[];
  /** x64 12-byte records. Empty for PE32 and for ARM64 (see the header). */
  pdata: RefPdata[];
  /** Records the reference read whose begin >= end; the parser drops these. */
  pdataDegenerate: number;
  /**
   * Records whose UNWIND_INFO carries a version other than 1 or 2 — the
   * population `peek-a-bin-eu8`'s version check exists for. 0 here means that
   * check is NOT exercised by this corpus, which is why it is reported.
   */
  pdataOddVersion: number;
  /** Records whose `unwindInfoAddress` resolves to nothing. */
  pdataUnresolvedUnwind: number;
  relocations: RefRelocBlock[];
  /** The image's own checksum, recomputed. */
  checksum: number;
  /** The pefile `dll.func,dll.func` string, before hashing. */
  imphashString: string;
  imphash: string;
  /** Ordinal imports from a DLL pefile resolves through `ordlookup`. */
  ordlookupImports: number;
}

/** A NUL-terminated byte string, read as bytes so no decoder is involved. */
function refCString(dv: DataView, off: number, max = 1024): { s: string; nonAscii: boolean } {
  const chars: number[] = [];
  let nonAscii = false;
  for (let i = 0; i < max; i++) {
    const p = off + i;
    if (p >= dv.byteLength) break;
    const b = dv.getUint8(p);
    if (b === 0) break;
    if (b >= 0x80) nonAscii = true;
    chars.push(b);
  }
  return { s: String.fromCharCode(...chars), nonAscii };
}

/**
 * RVA → file offset, by a plain scan of the section table in file order.
 *
 * The spec permits one rule and both readers implement it (see the header); the
 * independence this buys is over the parser's sorted-binary-search index, not
 * over the rule. A section with `virtualSize === 0` is measured by its raw size,
 * which is what the loader does for an object-style table.
 */
function refRvaToOffset(rva: number, sections: readonly RefSection[]): number {
  for (const s of sections) {
    const extent = s.virtualSize > 0 ? s.virtualSize : s.sizeOfRawData;
    if (rva >= s.virtualAddress && rva < s.virtualAddress + extent) {
      const delta = rva - s.virtualAddress;
      if (delta >= s.sizeOfRawData) return -1;
      return s.pointerToRawData + delta;
    }
  }
  return -1;
}

function refSections(dv: DataView, off: number, count: number): RefSection[] {
  const out: RefSection[] = [];
  for (let i = 0; i < count; i++) {
    const p = off + i * 40;
    if (p + 40 > dv.byteLength) break;
    // Null-padded, 8 bytes. The name is what precedes the first NUL; a byte
    // after one, or a byte >= 0x80, is recorded so the comparison can exclude
    // the row rather than report a decoder difference as a parser defect.
    const chars: number[] = [];
    let seenNul = false;
    let odd = false;
    for (let j = 0; j < 8; j++) {
      const b = dv.getUint8(p + j);
      if (b === 0) {
        seenNul = true;
        continue;
      }
      if (seenNul) odd = true;
      if (b >= 0x80) odd = true;
      if (!seenNul) chars.push(b);
    }
    out.push({
      name: String.fromCharCode(...chars),
      oddName: odd,
      virtualSize: dv.getUint32(p + 8, true),
      virtualAddress: dv.getUint32(p + 12, true),
      sizeOfRawData: dv.getUint32(p + 16, true),
      pointerToRawData: dv.getUint32(p + 20, true),
      pointerToRelocations: dv.getUint32(p + 24, true),
      pointerToLinenumbers: dv.getUint32(p + 28, true),
      numberOfRelocations: dv.getUint16(p + 32, true),
      numberOfLinenumbers: dv.getUint16(p + 34, true),
      characteristics: dv.getUint32(p + 36, true),
    });
  }
  return out;
}

function refImports(
  dv: DataView,
  dir: RefDirectory,
  sections: readonly RefSection[],
  is64: boolean,
  imageBase: number,
): RefImport[] {
  const out: RefImport[] = [];
  if (!dir.virtualAddress || !dir.size) return out;
  const base = refRvaToOffset(dir.virtualAddress, sections);
  if (base < 0) return out;

  const width = is64 ? 8 : 4;
  const ordinalBit = is64 ? 1n << 63n : 1n << 31n;

  for (let d = 0; ; d++) {
    const p = base + d * 20;
    if (p + 20 > dv.byteLength) break;
    const oft = dv.getUint32(p, true);
    const nameRva = dv.getUint32(p + 12, true);
    const ft = dv.getUint32(p + 16, true);
    if (oft === 0 && nameRva === 0 && ft === 0) break;

    const nameOff = refRvaToOffset(nameRva, sections);
    if (nameOff < 0) continue;
    const dll = refCString(dv, nameOff);

    const funcs: RefImportFunc[] = [];
    const iat: number[] = [];
    // The Import Name Table if the image has one, else the IAT, which before
    // binding holds the same values.
    const thunkRva = oft || ft;
    let t = thunkRva ? refRvaToOffset(thunkRva, sections) : -1;
    if (t >= 0) {
      for (let i = 0; t + width <= dv.byteLength; i++, t += width) {
        const raw = is64 ? dv.getBigUint64(t, true) : BigInt(dv.getUint32(t, true));
        if (raw === 0n) break;
        iat.push(imageBase + ft + i * width);
        if (raw & ordinalBit) {
          funcs.push({ kind: "ordinal", ordinal: Number(raw & 0xffffn) });
          continue;
        }
        const hintOff = refRvaToOffset(Number(raw), sections);
        if (hintOff < 0 || hintOff + 2 >= dv.byteLength) continue;
        const hint = dv.getUint16(hintOff, true);
        const nm = refCString(dv, hintOff + 2);
        funcs.push({ kind: "name", name: nm.s, hint, nonAscii: nm.nonAscii });
      }
    }
    out.push({ dll: dll.s, dllNonAscii: dll.nonAscii, funcs, iat });
  }
  return out;
}

function refExports(
  dv: DataView,
  dir: RefDirectory,
  sections: readonly RefSection[],
): { list: RefExport[]; present: boolean } {
  if (!dir.virtualAddress || !dir.size) return { list: [], present: false };
  const base = refRvaToOffset(dir.virtualAddress, sections);
  if (base < 0 || base + 40 > dv.byteLength) return { list: [], present: false };

  const ordinalBase = dv.getUint32(base + 16, true);
  const nFuncs = dv.getUint32(base + 20, true);
  const nNames = dv.getUint32(base + 24, true);
  const eatOff = refRvaToOffset(dv.getUint32(base + 28, true), sections);
  const entOff = refRvaToOffset(dv.getUint32(base + 32, true), sections);
  const ordOff = refRvaToOffset(dv.getUint32(base + 36, true), sections);
  if (eatOff < 0) return { list: [], present: true };

  // The name tables are parallel: name i belongs to address-table slot
  // `ordinalTable[i]`, which is the UNBIASED index. Several names may share a
  // slot — an alias — and each is an export in its own right.
  const namesBySlot = new Map<number, string[]>();
  if (entOff >= 0 && ordOff >= 0) {
    for (let i = 0; i < nNames; i++) {
      const np = entOff + i * 4;
      const op = ordOff + i * 2;
      if (np + 4 > dv.byteLength || op + 2 > dv.byteLength) break;
      const slot = dv.getUint16(op, true);
      const nOff = refRvaToOffset(dv.getUint32(np, true), sections);
      if (nOff < 0) continue;
      const nm = refCString(dv, nOff).s;
      const cur = namesBySlot.get(slot);
      if (cur) cur.push(nm);
      else namesBySlot.set(slot, [nm]);
    }
  }

  // A value inside the export directory's own extent is not code — it is the
  // RVA of an "OTHER.Func" redirect string.
  const fwdLo = dir.virtualAddress;
  const fwdHi = dir.virtualAddress + dir.size;

  const list: RefExport[] = [];
  for (let i = 0; i < nFuncs; i++) {
    const p = eatOff + i * 4;
    if (p + 4 > dv.byteLength) break;
    const rva = dv.getUint32(p, true);
    const names = namesBySlot.get(i);
    if (rva === 0 && !names) continue;
    let forwarder: string | null = null;
    if (rva >= fwdLo && rva < fwdHi) {
      const fo = refRvaToOffset(rva, sections);
      if (fo >= 0) forwarder = refCString(dv, fo).s || null;
    }
    const ordinal = ordinalBase + i;
    if (names) for (const n of names) list.push({ name: n, ordinal, rva, forwarder });
    else list.push({ name: null, ordinal, rva, forwarder });
  }
  return { list, present: true };
}

/** UTF-16LE, length-prefixed in characters — the resource directory's strings. */
function refResourceString(dv: DataView, off: number): string {
  if (off + 2 > dv.byteLength) return "";
  const n = dv.getUint16(off, true);
  const chars: number[] = [];
  for (let i = 0; i < n; i++) {
    const p = off + 2 + i * 2;
    if (p + 2 > dv.byteLength) break;
    chars.push(dv.getUint16(p, true));
  }
  return String.fromCharCode(...chars);
}

function refResources(
  dv: DataView,
  dir: RefDirectory,
  sections: readonly RefSection[],
): { entries: RefResourceEntry[]; rootIds: (number | string)[] } {
  const entries: RefResourceEntry[] = [];
  const rootIds: (number | string)[] = [];
  if (!dir.virtualAddress || !dir.size) return { entries, rootIds };
  const secBase = refRvaToOffset(dir.virtualAddress, sections);
  if (secBase < 0) return { entries, rootIds };

  // Three levels — type, name, language — each an IMAGE_RESOURCE_DIRECTORY of
  // 16 bytes followed by 8-byte entries, named entries first. Every offset in
  // the tree is relative to the start of the resource directory.
  const walk = (dirOff: number, depth: number, path: (number | string)[]): void => {
    if (depth > 3) return;
    const a = secBase + dirOff;
    if (a + 16 > dv.byteLength) return;
    const named = dv.getUint16(a + 12, true);
    const ids = dv.getUint16(a + 14, true);
    for (let i = 0; i < named + ids; i++) {
      const e = a + 16 + i * 8;
      if (e + 8 > dv.byteLength) break;
      const nameField = dv.getUint32(e, true);
      const dataField = dv.getUint32(e + 4, true);
      const id: number | string =
        nameField & 0x80000000
          ? refResourceString(dv, secBase + (nameField & 0x7fffffff))
          : nameField;
      if (depth === 0) rootIds.push(id);
      const here = [...path, id];
      if (dataField & 0x80000000) {
        walk(dataField & 0x7fffffff, depth + 1, here);
        continue;
      }
      const leaf = secBase + dataField;
      if (leaf + 16 > dv.byteLength) continue;
      entries.push({
        type: here[0] ?? 0,
        name: here[1] ?? 0,
        lang: typeof here[2] === "number" ? here[2] : 0,
        rva: dv.getUint32(leaf, true),
        size: dv.getUint32(leaf + 4, true),
      });
    }
  };
  walk(0, 0, []);
  return { entries, rootIds };
}

/**
 * x64 `.pdata`: 12-byte RUNTIME_FUNCTION records of begin/end/unwind RVAs, plus
 * the handler the UNWIND_INFO names.
 *
 * Deliberately NOT asked of ARM64, whose records are 8 bytes and are already
 * gated against the sweep by `npm run corpus:arm64` — see the header.
 */
function refPdata(
  dv: DataView,
  dir: RefDirectory,
  sections: readonly RefSection[],
): { list: RefPdata[]; degenerate: number; oddVersion: number; unresolvedUnwind: number } {
  const list: RefPdata[] = [];
  let degenerate = 0;
  let oddVersion = 0;
  let unresolvedUnwind = 0;
  const empty = { list, degenerate, oddVersion, unresolvedUnwind };
  if (!dir.virtualAddress || !dir.size) return empty;
  const base = refRvaToOffset(dir.virtualAddress, sections);
  if (base < 0) return empty;

  for (let i = 0; i * 12 < dir.size; i++) {
    const p = base + i * 12;
    if (p + 12 > dv.byteLength) break;
    const begin = dv.getUint32(p, true);
    const end = dv.getUint32(p + 4, true);
    const unwind = dv.getUint32(p + 8, true);
    if (begin >= end) {
      degenerate++;
      continue;
    }
    const rec: RefPdata = { begin, end, unwind };
    const u = refRvaToOffset(unwind, sections);
    if (u < 0 || u + 4 > dv.byteLength) unresolvedUnwind++;
    if (u >= 0 && u + 4 <= dv.byteLength) {
      const vf = dv.getUint8(u);
      const version = vf & 0x7;
      // Counted so the report can say whether the version check is exercised at
      // all. `peek-a-bin-eu8` added it because an `unwindInfoAddress` landing in
      // any mapped section otherwise yields a `handlerFlags` for one byte in
      // four of arbitrary data — but a corpus in which every record points at a
      // real version-1 record never asks the question.
      if (version !== 1 && version !== 2) oddVersion++;
      if (version === 1 || version === 2) {
        const flags = (vf >> 3) & 0x1f;
        rec.handlerFlags = flags;
        // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER, and not UNW_FLAG_CHAININFO
        // (0x4), which puts a RUNTIME_FUNCTION where the handler RVA would be.
        if (flags & 0x3 && !(flags & 0x4)) {
          const codes = dv.getUint8(u + 2);
          const bytes = codes * 2;
          const h = u + 4 + bytes + (bytes % 4 ? 4 - (bytes % 4) : 0);
          if (h + 4 <= dv.byteLength) rec.handlerAddress = dv.getUint32(h, true);
        }
      }
    }
    list.push(rec);
  }
  return { list, degenerate, oddVersion, unresolvedUnwind };
}

function refRelocations(
  dv: DataView,
  dir: RefDirectory,
  sections: readonly RefSection[],
): RefRelocBlock[] {
  const out: RefRelocBlock[] = [];
  if (!dir.virtualAddress || !dir.size) return out;
  const base = refRvaToOffset(dir.virtualAddress, sections);
  if (base < 0) return out;
  let p = base;
  const end = base + dir.size;
  while (p + 8 <= dv.byteLength && p < end) {
    const va = dv.getUint32(p, true);
    const size = dv.getUint32(p + 4, true);
    if (va === 0 || size < 8) break;
    const entries: { type: number; offset: number }[] = [];
    for (let i = 0; i < (size - 8) / 2; i++) {
      const q = p + 8 + i * 2;
      if (q + 2 > dv.byteLength) break;
      const v = dv.getUint16(q, true);
      entries.push({ type: (v >> 12) & 0xf, offset: v & 0xfff });
    }
    out.push({ virtualAddress: va, entries });
    p += size;
  }
  return out;
}

/**
 * The PE checksum, computed the textbook way: a ones-complement sum of the
 * image's 16-bit words with the CheckSum field itself excluded, folded after
 * every word, plus the file's length.
 *
 * Deliberately a different FORMULATION from the production one, which sums
 * unfolded in four lanes and *subtracts* the checksum field afterwards. The two
 * are equal because the fold is a reduction modulo 0xFFFF either way — that
 * equality is the thing this row tests, and it is exactly the kind of
 * optimisation a differential is for.
 */
function refChecksum(bytes: Uint8Array, eLfanew: number): number {
  const checksumOff = eLfanew + 4 + 20 + 64;
  let sum = 0;
  const n = bytes.length;
  for (let i = 0; i + 1 < n; i += 2) {
    if (i === checksumOff || i === checksumOff + 2) continue;
    sum += bytes[i] | (bytes[i + 1] << 8);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  if (n & 1) {
    sum += bytes[n - 1];
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + n) >>> 0;
}

/**
 * pefile strips a DLL's extension only for these three. `foo.exe` keeps its
 * extension; `foo.dll` does not. Reproduced from pefile's documented rule.
 */
const REF_STRIPPED_EXT = new Set(["dll", "ocx", "sys"]);

/**
 * The DLLs pefile resolves ordinals for, via `ordlookup`. The reference has no
 * independent copy of that table and does not invent one: an ordinal import
 * from one of these is EXCLUDED from the imphash comparison and counted, so the
 * row can never be green by accident. On this corpus the count is 0 of 0.
 */
const REF_ORDLOOKUP_DLLS = new Set(["ws2_32.dll", "wsock32.dll", "oleaut32.dll"]);

function refImphash(imports: readonly RefImport[]): {
  str: string;
  hash: string;
  ordlookup: number;
} {
  const parts: string[] = [];
  let ordlookup = 0;
  for (const imp of imports) {
    const lib = imp.dll.toLowerCase();
    const dot = lib.lastIndexOf(".");
    const base = dot > 0 && REF_STRIPPED_EXT.has(lib.slice(dot + 1)) ? lib.slice(0, dot) : lib;
    for (const f of imp.funcs) {
      if (f.kind === "ordinal") {
        if (REF_ORDLOOKUP_DLLS.has(lib)) ordlookup++;
        // pefile renders an unresolved ordinal as `ord<N>`.
        parts.push(`${base}.ord${f.ordinal}`);
      } else if (f.name) {
        // pefile skips an import it could not name at all.
        parts.push(`${base}.${f.name.toLowerCase()}`);
      }
    }
  }
  const str = parts.join(",");
  return {
    str,
    hash: str === "" ? "" : createHash("md5").update(Buffer.from(str, "utf8")).digest("hex"),
    ordlookup,
  };
}

/** Read an image from the spec. Throws only where the file is not a PE at all. */
export function readReference(buffer: ArrayBuffer): RefImage {
  const dv = new DataView(buffer);
  if (dv.byteLength < 64 || dv.getUint16(0, true) !== DOS_MAGIC) {
    throw new Error("not an MZ image");
  }
  const eLfanew = dv.getUint32(0x3c, true);
  if (eLfanew + 24 > dv.byteLength || dv.getUint32(eLfanew, true) !== PE_MAGIC) {
    throw new Error("no PE signature");
  }
  const coff = eLfanew + 4;
  const machine = dv.getUint16(coff, true);
  const numberOfSections = dv.getUint16(coff + 2, true);
  const timeDateStamp = dv.getUint32(coff + 4, true);
  const sizeOfOptionalHeader = dv.getUint16(coff + 16, true);
  const characteristics = dv.getUint16(coff + 18, true);

  const opt = coff + 20;
  const magic = dv.getUint16(opt, true);
  const is64 = magic === PE32PLUS_MAGIC;
  if (magic !== PE32_MAGIC && magic !== PE32PLUS_MAGIC) {
    throw new Error(`unknown optional header magic 0x${magic.toString(16)}`);
  }
  // PE32 puts a 4-byte BaseOfData before ImageBase; PE32+ has no BaseOfData and
  // an 8-byte ImageBase, which shifts everything after SizeOfHeapCommit by 16.
  const imageBase = is64 ? Number(dv.getBigUint64(opt + 24, true)) : dv.getUint32(opt + 28, true);
  const rvaCountOff = is64 ? opt + 108 : opt + 92;
  const dirsOff = is64 ? opt + 112 : opt + 96;
  const numberOfRvaAndSizes = dv.getUint32(rvaCountOff, true);

  const directories: RefDirectory[] = [];
  for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
    const p = dirsOff + i * 8;
    if (p + 8 > dv.byteLength) break;
    directories.push({
      virtualAddress: dv.getUint32(p, true),
      size: dv.getUint32(p + 4, true),
    });
  }
  const dirAt = (i: number): RefDirectory => directories[i] ?? { virtualAddress: 0, size: 0 };

  const sections = refSections(dv, opt + sizeOfOptionalHeader, numberOfSections);
  const imports = refImports(dv, dirAt(DIR_IMPORT), sections, is64, imageBase);
  const ex = refExports(dv, dirAt(DIR_EXPORT), sections);
  const res = refResources(dv, dirAt(DIR_RESOURCE), sections);
  // ARM64's records are 8 bytes and a different structure; see the header.
  const pd =
    is64 && machine !== 0xaa64
      ? refPdata(dv, dirAt(DIR_EXCEPTION), sections)
      : { list: [], degenerate: 0, oddVersion: 0, unresolvedUnwind: 0 };
  const imp = refImphash(imports);

  return {
    eLfanew,
    machine,
    numberOfSections,
    timeDateStamp,
    sizeOfOptionalHeader,
    characteristics,
    magic,
    is64,
    addressOfEntryPoint: dv.getUint32(opt + 16, true),
    baseOfCode: dv.getUint32(opt + 20, true),
    sizeOfCode: dv.getUint32(opt + 4, true),
    imageBase,
    sectionAlignment: dv.getUint32(opt + 32, true),
    fileAlignment: dv.getUint32(opt + 36, true),
    sizeOfImage: dv.getUint32(opt + 56, true),
    sizeOfHeaders: dv.getUint32(opt + 60, true),
    storedChecksum: dv.getUint32(opt + 64, true),
    subsystem: dv.getUint16(opt + 68, true),
    dllCharacteristics: dv.getUint16(opt + 70, true),
    numberOfRvaAndSizes,
    directories,
    sections,
    imports,
    exports: ex.list,
    hasExportDir: ex.present,
    resources: res.entries,
    resourceRootIds: res.rootIds,
    pdata: pd.list,
    pdataDegenerate: pd.degenerate,
    pdataOddVersion: pd.oddVersion,
    pdataUnresolvedUnwind: pd.unresolvedUnwind,
    relocations: refRelocations(dv, dirAt(DIR_BASERELOC), sections),
    checksum: refChecksum(new Uint8Array(buffer), eLfanew),
    imphashString: imp.str,
    imphash: imp.hash,
    ordlookupImports: imp.ordlookup,
  };
}

// ════════════════════════════════════════════════════════════════════════════
// THE SUBJECTS.  Everything below compares the reference above against the code
// under test, and may import it.
// ════════════════════════════════════════════════════════════════════════════

/**
 * `Ordinal_<n>` written out LITERALLY, on purpose.
 *
 * `pe/ordinalTables.ts` owns the one declaration of this spelling because it is
 * a wire format: `parsePE` writes it and `computeImphash` reads it back, and
 * nothing in the type system connects the two, so a respelling changes every
 * affected imphash silently. Importing the constant here would make this audit
 * agree with any respelling by construction — the audit's whole job is to be the
 * outside reader that does not.
 */
const EXPECTED_ORDINAL_PREFIX = "Ordinal_";

/** The parser's display name for an address-table slot with no name of its own. */
const EXPECTED_NAMELESS_EXPORT = (ordinal: number) => `Ordinal#${ordinal}`;

/** How many offending entries a row prints. */
const SAMPLE = 6;

export interface Row {
  gate: boolean;
  name: string;
  /** The count that must be zero (gate) or is merely observed (report). */
  value: number;
  /** The population it was drawn from. A row that matched nothing is not green. */
  live: string;
  /** True when the population is empty, so a zero says nothing. */
  vacuous?: boolean;
  rows: string[];
}

function gate(name: string, value: number, live: string, rows: string[] = []): Row {
  return { gate: true, name, value, live, rows: rows.slice(0, SAMPLE) };
}
function report(name: string, value: number, live: string, rows: string[] = []): Row {
  return { gate: false, name, value, live, rows: rows.slice(0, SAMPLE) };
}
/**
 * A gate whose population may legitimately be empty on this corpus.
 *
 * It prints VACUOUS rather than ok when nothing was compared, because "a green
 * row over an empty population says nothing" is this directory's standing rule
 * and the export and ordinal-import rows are both in that position on every
 * binary available here. A vacuous row is not red — there is no defect — but it
 * is not evidence either, and the report must not let the two look alike.
 */
function popGate(
  name: string,
  value: number,
  population: number,
  live: string,
  rows: string[] = [],
): Row {
  return { gate: true, name, value, live, vacuous: population === 0, rows: rows.slice(0, SAMPLE) };
}
/**
 * The liveness half. A population-based audit fails by silently matching
 * nothing, so every subject that MUST have a population on a real MSVC image
 * asserts that here and goes red if it ever stops looking.
 */
function liveness(name: string, population: number): Row {
  return gate(
    `liveness: ${name} population is empty`,
    population === 0 ? 1 : 0,
    `${population} compared`,
  );
}

const hex = (n: number) => `0x${n.toString(16)}`;

/** Collect field-by-field disagreements between two flat records. */
function diffFields(
  where: string,
  a: Record<string, unknown>,
  b: Record<string, unknown>,
  fields: readonly string[],
  out: string[],
): number {
  let bad = 0;
  for (const f of fields) {
    if (a[f] !== b[f]) {
      bad++;
      out.push(`${where}.${f}: reference ${String(a[f])} vs parser ${String(b[f])}`);
    }
  }
  return bad;
}

// ── 1. sections ─────────────────────────────────────────────────────────────

const SECTION_FIELDS = [
  "virtualSize",
  "virtualAddress",
  "sizeOfRawData",
  "pointerToRawData",
  "pointerToRelocations",
  "pointerToLinenumbers",
  "numberOfRelocations",
  "numberOfLinenumbers",
  "characteristics",
] as const;

export function sectionSubject(ref: RefImage, pe: PEFile): Row[] {
  const bad: string[] = [];
  let mismatches = 0;
  let compared = 0;
  let oddNames = 0;

  if (ref.sections.length !== pe.sections.length) {
    mismatches++;
    bad.push(`section count: reference ${ref.sections.length} vs parser ${pe.sections.length}`);
  }
  const n = Math.min(ref.sections.length, pe.sections.length);
  for (let i = 0; i < n; i++) {
    const r = ref.sections[i];
    const p = pe.sections[i];
    compared++;
    // A name with an interior NUL or a high byte is read differently by the two
    // (`String.fromCharCode` over bytes here, `TextDecoder` there) and that is a
    // decoder difference, not a parser defect. Counted, not judged. 0 here.
    if (r.oddName) oddNames++;
    else if (r.name !== p.name) {
      mismatches++;
      bad.push(`section ${i} name: reference "${r.name}" vs parser "${p.name}"`);
    }
    mismatches += diffFields(
      `section ${i} (${r.name})`,
      r as unknown as Record<string, unknown>,
      p as unknown as Record<string, unknown>,
      SECTION_FIELDS,
      bad,
    );
  }

  return [
    gate(
      "sections: field disagreements",
      mismatches,
      `${compared} sections, ${compared * (SECTION_FIELDS.length + 1)} fields`,
      bad,
    ),
    liveness("sections", compared),
    report("sections: names not comparable as bytes", oddNames, `${compared} sections`),
  ];
}

// ── 2. headers and data directories ─────────────────────────────────────────

export function headerSubject(ref: RefImage, pe: PEFile): Row[] {
  const bad: string[] = [];
  let mismatches = 0;

  const pairs: [string, unknown, unknown][] = [
    ["e_lfanew", ref.eLfanew, pe.dosHeader.e_lfanew],
    ["machine", ref.machine, pe.coffHeader.machine],
    ["numberOfSections", ref.numberOfSections, pe.coffHeader.numberOfSections],
    ["timeDateStamp", ref.timeDateStamp, pe.coffHeader.timeDateStamp],
    ["sizeOfOptionalHeader", ref.sizeOfOptionalHeader, pe.coffHeader.sizeOfOptionalHeader],
    ["characteristics", ref.characteristics, pe.coffHeader.characteristics],
    ["magic", ref.magic, pe.optionalHeader.magic],
    ["is64", ref.is64, pe.is64],
    ["addressOfEntryPoint", ref.addressOfEntryPoint, pe.optionalHeader.addressOfEntryPoint],
    ["baseOfCode", ref.baseOfCode, pe.optionalHeader.baseOfCode],
    ["sizeOfCode", ref.sizeOfCode, pe.optionalHeader.sizeOfCode],
    ["imageBase", ref.imageBase, pe.optionalHeader.imageBase],
    ["sectionAlignment", ref.sectionAlignment, pe.optionalHeader.sectionAlignment],
    ["fileAlignment", ref.fileAlignment, pe.optionalHeader.fileAlignment],
    ["sizeOfImage", ref.sizeOfImage, pe.optionalHeader.sizeOfImage],
    ["sizeOfHeaders", ref.sizeOfHeaders, pe.optionalHeader.sizeOfHeaders],
    ["checkSum (stored)", ref.storedChecksum, pe.optionalHeader.checksum],
    ["subsystem", ref.subsystem, pe.optionalHeader.subsystem],
    ["dllCharacteristics", ref.dllCharacteristics, pe.optionalHeader.dllCharacteristics],
    ["numberOfRvaAndSizes", ref.numberOfRvaAndSizes, pe.optionalHeader.numberOfRvaAndSizes],
  ];
  for (const [name, a, b] of pairs) {
    if (a !== b) {
      mismatches++;
      bad.push(`${name}: reference ${String(a)} vs parser ${String(b)}`);
    }
  }

  let dirBad = 0;
  const dirRows: string[] = [];
  const dn = Math.min(ref.directories.length, pe.dataDirectories.length);
  if (ref.directories.length !== pe.dataDirectories.length) {
    dirBad++;
    dirRows.push(
      `directory count: reference ${ref.directories.length} vs parser ${pe.dataDirectories.length}`,
    );
  }
  for (let i = 0; i < dn; i++) {
    const r = ref.directories[i];
    const p = pe.dataDirectories[i];
    if (r.virtualAddress !== p.virtualAddress || r.size !== p.size) {
      dirBad++;
      dirRows.push(
        `directory ${i}: reference ${hex(r.virtualAddress)}/${r.size}` +
          ` vs parser ${hex(p.virtualAddress)}/${p.size}`,
      );
    }
  }

  return [
    gate("headers: field disagreements", mismatches, `${pairs.length} fields`, bad),
    gate("directories: entry disagreements", dirBad, `${dn} data directories`, dirRows),
    liveness("data directories", dn),
  ];
}

// ── 3. imports ──────────────────────────────────────────────────────────────

export function importSubject(ref: RefImage, pe: PEFile): Row[] {
  const bad: string[] = [];
  const ordRows: string[] = [];
  const iatRows: string[] = [];
  let mismatches = 0;
  let ordBad = 0;
  let iatBad = 0;
  let dlls = 0;
  let funcs = 0;
  let ordinals = 0;
  let nonAscii = 0;

  if (ref.imports.length !== pe.imports.length) {
    mismatches++;
    bad.push(`DLL count: reference ${ref.imports.length} vs parser ${pe.imports.length}`);
  }
  const n = Math.min(ref.imports.length, pe.imports.length);
  for (let i = 0; i < n; i++) {
    const r = ref.imports[i];
    const p = pe.imports[i];
    dlls++;
    if (!r.dllNonAscii && r.dll !== p.libraryName) {
      mismatches++;
      bad.push(`import ${i} DLL: reference "${r.dll}" vs parser "${p.libraryName}"`);
    }
    if (r.dllNonAscii) nonAscii++;

    if (r.funcs.length !== p.functions.length) {
      mismatches++;
      bad.push(
        `${r.dll}: function count reference ${r.funcs.length} vs parser ${p.functions.length}`,
      );
    }
    // The parser's `iatAddresses` is pushed before its `functions` entry, so a
    // name it could not read leaves the two arrays a different length. Real
    // images never do that; asked because a silent skew is the shape of a real
    // defect and nothing else looks at it.
    if (p.functions.length !== p.iatAddresses.length) {
      iatBad++;
      iatRows.push(
        `${p.libraryName}: parser has ${p.functions.length} names for` +
          ` ${p.iatAddresses.length} IAT slots`,
      );
    }

    const fn = Math.min(r.funcs.length, p.functions.length);
    for (let j = 0; j < fn; j++) {
      const rf = r.funcs[j];
      const pf = p.functions[j];
      funcs++;
      if (rf.kind === "ordinal") {
        ordinals++;
        // The comparison spells the wire format itself — see
        // EXPECTED_ORDINAL_PREFIX.
        const want = `${EXPECTED_ORDINAL_PREFIX}${rf.ordinal}`;
        if (pf !== want) {
          ordBad++;
          ordRows.push(`${r.dll}[${j}]: reference ordinal ${rf.ordinal} spelled "${pf}"`);
        }
        continue;
      }
      if (rf.nonAscii) {
        nonAscii++;
        continue;
      }
      if (rf.name !== pf) {
        mismatches++;
        bad.push(`${r.dll}[${j}]: reference "${rf.name}" vs parser "${pf}"`);
      }
    }

    const an = Math.min(r.iat.length, p.iatAddresses.length);
    for (let j = 0; j < an; j++) {
      if (r.iat[j] !== p.iatAddresses[j]) {
        iatBad++;
        iatRows.push(
          `${r.dll}[${j}] IAT: reference ${hex(r.iat[j])} vs parser ${hex(p.iatAddresses[j])}`,
        );
      }
    }
  }

  return [
    gate(
      "imports: DLL and function-name disagreements",
      mismatches,
      `${dlls} DLLs, ${funcs} functions`,
      bad,
    ),
    gate("imports: IAT address disagreements", iatBad, `${dlls} DLLs, ${funcs} slots`, iatRows),
    liveness("imports", funcs),
    popGate(
      `imports: ordinal imports not spelled "${EXPECTED_ORDINAL_PREFIX}<n>"`,
      ordBad,
      ordinals,
      `${ordinals} ordinal imports of ${funcs}`,
      ordRows,
    ),
    report("imports: names not comparable as bytes", nonAscii, `${funcs} functions`),
  ];
}

// ── 4. exports ──────────────────────────────────────────────────────────────

export function exportSubject(ref: RefImage, pe: PEFile): Row[] {
  const bad: string[] = [];
  let mismatches = 0;
  let compared = 0;
  let forwarders = 0;
  let nameless = 0;

  if (ref.exports.length !== pe.exports.length) {
    mismatches++;
    bad.push(`export count: reference ${ref.exports.length} vs parser ${pe.exports.length}`);
  }
  const n = Math.min(ref.exports.length, pe.exports.length);
  for (let i = 0; i < n; i++) {
    const r = ref.exports[i];
    const p = pe.exports[i];
    compared++;
    const want = r.name ?? EXPECTED_NAMELESS_EXPORT(r.ordinal);
    if (r.name === null) nameless++;
    if (want !== p.name) {
      mismatches++;
      bad.push(`export ${i}: reference "${want}" vs parser "${p.name}"`);
    }
    if ((r.name === null) !== (p.byOrdinal === true)) {
      mismatches++;
      bad.push(`export ${p.name}: byOrdinal reference ${r.name === null} vs parser ${p.byOrdinal}`);
    }
    if (r.ordinal !== p.ordinal) {
      mismatches++;
      bad.push(`export ${p.name}: ordinal reference ${r.ordinal} vs parser ${p.ordinal}`);
    }
    if (r.rva !== p.address) {
      mismatches++;
      bad.push(`export ${p.name}: RVA reference ${hex(r.rva)} vs parser ${hex(p.address)}`);
    }
    // A forwarder's address lies inside the export directory, so it is a string
    // RVA rather than code. Both readers must agree on WHICH exports are
    // forwarders as well as on the redirect text.
    if (r.forwarder !== null) forwarders++;
    if ((r.forwarder ?? undefined) !== p.forwarder) {
      mismatches++;
      bad.push(
        `export ${p.name}: forwarder reference ${String(r.forwarder)} vs parser ${String(p.forwarder)}`,
      );
    }
  }

  return [
    popGate("exports: entry disagreements", mismatches, compared, `${compared} exports`, bad),
    popGate(
      "exports: forwarder disagreements (subset of the row above)",
      0,
      forwarders,
      `${forwarders} forwarders of ${compared}`,
    ),
    report("exports: nameless (ordinal-only) slots", nameless, `${compared} exports`),
  ];
}

// ── 5. checksum ─────────────────────────────────────────────────────────────

export function checksumSubject(ref: RefImage, pe: PEFile, ab: ArrayBuffer): Row[] {
  const prod = checksumFile(ab, pe.dosHeader.e_lfanew, pe.optionalHeader.checksum);
  const rows: string[] = [];
  const disagree = prod.actual !== ref.checksum ? 1 : 0;
  if (disagree) {
    rows.push(`reference ${hex(ref.checksum)} vs parser ${hex(prod.actual)}`);
  }

  // The linker's own value, which is an oracle OUTSIDE both readers — the one
  // row here that does not depend on either being right. Zero means the image
  // was never checksummed (both ARM64 launchers), so there is no oracle and the
  // row is vacuous rather than green.
  const stored = ref.storedChecksum;
  const linkerRows: string[] = [];
  let linkerBad = 0;
  if (stored !== 0 && stored !== ref.checksum) {
    linkerBad = 1;
    linkerRows.push(`header says ${hex(stored)}, reference computes ${hex(ref.checksum)}`);
  }

  return [
    gate("checksum: reference and parser disagree", disagree, "1 image", rows),
    popGate(
      "checksum: reference disagrees with the value the linker stored",
      linkerBad,
      stored === 0 ? 0 : 1,
      stored === 0 ? "image stores no checksum" : `stored ${hex(stored)}`,
      linkerRows,
    ),
  ];
}

// ── 6. imphash ──────────────────────────────────────────────────────────────

export function imphashSubject(ref: RefImage, pe: PEFile): Row[] {
  // Takes the FILE, not the list: `computeImphash` refuses (returns null) when
  // the import walk was cut short, and asking that of the list is impossible by
  // construction (peek-a-bin-tmo9). On this corpus no walk is ever truncated,
  // so `prod` is a string on every row here — a null would show up as a
  // disagreement rather than being quietly compared as `"null"`.
  const prod = computeImphash(pe);
  const rows: string[] = [];
  let bad = 0;
  // An ordinal import from a DLL pefile resolves through `ordlookup` is
  // excluded: the reference has no independent copy of that table (see
  // REF_ORDLOOKUP_DLLS) and inventing one would make the row agree with the
  // parser by construction.
  const comparable = ref.ordlookupImports === 0;
  if (comparable && prod !== ref.imphash) {
    bad = 1;
    rows.push(`reference ${ref.imphash} vs parser ${prod}`);
    rows.push(`reference string: ${ref.imphashString.slice(0, 160)}`);
  }
  const parts = ref.imphashString === "" ? 0 : ref.imphashString.split(",").length;
  return [
    popGate(
      "imphash: reference and parser disagree",
      bad,
      comparable ? parts : 0,
      comparable
        ? `${parts} dll.func parts, ${ref.imphash.slice(0, 12)}…`
        : `${ref.ordlookupImports} ordlookup ordinals — not comparable`,
      rows,
    ),
    report(
      "imphash: ordinal imports from an ordlookup DLL",
      ref.ordlookupImports,
      `${parts} parts`,
    ),
  ];
}

// ── 7. resources ────────────────────────────────────────────────────────────

export function resourceSubject(ref: RefImage, pe: PEFile): Row[] {
  const bad: string[] = [];
  let mismatches = 0;
  const parsed = pe.resources?.entries ?? [];
  if (ref.resources.length !== parsed.length) {
    mismatches++;
    bad.push(`entry count: reference ${ref.resources.length} vs parser ${parsed.length}`);
  }
  const n = Math.min(ref.resources.length, parsed.length);
  for (let i = 0; i < n; i++) {
    const r = ref.resources[i];
    const p = parsed[i];
    if (r.type !== p.type || r.name !== p.name || r.lang !== p.lang) {
      mismatches++;
      bad.push(
        `resource ${i} path: reference ${String(r.type)}/${String(r.name)}/${r.lang}` +
          ` vs parser ${String(p.type)}/${String(p.name)}/${p.lang}`,
      );
    }
    if (r.rva !== p.rva || r.size !== p.size) {
      mismatches++;
      bad.push(
        `resource ${i} data: reference ${hex(r.rva)}/${r.size} vs parser ${hex(p.rva)}/${p.size}`,
      );
    }
  }

  // The flattened entry list is what the Resources tab reads, but it cannot see
  // the SHAPE of the tree — a walk that mis-nested every level would still emit
  // the same leaves. The top-level node ids are the cheapest independent check
  // of the shape.
  const rootRows: string[] = [];
  let rootBad = 0;
  const refRoot = ref.resourceRootIds;
  const peRoot = (pe.resources?.root ?? []).map((x) => x.id);
  if (refRoot.length !== peRoot.length) {
    rootBad++;
    rootRows.push(`root children: reference ${refRoot.length} vs parser ${peRoot.length}`);
  }
  for (let i = 0; i < Math.min(refRoot.length, peRoot.length); i++) {
    if (refRoot[i] !== peRoot[i]) {
      rootBad++;
      rootRows.push(`root ${i}: reference ${String(refRoot[i])} vs parser ${String(peRoot[i])}`);
    }
  }

  return [
    gate("resources: leaf disagreements", mismatches, `${n} entries`, bad),
    gate(
      "resources: top-level tree disagreements",
      rootBad,
      `${peRoot.length} type nodes`,
      rootRows,
    ),
    liveness("resource entries", n),
    report(
      // The flag no longer means only "the entry budget ran out": as of
      // peek-a-bin-dhcx it also covers a directory or subdirectory header past
      // the buffer and an unresolvable .rsrc RVA, all three being declared
      // entries the walk abandoned. The label follows the flag.
      "resources: walk left incomplete",
      pe.resources?.truncated ? 1 : 0,
      "1 image",
    ),
  ];
}

// ── 8. .pdata (x64 only) ────────────────────────────────────────────────────

export function pdataSubject(ref: RefImage, pe: PEFile): Row[] {
  // ARM64 is gated by `npm run corpus:arm64` against the sweep itself, which is
  // a stronger oracle than a second reader; PE32 has no exception directory.
  if (!ref.is64 || ref.machine === 0xaa64) return [];

  const parsed = pe.runtimeFunctions ?? [];
  const bad: string[] = [];
  let mismatches = 0;
  if (ref.pdata.length !== parsed.length) {
    mismatches++;
    bad.push(`record count: reference ${ref.pdata.length} vs parser ${parsed.length}`);
  }
  const n = Math.min(ref.pdata.length, parsed.length);
  let handlers = 0;
  for (let i = 0; i < n; i++) {
    const r = ref.pdata[i];
    const p = parsed[i];
    if (r.begin !== p.beginAddress || r.end !== p.endAddress || r.unwind !== p.unwindInfoAddress) {
      mismatches++;
      bad.push(
        `pdata ${i}: reference ${hex(r.begin)}-${hex(r.end)}/${hex(r.unwind)}` +
          ` vs parser ${hex(p.beginAddress)}-${hex(p.endAddress)}/${hex(p.unwindInfoAddress)}`,
      );
    }
    if (r.handlerFlags !== p.handlerFlags) {
      mismatches++;
      bad.push(
        `pdata ${i} (${hex(r.begin)}): handlerFlags reference ${String(r.handlerFlags)}` +
          ` vs parser ${String(p.handlerFlags)}`,
      );
    }
    if (r.handlerAddress !== p.handlerAddress) {
      mismatches++;
      bad.push(
        `pdata ${i} (${hex(r.begin)}): handler reference ${String(r.handlerAddress)}` +
          ` vs parser ${String(p.handlerAddress)}`,
      );
    }
    if (r.handlerAddress !== undefined) handlers++;
  }

  return [
    gate("pdata: x64 record disagreements", mismatches, `${n} records`, bad),
    liveness("x64 .pdata records", n),
    report("pdata: records naming an exception handler", handlers, `${n} records`),
    report("pdata: degenerate records both readers drop", ref.pdataDegenerate, `${n} kept`),
    // The two rows that say what this corpus does NOT exercise. Both are 0 on
    // t64 and w64, so `parsePdata`'s UNWIND_INFO version check and its
    // unresolvable-RVA arm have an EMPTY population here — a measured control
    // (accepting version 0 as well) moves no row. Reported rather than gated
    // because a rise is not a defect: it is a file with unwind data this reader
    // cannot vouch for.
    report(
      "pdata: records whose UNWIND_INFO version is not 1 or 2 (version check unexercised at 0)",
      ref.pdataOddVersion,
      `${n} records`,
    ),
    report(
      "pdata: records whose unwindInfoAddress resolves to nothing",
      ref.pdataUnresolvedUnwind,
      `${n} records`,
    ),
  ];
}

// ── 9. relocations ──────────────────────────────────────────────────────────

export function relocationSubject(ref: RefImage, pe: PEFile): Row[] {
  const parsed = pe.relocations ?? [];
  const bad: string[] = [];
  let mismatches = 0;
  let entries = 0;
  if (ref.relocations.length !== parsed.length) {
    mismatches++;
    bad.push(`block count: reference ${ref.relocations.length} vs parser ${parsed.length}`);
  }
  const n = Math.min(ref.relocations.length, parsed.length);
  for (let i = 0; i < n; i++) {
    const r = ref.relocations[i];
    const p = parsed[i];
    if (r.virtualAddress !== p.virtualAddress) {
      mismatches++;
      bad.push(
        `reloc block ${i}: reference ${hex(r.virtualAddress)} vs parser ${hex(p.virtualAddress)}`,
      );
    }
    if (r.entries.length !== p.entries.length) {
      mismatches++;
      bad.push(
        `reloc block ${hex(r.virtualAddress)}: ${r.entries.length} entries vs ${p.entries.length}`,
      );
    }
    for (let j = 0; j < Math.min(r.entries.length, p.entries.length); j++) {
      entries++;
      if (r.entries[j].type !== p.entries[j].type || r.entries[j].offset !== p.entries[j].offset) {
        mismatches++;
        bad.push(
          `reloc ${hex(r.virtualAddress)}[${j}]: reference ${r.entries[j].type}/${hex(r.entries[j].offset)}` +
            ` vs parser ${p.entries[j].type}/${hex(p.entries[j].offset)}`,
        );
      }
    }
  }
  return [
    gate(
      "relocations: block and entry disagreements",
      mismatches,
      `${n} blocks, ${entries} entries`,
      bad,
    ),
    liveness("relocation entries", entries),
  ];
}

// ── the run ─────────────────────────────────────────────────────────────────

export function auditImage(ab: ArrayBuffer): { rows: Row[]; summary: string } {
  const ref = readReference(ab);
  const pe = parsePE(ab);
  const rows = [
    ...headerSubject(ref, pe),
    ...sectionSubject(ref, pe),
    ...importSubject(ref, pe),
    ...exportSubject(ref, pe),
    ...checksumSubject(ref, pe, ab),
    ...imphashSubject(ref, pe),
    ...resourceSubject(ref, pe),
    ...pdataSubject(ref, pe),
    ...relocationSubject(ref, pe),
  ];
  const summary =
    `machine ${hex(ref.machine)}, ${ref.sections.length} sections, ` +
    `${ref.imports.length} DLLs / ${ref.imports.reduce((a, i) => a + i.funcs.length, 0)} imports, ` +
    `${ref.exports.length} exports, ${ref.resources.length} resources, ` +
    `${ref.pdata.length} x64 .pdata, ` +
    `${ref.relocations.reduce((a, b) => a + b.entries.length, 0)} relocations`;
  return { rows, summary };
}

function readImage(file: string): ArrayBuffer {
  const b = readFileSync(file);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

function main(): void {
  const extra = process.argv.slice(2);

  // Both searches, so the header can name every binary actually read. The ARM64
  // pair is included because sections, imports, resources, the checksum and the
  // imphash are format-level questions with nothing architecture-specific in
  // them — only `.pdata` is skipped there, and it is skipped for a stated
  // reason rather than by omission. This harness has its own denominators and
  // is not `npm run corpus`, so adding them changes no documented figure.
  const x86 = resolveCorpus(ALL_BINS);
  const arm = resolveArmCorpus();

  const files: [string, string][] = [];
  if (x86.found) for (const k of ALL_BINS) files.push([k, `${x86.dir}/${k}.exe`]);
  for (const [k, p] of arm.present) files.push([k, p]);
  for (const p of extra) files.push([basename(p), p]);

  console.log(`corpus: ${x86.dir}  [${x86.source}]`);
  if (!x86.found) {
    console.log("SKIPPED for the x86 four — not all present.");
    for (const pr of x86.probes) console.log(`    ${pr.dir}  — ${pr.note}  [${pr.source}]`);
  }
  if (arm.missing.length > 0)
    console.log(`SKIPPED for ${arm.missing.join(", ")} — not in ${arm.dir}`);
  console.log(`binaries read: ${files.map(([k]) => k).join(", ") || "none"}`);
  if (files.length === 0) {
    console.log("\nCORPUS DIFFERENTIAL SKIPPED — nothing was verified.");
    if (!x86.found && arm.detail) console.log(arm.detail);
    return;
  }

  const findings: { bin: string; row: Row }[] = [];
  for (const [key, file] of files) {
    let res: { rows: Row[]; summary: string };
    try {
      res = auditImage(readImage(file));
    } catch (e) {
      console.log(`\n${key}: READ FAILED — ${e instanceof Error ? e.message : String(e)}`);
      findings.push({
        bin: key,
        row: gate("image: could not be read by both readers", 1, "1 image", [
          String(e).slice(0, 200),
        ]),
      });
      continue;
    }
    console.log(`\n${key}: ${res.summary}`);
    for (const row of res.rows) findings.push({ bin: key, row });
  }

  console.log(`\n── results ${"─".repeat(56)}`);
  let red = 0;
  let vac = 0;
  for (const { bin, row } of findings) {
    const tag = row.gate
      ? row.value !== 0
        ? "GATE  RED"
        : row.vacuous
          ? "GATE  VAC"
          : "GATE  ok "
      : "report   ";
    if (row.gate && row.value !== 0) red++;
    if (row.gate && row.value === 0 && row.vacuous) vac++;
    console.log(`${tag} ${bin.padEnd(8)} ${row.name}: ${row.value}   [${row.live}]`);
    for (const r of row.rows) console.log(`             ${r}`);
  }
  const gates = findings.filter((f) => f.row.gate).length;
  console.log(
    `\n${gates - red - vac} of ${gates} gates green, ${vac} VACUOUS (empty population — no evidence), ` +
      `${findings.length - gates} rows reported. ` +
      (red === 0 ? "OK" : `${red} RED`),
  );
  if (red > 0) process.exit(1);
}

/**
 * Only run when invoked directly, so `build/parserIndependence.test.ts` and any
 * other consumer can import the reference reader and the judging functions
 * without driving a whole corpus run as a side effect of the import.
 */
if (process.argv[1] !== undefined && /parserDifferential\.[cm]?[tj]s$/.test(process.argv[1])) {
  main();
}
