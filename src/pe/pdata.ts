import { decodePackedArm64Unwind, frameFromUnwindCodes } from "./arm64Unwind";
import { IMAGE_FILE_MACHINE_ARM64 } from "./constants";
import {
  buildSectionIndex,
  rvaToFileOffsetIndexed,
  type SectionIndex,
  sectionRawLimitForRva,
} from "./parser";
import type { DataDirectory, RuntimeFunction, SectionHeader } from "./types";

/** UNWIND_INFO flag: the record carries an exception handler. */
const UNW_FLAG_EHANDLER = 0x1;

/**
 * UNWIND_INFO flag: what follows the unwind codes is a chained
 * `RUNTIME_FUNCTION`, not a handler RVA + language-specific data.
 *
 * Mutually exclusive with the two handler flags — the same four bytes cannot be
 * both — so a record claiming both is malformed and the handler is not read.
 * `EHANDLER | UHANDLER` together is fine and ordinary; that pair shares one RVA.
 */
const UNW_FLAG_CHAININFO = 0x4;

const X64_ENTRY_SIZE = 12;
const ARM64_ENTRY_SIZE = 8;

/**
 * The most `RUNTIME_FUNCTION` entries that will be read out of one exception
 * directory.
 *
 * `count` was `Math.floor(size / entrySize)` over a `uint32` from the file,
 * with the end of the BUFFER as its only backstop — so a crafted `size` of
 * `0xFFFFFFFF` takes the whole file: `buffer / 12` on x64, `buffer / 8` on
 * ARM64.
 *
 * 2^20 is an order of magnitude above the largest real table this codebase
 * knows of (`parsePdata`'s own docstring records ntoskrnl-sized images at ~100k
 * entries; the corpus tops out at 419). At 12 bytes an entry that is a 12 MiB
 * `.pdata`, larger than any observed. It is a backstop rather than the primary
 * bound: the containing section's raw extent, applied beside it, is the bound
 * the file itself provides and cannot inflate beyond the image.
 */
export const MAX_PDATA_ENTRIES = 1 << 20;

/**
 * The most `.xdata` unwind-code bytes that will be decoded across one whole
 * ARM64 exception table.
 *
 * **THIS IS THE PRODUCT, AND IT IS THE WORST FINDING IN THE CENSUS BY WALL
 * CLOCK.** An `.xdata` record's extension word gives `codeWords` eight bits, so
 * one record may legitimately carry 255 * 4 = 1020 code bytes, which
 * `parseArm64XdataRecord` copies into a fresh `number[]` and then walks. Nothing
 * stopped every entry in the table from naming the SAME record, so the cost is
 * `entries x 1020` — and entries was `buffer / 8`. Measured at `d8d8a6d` with
 * `size = 0xFFFFFFFF` and every entry aimed at one 1020-byte record:
 *
 * | file      | entries | unwind bytes walked | wall clock |
 * |-----------|---------|---------------------|------------|
 * | 69,632    |   8,064 |           8,225,280 |    8.3 s   |
 * | 266,240   |  32,640 |          33,292,800 |   37.7 s   |
 *
 * — linear in file size with a ~1020x constant, in `parsePE`, on the main
 * thread. A 1 MiB file is ~150 s; the 253 MiB images this tool opens are hours.
 * A 1 MiB fixture did not complete inside a two-minute harness timeout.
 *
 * A per-record cap cannot fix that (`peek-a-bin-tmo9`'s lesson: capping each of
 * two file-supplied counts still multiplies out), so this is ONE budget for the
 * whole table.
 *
 * **4 MiB IS CALIBRATED AGAINST THE REAL TABLES, not picked round.** Measured at
 * `d8d8a6d` over both ARM64 corpus binaries: `t64-arm` has 419 `.pdata` entries,
 * 156 of them naming an `.xdata` record, **1220 code bytes in total** and **28
 * bytes in the largest single record**; `w64-arm` 381 / 144 / **1100** / **28**.
 * So the format's 1020-byte per-record ceiling is ~36x anything a linker
 * actually emits, and 4 MiB is ~3400x either whole-table total. It still covers
 * an ntoskrnl-scale table — `parsePdata`'s docstring puts those at ~100k entries,
 * i.e. ~2.8 MB at the observed 28 bytes each — so a legitimate large ARM64 image
 * cannot be cut by it.
 *
 * **What the budget canNOT fix, and it is worth knowing:** `readUnwindCode`
 * allocates two closures and a result object per BYTE, so the walk costs ~1.1 µs
 * a byte (8.2 MB in 8.9 s, measured after this fix's `Uint8Array` change, which
 * itself took 25 s → 18 s off the 16 MiB case). At 4 MiB the hostile ceiling is
 * therefore still ~4 s on the main thread — and a legitimate 100k-entry ARM64
 * image already pays ~3 s of it today. That is a pre-existing property of the
 * decoder, not of the bound, and rewriting it does not belong in a bounds change.
 *
 * The narrowing is honest without a new channel: a record whose codes are not
 * decoded yields **no `arm64Frame`**, which is already exactly what
 * `frameFromUnwindCodes` returns for a record it cannot read, and what every
 * consumer of `RuntimeFunction.arm64Frame` already handles. The function's
 * *extent* — the part `functionDetect` treats as authoritative — is read out of
 * the header word and is unaffected.
 */
export const MAX_ARM64_UNWIND_CODE_BYTES = 4 * 1024 * 1024;

/** Unwind-code bytes left in one table's budget. See MAX_ARM64_UNWIND_CODE_BYTES. */
interface UnwindBudget {
  remaining: number;
}

/**
 * Parse .pdata (Exception Directory).
 *
 * **The schema is chosen by machine type, not by PE32+ magic.** An ARM64 image
 * is PE32+ like an x64 one, but its RUNTIME_FUNCTION is a different structure of
 * a different size, so reading one with the other's layout does not merely lose
 * the unwind flags — it desynchronises the whole table and reports about a third
 * of the entries, at addresses that are really other entries' unwind words
 * (peek-a-bin-kwc). Anything but ARM64 is read as x64, which is what every PE32+
 * image the tool has ever been pointed at is.
 *
 * **A HYBRID IMAGE HAS TWO FUNCTION TABLES AND THIS READS ONE OF THEM — the
 * one it reads is the one the machine word describes, which is why keying on the
 * machine word is right here and could never be right for the other.** Settled
 * against documentation at peek-a-bin-c71x; there is no ARM64EC or ARM64X binary
 * on this machine, so none of it is observed. An ARM64EC image contains native
 * A64 code following x64 software conventions *and* genuine x64 code, and each
 * half has its own table in its own architecture's format:
 *
 * | image, as it lies on disk        | `IMAGE_DIRECTORY_ENTRY_EXCEPTION` | CHPE `ExtraRFETable` |
 * |----------------------------------|-----------------------------------|----------------------|
 * | ARM64EC (marked 0x8664)          | **x64**, 12-byte entries          | **ARM64**, 8-byte    |
 * | ARM64X (marked 0xAA64, default)  | **ARM64**, 8-byte entries         | **x64**, 12-byte     |
 *
 * so the invariant is that the exception directory always holds the table of the
 * architecture the image *presents itself as*, and `ExtraRFETable` — a field of
 * `IMAGE_ARM64EC_METADATA`, reached through `LoadConfigDirectory`'s
 * `chpeMetadataPointer` — always holds the other one. For ARM64X the two are
 * *swapped by the ARM64X dynamic-value relocations* when the image is loaded into
 * an x64/EC process, so its hybrid view is byte-for-byte an ARM64EC image's
 * layout; a static reader sees the un-fixed-up view, which is the ARM64 one.
 *
 * Three independent sources, none of them a secondary account:
 *  - lld's COFF writer says it outright — `// ARM64EC (but not ARM64X) contains
 *    x86_64 exception table in data directory`, over
 *    `machine == ARM64EC ? hybridPdata : pdata`, where `hybridPdata` is declared
 *    `// x86_64 .pdata sections on ARM64EC/ARM64X targets` and `mergeSections`
 *    splits `.pdata` into the two by `chunk->getMachine() == AMD64`. The same
 *    file points `__arm64x_extra_rfe_table` at the complement
 *    (`machine == ARM64X ? hybridPdata : pdata`) and, for ARM64X, emits
 *    `IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE` relocations over both the
 *    `EXCEPTION_TABLE` data directory and `offsetof(chpe_metadata,
 *    ExtraRFETable)`. https://github.com/llvm/llvm-project/blob/main/lld/COFF/Writer.cpp
 *  - Wine's loader routes by *code range* rather than by image:
 *    `RtlLookupFunctionTable` answers `ExtraRFETable`/`ExtraRFETableSize` when
 *    `RtlIsEcCode(pc)` and `IMAGE_DIRECTORY_ENTRY_EXCEPTION` otherwise, and the
 *    x64 `RtlLookupFunctionEntry` delegates an EC pc to the ARM64 one, which
 *    searches `ARM64_RUNTIME_FUNCTION` {BeginAddress, Flag, FunctionLength,
 *    UnwindData} — the 8-byte form `parseArm64Pdata` decodes.
 *    https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unwind.c
 *  - Microsoft's Arm64EC ABI page requires *dynamically* added EC unwind entries
 *    to "be in Arm64 format", noting `RUNTIME_FUNCTION` is the x64 shape when
 *    compiling EC so `ARM64_RUNTIME_FUNCTION` must be named explicitly, and its
 *    worked entry-thunk listing is ARM64 unwind codes (`E7 save_any_reg`,
 *    `E6 save_next_pair`, `E1`, `E4 end`).
 *    https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi
 *
 * **So this function's answer is RIGHT for every hybrid case and INCOMPLETE for
 * all of them**: the directory really does hold what the machine word says, and
 * the other half of the image's functions is in a table nothing here reads.
 * Reading it is not attempted, because `chpeMetadataPointer` has never once been
 * observed non-zero on any file here — measured at 11408ac, t64/w64 have no
 * load-config directory at all, the ARM64 pair read 0, and the PE32 pair declare
 * a structure too short to reach the field — so a consumer of it would be
 * unverifiable in both directions (peek-a-bin-3ucw). What a future reader needs
 * is here rather than in a half-built reader: `ExtraRFETable` is at **0x40** and
 * `ExtraRFETableSize` at **0x44** of `IMAGE_ARM64EC_METADATA` (all-`ULONG`
 * fields, `Version` first), both RVAs; and its schema is the **complement** of
 * the machine word, never the machine word itself.
 *
 * **THE TWO HYBRID MACHINE CONSTANTS ARE GONE, AND ONE OF THEM WAS WRONG RATHER
 * THAN MERELY UNREACHABLE.** `isArm64Machine` used to send
 * `IMAGE_FILE_MACHINE_ARM64EC` (0xA641) and `IMAGE_FILE_MACHINE_ARM64X` (0xA64E)
 * down the ARM64 path as a "deliberate superset", on the reasoning that it would
 * be right if either ever reached a `coffHeader`. The table above refutes half of
 * that: 0xA641 means an ARM64EC image, whose exception directory is the **x64**
 * table, so the arm would have read 12-byte entries at an 8-byte stride — the
 * peek-a-bin-kwc desynchronisation this docstring opens by warning about, arrived
 * at from the other direction. 0xA64E's intention was right, and is already
 * served by 0xAA64, which is the word an ARM64X image actually carries; keeping
 * an unreachable duplicate of a correct answer beside a refuted one only invites
 * re-adding both. Neither constant reaches a linked image's machine field
 * (peek-a-bin-3ucw, citations in `disasm/arch.ts`), so removing them moves no
 * output — but the reason to remove 0xA641 is that its reading is now known to be
 * wrong, not that it is dead. `__tests__/pdata.test.ts` pins that, since nothing
 * measurable can.
 *
 * `index` is the caller's prebuilt section lookup — ntoskrnl-sized images have
 * ~100k entries and each one resolves an unwind RVA, so building it per call
 * (let alone scanning the section table per lookup) is the whole cost here.
 * Omitted, one is built from `sections`.
 */
export function parsePdata(
  buffer: ArrayBuffer,
  exceptionDir: DataDirectory,
  sections: SectionHeader[],
  machine: number,
  index?: SectionIndex,
): RuntimeFunction[] {
  if (!exceptionDir.virtualAddress || !exceptionDir.size) return [];

  const sectionIndex = index ?? buildSectionIndex(sections);
  const offset = rvaToFileOffsetIndexed(exceptionDir.virtualAddress, sectionIndex);
  if (offset < 0) return [];

  const view = new DataView(buffer);
  // How far the table may be read: its own section's raw extent where the
  // section table places it, and the buffer otherwise. The `size` the directory
  // declares is honoured by the two readers below; this is the bound it cannot
  // inflate past. See MAX_PDATA_ENTRIES.
  const sectionLimit = sectionRawLimitForRva(exceptionDir.virtualAddress, sectionIndex);
  const limit = Math.min(
    view.byteLength,
    sectionLimit >= 0 ? sectionLimit : Number.POSITIVE_INFINITY,
  );
  return machine === IMAGE_FILE_MACHINE_ARM64
    ? parseArm64Pdata(view, offset, exceptionDir.size, limit, sectionIndex)
    : parseX64Pdata(view, offset, exceptionDir.size, limit, sectionIndex);
}

/**
 * How many fixed-size entries a table at `offset` may hold: its declared size,
 * what the section and buffer leave, and {@link MAX_PDATA_ENTRIES}. One helper
 * because both readers ask the identical question and a second hand-written
 * copy is how these bounds drift apart.
 */
function entryCountFor(offset: number, size: number, limit: number, entrySize: number): number {
  return Math.min(
    Math.floor(Math.max(0, size) / entrySize),
    Math.floor(Math.max(0, limit - offset) / entrySize),
    MAX_PDATA_ENTRIES,
  );
}

/**
 * x64 (and IA64) RUNTIME_FUNCTION: beginAddress (u32), endAddress (u32),
 * unwindInfoAddress (u32), all RVAs.
 */
function parseX64Pdata(
  view: DataView,
  offset: number,
  size: number,
  limit: number,
  sectionIndex: SectionIndex,
): RuntimeFunction[] {
  const count = entryCountFor(offset, size, limit, X64_ENTRY_SIZE);
  const results: RuntimeFunction[] = [];

  for (let i = 0; i < count; i++) {
    const entryOffset = offset + i * X64_ENTRY_SIZE;

    const beginAddress = view.getUint32(entryOffset, true);
    const endAddress = view.getUint32(entryOffset + 4, true);
    const unwindInfoAddress = view.getUint32(entryOffset + 8, true);

    // Validate: begin < end
    if (beginAddress >= endAddress) continue;

    const rf: RuntimeFunction = { beginAddress, endAddress, unwindInfoAddress };

    // Parse UNWIND_INFO to check for exception handler.
    //
    // The first byte is `version:3 | flags:5`, and the version has to be read
    // before the flags mean anything (peek-a-bin-eu8). Without that check any
    // `unwindInfoAddress` landing anywhere in a mapped section produced a
    // `handlerFlags` value, and one byte in four of arbitrary data has bit 0 or
    // 1 of those flags set — at which point a `handlerAddress` is read from an
    // offset computed out of the *next* byte and reported as the image's
    // exception handler. `handlerFlags` is left `undefined` rather than zeroed
    // when the version is wrong: the record says nothing about a handler, which
    // is not the same claim as "there is no handler".
    const unwindOffset = rvaToFileOffsetIndexed(unwindInfoAddress, sectionIndex);
    if (unwindOffset >= 0 && unwindOffset + 4 <= view.byteLength) {
      const versionFlags = view.getUint8(unwindOffset);
      const version = versionFlags & 0x7;
      // 1 is what every linker emits; 2 is the newer form that adds
      // UWOP_EPILOG, and its header and handler placement are unchanged.
      if (version === 1 || version === 2) {
        const flags = (versionFlags >> 3) & 0x1f;
        rf.handlerFlags = flags;

        // UNW_FLAG_EHANDLER (0x1) or UNW_FLAG_UHANDLER (0x2), and not the
        // chained form, which puts a RUNTIME_FUNCTION where the handler RVA
        // would be.
        if (flags & 0x3 && !(flags & UNW_FLAG_CHAININFO)) {
          const countOfCodes = view.getUint8(unwindOffset + 2);
          // Handler RVA follows after the unwind codes (each 2 bytes), aligned to 4 bytes
          const codesSize = countOfCodes * 2;
          const handlerOffset =
            unwindOffset + 4 + codesSize + (codesSize % 4 ? 4 - (codesSize % 4) : 0);
          if (handlerOffset + 4 <= view.byteLength) {
            rf.handlerAddress = view.getUint32(handlerOffset, true);
          }
        }
      }
    }

    results.push(rf);
  }

  return results;
}

/**
 * ARM64 RUNTIME_FUNCTION: beginAddress (u32 RVA) and one UnwindData word — 8
 * bytes, with no end address in the entry at all. The low two bits of UnwindData
 * say how to read the rest:
 *
 * - `0`: UnwindData is the RVA of a variable-length `.xdata` record, whose
 *   header word carries the function length and, optionally, a handler.
 * - `1` or `2`: the unwind data is *packed into the word itself* (2 is a
 *   fragment of a larger function), with the function length in bits 2-12
 *   counted in 4-byte words. There is no `.xdata` record and no handler.
 * - `3`: reserved. Nothing can be read out of it, so the entry is dropped.
 *
 * An entry whose extent cannot be established — reserved flag, unresolvable
 * `.xdata` RVA, unknown record version, zero length — is dropped rather than
 * guessed at, on the same principle as the x64 `begin < end` check: a
 * `RuntimeFunction` is consumed as an authoritative function boundary.
 */
function parseArm64Pdata(
  view: DataView,
  offset: number,
  size: number,
  limit: number,
  sectionIndex: SectionIndex,
): RuntimeFunction[] {
  const count = entryCountFor(offset, size, limit, ARM64_ENTRY_SIZE);
  const results: RuntimeFunction[] = [];
  // ONE budget for the whole table, not one per record — see
  // MAX_ARM64_UNWIND_CODE_BYTES for why a per-record cap cannot bound this.
  const unwindBudget: UnwindBudget = { remaining: MAX_ARM64_UNWIND_CODE_BYTES };

  for (let i = 0; i < count; i++) {
    const entryOffset = offset + i * ARM64_ENTRY_SIZE;

    const beginAddress = view.getUint32(entryOffset, true);
    const unwindData = view.getUint32(entryOffset + 4, true);
    const flag = unwindData & 0x3;

    if (flag === 0) {
      const rf = parseArm64XdataRecord(view, beginAddress, unwindData, sectionIndex, unwindBudget);
      if (rf) results.push(rf);
      continue;
    }
    if (flag === 3) continue; // reserved encoding

    // Packed: bits 2-12 hold the function length in 4-byte words.
    const functionLength = ((unwindData >>> 2) & 0x7ff) * 4;
    if (functionLength === 0) continue;
    results.push({
      beginAddress,
      endAddress: beginAddress + functionLength,
      // There is no unwind-info record to point at. Reporting the raw packed
      // word here would hand consumers an RVA that resolves somewhere real.
      unwindInfoAddress: 0,
      // The rest of the word IS the frame — see `arm64Unwind.ts`. Decoding it
      // here costs a handful of shifts on a word already read, which is why
      // this is eager where the `.xdata` walk below is a few extra byte reads.
      arm64Frame: decodePackedArm64Unwind(unwindData),
    });
  }

  return results;
}

/**
 * Read one ARM64 `.xdata` record. Header word 0 is:
 *
 * | bits  | field                                                      |
 * |-------|------------------------------------------------------------|
 * | 0-17  | function length, in 4-byte words                            |
 * | 18-19 | version (only 0 is defined)                                 |
 * | 20    | X — exception handler present                               |
 * | 21    | E — the single epilog is packed into the header             |
 * | 22-26 | epilog count, or (E=1) the first unwind code's index        |
 * | 27-31 | code words                                                  |
 *
 * A zero epilog count *and* zero code words means both were too large for
 * those fields and an extension word follows holding wider copies. The handler
 * RVA sits after the epilog scope words (absent when E=1) and the unwind code
 * words; failing to reach it costs the handler, not the function's extent.
 */
function parseArm64XdataRecord(
  view: DataView,
  beginAddress: number,
  xdataRVA: number,
  sectionIndex: SectionIndex,
  unwindBudget: UnwindBudget,
): RuntimeFunction | null {
  const recordOffset = rvaToFileOffsetIndexed(xdataRVA, sectionIndex);
  if (recordOffset < 0 || recordOffset + 4 > view.byteLength) return null;

  const header = view.getUint32(recordOffset, true);
  const version = (header >>> 18) & 0x3;
  if (version !== 0) return null;
  const functionLength = (header & 0x3ffff) * 4;
  if (functionLength === 0) return null;

  const rf: RuntimeFunction = {
    beginAddress,
    endAddress: beginAddress + functionLength,
    unwindInfoAddress: xdataRVA,
  };

  const singleEpilog = ((header >>> 21) & 0x1) === 1;
  let epilogCount = (header >>> 22) & 0x1f;
  let codeWords = (header >>> 27) & 0x1f;
  let cursor = recordOffset + 4;

  if (epilogCount === 0 && codeWords === 0) {
    if (cursor + 4 > view.byteLength) return rf;
    const extension = view.getUint32(cursor, true);
    epilogCount = extension & 0xffff;
    codeWords = (extension >>> 16) & 0xff;
    cursor += 4;
  }

  if (!singleEpilog) cursor += epilogCount * 4;

  // The unwind codes ARE the prologue, so they are the frame — see
  // `arm64Unwind.ts`. Read before the handler, because the handler RVA sits
  // after them and the cursor arithmetic is shared; a record whose codes run
  // past the buffer yields no frame rather than a truncated one.
  const codesEnd = cursor + codeWords * 4;
  // The budget gates the DECODE, never the extent: `endAddress` above is read
  // out of the header word and is what `functionDetect` treats as
  // authoritative. A record the budget refuses yields no `arm64Frame`, which is
  // already what an undecodable record yields.
  if (codesEnd <= view.byteLength && codesEnd - cursor <= unwindBudget.remaining) {
    unwindBudget.remaining -= codesEnd - cursor;
    // A `Uint8Array` window, not a `number[]` built byte by byte: the walk only
    // ever indexes and reads `.length`, so the two are interchangeable to it
    // (hence `ArrayLike<number>`), and the copy was ~1020 pushes plus an array
    // per record with a hostile table naming one record from every entry.
    const codes = new Uint8Array(view.buffer, view.byteOffset + cursor, codesEnd - cursor);
    const frame = frameFromUnwindCodes(codes);
    if (frame) rf.arm64Frame = frame;
  }

  const hasHandler = ((header >>> 20) & 0x1) === 1;
  if (!hasHandler) return rf;

  cursor = codesEnd;
  if (cursor + 4 > view.byteLength) return rf;

  rf.handlerAddress = view.getUint32(cursor, true);
  // ARM64 records a single "has a handler" bit where x64 distinguishes an
  // exception handler from an unwind handler, so this is the flag consumers
  // test for (`handlerFlags & 0x3`) and nothing finer.
  rf.handlerFlags = UNW_FLAG_EHANDLER;
  return rf;
}
