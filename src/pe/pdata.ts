import { decodePackedArm64Unwind, frameFromUnwindCodes } from "./arm64Unwind";
import { IMAGE_FILE_MACHINE_ARM64 } from "./constants";
import { buildSectionIndex, rvaToFileOffsetIndexed, type SectionIndex } from "./parser";
import type { DataDirectory, RuntimeFunction, SectionHeader } from "./types";

/**
 * ARM64 variants that describe their unwind data with the ARM64 schema below:
 * plain ARM64, plus the two hybrid machine constants (ARM64EC and ARM64X),
 * whose exception directory is in ARM64 form. Neither hybrid constant is in
 * `constants.ts` because nothing else in the parser distinguishes them.
 *
 * The two hybrid constants are a deliberate **superset** and not a live case:
 * 0xA641 and 0xA64E identify object files, and a linked ARM64EC or ARM64X image
 * is marked 0x8664 or 0xAA64 instead (settled against Microsoft's docs at
 * peek-a-bin-3ucw — see `disasm/arch.ts` for the citations). Accepting them
 * costs nothing and would be right if either ever reached a `coffHeader`, so
 * they stay. What they do not do is route a real hybrid image: an ARM64EC one
 * arrives marked 0x8664 and is therefore read with the **x64** schema below.
 * Whether that is the right schema for it is *not* established here — a hybrid
 * image carries more than one view of its exception data, reached through the
 * CHPE metadata this module does not read — and there is no such binary on this
 * machine to settle it. Stated rather than assumed either way.
 */
const IMAGE_FILE_MACHINE_ARM64EC = 0xa641;
const IMAGE_FILE_MACHINE_ARM64X = 0xa64e;

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

function isArm64Machine(machine: number): boolean {
  return (
    machine === IMAGE_FILE_MACHINE_ARM64 ||
    machine === IMAGE_FILE_MACHINE_ARM64EC ||
    machine === IMAGE_FILE_MACHINE_ARM64X
  );
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
  return isArm64Machine(machine)
    ? parseArm64Pdata(view, offset, exceptionDir.size, sectionIndex)
    : parseX64Pdata(view, offset, exceptionDir.size, sectionIndex);
}

/**
 * x64 (and IA64) RUNTIME_FUNCTION: beginAddress (u32), endAddress (u32),
 * unwindInfoAddress (u32), all RVAs.
 */
function parseX64Pdata(
  view: DataView,
  offset: number,
  size: number,
  sectionIndex: SectionIndex,
): RuntimeFunction[] {
  const count = Math.floor(size / X64_ENTRY_SIZE);
  const results: RuntimeFunction[] = [];

  for (let i = 0; i < count; i++) {
    const entryOffset = offset + i * X64_ENTRY_SIZE;
    if (entryOffset + X64_ENTRY_SIZE > view.byteLength) break;

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
  sectionIndex: SectionIndex,
): RuntimeFunction[] {
  const count = Math.floor(size / ARM64_ENTRY_SIZE);
  const results: RuntimeFunction[] = [];

  for (let i = 0; i < count; i++) {
    const entryOffset = offset + i * ARM64_ENTRY_SIZE;
    if (entryOffset + ARM64_ENTRY_SIZE > view.byteLength) break;

    const beginAddress = view.getUint32(entryOffset, true);
    const unwindData = view.getUint32(entryOffset + 4, true);
    const flag = unwindData & 0x3;

    if (flag === 0) {
      const rf = parseArm64XdataRecord(view, beginAddress, unwindData, sectionIndex);
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
  if (codesEnd <= view.byteLength) {
    const codes: number[] = [];
    for (let i = cursor; i < codesEnd; i++) codes.push(view.getUint8(i));
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
