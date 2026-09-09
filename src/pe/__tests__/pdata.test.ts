import { describe, expect, it } from "vitest";
import {
  IMAGE_DIRECTORY_ENTRY_EXCEPTION,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_READ,
} from "../constants";
import { parsePE } from "../parser";
import { parsePdata } from "../pdata";
import type { DataDirectory, SectionHeader } from "../types";
import { buildMinimalPE64 } from "./fixtures";

/**
 * Helper: build an ArrayBuffer containing pdata entries at a given file offset,
 * and matching section headers so rvaToFileOffset can resolve them.
 */
function buildPdataBuffer(
  entries: Array<{ begin: number; end: number; unwind: number }>,
  sectionVA: number = 0x3000,
  fileOffset: number = 0x600,
): { buffer: ArrayBuffer; sections: SectionHeader[]; dir: DataDirectory } {
  const entrySize = 12;
  const dataSize = entries.length * entrySize;
  const bufferSize = fileOffset + dataSize + 64; // some padding
  const buffer = new ArrayBuffer(bufferSize);
  const view = new DataView(buffer);

  // Write pdata entries at fileOffset
  for (let i = 0; i < entries.length; i++) {
    const off = fileOffset + i * entrySize;
    view.setUint32(off, entries[i].begin, true);
    view.setUint32(off + 4, entries[i].end, true);
    view.setUint32(off + 8, entries[i].unwind, true);
  }

  const sections: SectionHeader[] = [
    {
      name: ".pdata",
      virtualSize: dataSize,
      virtualAddress: sectionVA,
      sizeOfRawData: dataSize + 64,
      pointerToRawData: fileOffset,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0x40000040, // INITIALIZED_DATA | READ
    },
  ];

  const dir: DataDirectory = {
    virtualAddress: sectionVA,
    size: dataSize,
  };

  return { buffer, sections, dir };
}

describe("parsePdata", () => {
  it("parses entries with correct begin/end/unwind addresses", () => {
    const { buffer, sections, dir } = buildPdataBuffer([
      { begin: 0x1000, end: 0x1050, unwind: 0x4000 },
      { begin: 0x1050, end: 0x1100, unwind: 0x4010 },
    ]);

    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_AMD64);
    expect(results).toHaveLength(2);
    expect(results[0]).toEqual({
      beginAddress: 0x1000,
      endAddress: 0x1050,
      unwindInfoAddress: 0x4000,
    });
    expect(results[1]).toEqual({
      beginAddress: 0x1050,
      endAddress: 0x1100,
      unwindInfoAddress: 0x4010,
    });
  });

  it("filters out entries where beginAddress >= endAddress", () => {
    const { buffer, sections, dir } = buildPdataBuffer([
      { begin: 0x1000, end: 0x1050, unwind: 0x4000 },
      { begin: 0x2000, end: 0x2000, unwind: 0x4010 }, // begin == end
      { begin: 0x3000, end: 0x2000, unwind: 0x4020 }, // begin > end
      { begin: 0x1050, end: 0x1100, unwind: 0x4030 },
    ]);

    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_AMD64);
    expect(results).toHaveLength(2);
    expect(results[0].beginAddress).toBe(0x1000);
    expect(results[1].beginAddress).toBe(0x1050);
  });

  it("returns empty array for zero virtualAddress", () => {
    const dir: DataDirectory = { virtualAddress: 0, size: 0 };
    const results = parsePdata(new ArrayBuffer(64), dir, [], IMAGE_FILE_MACHINE_AMD64);
    expect(results).toEqual([]);
  });

  it("returns empty array for zero size", () => {
    const dir: DataDirectory = { virtualAddress: 0x3000, size: 0 };
    const results = parsePdata(new ArrayBuffer(64), dir, [], IMAGE_FILE_MACHINE_AMD64);
    expect(results).toEqual([]);
  });

  it("returns empty array when rvaToFileOffset cannot resolve the directory", () => {
    const dir: DataDirectory = { virtualAddress: 0x9000, size: 24 };
    // No sections that contain 0x9000
    const sections: SectionHeader[] = [
      {
        name: ".text",
        virtualSize: 0x1000,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x200,
        pointerToRawData: 0x200,
        pointerToRelocations: 0,
        pointerToLinenumbers: 0,
        numberOfRelocations: 0,
        numberOfLinenumbers: 0,
        characteristics: 0,
      },
    ];
    const results = parsePdata(new ArrayBuffer(1024), dir, sections, IMAGE_FILE_MACHINE_AMD64);
    expect(results).toEqual([]);
  });
});

/**
 * x64 `.pdata` plus a second section holding UNWIND_INFO records, so that an
 * `unwindInfoAddress` can be made to resolve. `buildPdataBuffer`'s unwind RVAs
 * deliberately point at nothing, which is why nothing above reaches the
 * UNWIND_INFO decode at all.
 *
 * `unwind` maps an RVA in the `.xdata` section to raw bytes placed there.
 */
function buildX64UnwindBuffer(
  entries: Array<{ begin: number; end: number; unwind: number }>,
  unwind: Record<number, number[]> = {},
): { buffer: ArrayBuffer; sections: SectionHeader[]; dir: DataDirectory } {
  const pdataVA = 0x3000;
  const pdataOffset = 0x600;
  const xdataVA = 0x4000;
  const xdataOffset = 0x800;
  const xdataSize = 0x200;
  const dataSize = entries.length * 12;
  const buffer = new ArrayBuffer(xdataOffset + xdataSize);
  const view = new DataView(buffer);

  entries.forEach((e, i) => {
    const off = pdataOffset + i * 12;
    view.setUint32(off, e.begin, true);
    view.setUint32(off + 4, e.end, true);
    view.setUint32(off + 8, e.unwind, true);
  });
  for (const [rva, bytes] of Object.entries(unwind)) {
    const base = xdataOffset + (Number(rva) - xdataVA);
    bytes.forEach((b, i) => {
      if (base + i < buffer.byteLength) view.setUint8(base + i, b);
    });
  }

  const section = (name: string, va: number, raw: number, size: number): SectionHeader => ({
    name,
    virtualSize: size,
    virtualAddress: va,
    sizeOfRawData: size,
    pointerToRawData: raw,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics: 0x40000040,
  });

  return {
    buffer,
    sections: [
      section(".pdata", pdataVA, pdataOffset, 0x200),
      section(".xdata", xdataVA, xdataOffset, xdataSize),
    ],
    dir: { virtualAddress: pdataVA, size: dataSize },
  };
}

/** UNWIND_INFO byte 0: `version:3 | flags:5`. */
const versionFlags = (version: number, flags: number) => ((flags & 0x1f) << 3) | (version & 0x7);

/**
 * peek-a-bin-eu8. UNWIND_INFO's first byte is a version *and* a flags field, and
 * the flags mean nothing until the version has been checked. Every record below
 * is one an `unwindInfoAddress` can land on in a real image without the file
 * ever having meant it as unwind data.
 */
describe("parsePdata — x64 UNWIND_INFO version", () => {
  const UNW_FLAG_EHANDLER = 0x1;
  const UNW_FLAG_CHAININFO = 0x4;

  /** A record with EHANDLER set, one unwind code, handler RVA 0x5000. */
  const handlerRecord = (version: number) => [
    versionFlags(version, UNW_FLAG_EHANDLER),
    0x04, // size of prolog
    0x01, // count of codes
    0x00, // frame register/offset
    0x00,
    0x00, // one unwind code (2 bytes)
    0x00,
    0x00, // pad to 4-byte alignment
    0x00,
    0x50,
    0x00,
    0x00, // handler RVA 0x5000
  ];

  const parse = (unwindBytes: number[]) => {
    const { buffer, sections, dir } = buildX64UnwindBuffer(
      [{ begin: 0x1000, end: 0x1050, unwind: 0x4000 }],
      { 0x4000: unwindBytes },
    );
    return parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_AMD64);
  };

  it("decodes the handler of a version-1 record", () => {
    const [rf] = parse(handlerRecord(1));
    expect(rf.handlerFlags).toBe(UNW_FLAG_EHANDLER);
    expect(rf.handlerAddress).toBe(0x5000);
  });

  it("decodes the handler of a version-2 record", () => {
    const [rf] = parse(handlerRecord(2));
    expect(rf.handlerFlags).toBe(UNW_FLAG_EHANDLER);
    expect(rf.handlerAddress).toBe(0x5000);
  });

  it("reports no flags and no handler when the version is 0", () => {
    const [rf] = parse(handlerRecord(0));
    expect(rf.handlerFlags).toBeUndefined();
    expect(rf.handlerAddress).toBeUndefined();
  });

  it("reports no flags and no handler for versions 3 through 7", () => {
    for (const v of [3, 4, 5, 6, 7]) {
      const [rf] = parse(handlerRecord(v));
      expect(rf.handlerFlags, `version ${v}`).toBeUndefined();
      expect(rf.handlerAddress, `version ${v}`).toBeUndefined();
    }
  });

  it("keeps begin and end when the version is rejected", () => {
    const [rf] = parse(handlerRecord(0));
    expect(rf).toEqual({
      beginAddress: 0x1000,
      endAddress: 0x1050,
      unwindInfoAddress: 0x4000,
    });
  });

  it("reads no handler out of an ASCII string an unwind RVA happens to land on", () => {
    // "Program" — 'P' is 0x50: version 0, flags 0b01010. Under the old reading
    // that is UNW_FLAG_UHANDLER, count-of-codes 0x6f ('o'), and a handler RVA
    // read 226 bytes further into the string.
    const text = "ProgramFiles\\Common\\".repeat(12);
    const [rf] = parse([...text].map((c) => c.charCodeAt(0)));
    expect(rf.handlerFlags).toBeUndefined();
    expect(rf.handlerAddress).toBeUndefined();
  });

  it("reads no handler from a chained-info record, whose handler slot is a RUNTIME_FUNCTION", () => {
    // flags = CHAININFO | EHANDLER: malformed, since the chained
    // RUNTIME_FUNCTION occupies the bytes a handler RVA would.
    const rec = handlerRecord(1);
    rec[0] = versionFlags(1, UNW_FLAG_CHAININFO | UNW_FLAG_EHANDLER);
    const [rf] = parse(rec);
    expect(rf.handlerFlags).toBe(0x5);
    expect(rf.handlerAddress).toBeUndefined();
  });

  it("still reports flags with no handler bits for an ordinary version-1 record", () => {
    const rec = handlerRecord(1);
    rec[0] = versionFlags(1, 0);
    const [rf] = parse(rec);
    expect(rf.handlerFlags).toBe(0);
    expect(rf.handlerAddress).toBeUndefined();
  });
});

/**
 * ARM64 `.pdata` fixture. An ARM64 RUNTIME_FUNCTION is **8** bytes — an RVA and
 * one `UnwindData` word — not the 12-byte x64 triple, and the function's extent
 * lives in the unwind data rather than in the entry. `xdata` places raw words at
 * chosen RVAs in a second section so full (non-packed) records can be pointed at.
 */
function buildArm64PdataBuffer(
  entries: Array<{ begin: number; unwind: number }>,
  xdata: Record<number, number[]> = {},
  opts: { totalSize?: number } = {},
): { buffer: ArrayBuffer; sections: SectionHeader[]; dir: DataDirectory } {
  const pdataVA = 0x3000;
  const pdataOffset = 0x600;
  const xdataVA = 0x4000;
  const xdataOffset = 0x800;
  const xdataSize = 0x400;
  const dataSize = entries.length * 8;
  const buffer = new ArrayBuffer(opts.totalSize ?? xdataOffset + xdataSize);
  const view = new DataView(buffer);

  for (let i = 0; i < entries.length; i++) {
    const off = pdataOffset + i * 8;
    if (off + 8 > buffer.byteLength) break;
    view.setUint32(off, entries[i].begin, true);
    view.setUint32(off + 4, entries[i].unwind, true);
  }
  for (const [rva, words] of Object.entries(xdata)) {
    const base = xdataOffset + (Number(rva) - xdataVA);
    words.forEach((w, i) => {
      if (base + i * 4 + 4 <= buffer.byteLength) view.setUint32(base + i * 4, w, true);
    });
  }

  const section = (name: string, va: number, raw: number, size: number): SectionHeader => ({
    name,
    virtualSize: size,
    virtualAddress: va,
    sizeOfRawData: size,
    pointerToRawData: raw,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics: 0x40000040,
  });

  return {
    buffer,
    sections: [
      section(".pdata", pdataVA, pdataOffset, 0x200),
      section(".xdata", xdataVA, xdataOffset, xdataSize),
    ],
    dir: { virtualAddress: pdataVA, size: dataSize },
  };
}

/** `.xdata` header word 0, per the ARM64 exception-data layout. */
function xdataHeader(o: {
  lengthWords: number;
  version?: number;
  hasHandler?: boolean;
  singleEpilog?: boolean;
  epilogCount?: number;
  codeWords?: number;
}): number {
  return (
    ((o.lengthWords & 0x3ffff) |
      ((o.version ?? 0) << 18) |
      ((o.hasHandler ? 1 : 0) << 20) |
      ((o.singleEpilog ? 1 : 0) << 21) |
      ((o.epilogCount ?? 0) << 22) |
      ((o.codeWords ?? 0) << 27)) >>>
    0
  );
}

/** Packed unwind word: flag in bits 0-1, function length (words) in bits 2-12. */
const packed = (lengthWords: number, flag = 1) => (flag | (lengthWords << 2)) >>> 0;

/**
 * peek-a-bin-c71x. `parsePdata` used to route `IMAGE_FILE_MACHINE_ARM64EC`
 * (0xA641) and `IMAGE_FILE_MACHINE_ARM64X` (0xA64E) to the ARM64 schema as a
 * "deliberate superset", on the reasoning that it would be right if either ever
 * reached a `coffHeader`. Neither reaches a linked image (peek-a-bin-3ucw), and
 * the 0xA641 half of the reasoning is refuted besides: an ARM64EC image's
 * exception directory holds the **x64** table, and its A64 functions are in the
 * CHPE `ExtraRFETable` instead. See `pdata.ts` for the citations.
 *
 * A documentation claim pinned as a test, because no hybrid binary exists here
 * and no corpus gate has a population for it. The fixture is deliberately a
 * *well-formed x64 table*, so the assertion shows what the withdrawn arm would
 * have done rather than merely that it is gone: at an 8-byte stride these 24
 * bytes read as one packed entry claiming a 0x1054-byte function at 0x1000 —
 * fiction, and longer than the whole table describes — plus two entries whose
 * `.xdata` RVA resolves nowhere and which are dropped.
 */
describe("parsePdata — hybrid machine constants", () => {
  const x64Table = [
    { begin: 0x1000, end: 0x1055, unwind: 0x4000 },
    { begin: 0x1060, end: 0x10b9, unwind: 0x4010 },
  ];

  it.each([
    ["ARM64EC object marker (0xA641)", 0xa641],
    ["ARM64X (0xA64E)", 0xa64e],
  ])("reads an x64 table as x64 under %s, not at the ARM64 stride", (_label, machine) => {
    const { buffer, sections, dir } = buildPdataBuffer(x64Table);
    const results = parsePdata(buffer, dir, sections, machine);

    expect(results.map((r) => [r.beginAddress, r.endAddress])).toEqual([
      [0x1000, 0x1055],
      [0x1060, 0x10b9],
    ]);
    // The withdrawn arm's answer, spelled out so a reinstatement fails here.
    expect(results).not.toContainEqual(
      expect.objectContaining({ beginAddress: 0x1000, endAddress: 0x2054 }),
    );
  });

  it("still routes the word an ARM64 image actually carries to the ARM64 schema", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([
      { begin: 0x1000, unwind: packed(4) },
      { begin: 0x1010, unwind: packed(8) },
    ]);
    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(results.map((r) => r.beginAddress)).toEqual([0x1000, 0x1010]);
  });
});

describe("parsePdata — ARM64", () => {
  it("reads entries at the ARM64 8-byte stride, not the x64 12-byte one", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([
      { begin: 0x1000, unwind: packed(4) },
      { begin: 0x1010, unwind: packed(8) },
      { begin: 0x1030, unwind: packed(2) },
    ]);
    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(results.map((r) => r.beginAddress)).toEqual([0x1000, 0x1010, 0x1030]);
  });

  it("derives the end address from packed unwind data", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: packed(6) }]);
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.endAddress).toBe(0x1000 + 6 * 4);
  });

  it("reports no unwind-info RVA and no handler for packed unwind data", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: packed(6) }]);
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.unwindInfoAddress).toBe(0);
    expect(rf.handlerAddress).toBeUndefined();
    expect(rf.handlerFlags).toBeUndefined();
  });

  it("accepts a packed fragment (flag 2)", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([
      { begin: 0x1000, unwind: packed(3, 2) },
    ]);
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.endAddress).toBe(0x1000 + 12);
  });

  it("skips the reserved flag value 3", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([
      { begin: 0x1000, unwind: packed(3, 3) },
      { begin: 0x1100, unwind: packed(3) },
    ]);
    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(results.map((r) => r.beginAddress)).toEqual([0x1100]);
  });

  it("derives the end address from a full .xdata record", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [xdataHeader({ lengthWords: 9, codeWords: 1 }), 0],
    });
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf).toMatchObject({
      beginAddress: 0x1000,
      endAddress: 0x1000 + 9 * 4,
      unwindInfoAddress: 0x4000,
    });
    expect(rf.handlerAddress).toBeUndefined();
  });

  it("decodes the exception handler RVA past the epilog scopes and unwind codes", () => {
    const header = xdataHeader({
      lengthWords: 8,
      hasHandler: true,
      epilogCount: 2,
      codeWords: 3,
    });
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [header, 0xee00, 0xee01, 0xc0de0, 0xc0de1, 0xc0de2, 0x5000],
    });
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.handlerAddress).toBe(0x5000);
    expect(rf.handlerFlags).toBe(1);
  });

  it("skips the epilog scope words when the single-epilog bit is set", () => {
    const header = xdataHeader({
      lengthWords: 8,
      hasHandler: true,
      singleEpilog: true,
      epilogCount: 2, // an epilog start index in this form, not a count
      codeWords: 3,
    });
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [header, 0xc0de0, 0xc0de1, 0xc0de2, 0x6000, 0xbad],
    });
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.handlerAddress).toBe(0x6000);
  });

  it("reads the extension word when both code words and epilog count are zero", () => {
    const header = xdataHeader({ lengthWords: 4, hasHandler: true });
    const ext = (1 | (2 << 16)) >>> 0; // 1 epilog scope, 2 code words
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [header, ext, 0xee00, 0xc0de0, 0xc0de1, 0x7000],
    });
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.endAddress).toBe(0x1010);
    expect(rf.handlerAddress).toBe(0x7000);
  });

  it("ignores an .xdata record with an unknown version", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [xdataHeader({ lengthWords: 9, version: 1, codeWords: 1 })],
    });
    expect(parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64)).toEqual([]);
  });

  it("ignores an .xdata record whose function length is zero", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [xdataHeader({ lengthWords: 0, codeWords: 1 })],
    });
    expect(parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64)).toEqual([]);
  });

  it("drops an entry whose .xdata RVA resolves to no section", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer([
      { begin: 0x1000, unwind: 0x9000 },
      { begin: 0x1100, unwind: packed(3) },
    ]);
    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(results.map((r) => r.beginAddress)).toEqual([0x1100]);
  });

  it("keeps the range when the handler word runs past the end of the file", () => {
    const header = xdataHeader({ lengthWords: 8, hasHandler: true });
    // An extension word claiming 65535 epilog scopes puts the handler word
    // hundreds of kilobytes past a 3 KiB file.
    const ext = (0xffff | (4 << 16)) >>> 0;
    const { buffer, sections, dir } = buildArm64PdataBuffer([{ begin: 0x1000, unwind: 0x4000 }], {
      0x4000: [header, ext],
    });
    const [rf] = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(rf.endAddress).toBe(0x1020);
    expect(rf.handlerAddress).toBeUndefined();
  });

  it("stops at the end of a truncated file instead of reading past it", () => {
    const { buffer, sections, dir } = buildArm64PdataBuffer(
      [
        { begin: 0x1000, unwind: packed(3) },
        { begin: 0x1100, unwind: packed(3) },
      ],
      {},
      { totalSize: 0x608 },
    );
    const results = parsePdata(buffer, dir, sections, IMAGE_FILE_MACHINE_ARM64);
    expect(results.map((r) => r.beginAddress)).toEqual([0x1000]);
  });
});

describe("parsePE — .pdata schema follows the machine type", () => {
  /**
   * One 16-byte `.pdata` blob, deliberately legible under both schemas: two
   * ARM64 entries (a packed one and a full one), or a single x64
   * RUNTIME_FUNCTION whose begin/end pass the begin < end check. Which reading
   * comes back is then evidence about the machine gate rather than about how
   * the bytes happen to fall.
   */
  function pdataSections() {
    const pdata = new Uint8Array(16);
    const pv = new DataView(pdata.buffer);
    pv.setUint32(0, 0x1000, true);
    pv.setUint32(4, packed(1024), true); // 0x1001 as an x64 end address
    pv.setUint32(8, 0x2100, true);
    pv.setUint32(12, 0x4000, true); // full record in .xdata
    const xdata = new Uint8Array(16);
    new DataView(xdata.buffer).setUint32(0, xdataHeader({ lengthWords: 10, codeWords: 1 }), true);
    const chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    return [
      {
        name: ".text",
        virtualAddress: 0x1000,
        virtualSize: 0x100,
        data: new Uint8Array([0xc3]),
        characteristics: 0x60000020,
      },
      {
        name: ".pdata",
        virtualAddress: 0x3000,
        virtualSize: pdata.length,
        data: pdata,
        characteristics: chars,
      },
      {
        name: ".xdata",
        virtualAddress: 0x4000,
        virtualSize: xdata.length,
        data: xdata,
        characteristics: chars,
      },
    ];
  }

  const dirs = new Map([[IMAGE_DIRECTORY_ENTRY_EXCEPTION, { virtualAddress: 0x3000, size: 16 }]]);

  it("decodes an ARM64 image with the ARM64 schema", () => {
    const buffer = buildMinimalPE64({
      machine: IMAGE_FILE_MACHINE_ARM64,
      sections: pdataSections(),
      dataDirectories: dirs,
    });
    const pe = parsePE(buffer);
    expect(pe.runtimeFunctions).toEqual([
      {
        beginAddress: 0x1000,
        endAddress: 0x2000,
        unwindInfoAddress: 0,
        // Both entries now carry the frame the record describes
        // (`peek-a-bin-hof0`). This fixture's packed word has `CR` 0 and
        // `FrameSize` 0, so the honest answer is "no frame pointer, nothing
        // allocated" — asserted here rather than admitted with a looser matcher,
        // because a whole-object `toEqual` is what caught the field being added
        // at all and that is worth keeping.
        arm64Frame: {
          frameDelta: null,
          frameSize: 0,
          savedIntRegs: 0,
          savedFpRegs: 0,
          homesParams: false,
          source: "packed",
        },
      },
      {
        beginAddress: 0x2100,
        endAddress: 0x2128,
        unwindInfoAddress: 0x4000,
        // The `.xdata` record's one code word is zero bytes, i.e. four
        // `alloc_s #0` codes: no allocation and no `set_fp`.
        arm64Frame: {
          frameDelta: null,
          frameSize: 0,
          savedIntRegs: 0,
          savedFpRegs: 0,
          homesParams: false,
          source: "xdata",
        },
      },
    ]);
  });

  it("leaves an x64 record with NO arm64Frame — the field is ARM64's alone", () => {
    // x64's `UNWIND_INFO` is a different structure and nothing here has ever
    // needed a frame out of it, so `undefined` means "not this schema's
    // business" rather than "no frame".
    const buffer = buildMinimalPE64({
      machine: IMAGE_FILE_MACHINE_AMD64,
      sections: pdataSections(),
      dataDirectories: dirs,
    });
    expect(parsePE(buffer).runtimeFunctions?.[0].arm64Frame).toBeUndefined();
  });

  it("still decodes an x64 image with the x64 schema", () => {
    const buffer = buildMinimalPE64({
      machine: IMAGE_FILE_MACHINE_AMD64,
      sections: pdataSections(),
      dataDirectories: dirs,
    });
    const pe = parsePE(buffer);
    expect(pe.runtimeFunctions).toEqual([
      { beginAddress: 0x1000, endAddress: 0x1001, unwindInfoAddress: 0x2100 },
    ]);
  });
});

/**
 * The x64 `__C_specific_handler` scope table — the language-specific data that
 * follows the handler RVA. `peek-a-bin-j4uk.4`.
 *
 * The fixture places three sections in a buffer much LARGER than the `.xdata`
 * section, so that the extent test can be shown to be bounded by the SECTION
 * rather than by the end of the file: `.xdata` runs to file offset 0x900 while
 * the buffer runs to 0x2000. `.text` exists so that a handler RVA can be made
 * to resolve, which check (4) requires of anything above 1.
 *
 * The guarded function is `[0x1000, 0x1100)` throughout, so a region's
 * containment can be reasoned about by reading the literals.
 */
describe("parsePdata — x64 scope table", () => {
  const FN_BEGIN = 0x1000;
  const FN_END = 0x1100;
  const XDATA_VA = 0x4000;
  const XDATA_OFFSET = 0x800;
  /** One past the last byte of `.xdata`'s raw data — the operative bound. */
  const XDATA_LIMIT = 0x900;
  const BUFFER_SIZE = 0x2000;
  const UNW_FLAG_EHANDLER = 0x1;
  const UNW_FLAG_UHANDLER = 0x2;

  /**
   * One handler-bearing `.pdata` record over `[0x1000, 0x1100)`, with `lsd`
   * written as raw `uint32` words where the language-specific data goes.
   *
   * `countOfCodes` is 0, so the handler RVA lands at `unwindOffset + 4` and the
   * language-specific data at `unwindOffset + 8`.
   */
  function build(lsd: number[], flags = UNW_FLAG_EHANDLER) {
    const buffer = new ArrayBuffer(BUFFER_SIZE);
    const view = new DataView(buffer);

    // .pdata: one 12-byte RUNTIME_FUNCTION.
    view.setUint32(0x600, FN_BEGIN, true);
    view.setUint32(0x604, FN_END, true);
    view.setUint32(0x608, XDATA_VA, true);

    // .xdata: UNWIND_INFO, handler RVA, then the language-specific data.
    view.setUint8(XDATA_OFFSET, versionFlags(1, flags));
    view.setUint8(XDATA_OFFSET + 1, 0x04); // size of prolog
    view.setUint8(XDATA_OFFSET + 2, 0x00); // count of codes
    view.setUint8(XDATA_OFFSET + 3, 0x00);
    view.setUint32(XDATA_OFFSET + 4, 0x1080, true); // handler RVA
    lsd.forEach((w, i) => {
      const at = XDATA_OFFSET + 8 + i * 4;
      if (at + 4 <= BUFFER_SIZE) view.setUint32(at, w, true);
    });

    const section = (name: string, va: number, raw: number, size: number): SectionHeader => ({
      name,
      virtualSize: size,
      virtualAddress: va,
      sizeOfRawData: size,
      pointerToRawData: raw,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0x40000040,
    });

    return parsePdata(
      buffer,
      { virtualAddress: 0x3000, size: 12 },
      [
        section(".text", FN_BEGIN, 0x400, 0x200),
        section(".pdata", 0x3000, 0x600, 0x100),
        section(".xdata", XDATA_VA, XDATA_OFFSET, XDATA_LIMIT - XDATA_OFFSET),
      ],
      IMAGE_FILE_MACHINE_AMD64,
    );
  }

  /**
   * A well-formed language-specific data block: the `Count` word derived from
   * the regions that follow it, each region a `[begin, end, handler,
   * jumpTarget]` tuple. Tests that need a `Count` DISAGREEING with what follows
   * — which is the whole `__GSHandlerCheck` case — pass a raw word array
   * instead.
   */
  const lsd = (...regions: Array<[number, number, number, number]>) => [
    regions.length,
    ...regions.flat(),
  ];

  /** Two well-formed `__finally` regions. */
  const twoRegions = lsd([0x1010, 0x1020, 0x1080, 0], [0x1030, 0x1040, 0x1090, 0]);

  it("reads a valid two-region table", () => {
    const [rf] = build(twoRegions);
    expect(rf.scopeTable).toEqual([
      { begin: 0x1010, end: 0x1020, handler: 0x1080, jumpTarget: 0 },
      { begin: 0x1030, end: 0x1040, handler: 0x1090, jumpTarget: 0 },
    ]);
    // The record's own fields are untouched by the new read.
    expect(rf.beginAddress).toBe(FN_BEGIN);
    expect(rf.endAddress).toBe(FN_END);
    expect(rf.handlerAddress).toBe(0x1080);
  });

  it("round-trips handler == 1, the format's spelling of EXCEPTION_EXECUTE_HANDLER", () => {
    // Not an RVA, and deliberately not resolved as one: check (4) exempts 0 and
    // 1 explicitly, so a `__except (EXCEPTION_EXECUTE_HANDLER)` with no filter
    // funclet is admitted rather than refused for naming an unmapped address.
    const [rf] = build(lsd([0x1010, 0x1020, 1, 0x1050]));
    expect(rf.scopeTable).toEqual([{ begin: 0x1010, end: 0x1020, handler: 1, jumpTarget: 0x1050 }]);
  });

  it("round-trips a __finally, whose jumpTarget is 0 and whose handler is the funclet", () => {
    const [rf] = build(lsd([0x1010, 0x1020, 0x1080, 0]));
    expect(rf.scopeTable?.[0]).toEqual({
      begin: 0x1010,
      end: 0x1020,
      handler: 0x1080,
      jumpTarget: 0,
    });
  });

  /**
   * `Count` = `n` over `n` regions that are each INDIVIDUALLY VALID — ascending,
   * inside the function, with a resolvable handler and a zero jump target — so
   * that checks (2), (3) and (4) all pass and the extent test is the only thing
   * that can refuse the table.
   *
   * That isolation is the point, and it was arrived at by a control coming back
   * inert: with filler entries of `0x1010` the degenerate-region test caught the
   * overrun too, so removing the extent test moved nothing and the test proved
   * only that *something* refused. `.xdata` holds 0x100 bytes and the data
   * begins 8 bytes in, so 15 entries fit and 16 do not; the buffer has 0x2000
   * and would supply either.
   */
  const validRegions = (n: number) =>
    lsd(
      ...Array.from(
        { length: n },
        (_, i) => [0x1000 + i * 4, 0x1002 + i * 4, 0x1080, 0] as [number, number, number, number],
      ),
    );

  it("withholds a table whose Count * 16 overruns the containing SECTION", () => {
    // This is the part of check (1) that refuses a `__GSHandlerCheck` cookie
    // offset read as a count, and the census at 0870e14 shows it doing exactly
    // that for 12 of t64's 20 refusals (counts of 1072, 1504, 1936, 2096, 2784).
    // 4 + 16 * 16 = 260 bytes against `.xdata`'s remaining 248.
    expect(build(validRegions(16))[0].scopeTable).toBeUndefined();
    // Liveness in two directions: one fewer entry fits and IS read, so the
    // refusal is the extent rather than the fixture or the entries.
    expect(build(validRegions(15))[0].scopeTable).toHaveLength(15);
  });

  it("withholds a table whose Count is 0", () => {
    // An empty table is not a thing the compiler emits, and admitting one would
    // publish `[]` — the "there are no regions" claim the field must never make.
    const [rf] = build([0, 0x1010, 0x1020, 0x1080, 0x0000]);
    expect(rf.scopeTable).toBeUndefined();
  });

  it("withholds a table with a region outside the function", () => {
    expect(build(lsd([0x0f00, 0x1020, 0x1080, 0]))[0].scopeTable).toBeUndefined();
    expect(build(lsd([0x1010, 0x1200, 0x1080, 0]))[0].scopeTable).toBeUndefined();
  });

  it("withholds a table with a degenerate region", () => {
    expect(build(lsd([0x1020, 0x1020, 0x1080, 0]))[0].scopeTable).toBeUndefined();
    expect(build(lsd([0x1040, 0x1020, 0x1080, 0]))[0].scopeTable).toBeUndefined();
  });

  it("withholds a table whose begins are not in address order", () => {
    // Both regions are individually valid and inside the function; only their
    // ORDER is wrong, so nothing but check (3) can refuse this.
    const [rf] = build(lsd([0x1030, 0x1040, 0x1080, 0], [0x1010, 0x1020, 0x1090, 0]));
    expect(rf.scopeTable).toBeUndefined();
  });

  it("admits two regions sharing a begin — non-decreasing, not strictly increasing", () => {
    // Nested `__try` blocks starting at the same address are ordinary output, so
    // check (3) must not be a strict comparison.
    const [rf] = build(lsd([0x1010, 0x1020, 0x1080, 0], [0x1010, 0x1040, 0x1090, 0]));
    expect(rf.scopeTable).toHaveLength(2);
  });

  it("withholds a table whose handler resolves to no section", () => {
    const [rf] = build(lsd([0x1010, 0x1020, 0x99999999, 0]));
    expect(rf.scopeTable).toBeUndefined();
  });

  it("withholds a table whose jumpTarget is outside the function", () => {
    const [rf] = build(lsd([0x1010, 0x1020, 0x1080, 0x1200]));
    expect(rf.scopeTable).toBeUndefined();
  });

  it("withholds a __GSHandlerCheck-shaped LSD — one u32 cookie offset", () => {
    // THE CASE THE CHECK EXISTS FOR. `__GSHandlerCheck`'s language-specific data
    // is a single `uint32` frame offset of the stack cookie, followed by
    // whatever the linker packed next. Read as a `Count` it claims a table of
    // that many 16-byte records.
    //
    // A SMALL cookie offset (0x30 = 48 entries, which is what t64 actually
    // carries at six sites) fits inside `.xdata` here, so check (1) passes it
    // and the region test is what refuses it — measured, that is exactly how the
    // corpus splits: 12 refusals by extent, 6 by region, 2 by order.
    const small = build([0x30, 0x00000000, 0x00000000, 0x00000000, 0x00000000]);
    expect(small[0].scopeTable).toBeUndefined();
    // A LARGE one (a cookie offset like t64's 2096) cannot fit and is refused by
    // check (1) before any entry is read.
    const large = build([2096]);
    expect(large[0].scopeTable).toBeUndefined();
  });

  it("withholds a table for a __CxxFrameHandler3-shaped LSD — one FuncInfo RVA", () => {
    // A `FuncInfo` RVA read as a count claims hundreds of thousands of entries.
    const [rf] = build([0x00004010]);
    expect(rf.scopeTable).toBeUndefined();
  });

  it("reads a table off a UHANDLER record as well as an EHANDLER one", () => {
    // Both flags share one handler RVA and one language-specific-data slot, so
    // the schema question is the same for either.
    const [rf] = build(twoRegions, UNW_FLAG_UHANDLER);
    expect(rf.scopeTable).toHaveLength(2);
  });

  it("leaves scopeTable undefined for a record with no handler at all", () => {
    // `undefined` MEANS "THE RECORD DID NOT SAY". There is no handler here, so
    // there is no language-specific data to read — which is not the claim that
    // the function guards nothing.
    const [rf] = build(twoRegions, 0);
    expect(rf.handlerAddress).toBeUndefined();
    expect(rf.scopeTable).toBeUndefined();
  });

  it("withholds a table when the language-specific data is past the section", () => {
    // The Count word itself does not fit: `.xdata` is 0x100 bytes and the record
    // is placed so the LSD begins past its end.
    const buffer = new ArrayBuffer(BUFFER_SIZE);
    const view = new DataView(buffer);
    view.setUint32(0x600, FN_BEGIN, true);
    view.setUint32(0x604, FN_END, true);
    view.setUint32(0x608, XDATA_VA + 0xf8, true);
    const at = XDATA_OFFSET + 0xf8;
    view.setUint8(at, versionFlags(1, UNW_FLAG_EHANDLER));
    view.setUint32(at + 4, 0x1080, true);
    view.setUint32(at + 8, 2, true); // a Count, past `.xdata`'s 0x900 limit

    const section = (name: string, va: number, raw: number, size: number): SectionHeader => ({
      name,
      virtualSize: size,
      virtualAddress: va,
      sizeOfRawData: size,
      pointerToRawData: raw,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0x40000040,
    });
    const [rf] = parsePdata(
      buffer,
      { virtualAddress: 0x3000, size: 12 },
      [
        section(".text", FN_BEGIN, 0x400, 0x200),
        section(".pdata", 0x3000, 0x600, 0x100),
        section(".xdata", XDATA_VA, XDATA_OFFSET, XDATA_LIMIT - XDATA_OFFSET),
      ],
      IMAGE_FILE_MACHINE_AMD64,
    );
    // The handler is still read — it is inside the buffer — but the table is not.
    expect(rf.scopeTable).toBeUndefined();
  });

  it("withholds a table but keeps the record when the check fails", () => {
    // A refusal costs the scope table and nothing else: the extent
    // `functionDetect` treats as authoritative is unaffected.
    const [rf] = build([2096]);
    expect(rf).toEqual({
      beginAddress: FN_BEGIN,
      endAddress: FN_END,
      unwindInfoAddress: XDATA_VA,
      handlerFlags: UNW_FLAG_EHANDLER,
      handlerAddress: 0x1080,
    });
  });
});
