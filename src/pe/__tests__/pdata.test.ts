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
      { beginAddress: 0x1000, endAddress: 0x2000, unwindInfoAddress: 0 },
      { beginAddress: 0x2100, endAddress: 0x2128, unwindInfoAddress: 0x4000 },
    ]);
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
