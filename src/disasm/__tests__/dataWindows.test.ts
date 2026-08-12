/**
 * peek-a-bin-g17 — the readable-data spans an x64 jump table needs, and the
 * flat wire format they cross the worker boundary in.
 *
 * Two properties matter here and neither is visible at a call site:
 *
 *  * **what is selected.** A window that is missing costs a whole switch
 *    statement; a window that is pure payload (`.rsrc` is routinely the largest
 *    section in a GUI binary) costs a copy on every load.
 *  * **that the bytes stay views.** `buildDataWindows` runs on the main thread
 *    with the file buffer live, so it must not duplicate the image, and the
 *    packed form must not smuggle a whole-file view across the wire.
 */

import { describe, it, expect } from "vitest";
import {
  buildDataWindows,
  packDataWindows,
  unpackDataWindows,
  type DataWindow,
} from "../dataWindows";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import type { SectionHeader } from "../../pe/types";

const IMAGE_BASE = 0x140000000;

const CODE = 0x60000020; // CNT_CODE | MEM_EXECUTE | MEM_READ
const RDATA = 0x40000040; // CNT_INITIALIZED_DATA | MEM_READ
const DATA = 0xc0000040; // + MEM_WRITE
const RELOC = 0x42000040; // + MEM_DISCARDABLE

/** A PE with one 0x100-byte section per entry, each filled with its own byte. */
function imageOf(defs: { name: string; characteristics: number; fill: number }[]) {
  const buffer = buildMinimalPE64({
    imageBase: IMAGE_BASE,
    addressOfEntryPoint: 0x1000,
    sections: defs.map((d, i) => ({
      name: d.name,
      virtualAddress: 0x1000 * (i + 1),
      virtualSize: 0x100,
      data: new Uint8Array(0x100).fill(d.fill),
      characteristics: d.characteristics,
    })),
  });
  return { buffer, sections: parsePE(buffer).sections };
}

const named = (windows: DataWindow[]) => windows.map((w) => `0x${w.base.toString(16)}`);

describe("buildDataWindows — which sections are worth sending", () => {
  it("takes .rdata, where x64 compilers put their jump tables", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".rdata", characteristics: RDATA, fill: 0x11 },
    ]);

    const windows = buildDataWindows(buffer, sections, IMAGE_BASE);

    expect(named(windows)).toEqual(["0x140002000"]);
    expect(windows[0].bytes[0]).toBe(0x11);
    expect(windows[0].bytes.length).toBe(0x100);
  });

  it("leaves the code section out — it is already the disassembly window", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".rdata", characteristics: RDATA, fill: 0x11 },
    ]);

    expect(buildDataWindows(buffer, sections, IMAGE_BASE)).toHaveLength(1);
  });

  it("keeps writable .data as well", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".data", characteristics: DATA, fill: 0x22 },
    ]);

    expect(named(buildDataWindows(buffer, sections, IMAGE_BASE))).toEqual(["0x140002000"]);
  });

  it("drops .rsrc, which is icons and manifests and often the biggest section", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".rsrc", characteristics: RDATA, fill: 0x33 },
    ]);

    expect(buildDataWindows(buffer, sections, IMAGE_BASE)).toEqual([]);
  });

  it("drops discardable sections such as .reloc", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".reloc", characteristics: RELOC, fill: 0x44 },
    ]);

    expect(buildDataWindows(buffer, sections, IMAGE_BASE)).toEqual([]);
  });

  it("keys each window by its virtual address, not its file offset", () => {
    // The detector resolves a table address the code computed; a window keyed
    // by file offset would read the right bytes from the wrong place, or
    // nothing at all.
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".rdata", characteristics: RDATA, fill: 0x11 },
      { name: ".data", characteristics: DATA, fill: 0x22 },
    ]);

    expect(named(buildDataWindows(buffer, sections, IMAGE_BASE))).toEqual([
      "0x140002000",
      "0x140003000",
    ]);
  });

  it("hands back views onto the file, not copies of it", () => {
    const { buffer, sections } = imageOf([
      { name: ".text", characteristics: CODE, fill: 0xcc },
      { name: ".rdata", characteristics: RDATA, fill: 0x11 },
    ]);

    const [window] = buildDataWindows(buffer, sections, IMAGE_BASE);

    expect(window.bytes.buffer).toBe(buffer);
  });
});

describe("buildDataWindows — a malformed section table must not throw", () => {
  /** Section headers with no backing image, as a hostile file can produce. */
  const header = (over: Partial<SectionHeader>): SectionHeader =>
    ({
      name: ".rdata",
      virtualSize: 0x100,
      virtualAddress: 0x2000,
      sizeOfRawData: 0x100,
      pointerToRawData: 0x400,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: RDATA,
      ...over,
    }) as SectionHeader;

  it("clamps a section whose raw size runs past the end of the file", () => {
    const buffer = new ArrayBuffer(0x500);

    const [window] = buildDataWindows(buffer, [header({ sizeOfRawData: 0x10000 })], IMAGE_BASE);

    expect(window.bytes.length).toBe(0x100);
  });

  it("skips a section whose file pointer is past the end of the file", () => {
    const buffer = new ArrayBuffer(0x500);

    expect(buildDataWindows(buffer, [header({ pointerToRawData: 0x9000 })], IMAGE_BASE)).toEqual(
      [],
    );
  });

  it("skips a section with no raw data at all", () => {
    const buffer = new ArrayBuffer(0x500);

    expect(buildDataWindows(buffer, [header({ pointerToRawData: 0 })], IMAGE_BASE)).toEqual([]);
    expect(buildDataWindows(buffer, [header({ sizeOfRawData: 0 })], IMAGE_BASE)).toEqual([]);
  });
});

describe("packDataWindows / unpackDataWindows — the wire format", () => {
  /** Two windows carved out of one 4 KiB "file", as a real caller's are. */
  function windows() {
    const file = new ArrayBuffer(4096);
    new Uint8Array(file, 1024, 64).fill(0x11);
    new Uint8Array(file, 2048, 32).fill(0x22);
    return {
      file,
      windows: [
        { base: 0x140002000, bytes: new Uint8Array(file, 1024, 64) },
        { base: 0x140003000, bytes: new Uint8Array(file, 2048, 32) },
      ],
    };
  }

  it("packs into a buffer holding the windows and nothing else", () => {
    // The whole point: not 4096 bytes, and not 4096 twice.
    const packed = packDataWindows(windows().windows)!;

    expect(packed.dataBytes.length).toBe(96);
    expect(packed.dataBytes.buffer.byteLength).toBe(96);
  });

  it("records where each window landed", () => {
    const packed = packDataWindows(windows().windows)!;

    expect(packed.dataSpans).toEqual([
      { base: 0x140002000, offset: 0, length: 64 },
      { base: 0x140003000, offset: 64, length: 32 },
    ]);
  });

  it("round-trips base and bytes", () => {
    const packed = packDataWindows(windows().windows)!;

    const restored = unpackDataWindows(packed.dataBytes, packed.dataSpans)!;

    expect(restored.map((w) => w.base)).toEqual([0x140002000, 0x140003000]);
    expect(restored[0].bytes.length).toBe(64);
    expect(Array.from(restored[0].bytes.slice(0, 2))).toEqual([0x11, 0x11]);
    expect(Array.from(restored[1].bytes.slice(0, 2))).toEqual([0x22, 0x22]);
  });

  it("restores views into the received buffer rather than copying again", () => {
    const packed = packDataWindows(windows().windows)!;

    const restored = unpackDataWindows(packed.dataBytes, packed.dataSpans)!;

    expect(restored[0].bytes.buffer).toBe(packed.dataBytes.buffer);
  });

  it("packs nothing for an empty or absent window list", () => {
    expect(packDataWindows([])).toBeUndefined();
    expect(packDataWindows(undefined)).toBeUndefined();
    expect(packDataWindows([{ base: 0x1000, bytes: new Uint8Array(0) }])).toBeUndefined();
  });

  it("unpacks nothing when either half is missing", () => {
    expect(unpackDataWindows(undefined, [{ base: 1, offset: 0, length: 1 }])).toBeUndefined();
    expect(unpackDataWindows(new Uint8Array(4), undefined)).toBeUndefined();
    expect(unpackDataWindows(new Uint8Array(4), [])).toBeUndefined();
  });

  it("drops a span that does not fit the bytes it arrived with", () => {
    // Not a hypothetical: the args object is data from another thread, and a
    // span read past the buffer would report a jump table built out of
    // whatever `subarray` clamped to.
    const bytes = new Uint8Array(8).fill(0x5a);

    expect(unpackDataWindows(bytes, [{ base: 0x1000, offset: 4, length: 16 }])).toBeUndefined();
    expect(unpackDataWindows(bytes, [{ base: 0x1000, offset: -4, length: 4 }])).toBeUndefined();
    expect(unpackDataWindows(bytes, [{ base: 0x1000, offset: 0, length: 0 }])).toBeUndefined();
  });

  it("keeps the good spans when one is bad", () => {
    const bytes = new Uint8Array(8).fill(0x5a);

    const restored = unpackDataWindows(bytes, [
      { base: 0x1000, offset: 0, length: 4 },
      { base: 0x2000, offset: 0, length: 64 },
    ])!;

    expect(restored.map((w) => w.base)).toEqual([0x1000]);
  });
});
