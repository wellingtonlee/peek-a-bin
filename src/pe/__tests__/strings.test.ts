/**
 * String extraction (`extractStrings`, and through it the ASCII and UTF-16LE
 * scanners). Runs separately from parsePE, so it is driven directly here with
 * the section table a fixture produced.
 */

import { describe, it, expect } from "vitest";
import { parsePE, extractStrings } from "../parser";
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from "./fixtures";
import {
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
} from "../constants";

const PE32_BASE = 0x00400000;
const PE64_BASE = 0x140000000;
const RDATA_RVA = 0x2000;
const DATA_RVA = 0x3000;
const TEXT_RVA = 0x1000;

/** Write an ASCII string plus its NUL terminator at `off`. */
function putAscii(buf: Uint8Array, off: number, s: string): void {
  for (let i = 0; i < s.length; i++) buf[off + i] = s.charCodeAt(i);
}

/** Write a UTF-16LE string plus its NUL terminator at `off`. */
function putUtf16(buf: Uint8Array, off: number, s: string): void {
  for (let i = 0; i < s.length; i++) buf[off + i * 2] = s.charCodeAt(i);
}

/** Offsets inside .rdata used by the fixture below. */
const OFF_HELLO = 0x00;
const OFF_SHORT = 0x20;
const OFF_WIDE = 0x40;
const OFF_TABBED = 0x60;

function rdataSection(): SectionDef {
  const data = new Uint8Array(0x100);
  putAscii(data, OFF_HELLO, "Hello, World");
  putAscii(data, OFF_SHORT, "abc"); // 3 chars — below the 4-char minimum
  putUtf16(data, OFF_WIDE, "Wide");
  putAscii(data, OFF_TABBED, "\t\tTabbed");
  return {
    name: ".rdata",
    virtualAddress: RDATA_RVA,
    virtualSize: data.length,
    data,
    characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
  };
}

function textSection(): SectionDef {
  const data = new Uint8Array(0x100);
  putAscii(data, 0x00, "short"); // 5 chars — below the 8-char .text minimum
  putAscii(data, 0x20, "LongEnoughString");
  return {
    name: ".text",
    virtualAddress: TEXT_RVA,
    virtualSize: data.length,
    data,
    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
  };
}

/** A .data section holding a pointer (at offset 8) to the given VA. */
function dataSectionWithPointer(targetVA: number, is64: boolean): SectionDef {
  const data = new Uint8Array(0x100);
  const dv = new DataView(data.buffer);
  if (is64) dv.setBigUint64(8, BigInt(targetVA), true);
  else dv.setUint32(8, targetVA, true);
  return {
    name: ".data",
    virtualAddress: DATA_RVA,
    virtualSize: data.length,
    data,
    characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
  };
}

function extract32(sections: SectionDef[]) {
  const buf = buildMinimalPE32({ sections });
  const pe = parsePE(buf);
  return extractStrings(buf, pe.sections, PE32_BASE, false);
}

describe("extractStrings — ASCII", () => {
  it("keys each string by its virtual address", () => {
    const { strings } = extract32([textSection(), rdataSection()]);
    expect(strings.get(PE32_BASE + RDATA_RVA + OFF_HELLO)).toBe("Hello, World");
  });

  it("tags ASCII strings as ascii", () => {
    const { stringTypes } = extract32([textSection(), rdataSection()]);
    expect(stringTypes.get(PE32_BASE + RDATA_RVA + OFF_HELLO)).toBe("ascii");
  });

  it("skips runs shorter than the 4-char minimum in data sections", () => {
    const { strings } = extract32([textSection(), rdataSection()]);
    expect(strings.get(PE32_BASE + RDATA_RVA + OFF_SHORT)).toBeUndefined();
    expect([...strings.values()]).not.toContain("abc");
  });

  it("ignores sections that are neither code nor a known data section", () => {
    const misc: SectionDef = {
      name: ".misc",
      virtualAddress: 0x4000,
      virtualSize: 0x100,
      data: (() => {
        const d = new Uint8Array(0x100);
        putAscii(d, 0, "NeverScanned");
        return d;
      })(),
      characteristics: IMAGE_SCN_MEM_READ,
    };
    const { strings } = extract32([textSection(), misc]);
    expect([...strings.values()]).not.toContain("NeverScanned");
  });

  it("starts the string after leading tabs but still maps their addresses to it", () => {
    // Addresses of the skipped whitespace resolve to the same string so a
    // reference to "\t\tTabbed" still shows the literal in the disassembly.
    const { strings } = extract32([textSection(), rdataSection()]);
    const stringVA = PE32_BASE + RDATA_RVA + OFF_TABBED + 2;
    expect(strings.get(stringVA)).toBe("Tabbed");
    expect(strings.get(stringVA - 1)).toBe("Tabbed");
    expect(strings.get(stringVA - 2)).toBe("Tabbed");
  });
});

describe("extractStrings — UTF-16LE", () => {
  it("decodes a UTF-16LE literal and tags it utf16le", () => {
    const { strings, stringTypes } = extract32([textSection(), rdataSection()]);
    const va = PE32_BASE + RDATA_RVA + OFF_WIDE;
    expect(strings.get(va)).toBe("Wide");
    expect(stringTypes.get(va)).toBe("utf16le");
  });

  it("does not mistake a UTF-16LE literal for a 1-char ASCII string", () => {
    const { stringTypes } = extract32([textSection(), rdataSection()]);
    expect(stringTypes.get(PE32_BASE + RDATA_RVA + OFF_WIDE)).not.toBe("ascii");
  });
});

describe("extractStrings — code sections", () => {
  it("applies a higher 8-char minimum inside .text", () => {
    const { strings } = extract32([textSection(), rdataSection()]);
    expect(strings.get(PE32_BASE + TEXT_RVA + 0x20)).toBe("LongEnoughString");
    expect(strings.get(PE32_BASE + TEXT_RVA + 0x00)).toBeUndefined();
  });
});

describe("extractStrings — pointer indirection", () => {
  it("maps a 32-bit pointer slot to the string it points at", () => {
    const targetVA = PE32_BASE + RDATA_RVA + OFF_HELLO;
    const { strings } = extract32([
      textSection(),
      rdataSection(),
      dataSectionWithPointer(targetVA, false),
    ]);
    expect(strings.get(PE32_BASE + DATA_RVA + 8)).toBe("Hello, World");
  });

  it("carries the pointed-at string type through the indirection", () => {
    const targetVA = PE32_BASE + RDATA_RVA + OFF_HELLO;
    const { stringTypes } = extract32([
      textSection(),
      rdataSection(),
      dataSectionWithPointer(targetVA, false),
    ]);
    expect(stringTypes.get(PE32_BASE + DATA_RVA + 8)).toBe("ascii");
  });

  it("reads 8-byte pointers on PE64", () => {
    const rdata = rdataSection();
    const targetVA = PE64_BASE + RDATA_RVA + OFF_HELLO;
    const sections = [textSection(), rdata, dataSectionWithPointer(targetVA, true)];
    const buf = buildMinimalPE64({ sections });
    const pe = parsePE(buf);

    const { strings } = extractStrings(buf, pe.sections, PE64_BASE, true);
    expect(strings.get(targetVA)).toBe("Hello, World");
    expect(strings.get(PE64_BASE + DATA_RVA + 8)).toBe("Hello, World");
  });

  it("ignores pointer-shaped words that do not target a known string", () => {
    const { strings } = extract32([
      textSection(),
      rdataSection(),
      dataSectionWithPointer(PE32_BASE + RDATA_RVA + 0x08, false), // mid-string, not a start
    ]);
    expect(strings.get(PE32_BASE + DATA_RVA + 8)).toBeUndefined();
  });
});
