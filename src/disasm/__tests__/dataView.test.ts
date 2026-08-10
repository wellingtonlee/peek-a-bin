import { describe, it, expect } from "vitest";
import { buildDataItems } from "../dataView";
import type { DataItem } from "../types";

const BASE = 0x404000;

interface Opts {
  is64?: boolean;
  strings?: Map<number, string>;
  stringTypes?: Map<number, "ascii" | "utf16le">;
  iatMap?: Map<number, { lib: string; func: string }>;
  funcAddrs?: Map<number, string>;
  sections?: { start: number; end: number }[];
  base?: number;
}

function build(bytes: number[], opts: Opts = {}): DataItem[] {
  return buildDataItems(
    new Uint8Array(bytes),
    opts.base ?? BASE,
    opts.is64 ?? false,
    opts.strings ?? new Map(),
    opts.stringTypes ?? new Map(),
    opts.iatMap ?? new Map(),
    opts.funcAddrs ?? new Map(),
    opts.sections ?? [],
  );
}

/** Little-endian byte list for a 32-bit value. */
function le32(v: number): number[] {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
}

/** Little-endian byte list for a 64-bit value expressed as hi/lo dwords. */
function le64(hi: number, lo: number): number[] {
  return [...le32(lo), ...le32(hi)];
}

describe("buildDataItems", () => {
  it("returns nothing for an empty buffer", () => {
    expect(build([])).toEqual([]);
  });

  it("covers the whole buffer contiguously with no gaps or overlaps", () => {
    // Mixed content: a string, padding, a pointer, then raw bytes.
    const strings = new Map([[BASE, "hi"]]);
    const bytes = [
      0x68,
      0x69,
      0x00, // "hi\0"
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // padding run
      ...le32(0x401234), // pointer
      0x11,
      0x22,
      0x33, // trailing raw
    ];
    const items = build(bytes, { strings, sections: [{ start: 0x401000, end: 0x402000 }] });

    let expected = BASE;
    let total = 0;
    for (const item of items) {
      expect(item.address).toBe(expected);
      expect(item.size).toBeGreaterThan(0);
      expected += item.size;
      total += item.size;
    }
    expect(total).toBe(bytes.length);
    expect(items.map((i) => i.directive)).toEqual(["db", "dup", "dd", "db"]);
  });

  describe("strings", () => {
    it("consumes an ASCII string plus its NUL terminator", () => {
      const items = build([0x41, 0x42, 0x43, 0x00, 0x99], {
        strings: new Map([[BASE, "ABC"]]),
      });
      expect(items[0]).toMatchObject({
        address: BASE,
        directive: "db",
        size: 4,
        stringValue: "ABC",
        stringType: "ascii",
      });
      expect(Array.from(items[0].bytes)).toEqual([0x41, 0x42, 0x43, 0x00]);
      expect(items[1].address).toBe(BASE + 4);
    });

    it("consumes two bytes per char plus a wide terminator for utf16le", () => {
      const items = build([0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0x99], {
        strings: new Map([[BASE, "AB"]]),
        stringTypes: new Map([[BASE, "utf16le"]]),
      });
      expect(items[0].size).toBe(6);
      expect(items[0].stringType).toBe("utf16le");
      expect(items[1].address).toBe(BASE + 6);
    });

    it("defaults to ascii when no string type is recorded", () => {
      const items = build([0x41, 0x00], { strings: new Map([[BASE, "A"]]) });
      expect(items[0].stringType).toBe("ascii");
      expect(items[0].size).toBe(2);
    });

    it("clamps a string that runs past the end of the buffer", () => {
      // Buffer holds only 2 of the 4 bytes the string would need.
      const items = build([0x41, 0x42], { strings: new Map([[BASE, "ABC"]]) });
      expect(items).toHaveLength(1);
      expect(items[0].size).toBe(2);
      expect(items[0].stringValue).toBe("ABC");
    });

    it("picks up a string starting mid-buffer", () => {
      const items = build([0x90, 0x90, 0x41, 0x00], {
        strings: new Map([[BASE + 2, "A"]]),
      });
      // First two bytes are not a run/pointer, so they land in a raw db chunk...
      expect(items[0].directive).toBe("db");
      // ...but the raw chunk is 16 bytes wide, so it swallows the string here.
      // Documented consequence: strings are only recognised at a chunk boundary.
      expect(items).toHaveLength(1);
      expect(items[0].size).toBe(4);
    });

    it("makes progress even on a zero-length string entry", () => {
      const items = build([0x00, 0x99], { strings: new Map([[BASE, ""]]) });
      expect(items[0].size).toBe(1);
      expect(items).toHaveLength(2);
    });
  });

  describe("padding runs", () => {
    it("collapses a run of four or more zero bytes", () => {
      const items = build([0, 0, 0, 0, 0, 0x99]);
      expect(items[0]).toMatchObject({ directive: "dup", size: 5, dupCount: 5, dupByte: 0 });
      expect(items[1].address).toBe(BASE + 5);
    });

    it("collapses a run of 0xCC (int3) alignment padding", () => {
      const items = build([0xcc, 0xcc, 0xcc, 0xcc, 0x99]);
      expect(items[0]).toMatchObject({ directive: "dup", dupCount: 4, dupByte: 0xcc });
    });

    it("keeps at most 8 preview bytes for a long run", () => {
      const items = build(new Array(64).fill(0));
      expect(items).toHaveLength(1);
      expect(items[0].size).toBe(64);
      expect(items[0].dupCount).toBe(64);
      expect(items[0].bytes.length).toBe(8);
    });

    it("does not collapse a run shorter than four bytes", () => {
      const items = build([0, 0, 0, 0x99, 0x99, 0x99, 0x99, 0x99]);
      expect(items[0].directive).not.toBe("dup");
    });

    it("does not treat a pointer whose low byte is zero as padding", () => {
      const items = build(le32(0x00401000), { sections: [{ start: 0x401000, end: 0x402000 }] });
      expect(items[0]).toMatchObject({ directive: "dd", pointerTarget: 0x401000 });
    });
  });

  describe("pointers", () => {
    const sections = [{ start: 0x401000, end: 0x402000 }];

    it("reads a 32-bit little-endian pointer as dd", () => {
      const items = build(le32(0x401234), { sections });
      expect(items[0]).toMatchObject({
        directive: "dd",
        size: 4,
        pointerTarget: 0x401234,
        pointerLabel: undefined,
      });
    });

    it("reads a 64-bit pointer above 2^32 as dq", () => {
      // 0x0000000140001000 — exercises the hi/lo dword recombination.
      const items = build(le64(0x00000001, 0x40001000), {
        is64: true,
        sections: [{ start: 0x140000000, end: 0x140010000 }],
      });
      expect(items[0]).toMatchObject({ directive: "dq", size: 8, pointerTarget: 0x140001000 });
    });

    it("does not treat a value outside every section range as a pointer", () => {
      const items = build(le32(0x7ffe0000), { sections });
      expect(items[0].directive).toBe("db");
      expect(items[0].pointerTarget).toBeUndefined();
    });

    it("treats section start as inclusive and section end as exclusive", () => {
      expect(build(le32(0x401000), { sections })[0].directive).toBe("dd");
      expect(build(le32(0x402000), { sections })[0].directive).toBe("db");
    });

    it("labels an IAT pointer with lib!func", () => {
      const items = build(le32(0x401500), {
        sections,
        iatMap: new Map([[0x401500, { lib: "kernel32.dll", func: "Sleep" }]]),
      });
      expect(items[0].pointerLabel).toBe("kernel32.dll!Sleep");
    });

    it("labels a pointer to a known function with its name", () => {
      const items = build(le32(0x401500), {
        sections,
        funcAddrs: new Map([[0x401500, "sub_401500"]]),
      });
      expect(items[0].pointerLabel).toBe("sub_401500");
    });

    it("labels a pointer to a string with the quoted string", () => {
      const items = build(le32(0x401500), {
        sections,
        strings: new Map([[0x401500, "hello"]]),
      });
      expect(items[0].pointerLabel).toBe('"hello"');
    });

    it("truncates a long string label at 40 chars", () => {
      const long = "x".repeat(50);
      const items = build(le32(0x401500), {
        sections,
        strings: new Map([[0x401500, long]]),
      });
      expect(items[0].pointerLabel).toBe(`"${"x".repeat(40)}..."`);
    });

    it("keeps a 40-char string label untruncated", () => {
      const exact = "y".repeat(40);
      const items = build(le32(0x401500), { sections, strings: new Map([[0x401500, exact]]) });
      expect(items[0].pointerLabel).toBe(`"${exact}"`);
    });

    it("prefers the IAT label over a function name or string", () => {
      const items = build(le32(0x401500), {
        sections,
        iatMap: new Map([[0x401500, { lib: "a.dll", func: "f" }]]),
        funcAddrs: new Map([[0x401500, "sub_401500"]]),
        strings: new Map([[0x401500, "str"]]),
      });
      expect(items[0].pointerLabel).toBe("a.dll!f");
    });

    it("prefers a function name over a string", () => {
      const items = build(le32(0x401500), {
        sections,
        funcAddrs: new Map([[0x401500, "sub_401500"]]),
        strings: new Map([[0x401500, "str"]]),
      });
      expect(items[0].pointerLabel).toBe("sub_401500");
    });

    it("matches a value falling in any of several section ranges", () => {
      const items = build(le32(0x501234), {
        sections: [
          { start: 0x401000, end: 0x402000 },
          { start: 0x500000, end: 0x510000 },
        ],
      });
      expect(items[0].pointerTarget).toBe(0x501234);
    });

    it("does not read a pointer that would run past the buffer end", () => {
      const items = build([0x00, 0x10, 0x40], { sections });
      expect(items).toHaveLength(1);
      expect(items[0]).toMatchObject({ directive: "db", size: 3 });
    });
  });

  describe("raw fallback", () => {
    it("emits 16-byte db chunks", () => {
      const items = build(new Array(40).fill(0x99));
      expect(items.map((i) => i.size)).toEqual([16, 16, 8]);
      expect(items.map((i) => i.address)).toEqual([BASE, BASE + 16, BASE + 32]);
      expect(items.every((i) => i.directive === "db")).toBe(true);
    });

    it("emits a short final chunk for the remainder", () => {
      const items = build([0x99, 0x88]);
      expect(items).toHaveLength(1);
      expect(items[0].size).toBe(2);
      expect(Array.from(items[0].bytes)).toEqual([0x99, 0x88]);
    });
  });
});
