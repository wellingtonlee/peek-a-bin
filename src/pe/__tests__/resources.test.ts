/**
 * Resource directory walking, VS_VERSIONINFO parsing and .ico reconstruction.
 *
 * The resource directory is a tree whose edges are attacker-controlled offsets,
 * so the adversarial cases here are cycles, self-references, absurd entry counts
 * and the breadth blowup that the depth limit alone does not bound.
 */

import { describe, expect, it } from "vitest";
import {
  IMAGE_DIRECTORY_ENTRY_RESOURCE,
  RT_ICON,
  RT_MANIFEST,
  RT_RCDATA,
  RT_STRING,
} from "../constants";
import { parsePE, rvaToFileOffset } from "../parser";
import {
  MAX_TOTAL_ENTRIES,
  parseResourceDirectory,
  parseVersionInfo,
  reconstructIcon,
} from "../resources";
import type { ResourceNode, SectionHeader } from "../types";
import { buildMinimalPE32, buildMinimalPE64, type PEFixtureOptions } from "./fixtures";

const TIMEOUT = 5000;
const RSRC_RVA = 0x1000;

/** One .rsrc section mapping RVA 0x1000 to file offset 0. */
function rsrcSections(size: number): SectionHeader[] {
  return [
    {
      name: ".rsrc",
      virtualSize: size,
      virtualAddress: RSRC_RVA,
      sizeOfRawData: size,
      pointerToRawData: 0,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0,
    },
  ];
}

function parseRsrc(buf: ArrayBuffer) {
  return parseResourceDirectory(
    buf,
    { virtualAddress: RSRC_RVA, size: buf.byteLength },
    rsrcSections(buf.byteLength),
  );
}

/** Minimal builder for IMAGE_RESOURCE_DIRECTORY structures at fixed offsets. */
class RsrcBuilder {
  readonly buf: ArrayBuffer;
  readonly dv: DataView;

  constructor(size = 0x1000) {
    this.buf = new ArrayBuffer(size);
    this.dv = new DataView(this.buf);
  }

  /** Write a directory header at `offset` declaring `named` + `ids` entries. */
  dir(offset: number, named: number, ids: number): this {
    this.dv.setUint16(offset + 12, named, true);
    this.dv.setUint16(offset + 14, ids, true);
    return this;
  }

  /** Write entry `index` of the directory at `dirOffset`. */
  entry(
    dirOffset: number,
    index: number,
    nameOrId: number,
    target: number,
    isSubdir: boolean,
  ): this {
    const at = dirOffset + 16 + index * 8;
    this.dv.setUint32(at, nameOrId >>> 0, true);
    this.dv.setUint32(at + 4, (isSubdir ? target | 0x80000000 : target) >>> 0, true);
    return this;
  }

  /** IMAGE_RESOURCE_DATA_ENTRY. */
  data(offset: number, rva: number, size: number, codePage = 1252): this {
    this.dv.setUint32(offset, rva, true);
    this.dv.setUint32(offset + 4, size, true);
    this.dv.setUint32(offset + 8, codePage, true);
    return this;
  }

  /** Length-prefixed UTF-16LE name string. */
  nameString(offset: number, str: string): this {
    this.dv.setUint16(offset, str.length, true);
    for (let i = 0; i < str.length; i++) {
      this.dv.setUint16(offset + 2 + i * 2, str.charCodeAt(i), true);
    }
    return this;
  }
}

describe("parseResourceDirectory", () => {
  it("walks a three-level tree and flattens the leaves", () => {
    const b = new RsrcBuilder();
    // root -> type 3 (ICON) -> name 1 -> lang 1033 -> data
    b.dir(0, 0, 1).entry(0, 0, 3, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 1, 0x200, true);
    b.dir(0x200, 0, 1).entry(0x200, 0, 1033, 0x300, false);
    b.data(0x300, 0x5000, 0x40);

    const tree = parseRsrc(b.buf);
    expect(tree.root).toHaveLength(1);
    expect(tree.root[0].id).toBe(3);
    expect(tree.root[0].children?.[0].id).toBe(1);
    expect(tree.root[0].children?.[0].children?.[0].dataEntry).toEqual({
      rva: 0x5000,
      size: 0x40,
      codePage: 1252,
    });
    expect(tree.entries).toEqual([{ type: 3, name: 1, lang: 1033, rva: 0x5000, size: 0x40 }]);
    expect(tree.truncated).toBeUndefined();
  });

  it("decodes string-named entries", () => {
    const b = new RsrcBuilder();
    b.nameString(0x400, "MYDATA");
    b.dir(0, 1, 0).entry(0, 0, 0x80000000 | 0x400, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 1, 0x300, false);
    b.data(0x300, 0x5000, 8);

    const tree = parseRsrc(b.buf);
    expect(tree.root[0].id).toBe("MYDATA");
    expect(tree.entries[0].type).toBe("MYDATA");
  });

  it("returns an empty tree when the directory RVA is unmapped", () => {
    const buf = new ArrayBuffer(0x100);
    const tree = parseResourceDirectory(
      buf,
      { virtualAddress: 0x99999999, size: 0x100 },
      rsrcSections(0x100),
    );
    expect(tree).toEqual({ root: [], entries: [] });
  });

  it("ignores a leaf whose data entry runs past the end of the buffer", () => {
    const b = new RsrcBuilder(0x40);
    b.dir(0, 0, 1).entry(0, 0, 1, 0x38, false); // data entry needs 16 bytes, only 8 remain

    const tree = parseRsrc(b.buf);
    expect(tree.root).toHaveLength(1);
    expect(tree.root[0].dataEntry).toBeUndefined();
    expect(tree.entries).toEqual([]);
  });

  it("yields an empty name when the name string lies past the end", () => {
    const b = new RsrcBuilder(0x40);
    b.dir(0, 1, 0).entry(0, 0, 0x80000000 | 0x3f0, 0x20, false);
    const tree = parseRsrc(b.buf);
    expect(tree.root[0].id).toBe("");
  });

  it("keeps a NAME-identified LANGUAGE level a name instead of calling it zero", () => {
    /**
     * THE THIRD LEVEL IS IDENTIFIED BY THE SAME HIGH BIT AS THE TWO ABOVE IT,
     * and the flatten step used to answer `typeof … === "number" ? … : 0`, so a
     * named language became `lang: 0`. Nothing said so, and 0 is a REAL LANGID
     * (neutral) — the narrower answer wearing a complete one's shape, which is
     * the shape this codebase refuses everywhere else.
     *
     * `rc.exe` never writes one, so a file with a named language is the output
     * of a hand-rolled or non-Microsoft resource compiler, and precisely the
     * sort of thing a hostile sample reaches for because tools mishandle it.
     */
    const b = new RsrcBuilder();
    b.nameString(0x400, "MYLANG");
    b.dir(0, 0, 1).entry(0, 0, RT_RCDATA, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 1, 0x200, true);
    b.dir(0x200, 1, 0).entry(0x200, 0, 0x80000000 | 0x400, 0x300, false);
    b.data(0x300, 0x5000, 0x40);

    const tree = parseRsrc(b.buf);
    expect(tree.root[0].children?.[0].children?.[0].id).toBe("MYLANG");
    expect(tree.entries).toEqual([
      { type: RT_RCDATA, name: 1, lang: "MYLANG", rva: 0x5000, size: 0x40 },
    ]);
  });

  it("keeps two NAMED languages of one resource apart", () => {
    // The harm the row above describes, stated as the thing a reader sees: two
    // localisations that both answered `lang: 0` were two rows separable only by
    // RVA, in a column that claimed they were the same language.
    const b = new RsrcBuilder();
    b.nameString(0x400, "ALPHA");
    b.nameString(0x420, "BETA");
    b.dir(0, 0, 1).entry(0, 0, RT_RCDATA, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 1, 0x200, true);
    b.dir(0x200, 2, 0)
      .entry(0x200, 0, 0x80000000 | 0x400, 0x300, false)
      .entry(0x200, 1, 0x80000000 | 0x420, 0x310, false);
    b.data(0x300, 0x5000, 1);
    b.data(0x310, 0x6000, 2);

    expect(parseRsrc(b.buf).entries.map((e) => e.lang)).toEqual(["ALPHA", "BETA"]);
  });

  it("still answers 0 for a leaf that has no language level at all", () => {
    /**
     * THE OTHER DIRECTION, and the reason the fix is `?? 0` rather than a
     * sentinel. A leaf sitting SHALLOWER than the third level has no id to
     * carry, which is a different fact from "the id was a string"; both levels
     * above already spell that fallback `?? 0` and this one now agrees with
     * them.
     */
    const b = new RsrcBuilder();
    b.dir(0, 0, 1).entry(0, 0, RT_RCDATA, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 7, 0x300, false); // leaf at level 2
    b.data(0x300, 0x5000, 4);

    expect(parseRsrc(b.buf).entries).toEqual([
      { type: RT_RCDATA, name: 7, lang: 0, rva: 0x5000, size: 4 },
    ]);
  });

  describe("the entry budget's boundary", () => {
    /**
     * `truncated` USED TO BE READ OFF `remaining > 0`, which is false both when
     * the walk stopped early and when it spent its last allowed entry and
     * finished. A directory holding EXACTLY the budget therefore claimed to be
     * short over a complete answer — the wrong direction for a flag whose only
     * job is to warn a reader that what they are looking at is incomplete.
     *
     * Both sides are asserted, because a fix that simply stopped setting the
     * flag would pass the first row alone.
     */
    const rootWithEntries = (n: number): ArrayBuffer => {
      const size = 16 + n * 8 + 64;
      const buf = new ArrayBuffer(size);
      const dv = new DataView(buf);
      // One directory cannot declare more than 0xFFFF of either kind, so the
      // budget's worth needs both counts. Every entry's `Name` is left without
      // the high bit, so the walk reads them all as IDs whatever the split says
      // — it sums the two counts and decides each entry's kind for itself.
      const ids = Math.min(n, 0xffff);
      dv.setUint16(12, n - ids, true);
      dv.setUint16(14, ids, true);
      for (let i = 0; i < n; i++) {
        const at = 16 + i * 8;
        dv.setUint32(at, i, true);
        // A leaf whose data entry starts at the end of the buffer: the budget is
        // spent, nothing is flattened, and the case stays cheap.
        dv.setUint32(at + 4, size, true);
      }
      return buf;
    };

    it("does not claim truncation for exactly the budget's worth of entries", () => {
      const tree = parseRsrc(rootWithEntries(MAX_TOTAL_ENTRIES));
      expect(tree.root).toHaveLength(MAX_TOTAL_ENTRIES);
      expect(tree.truncated).toBeUndefined();
    });

    it("claims truncation one entry past the budget", () => {
      const tree = parseRsrc(rootWithEntries(MAX_TOTAL_ENTRIES + 1));
      expect(tree.root).toHaveLength(MAX_TOTAL_ENTRIES);
      expect(tree.truncated).toBe(true);
    });
  });

  describe("hostile trees", () => {
    it("terminates on a self-referential directory", { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder();
      b.dir(0, 0, 1).entry(0, 0, 1, 0, true); // points at itself

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.root[0].children).toEqual([]);
    });

    it("terminates on a two-directory cycle", { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder();
      b.dir(0, 0, 1).entry(0, 0, 1, 0x100, true);
      b.dir(0x100, 0, 1).entry(0x100, 0, 2, 0, true); // back to the root

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.root[0].children?.[0].children).toEqual([]);
    });

    it("stops at the depth limit", { timeout: TIMEOUT }, () => {
      // Six levels of directories, each a distinct offset so `visited` does not
      // short-circuit the walk before the depth limit does.
      const b = new RsrcBuilder();
      for (let level = 0; level < 6; level++) {
        const at = level * 0x100;
        b.dir(at, 0, 1).entry(at, 0, level, at + 0x100, true);
      }

      const tree = parseRsrc(b.buf);
      let node = tree.root[0];
      let depth = 1;
      while (node.children && node.children.length > 0) {
        node = node.children[0];
        depth++;
      }
      expect(depth).toBe(4); // MAX_DEPTH
    });

    it("bounds a directory that claims 131070 entries", { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder(0x400);
      b.dir(0, 0xffff, 0xffff);

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      // The buffer only holds (0x400 - 16) / 8 entries.
      expect(tree.root.length).toBeLessThanOrEqual(0x400 / 8);
    });

    it("bounds the breadth blowup that the depth limit does not", { timeout: TIMEOUT }, () => {
      // Every 16-byte window reads as a directory claiming 131070 children, and
      // the root hands each of its 65535 entries a DISTINCT subdirectory offset
      // so the `visited` set cannot collapse them. Before the entry budget this
      // shape exhausted a 4 GB heap in under a minute on a 256 KB input.
      const size = 256 * 1024;
      const buf = new ArrayBuffer(size);
      const dv = new DataView(buf);
      new Uint8Array(buf).fill(0xff);

      dv.setUint16(12, 0, true);
      dv.setUint16(14, 0xffff, true);
      for (let i = 0; i < 0xffff; i++) {
        const at = 16 + i * 8;
        if (at + 8 > size) break;
        dv.setUint32(at, i, true); // numeric id
        dv.setUint32(at + 4, (0x80000000 | (0x10000 + i * 16)) >>> 0, true);
      }

      const started = Date.now();
      const tree = parseResourceDirectory(
        buf,
        { virtualAddress: RSRC_RVA, size },
        rsrcSections(size),
      );
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.truncated).toBe(true);
    });

    it("caps an absurdly long resource name string", { timeout: TIMEOUT }, () => {
      const size = 0x40000;
      const buf = new ArrayBuffer(size);
      const dv = new DataView(buf);
      new Uint8Array(buf).fill(0x41);
      dv.setUint16(12, 0, true);
      dv.setUint16(14, 1, true);
      dv.setUint32(16, (0x80000000 | 0x1000) >>> 0, true); // name string at 0x1000
      dv.setUint32(20, 0x2000, true); // leaf
      dv.setUint16(0x1000, 0xffff, true); // claims 65535 chars

      const tree = parseResourceDirectory(
        buf,
        { virtualAddress: RSRC_RVA, size },
        rsrcSections(size),
      );
      expect(typeof tree.root[0].id).toBe("string");
      expect((tree.root[0].id as string).length).toBeLessThanOrEqual(4096);
    });
  });
});

// ── VS_VERSIONINFO ──────────────────────────────────────────────────────────

const utf16 = (s: string): Uint8Array => {
  const out = new Uint8Array((s.length + 1) * 2);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < s.length; i++) dv.setUint16(i * 2, s.charCodeAt(i), true);
  return out;
};

const pad4 = (n: number) => (n + 3) & ~3;

/** Build one VS_VERSIONINFO-style node: header, key, value, children. */
function viNode(key: string, value: Uint8Array, children: Uint8Array[], wType = 1): Uint8Array {
  const keyBytes = utf16(key);
  const headerLen = pad4(6 + keyBytes.length);
  const valueLen = pad4(value.length);
  const childBytes: Uint8Array[] = [];
  let childTotal = 0;
  for (const c of children) {
    const padded = new Uint8Array(pad4(c.length));
    padded.set(c);
    childBytes.push(padded);
    childTotal += padded.length;
  }

  const total = headerLen + valueLen + childTotal;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, total, true);
  // wValueLength counts characters for string values, bytes for binary ones;
  // the parser only compares it against 52 and tests it for non-zero.
  dv.setUint16(2, wType === 1 ? value.length / 2 : value.length, true);
  dv.setUint16(4, wType, true);
  out.set(keyBytes, 6);
  out.set(value, headerLen);
  let at = headerLen + valueLen;
  for (const c of childBytes) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

function fixedFileInfo(): Uint8Array {
  const out = new Uint8Array(52);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0xfeef04bd, true); // signature
  dv.setUint32(4, 0x00010000, true); // strucVersion
  dv.setUint32(8, 0x00060002, true); // fileVersionMS -> 6.2
  dv.setUint32(12, 0x22220001, true); // fileVersionLS -> 8738.1
  dv.setUint32(16, 0x000a0000, true); // productVersionMS -> 10.0
  dv.setUint32(20, 0x04d20000, true); // productVersionLS -> 1234.0
  return out;
}

function buildVersionInfo(strings: Record<string, string>): Uint8Array {
  const stringEntries = Object.entries(strings).map(([k, v]) => viNode(k, utf16(v), []));
  const stringTable = viNode("040904B0", new Uint8Array(0), stringEntries, 0);
  const stringFileInfo = viNode("StringFileInfo", new Uint8Array(0), [stringTable], 0);
  return viNode("VS_VERSION_INFO", fixedFileInfo(), [stringFileInfo], 0);
}

/** Place a version-info blob at RVA 0x1000 and parse it. */
function parseVI(blob: Uint8Array, sizeOverride?: number) {
  const buf = new ArrayBuffer(Math.max(blob.length + 0x100, 0x200));
  new Uint8Array(buf).set(blob);
  return parseVersionInfo(buf, RSRC_RVA, sizeOverride ?? blob.length, rsrcSections(buf.byteLength));
}

describe("parseVersionInfo", () => {
  it("extracts fixed file info and string table values", () => {
    const info = parseVI(
      buildVersionInfo({ CompanyName: "Acme Corp", FileDescription: "Test Binary" }),
    );
    expect(info.FileVersion).toBe("6.2.8738.1");
    expect(info.ProductVersion).toBe("10.0.1234.0");
    expect(info.CompanyName).toBe("Acme Corp");
    expect(info.FileDescription).toBe("Test Binary");
  });

  it("returns nothing when the key is not VS_VERSION_INFO", () => {
    const blob = buildVersionInfo({ CompanyName: "Acme" });
    // Corrupt the first character of the key.
    new DataView(blob.buffer).setUint16(6, 0x58, true);
    expect(parseVI(blob)).toEqual({});
  });

  it("returns nothing for a zero size or an unmapped RVA", () => {
    expect(parseVI(buildVersionInfo({ A: "b" }), 0)).toEqual({});
    expect(
      parseVersionInfo(new ArrayBuffer(0x200), 0x99999999, 0x100, rsrcSections(0x200)),
    ).toEqual({});
  });

  it("survives truncation at every prefix length", { timeout: 20000 }, () => {
    const full = buildVersionInfo({ CompanyName: "Acme Corp", ProductName: "Widget" });
    for (let len = 0; len <= full.length; len++) {
      expect(() => parseVI(full.subarray(0, len), len), `truncated to ${len}`).not.toThrow();
    }
  });

  it("does not loop forever on zero-length child structures", { timeout: TIMEOUT }, () => {
    const blob = buildVersionInfo({ CompanyName: "Acme" });
    // Zero every wLength field after the header: each walk must break, not spin.
    const dv = new DataView(blob.buffer);
    for (let at = 0x40; at + 2 <= blob.length; at += 2) dv.setUint16(at, 0, true);

    const started = Date.now();
    expect(() => parseVI(blob)).not.toThrow();
    expect(Date.now() - started).toBeLessThan(TIMEOUT);
  });

  it("does not spin when child lengths point backwards", { timeout: TIMEOUT }, () => {
    const blob = buildVersionInfo({ CompanyName: "Acme" });
    const dv = new DataView(blob.buffer);
    dv.setUint16(0, 0xffff, true); // outer length far beyond the blob
    for (let at = 0x40; at + 2 <= blob.length; at += 2) dv.setUint16(at, 1, true);

    const started = Date.now();
    expect(() => parseVI(blob, 0x400)).not.toThrow();
    expect(Date.now() - started).toBeLessThan(TIMEOUT);
  });

  it("caps an unterminated value string", { timeout: TIMEOUT }, () => {
    // A String entry whose value has no NUL runs to the end of the resource:
    // every remaining UTF-16 unit was collected and then spread into
    // String.fromCharCode as ~32k arguments, which is at the argument limit of
    // some engines. Hand-built because the shape cannot be produced by the
    // well-formed builder above.
    const size = 0x10000;
    const buf = new ArrayBuffer(size + 0x1000);
    const dv = new DataView(buf);
    const putKey = (at: number, key: string) => {
      for (let i = 0; i < key.length; i++) dv.setUint16(at + i * 2, key.charCodeAt(i), true);
      dv.setUint16(at + key.length * 2, 0, true);
      return pad4(at + (key.length + 1) * 2);
    };

    dv.setUint16(0, 0xffff, true); // wLength — the whole resource
    dv.setUint16(2, 52, true); // wValueLength — VS_FIXEDFILEINFO
    let at = putKey(6, "VS_VERSION_INFO"); // -> 40
    dv.setUint32(at, 0xfeef04bd, true); // fixed file info signature
    at = pad4(at + 52); // -> 92

    dv.setUint16(at, 0xff00, true); // StringFileInfo wLength
    at = putKey(at + 6, "StringFileInfo"); // -> 128

    dv.setUint16(at, 0xfe00, true); // StringTable wLength
    at = putKey(at + 6, "040904B0"); // -> 152

    dv.setUint16(at, 0xfd00, true); // String wLength
    dv.setUint16(at + 2, 1, true); // wValueLength — non-zero
    at = putKey(at + 6, "Key");

    // Value: UTF-16 'A's with no terminator, to the end of the resource.
    for (let p = at; p + 2 <= size; p += 2) dv.setUint16(p, 0x41, true);

    const info = parseVersionInfo(buf, RSRC_RVA, size, rsrcSections(buf.byteLength));
    expect(info.Key).toBeDefined();
    expect(info.Key.length).toBe(4096);
    expect(info.Key).toMatch(/^A+$/);
  });
});

// ── Icon reconstruction ─────────────────────────────────────────────────────

/** GRPICONDIR + `ids.length` GRPICONDIRENTRY records. */
function groupIcon(ids: number[], opts: { type?: number; count?: number } = {}): ArrayBuffer {
  const buf = new ArrayBuffer(6 + ids.length * 14);
  const dv = new DataView(buf);
  dv.setUint16(0, 0, true); // reserved
  dv.setUint16(2, opts.type ?? 1, true); // type = icon
  dv.setUint16(4, opts.count ?? ids.length, true);
  ids.forEach((id, i) => {
    const at = 6 + i * 14;
    dv.setUint8(at, 32); // width
    dv.setUint8(at + 1, 32); // height
    dv.setUint32(at + 8, 0x100, true); // bytesInRes
    dv.setUint16(at + 12, id, true); // nId
  });
  return buf;
}

describe("reconstructIcon", () => {
  const iconRVA = 0x2000;

  function fileWithIcons(count: number, size: number) {
    const buf = new ArrayBuffer(0x4000);
    new Uint8Array(buf).fill(0x7f, 0x2000, 0x2000 + count * size);
    return buf;
  }

  it("assembles an .ico from a group and its icon entries", () => {
    const buffer = fileWithIcons(2, 0x100);
    const entries = new Map([
      [1, { rva: iconRVA, size: 0x100 }],
      [2, { rva: iconRVA + 0x100, size: 0x100 }],
    ]);
    const ico = reconstructIcon(buffer, groupIcon([1, 2]), entries, rsrcSections(0x4000));

    expect(ico).not.toBeNull();
    const dv = new DataView(ico!.buffer);
    expect(dv.getUint16(0, true)).toBe(0); // reserved
    expect(dv.getUint16(2, true)).toBe(1); // type
    expect(dv.getUint16(4, true)).toBe(2); // image count
    // ICONDIR (6) + 2 * ICONDIRENTRY (16) = 38, then the image payloads.
    expect(dv.getUint32(6 + 12, true)).toBe(38);
    expect(dv.getUint32(6 + 16 + 12, true)).toBe(38 + 0x100);
    expect(ico!.length).toBe(38 + 0x200);
  });

  it("skips icon ids that are not present", () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);
    const ico = reconstructIcon(buffer, groupIcon([1, 99]), entries, rsrcSections(0x4000));
    expect(new DataView(ico!.buffer).getUint16(4, true)).toBe(1);
  });

  it("returns null for group data that is not an icon group", () => {
    const sections = rsrcSections(0x4000);
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);

    expect(reconstructIcon(buffer, new ArrayBuffer(4), entries, sections)).toBeNull();
    expect(reconstructIcon(buffer, groupIcon([1], { type: 2 }), entries, sections)).toBeNull();
    expect(reconstructIcon(buffer, groupIcon([], { count: 0 }), entries, sections)).toBeNull();
  });

  it("returns null when the declared count exceeds the group data", () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);
    expect(
      reconstructIcon(buffer, groupIcon([1], { count: 0xffff }), entries, rsrcSections(0x4000)),
    ).toBeNull();
  });

  it("skips entries whose icon data runs past the end of the file", () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([
      [1, { rva: iconRVA, size: 0x100 }],
      [2, { rva: iconRVA, size: 0xffffff }], // way past EOF
      [3, { rva: 0x99999999, size: 0x10 }], // unmapped
    ]);
    const ico = reconstructIcon(buffer, groupIcon([1, 2, 3]), entries, rsrcSections(0x4000));
    expect(new DataView(ico!.buffer).getUint16(4, true)).toBe(1);
  });

  it("returns null rather than throwing on random group data", () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);
    for (let seed = 0; seed < 200; seed++) {
      const data = new Uint8Array(6 + (seed % 40));
      for (let i = 0; i < data.length; i++) data[i] = (seed * 31 + i * 17) & 0xff;
      expect(() =>
        reconstructIcon(buffer, data.buffer, entries, rsrcSections(0x4000)),
      ).not.toThrow();
    }
  });
});

// ── The walk, driven out of a real PE ───────────────────────────────────────

/**
 * EVERYTHING ABOVE READS A HAND-PLACED BUFFER; THIS READS A FILE.
 *
 * `RsrcBuilder` writes directories at literal offsets into a bare `ArrayBuffer`
 * whose section maps RVA 0x1000 to file offset 0 — so the resource base, the
 * section base and the file base are all the same number and a walk that
 * confused any two of them is indistinguishable from a correct one. These cases
 * go through `parsePE`: a real section table, a real data directory, a real
 * `rvaToFileOffset`, and a `.rsrc` whose root is deliberately NOT at the start
 * of its section (`buildDirectorySection` puts sixteen bytes of 0xCC in front of
 * it — see the fixture) so the two bases differ by a number a test can name.
 *
 * The leaf's `OffsetToData` is the other half: it is an **RVA** while every
 * other offset in the block is relative to the resource base, and the only way
 * to see that being read against the wrong base is to assert the recovered
 * BYTES rather than the offset.
 */
describe("parseResourceDirectory over a built PE", () => {
  const MANIFEST = new TextEncoder().encode('<?xml version="1.0"?><assembly/>');
  const ICON_EN = new Uint8Array([0x28, 0x00, 0x00, 0x00, 0xde, 0xad]);
  const ICON_DE = new Uint8Array([0x28, 0x00, 0x00, 0x00, 0xbe, 0xef, 0x11]);
  const MOF = new Uint8Array([0x42]);
  const STR = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  const LANG_EN = 0x0409;
  const LANG_DE = 0x0407;

  /** Two ID-typed groups, one NAME-typed group, a NAME-identified resource, two languages. */
  const spec = {
    directorySectionName: ".rsrc",
    directoryRVA: 0x3000,
    directories: {
      resources: [
        {
          id: RT_ICON,
          names: [
            {
              id: 1,
              langs: [
                { lang: LANG_EN, data: ICON_EN },
                { lang: LANG_DE, data: ICON_DE, codePage: 932 },
              ],
            },
          ],
        },
        {
          id: RT_MANIFEST,
          names: [{ id: 1, langs: [{ lang: LANG_EN, data: MANIFEST, codePage: 65001 }] }],
        },
        {
          id: RT_STRING,
          names: [{ id: "STRINGSé", langs: [{ lang: 0, data: STR }] }],
        },
        { id: "MOFDATA", names: [{ id: 101, langs: [{ lang: LANG_EN, data: MOF }] }] },
      ],
    },
  } satisfies PEFixtureOptions;

  const built = () =>
    [buildMinimalPE32(spec), buildMinimalPE64(spec)].map((b) => ({ buf: b, pe: parsePE(b) }));

  it("puts the resource root somewhere other than the start of its section", () => {
    /**
     * THE LIVENESS HALF OF EVERY BASE ASSERTION BELOW. If the builder ever
     * stopped padding, resource base and section base would coincide again and
     * a walk anchored on the wrong one would pass every row in this file
     * without anybody noticing. Asserted about the FILE, not about the walk.
     */
    for (const { pe } of built()) {
      const dir = pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
      const rsrc = pe.sections.find((s) => s.name === ".rsrc");
      expect(rsrc).toBeDefined();
      expect(dir.virtualAddress).toBeGreaterThan(rsrc!.virtualAddress);
      expect(dir.size).toBeGreaterThan(0);
    }
  });

  it("recovers the three-level tree, on PE32 and PE32+ alike", () => {
    for (const { pe } of built()) {
      const tree = pe.resources;
      expect(tree).toBeDefined();
      // Named entries sort ahead of ID entries in a directory, which is the
      // order the file holds them in and therefore the order the walk returns.
      expect(tree!.root.map((n) => n.id)).toEqual(["MOFDATA", RT_ICON, RT_STRING, RT_MANIFEST]);

      const icon = tree!.root.find((n) => n.id === RT_ICON)!;
      expect(icon.children!.map((c) => c.id)).toEqual([1]);
      expect(icon.children![0].children!.map((c) => c.id)).toEqual([LANG_EN, LANG_DE]);
      // Only leaves carry a data entry; the two directory levels above carry none.
      expect(icon.dataEntry).toBeUndefined();
      expect(icon.children![0].dataEntry).toBeUndefined();
      expect(icon.children![0].children![0].dataEntry).toBeDefined();
    }
  });

  it("keeps a NAME entry a string and an ID entry a number, at both levels", () => {
    for (const { pe } of built()) {
      const entries = pe.resources!.entries;
      // A named TYPE and a named RESOURCE are different levels of the same
      // mechanism — the high bit of the entry's `Name` field — and a reader
      // that handled one and not the other would still pass a one-level test.
      expect(entries.find((e) => e.type === "MOFDATA")!.name).toBe(101);
      expect(entries.find((e) => e.type === RT_STRING)!.name).toBe("STRINGSé");
      expect(entries.filter((e) => typeof e.type === "number").length).toBe(4);
    }
  });

  it("reads a name length in CHARACTERS and the characters as UTF-16", () => {
    // `STRINGSé` is eight characters and sixteen bytes, and the last one is
    // outside ASCII: a length read as bytes truncates it to four, and a body
    // read as bytes turns it into mojibake. Both are visible in one assertion.
    for (const { pe } of built()) {
      const name = pe.resources!.entries.find((e) => e.type === RT_STRING)!.name;
      expect(name).toBe("STRINGSé");
      expect(String(name)).toHaveLength(8);
    }
  });

  it("distinguishes two languages of one resource", () => {
    for (const { pe } of built()) {
      const icons = pe.resources!.entries.filter((e) => e.type === RT_ICON);
      expect(icons.map((e) => e.lang)).toEqual([LANG_EN, LANG_DE]);
      expect(icons.map((e) => e.size)).toEqual([ICON_EN.length, ICON_DE.length]);
      // Two languages of one name are two distinct data entries at two RVAs.
      expect(icons[0].rva).not.toBe(icons[1].rva);
    }
  });

  it("carries each leaf's code page through, including ones that are not 1252", () => {
    // 0, 932 (Shift-JIS) and 65001 (UTF-8) all occur in real images; a reader
    // that hardcoded a default, or read the Reserved dword one field along,
    // would answer the same number for all three.
    for (const { pe } of built()) {
      const pages = new Map<string, number>();
      const walk = (nodes: ResourceNode[], path: (number | string)[]) => {
        for (const n of nodes ?? []) {
          if (n.dataEntry) pages.set([...path, n.id].join("/"), n.dataEntry.codePage);
          walk(n.children ?? [], [...path, n.id]);
        }
      };
      walk(pe.resources!.root, []);
      expect(Object.fromEntries(pages)).toEqual({
        [`${RT_ICON}/1/${LANG_EN}`]: 0,
        [`${RT_ICON}/1/${LANG_DE}`]: 932,
        [`${RT_MANIFEST}/1/${LANG_EN}`]: 65001,
        [`${RT_STRING}/STRINGSé/0`]: 0,
        [`MOFDATA/101/${LANG_EN}`]: 0,
      });
    }
  });

  it("names bytes the file really holds, resolving the leaf RVA as an RVA", () => {
    /**
     * THE ASSERTION THIS WHOLE FIXTURE EXISTS FOR. `OffsetToData` is an RVA;
     * every other offset in the block is relative to the resource base. Read it
     * against the resource base — the obvious mistake, since it is what the
     * three enclosing structures use — and it still resolves to somewhere
     * inside the section, so the only thing that catches it is the CONTENT.
     */
    for (const { buf, pe } of built()) {
      const want = new Map<number | string, Uint8Array>([
        [RT_MANIFEST, MANIFEST],
        [RT_STRING, STR],
        ["MOFDATA", MOF],
      ]);
      for (const [type, bytes] of want) {
        const entry = pe.resources!.entries.find((e) => e.type === type)!;
        expect(entry.size).toBe(bytes.length);
        const off = rvaToFileOffset(entry.rva, pe.sections);
        expect(off).toBeGreaterThan(0);
        expect(Array.from(new Uint8Array(buf, off, entry.size))).toEqual(Array.from(bytes));
      }
      // The two localisations differ in content, not just in RVA.
      const [en, de] = pe.resources!.entries.filter((e) => e.type === RT_ICON);
      const at = (e: { rva: number; size: number }) =>
        Array.from(new Uint8Array(buf, rvaToFileOffset(e.rva, pe.sections), e.size));
      expect(at(en)).toEqual(Array.from(ICON_EN));
      expect(at(de)).toEqual(Array.from(ICON_DE));
    }
  });

  it("carries a NAME-identified LANGUAGE level out of a real file", () => {
    /**
     * THE FIXTURE HALF, AND IT HAD TO COME FIRST. `ResourceLangDef.lang` was
     * `number`, so no builder in this repo could emit the bytes and there was
     * nothing for a walk test to fail against. It is `number | string` now and
     * the third level goes through the same named-entry path as the two above
     * it: a length-prefixed UTF-16 string elsewhere in the block, with the high
     * bit set in the entry's `Name`.
     *
     * THE LOAD-BEARING ROW IS THE THIRD LANGUAGE. A neutral LANGID of 0 sits
     * beside the two names deliberately: the defect answered `0` for ALL THREE,
     * so a case with only named languages would still be red under the fix while
     * a reader could not tell the two kinds apart. Sizes differ per leaf, so the
     * rows are provably three distinct resources and not one row read thrice.
     */
    const named = {
      directorySectionName: ".rsrc",
      directoryRVA: 0x3000,
      directories: {
        resources: [
          {
            id: RT_RCDATA,
            names: [
              {
                id: 1,
                langs: [
                  { lang: "ALPHA", data: new Uint8Array([0xa1]) },
                  { lang: "BÊTA", data: new Uint8Array([0xb2, 0xb2]) },
                  { lang: 0, data: new Uint8Array([0xc3, 0xc3, 0xc3]) },
                ],
              },
            ],
          },
        ],
      },
    } satisfies PEFixtureOptions;

    for (const build of [buildMinimalPE32, buildMinimalPE64]) {
      const buf = build(named);
      const pe = parsePE(buf);
      const leaf = pe.resources!.root[0].children![0];
      expect(leaf.children!.map((c) => c.id)).toEqual(["ALPHA", "BÊTA", 0]);
      expect(pe.resources!.entries.map((e) => e.lang)).toEqual(["ALPHA", "BÊTA", 0]);
      expect(pe.resources!.entries.map((e) => e.size)).toEqual([1, 2, 3]);
      // A named language is still a leaf like any other: its data entry's RVA
      // resolves and names the bytes the fixture put there.
      const alpha = pe.resources!.entries[0];
      const off = rvaToFileOffset(alpha.rva, pe.sections);
      expect(Array.from(new Uint8Array(buf, off, alpha.size))).toEqual([0xa1]);
    }
  });

  it("flattens every leaf exactly once and nothing else", () => {
    for (const { pe } of built()) {
      expect(pe.resources!.entries).toHaveLength(5);
      expect(pe.resources!.truncated).toBeUndefined();
    }
  });

  it("finds no resources at all when the fixture is not asked for any", () => {
    /**
     * THE CONTROL IN THE OTHER DIRECTION. Every row above would be equally
     * green against a builder that emitted nothing, if the rows were written as
     * "no wrong entry appears" instead of "these entries appear". This states
     * that the directory is opt-in and absent by default, so `pe.resources`
     * being populated above is the fixture's doing.
     */
    expect(parsePE(buildMinimalPE32({})).resources).toBeUndefined();
    expect(parsePE(buildMinimalPE64({ directories: { imports: [] } })).resources).toBeUndefined();
  });

  it("answers an empty tree for a resource directory with no entries", () => {
    // A root directory declaring zero named and zero id entries. The data
    // directory is present and non-empty, so `parsePE` really does walk — this
    // is not the "no directory" path above.
    const buf = buildMinimalPE64({
      directorySectionName: ".rsrc",
      directoryRVA: 0x3000,
      directories: { resources: [] },
    });
    const pe = parsePE(buf);
    expect(pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].size).toBeGreaterThan(0);
    expect(pe.resources).toEqual({ root: [], entries: [] });
  });

  it("returns a childless node for a resource with no languages", () => {
    // The middle level exists and the third is empty — a directory that
    // declares zero entries is not the same thing as a leaf, and conflating
    // them would invent a data entry out of whatever follows.
    const pe = parsePE(
      buildMinimalPE64({
        directorySectionName: ".rsrc",
        directoryRVA: 0x3000,
        directories: { resources: [{ id: RT_RCDATA, names: [{ id: 5, langs: [] }] }] },
      }),
    );
    expect(pe.resources!.root[0].children![0]).toEqual({ id: 5, children: [] });
    expect(pe.resources!.entries).toEqual([]);
  });

  it("still reads the tree when the leaf bytes are past the end of a truncated file", () => {
    /**
     * The shape a carved or part-downloaded sample has: the section table
     * describes the whole image, the file stops early. The directory tree and
     * the data entries are inside what survives, so the walk answers in full —
     * and every RVA it reports resolves, through the section table, to a file
     * offset that is not in the buffer. `rvaToFileOffset` never sees the buffer
     * and cannot say so; that is a fact about its CALLERS, and
     * `ResourcesView.dom.test.tsx` holds the row where one of them got it wrong.
     */
    const buf = buildMinimalPE64({
      directorySectionName: ".rsrc",
      directoryRVA: 0x3000,
      directories: {
        resources: [
          {
            id: RT_MANIFEST,
            names: [
              {
                id: 1,
                langs: [
                  { lang: LANG_EN, data: MANIFEST },
                  { lang: LANG_DE, data: MANIFEST },
                ],
              },
            ],
          },
        ],
      },
    });
    const full = parsePE(buf);
    const lastOff = Math.max(
      ...full.resources!.entries.map((e) => rvaToFileOffset(e.rva, full.sections)),
    );
    const cut = buf.slice(0, lastOff - 4);
    const pe = parsePE(cut);
    expect(pe.resources!.entries).toHaveLength(2);
    const off = rvaToFileOffset(pe.resources!.entries[1].rva, pe.sections);
    expect(off).toBeGreaterThan(cut.byteLength);
  });
});
