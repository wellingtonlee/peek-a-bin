/**
 * Resource directory walking, VS_VERSIONINFO parsing and .ico reconstruction.
 *
 * The resource directory is a tree whose edges are attacker-controlled offsets,
 * so the adversarial cases here are cycles, self-references, absurd entry counts
 * and the breadth blowup that the depth limit alone does not bound.
 */

import { describe, it, expect } from 'vitest';
import { parseResourceDirectory, parseVersionInfo, reconstructIcon } from '../resources';
import type { SectionHeader } from '../types';

const TIMEOUT = 5000;
const RSRC_RVA = 0x1000;

/** One .rsrc section mapping RVA 0x1000 to file offset 0. */
function rsrcSections(size: number): SectionHeader[] {
  return [
    {
      name: '.rsrc',
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
  return parseResourceDirectory(buf, { virtualAddress: RSRC_RVA, size: buf.byteLength }, rsrcSections(buf.byteLength));
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

describe('parseResourceDirectory', () => {
  it('walks a three-level tree and flattens the leaves', () => {
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
    expect(tree.entries).toEqual([
      { type: 3, name: 1, lang: 1033, rva: 0x5000, size: 0x40 },
    ]);
    expect(tree.truncated).toBeUndefined();
  });

  it('decodes string-named entries', () => {
    const b = new RsrcBuilder();
    b.nameString(0x400, 'MYDATA');
    b.dir(0, 1, 0).entry(0, 0, 0x80000000 | 0x400, 0x100, true);
    b.dir(0x100, 0, 1).entry(0x100, 0, 1, 0x300, false);
    b.data(0x300, 0x5000, 8);

    const tree = parseRsrc(b.buf);
    expect(tree.root[0].id).toBe('MYDATA');
    expect(tree.entries[0].type).toBe('MYDATA');
  });

  it('returns an empty tree when the directory RVA is unmapped', () => {
    const buf = new ArrayBuffer(0x100);
    const tree = parseResourceDirectory(buf, { virtualAddress: 0x99999999, size: 0x100 }, rsrcSections(0x100));
    expect(tree).toEqual({ root: [], entries: [] });
  });

  it('ignores a leaf whose data entry runs past the end of the buffer', () => {
    const b = new RsrcBuilder(0x40);
    b.dir(0, 0, 1).entry(0, 0, 1, 0x38, false); // data entry needs 16 bytes, only 8 remain

    const tree = parseRsrc(b.buf);
    expect(tree.root).toHaveLength(1);
    expect(tree.root[0].dataEntry).toBeUndefined();
    expect(tree.entries).toEqual([]);
  });

  it('yields an empty name when the name string lies past the end', () => {
    const b = new RsrcBuilder(0x40);
    b.dir(0, 1, 0).entry(0, 0, 0x80000000 | 0x3f0, 0x20, false);
    const tree = parseRsrc(b.buf);
    expect(tree.root[0].id).toBe('');
  });

  describe('hostile trees', () => {
    it('terminates on a self-referential directory', { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder();
      b.dir(0, 0, 1).entry(0, 0, 1, 0, true); // points at itself

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.root[0].children).toEqual([]);
    });

    it('terminates on a two-directory cycle', { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder();
      b.dir(0, 0, 1).entry(0, 0, 1, 0x100, true);
      b.dir(0x100, 0, 1).entry(0x100, 0, 2, 0, true); // back to the root

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.root[0].children?.[0].children).toEqual([]);
    });

    it('stops at the depth limit', { timeout: TIMEOUT }, () => {
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

    it('bounds a directory that claims 131070 entries', { timeout: TIMEOUT }, () => {
      const b = new RsrcBuilder(0x400);
      b.dir(0, 0xffff, 0xffff);

      const started = Date.now();
      const tree = parseRsrc(b.buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      // The buffer only holds (0x400 - 16) / 8 entries.
      expect(tree.root.length).toBeLessThanOrEqual(0x400 / 8);
    });

    it('bounds the breadth blowup that the depth limit does not', { timeout: TIMEOUT }, () => {
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
      const tree = parseResourceDirectory(buf, { virtualAddress: RSRC_RVA, size }, rsrcSections(size));
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(tree.truncated).toBe(true);
    });

    it('caps an absurdly long resource name string', { timeout: TIMEOUT }, () => {
      const size = 0x40000;
      const buf = new ArrayBuffer(size);
      const dv = new DataView(buf);
      new Uint8Array(buf).fill(0x41);
      dv.setUint16(12, 0, true);
      dv.setUint16(14, 1, true);
      dv.setUint32(16, (0x80000000 | 0x1000) >>> 0, true); // name string at 0x1000
      dv.setUint32(20, 0x2000, true); // leaf
      dv.setUint16(0x1000, 0xffff, true); // claims 65535 chars

      const tree = parseResourceDirectory(buf, { virtualAddress: RSRC_RVA, size }, rsrcSections(size));
      expect(typeof tree.root[0].id).toBe('string');
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
  const stringEntries = Object.entries(strings).map(([k, v]) =>
    viNode(k, utf16(v), []),
  );
  const stringTable = viNode('040904B0', new Uint8Array(0), stringEntries, 0);
  const stringFileInfo = viNode('StringFileInfo', new Uint8Array(0), [stringTable], 0);
  return viNode('VS_VERSION_INFO', fixedFileInfo(), [stringFileInfo], 0);
}

/** Place a version-info blob at RVA 0x1000 and parse it. */
function parseVI(blob: Uint8Array, sizeOverride?: number) {
  const buf = new ArrayBuffer(Math.max(blob.length + 0x100, 0x200));
  new Uint8Array(buf).set(blob);
  return parseVersionInfo(buf, RSRC_RVA, sizeOverride ?? blob.length, rsrcSections(buf.byteLength));
}

describe('parseVersionInfo', () => {
  it('extracts fixed file info and string table values', () => {
    const info = parseVI(
      buildVersionInfo({ CompanyName: 'Acme Corp', FileDescription: 'Test Binary' }),
    );
    expect(info.FileVersion).toBe('6.2.8738.1');
    expect(info.ProductVersion).toBe('10.0.1234.0');
    expect(info.CompanyName).toBe('Acme Corp');
    expect(info.FileDescription).toBe('Test Binary');
  });

  it('returns nothing when the key is not VS_VERSION_INFO', () => {
    const blob = buildVersionInfo({ CompanyName: 'Acme' });
    // Corrupt the first character of the key.
    new DataView(blob.buffer).setUint16(6, 0x58, true);
    expect(parseVI(blob)).toEqual({});
  });

  it('returns nothing for a zero size or an unmapped RVA', () => {
    expect(parseVI(buildVersionInfo({ A: 'b' }), 0)).toEqual({});
    expect(
      parseVersionInfo(new ArrayBuffer(0x200), 0x99999999, 0x100, rsrcSections(0x200)),
    ).toEqual({});
  });

  it('survives truncation at every prefix length', { timeout: 20000 }, () => {
    const full = buildVersionInfo({ CompanyName: 'Acme Corp', ProductName: 'Widget' });
    for (let len = 0; len <= full.length; len++) {
      expect(() => parseVI(full.subarray(0, len), len), `truncated to ${len}`).not.toThrow();
    }
  });

  it('does not loop forever on zero-length child structures', { timeout: TIMEOUT }, () => {
    const blob = buildVersionInfo({ CompanyName: 'Acme' });
    // Zero every wLength field after the header: each walk must break, not spin.
    const dv = new DataView(blob.buffer);
    for (let at = 0x40; at + 2 <= blob.length; at += 2) dv.setUint16(at, 0, true);

    const started = Date.now();
    expect(() => parseVI(blob)).not.toThrow();
    expect(Date.now() - started).toBeLessThan(TIMEOUT);
  });

  it('does not spin when child lengths point backwards', { timeout: TIMEOUT }, () => {
    const blob = buildVersionInfo({ CompanyName: 'Acme' });
    const dv = new DataView(blob.buffer);
    dv.setUint16(0, 0xffff, true); // outer length far beyond the blob
    for (let at = 0x40; at + 2 <= blob.length; at += 2) dv.setUint16(at, 1, true);

    const started = Date.now();
    expect(() => parseVI(blob, 0x400)).not.toThrow();
    expect(Date.now() - started).toBeLessThan(TIMEOUT);
  });

  it('caps an unterminated value string', { timeout: TIMEOUT }, () => {
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
    let at = putKey(6, 'VS_VERSION_INFO'); // -> 40
    dv.setUint32(at, 0xfeef04bd, true); // fixed file info signature
    at = pad4(at + 52); // -> 92

    dv.setUint16(at, 0xff00, true); // StringFileInfo wLength
    at = putKey(at + 6, 'StringFileInfo'); // -> 128

    dv.setUint16(at, 0xfe00, true); // StringTable wLength
    at = putKey(at + 6, '040904B0'); // -> 152

    dv.setUint16(at, 0xfd00, true); // String wLength
    dv.setUint16(at + 2, 1, true); // wValueLength — non-zero
    at = putKey(at + 6, 'Key');

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

describe('reconstructIcon', () => {
  const iconRVA = 0x2000;

  function fileWithIcons(count: number, size: number) {
    const buf = new ArrayBuffer(0x4000);
    new Uint8Array(buf).fill(0x7f, 0x2000, 0x2000 + count * size);
    return buf;
  }

  it('assembles an .ico from a group and its icon entries', () => {
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

  it('skips icon ids that are not present', () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);
    const ico = reconstructIcon(buffer, groupIcon([1, 99]), entries, rsrcSections(0x4000));
    expect(new DataView(ico!.buffer).getUint16(4, true)).toBe(1);
  });

  it('returns null for group data that is not an icon group', () => {
    const sections = rsrcSections(0x4000);
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);

    expect(reconstructIcon(buffer, new ArrayBuffer(4), entries, sections)).toBeNull();
    expect(reconstructIcon(buffer, groupIcon([1], { type: 2 }), entries, sections)).toBeNull();
    expect(reconstructIcon(buffer, groupIcon([], { count: 0 }), entries, sections)).toBeNull();
  });

  it('returns null when the declared count exceeds the group data', () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([[1, { rva: iconRVA, size: 0x100 }]]);
    expect(
      reconstructIcon(buffer, groupIcon([1], { count: 0xffff }), entries, rsrcSections(0x4000)),
    ).toBeNull();
  });

  it('skips entries whose icon data runs past the end of the file', () => {
    const buffer = fileWithIcons(1, 0x100);
    const entries = new Map([
      [1, { rva: iconRVA, size: 0x100 }],
      [2, { rva: iconRVA, size: 0xffffff }], // way past EOF
      [3, { rva: 0x99999999, size: 0x10 }], // unmapped
    ]);
    const ico = reconstructIcon(buffer, groupIcon([1, 2, 3]), entries, rsrcSections(0x4000));
    expect(new DataView(ico!.buffer).getUint16(4, true)).toBe(1);
  });

  it('returns null rather than throwing on random group data', () => {
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
