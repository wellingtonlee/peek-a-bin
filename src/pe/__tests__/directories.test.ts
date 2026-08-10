/**
 * Data-directory parsing: imports, exports, TLS and base relocations.
 *
 * These paths were previously unexercised — every fixture emitted zero data
 * directories, so `parseImports`/`parseExports`/`parseTLSDirectory`/
 * `parseBaseRelocations` only ever ran their "nothing here" early return.
 */

import { describe, it, expect } from 'vitest';
import { parsePE } from '../parser';
import { buildMinimalPE32, buildMinimalPE64 } from './fixtures';
import {
  IMAGE_REL_BASED_ABSOLUTE,
  IMAGE_REL_BASED_HIGHLOW,
  IMAGE_REL_BASED_DIR64,
} from '../constants';

const PE32_BASE = 0x00400000;
const PE64_BASE = 0x140000000;

describe('parseImports', () => {
  it('parses libraries and their imported names (PE32)', () => {
    const buf = buildMinimalPE32({
      directories: {
        imports: [
          { libraryName: 'KERNEL32.dll', functions: [{ name: 'CreateFileW' }, { name: 'ExitProcess' }] },
          { libraryName: 'USER32.dll', functions: [{ name: 'MessageBoxA' }] },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports.map(i => i.libraryName)).toEqual(['KERNEL32.dll', 'USER32.dll']);
    expect(pe.imports[0].functions).toEqual(['CreateFileW', 'ExitProcess']);
    expect(pe.imports[1].functions).toEqual(['MessageBoxA']);
  });

  it('parses libraries and their imported names (PE64)', () => {
    const buf = buildMinimalPE64({
      directories: {
        imports: [
          { libraryName: 'ntdll.dll', functions: [{ name: 'NtCreateFile' }, { name: 'NtClose' }] },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports).toHaveLength(1);
    expect(pe.imports[0].functions).toEqual(['NtCreateFile', 'NtClose']);
  });

  it('renders imports by ordinal as Ordinal_N', () => {
    const buf = buildMinimalPE32({
      directories: {
        imports: [
          {
            libraryName: 'WS2_32.dll',
            functions: [{ ordinal: 115 }, { name: 'gethostbyname' }, { ordinal: 3 }],
          },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports[0].functions).toEqual(['Ordinal_115', 'gethostbyname', 'Ordinal_3']);
  });

  it('renders 64-bit imports by ordinal (the flag is bit 63, not bit 31)', () => {
    const buf = buildMinimalPE64({
      directories: {
        imports: [{ libraryName: 'WS2_32.dll', functions: [{ ordinal: 500 }] }],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports[0].functions).toEqual(['Ordinal_500']);
  });

  it('computes one 4-byte-strided IAT VA per import on PE32', () => {
    const buf = buildMinimalPE32({
      directories: {
        imports: [
          { libraryName: 'KERNEL32.dll', functions: [{ name: 'Sleep' }, { name: 'GetLastError' }, { name: 'ExitProcess' }] },
        ],
      },
    });

    const pe = parsePE(buf);
    const iat = pe.imports[0].iatAddresses;
    expect(iat).toHaveLength(3);
    // The first entry is the IAT's own VA; the rest follow at pointer stride.
    expect(iat[0]).toBeGreaterThan(PE32_BASE);
    expect(iat[1] - iat[0]).toBe(4);
    expect(iat[2] - iat[1]).toBe(4);
  });

  it('strides IAT VAs by 8 bytes on PE64', () => {
    const buf = buildMinimalPE64({
      directories: {
        imports: [{ libraryName: 'ntdll.dll', functions: [{ name: 'NtClose' }, { name: 'NtCreateFile' }] }],
      },
    });

    const pe = parsePE(buf);
    const iat = pe.imports[0].iatAddresses;
    expect(iat).toHaveLength(2);
    expect(iat[0]).toBeGreaterThan(PE64_BASE);
    expect(iat[1] - iat[0]).toBe(8);
  });

  it('gives each library its own IAT range', () => {
    const buf = buildMinimalPE32({
      directories: {
        imports: [
          { libraryName: 'A.dll', functions: [{ name: 'fnA' }] },
          { libraryName: 'B.dll', functions: [{ name: 'fnB' }] },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports[0].iatAddresses[0]).not.toBe(pe.imports[1].iatAddresses[0]);
  });

  it('skips the hint word when reading an imported name', () => {
    // A non-zero hint in front of the name would leak into the string if the
    // parser forgot the 2-byte skip.
    const buf = buildMinimalPE32({
      directories: {
        imports: [{ libraryName: 'KERNEL32.dll', functions: [{ name: 'Sleep', hint: 0x1234 }] }],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports[0].functions).toEqual(['Sleep']);
  });

  it('stops at the null descriptor rather than walking to EOF', () => {
    const buf = buildMinimalPE32({
      directories: { imports: [{ libraryName: 'ONLY.dll', functions: [{ name: 'f' }] }] },
    });

    const pe = parsePE(buf);
    expect(pe.imports).toHaveLength(1);
  });
});

describe('parseExports', () => {
  it('parses named exports with their addresses', () => {
    const buf = buildMinimalPE32({
      directories: {
        exports: {
          dllName: 'sample.dll',
          addresses: [0x1000, 0x1100, 0x1200],
          names: [
            { name: 'AlphaFunc', addressIndex: 0 },
            { name: 'BetaFunc', addressIndex: 1 },
            { name: 'GammaFunc', addressIndex: 2 },
          ],
        },
      },
    });

    const pe = parsePE(buf);
    expect(pe.exports.map(e => e.name)).toEqual(['AlphaFunc', 'BetaFunc', 'GammaFunc']);
    expect(pe.exports.map(e => e.address)).toEqual([0x1000, 0x1100, 0x1200]);
  });

  it('resolves each name through the ordinal table, not by position', () => {
    // The ordinal table is the indirection under test: names are sorted
    // alphabetically in a real PE while their address slots are not, so reading
    // the address table positionally would silently pair the wrong addresses.
    const buf = buildMinimalPE64({
      directories: {
        exports: {
          dllName: 'sample.dll',
          addresses: [0xaaa0, 0xbbb0, 0xccc0],
          names: [
            { name: 'PointsAtThird', addressIndex: 2 },
            { name: 'PointsAtFirst', addressIndex: 0 },
            { name: 'PointsAtSecond', addressIndex: 1 },
          ],
        },
      },
    });

    const pe = parsePE(buf);
    const byName = new Map(pe.exports.map(e => [e.name, e.address]));
    expect(byName.get('PointsAtThird')).toBe(0xccc0);
    expect(byName.get('PointsAtFirst')).toBe(0xaaa0);
    expect(byName.get('PointsAtSecond')).toBe(0xbbb0);
  });

  it('reports the ordinal-table value verbatim (the Base field is not applied)', () => {
    // NOTE: current parser behaviour. The spec ordinal is Base + index, so with
    // the conventional Base of 1 these are each one lower than what dumpbin
    // reports. See the ordinal-base finding in the review notes.
    const buf = buildMinimalPE32({
      directories: {
        exports: {
          dllName: 'sample.dll',
          ordinalBase: 1,
          addresses: [0x1000, 0x1100],
          names: [
            { name: 'First', addressIndex: 0 },
            { name: 'Second', addressIndex: 1 },
          ],
        },
      },
    });

    const pe = parsePE(buf);
    expect(pe.exports.map(e => e.ordinal)).toEqual([0, 1]);
  });

  it('returns an empty list when the export directory is present but has no names', () => {
    const buf = buildMinimalPE32({
      directories: {
        exports: { dllName: 'sample.dll', addresses: [0x1000], names: [] },
      },
    });

    const pe = parsePE(buf);
    expect(pe.exports).toEqual([]);
  });
});

describe('parseTLSDirectory', () => {
  it('is undefined when no TLS directory is present', () => {
    const pe = parsePE(buildMinimalPE32());
    expect(pe.tlsDirectory).toBeUndefined();
  });

  it('parses the PE32 TLS fields', () => {
    const buf = buildMinimalPE32({
      directories: {
        tls: {
          startAddressOfRawData: PE32_BASE + 0x3000,
          endAddressOfRawData: PE32_BASE + 0x3100,
          addressOfIndex: PE32_BASE + 0x3200,
          sizeOfZeroFill: 0x40,
          characteristics: 0x00100000,
        },
      },
    });

    const tls = parsePE(buf).tlsDirectory;
    expect(tls).toBeDefined();
    expect(tls?.startAddressOfRawData).toBe(PE32_BASE + 0x3000);
    expect(tls?.endAddressOfRawData).toBe(PE32_BASE + 0x3100);
    expect(tls?.addressOfIndex).toBe(PE32_BASE + 0x3200);
    expect(tls?.sizeOfZeroFill).toBe(0x40);
    expect(tls?.characteristics).toBe(0x00100000);
    expect(tls?.callbacks).toEqual([]);
  });

  it('walks the null-terminated callback array (PE32)', () => {
    const buf = buildMinimalPE32({
      directories: {
        tls: { callbacks: [PE32_BASE + 0x1000, PE32_BASE + 0x1010, PE32_BASE + 0x1020] },
      },
    });

    const tls = parsePE(buf).tlsDirectory;
    expect(tls?.callbacks).toEqual([PE32_BASE + 0x1000, PE32_BASE + 0x1010, PE32_BASE + 0x1020]);
    expect(tls?.addressOfCallBacks).toBeGreaterThan(PE32_BASE);
  });

  it('walks the callback array with 8-byte pointers on PE64', () => {
    // The 64-bit TLS struct is 40 bytes with 8-byte fields; reading it with the
    // 32-bit layout would put AddressOfCallBacks at the wrong offset entirely.
    const buf = buildMinimalPE64({
      directories: {
        tls: {
          startAddressOfRawData: PE64_BASE + 0x3000,
          addressOfIndex: PE64_BASE + 0x3200,
          callbacks: [PE64_BASE + 0x1000, PE64_BASE + 0x1040],
          sizeOfZeroFill: 8,
          characteristics: 0x00300000,
        },
      },
    });

    const tls = parsePE(buf).tlsDirectory;
    expect(tls?.startAddressOfRawData).toBe(PE64_BASE + 0x3000);
    expect(tls?.addressOfIndex).toBe(PE64_BASE + 0x3200);
    expect(tls?.callbacks).toEqual([PE64_BASE + 0x1000, PE64_BASE + 0x1040]);
    expect(tls?.sizeOfZeroFill).toBe(8);
    expect(tls?.characteristics).toBe(0x00300000);
  });

  it('leaves callbacks empty when AddressOfCallBacks is unmapped', () => {
    // A VA that lands outside every section: rvaToFileOffset returns -1, so the
    // walk must be skipped rather than read from a negative offset.
    const buf = buildMinimalPE32({
      directories: { tls: { addressOfCallBacks: PE32_BASE + 0x99000000 } },
    });

    const pe = parsePE(buf);
    expect(pe.tlsDirectory?.addressOfCallBacks).toBe(PE32_BASE + 0x99000000);
    expect(pe.tlsDirectory?.callbacks).toEqual([]);
  });
});

describe('parseBaseRelocations', () => {
  it('is undefined when no relocation directory is present', () => {
    expect(parsePE(buildMinimalPE32()).relocations).toBeUndefined();
  });

  it('decodes type and offset out of each 16-bit entry', () => {
    const buf = buildMinimalPE32({
      directories: {
        relocations: [
          {
            virtualAddress: 0x1000,
            entries: [
              { type: IMAGE_REL_BASED_HIGHLOW, offset: 0x004 },
              { type: IMAGE_REL_BASED_HIGHLOW, offset: 0x123 },
              { type: IMAGE_REL_BASED_ABSOLUTE, offset: 0x000 },
            ],
          },
        ],
      },
    });

    const relocs = parsePE(buf).relocations;
    expect(relocs).toHaveLength(1);
    expect(relocs?.[0].virtualAddress).toBe(0x1000);
    expect(relocs?.[0].entries).toEqual([
      { type: IMAGE_REL_BASED_HIGHLOW, offset: 0x004 },
      { type: IMAGE_REL_BASED_HIGHLOW, offset: 0x123 },
      { type: IMAGE_REL_BASED_ABSOLUTE, offset: 0x000 },
    ]);
  });

  it('walks multiple blocks using each block SizeOfBlock', () => {
    // Blocks are variable-length and chained by SizeOfBlock; a fixed stride
    // would resynchronize onto garbage after the first block.
    const buf = buildMinimalPE64({
      directories: {
        relocations: [
          { virtualAddress: 0x1000, entries: [{ type: IMAGE_REL_BASED_DIR64, offset: 0x10 }] },
          {
            virtualAddress: 0x2000,
            entries: [
              { type: IMAGE_REL_BASED_DIR64, offset: 0x20 },
              { type: IMAGE_REL_BASED_DIR64, offset: 0x28 },
              { type: IMAGE_REL_BASED_ABSOLUTE, offset: 0 },
            ],
          },
          { virtualAddress: 0x3000, entries: [{ type: IMAGE_REL_BASED_DIR64, offset: 0x8 }] },
        ],
      },
    });

    const relocs = parsePE(buf).relocations;
    expect(relocs?.map(b => b.virtualAddress)).toEqual([0x1000, 0x2000, 0x3000]);
    expect(relocs?.map(b => b.entries.length)).toEqual([1, 3, 1]);
    expect(relocs?.[1].entries[1]).toEqual({ type: IMAGE_REL_BASED_DIR64, offset: 0x28 });
  });

  it('masks the offset to 12 bits and the type to 4', () => {
    const buf = buildMinimalPE32({
      directories: {
        relocations: [{ virtualAddress: 0x4000, entries: [{ type: 0xf, offset: 0xfff }] }],
      },
    });

    const relocs = parsePE(buf).relocations;
    expect(relocs?.[0].entries[0]).toEqual({ type: 0xf, offset: 0xfff });
  });
});

describe('all four directories together', () => {
  it('parses imports, exports, TLS and relocations from one image', () => {
    const buf = buildMinimalPE64({
      directories: {
        imports: [{ libraryName: 'KERNEL32.dll', functions: [{ name: 'Sleep' }, { ordinal: 42 }] }],
        exports: {
          dllName: 'combined.dll',
          addresses: [0x1000, 0x1200],
          names: [{ name: 'Start', addressIndex: 0 }, { name: 'Stop', addressIndex: 1 }],
        },
        tls: { callbacks: [PE64_BASE + 0x1000] },
        relocations: [
          { virtualAddress: 0x1000, entries: [{ type: IMAGE_REL_BASED_DIR64, offset: 0x18 }] },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.imports[0].functions).toEqual(['Sleep', 'Ordinal_42']);
    expect(pe.exports.map(e => e.name)).toEqual(['Start', 'Stop']);
    expect(pe.tlsDirectory?.callbacks).toEqual([PE64_BASE + 0x1000]);
    expect(pe.relocations?.[0].entries).toEqual([{ type: IMAGE_REL_BASED_DIR64, offset: 0x18 }]);
  });
});
