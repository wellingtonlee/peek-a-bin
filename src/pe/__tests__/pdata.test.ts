import { describe, it, expect } from 'vitest';
import { parsePdata } from '../pdata';
import type { DataDirectory, SectionHeader } from '../types';

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
      name: '.pdata',
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

describe('parsePdata', () => {
  it('parses entries with correct begin/end/unwind addresses', () => {
    const { buffer, sections, dir } = buildPdataBuffer([
      { begin: 0x1000, end: 0x1050, unwind: 0x4000 },
      { begin: 0x1050, end: 0x1100, unwind: 0x4010 },
    ]);

    const results = parsePdata(buffer, dir, sections);
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

  it('filters out entries where beginAddress >= endAddress', () => {
    const { buffer, sections, dir } = buildPdataBuffer([
      { begin: 0x1000, end: 0x1050, unwind: 0x4000 },
      { begin: 0x2000, end: 0x2000, unwind: 0x4010 }, // begin == end
      { begin: 0x3000, end: 0x2000, unwind: 0x4020 }, // begin > end
      { begin: 0x1050, end: 0x1100, unwind: 0x4030 },
    ]);

    const results = parsePdata(buffer, dir, sections);
    expect(results).toHaveLength(2);
    expect(results[0].beginAddress).toBe(0x1000);
    expect(results[1].beginAddress).toBe(0x1050);
  });

  it('returns empty array for zero virtualAddress', () => {
    const dir: DataDirectory = { virtualAddress: 0, size: 0 };
    const results = parsePdata(new ArrayBuffer(64), dir, []);
    expect(results).toEqual([]);
  });

  it('returns empty array for zero size', () => {
    const dir: DataDirectory = { virtualAddress: 0x3000, size: 0 };
    const results = parsePdata(new ArrayBuffer(64), dir, []);
    expect(results).toEqual([]);
  });

  it('returns empty array when rvaToFileOffset cannot resolve the directory', () => {
    const dir: DataDirectory = { virtualAddress: 0x9000, size: 24 };
    // No sections that contain 0x9000
    const sections: SectionHeader[] = [
      {
        name: '.text',
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
    const results = parsePdata(new ArrayBuffer(1024), dir, sections);
    expect(results).toEqual([]);
  });
});
