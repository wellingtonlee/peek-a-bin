import { describe, it, expect } from 'vitest';
import { parsePE, rvaToFileOffset } from '../parser';
import { buildMinimalPE32, buildMinimalPE64 } from './fixtures';
import {
  IMAGE_FILE_MACHINE_I386,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_CNT_CODE,
} from '../constants';
import type { SectionHeader } from '../types';

describe('parsePE', () => {
  it('returns is64=false for PE32', () => {
    const buf = buildMinimalPE32();
    const pe = parsePE(buf);
    expect(pe.is64).toBe(false);
  });

  it('returns is64=true for PE64', () => {
    const buf = buildMinimalPE64();
    const pe = parsePE(buf);
    expect(pe.is64).toBe(true);
  });

  it('throws on bad DOS magic', () => {
    const buf = buildMinimalPE32();
    const view = new DataView(buf);
    view.setUint16(0, 0xFFFF, true); // corrupt DOS magic
    expect(() => parsePE(buf)).toThrow('Invalid DOS signature');
  });

  it('throws on bad PE signature', () => {
    const buf = buildMinimalPE32();
    const view = new DataView(buf);
    // PE signature is at e_lfanew offset (64)
    view.setUint32(64, 0xDEADBEEF, true);
    expect(() => parsePE(buf)).toThrow('Invalid PE signature');
  });

  it('parses COFF machine field correctly for PE32 (i386)', () => {
    const buf = buildMinimalPE32({ machine: IMAGE_FILE_MACHINE_I386 });
    const pe = parsePE(buf);
    expect(pe.coffHeader.machine).toBe(IMAGE_FILE_MACHINE_I386);
  });

  it('parses COFF machine field correctly for PE64 (AMD64)', () => {
    const buf = buildMinimalPE64({ machine: IMAGE_FILE_MACHINE_AMD64 });
    const pe = parsePE(buf);
    expect(pe.coffHeader.machine).toBe(IMAGE_FILE_MACHINE_AMD64);
  });

  it('parses numberOfSections correctly', () => {
    const sections = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 4,
        data: new Uint8Array([0xCC, 0xCC, 0xCC, 0xCC]),
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
      },
      {
        name: '.data',
        virtualAddress: 0x2000,
        virtualSize: 4,
        data: new Uint8Array([0x00, 0x00, 0x00, 0x00]),
        characteristics: IMAGE_SCN_MEM_READ,
      },
    ];
    const buf = buildMinimalPE32({ sections });
    const pe = parsePE(buf);
    expect(pe.coffHeader.numberOfSections).toBe(2);
    expect(pe.sections).toHaveLength(2);
  });

  it('parses COFF characteristics correctly', () => {
    const buf = buildMinimalPE32({ characteristics: 0x0102 });
    const pe = parsePE(buf);
    expect(pe.coffHeader.characteristics).toBe(0x0102);
  });

  it('parses imageBase correctly for PE32', () => {
    const buf = buildMinimalPE32({ imageBase: 0x10000000 });
    const pe = parsePE(buf);
    expect(pe.optionalHeader.imageBase).toBe(0x10000000);
  });

  it('parses imageBase correctly for PE64', () => {
    const buf = buildMinimalPE64({ imageBase: 0x140000000 });
    const pe = parsePE(buf);
    expect(pe.optionalHeader.imageBase).toBe(0x140000000);
  });

  it('parses section names correctly', () => {
    const sections = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 4,
        data: new Uint8Array([0xCC, 0xCC, 0xCC, 0xCC]),
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
      },
      {
        name: '.rdata',
        virtualAddress: 0x2000,
        virtualSize: 8,
        data: new Uint8Array(8),
        characteristics: IMAGE_SCN_MEM_READ,
      },
    ];
    const buf = buildMinimalPE64({ sections });
    const pe = parsePE(buf);
    expect(pe.sections[0].name).toBe('.text');
    expect(pe.sections[1].name).toBe('.rdata');
  });

  it('parses section virtualAddress and virtualSize correctly', () => {
    const sections = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 0x500,
        data: new Uint8Array(0x200),
        characteristics: IMAGE_SCN_CNT_CODE,
      },
    ];
    const buf = buildMinimalPE32({ sections });
    const pe = parsePE(buf);
    expect(pe.sections[0].virtualAddress).toBe(0x1000);
    expect(pe.sections[0].virtualSize).toBe(0x500);
  });

  it('has empty imports and exports when data directories are zero', () => {
    const buf = buildMinimalPE32();
    const pe = parsePE(buf);
    expect(pe.imports).toEqual([]);
    expect(pe.exports).toEqual([]);
  });

  it('handles truncated buffer gracefully', () => {
    // A buffer too small to contain even a DOS header
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint16(0, 0x5A4D, true); // valid DOS magic
    // e_lfanew will read garbage or zero, but PE sig check should fail
    expect(() => parsePE(buf)).toThrow();
  });

  it('throws on empty buffer', () => {
    const buf = new ArrayBuffer(0);
    expect(() => parsePE(buf)).toThrow();
  });
});

describe('rvaToFileOffset', () => {
  const sections: SectionHeader[] = [
    {
      name: '.text',
      virtualSize: 0x1000,
      virtualAddress: 0x1000,
      sizeOfRawData: 0x800,
      pointerToRawData: 0x400,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0,
    },
    {
      name: '.data',
      virtualSize: 0x500,
      virtualAddress: 0x2000,
      sizeOfRawData: 0x200,
      pointerToRawData: 0xC00,
      pointerToRelocations: 0,
      pointerToLinenumbers: 0,
      numberOfRelocations: 0,
      numberOfLinenumbers: 0,
      characteristics: 0,
    },
  ];

  it('converts RVA at section start to correct file offset', () => {
    expect(rvaToFileOffset(0x1000, sections)).toBe(0x400);
  });

  it('converts RVA within section to correct file offset', () => {
    expect(rvaToFileOffset(0x1100, sections)).toBe(0x500);
  });

  it('converts RVA in second section correctly', () => {
    expect(rvaToFileOffset(0x2000, sections)).toBe(0xC00);
  });

  it('returns -1 for RVA before any section', () => {
    expect(rvaToFileOffset(0x500, sections)).toBe(-1);
  });

  it('returns -1 for RVA beyond all sections', () => {
    expect(rvaToFileOffset(0x5000, sections)).toBe(-1);
  });

  it('returns -1 when RVA is within virtualSize but beyond sizeOfRawData', () => {
    // .text: virtualSize=0x1000 but sizeOfRawData=0x800
    // RVA 0x1900 is at offset 0x900 into section, beyond sizeOfRawData 0x800
    expect(rvaToFileOffset(0x1900, sections)).toBe(-1);
  });

  it('returns -1 for empty sections array', () => {
    expect(rvaToFileOffset(0x1000, [])).toBe(-1);
  });
});
