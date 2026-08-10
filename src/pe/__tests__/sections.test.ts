import { describe, it, expect } from 'vitest';
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from './fixtures';
import { parsePE } from '../parser';
import type { SectionHeader } from '../types';
import { findCodeSection, isCodeSection, isDataSection, dataSectionRanges } from '../sections';
import {
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_MEM_WRITE,
} from '../constants';

const CODE_FLAGS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
const DATA_FLAGS = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

/** A section for the fixture builder, i.e. one that gets written into a real PE. */
function section(name: string, va: number, characteristics: number): SectionDef {
  const data = new Uint8Array([0xcc, 0xcc, 0xcc, 0xcc]);
  return { name, virtualAddress: va, virtualSize: data.length, data, characteristics };
}

/**
 * A parsed section header, for exercising the predicates directly on names the
 * fixture builder would normalize away (NUL padding, odd casing).
 */
function header(name: string, characteristics: number): SectionHeader {
  return {
    name,
    virtualSize: 4,
    virtualAddress: 0x1000,
    sizeOfRawData: 4,
    pointerToRawData: 0x400,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics,
  };
}

describe('findCodeSection', () => {
  it('finds the section named .text', () => {
    const pe = parsePE(buildMinimalPE32());
    expect(findCodeSection(pe.sections)?.name).toBe('.text');
  });

  it('finds an executable section that is not named .text', () => {
    // A packer-style layout: the only executable section is called UPX1.
    const pe = parsePE(
      buildMinimalPE32({
        sections: [
          section('.rdata', 0x1000, DATA_FLAGS),
          section('UPX1', 0x2000, CODE_FLAGS),
        ],
      }),
    );
    const found = findCodeSection(pe.sections);
    expect(found?.name).toBe('UPX1');
    expect(found?.virtualAddress).toBe(0x2000);
  });

  it('returns undefined when no section is named .text or marked executable', () => {
    const pe = parsePE(
      buildMinimalPE32({
        sections: [
          section('.rdata', 0x1000, DATA_FLAGS),
          section('.data', 0x2000, DATA_FLAGS),
        ],
      }),
    );
    expect(findCodeSection(pe.sections)).toBeUndefined();
  });

  it('matches a non-executable section named exactly .text', () => {
    // The name half of the predicate stands alone — no EXECUTE flag required.
    const pe = parsePE(
      buildMinimalPE32({
        sections: [section('.text', 0x1000, IMAGE_SCN_MEM_READ)],
      }),
    );
    const found = findCodeSection(pe.sections);
    expect(found?.name).toBe('.text');
    expect(found!.characteristics & IMAGE_SCN_MEM_EXECUTE).toBe(0);
  });

  it('is first-match-wins over section-table order, not ".text preferred"', () => {
    // An executable stub precedes a real .text. The helper returns the stub,
    // matching every call site it replaced. Pinned so a future "prefer .text"
    // rewrite is a deliberate, visible change rather than a silent one.
    const pe = parsePE(
      buildMinimalPE32({
        sections: [
          section('.stub', 0x1000, CODE_FLAGS),
          section('.text', 0x2000, CODE_FLAGS),
        ],
      }),
    );
    expect(findCodeSection(pe.sections)?.name).toBe('.stub');
  });

  it('returns undefined for an empty section table', () => {
    expect(findCodeSection([])).toBeUndefined();
  });

  it('behaves identically on PE32+', () => {
    const pe = parsePE(
      buildMinimalPE64({
        sections: [
          section('.rdata', 0x1000, DATA_FLAGS),
          section('.code', 0x2000, CODE_FLAGS),
        ],
      }),
    );
    expect(findCodeSection(pe.sections)?.name).toBe('.code');
  });

  it('agrees with the hand-written predicate it replaced', () => {
    const pe = parsePE(
      buildMinimalPE32({
        sections: [
          section('.rdata', 0x1000, DATA_FLAGS),
          section('.text', 0x2000, CODE_FLAGS),
          section('.altcode', 0x3000, CODE_FLAGS),
        ],
      }),
    );
    const legacy = pe.sections.find(
      s => s.name === '.text' || (s.characteristics & 0x20000000) !== 0,
    );
    expect(findCodeSection(pe.sections)).toBe(legacy);
  });
});

describe('isCodeSection', () => {
  it('requires an exact name match, so NUL padding does not count', () => {
    // Section names are NUL-padded to 8 bytes on disk. Only the EXECUTE flag
    // rescues a padded name, so this documents the parser's trimming as a real
    // dependency of the predicate rather than an incidental detail.
    expect(isCodeSection(header('.text\0', IMAGE_SCN_MEM_READ))).toBe(false);
    expect(isCodeSection(header('.text', IMAGE_SCN_MEM_READ))).toBe(true);
  });

  it('is case-sensitive on the name', () => {
    expect(isCodeSection(header('.TEXT', IMAGE_SCN_MEM_READ))).toBe(false);
  });

  it('matches on the EXECUTE flag regardless of name', () => {
    expect(isCodeSection(header('.TEXT', IMAGE_SCN_MEM_EXECUTE))).toBe(true);
  });
});

describe('isDataSection', () => {
  it('accepts the conventional data section names', () => {
    for (const name of ['.data', '.rdata', '.bss']) {
      expect(isDataSection(header(name, 0))).toBe(true);
    }
  });

  it('normalizes NULs, whitespace and case in the name, unlike isCodeSection', () => {
    expect(isDataSection(header('.RDATA\0', 0))).toBe(true);
  });

  it('accepts any readable, non-executable section', () => {
    expect(isDataSection(header('.weird', IMAGE_SCN_MEM_READ))).toBe(true);
  });

  it('rejects a readable section that is also executable', () => {
    expect(isDataSection(header('.weird', CODE_FLAGS))).toBe(false);
  });

  it('rejects a section that is neither named nor readable', () => {
    expect(isDataSection(header('.weird', 0))).toBe(false);
  });

  it('accepts a named data section even when marked executable', () => {
    // The name test short-circuits before the flag test — a WX .data still
    // counts as data here.
    expect(isDataSection(header('.data', CODE_FLAGS))).toBe(true);
  });
});

describe('dataSectionRanges', () => {
  it('maps data sections to image-base-relative VA ranges', () => {
    const pe = parsePE(
      buildMinimalPE32({
        imageBase: 0x400000,
        sections: [
          section('.text', 0x1000, CODE_FLAGS),
          section('.rdata', 0x2000, DATA_FLAGS),
          section('.data', 0x3000, DATA_FLAGS),
        ],
      }),
    );
    expect(dataSectionRanges(pe.sections, pe.optionalHeader.imageBase)).toEqual([
      { va: 0x402000, size: 4 },
      { va: 0x403000, size: 4 },
    ]);
  });

  it('excludes the code section', () => {
    const pe = parsePE(buildMinimalPE32({ imageBase: 0x400000 }));
    const ranges = dataSectionRanges(pe.sections, pe.optionalHeader.imageBase);
    expect(ranges.some(r => r.va === 0x401000)).toBe(false);
  });
});
