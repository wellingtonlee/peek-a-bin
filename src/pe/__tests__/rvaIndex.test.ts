/**
 * RVA -> file offset lookup: the prebuilt `SectionIndex` against the linear
 * scan it accelerates.
 *
 * `rvaToFileOffset` is the reference implementation, so every case here asserts
 * the indexed lookup agrees with it as well as asserting the literal answer.
 * The two can only disagree once sections overlap — a shape a linker never
 * emits and a hostile file emits for free, where "the section holding this RVA"
 * stops being a single section. So the overlapping and out-of-order tables are
 * the point of the suite, not an afterthought.
 *
 * The index only builds a searchable form past a section-count threshold, so
 * anything asserting on the *shape* of the index pads its table out with
 * `padded()`. Anything asserting on the *answer* does not have to care.
 */

import { describe, it, expect } from 'vitest';
import {
  buildSectionIndex,
  parsePE,
  rvaToFileOffset,
  rvaToFileOffsetIndexed,
} from '../parser';
import type { SectionHeader } from '../types';
import { buildMinimalPE32 } from './fixtures';
import {
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
} from '../constants';

function sec(
  name: string,
  virtualAddress: number,
  virtualSize: number,
  pointerToRawData: number,
  sizeOfRawData: number,
): SectionHeader {
  return {
    name,
    virtualSize,
    virtualAddress,
    sizeOfRawData,
    pointerToRawData,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics: 0,
  };
}

/**
 * Pad a table out past the threshold at which the index bothers building a
 * searchable form. The filler sits far above anything the tests look up and is
 * ascending and disjoint, so it never decides the property under test.
 */
function padded(sections: SectionHeader[], total = 40): SectionHeader[] {
  const out = sections.slice();
  for (let i = out.length; i < total; i++) {
    out.push(sec(`.pad${i}`, 0x800000 + i * 0x10000, 0x1000, 0x400000 + i * 0x1000, 0x1000));
  }
  return out;
}

/** Both implementations must return the same thing, and that thing is returned. */
function lookup(rva: number, sections: SectionHeader[]): number {
  const scanned = rvaToFileOffset(rva, sections);
  // Check the answer on a short table (which scans) and a padded one (which
  // searches), so no case here silently exercises only one path.
  expect(rvaToFileOffsetIndexed(rva, buildSectionIndex(sections))).toBe(scanned);
  expect(rvaToFileOffsetIndexed(rva, buildSectionIndex(padded(sections)))).toBe(scanned);
  return scanned;
}

describe('buildSectionIndex', () => {
  it('leaves a short table to the scan', () => {
    // Real images have a handful of sections and a scan over a handful beats a
    // binary search over them; the index is for the pathological end.
    expect(
      buildSectionIndex([
        sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
        sec('.data', 0x2000, 0x1000, 0x1400, 0x1000),
      ]).sorted,
    ).toBeNull();
    expect(buildSectionIndex([]).sorted).toBeNull();
  });

  it('builds a searchable form for a long sorted, disjoint table', () => {
    const table = padded([]);
    const index = buildSectionIndex(table);
    expect(index.sorted).not.toBeNull();
    expect(Array.from(index.sorted?.starts ?? [])).toEqual(
      table.map((s) => s.virtualAddress),
    );
    // Already in order, so the table is reused rather than copied.
    expect(index.sorted?.sections).toBe(index.sections);
  });

  it('builds it when sections abut exactly', () => {
    // .text ends at 0x2000 and .data starts there: adjacent, not overlapping.
    const index = buildSectionIndex(
      padded([
        sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
        sec('.data', 0x2000, 0x1000, 0x1400, 0x1000),
      ]),
    );
    expect(index.sorted).not.toBeNull();
  });

  it('builds it across a zero-virtualSize section sharing its neighbour’s RVA', () => {
    const index = buildSectionIndex(
      padded([
        sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
        sec('.empty', 0x2000, 0, 0x1400, 0),
        sec('.data', 0x2000, 0x1000, 0x1400, 0x1000),
      ]),
    );
    expect(index.sorted).not.toBeNull();
  });

  it('sorts an out-of-order but disjoint table instead of giving up on it', () => {
    // Nothing overlaps, so no RVA has more than one candidate and file order
    // cannot change any answer — the copy is safe to search.
    const index = buildSectionIndex(
      padded([
        sec('.data', 0x2000, 0x1000, 0x1400, 0x1000),
        sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
      ]),
    );
    expect(index.sorted).not.toBeNull();
    expect(index.sorted?.sections.slice(0, 2).map((s) => s.name)).toEqual(['.text', '.data']);
    // The original order is kept for the reference scan.
    expect(index.sections.slice(0, 2).map((s) => s.name)).toEqual(['.data', '.text']);
  });

  it('falls back to the scan for an overlapping table', () => {
    expect(
      buildSectionIndex(
        padded([
          sec('.text', 0x1000, 0x2000, 0x400, 0x2000),
          sec('.data', 0x2000, 0x1000, 0x2400, 0x1000),
        ]),
      ).sorted,
    ).toBeNull();
  });

  it('falls back to the scan when a poisoned virtualSize swallows the next section', () => {
    expect(
      buildSectionIndex(
        padded([
          sec('.text', 0x1000, 0xFFFFFFFF, 0x400, 0x200),
          sec('.data', 0x2000, 0x1000, 0x600, 0x1000),
        ]),
      ).sorted,
    ).toBeNull();
  });

  it('falls back to the scan on a NaN virtual size', () => {
    expect(
      buildSectionIndex(
        padded([
          sec('.text', 0x1000, Number.NaN, 0x400, 0x200),
          sec('.data', 0x2000, 0x1000, 0x600, 0x1000),
        ]),
      ).sorted,
    ).toBeNull();
  });

  it('falls back to the scan on a NaN virtual address', () => {
    expect(
      buildSectionIndex(
        padded([
          sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
          sec('.data', Number.NaN, 0x1000, 0x1400, 0x1000),
        ]),
      ).sorted,
    ).toBeNull();
  });
});

describe('rvaToFileOffsetIndexed', () => {
  const sections = [
    sec('.text', 0x1000, 0x1000, 0x400, 0x800),
    sec('.data', 0x2000, 0x0500, 0xC00, 0x200),
  ];

  it('resolves the first byte of a section', () => {
    expect(lookup(0x1000, sections)).toBe(0x400);
    expect(lookup(0x2000, sections)).toBe(0xC00);
  });

  it('resolves the last mapped byte of a section', () => {
    // .text has 0x800 raw bytes: 0x17FF is the last that exists on disk.
    expect(lookup(0x17FF, sections)).toBe(0xBFF);
    expect(lookup(0x21FF, sections)).toBe(0xDFF);
  });

  it('returns -1 one byte past the raw data, without falling into a later section', () => {
    expect(lookup(0x1800, sections)).toBe(-1);
    expect(lookup(0x2200, sections)).toBe(-1);
  });

  it('returns -1 one byte past the virtual end of the last section', () => {
    expect(lookup(0x2500, sections)).toBe(-1);
  });

  it('returns -1 below the first section', () => {
    expect(lookup(0, sections)).toBe(-1);
    expect(lookup(0xFFF, sections)).toBe(-1);
  });

  it('returns -1 in the gap between two sections', () => {
    // .text's virtual extent ends at 0x2000, .data starts at 0x2000 — so widen
    // the gap deliberately rather than relying on the abutting fixture.
    const gapped = [
      sec('.text', 0x1000, 0x0800, 0x400, 0x800),
      sec('.data', 0x3000, 0x0500, 0xC00, 0x200),
    ];
    expect(lookup(0x1800, gapped)).toBe(-1);
    expect(lookup(0x2FFF, gapped)).toBe(-1);
  });

  it('returns -1 for every RVA in a section with zero raw size', () => {
    // A .bss-style section: mapped at run time, absent from the file.
    const bss = [
      sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
      sec('.bss', 0x2000, 0x4000, 0x1400, 0),
      sec('.data', 0x6000, 0x1000, 0x1400, 0x1000),
    ];
    expect(lookup(0x2000, bss)).toBe(-1);
    expect(lookup(0x3000, bss)).toBe(-1);
    expect(lookup(0x5FFF, bss)).toBe(-1);
    // and the sections either side still resolve
    expect(lookup(0x1000, bss)).toBe(0x400);
    expect(lookup(0x6000, bss)).toBe(0x1400);
  });

  it('never matches a zero-virtualSize section', () => {
    const empty = [
      sec('.empty', 0x1000, 0, 0x400, 0x200),
      sec('.text', 0x1000, 0x1000, 0x600, 0x1000),
    ];
    // Two sections share a start RVA, which is only not an overlap because the
    // first is zero-length. It contains nothing, so .text has to answer.
    expect(lookup(0x1000, empty)).toBe(0x600);
  });

  it('returns -1 for an empty section table', () => {
    expect(lookup(0x1000, [])).toBe(-1);
  });

  it('returns -1 for a negative or NaN RVA rather than looping', () => {
    expect(lookup(-1, sections)).toBe(-1);
    expect(lookup(Number.NaN, sections)).toBe(-1);
    expect(lookup(Number.NEGATIVE_INFINITY, sections)).toBe(-1);
  });

  it('resolves a single-section table', () => {
    const one = [sec('.text', 0x1000, 0x1000, 0x200, 0x1000)];
    expect(lookup(0x1000, one)).toBe(0x200);
    expect(lookup(0x1FFF, one)).toBe(0x11FF);
    expect(lookup(0x2000, one)).toBe(-1);
  });

  it('agrees with the scan on an unsorted table', () => {
    const unsorted = [
      sec('.data', 0x3000, 0x1000, 0x1400, 0x1000),
      sec('.text', 0x1000, 0x1000, 0x400, 0x1000),
      sec('.rsrc', 0x2000, 0x1000, 0x2400, 0x1000),
    ];
    expect(lookup(0x1000, unsorted)).toBe(0x400);
    expect(lookup(0x2000, unsorted)).toBe(0x2400);
    expect(lookup(0x3000, unsorted)).toBe(0x1400);
    expect(lookup(0x4000, unsorted)).toBe(-1);
  });

  it('agrees with the scan on an overlapping table, where the earlier entry wins', () => {
    const overlapping = [
      sec('.a', 0x1000, 0x3000, 0x400, 0x3000),
      sec('.b', 0x2000, 0x1000, 0x4000, 0x1000),
    ];
    // 0x2000 is inside both; the scan takes .a because it comes first.
    expect(lookup(0x2000, overlapping)).toBe(0x1400);
  });

  it('agrees with the scan when an earlier overlapping section has no raw data there', () => {
    // The nastiest overlap: .a claims the RVA but cannot supply a byte for it,
    // and the linear scan gives up rather than trying .b. Losing that would
    // silently start resolving RVAs to a different section's bytes.
    const overlapping = [
      sec('.a', 0x1000, 0x3000, 0x400, 0x100),
      sec('.b', 0x2000, 0x1000, 0x4000, 0x1000),
    ];
    expect(lookup(0x2000, overlapping)).toBe(-1);
  });

  it('agrees with the scan on 10k random tables, short and long, sorted and not', () => {
    // Deterministic LCG: a failure has to be reproducible to be worth anything.
    let seed = 0x2545f491;
    const rand = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
      return seed % n;
    };

    // Two families, because they reach different code. Laying sections out end
    // to end with gaps keeps them disjoint however many there are, so long
    // tables reach the binary search; scattering them over a cramped RVA space
    // makes overlaps near-certain, so those reach the scan fallback. Random
    // tables alone are all overlap once the count goes up, and the search would
    // never be exercised at all.
    const disjoint = (count: number): SectionHeader[] => {
      const table: SectionHeader[] = [];
      let va = rand(2) * 0x1000;
      for (let i = 0; i < count; i++) {
        const vsize = rand(4) * 0x1000;
        table.push(sec(`.s${i}`, va, vsize, i * 0x1000 + 0x200, rand(4) * 0x1000));
        va += vsize + rand(3) * 0x1000;
      }
      return table;
    };
    const scattered = (count: number): SectionHeader[] => {
      const table: SectionHeader[] = [];
      for (let i = 0; i < count; i++) {
        table.push(
          sec(`.s${i}`, rand(8) * 0x1000, rand(4) * 0x1000, i * 0x1000 + 0x200, rand(4) * 0x1000),
        );
      }
      return table;
    };
    const shuffle = (table: SectionHeader[]): SectionHeader[] => {
      for (let i = table.length - 1; i > 0; i--) {
        const j = rand(i + 1);
        [table[i], table[j]] = [table[j], table[i]];
      }
      return table;
    };

    let searched = 0;
    let scanned = 0;
    // Compared with `!==` rather than an assertion per RVA: 10k tables is ~650k
    // comparisons and `expect` is far too slow to call that many times.
    const mismatches: string[] = [];
    for (let trial = 0; trial < 10000 && mismatches.length === 0; trial++) {
      const count = rand(48);
      let table = trial % 2 === 0 ? disjoint(count) : scattered(count);
      if (trial % 3 === 0) table = shuffle(table);

      const index = buildSectionIndex(table);
      if (index.sorted) searched++;
      else scanned++;
      for (let rva = 0; rva <= 0x20000; rva += 0x800) {
        const searchedOffset = rvaToFileOffsetIndexed(rva, index);
        const scannedOffset = rvaToFileOffset(rva, table);
        if (searchedOffset !== scannedOffset) {
          mismatches.push(
            `trial ${trial} rva 0x${rva.toString(16)}: index ${searchedOffset} != scan ${scannedOffset} for ` +
              JSON.stringify(
                table.map((s) => [s.virtualAddress, s.virtualSize, s.sizeOfRawData]),
              ),
          );
        }
      }
    }
    expect(mismatches).toEqual([]);

    // Guard the guard: a threshold change that quietly stopped exercising the
    // binary search would leave this suite passing on the scan alone.
    expect(searched).toBeGreaterThan(200);
    expect(scanned).toBeGreaterThan(200);
  });
});

describe('parsePE with a hostile section table', () => {
  const data = (name: string, virtualAddress: number, bytes: Uint8Array) => ({
    name,
    virtualAddress,
    virtualSize: bytes.length,
    data: bytes,
    characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
  });

  it('parses imports through a section table written out of order', () => {
    // The directory section is emitted last by the builder but mapped lowest,
    // so the table the parser sees is genuinely unsorted.
    const buf = buildMinimalPE32({
      sections: [data('.high', 0x9000, new Uint8Array(0x40).fill(0xAA))],
      directoryRVA: 0x2000,
      directories: {
        imports: [
          { libraryName: 'KERNEL32.dll', functions: [{ name: 'Sleep' }, { name: 'ExitProcess' }] },
        ],
      },
    });

    const pe = parsePE(buf);
    expect(pe.sections.map((s) => s.virtualAddress)).toEqual([0x9000, 0x2000]);
    expect(pe.imports.map((i) => i.libraryName)).toEqual(['KERNEL32.dll']);
    expect(pe.imports[0].functions).toEqual(['Sleep', 'ExitProcess']);
  });

  it('does not hang or throw on overlapping sections with absurd virtual sizes', () => {
    const bytes = new Uint8Array(0x40).fill(0x41);
    const buf = buildMinimalPE32({
      sections: [
        { ...data('.a', 0x1000, bytes), virtualSize: 0x7FFFFFFF },
        { ...data('.b', 0x1000, bytes), virtualSize: 0x7FFFFFFF },
      ],
    });

    const pe = parsePE(buf);
    expect(pe.sections).toHaveLength(2);
    const index = buildSectionIndex(pe.sections);
    for (const rva of [0, 0x1000, 0x1020, 0x40000000, 0x7FFFFFFF]) {
      expect(rvaToFileOffsetIndexed(rva, index)).toBe(rvaToFileOffset(rva, pe.sections));
    }
  });
});
