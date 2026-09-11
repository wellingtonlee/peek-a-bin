/**
 * `classifyAddress` is the one declaration of "is this bare number somewhere a
 * reader can be sent to", asked by the decompile panel's `lines` memo (to
 * style a constant as a link) and by its click handler (to decide where it
 * goes). Both ask the same function, so what this pins is the grounding rule
 * itself: INSIDE A SECTION, not inside the image.
 */
import { describe, expect, it } from "vitest";
import { IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE } from "../../pe/constants";
import type { SectionHeader } from "../../pe/types";
import { classifyAddress } from "../classifyAddress";

const IMAGE_BASE = 0x400000;
const SIZE_OF_IMAGE = 0x5000;

function section(
  name: string,
  virtualAddress: number,
  virtualSize: number,
  characteristics: number,
): SectionHeader {
  return {
    name,
    virtualAddress,
    virtualSize,
    sizeOfRawData: virtualSize,
    pointerToRawData: virtualAddress,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics,
  };
}

/** `.text` at RVA 0x1000, `.rdata` at 0x2000, a write-only oddity at 0x3000; the gap at 0x4000 is inside the image and in no section. */
const SECTIONS: SectionHeader[] = [
  section(".text", 0x1000, 0x1000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
  section(".rdata", 0x2000, 0x1000, IMAGE_SCN_MEM_READ),
  section(".odd", 0x3000, 0x800, IMAGE_SCN_MEM_WRITE),
];

const classify = (value: number) => classifyAddress(value, SECTIONS, IMAGE_BASE, SIZE_OF_IMAGE);

describe("classifyAddress", () => {
  it("answers code for a value inside an executable section", () => {
    expect(classify(0x401000)).toBe("code");
    expect(classify(0x401fff)).toBe("code");
  });

  it("answers data for a value inside a readable non-executable section", () => {
    expect(classify(0x402010)).toBe("data");
  });

  it("answers data for a section that is neither code nor isDataSection-shaped", () => {
    // The hex view shows every section's bytes, so a section with an odd flag
    // set is still somewhere the hex tab can take the reader. `isDataSection`
    // is the xref builder's question and is deliberately not consulted.
    expect(classify(0x403000)).toBe("data");
  });

  it("answers null for a small constant — the mask/stride/offset case", () => {
    // THE CONTROL the panel's `var_8 + 0x10` row rests on.
    expect(classify(0x10)).toBeNull();
    expect(classify(0)).toBeNull();
    expect(classify(0x1f)).toBeNull();
  });

  it("answers null INSIDE the image but in no section", () => {
    // The grounding is the section, not the image extent: the headers and the
    // gaps between sections hold nothing a reader can be sent to. This row is
    // what separates the rule from `imageBase <= v < imageBase + sizeOfImage`.
    expect(classify(0x400000)).toBeNull(); // the DOS header
    expect(classify(0x404000)).toBeNull(); // the gap past `.odd`
    expect(classify(0x403800)).toBeNull(); // one past `.odd`'s virtual size
  });

  it("answers null past the image, and for the section's raw excess", () => {
    expect(classify(0x405000)).toBeNull();
    expect(classify(0x3fffff)).toBeNull();
    // `sectionAtVirtualAddress` bounds by VIRTUAL size; a raw size larger than
    // that does not claim the excess. Same section table, raw size inflated.
    const inflated = SECTIONS.map((s) => ({ ...s, sizeOfRawData: 0x10000 }));
    expect(classifyAddress(0x404000, inflated, IMAGE_BASE, SIZE_OF_IMAGE)).toBeNull();
  });

  it("answers null for a value that is not a finite number", () => {
    expect(classify(Number.NaN)).toBeNull();
    expect(classify(Number.POSITIVE_INFINITY)).toBeNull();
  });

  it("is the same answer for an x64 image base above 2^32", () => {
    const base = 0x140000000;
    const secs = [section(".text", 0x1000, 0x1000, IMAGE_SCN_MEM_EXECUTE)];
    expect(classifyAddress(0x140001234, secs, base, 0x3000)).toBe("code");
    expect(classifyAddress(0x1234, secs, base, 0x3000)).toBeNull();
  });
});
