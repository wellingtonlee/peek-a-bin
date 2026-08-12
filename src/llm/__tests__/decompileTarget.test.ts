import { describe, expect, it } from "vitest";
import type { DisasmFunction } from "../../disasm/types";
import type { SectionHeader } from "../../pe/types";
import { functionByteRange, truncateCode } from "../decompileTarget";

const section: SectionHeader = {
  name: ".text",
  virtualSize: 0x1000,
  virtualAddress: 0x1000,
  sizeOfRawData: 0x400,
  pointerToRawData: 0x400,
  pointerToRelocations: 0,
  pointerToLinenumbers: 0,
  numberOfRelocations: 0,
  numberOfLinenumbers: 0,
  characteristics: 0x60000020,
};

const IMAGE_BASE = 0x400000;
/** VA of the first byte of `section`. */
const SECTION_VA = IMAGE_BASE + section.virtualAddress;

function fn(address: number, size: number): DisasmFunction {
  return { address, size, name: `sub_${address.toString(16)}` } as DisasmFunction;
}

describe("functionByteRange", () => {
  it("converts a VA to a section-relative byte range", () => {
    expect(functionByteRange(fn(SECTION_VA + 0x20, 0x10), section, IMAGE_BASE)).toEqual({
      start: 0x20,
      end: 0x30,
    });
  });

  it("accepts a function starting at the very first byte", () => {
    expect(functionByteRange(fn(SECTION_VA, 0x10), section, IMAGE_BASE)).toEqual({
      start: 0,
      end: 0x10,
    });
  });

  it("accepts a function ending exactly at sizeOfRawData", () => {
    expect(functionByteRange(fn(SECTION_VA + 0x3f0, 0x10), section, IMAGE_BASE)).toEqual({
      start: 0x3f0,
      end: 0x400,
    });
  });

  it("rejects a function one byte past sizeOfRawData", () => {
    expect(functionByteRange(fn(SECTION_VA + 0x3f0, 0x11), section, IMAGE_BASE)).toBeNull();
  });

  it("rejects a function starting before the section", () => {
    expect(functionByteRange(fn(SECTION_VA - 1, 0x10), section, IMAGE_BASE)).toBeNull();
  });

  it("bounds against sizeOfRawData, not virtualSize", () => {
    // virtualSize here is 0x1000, four times the raw size. A function inside the
    // virtual extent but past the on-disk bytes must be rejected — slicing it
    // would read the next section's file data.
    expect(section.virtualSize).toBeGreaterThan(section.sizeOfRawData);
    expect(functionByteRange(fn(SECTION_VA + 0x800, 0x10), section, IMAGE_BASE)).toBeNull();
  });

  it("rejects a function whose address belongs to a different image base", () => {
    expect(functionByteRange(fn(SECTION_VA + 0x20, 0x10), section, 0x140000000)).toBeNull();
  });

  it("allows a zero-size function at the section end", () => {
    expect(functionByteRange(fn(SECTION_VA + 0x400, 0), section, IMAGE_BASE)).toEqual({
      start: 0x400,
      end: 0x400,
    });
  });
});

describe("truncateCode", () => {
  const code = "a\nb\nc\nd\ne";

  it("returns the input unchanged when no cap is given", () => {
    expect(truncateCode(code)).toBe(code);
  });

  it("keeps the first maxLines lines", () => {
    expect(truncateCode(code, 3)).toBe("a\nb\nc");
  });

  it("is a no-op when the code is shorter than the cap", () => {
    expect(truncateCode(code, 99)).toBe(code);
  });

  it("handles a cap of zero", () => {
    expect(truncateCode(code, 0)).toBe("");
  });

  it("does not add or drop a trailing newline at the boundary", () => {
    expect(truncateCode("a\nb\n", 2)).toBe("a\nb");
  });
});
