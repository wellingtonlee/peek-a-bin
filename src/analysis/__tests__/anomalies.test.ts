/**
 * `detectAnomalies` — the two whole-file walks, and what happens without them.
 *
 * The pass had no test at all. What it needs now is a contract: the same
 * anomalies whether the checksum and per-section entropy were computed inline
 * (the MCP server and small files) or handed in from `metrics.worker.ts`
 * (peek-a-bin-vrl), and an honest answer when they could not be computed.
 *
 * The malformed-section cases are the reason the merge went in the direction it
 * did: `analysis/anomalies.ts` used to carry its own copy of the entropy walk,
 * and the copy had drifted from `utils/entropy`'s in three ways — see the
 * comment where it used to be.
 */

import { describe, expect, it } from "vitest";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ } from "../../pe/constants";
import { validateChecksum } from "../../pe/metadata";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { computeSectionEntropies } from "../../utils/entropy";
import { sectionRanges } from "../../workers/metricsDispatch";
import { detectAnomalies } from "../anomalies";

const CODE = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

/** `n` bytes with a flat byte distribution, i.e. entropy 8 — what a packer looks like. */
function highEntropy(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = i & 0xff;
  return out;
}

/** A PE whose single code section is incompressible. */
function packedPE(): PEFile {
  return parsePE(
    buildMinimalPE64({
      sections: [
        {
          name: ".text",
          virtualAddress: 0x1000,
          virtualSize: 0x1000,
          data: highEntropy(0x1000),
          characteristics: CODE,
        },
      ],
    }),
  );
}

function titles(pe: PEFile, metrics?: Parameters<typeof detectAnomalies>[1]): string[] {
  return detectAnomalies(pe, metrics).map((a) => a.title);
}

describe("detectAnomalies — precomputed metrics match computing them inline", () => {
  it("produces the identical anomaly list either way", () => {
    const pe = packedPE();
    const metrics = {
      checksum: validateChecksum(pe.buffer, pe),
      sectionEntropies: computeSectionEntropies(pe.buffer, sectionRanges(pe)),
    };

    expect(detectAnomalies(pe, metrics)).toEqual(detectAnomalies(pe));
  });

  it("reports the high-entropy code section from the supplied entropies", () => {
    const pe = packedPE();
    expect(titles(pe)).toContain("High entropy: .text");

    // Indexed by section-table position — the contract `sectionRanges` sets.
    // A wrong index here is the failure mode this pins: the anomaly would be
    // attributed to the wrong section, or vanish.
    expect(
      titles(pe, { checksum: null, sectionEntropies: [7.9] }).filter((t) => t.startsWith("High")),
    ).toEqual(["High entropy: .text"]);
    expect(
      titles(pe, { checksum: null, sectionEntropies: [1.0] }).filter((t) => t.startsWith("High")),
    ).toEqual([]);
  });

  it("reports a checksum mismatch from the supplied checksum", () => {
    const pe = packedPE();
    const mismatch = { valid: false, expected: 0x1234, actual: 0x5678 };

    expect(titles(pe, { checksum: mismatch, sectionEntropies: [] })).toContain("Checksum mismatch");
    // An image that never declared a checksum (expected 0) is not a mismatch.
    expect(
      titles(pe, { checksum: { valid: false, expected: 0, actual: 9 }, sectionEntropies: [] }),
    ).not.toContain("Checksum mismatch");
  });
});

describe("detectAnomalies — metrics that could not be computed", () => {
  it("says so rather than reporting a clean file", () => {
    // "No checksum warning" and "checksum not checked" are different answers,
    // and this list is where a user goes to find out if a file is suspicious.
    const found = detectAnomalies(packedPE(), { checksum: null, sectionEntropies: null });
    const skipped = found.find((a) => a.title === "Some checks did not run");

    expect(skipped?.severity).toBe("info");
    expect(skipped?.detail).toMatch(/checksum validation and section entropy/);
    expect(found.map((a) => a.title)).not.toContain("High entropy: .text");
  });

  it("still runs every check that needs no whole-file walk", () => {
    const found = titles(packedPE(), { checksum: null, sectionEntropies: null });
    expect(found).toContain("ASLR disabled");
    expect(found).toContain("DEP disabled");
  });
});

describe("detectAnomalies — attacker-controlled section table", () => {
  it("scores a section that overruns EOF over the bytes that are there", () => {
    // A packer truncating sizeOfRawData past the end of the file is common, and
    // this is the check meant to catch it. The private walk this module used to
    // have clamped; `computeSectionEntropies` used to score the section 0,
    // which would have read as "empty" and dropped the warning entirely.
    const pe = packedPE();
    pe.sections[0].sizeOfRawData = pe.buffer.byteLength * 4;

    expect(titles(pe)).toContain("High entropy: .text");
  });

  it.each([
    ["an offset past the end of the file", (pe: PEFile) => (pe.sections[0].pointerToRawData = 1e9)],
    ["a negative offset", (pe: PEFile) => (pe.sections[0].pointerToRawData = -8)],
    ["a nonsense size", (pe: PEFile) => (pe.sections[0].sizeOfRawData = -1)],
  ])("does not throw on %s", (_label, corrupt) => {
    // Every one of these threw RangeError out of the private entropy walk. In
    // App.tsx that call sits inside the try around parsePE, so a crafted section
    // table failed the whole load and reported it as a parse failure; in the MCP
    // server it rejected `load_pe`.
    const pe = packedPE();
    corrupt(pe);

    expect(() => detectAnomalies(pe)).not.toThrow();
    expect(() => detectAnomalies(pe, { checksum: null, sectionEntropies: null })).not.toThrow();
  });
});
