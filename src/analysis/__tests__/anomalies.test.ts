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
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
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

/**
 * A DIRECTORY THE FILE DECLARES AND THE READER GAVE UP ON (peek-a-bin-wo8g).
 *
 * `parsePE` reads the certificate table and the resource directory behind a
 * `catch {}`, and `parseSecurityDirectory` also answers `null` for a declared
 * certificate whose header does not fit in the file. Every one of those left the
 * field `undefined` — indistinguishable from a file that has neither — so the
 * Headers panel said "Unsigned" and the Resources pane said "No resources
 * found": positive claims about the FILE resting on the tool's own failure.
 *
 * This pass is here for `dataDirectoryClamp`'s reason and not by symmetry: the
 * panels mark the fact where a reader looking at that directory would see it,
 * and this is the surface an analyst opens on purpose — someone who never opens
 * the Resources tab never learns the file declares resources nothing could walk.
 *
 * The liveness half is the last case: an ordinary fixture must raise neither, or
 * the finding is noise on every binary the tool opens.
 */
describe("detectAnomalies — a declared directory the reader could not read", () => {
  const CERT_TITLE = "Certificate table could not be read";
  const RSRC_TITLE = "Resource directory could not be read";

  it("raises a warning for a certificate the file does not contain", () => {
    // Through the real parser: directory 4's address is a FILE OFFSET, and this
    // one is past the end of the fixture — a truncated or carved sample.
    const pe = parsePE(
      buildMinimalPE64({
        dataDirectories: new Map([[4, { virtualAddress: 0x100000, size: 0x200 }]]),
      }),
    );
    const found = detectAnomalies(pe).find((a) => a.title === CERT_TITLE);
    expect(found?.severity).toBe("warning");
  });

  it("says in words that the file is not unsigned", () => {
    // Split from the severity above: two expectations in one `it` hide each
    // other, and the whole point of the finding is the sentence.
    const pe = parsePE(
      buildMinimalPE64({
        dataDirectories: new Map([[4, { virtualAddress: 0x100000, size: 0x200 }]]),
      }),
    );
    const found = detectAnomalies(pe).find((a) => a.title === CERT_TITLE);
    expect(found?.detail).toContain("not unsigned");
    expect(found?.detail).toContain("0x100000");
  });

  it("raises a warning for a resource directory that produced no tree", () => {
    // No fixture reaches `parsePE`'s resource `catch` — `parseResourceDirectory`
    // bounds every read and flags an unresolvable RVA rather than throwing — so
    // the state is built directly, exactly as `resourcesUnreadable`'s docstring
    // says. See `src/pe/__tests__/unreadDirectories.test.ts`.
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          resources: [
            { id: 3, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1]) }] }] },
          ],
        },
      }),
    );
    const found = detectAnomalies({ ...pe, resources: undefined }).find(
      (a) => a.title === RSRC_TITLE,
    );
    expect(found?.severity).toBe("warning");
    expect(found?.detail).toContain("not that there are none");
  });

  it("raises NEITHER for a signed file with resources it read whole", () => {
    // THE LIVENESS HALF, and the control against a predicate that fires on every
    // file: both directories are declared here and both parsed.
    const pe = parsePE(
      buildMinimalPE64({
        certificate: { subjectCN: "Acme" },
        directories: {
          resources: [
            { id: 3, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1]) }] }] },
          ],
        },
      }),
    );
    expect(pe.certificate?.signed).toBe(true);
    expect(pe.resources?.entries).toHaveLength(1);
    const titles = detectAnomalies(pe).map((a) => a.title);
    expect(titles).not.toContain(CERT_TITLE);
    expect(titles).not.toContain(RSRC_TITLE);
  });

  it("raises NEITHER for an ordinary file that declares neither directory", () => {
    // The commonest file this tool opens: unsigned, no resources. Neither
    // finding may appear, or the pass says something false about every binary.
    const titles = detectAnomalies(parsePE(buildMinimalPE32())).map((a) => a.title);
    expect(titles).not.toContain(CERT_TITLE);
    expect(titles).not.toContain(RSRC_TITLE);
  });
});

/**
 * THE DECLARED DATA DIRECTORY COUNT (peek-a-bin-dd94).
 *
 * `numberOfRvaAndSizes` is attacker-controlled and `parseDataDirectories` clamps
 * what it reads; before this the raw count reached the Headers panel and the
 * clamp reached nothing at all, so the one deliberate crafted-PE tell the parser
 * had already noticed was visible on no surface. This pass is the surface an
 * analyst reads on purpose.
 *
 * Both arms of `dataDirectoryClamp` are reached here — a count above the format
 * maximum, and a file that ends mid-table — and the liveness half is the last
 * case: an ordinary fixture must raise neither.
 */
describe("detectAnomalies — the data directory count the file declares", () => {
  /** The bead's own measured case: a PE32+ whose optional header claims 40. */
  const declaring40 = () => parsePE(buildMinimalPE64({ numberOfRvaAndSizes: 40 }));

  it("raises a warning when the file declares more than the format defines", () => {
    const found = detectAnomalies(declaring40()).find(
      (a) => a.title === "Data directory count exceeds the format maximum",
    );
    expect(found?.severity).toBe("warning");
  });

  it("names both numbers, so the detail says what was dropped", () => {
    // Split from the assertion above deliberately: two expectations in one `it`
    // hide each other, and the severity and the prose fail for different
    // reasons.
    const found = detectAnomalies(declaring40()).find(
      (a) => a.title === "Data directory count exceeds the format maximum",
    );
    // 40 declared against the 16 `parsePE` read — asserted against the fixture's
    // own bytes rather than against a hardcoded sentence.
    const pe = declaring40();
    expect(pe.optionalHeader.numberOfRvaAndSizes).toBe(40);
    expect(pe.dataDirectories.length).toBe(16);
    expect(found?.detail).toContain("40");
    expect(found?.detail).toContain("16");
  });

  it("reports a file that ends mid-table as cut short instead", () => {
    // The other arm: a plausible count of 16 that the file has no room for. The
    // reason matters because "the count is out of range" and "the header is
    // truncated" are different findings, and only the second says bytes are
    // missing.
    const full = buildMinimalPE32();
    const dv0 = new DataView(full);
    const opt = dv0.getUint32(0x3c, true) + 4 + 20;
    const buf = full.slice(0, opt + 96 + 3 * 8); // room for three entries
    new DataView(buf).setUint32(opt + 92, 16, true);
    const pe = parsePE(buf);
    expect(pe.dataDirectories.length).toBe(3);

    const found = detectAnomalies(pe).find((a) => a.title === "Data directory table is cut short");
    expect(found?.severity).toBe("warning");
  });

  it("raises NEITHER on a file whose table is whole", () => {
    // The liveness half. A rule that fires on every file is not a finding, and
    // this is also the control for the panel's parenthetical: an ordinary
    // fixture declares 16 and holds 16.
    const pe = parsePE(buildMinimalPE64());
    expect(pe.optionalHeader.numberOfRvaAndSizes).toBe(pe.dataDirectories.length);

    const found = titles(pe);
    expect(found).not.toContain("Data directory count exceeds the format maximum");
    expect(found).not.toContain("Data directory table is cut short");
  });
});
