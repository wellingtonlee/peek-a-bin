/**
 * `parseAdmissions` — what the parse fell short on, as sentences, for the two
 * surfaces that OUTLIVE THE SESSION.
 *
 * The browser has a render site per fact, each worded for its own pane. An MCP
 * response is consumed by something that cannot ask a follow-up question, and an
 * exported report is a file the user keeps and may compare against another tool
 * months later — so an unmarked narrowing there is durable in a way a screen is
 * not (`peek-a-bin-8pod`).
 *
 * EVERY ROW HERE IS ASSERTED IN BOTH DIRECTIONS. A pass that reports an
 * admission for a whole parse is worse than one that reports none: it would put
 * "this parse was not complete" on the report of every binary the tool opens, at
 * which point the sentence stops being read at all.
 */

import { describe, expect, it } from "vitest";
import { parseAdmissions } from "../admissions";
import { computeImphash } from "../metadata";
import { parsePE } from "../parser";
import { isTruncatedValue } from "../truncation";
import type { PEFile } from "../types";
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from "./fixtures";

const RVA = 0x2000;

function rdata(data: Uint8Array): SectionDef {
  return {
    name: ".rdata",
    virtualAddress: RVA,
    virtualSize: data.length,
    data,
    characteristics: 0x40000040,
  };
}

/** An import descriptor whose library NAME runs on without a NUL. */
function peWithUnreadableImportName(): PEFile {
  const data = new Uint8Array(0x1000).fill(0x41); // 'A', no NUL anywhere
  const dv = new DataView(data.buffer);
  // IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp, ForwarderChain,
  // Name, FirstThunk.
  dv.setUint32(0, RVA + 0x100, true);
  dv.setUint32(4, 0, true);
  dv.setUint32(8, 0, true);
  dv.setUint32(12, RVA + 0x800, true);
  dv.setUint32(16, RVA + 0x100, true);
  dv.setUint32(0x100, 0x80000000 | 1, true); // import by ordinal 1
  dv.setUint32(0x104, 0, true); // terminated thunk array: only the NAME is bad
  return parsePE(
    buildMinimalPE32({
      sections: [rdata(data)],
      dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
    }),
  );
}

describe("parseAdmissions — a whole parse", () => {
  it("says nothing at all", () => {
    // THE HALF THAT MATTERS MOST. `length === 0` is what every consumer tests,
    // so a row invented here reaches the report of every ordinary binary.
    expect(parseAdmissions(parsePE(buildMinimalPE32()))).toEqual([]);
  });

  it("says nothing for a file with real imports, exports and resources", () => {
    const pe = parsePE(
      buildMinimalPE64({
        certificate: { subjectCN: "Acme" },
        directories: {
          imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "Sleep" }] }],
          exports: {
            dllName: "sample.dll",
            addresses: [0x1000],
            names: [{ name: "Start", addressIndex: 0 }],
          },
          resources: [
            { id: 3, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1]) }] }] },
          ],
        },
      }),
    );
    expect(pe.imports).toHaveLength(1);
    expect(pe.exports).toHaveLength(1);
    expect(pe.resources?.entries).toHaveLength(1);
    expect(parseAdmissions(pe)).toEqual([]);
  });
});

describe("parseAdmissions — each subject", () => {
  it("reports a cut-short import table, through the real parser", () => {
    const pe = peWithUnreadableImportName();
    expect(pe.importsTruncated).toBe(true);
    expect(isTruncatedValue(pe.imports[0].libraryName)).toBe(true);

    const found = parseAdmissions(pe).find((a) => a.subject === "imports");
    expect(found).toBeDefined();
    // The counts are named so a reader knows WHICH numbers are lower bounds,
    // derived from the parse rather than restated.
    expect(found?.sentence).toContain("1 library");
    expect(found?.sentence).toContain("LOWER BOUND");
    // …and the consequence a client would otherwise have to know to look for:
    // the digest is withheld, not wrong.
    expect(computeImphash(pe)).toBeNull();
    expect(found?.sentence).toContain("imphash");
  });

  it("reports a cut-short export table", () => {
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          exports: {
            dllName: "sample.dll",
            addresses: [0x1000],
            names: [{ name: "Start", addressIndex: 0 }],
          },
        },
      }),
    );
    const short: PEFile = { ...pe, exportsTruncated: true };
    const found = parseAdmissions(short).find((a) => a.subject === "exports");
    expect(found?.sentence).toContain("1 export");
    expect(found?.sentence).toContain("LOWER BOUND");
  });

  it("reports a resource walk that was cut short, naming what it recovered", () => {
    const pe = parsePE(
      buildMinimalPE32({ dataDirectories: new Map([[2, { virtualAddress: 0x900000, size: 64 }]]) }),
    );
    // The unmapped-RVA case: a tree exists and is flagged (peek-a-bin-dhcx).
    expect(pe.resources?.truncated).toBe(true);
    const found = parseAdmissions(pe).find((a) => a.subject === "resources");
    expect(found?.sentence).toContain("did not cover every entry");
  });

  it("reports a resource directory with no tree at all, and says the OTHER sentence", () => {
    // The two resource facts are different sizes of admission and must not
    // collapse: this one has nothing to describe, the one above has a short
    // tree. Only one is ever reported.
    const pe = parsePE(
      buildMinimalPE32({
        directories: {
          resources: [
            { id: 3, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1]) }] }] },
          ],
        },
      }),
    );
    const rows = parseAdmissions({ ...pe, resources: undefined }).filter(
      (a) => a.subject === "resources",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].sentence).toContain("could not be read at all");
    expect(rows[0].sentence).not.toContain("did not cover every entry");
  });

  it("reports a certificate table that could not be read", () => {
    const pe = parsePE(
      buildMinimalPE64({
        dataDirectories: new Map([[4, { virtualAddress: 0x100000, size: 0x200 }]]),
      }),
    );
    const found = parseAdmissions(pe).find((a) => a.subject === "certificate");
    // The claim a consumer would otherwise make from a missing certificate.
    expect(found?.sentence).toContain("NOT known to be unsigned");
  });

  it("reports the data-directory clamp, distinguishing its two reasons", () => {
    const overDeclared = parsePE(buildMinimalPE64({ numberOfRvaAndSizes: 40 }));
    const capped = parseAdmissions(overDeclared).find((a) => a.subject === "data-directories");
    expect(capped?.sentence).toContain("40");
    expect(capped?.sentence).toContain("defines 16");

    const full = buildMinimalPE32();
    const dv0 = new DataView(full);
    const opt = dv0.getUint32(0x3c, true) + 4 + 20;
    const buf = full.slice(0, opt + 96 + 3 * 8); // room for three entries
    new DataView(buf).setUint32(opt + 92, 16, true);
    const short = parseAdmissions(parsePE(buf)).find((a) => a.subject === "data-directories");
    expect(short?.sentence).toContain("the file ends after 3");
  });
});

describe("parseAdmissions — the sentences", () => {
  it("are safe to print into a markdown table cell or a JSON string", () => {
    // Both consumers put these verbatim into a formatted document: the report
    // into a blockquote beside tables, the MCP responses into JSON. A pipe or a
    // newline would break the first silently.
    const pe = peWithUnreadableImportName();
    const rows = parseAdmissions({
      ...pe,
      exportsTruncated: true,
      resources: undefined,
      dataDirectories: pe.dataDirectories.slice(0, 5),
    });
    expect(rows.length).toBeGreaterThan(1);
    for (const row of rows) {
      expect(row.sentence).not.toContain("|");
      expect(row.sentence).not.toContain("\n");
      // Prose, not a code: the consumer that has never heard of `subject` still
      // cannot be fooled by the value.
      expect(row.sentence.length).toBeGreaterThan(40);
      expect(row.sentence.endsWith(".")).toBe(true);
    }
  });
});
