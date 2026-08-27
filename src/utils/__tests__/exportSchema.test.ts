import { describe, expect, it } from "vitest";
import { type AppState, initialState } from "../../hooks/usePEFile";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { TRUNCATION_MARKER } from "../../pe/truncation";
import type { PEFile } from "../../pe/types";
import { generateMarkdownReport, validateAnnotations } from "../exportSchema";

/**
 * These guard two untrusted inputs that previously reached the reducer unchecked:
 * localStorage (editable by the user or any script on the origin) and the MCP
 * WebSocket bridge (remote input).
 */
describe("validateAnnotations", () => {
  it("accepts a well-formed payload and coerces string keys to numbers", () => {
    const result = validateAnnotations({
      bookmarks: [{ address: 0x401000, label: "entry" }],
      renames: { "4198400": "main" },
      comments: { "4198400": "entry point" },
    });

    expect(result).not.toBeNull();
    expect(result?.bookmarks).toEqual([{ address: 0x401000, label: "entry" }]);
    expect(result?.renames[4198400]).toBe("main");
    expect(result?.comments[4198400]).toBe("entry point");
  });

  it("defaults missing sections rather than rejecting", () => {
    const result = validateAnnotations({});
    expect(result).toEqual({ bookmarks: [], renames: {}, comments: {} });
  });

  it.each([
    ["a non-object", "nope"],
    ["null", null],
    ["bookmarks that are not an array", { bookmarks: { address: 1 } }],
    ["a bookmark without an address", { bookmarks: [{ label: "x" }] }],
    ["a bookmark with a non-numeric address", { bookmarks: [{ address: "0x1000", label: "x" }] }],
    ["a bookmark with a non-string label", { bookmarks: [{ address: 1, label: 42 }] }],
    ["renames as an array", { renames: ["main"] }],
    ["a rename with a non-numeric key", { renames: { notAnAddress: "main" } }],
    ["a rename with a non-string value", { renames: { "4096": 123 } }],
    ["a comment with a non-string value", { comments: { "4096": { nested: true } } }],
  ])("rejects %s", (_label, input) => {
    expect(validateAnnotations(input)).toBeNull();
  });

  it("rejects NaN-producing address keys instead of silently dropping them", () => {
    // Number("") is 0, but Number("abc") is NaN — the latter would previously
    // have become a NaN-keyed entry in app state.
    expect(validateAnnotations({ comments: { abc: "hi" } })).toBeNull();
  });
});

/**
 * THE MARKDOWN REPORT, WHICH HAD NO TEST AT ALL, and specifically whether it
 * reproduces a narrowed parse as a complete one.
 *
 * An exported report is a FILE THE USER KEEPS and may compare against another
 * tool months later, so an unmarked narrowing here is durable in a way a screen
 * is not — the census row `peek-a-bin-8pod` filed. Two defects: the Summary row
 * and the "## Imports" section stated a cut-short import list as fact, and the
 * report INTRODUCED a truncation of its own (`str.slice(0, 60) + "..."`) spelled
 * differently from every other truncation in the tool.
 *
 * Both directions, every row: a report that says "this parse was not complete"
 * over an ordinary binary is worse than one that says nothing, because then the
 * sentence stops being read.
 */
describe("generateMarkdownReport — what the parse did not read whole", () => {
  const RVA = 0x2000;

  function reportFor(pe: PEFile, over: Partial<AppState> = {}): string {
    return generateMarkdownReport({
      ...initialState,
      peFile: pe,
      fileName: "sample.exe",
      ...over,
    });
  }

  /** A parse whose import table is genuinely short: a library name with no NUL. */
  function shortImports(): PEFile {
    const data = new Uint8Array(0x1000).fill(0x41);
    const dv = new DataView(data.buffer);
    dv.setUint32(0, RVA + 0x100, true);
    dv.setUint32(12, RVA + 0x800, true);
    dv.setUint32(16, RVA + 0x100, true);
    dv.setUint32(0x100, 0x80000000 | 1, true);
    dv.setUint32(0x104, 0, true);
    return parsePE(
      buildMinimalPE32({
        sections: [
          {
            name: ".rdata",
            virtualAddress: RVA,
            virtualSize: data.length,
            data,
            characteristics: 0x40000040,
          },
        ],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      }),
    );
  }

  // SPLIT IN TWO ON PURPOSE: within one `it()` the first failure hides the
  // second, so a control that withdraws only the heading notes would show up as
  // the same single red row as one that withdraws the whole block.
  it("qualifies the counts it prints when the import table was cut short", () => {
    const pe = shortImports();
    expect(pe.importsTruncated).toBe(true);
    const md = reportFor(pe);

    // The block sits directly under the Summary table, because that is what it
    // qualifies: a reader takes those counts as facts about the file otherwise.
    expect(md).toContain("**This parse was not complete.**");
    expect(md).toContain("lower bound");
    expect(md.indexOf("| Imports |")).toBeLessThan(md.indexOf("This parse was not complete"));
  });

  it("repeats it on the section a reader scrolls to", () => {
    // A reader who has scrolled to the list has left the Summary table behind,
    // and the per-library note is a separate fact from the whole-table one:
    // each descriptor has its own thunk walk.
    const md = reportFor(shortImports());
    expect(md).toContain("## Imports (incomplete — see Summary)");
    expect(md).toContain("(incomplete — not every imported name was read)");
  });

  it("says none of that for a file whose imports are whole", () => {
    // THE CONTROL. A rule that marks everything is not a finding.
    const pe = parsePE(
      buildMinimalPE32({
        directories: {
          imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "Sleep" }] }],
        },
      }),
    );
    expect(pe.importsTruncated).toBeUndefined();
    const md = reportFor(pe);

    expect(md).not.toContain("This parse was not complete");
    expect(md).toContain("## Imports\n");
    expect(md).not.toContain("incomplete");
  });

  it("clips a long string with the parser's marker, not a bare ellipsis", () => {
    const pe = parsePE(buildMinimalPE32());
    const long = "A".repeat(200);
    const md = reportFor({ ...pe, strings: new Map([[0x402000, long]]) } as PEFile);

    expect(md).toContain(`${"A".repeat(60)}${TRUNCATION_MARKER}`);
    // The old spelling, which a string may legitimately end in and which
    // `isTruncatedValue` cannot recognise.
    expect(md).not.toContain(`${"A".repeat(60)}...`);
  });

  it("leaves a short string exactly as the parser read it", () => {
    // The other half: the marker must appear only where something was cut.
    const pe = parsePE(buildMinimalPE32());
    const md = reportFor({ ...pe, strings: new Map([[0x402000, "kernel32.dll"]]) } as PEFile);
    expect(md).toContain("| 0x402000 | kernel32.dll |");
    expect(md).not.toContain(TRUNCATION_MARKER);
  });
});
