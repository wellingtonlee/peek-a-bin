/**
 * Two things `npm run corpus:parserdiff` cannot check about itself.
 *
 * 1. **THE INDEPENDENCE.** `corpus/parserDifferential.ts` is only an oracle
 *    while its reference reader reads the specification rather than the parser.
 *    TypeScript puts every import at the top of a file, so that separation is a
 *    property of two REGIONS and nothing in the language or the linter can hold
 *    it: someone adding `rvaToFileOffset` to the reference "just for the section
 *    walk" turns the whole harness into a differential test between one
 *    implementation and itself, which is the trap CLAUDE.md names in as many
 *    words, and every row would stay green while doing it. This is the same
 *    family as `capstoneWindow.test.ts`'s `.disasm(` scan and
 *    `mcp/__tests__/importGraph.test.ts` — a text scrape, cheap, and catching a
 *    class nothing static can see.
 *
 * 2. **THE EXPORT AND ORDINAL-IMPORT ROWS**, which are VACUOUS on every binary
 *    obtainable here. All six corpus binaries are EXEs with no export directory
 *    and no ordinal import, and `find / -xdev -iname '*.dll'` finds nothing on
 *    this machine — so those rows are printed VACUOUS by the harness and are not
 *    evidence. They are exercised here instead, over an image built byte by byte
 *    in this file, exactly as `build/arm64Audit.test.ts` controls the ARM64 rows
 *    the corpus cannot make red. The judging functions take plain data, which is
 *    why this works with no corpus and no worker.
 *
 * Each row is asked in BOTH directions: once over well-formed input, where it
 * must be 0 over a NON-EMPTY population — a test that checks only the red
 * direction passes just as well against an audit that has stopped looking — and
 * once over input carrying exactly the defect, where it must name the offender.
 *
 * The image here is hand-built rather than taken from `src/pe/__tests__/fixtures.ts`
 * on purpose: those builders are the parser suite's own, and an audit sharing a
 * fixture with the code it judges is one more shared assumption.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  exportSubject,
  importSubject,
  imphashSubject,
  readReference,
  type Row,
} from "../corpus/parserDifferential";
import { parsePE } from "../src/pe/parser";

// ── 1. the independence guard ───────────────────────────────────────────────

const HARNESS = fileURLToPath(new URL("../corpus/parserDifferential.ts", import.meta.url));

/** The two banner lines the harness's own comments promise not to reword. */
const REFERENCE_BANNER = "// THE REFERENCE READER.";
const SUBJECTS_BANNER = "// THE SUBJECTS.";

function harnessRegions(): { reference: string; subjects: string; imported: string[] } {
  const text = readFileSync(HARNESS, "utf8");
  const a = text.indexOf(REFERENCE_BANNER);
  const b = text.indexOf(SUBJECTS_BANNER);
  expect(a, `${REFERENCE_BANNER} banner is missing`).toBeGreaterThan(0);
  expect(b, `${SUBJECTS_BANNER} banner is missing`).toBeGreaterThan(a);

  // Every binding brought in from `src/`, value imports and type imports alike.
  // A type import cannot carry an implementation, but naming one in the
  // reference still means the reference is reading the parser's shape rather
  // than the file's, so both are held to the same rule.
  const imported: string[] = [];
  for (const m of text.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+"(\.\.\/src\/[^"]+)"/g)) {
    for (const raw of m[1].split(",")) {
      const name = raw.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0].trim();
      if (name) imported.push(name);
    }
  }
  return { reference: text.slice(a, b), subjects: text.slice(b), imported };
}

describe("corpus/parserDifferential.ts stays an oracle", () => {
  it("imports something from src/ at all, so the guard has a population", () => {
    // Liveness. A guard whose list of forbidden names is empty passes by no
    // longer looking, which is the failure mode CLAUDE.md records for
    // DOC_ONLY_KEYS and for build/guardShape.test.ts.
    const { imported } = harnessRegions();
    expect(imported.length).toBeGreaterThan(0);
    expect(imported).toContain("parsePE");
  });

  it("never uses a name imported from src/ inside the reference reader", () => {
    const { reference, imported } = harnessRegions();
    const leaked = imported.filter((n) => new RegExp(`\\b${n}\\b`).test(reference));
    expect(leaked, `the reference reader must not read ${leaked.join(", ")}`).toEqual([]);
  });

  it("the comparison half does use them, so the split is where it claims", () => {
    // The other direction: if `parsePE` appeared in neither region the first
    // assertion would be green over a file that had stopped comparing anything.
    const { subjects, imported } = harnessRegions();
    const used = imported.filter((n) => new RegExp(`\\b${n}\\b`).test(subjects));
    expect(used).toContain("parsePE");
  });

  it("the reference reads bytes rather than the parser's answer", () => {
    const { reference } = harnessRegions();
    expect(reference).toContain("DataView");
    expect(reference).not.toMatch(/from\s+"\.\.\/src\//);
  });
});

// ── 2. an image with exports, forwarders and ordinal imports ────────────────

const IMAGE_BASE = 0x400000;
const SEC_RVA = 0x1000;
const SEC_RAW = 0x400;
/** RVA → file offset for the single section this builder emits. */
const at = (rva: number) => SEC_RAW + (rva - SEC_RVA);

/**
 * A PE32 with an export directory (a name, an alias, an ordinal-only slot and a
 * forwarder) and two imported DLLs (an ordinal import, a named import, and an
 * ordinal from a DLL pefile resolves through `ordlookup`).
 *
 * Written out as offsets and literals rather than through a helper, because the
 * point of the fixture is that the bytes are the fixture.
 */
function buildImageWithExports(): ArrayBuffer {
  const buf = new ArrayBuffer(0x800);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  const ascii = (off: number, s: string) => {
    for (let i = 0; i < s.length; i++) u8[off + i] = s.charCodeAt(i);
    u8[off + s.length] = 0;
  };

  dv.setUint16(0, 0x5a4d, true); // MZ
  dv.setUint32(0x3c, 0x80, true); // e_lfanew
  dv.setUint32(0x80, 0x00004550, true); // "PE\0\0"

  // COFF
  dv.setUint16(0x84, 0x014c, true); // machine i386
  dv.setUint16(0x86, 1, true); // one section
  dv.setUint32(0x88, 0x60000000, true); // timeDateStamp
  dv.setUint16(0x94, 0xe0, true); // sizeOfOptionalHeader
  dv.setUint16(0x96, 0x210e, true); // characteristics (DLL | EXECUTABLE | …)

  // Optional header (PE32) at 0x98
  const opt = 0x98;
  dv.setUint16(opt, 0x10b, true);
  dv.setUint32(opt + 16, 0x2000, true); // addressOfEntryPoint
  dv.setUint32(opt + 20, 0x2000, true); // baseOfCode
  dv.setUint32(opt + 28, IMAGE_BASE, true);
  dv.setUint32(opt + 32, 0x1000, true); // sectionAlignment
  dv.setUint32(opt + 36, 0x200, true); // fileAlignment
  dv.setUint32(opt + 56, 0x3000, true); // sizeOfImage
  dv.setUint32(opt + 60, 0x400, true); // sizeOfHeaders
  dv.setUint16(opt + 68, 3, true); // subsystem
  dv.setUint32(opt + 92, 16, true); // numberOfRvaAndSizes
  const dirs = opt + 96;
  dv.setUint32(dirs + 0 * 8, 0x1000, true); // export dir RVA
  dv.setUint32(dirs + 0 * 8 + 4, 0x100, true); // …and size: covers the forwarder
  dv.setUint32(dirs + 1 * 8, 0x1100, true); // import dir RVA
  dv.setUint32(dirs + 1 * 8 + 4, 60, true); // three descriptors, last one null

  // Section header at 0x178
  const sec = opt + 0xe0;
  ascii(sec, ".rdata");
  dv.setUint32(sec + 8, 0x400, true); // virtualSize
  dv.setUint32(sec + 12, SEC_RVA, true);
  dv.setUint32(sec + 16, 0x400, true); // sizeOfRawData
  dv.setUint32(sec + 20, SEC_RAW, true);
  dv.setUint32(sec + 36, 0x40000040, true); // initialised data, read

  // ── export directory at RVA 0x1000 ──
  const ed = at(0x1000);
  dv.setUint32(ed + 16, 1, true); // Base
  dv.setUint32(ed + 20, 4, true); // NumberOfFunctions
  dv.setUint32(ed + 24, 3, true); // NumberOfNames
  dv.setUint32(ed + 28, 0x1028, true); // AddressOfFunctions
  dv.setUint32(ed + 32, 0x1038, true); // AddressOfNames
  dv.setUint32(ed + 36, 0x1044, true); // AddressOfNameOrdinals

  // Address table: two code RVAs, an ordinal-only slot, and a forwarder whose
  // value lands INSIDE the export directory's own extent.
  dv.setUint32(at(0x1028) + 0, 0x2000, true);
  dv.setUint32(at(0x1028) + 4, 0x2010, true);
  dv.setUint32(at(0x1028) + 8, 0x2020, true);
  dv.setUint32(at(0x1028) + 12, 0x1080, true);
  // Name pointers, and the unbiased address-table index each belongs to. Two
  // names share slot 1 — an alias, which both readers must expand into two
  // exports of the same ordinal.
  dv.setUint32(at(0x1038) + 0, 0x1050, true);
  dv.setUint32(at(0x1038) + 4, 0x1056, true);
  dv.setUint32(at(0x1038) + 8, 0x105b, true);
  dv.setUint16(at(0x1044) + 0, 0, true);
  dv.setUint16(at(0x1044) + 2, 1, true);
  dv.setUint16(at(0x1044) + 4, 1, true);
  ascii(at(0x1050), "Alpha");
  ascii(at(0x1056), "Beta");
  ascii(at(0x105b), "BetaAlias");
  ascii(at(0x1080), "OTHER.Func");

  // ── import descriptors at RVA 0x1100 ──
  const id = at(0x1100);
  dv.setUint32(id + 0, 0x1140, true); // OriginalFirstThunk
  dv.setUint32(id + 12, 0x1160, true); // Name
  dv.setUint32(id + 16, 0x1180, true); // FirstThunk
  dv.setUint32(id + 20 + 0, 0x11a0, true);
  dv.setUint32(id + 20 + 12, 0x11d0, true);
  dv.setUint32(id + 20 + 16, 0x11c0, true);
  // third descriptor left zeroed — the null terminator

  // TEST.dll: one ordinal import, one by name.
  dv.setUint32(at(0x1140) + 0, 0x8000_0000 | 42, true);
  dv.setUint32(at(0x1140) + 4, 0x1150, true);
  dv.setUint16(at(0x1150), 7, true); // hint, which the name read must skip
  ascii(at(0x1150) + 2, "Foo");
  ascii(at(0x1160), "TEST.dll");
  // WS2_32.dll: an ordinal pefile would resolve through `ordlookup`.
  dv.setUint32(at(0x11a0) + 0, 0x8000_0000 | 115, true);
  ascii(at(0x11d0), "WS2_32.dll");

  return buf;
}

const value = (rows: Row[], needle: string): Row => {
  const r = rows.find((x) => x.name.includes(needle));
  if (!r) throw new Error(`no row matching ${needle} in ${rows.map((x) => x.name).join(" | ")}`);
  return r;
};

describe("the export and ordinal rows, which no binary here can exercise", () => {
  const ab = buildImageWithExports();
  const ref = readReference(ab);
  const pe = parsePE(ab);

  it("builds an image both readers agree is what it claims to be", () => {
    // The fixture's own liveness: if the builder drifted and produced nothing,
    // every assertion below would pass over an empty population.
    expect(ref.exports.map((e) => e.name)).toEqual(["Alpha", "Beta", "BetaAlias", null, null]);
    expect(ref.exports.filter((e) => e.forwarder !== null)).toHaveLength(1);
    expect(ref.imports.map((i) => i.dll)).toEqual(["TEST.dll", "WS2_32.dll"]);
    expect(pe.exports).toHaveLength(5);
    expect(pe.imports[0].functions).toEqual(["Ordinal_42", "Foo"]);
  });

  it("agrees on every export, over a population that is not empty", () => {
    const rows = exportSubject(ref, pe);
    const main = value(rows, "exports: entry disagreements");
    expect(main.value).toBe(0);
    expect(main.vacuous).toBe(false);
    expect(main.live).toContain("5 exports");
    expect(value(rows, "forwarder disagreements").vacuous).toBe(false);
    expect(value(rows, "nameless").value).toBe(2);
  });

  it("names a renamed export", () => {
    const bad = structuredClone(pe);
    bad.exports[1].name = "Gamma";
    const row = value(exportSubject(ref, bad), "exports: entry disagreements");
    expect(row.value).toBeGreaterThan(0);
    expect(row.rows.join("\n")).toContain("Beta");
  });

  it("names an export whose ordinal is biased wrongly", () => {
    // Base is 1 here, so an off-by-one in the ordinal bias — a real and easy
    // mistake, since the ordinal TABLE holds unbiased indices — is red.
    const bad = structuredClone(pe);
    for (const e of bad.exports) e.ordinal -= 1;
    const row = value(exportSubject(ref, bad), "exports: entry disagreements");
    expect(row.value).toBeGreaterThan(0);
    expect(row.rows.join("\n")).toContain("ordinal reference");
  });

  it("names a forwarder read as code", () => {
    const bad = structuredClone(pe);
    bad.exports[4].forwarder = undefined;
    const row = value(exportSubject(ref, bad), "exports: entry disagreements");
    expect(row.value).toBeGreaterThan(0);
    expect(row.rows.join("\n")).toContain("forwarder reference OTHER.Func");
  });

  it("names an ordinal-only export given a name", () => {
    const bad = structuredClone(pe);
    bad.exports[3].byOrdinal = undefined;
    const row = value(exportSubject(ref, bad), "exports: entry disagreements");
    expect(row.value).toBeGreaterThan(0);
    expect(row.rows.join("\n")).toContain("byOrdinal");
  });

  it("agrees on the Ordinal_<n> wire format, over a population that is not empty", () => {
    const rows = importSubject(ref, pe);
    const row = value(rows, "ordinal imports not spelled");
    expect(row.value).toBe(0);
    expect(row.vacuous).toBe(false);
    expect(row.live).toBe("2 ordinal imports of 3");
  });

  it("names an ordinal import spelled any other way", () => {
    // This is the whole point of writing the prefix out literally in the
    // harness: `Ordinal_<n>` is a wire format `computeImphash` reads back, so a
    // respelling changes every affected imphash with nothing to notice it by.
    const bad = structuredClone(pe);
    bad.imports[0].functions[0] = "Ordinal#42";
    const row = value(importSubject(ref, bad), "ordinal imports not spelled");
    expect(row.value).toBe(1);
    expect(row.rows.join("\n")).toContain('spelled "Ordinal#42"');
  });

  it("declines the imphash comparison where an ordlookup ordinal is present", () => {
    // The reference has no independent copy of pefile's `ordlookup` table and
    // does not invent one, so a WS2_32 ordinal makes the row non-comparable
    // rather than falsely green.
    const rows = imphashSubject(ref, pe);
    const row = value(rows, "imphash: reference and parser disagree");
    expect(row.vacuous).toBe(true);
    expect(row.live).toContain("not comparable");
    expect(value(rows, "ordlookup DLL").value).toBe(1);
  });
});
