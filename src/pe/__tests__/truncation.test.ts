/**
 * The truncation marker's ONE DECLARATION, and a drift guard that keeps it one.
 *
 * It was three literals in three files — `metadata.ts`, `parser.ts`,
 * `resources.ts` — each landed by a change that did not own the other two, each
 * with a docstring noting the duplication, and the last one filing the
 * consolidation (`peek-a-bin-wo8g`, out of `peek-a-bin-dhcx`). Three copies of a
 * string literal is this repo's most-repaired defect shape, and it is worse than
 * usual here: the marker is now READ BACK — by `isTruncatedValue`, which decides
 * `ImportEntry.truncated`, and by `utils/exportSchema.ts`, which recognises a
 * marked value in a string it did not produce. A drifted copy would make a reader
 * silently stop recognising the admission, not merely look different.
 *
 * The scan is a text scrape, so it is written the way this repo's other scrapes
 * are: a pattern a reformat cannot break, plus a LIVENESS half — a guard whose
 * population has emptied passes by no longer looking.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { isTruncatedValue, TRUNCATION_MARKER } from "../truncation";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...tsFiles(path));
    else if (name.endsWith(".ts") || name.endsWith(".tsx")) out.push(path);
  }
  return out;
}

describe("TRUNCATION_MARKER", () => {
  it("holds characters none of the strings this parser reads can contain", () => {
    // The property is what makes the marker safe to append to a value: a PE
    // import, export or library name is an ASCII C string a linker emitted, and
    // a Windows path may hold neither `<` nor `>`. Asserted rather than stated,
    // because a marker a name could legitimately contain would be unrecognisable
    // as an admission.
    expect(TRUNCATION_MARKER).toContain("…");
    expect(TRUNCATION_MARKER).toContain("<");
    expect(TRUNCATION_MARKER).toContain(">");
    // eslint-disable-next-line no-control-regex
    expect(/^[\x20-\x7e]*$/.test(TRUNCATION_MARKER)).toBe(false);
  });

  it("is recognised at the end of a value and nowhere else", () => {
    expect(isTruncatedValue(`C:\\build${TRUNCATION_MARKER}`)).toBe(true);
    expect(isTruncatedValue("KERNEL32.dll")).toBe(false);
    // The predicate is an `endsWith`, deliberately: a value that merely CONTAINS
    // the marker was not truncated by this parser, and treating it as truncated
    // would let a crafted name claim the admission for itself.
    expect(isTruncatedValue(`${TRUNCATION_MARKER} and more`)).toBe(false);
  });

  it("is declared exactly once under src/", () => {
    const files = tsFiles(SRC).filter((f) => !f.includes("__tests__"));
    // LIVENESS: the walk must actually reach the module under test, or a scan
    // that found nothing would pass for the wrong reason.
    expect(files).toContain(join(SRC, "pe", "truncation.ts"));
    expect(files.length).toBeGreaterThan(100);

    // Matched as the marker's own characters rather than as a `const` line, so
    // reformatting, renaming or re-quoting cannot slip a copy past this.
    const declaring = files.filter((f) => readFileSync(f, "utf8").includes(TRUNCATION_MARKER));
    expect(declaring).toEqual([join(SRC, "pe", "truncation.ts")]);
  });
});
