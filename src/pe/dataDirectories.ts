import type { PEFile } from "./types";

/**
 * What `parseDataDirectories` refused to read, derived rather than published.
 *
 * `optionalHeader.numberOfRvaAndSizes` is attacker-controlled, so `parsePE`
 * clamps the table it builds to `Math.min(count, 16, fits)`. Both halves of that
 * then sit on `PEFile` with nothing connecting them: a PE32+ declaring 40
 * renders `Number of RVA and Sizes: 40` above a table of SIXTEEN rows. Neither
 * number is false on its own — the raw count is what the file says and sixteen
 * rows is what the format allows — and the pair is what misleads.
 *
 * WHY THIS IS DERIVED AND NOT A `PEFile` FIELD, which is the decision worth
 * recording. The nearest precedent is `PEFile.importsTruncated`, and it exists
 * because the import walk's truncation is **not recoverable from its output**: a
 * list cut short at a bound is shaped exactly like a complete short list, so
 * unless the parser says so, nothing downstream can tell. The clamp here is the
 * opposite case. `directories.length === Math.min(count, 16, fits)` by
 * construction, so `dataDirectories.length < numberOfRvaAndSizes` is **exactly**
 * the clamp — not an approximation of it — over two fields that are already
 * public. A parser field beside them would be a second declaration of a fact the
 * data already carries, i.e. a thing that can disagree with the array it
 * describes; deriving it cannot.
 *
 * One declaration, for `pe/sections.ts`'s reason: two readers want it (the
 * Headers panel's own row and `analysis/anomalies.ts`), they are in different
 * top-level directories, and a predicate hand-written at two sites is this
 * repo's most frequently repaired defect.
 */
export interface DataDirectoryClamp {
  /** `numberOfRvaAndSizes` as the file states it. */
  declared: number;
  /** How many entries `parsePE` actually read. */
  present: number;
  /**
   * Which constraint bound the count.
   *
   * `"spec-maximum"` — the file declared more than the sixteen entries the PE
   * format defines. Provable from the numbers alone, and the crafted-PE tell:
   * every real linker writes exactly 16.
   *
   * `"short-header"` — the declared entries do not fit in the file at all, so
   * the optional header is truncated. Stronger evidence of malformation, and
   * reported in preference to the spec cap when both are true, because "the
   * file ends mid-table" says more than "the count is out of range".
   */
  reason: "spec-maximum" | "short-header";
}

/**
 * The clamp, or `null` when the table is whole — never a `{ clamped: false }`
 * shape, so a caller cannot render an admission for a file that earned none.
 */
export function dataDirectoryClamp(
  pe: Pick<PEFile, "dataDirectories" | "optionalHeader">,
): DataDirectoryClamp | null {
  const declared = pe.optionalHeader.numberOfRvaAndSizes;
  const present = pe.dataDirectories.length;
  if (present >= declared) return null;
  return {
    declared,
    present,
    // `present` short of even the spec cap means the bytes ran out; anything
    // else is the cap doing its job.
    reason: present < Math.min(declared, 16) ? "short-header" : "spec-maximum",
  };
}
