import { IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_DIRECTORY_ENTRY_SECURITY } from "./constants";
import type { DataDirectory, PEFile } from "./types";

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

/**
 * Whether the file DECLARES a directory at `index`: a non-zero address and a
 * non-zero size.
 *
 * One declaration because it is the gate `parsePE` opens each optional reader
 * behind, *and* the premise of every "could not read it" admission derived from
 * one — {@link certificateUnreadable}, {@link resourcesUnreadable}. If a view's
 * premise and the parser's gate drift apart, the view claims a read failed on a
 * directory the parser never attempted, which is a worse falsehood than the one
 * those predicates exist to remove.
 */
export function directoryDeclared(dir: DataDirectory | undefined): dir is DataDirectory {
  return dir !== undefined && dir.virtualAddress > 0 && dir.size > 0;
}

/**
 * The file declares a certificate table and `parsePE` produced no
 * {@link PEFile.certificate} for it — i.e. **the certificate could not be read**,
 * which is a different fact from the file being unsigned.
 *
 * WHY THIS IS DERIVED AND NOT A `PEFile` FLAG, which is the whole decision here
 * (`peek-a-bin-wo8g`, applying `peek-a-bin-dd94`'s criterion: *does the output
 * already carry the fact?*). It does. `parseSecurityDirectory` answers `null`
 * for a declared directory in exactly one circumstance — the `WIN_CERTIFICATE`
 * header does not fit in the file — and `parsePE`'s `catch` around it adds any
 * throw to the same channel; for every other malformation it returns
 * `signed: true` with null fields, which the panel already renders. So
 * "declared, and absent from the parse" **is** the failure, over two fields that
 * are already public, and a flag beside them would be a second declaration that
 * can disagree with the object it describes.
 *
 * The falsehood it removes: `HeaderView` rendered the grey **Unsigned** pill and
 * "No digital signature found in this binary." over an image whose optional
 * header declares an attribute certificate — a positive claim about the FILE
 * standing on the tool's failure to read it. The tool draws that distinction
 * everywhere else (`computeImphash`'s `null`, `ResourceTree.truncated`,
 * `PDB_PATH_TRUNCATION_MARKER`) and erased it here.
 */
export function certificateUnreadable(
  pe: Pick<PEFile, "dataDirectories" | "certificate">,
): boolean {
  return (
    pe.certificate === undefined &&
    directoryDeclared(pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY])
  );
}

/**
 * The file declares a resource directory and `parsePE` produced no
 * {@link PEFile.resources} for it — **the resource directory could not be read**,
 * as against a file that has none.
 *
 * Same channel and same reasoning as {@link certificateUnreadable}: `parsePE`
 * calls `parseResourceDirectory` behind exactly {@link directoryDeclared}, so a
 * missing tree under a declared directory is the reader having failed.
 *
 * **THE POPULATION IS CURRENTLY EMPTY AND THAT IS STATED RATHER THAN IMPLIED.**
 * `parseResourceDirectory` bounds every read on the buffer and recurses to a
 * fixed `MAX_DEPTH`, and an RVA that resolves nowhere returns a tree flagged
 * `truncated` rather than throwing (`peek-a-bin-dhcx`), so no fixture reaches
 * `parsePE`'s `catch` today — a control that proves this arm renders has to
 * build the state directly. It is a guard against that `catch` becoming
 * reachable, not a repair of an observed defect; the certificate half above is
 * the observed one. Without it, the day a reader does throw, the pane says "No
 * resources found in this PE file." and nothing anywhere says otherwise.
 */
export function resourcesUnreadable(pe: Pick<PEFile, "dataDirectories" | "resources">): boolean {
  return (
    pe.resources === undefined &&
    directoryDeclared(pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE])
  );
}
