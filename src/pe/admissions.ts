import { certificateUnreadable, dataDirectoryClamp, resourcesUnreadable } from "./dataDirectories";
import type { PEFile } from "./types";

/**
 * What part of the file the parse fell short on. A closed union, so a consumer
 * that places admissions by section (the markdown report does) fails to compile
 * when a new one is added rather than dropping it.
 */
export type AdmissionSubject =
  | "imports"
  | "exports"
  | "resources"
  | "certificate"
  | "data-directories";

export interface ParseAdmission {
  subject: AdmissionSubject;
  /**
   * One self-contained sentence, safe to print verbatim into JSON or a markdown
   * table cell (no pipes, no newlines).
   *
   * IT IS PROSE RATHER THAN A CODE, and that is the whole design. The consumers
   * are an **LLM** reading an MCP response and a **human** reading an exported
   * file months later; neither can be relied on to know what a `truncated: true`
   * means, and an LLM in particular has no way at all to notice that a count
   * looks small. So the value carries the fact, on
   * {@link TRUNCATION_MARKER}'s model: a consumer that has never heard of the
   * field still cannot be fooled by it, and one that has can key off the
   * `subject`.
   */
  sentence: string;
}

/**
 * Everything `parsePE` narrowed, clamped or gave up on, as sentences.
 *
 * WHY THIS EXISTS AT ALL, given that every fact below is already a public field
 * or a one-line predicate: the browser has a render site per fact — the Imports
 * tab's counts, the Resources pane's heading, the signature pill, the Headers
 * panel's row — and each is worded for the pane it sits in. The two surfaces
 * that OUTLIVE THE SESSION have no panes: an MCP answer is consumed by something
 * that cannot ask a follow-up question, and an exported report is a file the user
 * keeps and may compare against another tool later. Three call sites would
 * otherwise each write their own prose for the same five facts
 * (`peek-a-bin-8pod`).
 *
 * WHY IT IS NOT `analysis/anomalies.ts`, which reports two of these already. That
 * pass answers "what about this file should an analyst look at", carries a
 * severity, and includes findings that are nothing to do with the parse (WX
 * sections, entropy, an entry point in writable memory). This answers "how much
 * of what you are reading is actually there", and its consumers are formats
 * rather than a screen. The overlap is two *sentences*, not a predicate: both
 * read `certificateUnreadable` / `resourcesUnreadable`, which are the single
 * declaration either way.
 *
 * **EMPTY MEANS THE PARSE WAS WHOLE**, so a caller may test `length` — the array
 * is never populated with "everything is fine" rows.
 *
 * NOT COVERED, and stated rather than implied: `extractStrings`' per-call
 * `MAX_STRING_SCAN_BYTES` budget (the string map carries no flag at all, and
 * plumbing one would cross a worker RPC and `AppState`), `parseDebugDirectory`'s
 * `DebugDirectory.truncated` and `DebugInfo.pdbPathTruncated` (that reader is
 * called separately, by the one panel that renders it, and reaches neither
 * consumer here), the 256-callback TLS cap, and every `authenticode.ts`
 * narrowing (a chain read as one certificate, a DN read as a CN).
 */
export function parseAdmissions(pe: PEFile): ParseAdmission[] {
  const out: ParseAdmission[] = [];

  if (pe.importsTruncated) {
    const functions = pe.imports.reduce((n, imp) => n + imp.functions.length, 0);
    out.push({
      subject: "imports",
      sentence:
        `The import table was not read whole: a walk stopped at a bound rather than at its ` +
        `terminator, or a name ran past the length this parser will read. The ` +
        `${pe.imports.length} ${pe.imports.length === 1 ? "library" : "libraries"} and ` +
        `${functions} imported ${functions === 1 ? "name" : "names"} reported are a LOWER ` +
        `BOUND, and imphash is withheld for this file because a digest over a short list ` +
        `would be well-formed and wrong.`,
    });
  }

  if (pe.exportsTruncated) {
    out.push({
      subject: "exports",
      sentence:
        `The export table was not read whole: a name-pointer, ordinal or address-table walk ` +
        `stopped at a bound rather than at its declared count, or an export name ran past the ` +
        `length this parser will read. The ${pe.exports.length} ` +
        `${pe.exports.length === 1 ? "export" : "exports"} reported are a LOWER BOUND.`,
    });
  }

  // The two resource facts are mutually exclusive and are different sizes of
  // admission: one has a tree that is short, the other has no tree at all.
  if (resourcesUnreadable(pe)) {
    out.push({
      subject: "resources",
      sentence:
        "The file declares a resource directory that could not be read at all, so nothing " +
        "here describes its contents — which is not the same as the file having no resources.",
    });
  } else if (pe.resources?.truncated) {
    out.push({
      subject: "resources",
      sentence:
        `The resource directory walk did not cover every entry the file declares — it stopped ` +
        `at its entry budget, or where the directory runs past the end of the file. The ` +
        `${pe.resources.entries.length} ` +
        `${pe.resources.entries.length === 1 ? "entry" : "entries"} recovered are a LOWER BOUND.`,
    });
  }

  if (certificateUnreadable(pe)) {
    out.push({
      subject: "certificate",
      sentence:
        "The file declares a certificate table that could not be read, so this image is NOT " +
        "known to be unsigned — the certificate lies outside the file, or its structure did " +
        "not parse.",
    });
  }

  const clamp = dataDirectoryClamp(pe);
  if (clamp) {
    out.push({
      subject: "data-directories",
      sentence:
        clamp.reason === "short-header"
          ? `The optional header declares ${clamp.declared} data directories but the file ends ` +
            `after ${clamp.present}, so the header is truncated and any directory past ` +
            `${clamp.present} is not in the file at all.`
          : `The optional header declares ${clamp.declared} data directories where the PE format ` +
            `defines 16, so ${clamp.present} were read and the rest ignored.`,
    });
  }

  return out;
}
