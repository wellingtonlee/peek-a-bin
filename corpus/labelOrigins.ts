/**
 * WHY EACH `loc_` LABEL IN THE STRUCTURED TREE SURVIVED `pruneLabels`.
 *
 * `structureFrom` puts a label in front of every block it emits and
 * `pruneLabels` then keeps the ones a `goto` names — plus the ones the leftover
 * pass PINNED, which no `goto` names at all: a region the walk reached only by
 * starting afresh at it, whose label is what tells the reader the code above
 * does not fall into it. The emitted C shows a label and not the ground it was
 * kept on, so this reads the structurer's own report (`LabelPruneReport`,
 * carried on the structuring tap) rather than the text.
 *
 * **REPORT-ONLY.** Nothing here is a defect; it is a census that sizes a piece
 * of work. Epic 2's label-note child wants to replace a pinned label with a
 * note, and CLAUDE.md records why that is a fabrication hazard rather than a
 * cosmetic change: `structs.ts`'s `baseGenerations` resets every key at a label
 * NO `goto` names, so deleting one from the IR changes which accesses share a
 * base (docs/decompiler-ir.md). `pinnedOnly` is exactly that population.
 *
 * `seen` is the liveness half and the identity
 * `seen === targetedOnly + pinnedOnly + both + dropped + duplicates` is asserted
 * in the run: a report that does not add up is a broken instrument, not a
 * finding.
 */

import type { LabelPruneReport } from "../src/disasm/decompile/structure";

export interface LabelOriginRec extends LabelPruneReport {
  fn: string;
  addr: number;
}

export interface LabelOriginResult {
  /** Functions whose structuring tap carried a report. Liveness. */
  funcs: number;
  seen: number;
  targetedOnly: number;
  pinnedOnly: number;
  both: number;
  dropped: number;
  duplicates: number;
  /** Functions with at least one label kept ONLY because it was pinned. */
  funcsWithPinnedOnly: number;
  /** Functions whose report did not add up. Expect 0; an instrument failure. */
  inconsistent: number;
  rows: LabelOriginRec[];
}

export const emptyLabelOrigins = (): LabelOriginResult => ({
  funcs: 0,
  seen: 0,
  targetedOnly: 0,
  pinnedOnly: 0,
  both: 0,
  dropped: 0,
  duplicates: 0,
  funcsWithPinnedOnly: 0,
  inconsistent: 0,
  rows: [],
});

export function auditLabelOrigins(
  res: LabelOriginResult,
  fn: string,
  addr: number,
  report: LabelPruneReport | null,
): void {
  if (report === null) return;
  res.funcs++;
  res.seen += report.seen;
  res.targetedOnly += report.targetedOnly;
  res.pinnedOnly += report.pinnedOnly;
  res.both += report.both;
  res.dropped += report.dropped;
  res.duplicates += report.duplicates;
  if (report.pinnedOnly > 0) res.funcsWithPinnedOnly++;
  const sum =
    report.targetedOnly + report.pinnedOnly + report.both + report.dropped + report.duplicates;
  if (sum !== report.seen) res.inconsistent++;
  res.rows.push({ fn, addr, ...report });
}
