/**
 * WHICH OF TWO OVERLAPPING READINGS OF A BASE'S BYTES BECAME A FIELD.
 *
 * `candidateFields` (`src/disasm/decompile/structs.ts`) settles a base's
 * accesses in two steps, and both discard a directly observed reading:
 *
 * 1. **Same offset, widest wins.** Two accesses at one offset are one field of
 *    the wider width, so a byte read of a slot also read as a word contributes
 *    nothing. That is deliberate — the width is a direct measurement of one
 *    access (`peek-a-bin-hyv`).
 * 2. **Overlapping extents, first by offset wins.** What survives step 1 can
 *    still contradict itself: an 8-byte access at 0 and a 2-byte access at 2 are
 *    two readings of the same bytes and at most one is a member. The later one
 *    is not made a field and its access stays as byte arithmetic.
 *
 * Neither side of either decision is recoverable from the emitted C. The
 * declaration shows the winner; it does not say that there was a choice, what
 * the alternative was, or that a narrower reading of the same offset was seen
 * and dropped. So no standing instrument can see this class, and none of them
 * is even close: `offsetof` compiles and runs the declaration, which checks that
 * it is SELF-CONSISTENT and cannot see a wrong identity (CLAUDE.md says this in
 * stronger terms for a different question); `memberNameAgreement` sees a name
 * disagreeing with its own brackets; `gcc` compiles any layout; polarity,
 * `staleReads`, `staleGuards` and `lostDefs` are all indifferent to a field's
 * provenance. The oracle for a wrong reading is the emitted C read against
 * `objdump` by hand, which is how the verdict below was reached.
 *
 * WHAT IT IS INDEPENDENT OF. `StructGroupReport` carries the RAW accesses, not
 * the fields the rule chose, and this file re-derives step 1 and step 2 for
 * itself from the extents. It is therefore a differential test — the rule
 * written twice, once in `structs.ts` and once here — with the status
 * `crossEdgeGuards`' `admitted` count has, rather than a readout of the rule
 * against itself. `maximal` goes further and asks a question `structs.ts` never
 * asks at all: is first-by-offset's selection of maximum cardinality over the
 * same extents, computed by exhaustive search rather than by a sweep.
 *
 * REPORT-ONLY IN EVERY COLUMN, AND THAT IS A JUDGEMENT RATHER THAN CAUTION.
 * Nothing here is provably a defect in either direction, which is what
 * separates it from `wildBranches` or `arity over`:
 *
 * - A **non-maximal** selection is not automatically wrong. The wide access it
 *   kept is a real measurement, and a bulk word store really can be one member.
 * - A **maximal** one is not automatically right. Measured at `f3b89ec`, the
 *   `field_0x1F`/`field_0x2F` rows below are maximum-cardinality AND wrong:
 *   adjudicated against the CRT `ioinfo` layout, the object has a one-byte
 *   bitfield member there followed by a two-byte `pipech2[2]`, and the emitted
 *   two-byte field spans one of each. The correct pair is fully present in the
 *   accesses and was lost at step 1, not step 2.
 * - Every absolute here moves with function detection and with struct recovery,
 *   both of which move often.
 *
 * What it buys is that a change in this population is a ROW rather than
 * something the next agent has to think to measure — which is the whole of
 * `peek-a-bin-k6hh`, whose single count ("all nine overlaps") sat unstamped for
 * ten days and, when finally re-derived, turned out to be describing half its
 * own population. `groups` is the liveness half: a text- or structure-scraping
 * audit fails by silently matching nothing.
 */

import type { StructGroupReport } from "../src/disasm/decompile/structs";

/** One extent: an offset and the width read there. */
type Extent = [offset: number, size: number];

/** One overlap the first-by-offset rule settled. */
export interface StructOverlapRec {
  bin: string;
  func: string;
  funcAddr: number;
  /** Canonical base key — see `exprKey`. */
  base: string;
  /** Every extent surviving step 1, as `0xOFF:SIZE`, in offset order. */
  extents: string;
  keptOffset: number;
  keptSize: number;
  dropOffset: number;
  dropSize: number;
  /** The dropped extent lies wholly inside the kept one. */
  contained: boolean;
  /** first-by-offset's whole selection is of maximum cardinality. */
  maximal: boolean;
  /** More than one maximum-cardinality selection exists — the order-dependence
   *  is LIVE at this base rather than merely present. */
  ambiguous: boolean;
  /**
   * A strictly narrower access WAS observed at the kept offset, and it does not
   * reach the dropped extent — so step 1 is what created this overlap, and
   * keeping the narrower reading would have let both survive. This is the column
   * the hand adjudication found the wrong readings in.
   */
  narrowerAtKept: number | null;
  /** Fields `candidateFields` returned. Under 2 the base is no struct candidate,
   *  so the row never reaches a declaration. */
  fields: number;
}

export interface StructOverlapResult {
  rows: StructOverlapRec[];
  /** Groups reaching `candidateFields`. The liveness half. */
  groups: number;
  /** Of those, groups supporting two or more fields. */
  candidates: number;
  /** Distinct offsets across all groups, after step 1. */
  extents: number;
  /** Rows whose dropped extent is inside the kept one. */
  contained: number;
  /** Rows whose dropped extent runs past the kept one's end. */
  partial: number;
  /** Rows where first-by-offset's selection is NOT maximum-cardinality. */
  notMaximal: number;
  /** Rows at a base with more than one maximum-cardinality selection. */
  ambiguous: number;
  /** Rows where step 1 discarded a narrower reading that would not overlap. */
  narrowedOut: number;
  /** Rows in a group that is a struct candidate, i.e. that reach a declaration. */
  reaching: number;
}

export const emptyStructOverlaps = (): StructOverlapResult => ({
  rows: [],
  groups: 0,
  candidates: 0,
  extents: 0,
  contained: 0,
  partial: 0,
  notMaximal: 0,
  ambiguous: 0,
  narrowedOut: 0,
  reaching: 0,
});

/**
 * Step 1, re-derived: one extent per offset, of the widest access seen there.
 * Also returns, per offset, every distinct width observed — which is what makes
 * `narrowerAtKept` answerable and is exactly the evidence step 1 throws away.
 */
function widestPerOffset(accesses: StructGroupReport["accesses"]): {
  extents: Extent[];
  widths: Map<number, number[]>;
} {
  const widths = new Map<number, number[]>();
  for (const a of accesses) {
    const seen = widths.get(a.offset);
    if (seen) {
      if (!seen.includes(a.size)) seen.push(a.size);
    } else widths.set(a.offset, [a.size]);
  }
  const extents: Extent[] = [];
  for (const [offset, ws] of widths) extents.push([offset, Math.max(...ws)]);
  extents.sort((a, b) => a[0] - b[0]);
  for (const ws of widths.values()) ws.sort((a, b) => a - b);
  return { extents, widths };
}

/**
 * Step 2, re-derived: the sweep `candidateFields` performs, reported as which
 * extents it kept and, for each one it dropped, which kept extent shadowed it.
 */
function firstByOffset(extents: Extent[]): { kept: Extent[]; dropped: [Extent, Extent][] } {
  const kept: Extent[] = [];
  const dropped: [Extent, Extent][] = [];
  let end = 0;
  for (const e of extents) {
    if (e[0] < end) {
      dropped.push([kept[kept.length - 1], e]);
      continue;
    }
    kept.push(e);
    end = e[0] + e[1];
  }
  return { kept, dropped };
}

/**
 * The largest number of these extents that can coexist without overlapping, and
 * whether more than one selection achieves it.
 *
 * Exhaustive over the extents of one base, which is a handful — the largest
 * group in this corpus has seven. Deliberately NOT the sweep `structs.ts` runs:
 * an audit that computed the answer the same way could only ever agree.
 */
function maxSelection(extents: Extent[]): { size: number; solutions: number } {
  const memo = new Map<number, { size: number; solutions: number }>();
  function go(i: number): { size: number; solutions: number } {
    if (i >= extents.length) return { size: 0, solutions: 1 };
    const hit = memo.get(i);
    if (hit) return hit;
    const skip = go(i + 1);
    let j = i + 1;
    while (j < extents.length && extents[j][0] < extents[i][0] + extents[i][1]) j++;
    const inner = go(j);
    const take = { size: inner.size + 1, solutions: inner.solutions };
    const out =
      take.size > skip.size
        ? take
        : skip.size > take.size
          ? skip
          : { size: take.size, solutions: take.solutions + skip.solutions };
    memo.set(i, out);
    return out;
  }
  return go(0);
}

/** Judge one binary's groups. Called once per `synthesizeStructs` group. */
export function auditStructOverlaps(
  out: StructOverlapResult,
  bin: string,
  g: StructGroupReport,
): void {
  const { extents, widths } = widestPerOffset(g.accesses);
  out.groups++;
  out.extents += extents.length;
  if (g.fields >= 2) out.candidates++;

  const { kept, dropped } = firstByOffset(extents);
  if (dropped.length === 0) return;

  const best = maxSelection(extents);
  const maximal = kept.length >= best.size;
  const ambiguous = best.solutions > 1;
  const spelled = extents.map(([o, s]) => `0x${o.toString(16).toUpperCase()}:${s}`).join(" ");

  for (const [keeper, drop] of dropped) {
    const contained = drop[0] + drop[1] <= keeper[0] + keeper[1];
    // A narrower reading of the KEPT offset that stops before the dropped one
    // begins. `widths` is sorted, so the widest such is the last that fits.
    const narrower =
      widths
        .get(keeper[0])
        ?.filter((w) => w < keeper[1] && keeper[0] + w <= drop[0])
        .pop() ?? null;
    out.rows.push({
      bin,
      func: g.func,
      funcAddr: g.funcAddr,
      base: g.baseKey,
      extents: spelled,
      keptOffset: keeper[0],
      keptSize: keeper[1],
      dropOffset: drop[0],
      dropSize: drop[1],
      contained,
      maximal,
      ambiguous,
      narrowerAtKept: narrower,
      fields: g.fields,
    });
    if (contained) out.contained++;
    else out.partial++;
    if (!maximal) out.notMaximal++;
    if (ambiguous) out.ambiguous++;
    if (narrower !== null) out.narrowedOut++;
    if (g.fields >= 2) out.reaching++;
  }
}
