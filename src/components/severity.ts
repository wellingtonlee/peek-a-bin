import type { Anomaly } from "../analysis/anomalies";
import type { AIScanFinding } from "../llm/types";

/**
 * The one declaration of how a severity ranks, for the two unions that have one.
 *
 * THE PROBLEM THIS SOLVES is not that the two vocabularies should be merged —
 * they should not. `Anomaly["severity"]` has three members and
 * `AIScanFinding["severity"]` has five and no `warning`, and both are right for
 * what they describe. The problem is that three sites had each written their own
 * predicate over them: `AnomaliesView`'s two palettes (converted to declared
 * `Record`s last session) and `AddressBar`'s tab badge, which reduces BOTH lists
 * at once to their worst member with a hand-written
 * `severity === "critical" || severity === "high"` chain over a third palette.
 * The chain is the shape `peek-a-bin-n7q1` shipped: five sites spelling one
 * predicate by hand, the fifth missed, and one notice rendering amber and red at
 * the same time. A new member of either union joins a chain like that on
 * whichever side the author of the chain happened to leave open — silently.
 *
 * SO WHAT IS SHARED IS THE MAPPING AND THE ORDER, NOT THE PALETTE. Each union
 * member is mapped onto a {@link BadgeLevel} — the three-way scale the UI
 * actually paints — and the class names stay at the sites, because they really
 * do differ: `AnomaliesView` paints a table row (`-900/20` background, `-300`
 * text, `-600` badge) and `AddressBar` paints an 8px dot (`-500`). Both keep
 * `Record<BadgeLevel, …>` tables, so a fourth level would fail the build in both
 * places, and the union-to-level maps below fail the build on a fourth anomaly
 * severity or a sixth finding severity.
 *
 * THE TWO LOOKUPS ARE DELIBERATELY RAW `Record`s RATHER THAN FUNCTIONS WITH A
 * FALLBACK, because the three call sites want three different things from an
 * unknown value — one that reaches `AppState` over the MCP wire or out of a
 * stale snapshot, past the type system. `AnomaliesView`'s sort wants it last
 * (`?? 9`), its palette wants it blue (`?? info`), and {@link maxBadgeLevel}
 * treats it as the mildest level, since a badge that shouted about a severity
 * nothing recognises would be a false alarm. Folding those into one fallback
 * here would quietly change the sort — `AnomaliesView.dom.test.tsx` pins the
 * unknown row sorting behind even `info`.
 */
export type BadgeLevel = "critical" | "warning" | "info";

/** Ascending: 0 is the most severe, which is the order these are read in. */
export const BADGE_RANK: Record<BadgeLevel, number> = { critical: 0, warning: 1, info: 2 };

/** Identity today, and typed so it cannot stop being total. */
export const ANOMALY_BADGE: Record<Anomaly["severity"], BadgeLevel> = {
  critical: "critical",
  warning: "warning",
  info: "info",
};

/**
 * The five-member scale folded onto the three-member one. `high` reads as
 * critical and `medium` as warning, which is what all three sites already did.
 */
export const FINDING_BADGE: Record<AIScanFinding["severity"], BadgeLevel> = {
  critical: "critical",
  high: "critical",
  medium: "warning",
  low: "info",
  info: "info",
};

/**
 * The worst level across both lists, or `null` when there is nothing to report.
 *
 * `null` rather than `"info"`: "no findings" and "only mild findings" are
 * different facts, and the tab badge is not rendered at all for the first.
 */
export function maxBadgeLevel(
  anomalies: readonly Anomaly[],
  findings: readonly AIScanFinding[],
): BadgeLevel | null {
  let worst: BadgeLevel | null = null;
  const consider = (level: BadgeLevel) => {
    if (worst === null || BADGE_RANK[level] < BADGE_RANK[worst]) worst = level;
  };
  for (const a of anomalies) consider(ANOMALY_BADGE[a.severity] ?? "info");
  for (const f of findings) consider(FINDING_BADGE[f.severity] ?? "info");
  return worst;
}
