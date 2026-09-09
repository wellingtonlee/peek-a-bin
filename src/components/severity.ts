import type { Anomaly } from "../analysis/anomalies";

/**
 * The one declaration of how an anomaly severity ranks and which of the three
 * levels the UI paints it as.
 *
 * THE HISTORY IS THE ARGUMENT. `peek-a-bin-n7q1` was five sites spelling one
 * predicate by hand, the fifth missed, so one notice rendered amber in the
 * status bar and red in the banner at the same time. `peek-a-bin-p0qw` found
 * the same shape twice more in `AnomaliesView`, whose severity tables were
 * keyed `Record<string, …>` — so a fourth severity would have compiled, sorted
 * last and rendered in `info`'s blue. `peek-a-bin-rl95` is what this module
 * became: the order declared once, the palettes left at their sites.
 *
 * WHAT IS LEFT OF THAT QUESTION IN THIS APP IS SMALLER, AND THIS MODULE IS
 * SMALLER WITH IT. The AI vulnerability scanner and the Anomalies tab are gone,
 * so `AIScanFinding` no longer exists, the fold of a five-member union onto a
 * three-member one has nothing to fold, and "the worst level across two lists"
 * is a question nothing asks. `FINDING_BADGE` and `maxBadgeLevel` were deleted
 * rather than kept warm.
 *
 * ONE SURFACE SURVIVES AND IT WAS NEVER IN THAT CHAIN. `HeaderView`'s
 * `AnomalyBanners` is now the only place that paints and orders anomaly
 * severities, and it carried a FOURTH hand-written palette — an untyped object
 * literal beside a hand-typed `["critical","warning","info"]` order array —
 * that none of the three beads above ever reached. It was strictly worse than
 * what `p0qw` closed: an unknown severity matched no entry in that order array
 * and was dropped from the page entirely, where `AnomaliesView` at least
 * rendered the row in blue. Keying its palette on {@link BadgeLevel} and
 * deriving its order from {@link BADGE_RANK} is what makes a fourth
 * `Anomaly["severity"]` a build error there instead of a silent omission.
 *
 * THE PALETTE IS STILL NOT SHARED, deliberately: what belongs here is the
 * mapping and the order, and the class names belong at the site that paints
 * them. There is one painter today, but a second would legitimately differ —
 * a table row (`-900/20` background, `-300` text) and an 8px dot (`-500`) are
 * not the same colours — and the reason `rl95` split them has not changed.
 *
 * {@link ANOMALY_BADGE} IS A RAW `Record` RATHER THAN A TOTAL FUNCTION, so the
 * fallback for a value that reaches `AppState` over the MCP wire or out of a
 * stale snapshot, past the type system, stays visible at the read site. There
 * is one such read site and it wants blue (`?? "info"`), because an unknown
 * severity is a thing to show, not a thing to shout about; when there were
 * three sites they wanted three different things from it, which is why folding
 * a fallback in here was refused then and is not worth doing now.
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
