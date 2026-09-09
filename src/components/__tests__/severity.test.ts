/**
 * The anomaly severity → level mapping and the order it is read in.
 *
 * WHY A PURE SUITE AT ALL, and the honest answer is that the argument is
 * thinner than it was. This file used to justify itself on combinations: the
 * reduction it covered folded TWO unions with different vocabularies and took a
 * maximum across two lists, so the interesting cases were pairs — an `info`
 * anomaly beside a `high` finding — which a render test can only reach one at a
 * time and at ~2s of jsdom apiece. The AI scanner and the Anomalies tab are
 * gone, `FINDING_BADGE` and `maxBadgeLevel` with them, and what is left is two
 * small tables with a single reader.
 *
 * SO WHAT THESE ROWS STILL BUY is exhaustiveness and totality — that every
 * member maps somewhere, that nothing maps outside the three levels, and that
 * the rank orders them the way a reader expects — asked of the data rather than
 * of a rendered page, where each case would cost a jsdom mount. The behaviour
 * that only exists on screen is `HeaderView.dom.test.tsx`'s: the three palettes
 * being distinguishable, and a severity from outside the type system rendering
 * blue instead of vanishing. That fallback lives at the read site now, so it is
 * tested there and deliberately not here.
 *
 * The exhaustive tables below are written out rather than derived. A test that
 * recomputes the mapping agrees with any change to it, including a wrong one —
 * which is the whole failure mode a declared `Record` exists to prevent, so
 * reintroducing it in the test would be pointless.
 */

import { describe, expect, it } from "vitest";
import type { Anomaly } from "../../analysis/anomalies";
import { ANOMALY_BADGE, BADGE_RANK, type BadgeLevel } from "../severity";

describe("the severity → level table", () => {
  it.each([
    ["critical", "critical"],
    ["warning", "warning"],
    ["info", "info"],
  ] as [Anomaly["severity"], BadgeLevel][])("maps anomaly %s to %s", (severity, level) => {
    expect(ANOMALY_BADGE[severity]).toBe(level);
  });

  it("ranks the levels in the order they are read", () => {
    expect(BADGE_RANK.critical).toBeLessThan(BADGE_RANK.warning);
    expect(BADGE_RANK.warning).toBeLessThan(BADGE_RANK.info);
  });

  it("covers the union with no level outside the three", () => {
    // The liveness half: a table that quietly lost an entry would make its
    // lookup `undefined`, and `AnomalyBanners`' `?? "info"` would hide it by
    // painting the row blue — present, but in the wrong colour.
    const levels: BadgeLevel[] = ["critical", "warning", "info"];
    for (const v of Object.values(ANOMALY_BADGE)) expect(levels).toContain(v);
    expect(Object.keys(ANOMALY_BADGE)).toHaveLength(3);
    expect(Object.keys(BADGE_RANK)).toHaveLength(3);
  });
});
