/**
 * The shared severity ordering, and the reduction the tab badge is built on.
 *
 * WHY A PURE SUITE AT ALL when both readers have DOM tests: the reduction is
 * over TWO lists with DIFFERENT vocabularies, and the interesting cases are
 * combinations — an `info` anomaly beside a `high` finding, a `medium` finding
 * beside a `warning` anomaly — which a render test can only reach one at a time
 * and at ~2s of jsdom apiece. The DOM half is still needed and is in
 * `AddressBar.dom.test.tsx`: it is what checks the answer reaches the page as a
 * colour, which no test over plain data can see.
 *
 * The exhaustive tables below are written out rather than derived. A test that
 * recomputes the mapping agrees with any change to it, including a wrong one —
 * which is the whole failure mode a declared `Record` exists to prevent, so
 * reintroducing it in the test would be pointless.
 */

import { describe, expect, it } from "vitest";
import type { Anomaly } from "../../analysis/anomalies";
import type { AIScanFinding } from "../../llm/types";
import {
  ANOMALY_BADGE,
  BADGE_RANK,
  type BadgeLevel,
  FINDING_BADGE,
  maxBadgeLevel,
} from "../severity";

const anomaly = (severity: Anomaly["severity"]): Anomaly => ({
  severity,
  title: severity,
  detail: "",
});

const finding = (severity: AIScanFinding["severity"]): AIScanFinding => ({
  severity,
  title: severity,
  description: "",
  functionAddress: 0x1000,
  functionName: "sub_1000",
  remediation: "",
  source: "ai-scan",
});

describe("the severity → level tables", () => {
  it.each([
    ["critical", "critical"],
    ["warning", "warning"],
    ["info", "info"],
  ] as [Anomaly["severity"], BadgeLevel][])("maps anomaly %s to %s", (severity, level) => {
    expect(ANOMALY_BADGE[severity]).toBe(level);
  });

  it.each([
    ["critical", "critical"],
    // `high` is red and `medium` amber — the fold that used to be written out
    // three times, twice as a table and once as a predicate chain.
    ["high", "critical"],
    ["medium", "warning"],
    ["low", "info"],
    ["info", "info"],
  ] as [AIScanFinding["severity"], BadgeLevel][])("maps finding %s to %s", (severity, level) => {
    expect(FINDING_BADGE[severity]).toBe(level);
  });

  it("ranks the levels in the order they are read", () => {
    expect(BADGE_RANK.critical).toBeLessThan(BADGE_RANK.warning);
    expect(BADGE_RANK.warning).toBeLessThan(BADGE_RANK.info);
  });

  it("covers both unions with no level outside the three", () => {
    // The liveness half: a table that quietly lost an entry would make every
    // lookup above `undefined`, and `maxBadgeLevel`'s `?? "info"` would hide it.
    const levels: BadgeLevel[] = ["critical", "warning", "info"];
    for (const v of Object.values(ANOMALY_BADGE)) expect(levels).toContain(v);
    for (const v of Object.values(FINDING_BADGE)) expect(levels).toContain(v);
    expect(Object.keys(ANOMALY_BADGE)).toHaveLength(3);
    expect(Object.keys(FINDING_BADGE)).toHaveLength(5);
  });
});

describe("maxBadgeLevel", () => {
  it("says nothing when there is nothing to report", () => {
    // `null`, not `"info"`: "no findings" and "only mild findings" are different
    // facts, and the badge is not rendered at all for the first.
    expect(maxBadgeLevel([], [])).toBeNull();
  });

  it("takes the worst within one list", () => {
    expect(maxBadgeLevel([anomaly("info"), anomaly("critical"), anomaly("warning")], [])).toBe(
      "critical",
    );
    expect(maxBadgeLevel([anomaly("info"), anomaly("warning")], [])).toBe("warning");
    expect(maxBadgeLevel([anomaly("info")], [])).toBe("info");
  });

  it("takes the worst ACROSS the two lists, which is the whole reason it exists", () => {
    // Each of these is a case the reduction gets wrong if it reads one list, or
    // if one union's fold disagrees with the other's.
    expect(maxBadgeLevel([anomaly("info")], [finding("high")])).toBe("critical");
    expect(maxBadgeLevel([anomaly("warning")], [finding("low")])).toBe("warning");
    expect(maxBadgeLevel([anomaly("info")], [finding("medium")])).toBe("warning");
    expect(maxBadgeLevel([anomaly("critical")], [finding("info")])).toBe("critical");
    expect(maxBadgeLevel([], [finding("info"), finding("low")])).toBe("info");
  });

  it("is not fooled by order", () => {
    // The reduction keeps a running worst, so a critical arriving last must not
    // be lost — and the two loops run one list then the other, so the critical
    // being in the SECOND list is the case a `break` in the wrong place breaks.
    expect(maxBadgeLevel([anomaly("info"), anomaly("critical")], [])).toBe("critical");
    expect(maxBadgeLevel([anomaly("critical"), anomaly("info")], [])).toBe("critical");
    expect(maxBadgeLevel([anomaly("info")], [finding("low"), finding("critical")])).toBe(
      "critical",
    );
  });

  it("treats a severity from outside the type system as the mildest", () => {
    // The MCP wire and a restored snapshot can both put one in `AppState`. A
    // badge that shouted about a severity nothing recognises would be a false
    // alarm, so unknown reads as `info` HERE — deliberately a different fallback
    // from `AnomaliesView`'s sort, which puts unknown last. That is why
    // `severity.ts` exports raw lookups instead of one total function.
    const rogue = { severity: "fatal", title: "x", detail: "" } as unknown as Anomaly;
    expect(maxBadgeLevel([rogue], [])).toBe("info");
    expect(maxBadgeLevel([rogue, anomaly("warning")], [])).toBe("warning");
  });
});
