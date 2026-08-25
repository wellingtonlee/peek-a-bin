import { describe, expect, it } from "vitest";
import { clampFloatingPosition, MIN_VISIBLE_EDGE, MIN_VISIBLE_HEADER } from "../floatingClamp";

/**
 * THE FLOATING-PANEL CLAMP, as arithmetic.
 *
 * This is the primary instrument for `peek-a-bin-goz4`. The DOM suite beside it
 * (`BottomPanels.dom.test.tsx`) checks that the drag, the mint and the restore
 * all route through this rule and write its answer into the inline styles; what
 * the rule IS belongs here, where it needs no render and no drag.
 *
 * The viewport used throughout is jsdom's own 1024x768 — deliberately not
 * square, so an implementation that transposed the two viewport arguments would
 * fail rather than agree.
 */

const VW = 1024;
const VH = 768;
const W = 400;

/** The four bounds, spelled from the constants so a change to one is visible. */
const MAX_X = VW - MIN_VISIBLE_EDGE; // 976
const MIN_X = MIN_VISIBLE_EDGE - W; // -352
const MAX_Y = VH - MIN_VISIBLE_HEADER; // 744
const MIN_Y = 0;

describe("clampFloatingPosition", () => {
  it("leaves a position that is already legal exactly alone", () => {
    expect(clampFloatingPosition(312, 234, W, VW, VH)).toEqual({ x: 312, y: 234 });
  });

  it("keeps a slice of the panel on screen when it leaves to the RIGHT", () => {
    expect(clampFloatingPosition(5000, 100, W, VW, VH)).toEqual({ x: MAX_X, y: 100 });
    // The bound is inclusive: the last legal position is not clamped.
    expect(clampFloatingPosition(MAX_X, 100, W, VW, VH).x).toBe(MAX_X);
    expect(clampFloatingPosition(MAX_X + 1, 100, W, VW, VH).x).toBe(MAX_X);
  });

  it("keeps a slice of the panel on screen when it leaves to the LEFT", () => {
    // Off to the left it is the panel's RIGHT edge that stays visible, which is
    // why the rule needs the width and the vertical half does not need a height.
    expect(clampFloatingPosition(-5000, 100, W, VW, VH)).toEqual({ x: MIN_X, y: 100 });
    expect(clampFloatingPosition(MIN_X - 1, 100, W, VW, VH).x).toBe(MIN_X);
  });

  it("scales the left bound with the panel's own width", () => {
    // A 200px panel (the corner-resize floor) may go 152px off the left; a
    // 400px one may go 352px. Both leave MIN_VISIBLE_EDGE on screen.
    expect(clampFloatingPosition(-5000, 0, 200, VW, VH).x).toBe(MIN_VISIBLE_EDGE - 200);
    expect(clampFloatingPosition(-5000, 0, 400, VW, VH).x).toBe(MIN_VISIBLE_EDGE - 400);
  });

  it("stops the header at the BOTTOM edge with a band still above the fold", () => {
    expect(clampFloatingPosition(100, 5000, W, VW, VH)).toEqual({ x: 100, y: MAX_Y });
    expect(clampFloatingPosition(100, MAX_Y, W, VW, VH).y).toBe(MAX_Y);
  });

  /**
   * The TOP is a hard zero and not a slice, because the header is flush with the
   * panel's top edge: a negative `y` eats the only affordance that can drag the
   * panel back, and `-MIN_VISIBLE_HEADER` removes it outright. This asymmetry is
   * the whole reason the rule is per-edge.
   */
  it("refuses any negative y at all", () => {
    expect(clampFloatingPosition(100, -1, W, VW, VH).y).toBe(MIN_Y);
    expect(clampFloatingPosition(100, -5000, W, VW, VH).y).toBe(MIN_Y);
    expect(clampFloatingPosition(100, 0, W, VW, VH).y).toBe(0);
  });

  /**
   * THE PROPERTY THE REJECTED RULE FAILS. "Keep the whole panel inside the
   * viewport" makes the bottom bound `viewportHeight - height`; for a panel
   * taller than the window that is negative, collides with the top bound, and
   * leaves exactly ONE legal y — the panel is pinned at the moment it most needs
   * moving. Anchoring on the handle instead makes the vertical range depend on
   * the viewport alone, which is why this function takes no height at all.
   */
  it("still gives a panel TALLER than the viewport somewhere to go", () => {
    const shortVH = 200; // a 300-tall panel does not fit
    const range = [0, 50, 176, 5000].map((y) => clampFloatingPosition(0, y, W, VW, shortVH).y);
    expect(range).toEqual([0, 50, shortVH - MIN_VISIBLE_HEADER, shortVH - MIN_VISIBLE_HEADER]);
    // Distinct inputs still reach distinct positions: it can be moved.
    expect(new Set(range).size).toBeGreaterThan(1);
  });

  it("uses the viewport's WIDTH for x and its HEIGHT for y", () => {
    // A deliberately lopsided viewport: transposing the two arguments changes
    // both answers, so this fails rather than coincidentally agreeing.
    const wide = clampFloatingPosition(5000, 5000, W, 1000, 100);
    expect(wide).toEqual({ x: 1000 - MIN_VISIBLE_EDGE, y: 100 - MIN_VISIBLE_HEADER });
  });

  /**
   * On a viewport too small to satisfy both vertical bounds the LOWER one wins,
   * because `Math.max` is outermost. The header ends up at the very top edge
   * rather than above it — the failure that is still recoverable.
   */
  it("pins the header to the top edge on a viewport shorter than the slice", () => {
    expect(clampFloatingPosition(0, 500, W, VW, MIN_VISIBLE_HEADER - 1).y).toBe(0);
    expect(clampFloatingPosition(0, -500, W, VW, 0).y).toBe(0);
  });

  it("survives a viewport narrower than the slice it wants to keep", () => {
    // maxX goes negative (10 - 48); minX is -352, so the range is still real and
    // the panel is pushed left until 48px of its right edge is at the screen.
    expect(clampFloatingPosition(5000, 0, W, 10, VH).x).toBe(10 - MIN_VISIBLE_EDGE);
  });

  it("is idempotent — clamping an answer changes nothing", () => {
    for (const [x, y] of [
      [5000, 5000],
      [-5000, -5000],
      [312, 234],
      [-5000, 5000],
    ]) {
      const once = clampFloatingPosition(x, y, W, VW, VH);
      expect(clampFloatingPosition(once.x, once.y, W, VW, VH)).toEqual(once);
    }
  });
});
