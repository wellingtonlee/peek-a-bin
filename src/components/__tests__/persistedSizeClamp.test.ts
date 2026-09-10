import { describe, expect, it } from "vitest";
import {
  clampPersistedSize,
  DOCKED_PANEL_HEIGHT_RESERVE,
  SIDEBAR_WIDTH_RESERVE,
} from "../persistedSizeClamp";

/**
 * THE PERSISTED-SIZE CLAMP, as arithmetic — the only part of `peek-a-bin-0tt6`
 * that is verifiable at all.
 *
 * `floatingClamp.test.ts` beside it is the model. jsdom performs no layout and
 * reports every measured extent as 0, so NOTHING here or anywhere else has seen
 * a sidebar be too wide, a listing be squeezed to nothing, or a docked panel
 * overflow its column; the two DOM suites can only check that the components
 * route through this rule and write its answer into an inline style. What the
 * rule IS belongs here, where it needs no render and no drag. Every assertion
 * below is about a number, and is written to say so.
 *
 * The viewport used throughout is jsdom's own 1024x768 — deliberately not
 * square, so an implementation that transposed a width for a height would fail
 * rather than agree.
 */

const VW = 1024;
const VH = 768;

/** The sidebar's own constants (`Sidebar.tsx`). */
const W_MIN = 180;
const W_MAX = 400;

/** The docked bottom panel's own constants (`BottomPanelContainer.tsx`). */
const H_MIN = 80;
const H_MAX = 600;

const width = (stored: number, viewport = VW) =>
  clampPersistedSize(stored, W_MIN, W_MAX, viewport, SIDEBAR_WIDTH_RESERVE);
const height = (stored: number, viewport = VH) =>
  clampPersistedSize(stored, H_MIN, H_MAX, viewport, DOCKED_PANEL_HEIGHT_RESERVE);

describe("the reserves", () => {
  /**
   * Pinned as literals so a change to either sum is a failing test rather than
   * a silent shift in when the clamp starts biting. Both are derived in the
   * module's docstrings; the arithmetic is repeated here, not the reasoning.
   */
  it("are the sums their docstrings derive", () => {
    // 28.5ch of fixed disassembly-grid columns at the 16px maximum mono size
    // (0.6em advance) plus `--row-px` on both sides.
    expect(SIDEBAR_WIDTH_RESERVE).toBe(Math.round(28.5 * 9.6) + 32);
    expect(SIDEBAR_WIDTH_RESERVE).toBe(306);
    // AddressBar (two rows) + toolbar + breadcrumbs + status bar + one row.
    expect(DOCKED_PANEL_HEIGHT_RESERVE).toBe(73 + 31 + 21 + 21 + 20);
    expect(DOCKED_PANEL_HEIGHT_RESERVE).toBe(166);
  });
});

describe("clampPersistedSize", () => {
  it("returns a stored size that already fits EXACTLY unchanged", () => {
    // The ordinary case, and the one that must be inert: on a 1024x768 window
    // neither site's whole range is constrained at all, which is why no
    // existing DOM assertion moves.
    expect(width(224)).toBe(224);
    expect(width(W_MAX)).toBe(W_MAX);
    expect(height(220)).toBe(220);
    expect(height(H_MAX)).toBe(H_MAX);
  });

  it("still enforces the site's own ceiling when the viewport is generous", () => {
    // A stored value above `max` cannot arrive through either loader, but the
    // rule is the third bound and not a replacement for the other two.
    expect(width(5000, 4000)).toBe(W_MAX);
    expect(height(5000, 3000)).toBe(H_MAX);
  });

  it("yields to the viewport once the window cannot afford the preference", () => {
    // Width: 700 - 306 = 394, just under the 400 the user asked for.
    expect(width(W_MAX, 700)).toBe(394);
    // Height: the bead's own case. 768 grants 600; a 700-tall window does not.
    expect(height(H_MAX, 700)).toBe(534);
    expect(height(H_MAX, 500)).toBe(334);
  });

  it("names the boundary where each site's ceiling stops being reachable", () => {
    // Inclusive on the roomy side, so the clamp is provably inert above it.
    expect(width(W_MAX, W_MAX + SIDEBAR_WIDTH_RESERVE)).toBe(W_MAX); // 706
    expect(width(W_MAX, W_MAX + SIDEBAR_WIDTH_RESERVE - 1)).toBe(W_MAX - 1);
    expect(height(H_MAX, H_MAX + DOCKED_PANEL_HEIGHT_RESERVE)).toBe(H_MAX); // 766
    expect(height(H_MAX, H_MAX + DOCKED_PANEL_HEIGHT_RESERVE - 1)).toBe(H_MAX - 1);
  });

  /**
   * THE FLOOR WINS, and it is a named case rather than an accident of
   * `Math.min`/`Math.max` ordering. The two terms genuinely cannot both be
   * satisfied — a 180px minimum sidebar plus a 306px reserve does not fit in a
   * 375px viewport — and yielding to the viewport instead would drive the size
   * to `viewport - reserve`, which reaches zero and then goes negative, leaving
   * an element of no extent that cannot be dragged or grabbed back. Overflowing
   * at the floor is recoverable: the sidebar has a collapse rail and the panel a
   * close button.
   */
  it("honours the floor on a viewport that cannot afford it", () => {
    // 375 - 306 = 69, well under the 180 floor.
    expect(width(W_MAX, 375)).toBe(W_MIN);
    expect(width(W_MIN, 375)).toBe(W_MIN);
    // 200 - 166 = 34, under the 80 floor.
    expect(height(H_MAX, 200)).toBe(H_MIN);
    expect(height(H_MIN, 200)).toBe(H_MIN);
  });

  it("honours the floor even where the reserve alone exceeds the viewport", () => {
    // `viewport - reserve` is NEGATIVE here, which is the arm that would make a
    // viewport-first rule emit a negative CSS length.
    expect(width(W_MAX, 100)).toBe(W_MIN);
    expect(width(W_MAX, 0)).toBe(W_MIN);
    expect(height(H_MAX, 20)).toBe(H_MIN);
    expect(height(H_MAX, 0)).toBe(H_MIN);
    // Never negative and never zero, at any viewport, for either site.
    for (const v of [0, 1, 50, 200, 375, 500, 768, 1024, 4000]) {
      expect(width(W_MAX, v)).toBeGreaterThanOrEqual(W_MIN);
      expect(height(H_MAX, v)).toBeGreaterThanOrEqual(H_MIN);
    }
  });

  it("names the boundary where the floor takes over from the viewport", () => {
    expect(width(W_MAX, W_MIN + SIDEBAR_WIDTH_RESERVE)).toBe(W_MIN); // 486
    expect(width(W_MAX, W_MIN + SIDEBAR_WIDTH_RESERVE + 1)).toBe(W_MIN + 1);
    expect(height(H_MAX, H_MIN + DOCKED_PANEL_HEIGHT_RESERVE)).toBe(H_MIN); // 246
    expect(height(H_MAX, H_MIN + DOCKED_PANEL_HEIGHT_RESERVE + 1)).toBe(H_MIN + 1);
  });

  it("uses the axis it is handed, so the two sites cannot be transposed", () => {
    // A lopsided call: swapping the reserves changes both answers, so a wiring
    // mistake fails here rather than coincidentally agreeing. At viewport 500
    // the width rule gives 194 and the height rule 334.
    expect(clampPersistedSize(W_MAX, W_MIN, W_MAX, 500, SIDEBAR_WIDTH_RESERVE)).toBe(194);
    expect(clampPersistedSize(H_MAX, H_MIN, H_MAX, 500, DOCKED_PANEL_HEIGHT_RESERVE)).toBe(334);
  });

  it("is idempotent — clamping an answer changes nothing", () => {
    // The property the derive-don't-store rule makes unnecessary but which must
    // hold anyway: a render that re-clamps its own output is stable.
    for (const [stored, v] of [
      [W_MAX, 700],
      [W_MAX, 375],
      [224, VW],
      [W_MIN, 0],
    ]) {
      expect(width(width(stored, v), v)).toBe(width(stored, v));
    }
    for (const [stored, v] of [
      [H_MAX, 700],
      [H_MAX, 200],
      [220, VH],
      [H_MIN, 0],
    ]) {
      expect(height(height(stored, v), v)).toBe(height(stored, v));
    }
  });

  it("makes no claim about a fractional or non-finite viewport", () => {
    // `window.innerWidth` is an integer in every engine, but a fractional one
    // passes through the arithmetic rather than being rounded — recorded so a
    // later caller reading a `getBoundingClientRect` knows it must round first.
    expect(width(W_MAX, 700.5)).toBe(394.5);
  });
});
