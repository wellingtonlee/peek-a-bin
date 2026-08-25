/**
 * WHERE A FLOATING PANEL IS ALLOWED TO BE — the one declaration of the rule,
 * kept out of {@link ./BottomPanelContainer} so it can be stated and tested as
 * arithmetic, with no DOM, no drag and no layout. Three sites position a
 * floating panel (the header drag, the mint in `handlePopOut`, and the
 * derivation that re-places a stored position against the current viewport) and
 * every one of them reads this function rather than re-rolling an inequality.
 *
 * WHAT STAYS REACHABLE, which is the decision rather than the `Math.min`.
 * Clamping the whole panel inside the viewport is the obvious rule and is wrong,
 * and wrong in a way that is arithmetic rather than taste: it makes the bottom
 * bound `viewportHeight - height`, which for a panel taller than the window is
 * NEGATIVE and collides with the top bound, leaving exactly one legal `y` — the
 * panel becomes immovable at the moment it most needs moving. So the quantity
 * kept on screen is a slice of the DRAG HANDLE, whose size is a constant, and
 * the bound is therefore independent of how tall the panel is. That is why this
 * function takes no `height` parameter: the absence is the decision, not an
 * oversight, and adding one would be the first step back to the rule above.
 *
 * PER EDGE, and deliberately asymmetric:
 *
 * - **Top: a hard 0.** The header is flush with the panel's top edge, so *any*
 *   negative `y` eats into the only affordance that can drag the panel back, and
 *   `y = -MIN_VISIBLE_HEADER` removes it outright. No other edge can strand the
 *   panel that cheaply.
 * - **Bottom: `viewportHeight - MIN_VISIBLE_HEADER`.** A band of header stays
 *   above the fold whatever the panel's height is. A short panel may hang most
 *   of its body below the fold under this rule, which is the same answer at
 *   every size and is the point of anchoring on the handle.
 * - **Left and right: `MIN_VISIBLE_EDGE` of the panel's WIDTH stays within the
 *   viewport**, from whichever side it is leaving. The header spans the full
 *   width, so either sliver is grabbable: the left one carries the label and
 *   bare header, the right one the re-dock and close buttons.
 *
 * The bounds are applied upper-first, so on a viewport too small to satisfy both
 * the LOWER bound wins (`Math.max` outermost). That matters only for the
 * vertical pair — a viewport under {@link MIN_VISIBLE_HEADER} pixels tall pins
 * the panel at `y = 0`, i.e. the header at the top edge, rather than above it.
 */

/**
 * How much of the panel's width must remain inside the viewport horizontally.
 *
 * 48px shows and hits either end of the header — the label and its bare grab
 * area on one side, the ↙/✕ buttons on the other — and sits at the conventional
 * ~44-48px floor for a pointer target.
 */
export const MIN_VISIBLE_EDGE = 48;

/**
 * How much of the panel's height must remain inside the viewport at the bottom
 * edge: the header's own nominal height.
 *
 * `px-2 py-1` around a `text-[10px]` line plus a 1px bottom border is ~24px. It
 * is a CONSTANT rather than a measurement for two reasons, both practical: this
 * runs on every `mousemove` of a drag, where reading an element's box would
 * force a layout; and the only environment that runs these tests is jsdom, which
 * performs no layout at all, so a measured value could never be checked here
 * anyway. If the header's padding changes materially, change this with it.
 */
export const MIN_VISIBLE_HEADER = 24;

/** A clamped top-left corner, in the same CSS pixels the caller passed in. */
export interface FloatingPosition {
  x: number;
  y: number;
}

/**
 * Clamp a floating panel's top-left corner so a slice of its drag handle stays
 * reachable. Pure: it reads no `window`, so callers supply the viewport.
 *
 * @param x           proposed left edge, CSS px from the viewport's left
 * @param y           proposed top edge, CSS px from the viewport's top
 * @param width       the panel's width — the horizontal bounds need it, because
 *                    a sliver of the panel's RIGHT edge is what stays visible
 *                    when it leaves to the left
 * @param viewportWidth   `window.innerWidth` at the call site
 * @param viewportHeight  `window.innerHeight` at the call site
 */
export function clampFloatingPosition(
  x: number,
  y: number,
  width: number,
  viewportWidth: number,
  viewportHeight: number,
): FloatingPosition {
  return {
    x: Math.max(MIN_VISIBLE_EDGE - width, Math.min(viewportWidth - MIN_VISIBLE_EDGE, x)),
    y: Math.max(0, Math.min(viewportHeight - MIN_VISIBLE_HEADER, y)),
  };
}
