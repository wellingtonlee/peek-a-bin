/**
 * HOW LARGE A PERSISTED, USER-CHOSEN SIZE MAY BE, GIVEN THE VIEWPORT — the one
 * declaration of the rule, kept out of {@link ./Sidebar} and
 * {@link ./BottomPanelContainer} so it can be stated and tested as arithmetic,
 * with no DOM, no drag and no layout. Same shape and same reasons as
 * {@link ./floatingClamp}, which owns the neighbouring question ("where may a
 * floating panel BE") and is deliberately a different function: that one
 * anchors on a constant slice of a drag handle and therefore takes no size at
 * all, where this one is *about* the size.
 *
 * THE DEFECT IT CLOSES. Two sites persist a dragged pixel size to localStorage
 * and restore it clamped against a pair of COMPILE-TIME CONSTANTS alone —
 * `[MIN_WIDTH, MAX_WIDTH]` for the sidebar, `[MIN_HEIGHT, MAX_HEIGHT]` for the
 * docked bottom panel. Neither consulted the viewport and neither re-derived on
 * a window resize, so a size chosen on a large display was restored verbatim
 * into a small window and the user's own preference became the thing that made
 * the app unusable: at a 400px viewport height a stored 600px panel is taller
 * than the window it is in.
 *
 * THE ANSWER IS DERIVED FOR RENDERING AND IS NEVER WRITTEN BACK. This is the
 * whole of the rule's safety and it is a mistake this repo has already made and
 * fixed once, on `floatingClamp`'s position: a callback that spread the derived
 * object back into state "replaces the user's stored position with the picture
 * of it", so a resize during a lapse in the room to honour a preference
 * silently destroyed the preference. So: the STATE and localStorage hold what
 * the user asked for, bounded only by the site's own constants; this function's
 * answer goes into an inline style and nowhere else. Restoring a large window
 * restores the large sidebar. Same split as `XrefPanel`'s `effectiveScope`.
 *
 * A DRAG IS NOT CLAMPED HERE, AND THAT IS THE DELIBERATE ASYMMETRY WITH
 * `floatingClamp`. There the drag's WRITE is clamped too, because a pointer
 * that ran off to (5000, 5000) named a position the user did not choose. A size
 * is different: the number a drag produces is already bounded by the site's own
 * `MIN`/`MAX`, and clamping the write against the viewport would mean one drag
 * on a narrow window permanently discards a wide preference — the exact trap
 * the paragraph above exists to avoid. The visible consequence is that on a
 * viewport too small to grant it, the panel stops following the pointer before
 * the pointer stops moving. That is what `MAX_WIDTH` already does at 400px and
 * is accepted for the same reason.
 *
 * WHEN THE FLOOR AND THE VIEWPORT CANNOT BOTH BE SATISFIED, THE FLOOR WINS.
 * They genuinely cannot at small sizes: a 180px minimum sidebar beside a 306px
 * reserve does not fit in a 375px viewport, and neither term is negotiable
 * inside this function. `Math.max(min, …)` is therefore OUTERMOST, which makes
 * the choice a named, tested case rather than an accident of ordering. The
 * argument for that direction is `floatingClamp`'s: yielding to the viewport
 * instead would drive the size to `viewport - reserve`, which goes to zero and
 * then negative, and an element of zero extent cannot be dragged back. A floor
 * that overflows is recoverable — the sidebar has a collapse rail and the panel
 * a close button — where a floor of nothing is not.
 */

/**
 * Space the sidebar must leave to the right of itself, in CSS px.
 *
 * DERIVED, from the disassembly listing's own grid. `.disasm-grid.hide-bytes`
 * (`src/styles/index.css`) is `--col-badge 2.5ch`, `--col-addr` (18ch for a
 * 64-bit image, set in `DisassemblyView`), `--col-mnemonic 8ch`, then `1fr` and
 * `auto` — so 28.5ch of FIXED columns before a single operand character, inside
 * `--row-px: 1rem` of padding on each side (32px). At the largest mono font
 * size the settings offer (16px, `loadFontSize`'s ceiling) and a 0.6em advance,
 * 28.5ch is 274px, giving 306px.
 *
 * THREE THINGS IN THAT ARE JUDGEMENTS AND ARE NOT DERIVED, stated rather than
 * buried:
 *
 * - **That the BYTES-HIDDEN column set is the floor.** With the bytes column
 *   shown the fixed prefix is 56.5ch — 439px at the default 12px and 575px at
 *   16px — and reserving that would push the sidebar to its floor on any window
 *   under about 760px. The listing scrolls horizontally, so neither figure is a
 *   hard requirement; this one is the point at which the address and the
 *   mnemonic are both readable without scrolling, which is the weaker and
 *   safer claim.
 * - **The 0.6em character advance**, which is a property of the font stack
 *   (`--font-mono`) and not of this repo. Every candidate in that stack is a
 *   0.6em monospace, but nothing here measures it and nothing could — jsdom
 *   performs no layout.
 * - **Taking the 16px figure rather than the 12px default**, i.e. sizing the
 *   reserve for the worst case a user can select rather than the common one.
 *   No allowance is made for the listing's vertical scrollbar (~15px in a real
 *   browser), deliberately: that would be a fourth judgement stacked on three.
 */
export const SIDEBAR_WIDTH_RESERVE = Math.round(28.5 * 9.6) + 32;

/**
 * Space the docked bottom panel must leave above itself, in CSS px.
 *
 * A SUM OF MEASURED ELEMENT HEIGHTS, not a round number. The panel lives at the
 * bottom of `DisassemblyView`'s `h-full` column, inside `main`, so what
 * competes with it is the two bars outside `main` (which shorten the column)
 * plus the two strips above it inside the column:
 *
 * | Element                            | Classes                       | px |
 * |------------------------------------|-------------------------------|----|
 * | `AddressBar`, TWO rows             | `py-1.5 gap-1` + `border-b`   | 73 |
 * | `DisassemblyToolbar`               | `py-1` + `border-b`           | 31 |
 * | `Breadcrumbs`                      | `py-0.5` + `border-b`         | 21 |
 * | `StatusBar`                        | `h-5` + `border-t`            | 21 |
 * | one listing row                    | `--row-height`                | 20 |
 *
 * The arithmetic, so a class change can be checked against it: a `text-sm`
 * button at `py-1` is 20 + 8 = 28px, and below `2xl` (1536px) the view tabs
 * take a row of their own (`basis-full`, added at `16f37df`), so the bar is
 * 28 + 4 + 28 + 12 + 1 = 73 rather than the 41 it measures above that width —
 * **the two-row figure is taken, because it is the tier where a short window is
 * likely.** The toolbar's tallest child is its `w-48 px-2 py-0.5` search input,
 * 16 + 4 + 2 = 22, so 22 + 8 + 1 = 31. Breadcrumbs are `text-[10px]` inside
 * `py-0.5` with a `border-b`, ~16 + 4 + 1 = 21. `--row-height` is declared as
 * `20px` in `src/styles/index.css`.
 *
 * WHAT IS A JUDGEMENT HERE IS THE LISTING FLOOR, AND IT IS ONE ROW. The four
 * chrome terms are measurements. A floor of one row is the only row count that
 * is not arbitrary — it is the boundary between a listing and no listing — and
 * without any floor term the guarantee degenerates to "the listing is never of
 * negative height", which stops `main` from overflowing and scrolling but
 * leaves nothing on the page.
 *
 * A LARGER FLOOR WOULD BE BETTER AND COULD NOT BE LANDED HERE. Four or five
 * rows is the size at which the pane is worth looking at; at jsdom's 768px
 * viewport any floor above 22px takes the ceiling below `MAX_HEIGHT`, and
 * `BottomPanels.dom.test.tsx`'s "clamps to the minimum and the maximum" asserts
 * a rendered `600px` there. That test pins the constants-only clamp — the very
 * thing this module exists to widen — so raising the floor is a decision about
 * that test rather than about this number, and it was reported rather than
 * taken. Four conditional strips are also NOT counted (the driver banner, the
 * analysis notice, and the toolbar's search/filter sub-rows, ~30px each): a
 * reserve sized for chrome no single session shows would be larger than the
 * chrome actually on screen.
 */
export const DOCKED_PANEL_HEIGHT_RESERVE = 73 + 31 + 21 + 21 + 20;

/**
 * Clamp a persisted, user-chosen size for RENDERING. Pure: it reads no
 * `window`, so callers supply the viewport.
 *
 * `min` and `max` stay parameters rather than moving in here because they are
 * facts about the SITE — how narrow a function list is still a list — where the
 * reserve and the floor-wins rule are facts about the app's layout. Both sites
 * keep enforcing `[min, max]` on the value they STORE; this is the third bound,
 * and the only one that can move without the user touching anything.
 *
 * @param stored    the size the user chose, already inside `[min, max]`
 * @param min       the site's floor — honoured even when the viewport cannot
 *                  afford it, which is the decision this rule exists to name
 * @param max       the site's ceiling
 * @param viewport  `window.innerWidth` or `window.innerHeight` at the call
 *                  site, on the same axis as `stored`
 * @param reserve   how much of that axis the rest of the app needs — one of the
 *                  two constants above, never an inline number
 */
export function clampPersistedSize(
  stored: number,
  min: number,
  max: number,
  viewport: number,
  reserve: number,
): number {
  return Math.max(min, Math.min(max, viewport - reserve, stored));
}
