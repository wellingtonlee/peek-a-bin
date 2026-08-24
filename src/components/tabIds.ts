import type { ViewTab } from "../hooks/usePEFile";

/**
 * Id arithmetic for the view switcher's `role="tablist"`.
 *
 * The tab buttons live in `AddressBar.tsx` and the panels they control live in
 * `App.tsx`, so the two halves of every ARIA reference are minted in different
 * files: a tab carries `aria-controls={tabPanelId(tab)}` and `id={tabId(tab)}`,
 * and its panel carries the mirror pair. That is exactly the agreement that rots
 * silently — a mismatch produces no error, no warning and no visible change,
 * just a dangling reference that a screen reader resolves to nothing. The same
 * reasoning as {@link ./listboxIds}, which is this module's model.
 *
 * TYPE-ONLY IMPORT, deliberately: keying on `ViewTab` means a tab that is not
 * one of the nine cannot be given an id, and nothing is pulled in at runtime, so
 * this stays a leaf both halves can read.
 *
 * These are pure so `__tests__/tabIds.test.ts` can pin them over plain strings.
 * THAT IS HALF THE PROBLEM, and the half that is cheap: the ids can be
 * arithmetically perfect and still name an element nobody rendered. The
 * *resolution* is covered where both halves are on screen together, in
 * `src/__tests__/App.dom.test.tsx`, which walks every rendered `role="tab"`,
 * resolves its `aria-controls` against the document, and checks the panel it
 * lands on points back at that same tab. `AddressBar.dom.test.tsx` renders the
 * bar without any panels, so it can only assert the correspondence with these
 * functions — which is why both suites are needed and neither is redundant.
 */

/** DOM id of the tab button for `tab`. */
export function tabId(tab: ViewTab): string {
  return `view-tab-${tab}`;
}

/** DOM id of the panel that tab controls. */
export function tabPanelId(tab: ViewTab): string {
  return `view-tabpanel-${tab}`;
}
