/**
 * Id arithmetic for an `aria-activedescendant` listbox.
 *
 * In that pattern focus never leaves the input: the rows are not focusable, and
 * the input names the active row by id so a screen reader announces it. The ids
 * therefore have to agree between the option that renders them and the input
 * that points at one, which is exactly the kind of agreement that rots silently
 * — a mismatch produces no error, just a dangling reference and a selection
 * that is never announced.
 *
 * These are pure so they can be pinned by tests; the DOM wiring in
 * `CommandPalette` cannot be, since there is no React renderer in this repo.
 */

/** Id of the option at `index` within the listbox named `listId`. */
export function optionId(listId: string, index: number): string {
  return `${listId}-option-${index}`;
}

/**
 * Value for the input's `aria-activedescendant`, or `undefined` when there is
 * nothing active.
 *
 * `undefined` rather than `""`: an empty string is still an id reference, just a
 * broken one, and assistive technology is entitled to look it up and find
 * nothing. Omitting the attribute says "no active option", which is the truth
 * when the result list is empty or nothing is selected yet.
 */
export function activeDescendantId(
  listId: string,
  selectedIndex: number,
  count: number,
): string | undefined {
  if (count <= 0) return undefined;
  if (selectedIndex < 0 || selectedIndex >= count) return undefined;
  return optionId(listId, selectedIndex);
}
