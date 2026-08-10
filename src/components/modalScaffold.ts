/**
 * The decision logic behind {@link ./Modal}, kept out of the component so it can
 * be tested.
 *
 * There is no React renderer in this repo (no jsdom, no @testing-library/react),
 * so a component cannot be mounted and nothing here can be verified through the
 * DOM. What *can* be pinned is the arithmetic — where Tab sends focus, and which
 * layout classes each placement produces — so that lives here as pure functions
 * over plain values. `focusableWithin` is the one exception: it needs a real
 * element, touches the DOM only when called, and is therefore untested.
 */

/** Vertical placement of the dialog box within the viewport. */
export type ModalPlacement = "center" | "top";

/**
 * Elements that can take focus inside a dialog.
 *
 * `[tabindex="-1"]` is excluded on purpose: it means "focusable by script, not by
 * Tab", which is exactly what the dialog container itself uses. Disabled controls
 * and `type="hidden"` inputs are excluded because the browser skips them too, and
 * a trap that stopped on them would strand the user.
 */
export const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not(:disabled)",
  "input:not(:disabled):not([type='hidden'])",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

/**
 * Focusable descendants of `container`, in document order.
 *
 * Document order is what the browser uses for Tab as long as no positive
 * tabindex is in play, and none is anywhere in this app.
 *
 * Elements hidden with `display:none` are filtered out via `offsetParent`. This
 * matters for the settings dialog, where three of the four tab panels are
 * unmounted rather than hidden — but the file-import `<input type="file">` is
 * `className="hidden"` and permanently present, so without the filter Tab would
 * stop on an invisible control.
 */
export function focusableWithin(container: HTMLElement): HTMLElement[] {
  const all = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
  return all.filter((el) => el.offsetParent !== null);
}

/** Focus the dialog container itself rather than any element inside it. */
export const FOCUS_CONTAINER = -1;

/**
 * Where a Tab keypress should send focus inside a trapped dialog.
 *
 * @param count      how many focusable elements the dialog holds
 * @param current    index of the focused element in that list, or -1 if focus is
 *                   on the container itself (or has escaped)
 * @param shift      whether Shift was held
 * @returns an index into the focusable list, {@link FOCUS_CONTAINER} when there
 *          is nothing to focus, or `null` to let the browser move focus itself.
 *
 * Returning `null` for the interior of the list is the point: the trap only has
 * to intervene at the two ends. Calling preventDefault on every Tab would mean
 * reimplementing the browser's own ordering, which goes wrong the moment a
 * control has non-obvious focus behaviour (radio groups move as a unit).
 */
export function nextTrapIndex(count: number, current: number, shift: boolean): number | null {
  if (count === 0) return FOCUS_CONTAINER;
  // Focus is on the container or somewhere unexpected: enter the list from the
  // end Tab would have come from.
  if (current < 0 || current >= count) return shift ? count - 1 : 0;
  if (shift && current === 0) return count - 1;
  if (!shift && current === count - 1) return 0;
  return null;
}

/**
 * Classes for the full-viewport wrapper.
 *
 * `tint` is the overlay dim, and is applied here only when the dialog has no
 * click-to-dismiss backdrop. When it does, {@link ./ModalBackdrop} paints the
 * dim itself from its own absolutely-positioned layer; putting it in both places
 * would double the darkness.
 */
export function modalWrapperClass(placement: ModalPlacement, tint: string | null): string {
  const position =
    placement === "top" ? "items-start justify-center pt-[15vh]" : "items-center justify-center";
  return `fixed inset-0 z-50 flex ${position}${tint ? ` ${tint}` : ""}`;
}

/**
 * Classes for the dialog box.
 *
 * `relative` is what lifts the box above the absolutely-positioned backdrop;
 * it is unconditional because on a dialog with no backdrop it is inert.
 *
 * `focus:outline-none` suppresses the ring on the container itself. The container
 * only ever takes focus as the trap's fallback when it holds no focusable control
 * at all, and it is not reachable by Tab, so the ring would be noise rather than
 * a navigation cue — every control inside keeps its own focus styling.
 */
export function modalDialogClass(className: string): string {
  return `relative focus:outline-none bg-gray-800 border border-gray-600 rounded-lg ${className}`.trimEnd();
}
