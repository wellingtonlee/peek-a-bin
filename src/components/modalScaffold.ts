/**
 * The decision logic behind {@link ./Modal}, kept out of the component so it can
 * be tested.
 *
 * What is pinned here is the arithmetic — where Tab sends focus, which layout
 * classes each placement produces, which naming attribute the dialog gets, how
 * the scroll lock nests, and which dialogs may be dismissed by accident — as
 * pure functions over plain values, which is both cheaper than a render and the
 * only form in which the *rule* can be stated apart from any one dialog.
 *
 * There IS a renderer now (jsdom plus @testing-library/react, opted into per
 * file — see CLAUDE.md's "Component tests"), so these answers are additionally
 * checked in effect: `Modal.dom.test.tsx` drives the trap, the lock and the
 * naming through the real component, and the dialog suites beside it check
 * which arguments each dialog passes to `accidentalDismissAllowed` — the one
 * thing a pure test of the rule structurally cannot see. `focusableWithin` is
 * still the one function here that needs a real element; it is exercised only
 * through those renders, and under jsdom its `offsetParent` filter runs against
 * a stand-in (see `src/test/domSetup.ts`) rather than against a browser.
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

/** The two ways a dialog can carry its accessible name. */
export interface ModalNameAttrs {
  ariaLabel?: string;
  ariaLabelledBy?: string;
}

/**
 * Which naming attribute the dialog element gets.
 *
 * A dialog with a visible heading is named by pointing at that heading, so the
 * name a screen reader announces is literally the text a sighted user reads and
 * the two cannot drift apart. `aria-label` remains for the dialogs that have no
 * heading — the command palette opens straight onto a search field.
 *
 * Exactly one of the two is ever emitted. Setting both is legal (labelledby
 * wins) but leaves a second, unused string in the source that nothing keeps
 * honest, which is the drift this is meant to remove.
 */
export function modalNameAttrs(
  label: string | undefined,
  labelledBy: string | undefined,
): ModalNameAttrs {
  return labelledBy ? { ariaLabelledBy: labelledBy } : { ariaLabel: label };
}

/** Inline `<body>` styles the scroll lock overwrites, as they were found. */
export interface BodyStyles {
  overflow: string;
  paddingRight: string;
}

/**
 * Book-keeping for the body scroll lock.
 *
 * `depth` is a count, not a flag: two dialogs can be open at once (the command
 * palette can launch batch rename), and a boolean would let the first one to
 * close unlock the page while the second is still up.
 *
 * `saved` is captured from the *first* lock only. Re-reading the inline styles
 * on a nested lock would save the locked values and restore them for ever.
 */
export interface ScrollLockState {
  depth: number;
  saved: BodyStyles | null;
}

export const UNLOCKED: ScrollLockState = { depth: 0, saved: null };

/**
 * Styles to write onto `<body>`. `paddingRight: null` means "leave the existing
 * padding alone" — distinct from `""`, which would clear an inline padding the
 * page had set for its own reasons.
 */
export interface ScrollLockPatch {
  overflow: string;
  paddingRight: string | null;
}

/**
 * Take a lock, returning the next state and the styles to apply (or `null` when
 * a lock is already held and the DOM needs no further change).
 *
 * @param inline            the inline styles currently on `<body>`
 * @param gutter            width of the scrollbar about to disappear, i.e.
 *                          `innerWidth - documentElement.clientWidth`
 * @param basePaddingRight  computed `padding-right` of `<body>` in px
 *
 * The gutter is added back as padding so that hiding the scrollbar does not
 * widen the viewport and shift the whole page sideways. When there is no
 * scrollbar to hide — overlay scrollbars, or a page that never scrolled — the
 * padding is left untouched rather than being set to the same value it already
 * had, which keeps the restore a no-op too.
 */
export function lockBodyScroll(
  state: ScrollLockState,
  inline: BodyStyles,
  gutter: number,
  basePaddingRight: number,
): { state: ScrollLockState; patch: ScrollLockPatch | null } {
  if (state.depth > 0) {
    return { state: { ...state, depth: state.depth + 1 }, patch: null };
  }
  return {
    state: { depth: 1, saved: inline },
    patch: {
      overflow: "hidden",
      paddingRight: gutter > 0 ? `${basePaddingRight + gutter}px` : null,
    },
  };
}

/**
 * Release a lock, returning the next state and the styles to put back (or
 * `null` while other dialogs still hold the lock).
 *
 * The restore is the saved values, not `""`. Blindly clearing would drop an
 * inline `overflow` the page had before any dialog opened — this app sets
 * `overflow: hidden` on `<body>` from CSS rather than inline, but a stylesheet
 * change should not turn into a scroll bug here.
 *
 * A release with nothing held returns `UNLOCKED` and no restore, so an
 * unbalanced cleanup cannot drive the depth negative and wedge the lock on.
 */
export function unlockBodyScroll(state: ScrollLockState): {
  state: ScrollLockState;
  restore: BodyStyles | null;
} {
  if (state.depth > 1) {
    return { state: { ...state, depth: state.depth - 1 }, restore: null };
  }
  return { state: UNLOCKED, restore: state.saved };
}

/**
 * Whether closing a dialog by Escape or a stray backdrop click is acceptable.
 *
 * Escape is the expected key for a dialog, and most of them should have it.
 * The exceptions are not "important" dialogs — they are dialogs where the
 * keystroke destroys something the user cannot get back by reopening: a request
 * that is still in flight, or a set of choices they have made in the dialog and
 * not yet applied. Both are one keystroke away from the Escape a user presses
 * out of habit when a dialog is in the way.
 *
 * The visible Cancel/Close button stays either way, so WCAG 2.1.2 is satisfied
 * regardless; this only decides whether the *accidental* dismissal is offered.
 */
export function accidentalDismissAllowed(risk: {
  /** A request is running that closing would abandon or waste. */
  inFlight: boolean;
  /** The dialog holds user decisions or results that closing would discard. */
  unsavedWork: boolean;
}): boolean {
  return !risk.inFlight && !risk.unsavedWork;
}

/**
 * What a dialog's error boundary should put on screen.
 *
 * `"children"` is the ordinary case. `"fallback"` is a caught render error with
 * the dialog still open in the caller's state — the fallback must go inside a
 * real {@link ./Modal}, or the user is left with a red box floating in `App`'s
 * root with no backdrop, no Escape and no Close, over an app the focus trap has
 * not released. `"nothing"` is the caught error with the dialog closed: the
 * children are deliberately NOT re-rendered, because the throw may have come
 * from a hook or a memo that runs above each dialog's own `if (!open) return
 * null`, and re-running it would throw again with nobody left to catch it.
 *
 * The cost of `"nothing"` is that a broken dialog is unmounted while closed and
 * loses its internal state. That is a state the session is already degraded in,
 * and the alternative is a render loop.
 */
export type DialogBoundaryRender = "children" | "fallback" | "nothing";

export function dialogBoundaryRender(open: boolean, caught: boolean): DialogBoundaryRender {
  if (!caught) return "children";
  return open ? "fallback" : "nothing";
}

/**
 * Whether a caught error should be cleared, given the dialog's `open` prop now
 * and on the previous render.
 *
 * THE TRIGGER IS THE CLOSED → OPEN TRANSITION AND NOTHING ELSE, which is what
 * keeps this compatible with {@link ./ErrorBoundary}'s deliberate refusal to
 * clear on a re-render. That rule's argument is specifically against retrying a
 * deterministic fault on every parent render — the fallback would flicker in and
 * out with no way to read it, and the retry would be nobody's decision. Opening
 * a dialog the user closed is a named, explicit act by the user, exactly like
 * the "Try again" button the pane and chrome fallbacks already offer; it just
 * happens to be spelled Ctrl+P.
 *
 * It is a separate function from {@link dialogBoundaryRender} because the two
 * answer different questions at different moments — this one runs before a
 * render, from the props, and must be a no-op on every render that is not that
 * transition, including the re-render that follows the catch itself.
 */
export function dialogBoundaryReset(wasOpen: boolean, open: boolean, caught: boolean): boolean {
  return caught && open && !wasOpen;
}
