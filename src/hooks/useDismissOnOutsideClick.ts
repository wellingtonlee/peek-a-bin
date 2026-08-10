import { type RefObject, useEffect, useRef } from "react";

/** Which pointer event closes the popup. */
export type DismissEvent = "mousedown" | "click";

/** Which global object the listeners are attached to. */
export type DismissTarget = "document" | "window";

export interface DismissOnOutsideClickOptions {
  /** When false the listeners are not attached at all. */
  active: boolean;
  /** Element that counts as "inside"; events landing within it are ignored. */
  ref: RefObject<HTMLElement | null>;
  /** Called when the popup should close. May be a fresh closure every render. */
  onDismiss: () => void;
  /**
   * `mousedown` fires before the click reaches React's handlers, `click` after.
   * A popup whose toggle button sits *outside* `ref` must use `mousedown` only
   * if it wants the button's own onClick to re-open it; the two are not
   * interchangeable. Defaults to `mousedown`.
   */
  event?: DismissEvent;
  /** Defaults to `document`. */
  target?: DismissTarget;
  /** Also close on Escape, on the same target. Defaults to false. */
  dismissOnEscape?: boolean;
  /**
   * What to do when `ref.current` is null (popup not mounted yet, or the ref
   * belongs to a sibling that is not rendered). `true` treats every event as
   * outside and closes; `false` ignores the event. Defaults to false.
   */
  dismissIfRefMissing?: boolean;
}

/**
 * Pure decision half of the hook: given the container element (or null) and the
 * event target, should the popup be dismissed?
 *
 * Split out because there is no React renderer in this repo, so the effect
 * plumbing cannot be exercised in a test but this can.
 */
export function isOutsideDismiss(
  container: Pick<HTMLElement, "contains"> | null,
  eventTarget: EventTarget | null,
  dismissIfRefMissing = false,
): boolean {
  if (!container) return dismissIfRefMissing;
  return !container.contains(eventTarget as Node | null);
}

/**
 * Close a popup when a pointer event lands outside `ref` (and optionally on
 * Escape). Replaces the hand-rolled effect that was copy-pasted across the
 * address bar, status bar and disassembly view.
 *
 * `onDismiss` is read through a ref, so passing an inline arrow does not cause
 * the listeners to be torn down and re-attached on every render.
 */
export function useDismissOnOutsideClick({
  active,
  ref,
  onDismiss,
  event = "mousedown",
  target = "document",
  dismissOnEscape = false,
  dismissIfRefMissing = false,
}: DismissOnOutsideClickOptions): void {
  const onDismissRef = useRef(onDismiss);
  onDismissRef.current = onDismiss;

  useEffect(() => {
    if (!active) return;
    const host: Document | Window = target === "window" ? window : document;

    const handlePointer = (e: Event) => {
      if (isOutsideDismiss(ref.current, e.target, dismissIfRefMissing)) {
        onDismissRef.current();
      }
    };
    host.addEventListener(event, handlePointer);

    let handleKey: ((e: Event) => void) | undefined;
    if (dismissOnEscape) {
      handleKey = (e: Event) => {
        if ((e as KeyboardEvent).key === "Escape") onDismissRef.current();
      };
      host.addEventListener("keydown", handleKey);
    }

    return () => {
      host.removeEventListener(event, handlePointer);
      if (handleKey) host.removeEventListener("keydown", handleKey);
    };
  }, [active, ref, event, target, dismissOnEscape, dismissIfRefMissing]);
}
