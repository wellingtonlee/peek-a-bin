/**
 * Covers the parts of the shared modal shell that can be tested without a
 * renderer: the focus-trap arithmetic and the layout-class composition.
 *
 * There is no jsdom and no @testing-library/react in this repo, so `Modal`
 * itself cannot be mounted. Everything the component does *to the DOM* — moving
 * focus on open, restoring it on close, reading `document.activeElement` — is
 * out of reach here and has to be checked by hand in a browser. What these tests
 * pin is the logic that decides *what* should happen, which is where the wrap
 * bugs live.
 */

import { describe, expect, it } from "vitest";
import {
  accidentalDismissAllowed,
  FOCUS_CONTAINER,
  FOCUSABLE_SELECTOR,
  lockBodyScroll,
  modalDialogClass,
  modalNameAttrs,
  modalWrapperClass,
  nextTrapIndex,
  type ScrollLockState,
  UNLOCKED,
  unlockBodyScroll,
} from "../modalScaffold";

describe("nextTrapIndex", () => {
  it("hands Tab back to the browser in the interior of the list", () => {
    // The trap only intervenes at the two ends; anything else is native order.
    expect(nextTrapIndex(5, 1, false)).toBeNull();
    expect(nextTrapIndex(5, 3, false)).toBeNull();
    expect(nextTrapIndex(5, 1, true)).toBeNull();
    expect(nextTrapIndex(5, 4, true)).toBeNull();
  });

  it("wraps forward off the last element to the first", () => {
    expect(nextTrapIndex(5, 4, false)).toBe(0);
  });

  it("wraps backward off the first element to the last", () => {
    expect(nextTrapIndex(5, 0, true)).toBe(4);
  });

  it("wraps in both directions on a single-element dialog", () => {
    // Index 0 is simultaneously the first and last element, so both directions
    // must resolve to it rather than one of them falling through to null and
    // letting focus leave the dialog.
    expect(nextTrapIndex(1, 0, false)).toBe(0);
    expect(nextTrapIndex(1, 0, true)).toBe(0);
  });

  it("enters the list from the matching end when focus is on the container", () => {
    // -1 is what indexOf returns for the dialog box itself, which is what holds
    // focus right after opening a dialog with no autofocused control.
    expect(nextTrapIndex(5, -1, false)).toBe(0);
    expect(nextTrapIndex(5, -1, true)).toBe(4);
  });

  it("recovers when focus is somewhere it should not be", () => {
    // An index past the end means the focused element is no longer in the list —
    // it was unmounted, or focus escaped. Pull it back in rather than returning
    // null, which would let the next Tab walk into the page behind the dialog.
    expect(nextTrapIndex(3, 7, false)).toBe(0);
    expect(nextTrapIndex(3, 7, true)).toBe(2);
  });

  it("parks focus on the container when the dialog holds nothing focusable", () => {
    // The keyboard-shortcuts panel is exactly this: text and <kbd> elements, no
    // controls at all. Tab must not walk out of it.
    expect(nextTrapIndex(0, -1, false)).toBe(FOCUS_CONTAINER);
    expect(nextTrapIndex(0, -1, true)).toBe(FOCUS_CONTAINER);
  });
});

describe("FOCUSABLE_SELECTOR", () => {
  it("excludes tabindex=-1 so the backdrop stays out of the cycle", () => {
    // ModalBackdrop is a <button tabIndex={-1}>. It sits outside the dialog box
    // so the trap would not see it anyway, but a selector that matched it would
    // also match every other script-focusable element in a dialog body.
    expect(FOCUSABLE_SELECTOR).toContain("[tabindex='-1']");
    expect(FOCUSABLE_SELECTOR).toContain("button:not(:disabled)");
  });

  it("skips disabled controls", () => {
    // Go-to-address disables its Go button until the address parses; stopping
    // Tab there would strand the user on a dead control.
    for (const tag of ["button", "input", "select", "textarea"]) {
      expect(FOCUSABLE_SELECTOR).toContain(`${tag}:not(:disabled)`);
    }
  });
});

describe("modalWrapperClass", () => {
  it("centres by default and drops from 15vh for palette-style dialogs", () => {
    expect(modalWrapperClass("center", null)).toBe(
      "fixed inset-0 z-50 flex items-center justify-center",
    );
    expect(modalWrapperClass("top", null)).toBe(
      "fixed inset-0 z-50 flex items-start justify-center pt-[15vh]",
    );
  });

  it("carries the dim only when there is no backdrop element to paint it", () => {
    // A dialog with a click-to-dismiss backdrop gets its dim from ModalBackdrop;
    // applying it here as well would darken the page twice over.
    expect(modalWrapperClass("center", "bg-black/60")).toContain("bg-black/60");
    expect(modalWrapperClass("center", null)).not.toContain("bg-black");
  });
});

describe("modalDialogClass", () => {
  it("supplies the shared surface and the stacking context for the backdrop", () => {
    const cls = modalDialogClass("w-80 p-4");
    expect(cls).toContain("relative");
    expect(cls).toContain("bg-gray-800");
    expect(cls).toContain("border border-gray-600");
    expect(cls).toContain("rounded-lg");
    expect(cls).toContain("w-80 p-4");
  });

  it("does not leave a trailing space when the caller adds nothing", () => {
    expect(modalDialogClass("")).toBe(
      "relative focus:outline-none bg-gray-800 border border-gray-600 rounded-lg",
    );
  });
});

describe("modalNameAttrs", () => {
  it("names the dialog by its heading when there is one", () => {
    expect(modalNameAttrs(undefined, "settings-title")).toEqual({
      ariaLabelledBy: "settings-title",
    });
  });

  it("falls back to a string for dialogs with no heading", () => {
    // The command palette opens onto a search field and has no title to point at.
    expect(modalNameAttrs("Command palette", undefined)).toEqual({
      ariaLabel: "Command palette",
    });
  });

  it("never emits both, so there is no second name to fall out of date", () => {
    const attrs = modalNameAttrs("Settings", "settings-title");
    expect(attrs.ariaLabel).toBeUndefined();
    expect(attrs.ariaLabelledBy).toBe("settings-title");
  });
});

describe("body scroll lock", () => {
  const inline = { overflow: "", paddingRight: "" };

  it("hides overflow on the first lock and remembers what was there", () => {
    const taken = lockBodyScroll(UNLOCKED, { overflow: "auto", paddingRight: "4px" }, 0, 0);
    expect(taken.patch?.overflow).toBe("hidden");
    expect(taken.state).toEqual({
      depth: 1,
      saved: { overflow: "auto", paddingRight: "4px" },
    });
  });

  it("restores the previous value rather than clearing it", () => {
    // Blindly setting overflow back to "" would drop a value the page had set
    // for its own reasons before any dialog opened.
    const taken = lockBodyScroll(UNLOCKED, { overflow: "auto", paddingRight: "4px" }, 0, 0);
    const released = unlockBodyScroll(taken.state);
    expect(released.restore).toEqual({ overflow: "auto", paddingRight: "4px" });
    expect(released.state).toEqual(UNLOCKED);
  });

  it("counts nested dialogs instead of flagging them", () => {
    // Two dialogs can be open at once. With a boolean, closing the first would
    // unlock the page while the second is still covering it.
    const first = lockBodyScroll(UNLOCKED, inline, 0, 0);
    const second = lockBodyScroll(first.state, inline, 0, 0);
    expect(second.state.depth).toBe(2);
    expect(second.patch).toBeNull();

    const inner = unlockBodyScroll(second.state);
    expect(inner.restore).toBeNull();
    expect(inner.state.depth).toBe(1);

    const outer = unlockBodyScroll(inner.state);
    expect(outer.restore).toEqual(inline);
    expect(outer.state).toEqual(UNLOCKED);
  });

  it("saves the styles from before the first lock, not from between locks", () => {
    // By the time a second dialog opens, <body> is already overflow:hidden. A
    // nested lock that re-read the inline styles would save that and restore it
    // for ever, leaving the page permanently unscrollable.
    const first = lockBodyScroll(UNLOCKED, { overflow: "auto", paddingRight: "" }, 0, 0);
    const second = lockBodyScroll(first.state, { overflow: "hidden", paddingRight: "" }, 0, 0);
    expect(second.state.saved).toEqual({ overflow: "auto", paddingRight: "" });
  });

  it("pads out the scrollbar it is about to hide", () => {
    // Without this the viewport widens by the scrollbar's width the instant a
    // dialog opens and the whole page jumps sideways behind it.
    const taken = lockBodyScroll(UNLOCKED, inline, 15, 8);
    expect(taken.patch?.paddingRight).toBe("23px");
  });

  it("leaves padding alone when there is no scrollbar to hide", () => {
    // null, not "": this app's <body> is overflow:hidden from CSS and never has
    // a scrollbar, and clearing an inline padding that was not ours to clear is
    // a layout change in its own right.
    expect(lockBodyScroll(UNLOCKED, inline, 0, 8).patch?.paddingRight).toBeNull();
  });

  it("survives an unbalanced release without wedging the lock on", () => {
    const released = unlockBodyScroll(UNLOCKED);
    expect(released.state).toEqual(UNLOCKED);
    expect(released.restore).toBeNull();
    // A negative depth would make the next lock believe one is already held and
    // never apply the patch.
    expect(released.state.depth).toBe(0);
  });

  it("comes back cleanly from React's development double-mount", () => {
    // StrictMode runs mount → unmount → mount. The second mount must re-apply
    // the patch, which it only does if the first cycle left the depth at zero.
    let state: ScrollLockState = UNLOCKED;
    const mount = lockBodyScroll(state, { overflow: "auto", paddingRight: "" }, 0, 0);
    state = unlockBodyScroll(mount.state).state;
    const remount = lockBodyScroll(state, { overflow: "auto", paddingRight: "" }, 0, 0);
    expect(remount.patch?.overflow).toBe("hidden");
    expect(remount.state.saved).toEqual({ overflow: "auto", paddingRight: "" });
  });
});

describe("accidentalDismissAllowed", () => {
  it("offers Escape and backdrop click to an idle dialog", () => {
    // The go-to-address, palette, shortcuts and batch-rename-error dialogs.
    expect(accidentalDismissAllowed({ inFlight: false, unsavedWork: false })).toBe(true);
  });

  it("withholds it while a request is in flight", () => {
    // Batch rename mid-run, or a report still streaming: dismissing abandons
    // work that has already been paid for and is not written down anywhere.
    expect(accidentalDismissAllowed({ inFlight: true, unsavedWork: false })).toBe(false);
  });

  it("withholds it from a dialog holding uncommitted decisions", () => {
    // The batch-rename review table: dismissing drops both the suggestions and
    // every accept/reject the user has clicked.
    expect(accidentalDismissAllowed({ inFlight: false, unsavedWork: true })).toBe(false);
  });

  it("needs both to be clear, not either", () => {
    expect(accidentalDismissAllowed({ inFlight: true, unsavedWork: true })).toBe(false);
  });
});
