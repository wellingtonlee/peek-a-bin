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

import { describe, it, expect } from "vitest";
import {
  FOCUSABLE_SELECTOR,
  FOCUS_CONTAINER,
  modalDialogClass,
  modalWrapperClass,
  nextTrapIndex,
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
