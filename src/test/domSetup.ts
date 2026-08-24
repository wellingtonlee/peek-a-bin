import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";

/**
 * Setup for the component tests — the only ones that render React.
 *
 * IMPORTED BY EACH COMPONENT TEST, not listed in `vitest.config.ts`, and that is
 * a measurement rather than a style preference. As a global `setupFiles` entry
 * — even with its whole body behind a `typeof document` check and
 * `@testing-library/react` behind a dynamic import — it cost **3.0s of `setup`
 * and took `--dir src` from 28.0s to 39.0s**, because vitest loads a setup
 * module once per test file and there are ~110 of them that want nothing from
 * it. Imported instead, the node suites pay exactly zero.
 *
 * The cost of that is two things to remember per new component test (the
 * environment docblock and this import) rather than one, so
 * `build/domTestNaming.test.ts` fails the ordinary suite if a `*.dom.test.tsx`
 * file is missing either.
 *
 * READ THE `offsetParent` SECTION BEFORE TRUSTING A FOCUS-TRAP TEST. jsdom does
 * no layout, so one thing the app's focus trap genuinely depends on is missing
 * and is supplied here by a stand-in.
 */

/**
 * jsdom implements `HTMLElement.offsetParent` as **always null**, for every
 * element, because it performs no layout at all (verified against jsdom 28:
 * a plain `<button>` attached to a rendered body reports `null`).
 *
 * That matters because {@link ../components/modalScaffold#focusableWithin}
 * filters its candidates with `el.offsetParent !== null`, to keep the focus
 * trap off controls the browser itself skips — specifically the settings
 * dialog's permanently-present `<input type="file" className="hidden">`. Under
 * unpatched jsdom that filter discards *everything*, `focusableWithin` returns
 * `[]` for every dialog, and `nextTrapIndex(0, …)` answers `FOCUS_CONTAINER` —
 * so a Tab test would pass while proving only that a dialog with no focusable
 * controls keeps focus on itself. Vacuously green, which is worse than absent.
 *
 * So `offsetParent` is defined here as exactly the one fact the production
 * code reads it for: **null when the element or any ancestor is
 * `display: none`, non-null otherwise.** Nothing else is modelled — not
 * `position`, not the real offset ancestor, not `visibility: hidden`, not zero
 * size, not `content-visibility`.
 *
 * THE HONEST STATEMENT OF WHAT THIS BUYS: a Tab-cycling test now walks the
 * real element list rather than an empty one, and the `display:none` exclusion
 * is checked against a stand-in written to have that behaviour rather than
 * against a browser. `domSetup.dom.test.tsx` asserts the shim discriminates in
 * both directions so it cannot rot into a constant; it is still a stand-in,
 * and only a real browser settles whether a browser agrees.
 */
Object.defineProperty(HTMLElement.prototype, "offsetParent", {
  configurable: true,
  get(this: HTMLElement): Element | null {
    if (!this.isConnected) return null;
    for (let el: Element | null = this; el; el = el.parentElement) {
      if (!(el instanceof HTMLElement)) continue;
      // Inline style first: jsdom does resolve a stylesheet rule, but every
      // fixture here sets visibility inline or with a Tailwind class, and a
      // class carries no `display` without Tailwind — deliberately not loaded,
      // see vitest.config.ts.
      const display = el.style.display || getComputedStyle(el).display;
      if (display === "none") return null;
    }
    return this.ownerDocument.body;
  },
});

/**
 * jsdom implements no scrolling at all, so `Element.prototype.scrollIntoView`
 * is simply **absent** (verified against jsdom 28: `typeof el.scrollIntoView`
 * is `"undefined"` and calling it throws `is not a function`).
 *
 * That is not a curiosity: `CommandPalette` keeps the highlighted row visible
 * with an effect that calls it on every selection change, and an exception
 * thrown inside a `useEffect` tears the tree down — so without this, every
 * arrow-key test of a scrolling list dies on the first ArrowDown, for a reason
 * that has nothing to do with the behaviour under test.
 *
 * A NO-OP, and deliberately not a spy: this file runs before every component
 * test, and a shared spy would accumulate calls across them. A test that wants
 * to observe the call can `vi.spyOn` it itself.
 *
 * WHAT THIS BUYS, EXACTLY: the component's own effect gets to run to
 * completion. It buys nothing whatever about scrolling — whether the row ends
 * up visible, whether the container scrolled, whether `block: "nearest"` was
 * the right choice — because jsdom performs no layout and every scroll offset
 * there is a constant 0. Do not write an assertion that reads as being about
 * visibility.
 */
if (!HTMLElement.prototype.scrollIntoView) {
  HTMLElement.prototype.scrollIntoView = function scrollIntoView() {};
}

beforeEach(() => {
  // The scroll lock writes inline styles onto <body> and restores what it
  // found. Start every test from the same place, so one leaking test cannot
  // change what the next one's assertion about `body.style` means.
  document.body.style.overflow = "";
  document.body.style.paddingRight = "";
});

// `globals` is off, so @testing-library/react's own auto-cleanup (which keys
// on a global `afterEach`) never registers. Unmount explicitly, or each test
// leaves its tree — and its focus — behind for the next one.
afterEach(() => {
  cleanup();
});
