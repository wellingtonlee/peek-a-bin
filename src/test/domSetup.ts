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

/**
 * jsdom implements no layout, so it ships **no `ResizeObserver` at all**
 * (verified against jsdom 28: `typeof ResizeObserver` is `"undefined"`, and
 * `new ResizeObserver(...)` throws `ResizeObserver is not defined`).
 *
 * Three components in the disassembly panel construct one from an effect —
 * `Breadcrumbs`, `DisassemblyMinimap` and, indirectly, `@tanstack/react-virtual`
 * via its default `observeElementRect` — and a throw inside a `useEffect` tears
 * the whole tree down. So without this the populated panel cannot be mounted at
 * all, for a reason that has nothing to do with any behaviour under test.
 *
 * IT NEVER OBSERVES ANYTHING AND IT NEVER FIRES. `observe`, `unobserve` and
 * `disconnect` are no-ops and the callback is retained only so the shape is
 * right. That is the honest thing for it to be: jsdom has no layout, so there
 * is no resize to report and any callback invocation here would be inventing
 * one. A component that only paints on resize therefore paints once, at mount,
 * and never again — see the note in `DisassemblyView.dom.test.tsx` about what
 * the minimap and the breadcrumb fades are and are not covered by.
 *
 * WHAT THIS BUYS, EXACTLY: the components' own mount effects run to completion.
 * It buys **nothing** about sizing, overflow, fade indicators, or whether the
 * minimap's canvas is the right shape — every one of those is a layout question
 * jsdom cannot answer.
 */
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class ResizeObserver {
    // No constructor: the callback is accepted and dropped, because this never
    // fires. Declaring one only to ignore its argument is a Biome warning.
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  };
}

/**
 * OPT-IN, and the only thing here that is not installed automatically.
 *
 * `@tanstack/react-virtual` renders nothing at all unless its scroll container
 * reports a non-zero size: `virtual-core@3.13.18` computes its range as
 * `measurements.length > 0 && outerSize > 0 ? calculateRange(...) : null`, and
 * `outerSize` comes from one read of the scroll element's `offsetHeight`, taken
 * when `observeElementRect` subscribes (`getRect` there is
 * `({ offsetWidth, offsetHeight })` — NOT `getBoundingClientRect`, which is the
 * obvious guess and the wrong one). jsdom does no layout, so every
 * rect there is all-zero and a virtualized list renders **zero rows** — not a
 * short list, an empty one.
 *
 * Call this at the TOP LEVEL of a suite that mounts a virtualized list, before
 * anything renders. It defines `offsetHeight`/`offsetWidth`,
 * `clientHeight`/`clientWidth` and `getBoundingClientRect` on
 * `HTMLElement.prototype` — the four things the disassembly panel reads, kept
 * consistent with each other so no consumer can see two different worlds — for
 * that file only — vitest gives each test file its own jsdom environment
 * and its own prototypes, so nothing leaks into another suite. It is not
 * installed by default precisely because a world in which every element is
 * {@link height} tall is a lie that most suites have no need of.
 *
 * WHAT THIS BUYS, EXACTLY: the virtualizer computes a range, so rows exist in
 * the document and can be asserted on.
 *
 * WHAT IT DOES NOT BUY, AND THIS IS THE IMPORTANT HALF: **it does not make
 * virtualization real.** Every element reports the same rect, `scrollTop` stays
 * 0 because jsdom implements no scrolling, and the stub `ResizeObserver` above
 * never fires — so the range is computed once, from offset 0, and never moves.
 * Which rows are windowed in, whether `overscan` is right, whether
 * `scrollToIndex` puts the cursor on screen, and whether anything is *visible*
 * are all layout questions that stay unanswered. A row being in the document
 * here is not a row being on screen.
 */
export function stubLayoutRect({ height, width = 1200 }: { height: number; width?: number }): void {
  for (const [prop, value] of [
    ["offsetHeight", height],
    ["offsetWidth", width],
    ["clientHeight", height],
    ["clientWidth", width],
  ] as const) {
    Object.defineProperty(HTMLElement.prototype, prop, { configurable: true, get: () => value });
  }
  Object.defineProperty(HTMLElement.prototype, "getBoundingClientRect", {
    configurable: true,
    writable: true,
    value: (): DOMRect =>
      ({
        x: 0,
        y: 0,
        top: 0,
        left: 0,
        right: width,
        bottom: height,
        width,
        height,
        toJSON: () => ({}),
      }) as DOMRect,
  });
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
