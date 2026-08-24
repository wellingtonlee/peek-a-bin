/**
 * Stand-ins for two browser APIs jsdom does not implement, for the component
 * tests that mount something whose effects construct them.
 *
 * Both are ABSENT rather than degraded in jsdom 28 — `typeof ResizeObserver`
 * is `"undefined"` and `window.matchMedia` is not a function — and both are
 * reached from inside a `useEffect`, so the resulting throw tears the whole
 * tree down. `HexView`'s entropy-strip measurement effect uses both, one line
 * apart, which is why they are stubbed together: flipping the Entropy toggle
 * dies on the first and then on the second, neither for a reason connected to
 * the behaviour under test.
 *
 * NOT INSTALLED BY `domSetup.ts`, deliberately. That module is imported by
 * every component test, and these are wanted by one; a global that a single
 * suite depends on is better named at that suite's own import site, where a
 * reader can see why it is there. Import this NEXT TO `domSetup`, never instead
 * of it — `build/domTestNaming.test.ts` requires that one by name, and it
 * installs the `offsetParent` shim and the unmount hook that these do not.
 *
 * WHAT THESE BUY, EXACTLY: an effect that constructs an observer or a media
 * query runs to completion instead of throwing, and its cleanup finds the
 * methods it calls.
 *
 * WHAT THEY BUY ABOUT LAYOUT: NOTHING, AND THEY CANNOT.
 *
 *  - The observer's callback fires once on `observe`, mirroring the real
 *    contract that an observation arrives without waiting for a resize — but
 *    with an EMPTY entry list, so a component reading `entries[0]?.contentRect`
 *    takes its own fallback, and in jsdom every fallback (`clientWidth`,
 *    `getBoundingClientRect`) is a constant 0. Fabricating a width here would
 *    be inventing a measurement no browser made. No resize is ever synthesised
 *    either: nothing in jsdom can change an element's size, so a second
 *    delivery would be fiction.
 *  - The media query reports `matches: false` and never fires a change. jsdom
 *    has no device-pixel-ratio to query and no way to alter one, so a stub that
 *    claimed a match would be asserting a display that does not exist.
 *
 * The consequence for `HexView` specifically: `stripDevicePx` stays 0, the
 * strip's `showEntropy && stripDevicePx > 0` gate stays closed, `useEntropyStrip`
 * is asked for nothing and the canvas draws nothing — so the entropy path is
 * still unexercised, and that is a property of the environment rather than of
 * this file. Do not write an assertion that reads as being about a measured
 * width, a device pixel ratio, or a drawn strip.
 */

type ObserverCallback = (entries: ResizeObserverEntry[], observer: ResizeObserver) => void;

class ResizeObserverStub implements ResizeObserver {
  private readonly callback: ObserverCallback;

  constructor(callback: ObserverCallback) {
    this.callback = callback;
  }

  observe(): void {
    // Empty entries, on purpose — see the docstring. The observed element is
    // not passed on either, so a caller cannot mistake this for a measurement.
    this.callback([], this);
  }

  unobserve(): void {}

  disconnect(): void {}
}

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
}

if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}
