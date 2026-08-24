import { afterEach, describe, expect, it, vi } from "vitest";
import { copyText } from "../clipboard";

/**
 * `copyText`'s own logic, with no DOM.
 *
 * A NODE suite, deliberately: `copyText` reads exactly one global and every
 * branch it has is reachable by substituting that global, so a jsdom
 * environment (~2s of setup per file) would buy nothing. CLAUDE.md says to
 * prefer the pure form where it works; this is a case where it works
 * completely. The call sites' *behaviour* — whether the tick still appears, and
 * what appears instead when it does not — is a rendering question and is tested
 * in `components/__tests__/HeaderView.dom.test.tsx`.
 *
 * WHAT THIS IS A STAND-IN FOR, SAID PLAINLY. The defect being fixed is that
 * `navigator.clipboard` is a secure-context API and is ABSENT over plain
 * `http:` off localhost, which is a supported deployment here (nginx). Nothing
 * in this repo has served the app over plain http to a browser. These tests
 * simulate the absence by replacing `navigator`, exactly as
 * `test/domSetup.ts`'s `offsetParent` shim stands in for layout — so they show
 * that `copyText` and its callers behave when the API is missing, NOT that a
 * browser removes it under the conditions the specification says it does.
 */

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Install a `navigator` whose `clipboard` is exactly `clipboard`. */
function withNavigator(clipboard: unknown): void {
  vi.stubGlobal("navigator", { clipboard });
}

describe("copyText, when the clipboard is there", () => {
  it("writes the text verbatim and reports success", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    withNavigator({ writeText });
    expect(await copyText("0xDEADBEEF")).toBe(true);
    expect(writeText.mock.calls).toEqual([["0xDEADBEEF"]]);
  });

  it("passes the empty string through rather than treating it as nothing to do", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    withNavigator({ writeText });
    expect(await copyText("")).toBe(true);
    expect(writeText.mock.calls).toEqual([[""]]);
  });

  it("calls writeText with the clipboard as its receiver", async () => {
    // Not pedantry: a real `Clipboard.prototype.writeText` is a native method
    // that throws `Illegal invocation` if it is detached from its object, so
    // pulling the function out to feature-test it and then calling the loose
    // reference would fail in a browser and pass against any plain-object stub
    // here. This is the assertion that keeps the feature test from becoming
    // the call.
    const seen: unknown[] = [];
    const clipboard = {
      writeText(this: unknown) {
        seen.push(this);
        return Promise.resolve();
      },
    };
    withNavigator(clipboard);
    await copyText("x");
    expect(seen).toEqual([clipboard]);
  });

  /**
   * THE ORDERING GUARANTEE, and the reason it is asserted rather than trusted:
   * a clipboard write is only permitted from within the user gesture that
   * triggered it, so an `await` inserted above the `writeText` call would make
   * every copy fail in a real browser while every test here still passed. So
   * assert that the call has already happened before `copyText`'s promise is
   * even awaited.
   */
  it("calls writeText before it first suspends, so it stays in the user gesture", () => {
    const writeText = vi.fn(() => Promise.resolve());
    withNavigator({ writeText });
    const pending = copyText("x");
    expect(writeText).toHaveBeenCalledTimes(1);
    return pending;
  });
});

describe("copyText, when the clipboard is not there", () => {
  it("reports failure when navigator has no clipboard at all", async () => {
    // THE HTTP DEPLOYMENT. `navigator.clipboard` is `[SecureContext]`, so over
    // plain http off localhost the property is simply absent — which is why the
    // 18 unguarded call sites threw a TypeError rather than rejecting.
    withNavigator(undefined);
    expect(await copyText("x")).toBe(false);
  });

  it("reports failure when the clipboard object exists without writeText", async () => {
    // A partial surface is not hypothetical — an object can be present with
    // only `readText`, and a page can install a stub. Feature-testing
    // `clipboard` alone would call `undefined` here.
    withNavigator({ readText: () => Promise.resolve("") });
    expect(await copyText("x")).toBe(false);
  });

  it("reports failure when writeText is present but not callable", async () => {
    withNavigator({ writeText: "not a function" });
    expect(await copyText("x")).toBe(false);
  });

  it("reports failure when there is no navigator at all", async () => {
    vi.stubGlobal("navigator", undefined);
    expect(await copyText("x")).toBe(false);
  });
});

describe("copyText, when the write itself fails", () => {
  it("reports failure on a rejection, without rethrowing", async () => {
    // The denied-permission case, and Firefox's refusal to write from an
    // unfocused document.
    withNavigator({ writeText: () => Promise.reject(new Error("Write permission denied.")) });
    expect(await copyText("x")).toBe(false);
  });

  it("reports failure when writeText throws synchronously", async () => {
    withNavigator({
      writeText: () => {
        throw new TypeError("Illegal invocation");
      },
    });
    expect(await copyText("x")).toBe(false);
  });

  it("reports success when writeText returns a non-promise", async () => {
    // Several test doubles in this repo stub `writeText` as a bare `vi.fn()`,
    // which returns `undefined`. Awaiting that is fine and the write did
    // happen, so the honest answer is success — pinned so a future rewrite
    // cannot start demanding a thenable and quietly turn those into failures.
    const writeText = vi.fn();
    withNavigator({ writeText });
    expect(await copyText("x")).toBe(true);
  });
});
