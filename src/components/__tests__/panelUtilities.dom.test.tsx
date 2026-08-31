// @vitest-environment jsdom

import "../../test/domSetup";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import { DataInspector } from "../DataInspector";
import { ErrorBoundary } from "../ErrorBoundary";
import { ResizeHandle } from "../ResizeHandle";
import { Skeleton, SkeletonRows } from "../Skeleton";

/**
 * THE FOUR SMALL COMPONENTS NOTHING HAD EVER RENDERED.
 *
 * `ErrorBoundary`, `ResizeHandle` and `DataInspector` had no coverage of any
 * kind; `Skeleton` was reached incidentally by `Sidebar.dom.test.tsx` and
 * `StatusBar.dom.test.tsx` but never asserted on directly. None of the four
 * appears in CLAUDE.md's "Still NOT rendered" list, which named three surfaces
 * out of seventeen unrendered components — these are among the ones nobody had
 * counted.
 *
 * WHY EACH ONE NEEDS A RENDERER RATHER THAN A PURE TEST, since this repo's
 * standing preference is to extract the decision into an exported function and
 * test that (see CLAUDE.md, "Hook logic is otherwise tested by…"):
 *
 *  - **`ErrorBoundary` cannot be checked any other way at all.** Its whole
 *    behaviour is `getDerivedStateFromError` + `componentDidCatch`, which React
 *    calls only when a *render* throws. There is no signature to inspect, no
 *    pure function to extract, and `npm run typecheck` is equally happy with a
 *    class that declares neither hook — in which case the throw propagates and
 *    the user gets a blank page. The sharp negative control below is removing
 *    the catching half, not the fallback markup.
 *  - **`ResizeHandle` registers its listeners on `document`**, from inside a
 *    `mousedown` handler, and routes the callbacks through refs. Which callback
 *    a `mouseup` sees is a fact about a live tree across a re-render.
 *  - **`DataInspector`** is nearly pure, and the part worth checking is
 *    arithmetic — widths, signedness, endianness — but it is reached only
 *    through a `useMemo` in a component with an early return.
 *
 * WHAT THIS FILE DOES NOT COVER, and no assertion here should be read as
 * covering it. jsdom performs no layout, so `stubLayoutRect` is deliberately
 * NOT called here (nothing below virtualizes) and every geometric question is
 * out of reach: **the drag tests below prove that the callbacks fire with the
 * right deltas and nothing whatever about a panel changing size.** Tailwind is
 * not loaded in the test config either, so a class name carries no style — the
 * assertions on `className` are assertions on a *string*, stated as such.
 */

/* ────────────────────────────── ErrorBoundary ───────────────────────────── */

/** Throws during render, which is the only thing an error boundary reacts to. */
function Boom({ message = "kaboom-42" }: { message?: string }): never {
  throw new Error(message);
}

/** Throws a value that is not an `Error`, so `error?.message` is undefined. */
function BoomString(): never {
  // Throwing a non-Error is the point: it is the only way to reach the
  // `?? "Unknown error"` branch, and real code does it.
  throw "not-an-error-object";
}

describe("ErrorBoundary", () => {
  /**
   * React logs every error it hands to a boundary via `console.error`, and
   * `componentDidCatch` here logs a second time. Silenced DELIBERATELY and
   * per-test rather than globally: an unsilenced run prints two stack traces per
   * test into the gate output, and a global silence would hide a console.error
   * from an unrelated component. Each test that expects the logging asserts on
   * the spy, so the silence is not also a blindfold.
   */
  let errorLog: MockInstance<typeof console.error>;
  beforeEach(() => {
    errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    errorLog.mockRestore();
  });

  it("renders its children untouched when nothing throws", () => {
    render(
      <ErrorBoundary>
        <div>the main view</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText("the main view")).toBeTruthy();
    // Not the fallback: a boundary that renders its fallback unconditionally
    // would pass every other test in this describe block.
    expect(screen.queryByText("Something went wrong")).toBeNull();
  });

  it("catches a throw from a child and shows the fallback instead of nothing", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    // The two halves of "it caught": the child is gone, AND something is on
    // screen. A boundary that catches and returns null is a white screen, which
    // is the failure this component exists to prevent — so assert the page is
    // not blank rather than only that the throw did not escape.
    expect(screen.getByText("Something went wrong")).toBeTruthy();
    expect(document.body.textContent).toContain("Something went wrong");
    expect(document.body.textContent?.length ?? 0).toBeGreaterThan(0);
  });

  it("shows the thrown error's own message, so the fallback identifies the fault", () => {
    render(
      <ErrorBoundary>
        <Boom message="unique-marker-9f3" />
      </ErrorBoundary>,
    );
    expect(screen.getByText("unique-marker-9f3")).toBeTruthy();
  });

  it("says 'Unknown error' when what was thrown has no message", () => {
    render(
      <ErrorBoundary>
        <BoomString />
      </ErrorBoundary>,
    );
    // `this.state.error?.message ?? "Unknown error"` — reachable only by
    // throwing a non-Error, which real code does (a rejected string, a DOMError
    // from a browser API). Without this the branch is dead.
    expect(screen.getByText("Unknown error")).toBeTruthy();
  });

  it("logs the caught error, so a report is still possible from the console", () => {
    render(
      <ErrorBoundary>
        <Boom message="logged-marker" />
      </ErrorBoundary>,
    );
    const logged = errorLog.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
    expect(logged).toContain("ErrorBoundary caught:");
    expect(logged).toContain("logged-marker");
  });

  it("offers a recovery button, and it reloads the page", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    // `window.location.reload` is an own, NON-configurable property of jsdom's
    // Location, so it cannot be spied on; `window.location` itself is a
    // configurable accessor on `window`, so the whole object is replaced and
    // restored. Without the replacement jsdom logs "Not implemented:
    // navigation" to its virtual console instead of doing anything observable.
    const original = Object.getOwnPropertyDescriptor(window, "location");
    const reload = vi.fn();
    Object.defineProperty(window, "location", { configurable: true, value: { reload } });
    try {
      fireEvent.click(screen.getByRole("button", { name: "Reload" }));
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      if (original) Object.defineProperty(window, "location", original);
    }
  });

  /**
   * RE-RENDERING ALONE DOES NOT CLEAR THE ERROR, AND THAT IS NOW A DECISION
   * RATHER THAN A LIMITATION.
   *
   * When this was first written it pinned a real defect: `App` wrapped ONE
   * boundary around every mounted tab, so a throw anywhere replaced the whole
   * main area and — because `hasError` is never cleared on a re-render and the
   * boundary sat above the tab switch — changing tabs could not recover it. The
   * only exit was a page reload, which discards the parsed image and the
   * worker's disassembly. **That mount site is repaired**: it is one boundary
   * per tab pane now, so the blast radius is one tab (`peek-a-bin-p0qw`, and
   * `src/__tests__/App.dom.test.tsx` is where the blast radius is asserted).
   *
   * What this still pins is the boundary's own contract, and keeping it is
   * deliberate: an automatic reset on every re-render would retry a
   * deterministic fault on each parent render, flickering the fallback in and
   * out with no way to read it. Recovery is offered explicitly instead, by the
   * button the next test presses.
   */
  it("does not clear itself on a re-render, so a deterministic fault cannot flicker", () => {
    const { rerender } = render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    expect(screen.getByText("Something went wrong")).toBeTruthy();
    rerender(
      <ErrorBoundary>
        <div>healthy again</div>
      </ErrorBoundary>,
    );
    expect(screen.queryByText("healthy again")).toBeNull();
    expect(screen.getByText("Something went wrong")).toBeTruthy();
  });

  it("clears the error when Try again is pressed, and renders the children again", () => {
    // The counterpart to the case above. Nothing in the boundary decides whether
    // the fault has gone — the children simply run again — so the fixture stops
    // throwing between the two renders to make the outcome observable. A
    // deterministic fault throws straight back into the fallback, which is the
    // honest behaviour and cannot loop, since it takes a click.
    let boom = true;
    function Maybe() {
      if (boom) throw new Error("kaboom");
      return <div>healthy again</div>;
    }
    render(
      <ErrorBoundary>
        <Maybe />
      </ErrorBoundary>,
    );
    expect(screen.getByText("Something went wrong")).toBeTruthy();
    boom = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(screen.getByText("healthy again")).toBeTruthy();
    expect(screen.queryByText("Something went wrong")).toBeNull();
  });

  it("names the region it was guarding, when it was given one", () => {
    // The label exists because there is now more than one boundary: it is what
    // tells the user WHICH of the nine tabs failed, and therefore that the other
    // eight did not. `App` passes `VIEW_TAB_LABELS[key]`, so the fallback cannot
    // call a tab something the tab bar does not.
    render(
      <ErrorBoundary label="Hex">
        <Boom />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert").textContent).toContain("The Hex view went wrong");
  });

  it("falls back to a generic sentence with no label", () => {
    // The control for the case above: a label-shaped sentence that appeared
    // whatever was passed would satisfy it.
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Something went wrong");
    expect(alert.textContent).not.toContain("view went wrong");
  });

  /**
   * THE `"chrome"` VARIANT (`peek-a-bin-t23y`).
   *
   * The pane fallback is a centred card in a full-height flex container, which
   * is right for a tab pane and wrong everywhere the boundary went next: it
   * overflows a 224px sidebar column and dwarfs a 20px status strip, so the
   * boundary would push the rest of the app around to report a fault in
   * something the user was not looking at. The variant is the mount site saying
   * how much room it has, exactly as `label` is the mount site saying what it
   * is guarding.
   *
   * The blast-radius assertions live where the boundaries are mounted —
   * `src/__tests__/App.dom.test.tsx` for the sidebar and the status bar,
   * `DisassemblyPanel.dom.test.tsx` for the chat and bottom panels. What is
   * checked here is only what the variant itself changes.
   */
  it("states the region and the fault in one line, in the chrome variant", () => {
    render(
      <ErrorBoundary label="Sidebar" variant="chrome">
        <Boom message="unique-marker-c17" />
      </ErrorBoundary>,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Sidebar failed");
    expect(alert.textContent).toContain("unique-marker-c17");
    // Not the pane sentence: the two fallbacks are different renders, not one
    // render with different classes, so this is what says which ran.
    expect(alert.textContent).not.toContain("went wrong");
  });

  it("offers Try again but NOT Reload in the chrome variant", () => {
    // A DECISION, not an omission, and it is the variant's whole argument
    // restated as a control. A chrome boundary is only ever placed where the
    // app is still worth using without the region, so a reload — which discards
    // the parsed image and the worker's disassembly — is exactly the wrong
    // trade to put one click away from a user whose session is otherwise
    // intact. The pane fallback keeps it as the last resort; here it is not a
    // resort at all, and the browser's own reload still exists.
    render(
      <ErrorBoundary label="Sidebar" variant="chrome">
        <Boom />
      </ErrorBoundary>,
    );
    const alert = screen.getByRole("alert");
    expect(within(alert).getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(within(alert).queryByRole("button", { name: "Reload" })).toBeNull();
    // The control for the line above: the pane variant does offer it, so this
    // is a difference between the two rather than a button nobody renders.
    cleanup();
    render(
      <ErrorBoundary label="Sidebar">
        <Boom />
      </ErrorBoundary>,
    );
    expect(within(screen.getByRole("alert")).getByRole("button", { name: "Reload" })).toBeTruthy();
  });

  it("recovers the region in place from the chrome fallback", () => {
    function Flaky({ fail }: { fail: boolean }) {
      if (fail) throw new Error("flaky");
      return <div>chrome healthy</div>;
    }
    const { rerender } = render(
      <ErrorBoundary label="Chat" variant="chrome">
        <Flaky fail={true} />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert").textContent).toContain("Chat failed");
    rerender(
      <ErrorBoundary label="Chat" variant="chrome">
        <Flaky fail={false} />
      </ErrorBoundary>,
    );
    // Still the fallback: `hasError` is deliberately NOT cleared on a re-render
    // — an automatic reset would retry a deterministic fault on every parent
    // render and flicker the fallback with no way to read it. Recovery is the
    // click, in both variants.
    expect(screen.getByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(screen.getByText("chrome healthy")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("marks the fallback as an alert, so a replaced region is announced", () => {
    // The one a11y assertion in this file, and the reason it is worth one: the
    // fallback REPLACES a region of the page after the fact, which is precisely
    // the case a live region exists for. Nothing else here has been near a
    // screen reader — see CLAUDE.md's standing note that the a11y work has never
    // met one.
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeTruthy();
  });
});

/* ────────────────────────────── ResizeHandle ────────────────────────────── */

describe("ResizeHandle", () => {
  it("is a labelled button, one label per orientation", () => {
    const { unmount } = render(<ResizeHandle onResize={() => {}} />);
    // Default orientation is horizontal.
    expect(screen.getByRole("button", { name: "Resize panel width" })).toBeTruthy();
    unmount();
    render(<ResizeHandle orientation="vertical" onResize={() => {}} />);
    expect(screen.getByRole("button", { name: "Resize panel height" })).toBeTruthy();
  });

  it("carries the per-orientation class NAME (a string; Tailwind is not loaded)", () => {
    const { unmount } = render(<ResizeHandle onResize={() => {}} />);
    expect(screen.getByRole("button").className).toBe("panel-handle-h");
    unmount();
    render(<ResizeHandle orientation="vertical" onResize={() => {}} />);
    expect(screen.getByRole("button").className).toBe("panel-handle-v");
  });

  it("reports horizontal drag deltas from clientX, each relative to the last move", () => {
    const onResize = vi.fn();
    render(<ResizeHandle onResize={onResize} />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientX: 100, clientY: 400 });
    // The listeners are added to `document`, not to the button, so the moves are
    // dispatched there. Deltas are incremental: +30, then -10, then +5.
    fireEvent.mouseMove(document, { clientX: 130, clientY: 400 });
    fireEvent.mouseMove(document, { clientX: 120, clientY: 400 });
    fireEvent.mouseMove(document, { clientX: 125, clientY: 400 });
    expect(onResize.mock.calls.map((c) => c[0])).toEqual([30, -10, 5]);
  });

  it("reads clientY when vertical, and ignores clientX entirely", () => {
    const onResize = vi.fn();
    render(<ResizeHandle orientation="vertical" onResize={onResize} />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientX: 10, clientY: 200 });
    // clientX moves by a large amount that must NOT appear in the deltas — this
    // is what makes the axis assertion an assertion rather than a coincidence.
    fireEvent.mouseMove(document, { clientX: 999, clientY: 188 });
    fireEvent.mouseMove(document, { clientX: 0, clientY: 190 });
    expect(onResize.mock.calls.map((c) => c[0])).toEqual([-12, 2]);
  });

  it("ends the drag on mouseup: onResizeEnd fires once and later moves are dead", () => {
    const onResize = vi.fn();
    const onResizeEnd = vi.fn();
    render(<ResizeHandle onResize={onResize} onResizeEnd={onResizeEnd} />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientX: 100 });
    fireEvent.mouseMove(document, { clientX: 110 });
    fireEvent.mouseUp(document);
    expect(onResizeEnd).toHaveBeenCalledTimes(1);
    // The whole point of removeEventListener: a mouse move after the button is
    // released must not still be resizing the panel.
    fireEvent.mouseMove(document, { clientX: 400 });
    expect(onResize).toHaveBeenCalledTimes(1);
  });

  it("sets the drag cursor on <body> and restores it on mouseup", () => {
    render(<ResizeHandle onResize={() => {}} />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientX: 0 });
    // Inline styles on <body>, which jsdom does record — this is a DOM property
    // assertion, not a rendered-appearance one.
    expect(document.body.style.cursor).toBe("col-resize");
    expect(document.body.style.userSelect).toBe("none");
    fireEvent.mouseUp(document);
    expect(document.body.style.cursor).toBe("");
    expect(document.body.style.userSelect).toBe("");
  });

  it("uses row-resize for the vertical orientation", () => {
    render(<ResizeHandle orientation="vertical" onResize={() => {}} />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientY: 0 });
    expect(document.body.style.cursor).toBe("row-resize");
    fireEvent.mouseUp(document);
  });

  /**
   * THE REGRESSION THE `useRef` INDIRECTION EXISTS FOR, asserted end to end.
   * `ResizeHandle.tsx`'s own comment records it: the document listeners are
   * registered once per drag, so a naive implementation closes over the
   * callbacks as of `mousedown`. Callers pass inline arrows that read the panel
   * width from their render scope, so `onResizeEnd` persisted the PRE-drag width
   * on every resize. Nothing static can see this — both versions typecheck and
   * both call a function of the right shape.
   */
  it("calls the callbacks from the LATEST render, not the ones captured at mousedown", () => {
    const calls: string[] = [];
    function Harness() {
      const [width, setWidth] = useState(100);
      return (
        <>
          <ResizeHandle
            onResize={(delta) => {
              calls.push(`resize@${width}:${delta}`);
              setWidth((w) => w + delta);
            }}
            onResizeEnd={() => calls.push(`end@${width}`)}
          />
          <span data-testid="w">{width}</span>
        </>
      );
    }
    render(<Harness />);
    fireEvent.mouseDown(screen.getByRole("button"), { clientX: 0 });
    fireEvent.mouseMove(document, { clientX: 10 });
    fireEvent.mouseMove(document, { clientX: 15 });
    fireEvent.mouseUp(document);
    // Each callback saw the width as of its own render: 100, then 110, and the
    // end handler saw 115 — not the 100 a mousedown-time closure would have.
    expect(calls).toEqual(["resize@100:10", "resize@110:5", "end@115"]);
    expect(screen.getByTestId("w").textContent).toBe("115");
  });

  it("resizes by keyboard, one 16px step per arrow press, and ends each step", async () => {
    const onResize = vi.fn();
    const onResizeEnd = vi.fn();
    render(<ResizeHandle onResize={onResize} onResizeEnd={onResizeEnd} />);
    const handle = screen.getByRole("button");
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(onResize.mock.calls.map((c) => c[0])).toEqual([16, -16]);
    // `onResize` lands inline; `onResizeEnd` is deferred by one microtask so a
    // caller reading its own state sees the committed value. See the comment on
    // `handleKeyDown` — the awaits below are the visible cost of that, and the
    // reason they are here rather than in the mouse tests.
    expect(onResizeEnd).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(onResizeEnd).toHaveBeenCalledTimes(2);
  });

  /**
   * THE CONTRACT, ASSERTED ONCE FOR ALL FOUR CALLERS rather than at each of them.
   *
   * The natural way to write `onResizeEnd` is to read the size out of the
   * component's own render scope — all four call sites did, and three were wrong
   * because of it (peek-a-bin-ob8e, peek-a-bin-a2ze). The mouse path was always
   * fine: `mouseup` is a separate event, after React has committed the last
   * `mousemove`. The keyboard path was not, because `onResize` and `onResizeEnd`
   * ran in one handler with no render between them, so the callback the refs
   * handed back had never seen the new size.
   *
   * This harness is deliberately the NAIVE caller — state, no ref — because that
   * is the shape the component has to be safe for. `panelUtilities`' other
   * keyboard test uses a `vi.fn()` and therefore cannot see this class at all: it
   * can only say that `onResizeEnd` was called, never what a real caller would
   * have stored.
   */
  it("hands onResizeEnd the size as of AFTER the keyboard step, not before it", async () => {
    const stored: number[] = [];
    function NaiveCaller() {
      const [size, setSize] = useState(100);
      return (
        <ResizeHandle
          onResize={(delta) => setSize((s) => s - delta)}
          // Reads render state, with no ref anywhere. This is the shape that was
          // broken and the shape the deferral exists to make safe.
          onResizeEnd={() => stored.push(size)}
        />
      );
    }
    render(<NaiveCaller />);
    const handle = screen.getByRole("button");
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    await Promise.resolve();
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    await Promise.resolve();
    // 100 -> 84 -> 68 (ArrowRight is +16 through `s - delta`). Called inline the
    // caller would have pushed [100, 84]: correct in shape, one step stale.
    expect(stored).toEqual([84, 68]);
  });

  it("maps the arrow keys onto the handle's own axis and ignores the other axis", () => {
    const onResize = vi.fn();
    render(<ResizeHandle orientation="vertical" onResize={onResize} />);
    const handle = screen.getByRole("button");
    fireEvent.keyDown(handle, { key: "ArrowDown" });
    fireEvent.keyDown(handle, { key: "ArrowUp" });
    // The horizontal arrows belong to the other orientation and must do nothing
    // here, or a vertical handle would resize on a left/right press.
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    fireEvent.keyDown(handle, { key: "Enter" });
    expect(onResize.mock.calls.map((c) => c[0])).toEqual([16, -16]);
  });
});

/* ────────────────────────────── DataInspector ───────────────────────────── */

/**
 * The bytes below are chosen so that every assertion is HAND-DERIVABLE and so
 * that a wrong width or a byte-swap changes the answer. Reading the same value
 * back out of a second `DataView` would only prove `DataView` agrees with
 * itself, and a formatter slip here is invisible to `npm run typecheck` and to
 * every corpus gate — nothing else in the repo reads this component.
 */
const ASCII_8 = Uint8Array.from([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]); // "ABCDEFGH"

function labelled(label: string): string {
  // The grid renders each row as two sibling spans inside a `contents` div, so
  // the value is the label element's next sibling rather than a child.
  const span = screen.getByText(label);
  return span.nextElementSibling?.textContent ?? "";
}

describe("DataInspector", () => {
  it("reads every integer width little-endian from the selected offset", () => {
    render(<DataInspector offset={0} bytes={ASCII_8} baseAddress={0x140001000} />);
    // 0x41 = 65.
    expect(labelled("Int8")).toBe("65 (u: 65)");
    // Bytes 41 42 little-endian => 0x4241 = 16961. A big-endian read would say
    // 0x4142 = 16706, so this assertion is about the byte order, not the width.
    expect(labelled("Int16 LE")).toBe("16961 (u: 16961)");
    // Bytes 41 42 43 44 => 0x44434241 = 1145258561. Big-endian would be
    // 0x41424344 = 1094861636.
    expect(labelled("Int32 LE")).toBe("1145258561 (u: 1145258561)");
  });

  it("shows both the signed and the unsigned reading of the same bytes", () => {
    const ff = Uint8Array.from([0xff, 0xff, 0xff, 0xff]);
    render(<DataInspector offset={0} bytes={ff} baseAddress={0} />);
    // The pair is the whole value of the row: -1 and 4294967295 are the same
    // four bytes, and a viewer needs to be told which reading is which.
    expect(labelled("Int8")).toBe("-1 (u: 255)");
    expect(labelled("Int16 LE")).toBe("-1 (u: 65535)");
    expect(labelled("Int32 LE")).toBe("-1 (u: 4294967295)");
  });

  it("decodes a 32-bit float little-endian, at 7 significant digits", () => {
    // 00 00 80 3F little-endian is 0x3F800000, IEEE-754 single 1.0 exactly.
    // Read big-endian the same bytes are 0x0000803F, a subnormal near 4.6e-41,
    // so "1.000000" is evidence about the byte order and not just the width.
    render(
      <DataInspector
        offset={0}
        bytes={Uint8Array.from([0x00, 0x00, 0x80, 0x3f])}
        baseAddress={0}
      />,
    );
    expect(labelled("Float32 LE")).toBe("1.000000");
    // Only four bytes are available, so the 64-bit row must be withheld rather
    // than read out of bounds.
    expect(screen.queryByText("Float64 LE")).toBeNull();
  });

  it("decodes a 64-bit float little-endian, at 15 significant digits", () => {
    // 00 00 00 00 00 00 F8 3F is 0x3FF8000000000000 = 1.5 exactly.
    const d = Uint8Array.from([0, 0, 0, 0, 0, 0, 0xf8, 0x3f]);
    render(<DataInspector offset={0} bytes={d} baseAddress={0} />);
    expect(labelled("Float64 LE")).toBe("1.50000000000000");
    // The same eight bytes read as a single are 0x00000000 = +0.
    expect(labelled("Float32 LE")).toBe("0.000000");
  });

  it("reads a float whose value is not a round number, to pin the precision", () => {
    render(<DataInspector offset={0} bytes={ASCII_8} baseAddress={0} />);
    // 0x44434241: sign 0, exponent 0x88 = 136 => 2^9, mantissa 0x434241's low
    // 23 bits = 4407873, so (1 + 4407873/8388608) * 512 = 781.03515625, printed
    // at `toPrecision(7)`.
    expect(labelled("Float32 LE")).toBe("781.0352");
    // 0x4847464544434241: exponent 0x484 = 1156 => 2^133, so ~1.58e40.
    expect(labelled("Float64 LE")).toBe("1.58398001038048e+40");
  });

  it("shows the printable ASCII run and stops at the first byte outside it", () => {
    const s = Uint8Array.from([0x50, 0x45, 0x00, 0x41, 0x42]); // "PE", NUL, "AB"
    render(<DataInspector offset={0} bytes={s} baseAddress={0} />);
    // The run STOPS at the NUL rather than skipping it, so the trailing "AB" is
    // not part of this string.
    expect(labelled("ASCII")).toBe('"PE"');
  });

  it("omits the ASCII row when the first byte is not printable", () => {
    render(
      <DataInspector
        offset={0}
        bytes={Uint8Array.from([0x00, 0x41, 0x42, 0x43])}
        baseAddress={0}
      />,
    );
    expect(screen.queryByText("ASCII")).toBeNull();
    // …and the numeric rows are still there, so the omission is the string row
    // alone and not the component bailing out.
    expect(labelled("Int8")).toBe("0 (u: 0)");
  });

  it("decodes UTF-16LE only where the high bytes are zero", () => {
    const wide = Uint8Array.from([0x50, 0x00, 0x45, 0x00, 0x00, 0x00]); // L"PE"
    render(<DataInspector offset={0} bytes={wide} baseAddress={0} />);
    expect(labelled("UTF-16LE")).toBe('"PE"');
    // The same bytes are a one-character ASCII run, because the ASCII scan stops
    // at the NUL in the second byte. Both rows appear and they disagree, which
    // is correct: they are two readings of the same bytes.
    expect(labelled("ASCII")).toBe('"P"');
  });

  it("omits the UTF-16LE row for dense ASCII, where no high byte is zero", () => {
    render(<DataInspector offset={0} bytes={ASCII_8} baseAddress={0} />);
    expect(labelled("ASCII")).toBe('"ABCDEFGH"');
    // 0x42 is not a zero high byte, so there is no wide string here at all.
    expect(screen.queryByText("UTF-16LE")).toBeNull();
  });

  it("reads from the offset it was given, not from the start of the buffer", () => {
    render(<DataInspector offset={4} bytes={ASCII_8} baseAddress={0} />);
    expect(labelled("Int8")).toBe("69 (u: 69)"); // 0x45 = 'E'
    expect(labelled("ASCII")).toBe('"EFGH"');
  });

  it("withholds every row wider than what is left at the tail of the buffer", () => {
    render(<DataInspector offset={7} bytes={ASCII_8} baseAddress={0} />);
    // One byte remains, so Int8 and the one-character ASCII run are all that can
    // be read. Reading Int16 here would be an out-of-bounds DataView access —
    // the guards are the reason this renders at all.
    expect(labelled("Int8")).toBe("72 (u: 72)");
    expect(labelled("ASCII")).toBe('"H"');
    for (const gone of ["Int16 LE", "Int32 LE", "Float32 LE", "Float64 LE", "UTF-16LE"]) {
      expect(screen.queryByText(gone)).toBeNull();
    }
  });

  it("renders nothing at all when the offset is past the end", () => {
    const { container } = render(<DataInspector offset={8} bytes={ASCII_8} baseAddress={0} />);
    // `if (!data) return null` — the panel is absent rather than an empty shell,
    // which is what the caller's `selectedOffset !== null` guard assumes.
    expect(container.innerHTML).toBe("");
  });

  it("labels the selection with its offset and its virtual address, in hex", () => {
    render(<DataInspector offset={0x24} bytes={new Uint8Array(0x40)} baseAddress={0x140001000} />);
    // VA = baseAddress + offset = 0x140001024. The header is the only place the
    // component uses `baseAddress` at all.
    expect(screen.getByText(/Offset: 0x24/)).toBeTruthy();
    expect(screen.getByText(/VA: 0x140001024/)).toBeTruthy();
  });

  it("reads through a subarray's byteOffset rather than off the head of its buffer", () => {
    // A real caller hands it `sectionBytes`, a view onto the whole loaded file.
    // The memo slices `bytes.buffer` and must add `bytes.byteOffset`; without
    // that it would read the file's first bytes for every section.
    const backing = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x41, 0x42, 0x43, 0x44]);
    render(<DataInspector offset={0} bytes={backing.subarray(4)} baseAddress={0} />);
    expect(labelled("Int8")).toBe("65 (u: 65)");
    expect(labelled("ASCII")).toBe('"ABCD"');
  });
});

/* ──────────────────────────────── Skeleton ─────────────────────────────── */

describe("Skeleton", () => {
  it("renders one shimmer box at the default size", () => {
    const { container } = render(<Skeleton />);
    const box = container.firstElementChild as HTMLElement;
    expect(box).toBeTruthy();
    // Class NAME only — Tailwind and the app stylesheet are not loaded, so
    // whether it shimmers is not decidable here.
    expect(box.className).toContain("skeleton-shimmer");
    expect(box.style.width).toBe("100%");
    expect(box.style.height).toBe("12px");
  });

  it("passes an explicit width and height through as inline styles", () => {
    const { container } = render(<Skeleton width="60px" height="10px" />);
    const box = container.firstElementChild as HTMLElement;
    expect(box.style.width).toBe("60px");
    expect(box.style.height).toBe("10px");
  });

  it("draws one row per requested count, at varying widths", () => {
    const { container } = render(<SkeletonRows count={4} />);
    const rows = container.querySelectorAll(".skeleton-shimmer");
    expect(rows.length).toBe(4);
    // `60 + ((i * 17) % 35)` — the widths differ, which is the only reason the
    // placeholder reads as text rather than as a block.
    expect(Array.from(rows).map((r) => (r as HTMLElement).style.width)).toEqual([
      "60%",
      "77%",
      "94%",
      "76%",
    ]);
  });

  it("defaults to ten rows", () => {
    const { container } = render(<SkeletonRows />);
    expect(container.querySelectorAll(".skeleton-shimmer").length).toBe(10);
  });
});
