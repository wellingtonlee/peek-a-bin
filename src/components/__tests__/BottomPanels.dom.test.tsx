// @vitest-environment jsdom

import "../../test/domSetup";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DisasmFunction, Instruction } from "../../disasm/types";
import { BottomPanelContainer } from "../BottomPanelContainer";
import { CallPanel } from "../CallPanel";

/**
 * THE TABBED BOTTOM PANEL AND ITS CALL-GRAPH TAB, rendered for the first time.
 *
 * `BottomPanelContainer` (303 lines, including the floating `FloatingPanel` it
 * does not export) and `CallPanel` (141) had no coverage of any kind. Both are
 * mounted from `DisassemblyView.tsx:1554`, whose own test files stop above the
 * bottom panels.
 *
 * `XrefPanel` — the third tab — is in its own file, and that is not arbitrary:
 * it virtualizes, so it needs `stubLayoutRect`, which redefines `offsetHeight`
 * and `getBoundingClientRect` on `HTMLElement.prototype` for a whole file. This
 * container's own assertions are about inline styles that React wrote and about
 * class name strings, and installing a world where every element is 600px tall
 * would put a lie underneath them for no benefit. `InstructionDetail`, the
 * remaining tab, is already reached by `DisassemblyPanel.dom.test.tsx`.
 *
 * WHAT NONE OF THIS COVERS. jsdom performs no layout, so the drag and resize
 * tests below prove that the mouse handlers compute the right numbers and write
 * them into the right inline styles — **not that anything moved or resized on
 * screen.** Tailwind is not loaded either, so `className="hidden"` carries no
 * `display: none`; where an inactive panel is asserted to be hidden, the
 * assertion is on the class NAME as a string and is written to say so.
 */

/* ─────────────────────────── BottomPanelContainer ───────────────────────── */

const HEIGHT_KEY = "peek-a-bin:bottom-panel-height";

interface PanelSpec {
  id: string;
  label: string;
  visible: boolean;
  content: React.ReactNode;
  onClose: () => void;
}

function panel(id: string, label: string, visible = true, onClose = () => {}): PanelSpec {
  return { id, label, visible, content: <div>{`${id} body`}</div>, onClose };
}

/** The tab strip's per-panel buttons carry titles rather than text. */
function popOutButtons() {
  return screen.getAllByTitle("Pop out");
}

describe("BottomPanelContainer", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    localStorage.clear();
    setViewport(JSDOM_W, JSDOM_H);
  });

  /**
   * ITS NEGATIVE CONTROL IS INERT, AND THAT IS REPORTED RATHER THAN TUNED AWAY.
   * Deleting `if (visiblePanels.length === 0) return null;` leaves this test
   * GREEN — and no test could fail, because the early return is REDUNDANT: with
   * no visible panel, `tabbedPanels.length > 0 &&` is already false and
   * `floatingPanels` is already empty, so the fragment renders nothing either
   * way. The assertion is still worth keeping (an empty strip IS the defect a
   * reader would look for here); what is worth knowing is that it constrains the
   * OUTPUT and not that particular line.
   */
  it("renders nothing when no panel is visible", () => {
    const { container } = render(
      <BottomPanelContainer panels={[panel("a", "Alpha", false), panel("b", "Beta", false)]} />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("shows a tab per visible panel and hides the invisible ones entirely", () => {
    render(
      <BottomPanelContainer
        panels={[panel("a", "Alpha"), panel("b", "Beta", false), panel("c", "Gamma")]}
      />,
    );
    expect(screen.getByRole("button", { name: "Alpha" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Gamma" })).toBeTruthy();
    // Not merely hidden: an invisible panel has no tab and its content is not
    // in the document at all.
    expect(screen.queryByRole("button", { name: "Beta" })).toBeNull();
    expect(screen.queryByText("b body")).toBeNull();
  });

  it("activates the first visible panel on mount", () => {
    render(<BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />);
    // `activeTab` starts as "" and an effect fills it in; the highlight is the
    // only externally visible statement of which tab is active.
    expect(screen.getByRole("button", { name: "Alpha" }).parentElement?.className).toContain(
      "bg-blue-600",
    );
    expect(screen.getByRole("button", { name: "Beta" }).parentElement?.className).not.toContain(
      "bg-blue-600",
    );
  });

  it("MOUNTS every tab's content and marks the inactive ones with the 'hidden' class", () => {
    render(<BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />);
    // BOTH bodies are in the document — the container does not unmount an
    // inactive tab, so a panel keeps its state (and keeps doing its work) while
    // hidden. That is a real property with a real cost: XrefPanel's virtualizer
    // and CallPanel's memos run for a tab nobody is looking at.
    const a = screen.getByText("a body").parentElement as HTMLElement;
    const b = screen.getByText("b body").parentElement as HTMLElement;
    // CLASS NAME ONLY. Tailwind is not loaded in the test config, so "hidden"
    // carries no `display: none` here and nothing below is an assertion about
    // visibility.
    expect(a.className).toBe("h-full");
    expect(b.className).toBe("hidden");
  });

  it("switches the active tab when its label is clicked", () => {
    render(<BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />);
    fireEvent.click(screen.getByRole("button", { name: "Beta" }));
    expect((screen.getByText("a body").parentElement as HTMLElement).className).toBe("hidden");
    expect((screen.getByText("b body").parentElement as HTMLElement).className).toBe("h-full");
  });

  it("calls the panel's OWN onClose, not the container's, and not a neighbour's", () => {
    const closeA = vi.fn();
    const closeB = vi.fn();
    render(
      <BottomPanelContainer
        panels={[panel("a", "Alpha", true, closeA), panel("b", "Beta", true, closeB)]}
      />,
    );
    // The close buttons are ordered as the tabs are, so index 1 is Beta's.
    fireEvent.click(screen.getAllByTitle("Close")[1]);
    expect(closeB).toHaveBeenCalledTimes(1);
    expect(closeA).not.toHaveBeenCalled();
  });

  it("falls back to the first surviving tab when the active one becomes invisible", () => {
    const { rerender } = render(
      <BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />,
    );
    expect((screen.getByText("a body").parentElement as HTMLElement).className).toBe("h-full");
    rerender(<BottomPanelContainer panels={[panel("a", "Alpha", false), panel("b", "Beta")]} />);
    // Without the effect the container would render a tab strip with nothing
    // active and an empty body area.
    expect((screen.getByText("b body").parentElement as HTMLElement).className).toBe("h-full");
  });

  describe("height", () => {
    it("starts at the default height", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      // An inline style React wrote from state — not a measurement. jsdom does
      // no layout, so the rendered height of anything here is 0.
      expect(strip().style.height).toBe("220px");
    });

    it("restores a persisted height on mount", () => {
      localStorage.setItem(HEIGHT_KEY, "310");
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      expect(strip().style.height).toBe("310px");
    });

    it("ignores a persisted height outside the allowed range", () => {
      localStorage.setItem(HEIGHT_KEY, "5000");
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      // A stored value that is out of range, non-numeric or absent all mean the
      // same thing: use the default rather than a panel taller than the window.
      expect(strip().style.height).toBe("220px");
    });

    it("ignores unparseable persisted junk", () => {
      localStorage.setItem(HEIGHT_KEY, "not-a-number");
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      expect(strip().style.height).toBe("220px");
    });

    it("grows when the handle is dragged UP, because the panel is anchored below", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      const handle = screen.getByRole("button", { name: "Resize panel height" });
      fireEvent.mouseDown(handle, { clientY: 500 });
      // A negative delta (moving up the screen) must INCREASE the height:
      // `prev - delta`. Getting this sign wrong is the classic bottom-panel bug
      // and it is invisible to typecheck.
      fireEvent.mouseMove(document, { clientY: 470 });
      expect(strip().style.height).toBe("250px");
      fireEvent.mouseMove(document, { clientY: 480 });
      expect(strip().style.height).toBe("240px");
      fireEvent.mouseUp(document);
    });

    it("persists the height reached at the END of the drag, not the one it started at", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      const handle = screen.getByRole("button", { name: "Resize panel height" });
      fireEvent.mouseDown(handle, { clientY: 500 });
      fireEvent.mouseMove(document, { clientY: 460 });
      fireEvent.mouseUp(document);
      // THE REGRESSION `ResizeHandle`'s ref indirection EXISTS FOR, seen from
      // the caller's side: `handleResizeEnd` closes over `height` from its own
      // render, so a mouseup handler captured at mousedown would store 220 —
      // the pre-drag width — however far the user dragged.
      expect(localStorage.getItem(HEIGHT_KEY)).toBe("260");
      expect(strip().style.height).toBe("260px");
    });

    it("clamps to the minimum and the maximum", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      const handle = screen.getByRole("button", { name: "Resize panel height" });
      fireEvent.mouseDown(handle, { clientY: 500 });
      fireEvent.mouseMove(document, { clientY: 5000 }); // far down: shrink past MIN
      expect(strip().style.height).toBe("80px");
      fireEvent.mouseMove(document, { clientY: -5000 }); // far up: grow past MAX
      expect(strip().style.height).toBe("600px");
      fireEvent.mouseUp(document);
      expect(localStorage.getItem(HEIGHT_KEY)).toBe("600");
    });

    it("resizes by keyboard too, through the handle's arrow keys", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      const handle = screen.getByRole("button", { name: "Resize panel height" });
      // ArrowUp is a -16 delta, so `prev - delta` grows the panel by 16.
      fireEvent.keyDown(handle, { key: "ArrowUp" });
      expect(strip().style.height).toBe("236px");
      fireEvent.keyDown(handle, { key: "ArrowDown" });
      expect(strip().style.height).toBe("220px");
    });

    /**
     * THE CROSSING THE OTHER TWO SUITES MISS, and the defect it caught was live
     * (peek-a-bin-ob8e): one ArrowUp moved the panel to 236px and stored `220`,
     * so the first press saved nothing and every later press saved the height
     * from a step ago — reload and the panel came back one step behind.
     *
     * Neither existing half could see it. `panelUtilities.dom.test.tsx` drives
     * `ResizeHandle`'s keyboard path with a `vi.fn()`, so it asserts that
     * `onResizeEnd` is CALLED rather than what a real caller would store; the
     * persistence test above it drives only the MOUSE path, which works, because
     * mouseup is a separate event after a commit. `handleKeyDown` calls
     * `onResize` and `onResizeEnd` synchronously in ONE handler, so React has
     * not re-rendered in between and no amount of ref-routing inside
     * `ResizeHandle` can hand back a callback that has seen the new height. The
     * caller has to keep the live value somewhere that is not a render.
     */
    it("persists a KEYBOARD resize at its post-press height, not the pre-press one", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      const handle = screen.getByRole("button", { name: "Resize panel height" });
      fireEvent.keyDown(handle, { key: "ArrowUp" });
      expect(localStorage.getItem(HEIGHT_KEY)).toBe("236");
      fireEvent.keyDown(handle, { key: "ArrowUp" });
      expect(localStorage.getItem(HEIGHT_KEY)).toBe("252");
      fireEvent.keyDown(handle, { key: "ArrowDown" });
      expect(localStorage.getItem(HEIGHT_KEY)).toBe("236");
      expect(strip().style.height).toBe("236px");
    });
  });

  describe("popping a panel out", () => {
    it("moves it out of the tab strip into a floating window on <body>", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />);
      fireEvent.click(popOutButtons()[0]);
      // The tab is gone from the strip…
      expect(screen.queryByRole("button", { name: "Alpha" })).toBeNull();
      // …and the panel is portaled to document.body, outside the container's own
      // subtree, with its content and its label intact.
      const floater = floatingPanel();
      expect(within(floater).getByText("Alpha")).toBeTruthy();
      expect(within(floater).getByText("a body")).toBeTruthy();
      expect(floater.parentElement).toBe(document.body);
    });

    it("gives the floating window the centred position and default size it computes", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      // jsdom's window is 1024x768, so x = 1024/2 - 200 and y = 768/2 - 150.
      // Inline styles React wrote from state; nothing here is measured.
      const s = floatingPanel().style;
      expect([s.left, s.top, s.width, s.height]).toEqual(["312px", "234px", "400px", "300px"]);
    });

    it("drops the whole tab strip when every visible panel is floating", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      // `tabbedPanels.length > 0 &&` — an empty strip would be a bare 220px band
      // with a resize handle and no tabs.
      expect(screen.queryByRole("button", { name: "Resize panel height" })).toBeNull();
      expect(floatingPanel()).toBeTruthy();
    });

    it("re-docks it and makes it the active tab", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha"), panel("b", "Beta")]} />);
      fireEvent.click(popOutButtons()[0]);
      // Beta is now the only tab, so it is active; re-docking Alpha must make
      // ALPHA active rather than leaving the user on Beta.
      fireEvent.click(screen.getByTitle("Re-dock"));
      expect(screen.getByRole("button", { name: "Alpha" })).toBeTruthy();
      expect((screen.getByText("a body").parentElement as HTMLElement).className).toBe("h-full");
      expect((screen.getByText("b body").parentElement as HTMLElement).className).toBe("hidden");
    });

    /**
     * WAS A PIN, NOW A SPECIFICATION — and the change is entirely in the
     * writing. `poppedOut` is not pruned when a panel stops being visible, so a
     * floating panel closed and later reopened comes back FLOATING at the place
     * the user left it. That was pinned as odd-but-harmless only because
     * nothing in the source said it was meant; it now says so, at `poppedOut`'s
     * declaration in `BottomPanelContainer.tsx`, and this test asserts the
     * intent rather than recording a shrug.
     *
     * The behaviour was RE-ARGUED before being kept, not kept by default:
     * floating is a choice the user made about that panel and closing it is not
     * withdrawing that choice, the docked height is persisted one step further
     * still (to localStorage), and the map cannot grow — its keys are the three
     * panel-id literals at the single mount site, so it is bounded at three
     * entries.
     */
    it("remembers that a panel was floating across a close and a reopen", () => {
      const { rerender } = render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const before = floatingPanel().style.left;
      rerender(<BottomPanelContainer panels={[panel("a", "Alpha", false)]} />);
      expect(document.querySelector(".fixed.z-50")).toBeNull();
      rerender(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      expect(floatingPanel().style.left).toBe(before);
      expect(screen.queryByRole("button", { name: "Alpha" })).toBeNull();
    });

    it("closes a floating panel through its own onClose", () => {
      const closeA = vi.fn();
      render(<BottomPanelContainer panels={[panel("a", "Alpha", true, closeA)]} />);
      fireEvent.click(popOutButtons()[0]);
      fireEvent.click(within(floatingPanel()).getByTitle("Close"));
      expect(closeA).toHaveBeenCalledTimes(1);
    });

    it("moves the floating window by its header, relative to where the grab started", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const header = floatingPanel().querySelector(".cursor-move") as HTMLElement;
      // Grabbing at (100,100) on a window at (312,234) records an offset of
      // (-212,-134); moving the pointer to (150,150) must therefore put the
      // window at (362,284) — the grab point is preserved, the window does not
      // jump so its corner is under the cursor.
      fireEvent.mouseDown(header, { clientX: 100, clientY: 100 });
      fireEvent.mouseMove(document, { clientX: 150, clientY: 150 });
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["362px", "284px"]);
      fireEvent.mouseUp(document);
      // The listeners are removed, so a stray move no longer drags the window.
      fireEvent.mouseMove(document, { clientX: 900, clientY: 900 });
      expect(floatingPanel().style.left).toBe("362px");
    });

    it("resizes the floating window from its corner, with a floor on both axes", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const corner = floatingPanel().querySelector(".cursor-nwse-resize") as HTMLElement;
      fireEvent.mouseDown(corner, { clientX: 0, clientY: 0 });
      fireEvent.mouseMove(document, { clientX: 50, clientY: 40 });
      expect([floatingPanel().style.width, floatingPanel().style.height]).toEqual([
        "450px",
        "340px",
      ]);
      // Dragging far back up hits the 200x100 floor rather than inverting the
      // window.
      fireEvent.mouseMove(document, { clientX: -900, clientY: -900 });
      expect([floatingPanel().style.width, floatingPanel().style.height]).toEqual([
        "200px",
        "100px",
      ]);
      fireEvent.mouseUp(document);
    });
  });

  /**
   * THE CLAMP (`peek-a-bin-goz4`). A floating panel could be dragged past any
   * edge and become unreachable, the only escape being to close it from the tab
   * strip — if the user worked out that was what had happened.
   *
   * The RULE itself is pinned as arithmetic in `floatingClamp.test.ts`, which is
   * the primary instrument and needs neither a render nor a drag. What is
   * asserted here is that each of the three sites that positions a panel — the
   * header drag, the mint in `handlePopOut`, and the derivation that re-places a
   * stored position against the current viewport — actually routes through it,
   * and writes its answer into the inline styles React sets.
   *
   * jsdom performs no layout, so the numbers below are the numbers the handlers
   * computed and nothing here has been observed to be on screen or off it. The
   * viewport is jsdom's own 1024x768 unless a test moves it, which makes the
   * four bounds 976 / -352 / 744 / 0 for the 400x300 panel `handlePopOut` mints.
   */
  describe("keeping a floating panel reachable", () => {
    it("stops a drag at each edge instead of letting the panel out of reach", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const header = floatingPanel().querySelector(".cursor-move") as HTMLElement;
      // Grab at (400,240) on a window at (312,234): the offset is (88,6).
      fireEvent.mouseDown(header, { clientX: 400, clientY: 240 });

      // Far past the bottom-right. Unclamped this would be (4912, 4994).
      fireEvent.mouseMove(document, { clientX: 5000, clientY: 5000 });
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["976px", "744px"]);

      // Far past the top-left. Unclamped this would be (-5088, -5006). Note the
      // asymmetry: 48px of the panel's RIGHT edge stays on screen horizontally,
      // but the top is a hard zero, the header being flush with the panel's top.
      fireEvent.mouseMove(document, { clientX: -5000, clientY: -5000 });
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["-352px", "0px"]);
      fireEvent.mouseUp(document);
    });

    /**
     * The clamp is applied to the drag's OUTPUT and never to the grab offset, so
     * overshooting an edge does not accumulate: bring the pointer back and the
     * panel is under the same point of the header it was grabbed by. Clamping
     * the offset instead would leave it drifted by however far it overshot.
     */
    it("hands the panel back at the grab point after the pointer overshoots", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const header = floatingPanel().querySelector(".cursor-move") as HTMLElement;
      fireEvent.mouseDown(header, { clientX: 400, clientY: 240 });
      fireEvent.mouseMove(document, { clientX: 5000, clientY: 5000 });
      fireEvent.mouseMove(document, { clientX: 400, clientY: 240 });
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["312px", "234px"]);
      fireEvent.mouseUp(document);
    });

    /**
     * WHAT GETS STORED, which is the half the render-time derivation cannot do
     * and the reason the drag has a clamp of its own. A drag writes the clamped
     * position, because the user never chose the one the pointer ran off to; a
     * position that merely does not FIT the current window is left alone (see
     * the reopen and resize tests below). Without the clamp on the write the
     * panel is placed correctly right up until the window grows, and then leaps
     * out to a position nobody asked for — which this test is what discriminates.
     */
    it("stores the clamped position, not the one the pointer ran off to", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const header = floatingPanel().querySelector(".cursor-move") as HTMLElement;
      fireEvent.mouseDown(header, { clientX: 400, clientY: 240 });
      fireEvent.mouseMove(document, { clientX: 5000, clientY: 5000 });
      fireEvent.mouseUp(document);

      // Room appears. The stored position is the edge it stopped at, so it stays
      // there; had the raw (4912, 4994) been stored it would now be at
      // (3952, 2976), the new viewport's own bounds.
      setViewport(4000, 3000);
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["976px", "744px"]);
    });

    /**
     * The reopen case, which the bead names as `poppedOut`'s one real edge. Not
     * pruning `poppedOut` on close is deliberate and documented at that state's
     * declaration; the exposure it owns is a stored x/y that has gone off-screen
     * because the window shrank while the panel was closed.
     */
    it("re-places a panel reopened into a window that shrank while it was closed", () => {
      const { rerender } = render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["312px", "234px"]);

      rerender(<BottomPanelContainer panels={[panel("a", "Alpha", false)]} />);
      setViewport(300, 200);
      rerender(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      // 300 - 48 and 200 - 24. Unclamped it would come back at (312, 234), with
      // its header entirely below a 200px-tall viewport.
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["252px", "176px"]);
    });

    /**
     * The same derivation covers a window resized while the panel is OPEN, and
     * it is derived rather than written back — so the user's position survives a
     * lapse in the room to honour it. Same shape as `XrefPanel`'s
     * `effectiveScope`: the derived value is what the screen reads, the stored
     * one is the preference.
     */
    it("pulls a panel back inside when the window shrinks, and lets it return", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      setViewport(300, 200);
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["252px", "176px"]);
      setViewport(JSDOM_W, JSDOM_H);
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["312px", "234px"]);
    });

    /**
     * A CORNER RESIZE CARRIES NO POSITION, so it must carry the stored one
     * through untouched — and it is the site where the derive-don't-store split
     * is easiest to lose, because the derived object is right there and
     * spreading it reads as harmless. `{ ...fs, w, h }` writes the CLAMPED
     * position back, so making a panel bigger while the window happens to be
     * narrow silently discards the position it would otherwise have returned to.
     *
     * The lapse has to be real for this to be a test: the panel is dragged to
     * the right edge of a wide window, the window is narrowed under it so the
     * rendered position and the stored one differ, the resize happens THERE, and
     * the width is asserted mid-lapse so a control cannot pass by the resize
     * simply not happening. Restoring the window is what reads the stored value
     * back out — it is not otherwise observable from the rendered output.
     */
    it("leaves the stored position alone when the panel is resized during a lapse", () => {
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      const header = floatingPanel().querySelector(".cursor-move") as HTMLElement;
      // Park it against the right edge of the full-width window: stored (976, 234).
      fireEvent.mouseDown(header, { clientX: 400, clientY: 240 });
      fireEvent.mouseMove(document, { clientX: 5000, clientY: 240 });
      fireEvent.mouseUp(document);
      expect(floatingPanel().style.left).toBe("976px");

      // Narrow the window under it. 500 - 48; the stored 976 no longer fits.
      setViewport(500, JSDOM_H);
      expect(floatingPanel().style.left).toBe("452px");

      // Resize from the corner, mid-lapse. 400 + 60 wide, height unchanged.
      const corner = floatingPanel().querySelector(".cursor-nwse-resize") as HTMLElement;
      fireEvent.mouseDown(corner, { clientX: 0, clientY: 0 });
      fireEvent.mouseMove(document, { clientX: 60, clientY: 0 });
      fireEvent.mouseUp(document);
      // The resize really happened — otherwise the assertion below would pass
      // against a callback that never fired.
      expect(floatingPanel().style.width).toBe("460px");
      // …and it moved nothing: the clamp still answers for the narrow window.
      expect(floatingPanel().style.left).toBe("452px");

      // The room comes back, and so does the position. `{ ...fs, w, h }` leaves
      // it at 452px, having overwritten the preference with the picture of it.
      setViewport(JSDOM_W, JSDOM_H);
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["976px", "234px"]);
      expect(floatingPanel().style.width).toBe("460px");
    });

    /**
     * A panel popped out on a window too short to centre it in comes up with its
     * header at the top edge rather than above it.
     *
     * ITS CONTROL IS INERT AND THE INERTNESS IS PROVABLE, so it is reported
     * rather than tuned away. Deleting the `clampFloatingPosition` call inside
     * `handlePopOut` leaves this — and every other test — GREEN, because the
     * centring formula can violate exactly one bound and it is the one bound
     * that does not depend on the viewport. `vh/2 - h/2 < 0` whenever the window
     * is shorter than the panel; every other inequality holds identically for
     * all `vw`, `vh` (the algebra is at `handlePopOut`). A stored -50 and a
     * stored 0 therefore RENDER THE SAME at every viewport, now and after any
     * resize, so no assertion on the output can separate them — checked
     * exhaustively over the viewport grid, not argued. What this test does
     * constrain is the OUTPUT: with neither clamp the panel comes up at -50px,
     * its header entirely off the top of the screen.
     *
     * The second half — growing the window and re-asserting — is the inert
     * control itself, left in place as the statement of the gap.
     */
    it("mints a pop-out position through the same rule on a short window", () => {
      setViewport(JSDOM_W, 200);
      render(<BottomPanelContainer panels={[panel("a", "Alpha")]} />);
      fireEvent.click(popOutButtons()[0]);
      // Centred y would be 100 - 150 = -50; centred x is 512 - 200 = 312 and is
      // inside the horizontal bounds, so it is untouched.
      expect([floatingPanel().style.left, floatingPanel().style.top]).toEqual(["312px", "0px"]);
      setViewport(JSDOM_W, JSDOM_H);
      expect(floatingPanel().style.top).toBe("0px");
    });
  });
});

/** The docked strip: the only element carrying an inline height. */
function strip(): HTMLElement {
  const el = document.querySelector('[class*="panel-bg"][style*="height"]');
  if (!el) throw new Error("no docked panel strip in the document");
  return el as HTMLElement;
}

/** jsdom's own window, which every clamp assertion above is written against. */
const JSDOM_W = 1024;
const JSDOM_H = 768;

/**
 * Move the viewport the clamp is computed against.
 *
 * `innerWidth`/`innerHeight` are redefined rather than assigned because jsdom
 * exposes them as accessors, and the `resize` event is dispatched explicitly
 * because nothing here lays anything out — there is no real resize to observe,
 * only the two numbers the container reads.
 */
function setViewport(w: number, h: number) {
  Object.defineProperty(window, "innerWidth", { value: w, writable: true, configurable: true });
  Object.defineProperty(window, "innerHeight", { value: h, writable: true, configurable: true });
  fireEvent(window, new Event("resize"));
}

/** The portaled floating window, found by the class that positions it. */
function floatingPanel(): HTMLElement {
  const el = document.querySelector(".fixed.z-50");
  if (!el) throw new Error("no floating panel in the document");
  return el as HTMLElement;
}

/* ──────────────────────────────── CallPanel ─────────────────────────────── */

const BASE = 0x140001000;
const MAIN: DisasmFunction = { name: "main", address: BASE, size: 0x20 };
const HELPER: DisasmFunction = { name: "helper", address: BASE + 0x20, size: 0x20 };
const OTHER: DisasmFunction = { name: "other", address: BASE + 0x40, size: 0x20 };

function insn(address: number, mnemonic: string, opStr: string): Instruction {
  return { address, bytes: new Uint8Array(0), mnemonic, opStr, size: 4 };
}

/**
 * `main`'s body, in address order because `CallPanel` walks the array and
 * `break`s at the function's end. The last entry is deliberately past that end,
 * so a walk that failed to stop would pick up `helper`'s call.
 */
const INSNS: Instruction[] = [
  insn(BASE + 0x00, "push", "rbp"),
  insn(BASE + 0x04, "call", `0x${(BASE + 0x20).toString(16)}`), // → helper
  insn(BASE + 0x08, "call", `0x${(BASE + 0x40).toString(16)}`), // → other
  insn(BASE + 0x0c, "call", `0x${(BASE + 0x20).toString(16)}`), // → helper again
  insn(BASE + 0x10, "call", "qword ptr [rip + 0x2000]"), // indirect: no target
  insn(BASE + 0x14, "call", "0x140009999"), // direct, but no function there
  insn(BASE + 0x18, "ret", ""),
  insn(BASE + 0x20, "call", "0x140008888"), // inside `helper`, must be ignored
];

/** to → from[]. Two callers inside functions, plus one that is nowhere. */
const XREFS = new Map<number, number[]>([
  [BASE, [BASE + 0x24, BASE + 0x44, BASE + 0x28, 0x140005000]],
]);

function renderCallPanel(over: Partial<Parameters<typeof CallPanel>[0]> = {}) {
  const onNavigate = vi.fn();
  const onClose = vi.fn();
  render(
    <CallPanel
      func={MAIN}
      xrefMap={XREFS}
      instructions={INSNS}
      // Deliberately NOT in address order: `binarySearchFunc` requires sorted
      // input and the component sorts a copy itself. Handing it a sorted array
      // would let a missing sort pass.
      functions={[OTHER, MAIN, HELPER]}
      renames={{}}
      onNavigate={onNavigate}
      onClose={onClose}
      {...over}
    />,
  );
  return { onNavigate, onClose };
}

describe("CallPanel", () => {
  it("names the function it is describing", () => {
    renderCallPanel();
    expect(screen.getByText("Call Graph: main")).toBeTruthy();
  });

  it("uses the renamed identifier everywhere a function is named", () => {
    renderCallPanel({ renames: { [MAIN.address]: "WinMainCRTStartup", [HELPER.address]: "hlp" } });
    expect(screen.getByText("Call Graph: WinMainCRTStartup")).toBeTruthy();
    // A rename must reach the rows too, not just the header — `getDisplayName`
    // is called at three sites in this component, and `helper` is both a caller
    // and a callee here, so the renamed identifier must appear in both columns.
    expect(screen.getAllByText("hlp").length).toBe(2);
    expect(screen.queryByText("helper")).toBeNull();
  });

  it("resolves each caller address to the function containing it, once per function", () => {
    renderCallPanel();
    // `helper` calls twice (0x…24 and 0x…28) and is listed ONCE: two calls from
    // one function are one caller. The third row is the unattributed source
    // below.
    expect(screen.getByText("Called by (3)")).toBeTruthy();
    expect(callerRows().map((b) => b.textContent)).toEqual([
      "helper0x140001020",
      "other0x140001040",
      "unknown0x140005000",
    ]);
  });

  /**
   * WAS A PIN, NOW A SPECIFICATION. `0x140005000` is in no detected function, so
   * `findContainingFunc` answers null; the entry used to be skipped outright,
   * leaving neither a row nor a tally mark, so "Called by (2)" understated a map
   * holding four xrefs. Nothing false was on screen — but the COUNT is the part
   * a reader trusts, and a narrower answer in exactly the shape of a complete
   * one is the failure mode `DetectResult.omitted` exists to prevent. It is
   * reachable, not theoretical: PE32 has no `.pdata` to arbitrate boundaries and
   * detection is known to both over- and under-produce.
   *
   * The repair needed no new policy. The CALLEE column beside this one already
   * answers the same question for a target in no function — it labels it
   * "unknown" and shows the address — so the caller side now says the same
   * thing, and the two halves of one panel agree.
   */
  it("lists a caller outside every detected function, and counts it", () => {
    renderCallPanel();
    expect(screen.getByText("Called by (3)")).toBeTruthy();
    const unattributed = callerRows()[2];
    expect(unattributed.textContent).toBe("unknown0x140005000");
    // An attributed row shows its function's ENTRY address while navigating to
    // the call site; this one has no entry to show, so the address on the row is
    // the call site, and it is the address clicking it goes to.
    expect(screen.getByText("0x140005000")).toBeTruthy();
  });

  it("navigates to the call site of an unattributed caller", () => {
    const { onNavigate } = renderCallPanel();
    fireEvent.click(callerRows()[2]);
    expect(onNavigate).toHaveBeenCalledWith(0x140005000);
  });

  /**
   * THE TWO SIDES DEDUP BY DIFFERENT KEYS, and that is the decision listing
   * unattributed callers forced. An attributed source collapses into its
   * FUNCTION, because two calls from one function are one caller. An
   * unattributed source has no function to collapse into, so it dedups on its
   * own address — two distinct sources are two distinct facts, and merging them
   * would be the understating this change exists to stop, one level down.
   *
   * What is NOT asserted, because it is not reachable: the `f`/`a` prefixes on
   * the key are defensive. A bare number would mix "the entry of the containing
   * function" with "this source address", but `binarySearchFunc` answers with X
   * for X's own entry whenever X has a non-zero size, so a source cannot be both
   * unattributed and equal to some function's entry. The prefixes are kept for
   * what they say, not for a defect they prevent.
   */
  it("dedups an attributed caller by function and an unattributed one by address", () => {
    renderCallPanel({
      func: OTHER,
      xrefMap: new Map([
        [
          OTHER.address,
          // Two calls from inside `helper`; one unattributed source listed
          // twice; and a SECOND, different unattributed source. The second one
          // is what makes this discriminating — with only one distinct
          // unattributed address, a rule collapsing every function-less caller
          // into a single row passes this test unchanged. Measured: that was
          // negative control 4c, and it came back INERT until this address was
          // added.
          [HELPER.address + 4, HELPER.address + 8, 0x140003000, 0x140003000, 0x140004000],
        ],
      ]),
      functions: [MAIN, HELPER],
    });
    expect(screen.getByText("Called by (3)")).toBeTruthy();
    expect(callerRows().map((b) => b.textContent)).toEqual([
      "helper0x140001020",
      "unknown0x140003000",
      "unknown0x140004000",
    ]);
  });

  it("lists each distinct direct call target once, and labels an unknown one", () => {
    renderCallPanel();
    // helper (twice in the body, once here), other, and 0x140009999 which is not
    // a function. The indirect `call qword ptr [rip + …]` has no target and must
    // not appear at all.
    expect(screen.getByText("Calls (3)")).toBeTruthy();
    expect(calleeRows().map((b) => b.textContent)).toEqual([
      "helper0x140001020",
      "other0x140001040",
      "unknown0x140009999",
    ]);
    expect(screen.queryByText(/rip/)).toBeNull();
  });

  it("stops the callee scan at the function's end", () => {
    renderCallPanel();
    // `0x140008888` is called from an instruction at `helper`'s first address,
    // one past `main`'s range. A missing `break` would attribute it to main.
    expect(screen.queryByText(/140008888/)).toBeNull();
  });

  it("navigates to the CALL SITE for a caller, not to the caller's entry point", () => {
    const { onNavigate } = renderCallPanel();
    fireEvent.click(callerRows()[0]);
    // The row is labelled with `helper`'s entry (0x140001020) but the useful
    // destination is the instruction that made the call (0x140001024) — the
    // first of that function's xrefs. Those two differ, so this is a real
    // assertion about which address is passed.
    expect(onNavigate).toHaveBeenCalledWith(BASE + 0x24);
  });

  it("navigates to the target address for a callee", () => {
    const { onNavigate } = renderCallPanel();
    fireEvent.click(calleeRows()[1]);
    expect(onNavigate).toHaveBeenCalledWith(BASE + 0x40);
  });

  it("can navigate to an unknown callee, which is the only way to reach it", () => {
    const { onNavigate } = renderCallPanel();
    fireEvent.click(calleeRows()[2]);
    expect(onNavigate).toHaveBeenCalledWith(0x140009999);
  });

  it("says so, on both sides, when a function neither calls nor is called", () => {
    renderCallPanel({ func: OTHER, xrefMap: new Map(), instructions: [] });
    expect(screen.getByText("Called by (0)")).toBeTruthy();
    expect(screen.getByText("No callers found")).toBeTruthy();
    expect(screen.getByText("Calls (0)")).toBeTruthy();
    expect(screen.getByText("No calls found")).toBeTruthy();
  });

  it("closes", () => {
    const { onClose } = renderCallPanel();
    fireEvent.click(screen.getByRole("button", { name: "✕" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

/** The two columns are siblings; each row is a button inside one of them. */
function columnRows(heading: RegExp): HTMLElement[] {
  const head = screen.getByText(heading);
  const column = head.parentElement as HTMLElement;
  return Array.from(column.querySelectorAll("button"));
}
const callerRows = () => columnRows(/^Called by/);
const calleeRows = () => columnRows(/^Calls \(/);
