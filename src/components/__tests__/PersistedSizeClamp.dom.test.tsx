// @vitest-environment jsdom

import "../../test/domSetup";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BottomPanelContainer } from "../BottomPanelContainer";
import {
  clampPersistedSize,
  DOCKED_PANEL_HEIGHT_RESERVE,
  SIDEBAR_WIDTH_RESERVE,
} from "../persistedSizeClamp";
import { Sidebar } from "../Sidebar";
import { AppHarness, harnessPE, stateWithPE } from "./appStateHarness";

/**
 * THE WIRING HALF of `peek-a-bin-0tt6`: that the two persisting sites route
 * their rendered size through `clampPersistedSize` against the LIVE viewport,
 * and that neither writes the answer back.
 *
 * `persistedSizeClamp.test.ts` beside it is the rule; this is only the wiring,
 * and the split is `floatingClamp`'s. What the pure test cannot see is that a
 * component reads the derived value rather than the stored one, that a window
 * resize re-runs the derivation, and that localStorage still holds the
 * preference afterwards.
 *
 * WHAT NONE OF THIS COVERS, and the assertions are phrased so as not to imply
 * otherwise. jsdom performs no layout: every element measures 0, `innerWidth`
 * and `innerHeight` are two numbers nothing lays anything out against, and the
 * `resize` event is dispatched by hand because there is no real resize to
 * observe. So nothing here has seen a sidebar be too wide, a listing be
 * squeezed to nothing, a panel overflow its column, or any of it come back when
 * the window grows. What is asserted is the number the component computed and
 * the string React wrote into an inline style — CLAUDE.md's standing statement
 * about every drag and clamp in this repo, unchanged by this file
 * (`peek-a-bin-v2u`).
 */

const JSDOM_W = 1024;
const JSDOM_H = 768;

/**
 * Move the two numbers the clamps are computed against.
 *
 * Redefined rather than assigned because jsdom exposes them as accessors, and
 * the event is fired explicitly — the same helper `BottomPanels.dom.test.tsx`
 * uses, and duplicated rather than exported from there because that file is a
 * test module with no exports and importing one test file from another would
 * run its suites twice.
 */
function setViewport(w: number, h: number) {
  Object.defineProperty(window, "innerWidth", { value: w, writable: true, configurable: true });
  Object.defineProperty(window, "innerHeight", { value: h, writable: true, configurable: true });
  fireEvent(window, new Event("resize"));
}

const WIDTH_KEY = "peek-a-bin:sidebar-width";
const HEIGHT_KEY = "peek-a-bin:bottom-panel-height";

afterEach(() => {
  cleanup();
  localStorage.clear();
  setViewport(JSDOM_W, JSDOM_H);
});

/* ───────────────────────────── the sidebar's width ──────────────────────── */

describe("Sidebar width against the viewport", () => {
  beforeEach(() => localStorage.clear());

  const aside = (c: HTMLElement) => c.querySelector("aside") as HTMLElement;

  function renderSidebar() {
    return render(
      <AppHarness state={stateWithPE(harnessPE(), {})} dispatch={vi.fn()}>
        <Sidebar />
      </AppHarness>,
    );
  }

  it("mounts a stored width that FITS exactly as stored", () => {
    // The inert case, and the reason no existing assertion in
    // `Sidebar.dom.test.tsx` moves: at 1024 the whole [180, 400] range fits.
    localStorage.setItem(WIDTH_KEY, "400");
    expect(aside(renderSidebar().container).style.width).toBe("400px");
  });

  it("mounts a stored width the window cannot afford at the clamped value", () => {
    localStorage.setItem(WIDTH_KEY, "400");
    setViewport(700, JSDOM_H);
    // 700 - 306. Unclamped this renders 400px, leaving 300px for the pane.
    expect(aside(renderSidebar().container).style.width).toBe(`${700 - SIDEBAR_WIDTH_RESERVE}px`);
  });

  it("re-derives on a resize, and lets the preference return when room does", () => {
    localStorage.setItem(WIDTH_KEY, "400");
    const { container } = renderSidebar();
    expect(aside(container).style.width).toBe("400px");
    setViewport(500, JSDOM_H);
    // 500 - 306 = 194.
    expect(aside(container).style.width).toBe("194px");
    setViewport(JSDOM_W, JSDOM_H);
    expect(aside(container).style.width).toBe("400px");
  });

  it("keeps the floor on a window too narrow for it", () => {
    localStorage.setItem(WIDTH_KEY, "400");
    setViewport(375, JSDOM_H);
    // 375 - 306 = 69, under the 180 floor, so the floor wins. This is the case
    // the rule NAMES rather than the one it fixes: nothing here has seen what a
    // 180px sidebar in a 375px window looks like.
    expect(aside(renderSidebar().container).style.width).toBe("180px");
  });

  /**
   * DERIVED, NEVER WRITTEN BACK. The stored preference has to survive a mount
   * into a window that cannot honour it, or one session in a small window
   * silently narrows the sidebar for every later one — the mistake
   * `floatingClamp`'s position made once. The re-mount at the end is what reads
   * the stored value back out; it is not observable from the rendered output
   * during the lapse.
   */
  it("leaves the stored width alone while it cannot be honoured", () => {
    localStorage.setItem(WIDTH_KEY, "400");
    setViewport(500, JSDOM_H);
    const { container } = renderSidebar();
    expect(aside(container).style.width).toBe("194px");
    expect(localStorage.getItem(WIDTH_KEY)).toBe("400");
    cleanup();

    setViewport(JSDOM_W, JSDOM_H);
    expect(aside(renderSidebar().container).style.width).toBe("400px");
  });

  /**
   * A DRAG WRITES THE PREFERENCE, NOT THE CLAMPED VALUE — the deliberate
   * asymmetry with `floatingClamp`, whose drag DOES clamp its write. A size
   * drag is already bounded by `MAX_WIDTH`, and clamping the write here would
   * mean one drag in a narrow window discards a wide preference for good.
   */
  it("stores the width the drag asked for, not the one the window granted", () => {
    setViewport(500, JSDOM_H);
    const { container } = renderSidebar();
    const grip = screen.getByRole("button", { name: "Resize sidebar" });
    fireEvent.mouseDown(grip, { clientX: 300 });
    fireEvent.mouseMove(document, { clientX: 5000 });
    fireEvent.mouseUp(document);
    // The preference reached MAX_WIDTH; the render is held at 500 - 306.
    expect(localStorage.getItem(WIDTH_KEY)).toBe("400");
    expect(aside(container).style.width).toBe("194px");
    // And it is there when the room is.
    setViewport(JSDOM_W, JSDOM_H);
    expect(aside(container).style.width).toBe("400px");
  });

  it("does not clamp the collapsed rail, whose width is a constant class", () => {
    setViewport(200, JSDOM_H);
    const { container } = renderSidebar();
    fireEvent.click(screen.getByTitle("Collapse sidebar"));
    // `w-10` as a class name, not a measurement, and no inline width at all.
    expect(aside(container).className).toContain("w-10");
    expect(aside(container).style.width).toBe("");
  });
});

/* ─────────────────────── the docked bottom panel's height ───────────────── */

describe("BottomPanelContainer height against the viewport", () => {
  beforeEach(() => localStorage.clear());

  const strip = () =>
    document.querySelector(".shrink-0.flex.flex-col.panel-bg.border-t") as HTMLElement;

  const panels = [
    {
      id: "a",
      label: "Alpha",
      visible: true,
      content: <div>a body</div>,
      onClose: () => {},
    },
  ];

  it("mounts a stored height that FITS exactly as stored", () => {
    // Inert at 1024x768, which is why `BottomPanels.dom.test.tsx`'s own
    // "clamps to the minimum and the maximum" row is unaffected: 768 - 166 is
    // 602, still above MAX_HEIGHT.
    localStorage.setItem(HEIGHT_KEY, "600");
    render(<BottomPanelContainer panels={panels} />);
    expect(strip().style.height).toBe("600px");
  });

  it("mounts a stored height the window cannot afford at the clamped value", () => {
    localStorage.setItem(HEIGHT_KEY, "600");
    setViewport(JSDOM_W, 500);
    render(<BottomPanelContainer panels={panels} />);
    // 500 - 166. Unclamped this renders 600px in a 500px-tall window.
    expect(strip().style.height).toBe(`${500 - DOCKED_PANEL_HEIGHT_RESERVE}px`);
  });

  it("re-derives on a resize, and lets the preference return when room does", () => {
    localStorage.setItem(HEIGHT_KEY, "600");
    render(<BottomPanelContainer panels={panels} />);
    expect(strip().style.height).toBe("600px");
    setViewport(JSDOM_W, 400);
    expect(strip().style.height).toBe("234px");
    setViewport(JSDOM_W, JSDOM_H);
    expect(strip().style.height).toBe("600px");
  });

  it("keeps the floor on a window too short for it", () => {
    localStorage.setItem(HEIGHT_KEY, "600");
    setViewport(JSDOM_W, 200);
    render(<BottomPanelContainer panels={panels} />);
    // 200 - 166 = 34, under the 80 floor.
    expect(strip().style.height).toBe("80px");
  });

  it("leaves the stored height alone while it cannot be honoured", () => {
    localStorage.setItem(HEIGHT_KEY, "600");
    setViewport(JSDOM_W, 400);
    render(<BottomPanelContainer panels={panels} />);
    expect(strip().style.height).toBe("234px");
    expect(localStorage.getItem(HEIGHT_KEY)).toBe("600");
  });

  /**
   * The persisting path is `ResizeHandle`'s `onResizeEnd`, which this component
   * documents as safe to read state in. What it must persist is the state, not
   * the rendered number — and the clamp is what makes the two differ.
   */
  it("persists the height the drag asked for, not the one the window granted", () => {
    setViewport(JSDOM_W, 400);
    render(<BottomPanelContainer panels={panels} />);
    const handle = screen.getByRole("button", { name: "Resize panel height" });
    fireEvent.mouseDown(handle, { clientY: 500 });
    fireEvent.mouseMove(document, { clientY: -5000 }); // far up: grow past MAX
    fireEvent.mouseUp(document);
    expect(localStorage.getItem(HEIGHT_KEY)).toBe("600");
    expect(strip().style.height).toBe("234px");
    setViewport(JSDOM_W, JSDOM_H);
    expect(strip().style.height).toBe("600px");
  });
});

/* ──────────────────────────── the two agree ─────────────────────────────── */

/**
 * ONE RULE, TWO SITES. The point of the shared declaration is that the two
 * cannot drift on the answer, and the only way to state that is to compute each
 * site's rendered number here and require the components to match it.
 */
describe("both sites read the same rule", () => {
  it("renders exactly what the rule returns, at four viewports", () => {
    for (const v of [1024, 700, 500, 375]) {
      localStorage.setItem(WIDTH_KEY, "400");
      setViewport(v, JSDOM_H);
      const { container } = render(
        <AppHarness state={stateWithPE(harnessPE(), {})} dispatch={vi.fn()}>
          <Sidebar />
        </AppHarness>,
      );
      expect((container.querySelector("aside") as HTMLElement).style.width).toBe(
        `${clampPersistedSize(400, 180, 400, v, SIDEBAR_WIDTH_RESERVE)}px`,
      );
      cleanup();
    }

    for (const v of [768, 500, 400, 200]) {
      localStorage.setItem(HEIGHT_KEY, "600");
      setViewport(JSDOM_W, v);
      render(
        <BottomPanelContainer
          panels={[
            { id: "a", label: "Alpha", visible: true, content: <div>a</div>, onClose: () => {} },
          ]}
        />,
      );
      const el = document.querySelector(".shrink-0.flex.flex-col.panel-bg.border-t") as HTMLElement;
      expect(el.style.height).toBe(
        `${clampPersistedSize(600, 80, 600, v, DOCKED_PANEL_HEIGHT_RESERVE)}px`,
      );
      cleanup();
    }
  });
});
