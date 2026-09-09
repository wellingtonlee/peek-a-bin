// @vitest-environment jsdom

import "../../test/domSetup";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DisasmFunction } from "../../disasm/types";
import { ANALYSIS_IN_PROGRESS, type AnalysisPhase, type AppState } from "../../hooks/usePEFile";
import { Sidebar } from "../Sidebar";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * The sidebar's chrome, and the skeleton that peek-a-bin-bo3b is about.
 *
 * THE FUNCTION LIST ITSELF IS NOT TESTED HERE, and that is a limit of the tool
 * rather than a choice about what matters. The list is a `useVirtualizer` over
 * a `flex-1 overflow-auto` div; jsdom performs no layout, so that div measures
 * 0px, `getVirtualItems()` returns an empty array, and NOT ONE function row is
 * in the document — verified, not assumed: rendering this component with five
 * functions produces 2271 bytes of HTML containing the filter box, the sections
 * list and the footer, and none of the five names. Every assertion below is
 * therefore about something outside that container. Nothing here is evidence
 * that a function row renders, is clickable, is labelled, or scrolls to the
 * active address. Making the rows appear would mean fabricating `clientHeight`
 * on the container, which buys assertions resting on a measurement no browser
 * made; it was deliberately not done.
 *
 * WHAT IS WORTH HAVING ANYWAY is the skeleton, which is the bo3b claim at its
 * third site and is *outside* the virtualizer precisely because it stands in
 * for the list before there is one. CLAUDE.md records `ANALYSIS_IN_PROGRESS` as
 * a `Record<AnalysisPhase, boolean>` that replaced a hand-written phase chain at
 * three sites, because that chain "defaults any phase added later to 'still
 * analysing', which is a spinner that can never resolve". `analysisNotice.test.ts`
 * checks the record's own values and `StatusBar.dom.test.tsx` checks one reader;
 * this checks the other, and it checks the half the record cannot express — that
 * the skeleton is `functions.length === 0 AND in-progress`, so a slow phase with
 * results already in hand shows the results rather than a shimmer.
 */

const FUNCS: DisasmFunction[] = [
  { name: "sub_401000", address: IMAGE_BASE + 0x1000, size: 0x40 },
  { name: "sub_401040", address: IMAGE_BASE + 0x1040, size: 0x40 },
];

const PHASES = Object.keys(ANALYSIS_IN_PROGRESS) as AnalysisPhase[];

function renderSidebar(over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  // One `pe` for the whole mount, so a rerender does not hand the component a
  // new object identity and invalidate memos that never asked to be.
  const pe = harnessPE();
  const tree = (o: Partial<AppState>) => (
    <AppHarness state={stateWithPE(pe, o)} dispatch={dispatch}>
      <Sidebar />
    </AppHarness>
  );
  const { container, rerender } = render(tree(over));
  return {
    dispatch,
    container,
    user: userEvent.setup(),
    // Bound to the same provider nesting above rather than spelled a second
    // time at the call site.
    rerender: (next: Partial<AppState>) => rerender(tree(next)),
  };
}

/** The shimmer placeholders `SkeletonRows` draws; there is no text to query. */
const skeletonRows = (c: HTMLElement) => c.querySelectorAll(".skeleton-shimmer");

describe("Sidebar function-list skeleton", () => {
  it("shimmers while detection is running with nothing found yet", () => {
    const { container } = renderSidebar({ functions: [], analysisPhase: "detecting-functions" });
    expect(skeletonRows(container)).toHaveLength(20);
  });

  it("stops shimmering the moment there are functions, mid-analysis", () => {
    // The `functions.length === 0` half. A phase can legitimately still be
    // running — xrefs, strings — long after the list is populated, and a
    // shimmer over a list the user can already read is the same defect one
    // step milder.
    const { container } = renderSidebar({ functions: FUNCS, analysisPhase: "building-xrefs" });
    expect(skeletonRows(container)).toHaveLength(0);
  });

  it("shows an empty list, not a shimmer, at every terminal phase", () => {
    // The bo3b claim itself: a phase that is over must not read as "still
    // working". Driven from the record rather than a list written out here, so
    // a phase added to the union is covered without editing this test.
    for (const phase of PHASES.filter((p) => !ANALYSIS_IN_PROGRESS[p])) {
      const { container, unmount } = render(
        <AppHarness
          state={stateWithPE(harnessPE(), { functions: [], analysisPhase: phase })}
          dispatch={vi.fn()}
        >
          <Sidebar />
        </AppHarness>,
      );
      expect(skeletonRows(container), `phase ${phase}`).toHaveLength(0);
      unmount();
    }
  });

  it("shimmers at every in-progress phase", () => {
    for (const phase of PHASES.filter((p) => ANALYSIS_IN_PROGRESS[p])) {
      const { container, unmount } = render(
        <AppHarness
          state={stateWithPE(harnessPE(), { functions: [], analysisPhase: phase })}
          dispatch={vi.fn()}
        >
          <Sidebar />
        </AppHarness>,
      );
      expect(skeletonRows(container), `phase ${phase}`).toHaveLength(20);
      unmount();
    }
  });
});

describe("Sidebar function count", () => {
  it("counts what the file has when nothing is filtered", () => {
    renderSidebar({ functions: FUNCS });
    expect(screen.getByText(/^Functions \(/).textContent).toBe("Functions (2)");
  });

  it("shows matched-over-total once a filter narrows the list", async () => {
    const { user } = renderSidebar({ functions: FUNCS });
    await user.type(screen.getByPlaceholderText("Filter functions..."), "401040");
    // Debounced, so the count settles a tick later.
    await vi.waitFor(() =>
      expect(screen.getByText(/^Functions \(/).textContent).toBe("Functions (1/2)"),
    );
  });

  it("says zero rather than nothing when the filter matches none", async () => {
    const { user } = renderSidebar({ functions: FUNCS });
    await user.type(screen.getByPlaceholderText("Filter functions..."), "zzzz");
    await vi.waitFor(() =>
      expect(screen.getByText(/^Functions \(/).textContent).toBe("Functions (0/2)"),
    );
  });
});

describe("Sidebar sections panel", () => {
  it("lists every section with its virtual size in hex", () => {
    renderSidebar();
    expect(screen.getByText("Sections (2)")).toBeTruthy();
    expect(screen.getByText(".text")).toBeTruthy();
    expect(screen.getByText(".rdata")).toBeTruthy();
    // Sizes come from the fixture's own layout pass rather than being repeated
    // here — the harness docstring warns that duplicating them drifts.
    const pe = harnessPE();
    for (const sec of pe.sections) {
      expect(screen.getByText((sec.virtualSize >>> 0).toString(16))).toBeTruthy();
    }
  });

  it("navigates to a section's virtual address", async () => {
    const { dispatch, user } = renderSidebar();
    const pe = harnessPE();
    await user.click(screen.getByText(".rdata"));
    const rdata = pe.sections.find((s) => s.name === ".rdata");
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: pe.optionalHeader.imageBase + (rdata?.virtualAddress ?? 0),
    });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("collapses and reopens", async () => {
    const { user } = renderSidebar();
    await user.click(screen.getByText(/^Sections \(/));
    expect(screen.queryByText(".text")).toBeNull();
    await user.click(screen.getByText(/^Sections \(/));
    expect(screen.getByText(".text")).toBeTruthy();
  });
});

describe("Sidebar bookmarks panel", () => {
  it("is absent entirely when there are none", () => {
    renderSidebar();
    expect(screen.queryByText(/^Bookmarks \(/)).toBeNull();
  });

  it("appears with a count once one exists", () => {
    renderSidebar({ bookmarks: [{ address: IMAGE_BASE + 0x1000, label: "entry" }] });
    expect(screen.getByText("Bookmarks (1)")).toBeTruthy();
    expect(screen.getByText("entry")).toBeTruthy();
  });
});

describe("Sidebar export controls", () => {
  it("offers CSV only once there is something to export", () => {
    renderSidebar({ functions: [] });
    expect((screen.getByTitle("Export functions as CSV") as HTMLButtonElement).disabled).toBe(true);
  });

  it("enables CSV when functions exist", () => {
    renderSidebar({ functions: FUNCS });
    expect((screen.getByTitle("Export functions as CSV") as HTMLButtonElement).disabled).toBe(
      false,
    );
  });

  it("toggles the sort control between the two orders it names", async () => {
    const { user } = renderSidebar({ functions: FUNCS });
    // The button's label states the order it is currently in; the title states
    // it too, and the two must not come apart.
    expect(screen.getByTitle("Sort: by address").textContent).toBe("Addr");
    await user.click(screen.getByTitle("Sort: by address"));
    expect(screen.getByTitle("Sort: alphabetical").textContent).toBe("A-Z");
  });
});

describe("Sidebar footer", () => {
  it("states the image's bitness, section count and import count", () => {
    renderSidebar();
    const pe = harnessPE();
    expect(screen.getByText("PE32+ (64-bit)")).toBeTruthy();
    expect(screen.getByText(`${pe.sections.length} sections`)).toBeTruthy();
    expect(screen.getByText(`${pe.imports.length} imports`)).toBeTruthy();
  });
});

describe("Sidebar collapse", () => {
  it("hides its panels when collapsed and restores them", async () => {
    const { user } = renderSidebar({ functions: FUNCS });
    await user.click(screen.getByTitle("Collapse sidebar"));
    expect(screen.queryByText(/^Sections \(/)).toBeNull();
    expect(screen.queryByPlaceholderText("Filter functions...")).toBeNull();
    await user.click(screen.getByTitle("Expand sidebar"));
    expect(screen.getByText(/^Sections \(/)).toBeTruthy();
  });
});

describe("Sidebar without a file", () => {
  it("renders nothing at all", () => {
    const { container } = render(
      <AppHarness state={{ ...stateWithPE(harnessPE()), peFile: null }} dispatch={vi.fn()}>
        <Sidebar />
      </AppHarness>,
    );
    // An early `return null` above every hook-free branch. Asserted because the
    // sidebar is mounted by App unconditionally, so this is the pre-file state.
    expect(container.querySelector("aside")).toBeNull();
    expect(container.textContent).toBe("");
  });
});

describe("Sidebar virtualized list", () => {
  it("renders no function rows under jsdom, which is the tool and not the code", () => {
    // Recorded as an assertion so the scope note at the top of this file cannot
    // rot: if a future change makes rows appear here — a fabricated container
    // height, or a switch away from virtualization — this fails and the note
    // needs rewriting. It is NOT a claim that rows should be absent in a browser.
    const { container } = renderSidebar({ functions: FUNCS });
    expect(container.textContent).not.toContain("sub_401000");
    // TARGETED BY `data-panel`, NOT BY `.flex-1.overflow-auto`, and that is not
    // cosmetic. Since peek-a-bin-llrq.1 the Call Graph body carries those same
    // two classes, so a class selector returns whichever comes first in document
    // order — today the function list, by coincidence of the very ordering that
    // change introduced. Any future reordering would silently retarget this at a
    // container full of caller/callee buttons and turn it red for a reason that
    // has nothing to do with virtualization. (This case seeds no callGraph, so
    // no Call Graph renders and the retarget cannot change today's result —
    // which is the point: it was fixed while still inert.)
    const list = container.querySelector('[data-panel="functions"]');
    expect(list).not.toBeNull();
    expect(within(list as HTMLElement).queryAllByRole("button")).toHaveLength(0);
  });
});

/**
 * THE CALL GRAPH BLOCK, and what its position is and is not evidence for.
 *
 * peek-a-bin-llrq: the block used to sit immediately ABOVE the Functions header,
 * sized purely by its own content, so every cursor move changed the caller and
 * callee counts and dragged the header, the filter box and every row up or down.
 * It is below the list now.
 *
 * WHAT THESE SUITES ACTUALLY ASSERT is DOM ORDER, class-name SPELLING and inline
 * STYLE — never geometry. jsdom performs no layout, so the user-visible claim
 * ("the header holds still") has no instrument here at all and is left to
 * peek-a-bin-llrq.6, a browser pass. The `data-panel` index test below is a
 * PROXY: it discriminates against moving the block back and against nothing
 * else. The header can still move in pixels because Sections grew.
 *
 * Three controls are known-inert for the same reason and are recorded rather
 * than tuned away: widening `maxHeight` to 100%, deleting the list's
 * `min-h-[120px]` floor, and restoring `shrink-0` on the wrapper each leave
 * every assertion in this file green.
 */

/** A third function, so one cursor position has both a caller and a callee. */
const A = IMAGE_BASE + 0x1000;
const B = IMAGE_BASE + 0x1040;
const C = IMAGE_BASE + 0x1080;
const FUNCS3: DisasmFunction[] = [...FUNCS, { name: "sub_401080", address: C, size: 0x40 }];
/** In no edge of {@link GRAPH}, so the block does not render with the cursor here. */
const LONELY: DisasmFunction = { name: "sub_409000", address: IMAGE_BASE + 0x9000, size: 0x40 };
/** Cursor in B => callers [A], callees [C]. */
const GRAPH = new Map<number, number[]>([
  [A, [B]],
  [B, [C]],
]);

/**
 * The sidebar's own TOP-LEVEL regions, in document order.
 *
 * Scoped to direct children of the `<aside>` on purpose: `call-graph-body` is
 * also marked, but it is a child of `call-graph` rather than a sibling region,
 * and letting it into this list would make an assertion about column ORDER read
 * as one about nesting.
 */
const panels = (c: HTMLElement) =>
  [...c.querySelectorAll("aside > [data-panel]")].map((e) => e.getAttribute("data-panel"));

const callGraphBox = (c: HTMLElement) =>
  c.querySelector('[data-panel="call-graph"]') as HTMLElement | null;

function renderWithCallGraph(over: Partial<AppState> = {}) {
  return renderSidebar({
    functions: FUNCS3,
    callGraph: GRAPH,
    currentAddress: B,
    ...over,
  });
}

describe("Sidebar call graph placement", () => {
  it("renders the block at all, which every absence assertion below depends on", () => {
    renderWithCallGraph();
    // THE LIVENESS HALF. `currentAddress` must land inside a function's
    // [address, address + size) or `useContainingFunc` returns null, the guard
    // is false and the block never mounts — at which point every "is absent"
    // test below would pass by not looking.
    expect(screen.getByText("Call Graph")).toBeTruthy();
    expect(screen.getByText("Callers (1)")).toBeTruthy();
    expect(screen.getByText("Callees (1)")).toBeTruthy();
  });

  it("sits below the function list, not above the Functions header", () => {
    const { container } = renderWithCallGraph();
    // FIVE entries, not the six regions `Sidebar` marks: the harness seeds no
    // bookmarks, and it supplies no GraphOverviewContext.Provider (the context
    // default is `{ data: null }`), so neither of those blocks renders here.
    expect(panels(container)).toEqual([
      "sections",
      "functions-header",
      "functions",
      "call-graph",
      "footer",
    ]);
  });

  it("leaves the Functions header in place when the cross-reference count changes", () => {
    // THE BUG REPORT, AS AN ASSERTION, and the shape matters. The cursor moves
    // from a function with a caller and a callee to one with NEITHER, so the
    // block goes from present to absent — the largest jump the old layout could
    // produce. Rerendering between two states that both show the block would be
    // inert: the index is equal either way, so it would pass with the block
    // above the header too.
    const { container, rerender } = renderWithCallGraph({
      functions: [...FUNCS3, LONELY],
    });
    const before = panels(container).indexOf("functions-header");
    expect(screen.getByText("Callers (1)")).toBeTruthy();

    rerender({
      functions: [...FUNCS3, LONELY],
      callGraph: GRAPH,
      currentAddress: LONELY.address,
    });
    expect(screen.queryByText("Call Graph")).toBeNull();
    expect(panels(container).indexOf("functions-header")).toBe(before);
  });
});

describe("Sidebar call graph cap", () => {
  it("carries a fixed pixel height and a percentage ceiling", () => {
    // Inline styles React wrote from a constant — not measurements. jsdom does
    // no layout, so the rendered height of anything here is 0.
    const { container } = renderWithCallGraph();
    const box = callGraphBox(container);
    expect(box?.style.height).toBe("160px");
    expect(box?.style.maxHeight).toBe("40%");
  });

  it("stays 160px tall whether the function has three callees or three hundred", () => {
    // NOT written as `expect(heightWith(3)).toBe(heightWith(300))`: that form is
    // INERT against the regression it targets, because deleting the inline
    // height makes both sides "" and they are still equal. The literal is the
    // assertion.
    const many = Array.from({ length: 300 }, (_, i) => ({
      name: `sub_5${i.toString(16).padStart(5, "0")}`,
      address: IMAGE_BASE + 0x50000 + i * 0x40,
      size: 0x40,
    }));
    const graph = new Map<number, number[]>([[B, many.map((f) => f.address)]]);
    const { container } = renderWithCallGraph({
      functions: [...FUNCS3, ...many],
      callGraph: graph,
    });
    expect(callGraphBox(container)?.style.height).toBe("160px");
    // The liveness half: the height claim is only worth having over a block
    // that really did render three hundred rows.
    expect(container.querySelectorAll('[data-panel="call-graph-body"] li')).toHaveLength(300);
  });

  it("carries the scroller class NAME on its body (a string; Tailwind is not loaded)", () => {
    const { container } = renderWithCallGraph();
    const body = container.querySelector('[data-panel="call-graph-body"]');
    expect(body?.className).toContain("overflow-auto");
    expect(body?.className).toContain("flex-1");
  });
});

describe("Sidebar call graph collapse", () => {
  // `domSetup` unmounts between tests but does not clear storage, and this is
  // the only suite in the file that writes any.
  const KEY = "peek-a-bin:callers-open";
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  it("reserves no height at all once collapsed", async () => {
    const { container, user } = renderWithCallGraph();
    expect(callGraphBox(container)?.style.height).toBe("160px");
    await user.click(screen.getByText("Call Graph"));
    // A collapsed section still holding 160px of the list's space would be this
    // defect one step milder, so the style is dropped entirely rather than
    // shrunk.
    expect(callGraphBox(container)?.style.height).toBe("");
    expect(container.querySelector('[data-panel="call-graph-body"]')).toBeNull();
  });

  it("starts collapsed when the stored preference says so, and writes it back", async () => {
    localStorage.setItem(KEY, "false");
    const { container, user } = renderWithCallGraph();
    expect(callGraphBox(container)?.style.height).toBe("");
    expect(container.querySelector('[data-panel="call-graph-body"]')).toBeNull();
    await user.click(screen.getByText("Call Graph"));
    expect(localStorage.getItem(KEY)).toBe("true");
    expect(callGraphBox(container)?.style.height).toBe("160px");
  });
});

describe("Sidebar call graph render guard", () => {
  it("is absent with no call graph in state", () => {
    const { container } = renderSidebar({ functions: FUNCS3, currentAddress: B });
    expect(screen.queryByText("Call Graph")).toBeNull();
    expect(callGraphBox(container)).toBeNull();
  });

  it("is absent when the cursor's function has neither a caller nor a callee", () => {
    const { container } = renderSidebar({
      functions: [...FUNCS3, LONELY],
      callGraph: GRAPH,
      currentAddress: LONELY.address,
    });
    expect(screen.queryByText("Call Graph")).toBeNull();
    expect(callGraphBox(container)).toBeNull();
  });

  it("is absent when the cursor is outside every function", () => {
    const { container } = renderSidebar({ functions: FUNCS3, callGraph: GRAPH });
    expect(callGraphBox(container)).toBeNull();
  });
});

describe("Sidebar call graph resize", () => {
  /**
   * ARITHMETIC, NEVER MOTION — the house standard for every drag in this repo.
   * jsdom performs no layout, so nothing below has watched anything move or
   * resize; what is asserted is the number the handler computed and the string
   * React wrote into the inline style. `BottomPanels.dom.test.tsx` is the same
   * assertion one panel over.
   *
   * `ResizeHandle` updates its `prevPosRef` on EVERY mousemove, so each move's
   * delta is measured from the PREVIOUS move rather than from mousedown. That is
   * why 500 -> 470 -> 480 gives 190 then 180, and not 190 then 140.
   */
  const KEY = "peek-a-bin:callgraph-height";
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  /**
   * BY NAME, not by role alone. The sidebar has TWO buttons that are resize
   * handles — its own width grip is labelled "Resize sidebar" — so
   * `getByRole("button")` is ambiguous here in a way it is not in the bottom
   * panel's suite.
   */
  const grip = () => screen.getByRole("button", { name: "Resize panel height" });

  it("offers a height handle distinct from the sidebar's own width handle", () => {
    renderWithCallGraph();
    const height = screen.getByRole("button", { name: "Resize panel height" });
    const width = screen.getByRole("button", { name: "Resize sidebar" });
    expect(height).not.toBe(width);
  });

  it("grows when the grip is dragged UP, because the block is anchored below", () => {
    const { container } = renderWithCallGraph();
    fireEvent.mouseDown(grip(), { clientY: 500 });
    fireEvent.mouseMove(document, { clientY: 470 });
    expect(callGraphBox(container)?.style.height).toBe("190px");
    fireEvent.mouseMove(document, { clientY: 480 });
    expect(callGraphBox(container)?.style.height).toBe("180px");
    fireEvent.mouseUp(document);
  });

  it("clamps to the minimum and the maximum", () => {
    const { container } = renderWithCallGraph();
    fireEvent.mouseDown(grip(), { clientY: 500 });
    fireEvent.mouseMove(document, { clientY: 5000 });
    expect(callGraphBox(container)?.style.height).toBe("80px");
    fireEvent.mouseMove(document, { clientY: -5000 });
    expect(callGraphBox(container)?.style.height).toBe("400px");
    fireEvent.mouseUp(document);
  });

  it("persists the height reached at the END of the drag, not the one it started at", () => {
    const { container } = renderWithCallGraph();
    fireEvent.mouseDown(grip(), { clientY: 500 });
    fireEvent.mouseMove(document, { clientY: 460 });
    fireEvent.mouseUp(document);
    // THE REGRESSION `ResizeHandle`'s ref indirection EXISTS FOR, from the
    // caller's side: `handleCallGraphResizeEnd` closes over `callGraphHeight`
    // from its own render, so a mouseup handler captured at mousedown would
    // store 160 -- the pre-drag height -- however far the user dragged.
    expect(localStorage.getItem(KEY)).toBe("200");
    expect(callGraphBox(container)?.style.height).toBe("200px");
  });

  it("resizes by keyboard, one 16px step per arrow press, and persists each step", async () => {
    const { container } = renderWithCallGraph();
    // For a vertical handle ArrowUp is the DECREASE key and calls onResize(-16),
    // which through `prev - delta` GROWS the block -- the same direction the
    // mouse drag moves it.
    fireEvent.keyDown(grip(), { key: "ArrowUp" });
    expect(callGraphBox(container)?.style.height).toBe("176px");
    // `ResizeHandle` defers `onResizeEnd` by one microtask on this path.
    await Promise.resolve();
    expect(localStorage.getItem(KEY)).toBe("176");
    fireEvent.keyDown(grip(), { key: "ArrowDown" });
    expect(callGraphBox(container)?.style.height).toBe("160px");
    await Promise.resolve();
    expect(localStorage.getItem(KEY)).toBe("160");
  });

  it("restores a stored height, and refuses one outside the bounds it enforces", () => {
    localStorage.setItem(KEY, "240");
    expect(callGraphBox(renderWithCallGraph().container)?.style.height).toBe("240px");
    cleanup();

    // Out of range, unparseable and absent all fall to the default rather than
    // being clamped: a number outside these bounds was not written here.
    localStorage.setItem(KEY, "5000");
    expect(callGraphBox(renderWithCallGraph().container)?.style.height).toBe("160px");
    cleanup();

    localStorage.setItem(KEY, "not-a-number");
    expect(callGraphBox(renderWithCallGraph().container)?.style.height).toBe("160px");
  });

  it("offers no grip at all while the block is collapsed", async () => {
    const { user } = renderWithCallGraph();
    expect(screen.queryByRole("button", { name: "Resize panel height" })).not.toBeNull();
    await user.click(screen.getByText("Call Graph"));
    expect(screen.queryByRole("button", { name: "Resize panel height" })).toBeNull();
  });
});

describe("Sidebar width handle", () => {
  /**
   * THE SIDEBAR'S OWN GRIP, which had no test at all before this.
   *
   * It is a hand-rolled duplicate of `ResizeHandle orientation="horizontal"`
   * (peek-a-bin-smcf) and it does NOT share that component's shape: it closes
   * over `startX`/`startWidth` and computes an ABSOLUTE offset from mousedown,
   * where `ResizeHandle` accumulates per-move DELTAS. Both are correct; the
   * difference is why the two cannot simply be swapped, and it is pinned here
   * so a later consolidation is a refactor under test rather than a rewrite.
   *
   * Arithmetic only. jsdom performs no layout, so nothing here has seen the
   * sidebar change width — what is asserted is the number the handler computed
   * and the string React wrote into the inline style.
   */
  const KEY = "peek-a-bin:sidebar-width";
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  const aside = (c: HTMLElement) => c.querySelector("aside") as HTMLElement;
  const grip = () => screen.getByRole("button", { name: "Resize sidebar" });

  it("widens as the grip is dragged right, from the width at mousedown", () => {
    const { container } = renderSidebar();
    expect(aside(container).style.width).toBe("224px");
    fireEvent.mouseDown(grip(), { clientX: 300 });
    fireEvent.mouseMove(document, { clientX: 340 });
    expect(aside(container).style.width).toBe("264px");
    // ABSOLUTE, not accumulated: this move is measured from the 300 at
    // mousedown, so it lands on 224 + 20 rather than 264 + 40.
    fireEvent.mouseMove(document, { clientX: 320 });
    expect(aside(container).style.width).toBe("244px");
    fireEvent.mouseUp(document);
  });

  it("clamps to the minimum and the maximum", () => {
    const { container } = renderSidebar();
    fireEvent.mouseDown(grip(), { clientX: 300 });
    fireEvent.mouseMove(document, { clientX: -5000 });
    expect(aside(container).style.width).toBe("180px");
    fireEvent.mouseMove(document, { clientX: 5000 });
    expect(aside(container).style.width).toBe("400px");
    fireEvent.mouseUp(document);
  });

  it("resizes by keyboard, one 16px step per arrow press", () => {
    const { container } = renderSidebar();
    fireEvent.keyDown(grip(), { key: "ArrowRight" });
    expect(aside(container).style.width).toBe("240px");
    fireEvent.keyDown(grip(), { key: "ArrowLeft" });
    expect(aside(container).style.width).toBe("224px");
    // Not its axis: the vertical keys must not move a horizontal handle.
    fireEvent.keyDown(grip(), { key: "ArrowUp" });
    expect(aside(container).style.width).toBe("224px");
  });

  it("sets the drag cursor on <body> and restores it on mouseup", () => {
    renderSidebar();
    fireEvent.mouseDown(grip(), { clientX: 300 });
    expect(document.body.style.cursor).toBe("col-resize");
    expect(document.body.style.userSelect).toBe("none");
    fireEvent.mouseUp(document);
    expect(document.body.style.cursor).toBe("");
    expect(document.body.style.userSelect).toBe("");
  });

  it("marks itself active for the duration of a drag", () => {
    // The one thing this handle has that `ResizeHandle` does not, and therefore
    // the thing a consolidation would have to add or knowingly drop.
    renderSidebar();
    expect(grip().className).not.toContain("active");
    fireEvent.mouseDown(grip(), { clientX: 300 });
    expect(grip().className).toContain("active");
    fireEvent.mouseUp(document);
    expect(grip().className).not.toContain("active");
  });

  it("persists the width, and restores one inside the bounds it enforces", () => {
    renderSidebar();
    // Persisted from an effect keyed on the width, so unlike the Call Graph's
    // height this path is correct on the keyboard for free — at the cost of a
    // localStorage write on EVERY mousemove of a drag (peek-a-bin-smcf).
    fireEvent.keyDown(grip(), { key: "ArrowRight" });
    expect(localStorage.getItem(KEY)).toBe("240");
    cleanup();

    localStorage.setItem(KEY, "300");
    expect(aside(renderSidebar().container).style.width).toBe("300px");
    cleanup();

    localStorage.setItem(KEY, "5000");
    expect(aside(renderSidebar().container).style.width).toBe("224px");
  });
});

/**
 * THE ANNOTATIONS BLOCK — the user's own comments and renames as a list.
 *
 * Before peek-a-bin-v3uh.11 a comment appeared only inline at its own address
 * and a rename only on the function it renamed, so "what have I annotated?" and
 * "where did I write TODO?" had no answer anywhere in the app. The disassembly
 * search does match comment text, but only across the rows currently rendered,
 * so it cannot reach a comment in `.data` from `.text`.
 *
 * WHAT THESE SUITES ASSERT, AND WHAT THEY CANNOT. Rows, dispatches, edit
 * mechanics and the STRINGS React wrote into `className`/`style` are all real
 * assertions. THE BOUND IS NOT: jsdom performs no layout, so nothing here has
 * seen the block stop growing or the Functions header hold still. Deleting
 * `maxHeight`, deleting the body's `overflow-auto`, or deleting the function
 * list's `min-h-[120px]` floor each leave every assertion in this file green —
 * the same trio already recorded as inert at peek-a-bin-llrq.6, and left inert
 * rather than tuned away. "The Functions header holds still" is a BROWSER claim
 * with no instrument in this repo; it belongs to peek-a-bin-v2u.
 */

const CA = IMAGE_BASE + 0x1000;
const CB = IMAGE_BASE + 0x2000;
const HEX_A = `0x${CA.toString(16).toUpperCase()}`;
const HEX_B = `0x${CB.toString(16).toUpperCase()}`;

const annotationsBox = (c: HTMLElement) =>
  c.querySelector('[data-panel="annotations"]') as HTMLElement | null;
const annotationsBody = (c: HTMLElement) =>
  c.querySelector('[data-panel="annotations-body"]') as HTMLElement | null;

function renderAnnotated(over: Partial<AppState> = {}) {
  return renderSidebar({
    functions: FUNCS,
    comments: { [CA]: "check the bounds here" },
    renames: { [CB]: "parse_header" },
    ...over,
  });
}

describe("Sidebar annotations list", () => {
  it("lists every comment and every rename with its address", () => {
    // THE LIVENESS HALF. Every absence assertion below is worthless if the
    // block never mounts, so this one names all four strings.
    const { container } = renderAnnotated();
    expect(annotationsBox(container)).not.toBeNull();
    expect(screen.getByText("Annotations (2)")).toBeTruthy();
    expect(screen.getByText("Comments (1)")).toBeTruthy();
    expect(screen.getByText("Renames (1)")).toBeTruthy();
    expect(screen.getByText("check the bounds here")).toBeTruthy();
    expect(screen.getByText("parse_header")).toBeTruthy();
    expect(screen.getByText(HEX_A)).toBeTruthy();
    expect(screen.getByText(HEX_B)).toBeTruthy();
  });

  it("is absent when both maps are empty", () => {
    const { container } = renderSidebar({ functions: FUNCS, comments: {}, renames: {} });
    expect(annotationsBox(container)).toBeNull();
    expect(screen.queryByText(/^Annotations/)).toBeNull();
  });

  it("renders with only comments, and with only renames", () => {
    // The guard is on the SUM, and each sub-list has its own guard beneath it —
    // so a file with one kind and not the other must show that kind and no
    // empty heading for the other.
    const { container, rerender } = renderAnnotated({ renames: {} });
    expect(screen.getByText("Annotations (1)")).toBeTruthy();
    expect(screen.getByText("Comments (1)")).toBeTruthy();
    expect(screen.queryByText(/^Renames/)).toBeNull();

    rerender({ functions: FUNCS, comments: {}, renames: { [CB]: "parse_header" } });
    expect(annotationsBox(container)).not.toBeNull();
    expect(screen.getByText("Annotations (1)")).toBeTruthy();
    expect(screen.queryByText(/^Comments/)).toBeNull();
    expect(screen.getByText("Renames (1)")).toBeTruthy();
  });

  it("orders each sub-list by address, not by the order the user annotated in", () => {
    // NOT decoration. `Object.entries` returns integer-like keys in ascending
    // numeric order only for array indices; an x64 image base puts every
    // address here past 2^32 - 1, so without the sort these come back in
    // INSERTION order. The fixture is deliberately inserted high-first, which
    // is exactly what a real session produces when you annotate a callee first.
    const { container } = renderSidebar({
      functions: FUNCS,
      comments: { [CB]: "second", [CA]: "first" },
      renames: {},
    });
    const rows = [...(annotationsBody(container) as HTMLElement).querySelectorAll("li")];
    // The trailing glyph is the row's own delete affordance.
    expect(rows.map((r) => r.textContent)).toEqual([`${HEX_A}first✕`, `${HEX_B}second✕`]);
  });
});

describe("Sidebar annotations navigation", () => {
  it("jumps to the annotated address and switches to the disassembly tab", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.click(screen.getByText("check the bounds here"));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: CA });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("jumps from a rename row too, to the renamed function's own address", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.click(screen.getByText("parse_header"));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: CB });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });
});

describe("Sidebar annotations editing", () => {
  const editor = (name: "Edit comment" | "Edit name") =>
    screen.getByRole("textbox", { name }) as HTMLInputElement;

  it("opens an editor on double-click, focused, with the current text", async () => {
    const { user } = renderAnnotated();
    await user.dblClick(screen.getByText("check the bounds here"));
    const input = editor("Edit comment");
    expect(input.value).toBe("check the bounds here");
    // `focusOnMount`, asserted rather than assumed: an editor the caret is not
    // in is an editor the user has to click again.
    expect(document.activeElement).toBe(input);
  });

  it("commits a comment on Enter", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("check the bounds here"));
    await user.clear(editor("Edit comment"));
    await user.type(editor("Edit comment"), "TODO: revisit{Enter}");
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_COMMENT",
      address: CA,
      text: "TODO: revisit",
    });
  });

  it("commits a rename on Enter", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("parse_header"));
    await user.clear(editor("Edit name"));
    await user.type(editor("Edit name"), "parse_dos_header{Enter}");
    expect(dispatch).toHaveBeenCalledWith({
      type: "RENAME_FUNCTION",
      address: CB,
      name: "parse_dos_header",
    });
  });

  it("abandons on Escape, dispatching nothing", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("check the bounds here"));
    await user.clear(editor("Edit comment"));
    await user.type(editor("Edit comment"), "half a thought{Escape}");
    // WHAT THIS DOES AND DOES NOT ESTABLISH. Escape closes the editor and
    // dispatches nothing — that half is real, and removing the Escape branch
    // reddens this row. It is NOT evidence that Escape beats a blur fired by
    // unmounting the focused input: jsdom fires no blur on removal (probed,
    // not assumed), so the handler is simply gone by then. Whether a browser
    // agrees is untested here, and the Bookmarks editor above has had exactly
    // the same untested corner since long before this block existed.
    expect(dispatch).not.toHaveBeenCalledWith(expect.objectContaining({ type: "SET_COMMENT" }));
    expect(dispatch).not.toHaveBeenCalledWith(expect.objectContaining({ type: "DELETE_COMMENT" }));
    expect(screen.getByText("check the bounds here")).toBeTruthy();
  });

  it("commits on blur, which is the path a click elsewhere takes", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("parse_header"));
    await user.clear(editor("Edit name"));
    await user.type(editor("Edit name"), "renamed_by_blur");
    fireEvent.blur(editor("Edit name"));
    expect(dispatch).toHaveBeenCalledWith({
      type: "RENAME_FUNCTION",
      address: CB,
      name: "renamed_by_blur",
    });
  });

  it("reads an emptied field as a DELETE, never as an empty annotation", async () => {
    // A comment set to "" would render as a row with no text and a rename to ""
    // as a function called nothing. One declaration, `commitAnnotation`, so the
    // Enter and blur paths cannot come to disagree about it.
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("check the bounds here"));
    await user.clear(editor("Edit comment"));
    await user.type(editor("Edit comment"), "{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "DELETE_COMMENT", address: CA });

    await user.dblClick(screen.getByText("parse_header"));
    await user.clear(editor("Edit name"));
    fireEvent.blur(editor("Edit name"));
    expect(dispatch).toHaveBeenCalledWith({ type: "CLEAR_RENAME", address: CB });
  });

  it("does not navigate while the caret is being placed in the editor", async () => {
    // THE `stopPropagation` CONTROL'S TARGET. The input is nested inside the
    // row's own navigating <button> (the Bookmarks shape), so without the
    // handler on the input the click that puts the caret in the field also
    // bubbles to the button and jumps away mid-edit.
    const { dispatch, user } = renderAnnotated();
    await user.dblClick(screen.getByText("check the bounds here"));
    dispatch.mockClear();
    await user.click(editor("Edit comment"));
    expect(dispatch).not.toHaveBeenCalled();
  });
});

describe("Sidebar annotations context menu", () => {
  const openMenu = (text: string) => {
    const row = screen.getByText(text).closest("li") as HTMLElement;
    fireEvent.contextMenu(row, { clientX: 40, clientY: 60 });
  };

  it("deletes a comment", async () => {
    const { dispatch, user } = renderAnnotated();
    openMenu("check the bounds here");
    await user.click(screen.getByText("Delete comment"));
    expect(dispatch).toHaveBeenCalledWith({ type: "DELETE_COMMENT", address: CA });
    expect(screen.queryByText("Delete comment")).toBeNull();
  });

  it("clears a rename", async () => {
    const { dispatch, user } = renderAnnotated();
    openMenu("parse_header");
    await user.click(screen.getByText("Clear rename"));
    expect(dispatch).toHaveBeenCalledWith({ type: "CLEAR_RENAME", address: CB });
  });

  it("opens the editor from the menu, on the row the menu was opened over", async () => {
    const { user } = renderAnnotated();
    openMenu("parse_header");
    await user.click(screen.getByText("Rename"));
    expect((screen.getByRole("textbox", { name: "Edit name" }) as HTMLInputElement).value).toBe(
      "parse_header",
    );
  });

  it("names the two kinds differently, so the menu says what it will do", () => {
    renderAnnotated();
    openMenu("check the bounds here");
    expect(screen.getByText("Edit comment")).toBeTruthy();
    expect(screen.getByText("Delete comment")).toBeTruthy();
    expect(screen.queryByText("Clear rename")).toBeNull();
  });

  it("dismisses on a click outside", async () => {
    const { user } = renderAnnotated();
    openMenu("check the bounds here");
    expect(screen.getByText("Delete comment")).toBeTruthy();
    await user.click(document.body);
    expect(screen.queryByText("Delete comment")).toBeNull();
  });
});

describe("Sidebar annotations row delete affordance", () => {
  it("removes a comment and clears a rename without navigating", async () => {
    const { dispatch, user } = renderAnnotated();
    await user.click(screen.getByTitle(`Delete comment at ${HEX_A}`));
    expect(dispatch).toHaveBeenCalledWith({ type: "DELETE_COMMENT", address: CA });
    // The ✕ sits inside the row but outside the navigating button, and stops
    // propagation anyway; deleting must not also jump there.
    expect(dispatch).not.toHaveBeenCalledWith({ type: "SET_ADDRESS", address: CA });

    dispatch.mockClear();
    await user.click(screen.getByTitle(`Clear rename at ${HEX_B}`));
    expect(dispatch).toHaveBeenCalledWith({ type: "CLEAR_RENAME", address: CB });
  });
});

describe("Sidebar annotations bound", () => {
  /**
   * INLINE STYLE AND CLASS-NAME STRINGS ONLY. See this section's header comment:
   * every control on the bound itself is inert under jsdom (peek-a-bin-llrq.6).
   * What these DO discriminate against is the bound being deleted from the
   * source, which is the regression that would reach a browser.
   */
  it("carries a pixel cap and a percentage ceiling, and no fixed height", () => {
    const { container } = renderAnnotated();
    const box = annotationsBox(container) as HTMLElement;
    expect(box.style.maxHeight).toBe("min(180px, 30%)");
    // A CEILING, not a height: two comments must reserve two rows, not 180px.
    expect(box.style.height).toBe("");
  });

  it("stays capped whether there are two annotations or three hundred", () => {
    // Written as the literal rather than `expect(a).toBe(b)`, which is inert —
    // delete the cap and both sides are "" and still equal.
    const many: Record<number, string> = {};
    for (let i = 0; i < 300; i++) many[IMAGE_BASE + 0x30000 + i * 0x10] = `note ${i}`;
    const { container } = renderAnnotated({ comments: many, renames: {} });
    expect(annotationsBox(container)?.style.maxHeight).toBe("min(180px, 30%)");
    // The liveness half: the cap claim is only worth having over a block that
    // really did render three hundred rows.
    expect(container.querySelectorAll('[data-panel="annotations-body"] li')).toHaveLength(300);
  });

  it("scrolls inside its own body rather than growing the column", () => {
    const { container } = renderAnnotated();
    expect(annotationsBody(container)?.className).toContain("overflow-auto");
  });

  it("refuses `shrink-0` on the wrapper", () => {
    // NOT a style preference. CLAUDE.md: the bottom band may refuse to shrink
    // because its only competitor is the whole disassembly view; a sidebar
    // block competes with four content-sized siblings, and refusing would
    // starve the one child that matters.
    expect(annotationsBox(renderAnnotated().container)?.className).not.toContain("shrink-0");
  });
});

describe("Sidebar annotations collapse", () => {
  const KEY = "peek-a-bin:annotations-open";
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  it("hides the body and drops the cap once collapsed", async () => {
    const { container, user } = renderAnnotated();
    expect(annotationsBody(container)).not.toBeNull();
    await user.click(screen.getByText("Annotations (2)"));
    expect(annotationsBody(container)).toBeNull();
    // A collapsed block still holding a ceiling over one header row is dead
    // weight in the style map — the Call Graph's rule, one panel over.
    expect(annotationsBox(container)?.style.maxHeight).toBe("");
    expect(localStorage.getItem(KEY)).toBe("false");
  });

  it("starts collapsed when the stored preference says so", async () => {
    localStorage.setItem(KEY, "false");
    const { container, user } = renderAnnotated();
    expect(annotationsBody(container)).toBeNull();
    // The count is still readable while collapsed, which is what makes the
    // header worth leaving in place.
    expect(screen.getByText("Annotations (2)")).toBeTruthy();
    await user.click(screen.getByText("Annotations (2)"));
    expect(annotationsBody(container)).not.toBeNull();
    expect(localStorage.getItem(KEY)).toBe("true");
  });
});

describe("Sidebar probe ambiguity", () => {
  /**
   * peek-a-bin-llrq.3, EXTENDED TO THE ANNOTATIONS BLOCK.
   *
   * The guard exists because `.flex-1.overflow-auto` used to name the function
   * list only by coincidence of document order, and a relocation would have
   * retargeted every probe using it at a container full of caller/callee
   * buttons — silently, with the suite still green. The Annotations body is a
   * THIRD scroller and it sits ABOVE the list, so it is exactly the case that
   * guard was written for.
   *
   * It is answered by construction rather than by ordering: the body carries
   * `overflow-auto` and deliberately NOT `flex-1`, because a content-sized
   * wrapper has no spare height for a grow term to claim.
   */
  /**
   * Both collapse preferences cleared first. Every collapsible block here reads
   * localStorage at mount, `domSetup` does not clear storage between tests, and
   * an earlier suite in this file collapses the Call Graph — so without this the
   * liveness half below fails for a reason that has nothing to do with probes.
   */
  beforeEach(() => {
    localStorage.removeItem("peek-a-bin:callers-open");
    localStorage.removeItem("peek-a-bin:annotations-open");
  });
  afterEach(() => {
    localStorage.removeItem("peek-a-bin:callers-open");
    localStorage.removeItem("peek-a-bin:annotations-open");
  });

  it("leaves [data-panel=functions] the first .flex-1.overflow-auto with every block mounted", () => {
    const { container } = renderSidebar({
      functions: FUNCS3,
      callGraph: GRAPH,
      currentAddress: B,
      bookmarks: [{ address: CA, label: "entry" }],
      comments: { [CA]: "check the bounds here" },
      renames: { [CB]: "parse_header" },
    });
    // THE LIVENESS HALF: all three scrollers, and both optional blocks, really
    // are in this document. Without it the guard passes by not looking.
    expect(annotationsBody(container)).not.toBeNull();
    expect(container.querySelector('[data-panel="call-graph-body"]')).not.toBeNull();
    expect(panels(container)).toEqual([
      "sections",
      "bookmarks",
      "annotations",
      "functions-header",
      "functions",
      "call-graph",
      "footer",
    ]);

    const list = container.querySelector('[data-panel="functions"]');
    expect(container.querySelector(".flex-1.overflow-auto")).toBe(list);
  });

  it("keeps the annotations body out of that selector on purpose, not by luck", () => {
    const { container } = renderAnnotated();
    const body = annotationsBody(container) as HTMLElement;
    expect(body.className).toContain("overflow-auto");
    // The half that makes the guard above hold however the column is reordered.
    expect(body.className.split(/\s+/)).not.toContain("flex-1");
  });
});
