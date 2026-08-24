// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
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
  const { container } = render(
    <AppHarness state={stateWithPE(harnessPE(), over)} dispatch={dispatch}>
      <Sidebar />
    </AppHarness>,
  );
  return { dispatch, container, user: userEvent.setup() };
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
    const list = container.querySelector(".flex-1.overflow-auto");
    expect(list).not.toBeNull();
    expect(within(list as HTMLElement).queryAllByRole("button")).toHaveLength(0);
  });
});
