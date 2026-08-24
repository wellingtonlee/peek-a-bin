// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import { useReducer } from "react";
import { describe, expect, it } from "vitest";
import type { AnalysisPhase, AppState } from "../../hooks/usePEFile";
import {
  AppDispatchContext,
  AppStateContext,
  appReducer,
  initialState,
} from "../../hooks/usePEFile";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { analysisNotice } from "../analysisNotice";
import { StatusBar } from "../StatusBar";

/**
 * The RENDER STEP of the analysis notice, in a real app component.
 *
 * `analysisNotice.test.ts` covers the decision — which kind, which rank, which
 * `isFault` — and carries two guards that assert the *order of two regex matches*
 * in this file's source, because with no renderer the branch order was
 * unreachable any other way. Those stay; this is the stronger statement beside
 * them: the notice's label is actually on the screen, in the branch that is
 * actually taken.
 *
 * `StatusBar` is a cheap component to mount — its heaviest import is
 * `llm/settings`, which reads localStorage. Components reaching
 * `workers/disasmClient` were once unmountable here, because that module
 * constructed a `Worker` at module scope and jsdom has none; since
 * peek-a-bin-z8h1 it builds on first use, and `DisassemblyView.dom.test.tsx` is
 * the counterpart to this file on the other side of that change.
 */

const PE = parsePE(buildMinimalPE32());

function mount(overrides: Partial<AppState>) {
  function Host() {
    const [state, dispatch] = useReducer(appReducer, {
      ...initialState,
      peFile: PE,
      disasmReady: true,
      ...overrides,
    });
    return (
      <AppStateContext.Provider value={state}>
        <AppDispatchContext.Provider value={dispatch}>
          <StatusBar />
        </AppDispatchContext.Provider>
      </AppStateContext.Provider>
    );
  }
  return render(<Host />);
}

describe("StatusBar renders the analysis notice", () => {
  it("shows the green ready state when there is no notice", () => {
    mount({ analysisPhase: "ready" });
    expect(screen.getByText("Ready").className).toContain("text-green-400");
  });

  it("puts the notice label on screen ahead of the ready state", () => {
    // The `phase: "failed"` case: before the notice existed this fell through
    // to a green "Engine ready", which is true of the engine and a lie about
    // the file. analysisNotice.test.ts asserts the branch ORDER in this file's
    // source; this asserts the outcome.
    mount({ analysisPhase: "failed", error: "truncated file" });
    expect(screen.getByText("Analysis failed")).toBeTruthy();
    expect(screen.queryByText("Ready")).toBeNull();
  });

  it("puts the notice label on screen ahead of the phase spinner", () => {
    // A timed-out run is not in ANALYSIS_IN_PROGRESS, but an engine that died
    // mid-analysis is: the phase is still a working one and the notice must win.
    mount({ analysisPhase: "building-xrefs", disasmFailed: "engine died" });
    expect(screen.getByText("Engine unavailable")).toBeTruthy();
    expect(screen.queryByText("Building xrefs...")).toBeNull();
  });

  it("marks a short function list as partial, beside the count", () => {
    mount({ analysisPhase: "ready", omittedPasses: ["call-targets"] });
    expect(screen.getByText("(partial)")).toBeTruthy();
    expect(screen.getByText("Partial function list")).toBeTruthy();
  });

  it("carries the notice's full sentence as the title attribute", () => {
    mount({ analysisPhase: "failed", error: "truncated file" });
    const expected = analysisNotice({
      machine: PE.coffHeader.machine,
      phase: "failed",
      error: "truncated file",
      omitted: [],
      engineError: null,
    });
    expect(screen.getByText("Analysis failed").getAttribute("title")).toBe(expected?.detail);
  });
});

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * A DEFECT, FOUND BY RENDERING AND DELIBERATELY NOT FIXED HERE.
 *
 * `AnalysisNotice.isFault` exists so that "is this red or amber" is decided in
 * one place. CLAUDE.md records why: the render sites "each spelled
 * `kind === "analysis-failed"` to pick red over amber, which is a hand-written
 * predicate a new kind joins on the wrong side of silently", and says the *four*
 * sites in `App.tsx` were converted to read `isFault`.
 *
 * THERE IS A FIFTH SITE. `StatusBar.tsx` still spells the predicate by hand, and
 * two kinds have since joined on the wrong side of it: `"engine-unavailable"`
 * and `"analysis-timed-out"` are both `isFault: true` — the file argues at
 * length that the timeout's `isFault` being true is the point, and that reading
 * it as false is "the trap" — and both render AMBER in the status bar while the
 * same notice renders RED in App's banner. One notice, two colours, on screen
 * at the same time.
 *
 * Filed as `peek-a-bin-n7q1`, and left alone on purpose: this task added a
 * renderer, it did not change behaviour. The three tests below assert the CORRECT colour and are marked
 * `.fails`, so they document the defect, and the day someone fixes StatusBar
 * they turn red and want flipping to `it`.
 * ─────────────────────────────────────────────────────────────────────────────
 */
describe("StatusBar notice colour follows isFault", () => {
  function colourOf(overrides: Partial<AppState>, label: string): string {
    mount(overrides);
    return screen.getByText(label).className;
  }

  it("is red for a failure", () => {
    expect(colourOf({ analysisPhase: "failed", error: "x" }, "Analysis failed")).toContain(
      "text-red-400",
    );
  });

  it("is amber for a property of the file, which is not a fault", () => {
    // The control: this one is `isFault: false` and amber is right, so the two
    // tests below are not just "everything should be red".
    expect(colourOf({ analysisPhase: "no-code" as AnalysisPhase }, "No code section")).toContain(
      "text-amber-400",
    );
  });

  it("is red for a dead engine (isFault: true)", () => {
    expect(
      colourOf({ analysisPhase: "building-xrefs", disasmFailed: "boom" }, "Engine unavailable"),
    ).toContain("text-red-400");
  });

  it("is red for a timed-out run (isFault: true)", () => {
    expect(
      colourOf({ analysisPhase: "timed-out" as AnalysisPhase }, "Analysis timed out"),
    ).toContain("text-red-400");
  });

  it("agrees with App.tsx, which reads isFault", () => {
    // Stated as the invariant rather than as three cases, so a seventh kind is
    // covered the day it is added.
    for (const overrides of [
      { analysisPhase: "failed" as AnalysisPhase, error: "x" },
      { analysisPhase: "building-xrefs" as AnalysisPhase, disasmFailed: "boom" },
      { analysisPhase: "timed-out" as AnalysisPhase },
      { analysisPhase: "no-code" as AnalysisPhase },
      { analysisPhase: "ready" as AnalysisPhase, omittedPasses: ["call-targets" as const] },
    ]) {
      const notice = analysisNotice({
        machine: PE.coffHeader.machine,
        phase: overrides.analysisPhase,
        error: overrides.error ?? null,
        omitted: overrides.omittedPasses ?? [],
        engineError: overrides.disasmFailed ?? null,
      });
      if (!notice) continue;
      const { unmount } = mount(overrides);
      const cls = screen.getByText(notice.label).className;
      expect(cls).toContain(notice.isFault ? "text-red-400" : "text-amber-400");
      unmount();
    }
  });
});
