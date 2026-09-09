// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import { useReducer } from "react";
import { describe, expect, it } from "vitest";
import type { AnalysisPhase, AppState } from "../../hooks/usePEFile";
import {
  ANALYSIS_IN_PROGRESS,
  AppDispatchContext,
  AppStateContext,
  appReducer,
  initialState,
} from "../../hooks/usePEFile";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { type AnalysisNoticeKind, analysisNotice } from "../analysisNotice";
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
/**
 * ARM Thumb-2 (0x01C4) -- a machine word `archForMachine` answers
 * `"unsupported"` for. Reaching `"unsupported-arch"` needs no real ARM32
 * binary, only a flipped machine word.
 */
const ARM_PE = parsePE(buildMinimalPE32({ machine: 0x01c4 }));

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
 * A DEFECT FOUND BY RENDERING. FIXED IN 3fbfd64; THESE ARE ITS REGRESSION PINS.
 *
 * `AnalysisNotice.isFault` exists so that "is this red or amber" is decided in
 * one place. CLAUDE.md records why: the render sites "each spelled
 * `kind === "analysis-failed"` to pick red over amber, which is a hand-written
 * predicate a new kind joins on the wrong side of silently", and four sites had
 * been converted to read `isFault` — three in `App.tsx` and one in
 * `DisassemblyView.tsx`, which CLAUDE.md attributed wholly to `App.tsx` until
 * session 24 re-counted them.
 *
 * THERE WAS A FIFTH SITE. `StatusBar.tsx` still spelled the predicate by hand,
 * and two kinds had since joined on the wrong side of it: `"engine-unavailable"`
 * and `"analysis-timed-out"` are both `isFault: true` — the file argues at
 * length that the timeout's `isFault` being true is the point, and that reading
 * it as false is "the trap" — so both rendered AMBER in the status bar while the
 * same notice rendered RED in App's banner. One notice, two colours, on screen
 * at the same time.
 *
 * Filed as `peek-a-bin-n7q1` and fixed one line later in 3fbfd64, so the cases
 * below are plain `it`s asserting the CORRECT colour and they pass. They are
 * kept because the predicate they pin is one a future kind can rejoin on the
 * wrong side of; the last of them is stated as the INVARIANT over every kind
 * rather than as three cases, so a seventh kind is covered the day it is added.
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

  /**
   * One state per KIND, keyed by kind.
   *
   * It was an unkeyed array of five, and the comment above it claimed to state
   * "the invariant rather than three cases, so a seventh kind is covered the day
   * it is added" -- which a hand-written list cannot do, and did not: every
   * entry used the x86 `PE`, so `"unsupported-arch"`, the HIGHEST-ranked of the
   * six, had never been through this loop at all. A `Record<AnalysisNoticeKind,
   * ...>` is what makes the claim true, on `analysisNotice.test.ts`'s own model
   * and for the reason CLAUDE.md gives for `VIEW_TAB_LABELS` and
   * `DETECT_PASS_LABELS`: a seventh kind now fails the BUILD here.
   *
   * `peFile` is per case rather than fixed, because the architecture is a
   * property of the file and not of the phase -- the only way to reach
   * `"unsupported-arch"` is to hand the bar an image whose machine word no
   * decoder reads.
   */
  const REACHED: Record<AnalysisNoticeKind, Partial<AppState>> = {
    "unsupported-arch": { peFile: ARM_PE, analysisPhase: "failed", error: "xrefs refused" },
    "no-code-section": { analysisPhase: "no-code" },
    "engine-unavailable": { analysisPhase: "building-xrefs", disasmFailed: "boom" },
    "analysis-timed-out": { analysisPhase: "timed-out" },
    "analysis-failed": { analysisPhase: "failed", error: "x" },
    "partial-detection": { analysisPhase: "ready", omittedPasses: ["call-targets"] },
  };

  it.each(Object.keys(REACHED) as AnalysisNoticeKind[])(
    "agrees with App.tsx, which reads isFault: %s",
    (kind) => {
      const overrides = REACHED[kind];
      const notice = analysisNotice({
        machine: (overrides.peFile ?? PE).coffHeader.machine,
        phase: overrides.analysisPhase ?? "idle",
        error: overrides.error ?? null,
        omitted: overrides.omittedPasses ?? [],
        engineError: overrides.disasmFailed ?? null,
      });
      // The state has to actually REACH the kind it is filed under, or the
      // colour assertion below is about some other branch entirely -- the same
      // both-halves rule `analysisNotice.test.ts`'s isFault table states.
      expect(notice?.kind).toBe(kind);
      mount(overrides);
      const cls = screen.getByText(notice?.label ?? "").className;
      expect(cls).toContain(notice?.isFault ? "text-red-400" : "text-amber-400");
    },
  );
});

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * THE PHASE SENTENCE, OVER EVERY MEMBER OF `AnalysisPhase`.
 *
 * `StatusBar`'s `phaseLabels` was a `Record<string, string>` holding six of the
 * eleven phases, with the other five simply ABSENT and a comment explaining that
 * "failed" was left out on purpose. The comment's finding was right and is kept;
 * the SHAPE was the problem. A `Record<string, …>` cannot tell "deliberately has
 * no sentence" from "nobody thought about it", so a twelfth phase would also be
 * absent — and if it were an in-progress one the bar would have spun with no
 * sentence beside it, which is the defect `ANALYSIS_IN_PROGRESS` was introduced
 * one field over to stop (peek-a-bin-bo3b). It is
 * `Record<AnalysisPhase, string | null>` now, so writing `null` is a decision the
 * author of a new phase has to make (peek-a-bin-v3uh.8).
 *
 * *** THE FIVE `null`s CANNOT BE COVERED BY A RUNTIME ROW, AND THIS IS THE
 * HONEST STATEMENT OF THAT. *** The render site is behind `ANALYSIS_IN_PROGRESS`,
 * which excludes every terminal phase, so no terminal phase can ever look its
 * label up: there is no perturbation of `phaseLabels`' null entries that reddens
 * anything here. The rows below assert the OBSERVABLE half — that a terminal
 * phase puts no phase sentence on screen, which is a property of the render site
 * rather than of those entries. Their whole value is the compile-time
 * obligation, measured as a typecheck counterfactual and recorded in
 * docs/verification.md. Do not add a row that appears to cover them.
 *
 * The table is `Record<AnalysisPhase, string | null>` so that a twelfth phase
 * fails to compile HERE too, rather than quietly going untested. It restates the
 * six sentences rather than importing them, so a reworded label is a visible
 * diff instead of a tautology.
 * ─────────────────────────────────────────────────────────────────────────────
 */
describe("StatusBar's phase sentence", () => {
  const SENTENCES: Record<AnalysisPhase, string | null> = {
    idle: null,
    parsing: "Parsing PE...",
    "detecting-functions": "Detecting functions...",
    "recursive-descent": "Recursive descent...",
    "gap-filling": "Gap filling...",
    "building-xrefs": "Building xrefs...",
    "extracting-strings": "Extracting strings...",
    ready: null,
    failed: null,
    "no-code": null,
    "timed-out": null,
  };

  const PHASES = Object.keys(SENTENCES) as AnalysisPhase[];
  const IN_PROGRESS = PHASES.filter((p) => SENTENCES[p] !== null);
  const TERMINAL = PHASES.filter((p) => SENTENCES[p] === null);

  it("agrees with ANALYSIS_IN_PROGRESS about which phases are working phases", () => {
    // The liveness half, and the one that makes the two lists below mean
    // anything: a sentence is owed exactly to a phase the app calls in-flight.
    // Without this the table could drift into testing its own opinion.
    expect(IN_PROGRESS.filter((p) => !ANALYSIS_IN_PROGRESS[p])).toEqual([]);
    expect(TERMINAL.filter((p) => ANALYSIS_IN_PROGRESS[p])).toEqual([]);
    expect(IN_PROGRESS).toHaveLength(6);
    expect(TERMINAL).toHaveLength(5);
  });

  it.each(IN_PROGRESS)("shows the sentence for %s, beside a spinner", (phase) => {
    mount({ analysisPhase: phase });
    const sentence = SENTENCES[phase] ?? "";
    const span = screen.getByText(sentence, { exact: false });
    expect(span.textContent).toContain(sentence);
    // The spinner and the sentence are one span. Asserting the sentence alone
    // would pass over a bar that had stopped saying anything is happening.
    expect(span.querySelector("svg.animate-spin")).toBeTruthy();
    expect(span.className).toContain("text-yellow-400");
  });

  it.each(TERMINAL)("shows no phase sentence at all for %s", (phase) => {
    mount({ analysisPhase: phase });
    for (const s of Object.values(SENTENCES)) {
      if (s !== null) expect(screen.queryByText(s, { exact: false })).toBeNull();
    }
    expect(document.querySelector("svg.animate-spin")).toBeNull();
  });
});
