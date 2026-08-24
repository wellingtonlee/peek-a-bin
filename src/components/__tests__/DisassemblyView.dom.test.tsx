// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import { useReducer } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import {
  AppDispatchContext,
  AppStateContext,
  appReducer,
  initialState,
} from "../../hooks/usePEFile";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { DisassemblyView } from "../DisassemblyView";

/**
 * `DisassemblyView` mounted — which until `disasmClient` built its `Worker`
 * lazily was not possible at all.
 *
 * This component imports `workers/disasmClient`, and that module used to run
 * `new Worker(...)` at module scope; jsdom has no `Worker`, so the *import*
 * threw and CLAUDE.md listed the whole view, and everything split out of it, as
 * unmountable. One line moved and the largest component in the tree is
 * reachable from a test.
 *
 * WHAT THIS COVERS, AND IT IS DELIBERATELY NARROW: the four early-return
 * branches, and the ORDER between them. That order is the thing nothing else
 * here can check — `analysisNotice.test.ts` carries a guard that asserts two
 * regexes appear in a particular order *in this file's source*, precisely
 * because with no renderer the branch taken was unobservable. `StatusBar`'s
 * component test closed the other half of that pair; this closes this one, and
 * the source-order guards stay, since they also cover the case where a branch
 * exists but no state here reaches it.
 *
 * What it does NOT cover: the populated panel. Every assertion below returns
 * before the virtualized rows, the CFG, the minimap, the decompile panel and
 * the context menu, none of which has still been rendered by anything. Mounting
 * is not testing.
 *
 * The worker never has to answer, and mostly is never built: each branch here
 * is one `useDisassemblyRows` declines to post from (it returns early unless
 * `disasmReady`), or one where the request is left pending. `Worker` is stubbed
 * so that a post would be recorded rather than throwing, and so the count can
 * be asserted.
 */

class CountingWorker {
  static built = 0;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: ((e: unknown) => void) | null = null;
  constructor() {
    CountingWorker.built++;
  }
  postMessage() {}
  terminate() {}
}

/** ARM Thumb-2 (Windows on ARM32) — an architecture every decoder here refuses. */
const ARMNT = 0x01c4;

const X86 = parsePE(buildMinimalPE32());
const ARM = parsePE(buildMinimalPE32({ machine: ARMNT }));

function mount(overrides: Partial<AppState>) {
  function Host() {
    const [state, dispatch] = useReducer(appReducer, {
      ...initialState,
      peFile: X86,
      disasmReady: true,
      ...overrides,
    });
    return (
      <AppStateContext.Provider value={state}>
        <AppDispatchContext.Provider value={dispatch}>
          <DisassemblyView />
        </AppDispatchContext.Provider>
      </AppStateContext.Provider>
    );
  }
  return render(<Host />);
}

beforeEach(() => {
  CountingWorker.built = 0;
  vi.stubGlobal("Worker", CountingWorker);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DisassemblyView mounts", () => {
  it("renders nothing at all with no file open", () => {
    const { container } = mount({ peFile: null });
    expect(container.innerHTML).toBe("");
    // The point of the whole change: getting this far means the module graph
    // was imported and the component ran, neither of which was possible while
    // the client constructed its worker at import.
    expect(CountingWorker.built).toBe(0);
  });

  it("replaces the panel for an architecture no decoder here reads", () => {
    mount({ peFile: ARM, analysisPhase: "ready" });
    expect(screen.getByRole("heading").textContent).toBe("No disassembly for this image");
    // Amber, not red: an ARM32 image is what the file IS, not a fault.
    expect(screen.getByRole("heading").className).toContain("text-amber-400");
    expect(screen.getByText(/Still available:/)).toBeTruthy();
  });

  it("offers the parser-derived tabs as buttons, not as prose", () => {
    // The detail lists tabs from PARSER_DERIVED_TABS rather than spelling them,
    // so the sentence cannot disagree with the buttons. Both are on screen.
    mount({ peFile: ARM, analysisPhase: "ready" });
    const labels = screen.getAllByRole("button").map((b) => b.textContent);
    expect(labels).toContain("Imports");
    expect(labels).toContain("Strings");
  });

  it("says the engine failed, in red, rather than blaming the file", () => {
    mount({ disasmReady: false, disasmFailed: "engine died", analysisPhase: "ready" });
    const heading = screen.getByRole("heading");
    expect(heading.textContent).toBe("No disassembly: the engine did not load");
    expect(heading.className).toContain("text-red-400");
  });

  /**
   * The branch ORDER, which is the assertion this file exists for.
   *
   * `disasmFailed` and `!disasmReady` are set together — a rejected `init()`
   * sets the first and never clears the second — so both branches are live and
   * only their order decides what a user reads. Getting it wrong leaves
   * "Loading disassembly engine..." spinning for the rest of the session while
   * the status bar says the engine failed (peek-a-bin-b3jn).
   */
  it("puts the engine notice ahead of the spinner that would never resolve", () => {
    mount({ disasmReady: false, disasmFailed: "engine died", analysisPhase: "ready" });
    expect(screen.queryByText(/Loading disassembly engine/)).toBeNull();
  });

  it("still shows that spinner while the engine is merely loading", () => {
    // The control for the test above: with no failure recorded the spinner is
    // correct and must survive. An order test whose losing branch can never
    // render is not testing an order.
    mount({ disasmReady: false, analysisPhase: "idle" });
    expect(screen.getByText(/Loading disassembly engine/)).toBeTruthy();
    expect(screen.queryByRole("heading")).toBeNull();
  });

  it("builds no worker for any branch that cannot disassemble", () => {
    mount({ peFile: ARM, analysisPhase: "ready" });
    mount({ disasmReady: false, disasmFailed: "engine died" });
    mount({ disasmReady: false });
    expect(CountingWorker.built).toBe(0);
  });
});
