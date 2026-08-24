// @vitest-environment jsdom

import "../../test/domSetup";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { act, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useEffect, useReducer, useRef } from "react";
import { describe, expect, it } from "vitest";
import {
  AppDispatchContext,
  AppStateContext,
  appReducer,
  initialState,
  useAppDispatch,
  useAppState,
} from "../usePEFile";

/**
 * THE MEASUREMENT `peek-a-bin-qvv` HAS BEEN WAITING FOR, as far as a renderer
 * can take it.
 *
 * That bead says MEASURE FIRST and records the measurement as unobtainable —
 * "no React renderer exists". One now does, so the render COUNT half is settled
 * here. Read the boundary before quoting a number:
 *
 *  - **This is a HARNESS, not the real view.** `DisassemblyView` is ~1520 lines
 *    and is lazy-loaded. It is *mountable* since peek-a-bin-s22 made the worker
 *    lazy (see `DisassemblyView.dom.test.tsx`), but only its early-return
 *    branches have been rendered; nothing has yet driven the populated panel a
 *    render count would have to be counted over. What is
 *    real here is the reducer (`appReducer`), the state (`initialState`), the
 *    two contexts, and React's own batching. What is a transcription is the
 *    shape: one component holding the cursor effect, one reading the two fields
 *    it feeds, and some consumers that read neither. `describe("the shape this
 *    harness stands in for")` below scrapes the real files so the transcription
 *    cannot quietly stop describing them.
 *  - **Count is not cost.** Whether N full-tree renders per keystroke is slow
 *    depends on what a render of the *real* tree costs — a virtualized list, a
 *    dagre-laid-out graph — and that still needs React DevTools Profiler on a
 *    real binary in a real browser. This closes the bead's structural blocker,
 *    not the bead.
 *  - **No `StrictMode`**, deliberately: it double-invokes render, which would
 *    double every number below and measure React's development behaviour rather
 *    than the app's.
 */

interface Row {
  addr: number;
  size: number;
  bytes: number[];
  blockIdx: number;
}

const ROWS: Row[] = [
  { addr: 0x1000, size: 2, bytes: [0x8b, 0xec], blockIdx: 0 },
  { addr: 0x1002, size: 3, bytes: [0x83, 0xec, 0x10], blockIdx: 0 },
  { addr: 0x1005, size: 1, bytes: [0xc3], blockIdx: 1 },
];

/** Render tallies, keyed by component name. */
type Counts = Record<string, number>;

function useCount(counts: Counts, name: string) {
  const n = useRef(0);
  n.current += 1;
  counts[name] = n.current;
}

/** A consumer that reads the context and none of the cursor fields. */
function Bystander({ counts, name }: { counts: Counts; name: string }) {
  const state = useAppState();
  useCount(counts, name);
  // Read *something*, as every real consumer does, so the read is not elided.
  return <span>{state.activeTab}</span>;
}

/**
 * Stands in for `StatusBar`, the ONLY reader of `currentInstruction` and
 * `currentBlock` (see the scrape below).
 */
function StatusBarish({ counts }: { counts: Counts }) {
  const state = useAppState();
  useCount(counts, "StatusBar");
  return (
    <span>{`${state.currentInstruction?.size ?? "-"}/${state.currentBlock?.startAddr ?? "-"}`}</span>
  );
}

/**
 * Stands in for `DisassemblyView`: an arrow key dispatches `SET_ADDRESS`, and a
 * separate effect keyed on the derived cursor index then dispatches the two
 * fields the status bar wants. Transcribed from DisassemblyView.tsx's
 * "Dispatch current instruction & block info for status bar" effect.
 */
function DisassemblyViewish({ counts, rows }: { counts: Counts; rows: Row[] }) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  useCount(counts, "DisassemblyView");
  const currentIndex = rows.findIndex((r) => r.addr === state.currentAddress);

  useEffect(() => {
    const row = rows[currentIndex];
    if (row) {
      dispatch({
        type: "SET_CURRENT_INSTRUCTION",
        instruction: { bytes: Array.from(row.bytes), size: row.size },
      });
      let startAddr = row.addr;
      let endAddr = row.addr;
      for (let i = currentIndex; i >= 0; i--) {
        const r = rows[i];
        if (r?.blockIdx !== row.blockIdx) break;
        startAddr = r.addr;
      }
      for (let i = currentIndex; i < rows.length; i++) {
        const r = rows[i];
        if (r?.blockIdx !== row.blockIdx) break;
        endAddr = r.addr + r.size;
      }
      dispatch({ type: "SET_CURRENT_BLOCK", block: { startAddr, endAddr } });
    } else {
      dispatch({ type: "SET_CURRENT_INSTRUCTION", instruction: null });
      dispatch({ type: "SET_CURRENT_BLOCK", block: null });
    }
  }, [currentIndex, rows, dispatch]);

  return (
    // A button rather than the real view's focusable scroll container: what
    // matters is that one focused element carries the key handler, and a button
    // is the spelling that needs no a11y escape hatch in a fixture.
    <button
      type="button"
      data-testid="view"
      onKeyDown={(e) => {
        if (e.key !== "ArrowDown") return;
        const next = rows[Math.min(currentIndex + 1, rows.length - 1)];
        if (next) dispatch({ type: "SET_ADDRESS", address: next.addr });
      }}
    >
      {state.currentAddress}
    </button>
  );
}

function Tree({ counts, rows, children }: { counts: Counts; rows: Row[]; children?: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, {
    ...initialState,
    currentAddress: ROWS[0].addr,
  });
  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>
        <DisassemblyViewish counts={counts} rows={rows} />
        <StatusBarish counts={counts} />
        <Bystander counts={counts} name="HexView" />
        <Bystander counts={counts} name="Sidebar" />
        <Bystander counts={counts} name="AddressBar" />
        {children}
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}

describe("renders per cursor move", () => {
  it("costs TWO full-tree renders per arrow key, and the second one exists only for the status bar", async () => {
    const counts: Counts = {};
    const user = userEvent.setup();
    const { getByTestId } = render(<Tree counts={counts} rows={ROWS} />);
    getByTestId("view").focus();

    // The mount itself already costs a second pass, from the same effect.
    const afterMount = { ...counts };
    expect(afterMount.DisassemblyView).toBe(2);

    await user.keyboard("{ArrowDown}");

    const perKey = Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, v - (afterMount[k] ?? 0)]),
    );
    // THE NUMBER. Every consumer, including the three that read neither field.
    expect(perKey).toEqual({
      DisassemblyView: 2,
      StatusBar: 2,
      HexView: 2,
      Sidebar: 2,
      AddressBar: 2,
    });
  });

  it("re-renders every consumer for a change only the status bar reads", async () => {
    // Isolates the second of the two renders: dispatch the cursor fields alone,
    // with no SET_ADDRESS, and see who wakes up.
    const counts: Counts = {};
    let dispatchOut: ((a: { type: "SET_CURRENT_BLOCK"; block: null }) => void) | null = null;
    function Grab() {
      dispatchOut = useAppDispatch() as typeof dispatchOut;
      return null;
    }
    render(
      <Tree counts={counts} rows={ROWS}>
        <Grab />
      </Tree>,
    );
    const before = { ...counts };
    await act(async () => {
      dispatchOut?.({ type: "SET_CURRENT_BLOCK", block: null });
    });
    const delta = Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, v - (before[k] ?? 0)]),
    );
    // One render each — but four of the five components read nothing that moved.
    expect(delta).toEqual({
      DisassemblyView: 1,
      StatusBar: 1,
      HexView: 1,
      Sidebar: 1,
      AddressBar: 1,
    });
  });

  it("costs a full-tree render when rows are rebuilt and the cursor has not moved", async () => {
    // The bead's fifth fact: the effect's deps are [currentIndex, rows, dispatch]
    // and neither reducer branch has a no-op check, so a rename, a bookmark or a
    // hex patch — anything that rebuilds `rows` — re-renders everything for a
    // value that did not change.
    const counts: Counts = {};
    const { rerender } = render(<Tree counts={counts} rows={ROWS} />);
    const before = { ...counts };
    // Same rows, fresh array identity: exactly what a rename produces.
    rerender(<Tree counts={counts} rows={[...ROWS]} />);
    const delta = Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, v - (before[k] ?? 0)]),
    );
    // 1 for the rerender itself, 1 for the effect's redundant dispatches.
    expect(delta.HexView).toBe(2);
    expect(delta.StatusBar).toBe(2);
  });

  it("produces a NEW state object for an identical cursor payload", () => {
    // The render above is only wasted because the reducer cannot tell that
    // nothing changed. Asked of the reducer directly, with no renderer involved.
    const withBlock = appReducer(initialState, {
      type: "SET_CURRENT_BLOCK",
      block: { startAddr: 0x1000, endAddr: 0x1005 },
    });
    const again = appReducer(withBlock, {
      type: "SET_CURRENT_BLOCK",
      block: { startAddr: 0x1000, endAddr: 0x1005 },
    });
    expect(again).not.toBe(withBlock);
    expect(again.currentBlock).toEqual(withBlock.currentBlock);

    const nulled = appReducer(initialState, { type: "SET_CURRENT_INSTRUCTION", instruction: null });
    // Contrast SET_OMITTED_PASSES, which DOES return `state` for a no-op — the
    // pattern exists in this reducer, it just is not applied here.
    expect(nulled).not.toBe(initialState);
    expect(nulled.currentInstruction).toBeNull();
  });
});

const SRC = join(import.meta.dirname, "..", "..");
const read = (p: string) => readFileSync(join(SRC, p), "utf8");

/**
 * Drift guards. The harness above is a transcription, so these assert that the
 * thing it transcribes is still there — otherwise the render counts quietly
 * become a measurement of nothing.
 */
describe("the shape this harness stands in for", () => {
  it("still has DisassemblyView dispatching both cursor fields from one effect", () => {
    const src = read("components/DisassemblyView.tsx");
    const effect = src.slice(
      src.indexOf('type: "SET_CURRENT_INSTRUCTION"'),
      src.indexOf("[currentIndex, rows, dispatch]"),
    );
    expect(effect).toContain('type: "SET_CURRENT_BLOCK"');
    expect(src).toContain("[currentIndex, rows, dispatch]");
  });

  it("still has exactly one reader of currentInstruction and currentBlock", () => {
    const readers = filesUnder(SRC).filter((f) => {
      if (f.endsWith("usePEFile.ts") || f.includes("__tests__")) return false;
      const src = readFileSync(f, "utf8");
      return /\bstate\.current(Instruction|Block)\b/.test(src);
    });
    expect(readers.map((f) => f.slice(SRC.length + 1))).toEqual(["components/StatusBar.tsx"]);
  });

  it("still has no React.memo anywhere, so no consumer can opt out", () => {
    const memoed = filesUnder(SRC).filter(
      (f) =>
        !f.includes("__tests__") && /\bReact\.memo\(|[^.\w]memo\(/.test(readFileSync(f, "utf8")),
    );
    expect(memoed).toEqual([]);
  });
});

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(p));
    else if (/\.tsx?$/.test(entry.name)) out.push(p);
  }
  return out.sort();
}
