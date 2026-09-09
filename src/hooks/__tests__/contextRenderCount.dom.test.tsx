// @vitest-environment jsdom

import "../../test/domSetup";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { act, render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  createContext,
  memo,
  type ReactNode,
  useContext,
  useEffect,
  useReducer,
  useRef,
  useState,
} from "react";
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
 *    and is lazy-loaded. It is *mountable* since peek-a-bin-z8h1 made the worker
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
 *    not the bead. **Nothing measured in this file is evidence that anything
 *    got faster**, and no change made on its evidence may claim so.
 *
 * WHAT THE SECOND `describe` ADDS, and why it is here rather than in a report:
 * two of the three remedies `peek-a-bin-qvv` proposes are INERT as stated, and
 * both refusals are executable so the next agent does not re-derive them.
 * `App` owns the `useReducer` and renders the whole tree inline in its own JSX,
 * so a consumer re-renders because its PARENT did, not because a context value
 * changed — which is the wrong end of every context-shaped remedy. Splitting
 * the context changes nothing until the new state also moves into a provider
 * that takes `children`; `React.memo` changes nothing because every expensive
 * leaf either reads the context or is handed `currentAddress`.
 *
 * WHAT DID LAND on that evidence: the two cursor branches of `appReducer` now
 * compare before replacing, so an identical payload returns `state` itself.
 * That removes the *rows-rebuilt-cursor-still* render and **leaves the arrow
 * key at two**, which the fourth test asserts so the change cannot be
 * over-read.
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

  it("costs ONE render when rows are rebuilt and the cursor has not moved", async () => {
    // The effect's deps are [currentIndex, rows, dispatch], so anything that
    // rebuilds `rows` re-dispatches both cursor fields with an IDENTICAL
    // payload. This used to cost 2 — one for the rerender, one more for the
    // effect's redundant dispatches — and the assertion below pinned that 2 as
    // the rule while the docstring beside it called it waste. The two reducer
    // branches now compare before replacing, so the second pass is gone.
    //
    // Measured against the real view at 9178da0: 6 of the 12 cursor dispatches
    // a load plus three arrow keys produces carry a payload the state already
    // holds, 4 of them during the load's `rows` rebuilds.
    const counts: Counts = {};
    const { rerender } = render(<Tree counts={counts} rows={ROWS} />);
    const before = { ...counts };
    // Same rows, fresh array identity: exactly what a rename produces.
    rerender(<Tree counts={counts} rows={[...ROWS]} />);
    const delta = Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, v - (before[k] ?? 0)]),
    );
    // 1 for the rerender itself, and nothing for the effect.
    expect(delta.HexView).toBe(1);
    expect(delta.StatusBar).toBe(1);
  });

  it("still costs TWO renders per arrow key — the no-op guard does NOT touch this", async () => {
    // THE LIMIT OF THE CHANGE, asserted so it cannot be over-read. A cursor move
    // genuinely changes the instruction, and the two dispatches are batched into
    // one pass, so guarding them removes nothing here. The bead's headline
    // complaint — one whole-tree render per keystroke — is UNCHANGED.
    const counts: Counts = {};
    const user = userEvent.setup();
    const { getByTestId } = render(<Tree counts={counts} rows={ROWS} />);
    getByTestId("view").focus();
    const before = { ...counts };
    await user.keyboard("{ArrowDown}");
    expect(counts.HexView - before.HexView).toBe(2);
  });

  it("returns the SAME state object for an identical cursor payload", () => {
    // The render above was only wasted because the reducer could not tell that
    // nothing had changed. Asked of the reducer directly, with no renderer
    // involved. `SET_OMITTED_PASSES` is the precedent and carries the same
    // comment; these two branches now follow it.
    const block = { startAddr: 0x1000, endAddr: 0x1005 };
    const withBlock = appReducer(initialState, { type: "SET_CURRENT_BLOCK", block });
    expect(withBlock).not.toBe(initialState);
    // A structurally equal payload in a FRESH object — which is what the cursor
    // effect builds every time, so an identity check alone would be inert here.
    const again = appReducer(withBlock, {
      type: "SET_CURRENT_BLOCK",
      block: { startAddr: 0x1000, endAddr: 0x1005 },
    });
    expect(again).toBe(withBlock);

    // ...and a real change still replaces.
    const moved = appReducer(withBlock, {
      type: "SET_CURRENT_BLOCK",
      block: { startAddr: 0x1000, endAddr: 0x1006 },
    });
    expect(moved).not.toBe(withBlock);
    expect(moved.currentBlock).toEqual({ startAddr: 0x1000, endAddr: 0x1006 });

    // The instruction half compares `bytes` element-wise, not by identity.
    const withInsn = appReducer(initialState, {
      type: "SET_CURRENT_INSTRUCTION",
      instruction: { bytes: [0x8b, 0xec], size: 2 },
    });
    expect(
      appReducer(withInsn, {
        type: "SET_CURRENT_INSTRUCTION",
        instruction: { bytes: [0x8b, 0xec], size: 2 },
      }),
    ).toBe(withInsn);
    // A one-byte difference at the same size and length must still replace, or
    // the comparison is a length check wearing a value check's clothes.
    expect(
      appReducer(withInsn, {
        type: "SET_CURRENT_INSTRUCTION",
        instruction: { bytes: [0x8b, 0xed], size: 2 },
      }),
    ).not.toBe(withInsn);

    const nulled = appReducer(initialState, { type: "SET_CURRENT_INSTRUCTION", instruction: null });
    expect(nulled).toBe(initialState);
  });
});

/** One arrow key, counting every consumer. */
async function perKey(Root: (p: { counts: Counts }) => ReactNode) {
  const counts: Counts = {};
  const user = userEvent.setup();
  const { getByTestId } = render(<Root counts={counts} />);
  getByTestId("view").focus();
  const before = { ...counts };
  await user.keyboard("{ArrowDown}");
  return Object.fromEntries(Object.entries(counts).map(([k, v]) => [k, v - (before[k] ?? 0)]));
}

/** The cursor fields, moved off `AppState` into a context of their own. */
interface Cursor {
  insn: { size: number } | null;
}
const CursorState = createContext<Cursor>({ insn: null });
const CursorSet = createContext<(c: Cursor) => void>(() => {});

function SplitStatusBar({ counts }: { counts: Counts }) {
  const cursor = useContext(CursorState);
  useCount(counts, "StatusBar");
  return <span>{cursor.insn?.size ?? "-"}</span>;
}

function SplitView({ counts }: { counts: Counts }) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const setCursor = useContext(CursorSet);
  useCount(counts, "DisassemblyView");
  const i = ROWS.findIndex((r) => r.addr === state.currentAddress);
  useEffect(() => {
    setCursor({ insn: { size: ROWS[i]?.size ?? 0 } });
  }, [i, setCursor]);
  return (
    <button
      type="button"
      data-testid="view"
      onKeyDown={(e) => {
        if (e.key !== "ArrowDown") return;
        const next = ROWS[Math.min(i + 1, ROWS.length - 1)];
        if (next) dispatch({ type: "SET_ADDRESS", address: next.addr });
      }}
    >
      {state.currentAddress}
    </button>
  );
}

function SplitConsumers({ counts }: { counts: Counts }) {
  return (
    <>
      <SplitView counts={counts} />
      <SplitStatusBar counts={counts} />
      <Bystander counts={counts} name="HexView" />
      <Bystander counts={counts} name="Sidebar" />
    </>
  );
}

/**
 * THE THREE OPTIONS `peek-a-bin-qvv` LISTS, MEASURED — and two of them are
 * INERT as the bead states them. Executable rather than written down, because
 * otherwise the next agent re-derives them at the cost of a session.
 *
 * The finding that decides all three: **`App` owns the `useReducer` and renders
 * the whole tree inline in its own JSX** (`App.tsx`, `useReducer` at the top,
 * providers at the bottom of the same function). So a consumer re-renders
 * because its PARENT re-rendered, not because a context value changed — and
 * every remedy aimed at the context is answering the wrong question.
 */
describe("the options this bead lists, measured", () => {
  it("option 1, splitting the context, is INERT while the reducer lives in App", async () => {
    // A second context holding only the cursor fields, with its state still held
    // by the App-shaped component. Every consumer still wakes up twice, because
    // that component re-renders and recreates every child element — so the
    // context it read them through never enters into it.
    function Naive({ counts }: { counts: Counts }) {
      const [state, dispatch] = useReducer(appReducer, {
        ...initialState,
        currentAddress: ROWS[0].addr,
      });
      const [cursor, setCursor] = useState<Cursor>({ insn: null });
      return (
        <AppStateContext.Provider value={state}>
          <AppDispatchContext.Provider value={dispatch}>
            <CursorState.Provider value={cursor}>
              <CursorSet.Provider value={setCursor}>
                <SplitConsumers counts={counts} />
              </CursorSet.Provider>
            </CursorState.Provider>
          </AppDispatchContext.Provider>
        </AppStateContext.Provider>
      );
    }
    // THE REFUSAL: identical to the unsplit number in the first test above.
    expect(await perKey(Naive)).toEqual({
      DisassemblyView: 2,
      StatusBar: 2,
      HexView: 2,
      Sidebar: 2,
    });
  });

  it("...and works only once the cursor state is in a provider taking `children`", async () => {
    // The shape that DOES buy something, and what it costs to reach: the cursor
    // state must live in a provider COMPONENT that takes `children`, so its own
    // state change leaves the children element identical and React bails out of
    // the subtree. That is options 1 and 3 together, not either alone.
    function CursorProvider({ children }: { children: ReactNode }) {
      const [cursor, setCursor] = useState<Cursor>({ insn: null });
      return (
        <CursorState.Provider value={cursor}>
          <CursorSet.Provider value={setCursor}>{children}</CursorSet.Provider>
        </CursorState.Provider>
      );
    }
    function Lifted({ counts }: { counts: Counts }) {
      const [state, dispatch] = useReducer(appReducer, {
        ...initialState,
        currentAddress: ROWS[0].addr,
      });
      return (
        <AppStateContext.Provider value={state}>
          <AppDispatchContext.Provider value={dispatch}>
            <CursorProvider>
              <SplitConsumers counts={counts} />
            </CursorProvider>
          </AppDispatchContext.Provider>
        </AppStateContext.Provider>
      );
    }
    // Halved for everyone but the status bar — and note what is NOT bought: the
    // arrow key still costs ONE whole-tree render, because `SET_ADDRESS` is
    // still in App's reducer. The bead's "each arrow key re-renders the whole
    // app" SURVIVES this change; it is halved, not removed.
    expect(await perKey(Lifted)).toEqual({
      DisassemblyView: 1,
      StatusBar: 2,
      HexView: 1,
      Sidebar: 1,
    });
  });

  it("option 2, React.memo on the expensive leaves, is INERT in every shape this tree has", async () => {
    const MemoContextConsumer = memo(function MemoContextConsumer({ counts }: { counts: Counts }) {
      // The shape of CFGView, HexView, Sidebar and StatusBar, all four of which
      // call `useAppState()` — memo cannot stop a context-driven re-render.
      const state = useAppState();
      useCount(counts, "memo+context");
      return <span>{state.activeTab}</span>;
    });
    const MemoFreshProps = memo(function MemoFreshProps(_: {
      counts: Counts;
      data: number[];
      onX: () => void;
    }) {
      useCount(_.counts, "memo+freshProps");
      return null;
    });
    const MemoStable = memo(function MemoStable({ counts }: { counts: Counts }) {
      useCount(counts, "memo+stableProps");
      return null;
    });

    function Root({ counts }: { counts: Counts }) {
      const [state, dispatch] = useReducer(appReducer, {
        ...initialState,
        currentAddress: ROWS[0].addr,
      });
      return (
        <AppStateContext.Provider value={state}>
          <AppDispatchContext.Provider value={dispatch}>
            <DisassemblyViewish counts={counts} rows={ROWS} />
            <MemoContextConsumer counts={counts} />
            {/* An inline array and an inline closure: what `InsnRow` is handed. */}
            <MemoFreshProps counts={counts} data={[1, 2, 3]} onX={() => {}} />
            <MemoStable counts={counts} />
          </AppDispatchContext.Provider>
        </AppStateContext.Provider>
      );
    }

    expect(await perKey(Root)).toEqual({
      DisassemblyView: 2,
      // Reads the context, so memo is bypassed entirely.
      "memo+context": 2,
      // Props are recreated by the parent's render, so memo's compare fails.
      "memo+freshProps": 2,
      // The one shape memo helps — and no expensive leaf here is in it.
      "memo+stableProps": 0,
    });
  });

  it("still has every expensive leaf in one of the two inert shapes", () => {
    // The liveness half of the row above: it is a measurement of two SHAPES, and
    // it only bears on this app while the real components are in them.
    for (const f of ["CFGView", "HexView", "Sidebar", "StatusBar"]) {
      expect(read(`components/${f}.tsx`)).toContain("useAppState()");
    }
    // `DisassemblyRows` and `DisassemblyMinimap` read no context — but the rows
    // are handed `currentAddress`, which changes on every cursor move by
    // definition, so memoising them cannot help either.
    expect(read("components/DisassemblyRows.tsx")).not.toContain("useAppState()");
    const view = read("components/DisassemblyView.tsx");
    expect(view.slice(view.indexOf("<InsnRow"), view.indexOf("<InsnRow") + 1400)).toContain(
      "currentAddress={state.currentAddress}",
    );
  });

  it("still has App holding the reducer and rendering the tree inline", () => {
    // The premise of all three refusals. If App is ever restructured so the
    // providers take `children`, every number above has to be re-taken.
    const app = read("App.tsx");
    expect(app).toContain("useReducer(appReducer, initialState)");
    expect(app).toContain("<AppStateContext.Provider value={state}>");
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
