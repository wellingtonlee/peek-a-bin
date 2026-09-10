// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useCallback, useMemo, useReducer, useRef } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCfgLayout } from "../../disasm/cfg";
import type { DisasmFunction, Instruction, Xref } from "../../disasm/types";
import type { GraphOverviewData } from "../../hooks/useGraphOverview";
import { GraphOverviewContext } from "../../hooks/useGraphOverview";
import type { AnalysisPhase, AppAction, AppState } from "../../hooks/usePEFile";
import {
  ANALYSIS_IN_PROGRESS,
  appReducer,
  initialState,
  useAppDispatch,
  useAppState,
} from "../../hooks/usePEFile";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import {
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
} from "../../pe/constants";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { stubLayoutRect } from "../../test/domSetup";
import { COPY_FAILED_TITLE } from "../../utils/clipboard";
import { disasmWorker } from "../../workers/disasmClient";
import { DisassemblyView } from "../DisassemblyView";
import { AppHarness } from "./appStateHarness";

/**
 * THE POPULATED DISASSEMBLY PANEL, rendered for the first time.
 *
 * `DisassemblyView.dom.test.tsx` beside this file mounts the same component and
 * covers exactly its four EARLY-RETURN branches — the notices and the spinner.
 * Everything past those returns had never been rendered by anything: CLAUDE.md's
 * "Not verified" list named the virtualized rows, `DisassemblyRows`,
 * `DisassemblyToolbar`, `InsnContextMenu`, `JumpArrows`, `DisassemblyMinimap`
 * and `InstructionDetail`. This file drives them.
 *
 * WHAT IT TAKES TO GET HERE, because none of it is obvious and each piece is a
 * separate jsdom gap:
 *
 *  - **A worker that answers.** `useDisassemblyRows` posts `disassemble` or
 *    `hybridDisassemble` and renders nothing until it resolves. {@link
 *    ScriptedWorker} is a stand-in for the *thread*, not for the client: the
 *    real `disasmClient` singleton does the real `prepareBinaryArgs`, the real
 *    request/response correlation and the real caching, and only the far side of
 *    `postMessage` is scripted. So a change to the client's protocol breaks these
 *    tests, which is the point.
 *  - **`ResizeObserver`**, which jsdom does not have at all and which
 *    `Breadcrumbs`, `DisassemblyMinimap` and `@tanstack/react-virtual` each
 *    construct from an effect. Supplied in `src/test/domSetup.ts`.
 *  - **A non-zero element size**, or the virtualizer renders ZERO rows rather
 *    than a short list. {@link stubLayoutRect} supplies it and its docstring is
 *    the honest statement of what that does and does not buy.
 *
 * WHAT IS STILL NOT COVERED, and a green run here must not be read as covering
 * it. **Virtualization is a stand-in.** Every element reports the same size,
 * `scrollTop` is permanently 0, and the stub `ResizeObserver` never fires — so
 * the virtual range is computed once from offset 0 and never moves. Which rows
 * are windowed in, whether `overscan: 50` is right, whether `scrollToIndex`
 * actually brings the cursor on screen, and whether ANY of this is visible are
 * layout questions jsdom cannot answer. A row in the document is not a row on
 * screen. Likewise the minimap paints to a canvas jsdom does not implement, and
 * the jump-arrow geometry below is asserted as *arithmetic over estimated row
 * offsets*, never as pixels.
 *
 * `CFGView` (graph mode) and the decompile and AI chat panels are deliberately
 * out of scope here; they are their own components with their own dependencies.
 */

/**
 * Which side panel should throw when it renders, or null.
 *
 * Flag-plus-passthrough, the shape `App.dom.test.tsx` uses: the mocks render the
 * genuine components whenever they are not asked to fail, so the detail-panel
 * suite below still asserts on `InstructionDetail`'s real output.
 */
let boomPanel: "detail" | "chat" | null = null;

/**
 * How many times `buildCFG` has run since the last {@link resetInstruments}.
 *
 * There were FOUR call sites in the browser, all with identical arguments, and
 * the fourth — `DisassemblyView`'s `buildCFGForNav` — is a `useCallback`
 * invoked from the arrow/Tab handler, so it ran ONCE PER KEYPRESS in graph mode.
 * A mount-only instrument cannot see that one, which is why the count below is
 * taken across three arrow presses as well as a mount.
 */
let buildCFGRuns = 0;

vi.mock("../../disasm/cfg", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../disasm/cfg")>();
  return {
    ...actual,
    buildCFG: (...args: Parameters<typeof actual.buildCFG>) => {
      buildCFGRuns++;
      return actual.buildCFG(...args);
    },
  };
});

vi.mock("../InstructionDetail", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../InstructionDetail")>();
  return {
    ...actual,
    InstructionDetail: (props: Parameters<typeof actual.InstructionDetail>[0]) => {
      if (boomPanel === "detail") throw new Error("detail panel exploded");
      return <actual.InstructionDetail {...props} />;
    },
  };
});

vi.mock("../AIChatPanel", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../AIChatPanel")>();
  return {
    ...actual,
    AIChatPanel: (props: Parameters<typeof actual.AIChatPanel>[0]) => {
      if (boomPanel === "chat") throw new Error("chat panel exploded");
      return <actual.AIChatPanel {...props} />;
    },
  };
});

stubLayoutRect({ height: 600 });

/**
 * `DisassemblyMinimap` paints to a `<canvas>`, and jsdom implements
 * `getContext` as "return null, after logging `Not implemented:
 * HTMLCanvasElement's getContext() method` to the virtual console" — 62 lines of
 * it across this file. The component already handles the null (`if (!ctx)
 * return;` at both of its draw sites), so returning null explicitly is
 * BEHAVIOUR-IDENTICAL and removes only the noise.
 *
 * It is deliberately here rather than in `domSetup.ts`: it grants no capability
 * and stands in for nothing, so a future suite that actually wants to know a
 * canvas is unpaintable should still be told. **The minimap therefore mounts and
 * never draws.** Nothing below asserts anything about what it renders, and
 * nothing could — jsdom has no 2D context and no layout to feed one.
 */
HTMLCanvasElement.prototype.getContext = () => null;

const IMAGE_BASE = 0x140000000;
const TEXT_RVA = 0x1000;
const TEXT_VA = IMAGE_BASE + TEXT_RVA;
const RDATA_RVA = 0x2000;
const RDATA_VA = IMAGE_BASE + RDATA_RVA;

/**
 * The disassembly this fixture stands for, written as (mnemonic, operands,
 * bytes) and laid out by {@link buildStream} so that no address is typed twice.
 *
 * The bytes are real x86-64 encodings of these mnemonics and the section's
 * content is their concatenation, so the scripted answer is a disassembly OF
 * THE SECTION rather than an unrelated list that happens to be returned for it.
 * Nothing decodes them here — Capstone is not loaded — but a fixture whose bytes
 * and mnemonics disagree is one whose row content cannot be checked against
 * anything.
 */
const PROGRAM: { mnemonic: string; opStr?: string; to?: number; bytes: number[] }[] = [
  // Function 0 — the one the cursor starts in.
  { mnemonic: "push", opStr: "rbp", bytes: [0x55] },
  { mnemonic: "mov", opStr: "rbp, rsp", bytes: [0x48, 0x89, 0xe5] },
  { mnemonic: "jne", to: 5, bytes: [0x75, 0x05] }, // forward, out of the fallthrough
  { mnemonic: "xor", opStr: "eax, eax", bytes: [0x31, 0xc0] },
  { mnemonic: "jmp", to: 0, bytes: [0xeb, 0xf3] }, // backward, to the function head
  { mnemonic: "pop", opStr: "rbp", bytes: [0x5d] }, // the `jne` target
  { mnemonic: "ret", opStr: "", bytes: [0xc3] },
  // Function 1 — so a label row is not the only one, and so the separator rule
  // ("none after a `ret` a label follows") has something to apply to.
  { mnemonic: "xor", opStr: "eax, eax", bytes: [0x31, 0xc0] },
  { mnemonic: "ret", opStr: "", bytes: [0xc3] },
];
/** Indices into {@link PROGRAM} that start a function. */
const FUNC_STARTS = [0, 7];

function buildStream(base: number) {
  const bytes: number[] = [];
  const addrs: number[] = [];
  let addr = base;
  for (const p of PROGRAM) {
    addrs.push(addr);
    bytes.push(...p.bytes);
    addr += p.bytes.length;
  }
  const insns: Instruction[] = PROGRAM.map((p, i) => ({
    address: addrs[i],
    bytes: Uint8Array.from(p.bytes),
    mnemonic: p.mnemonic,
    // A branch's operand is formatted from the address the layout gave its
    // target, so the stream cannot come to disagree with itself.
    opStr: p.to === undefined ? (p.opStr ?? "") : `0x${addrs[p.to].toString(16)}`,
    size: p.bytes.length,
  }));
  return { insns, code: Uint8Array.from(bytes), end: addr };
}

const { insns: INSNS, code: CODE, end: TEXT_END } = buildStream(TEXT_VA);
/** Addresses derived from the stream, never written out. */
const A = INSNS.map((i) => i.address);
const named = (address: number, size: number): DisasmFunction => ({
  name: `sub_${address.toString(16).toUpperCase()}`,
  address,
  size,
});
const FN_A = named(A[FUNC_STARTS[0]], A[FUNC_STARTS[1]] - A[FUNC_STARTS[0]]);
const FN_B = named(A[FUNC_STARTS[1]], TEXT_END - A[FUNC_STARTS[1]]);
const FUNCS = [FN_A, FN_B];

/** One xref onto the `jne` target, so the row's `×N` affordance has something to show. */
const XREFS: [number, Xref[]][] = [[A[5], [{ from: A[2], type: "branch" }]]];

/** `.rdata`, so the non-executable path (data rows, no worker) can be driven too. */
const RDATA = Uint8Array.from([0x48, 0x69, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]);

function buildPE(machine?: number): PEFile {
  return parsePE(
    buildMinimalPE64({
      imageBase: IMAGE_BASE,
      ...(machine === undefined ? {} : { machine }),
      sections: [
        {
          name: ".text",
          virtualAddress: TEXT_RVA,
          virtualSize: CODE.length,
          data: CODE,
          characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        },
        {
          name: ".rdata",
          virtualAddress: RDATA_RVA,
          virtualSize: RDATA.length,
          data: RDATA,
          characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
      ],
    }),
  );
}

const X64 = buildPE();
const ARM64 = buildPE(IMAGE_FILE_MACHINE_ARM64);

/**
 * The far side of `postMessage`, and nothing nearer than that.
 *
 * The real `DisasmWorkerClient` is a module singleton and is used unmodified:
 * it builds one of these on first send (lazily, since peek-a-bin-z8h1), posts
 * `{ id, method, args }` through the real `prepareBinaryArgs`, and matches the
 * reply by id. Replying on a macrotask rather than synchronously keeps the
 * promise resolution outside the posting call stack, as a real thread's would
 * be.
 */
class ScriptedWorker {
  static posted: string[] = [];
  static built = 0;
  /**
   * Never answer `buildTypedXrefMap`, leaving `typedXrefMap` permanently empty.
   *
   * Stands in for the window every real load passes through: `buildAllXrefs` is
   * the LAST stage, so there is a stretch during which the disassembly is on
   * screen and the xref map is not there yet. Held open here rather than raced.
   */
  static withholdXrefs = false;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: ((e: unknown) => void) | null = null;
  constructor() {
    ScriptedWorker.built++;
  }
  postMessage(msg: { id: number; method: string; args: unknown }) {
    ScriptedWorker.posted.push(msg.method);
    let result: unknown;
    switch (msg.method) {
      case "disassemble":
        result = INSNS;
        break;
      case "hybridDisassemble":
        // The FUSED reply (peek-a-bin-w96b). `disassemble` above deliberately
        // keeps the bare array: only the client's `hybridDisassemble` sets
        // `withXrefs`, and the two shapes are what the dispatch really answers
        // with. The client pre-seeds its `xrefCache` from `xrefs`, so the
        // `buildTypedXrefMap` arm below is now reached only on a fallback.
        // `withholdXrefs` has to suppress the FUSED half too, not just the
        // `buildTypedXrefMap` arm below. peek-a-bin-w96b moved the xref map
        // into this reply, so withholding only the separate RPC stopped
        // withholding anything at all — the map arrived with the instructions,
        // which is a second genuine input change, and the CFG-count row went
        // 1 -> 2. Found on the integrated tree; neither agent could see it
        // alone, because each was right about its own half.
        result = ScriptedWorker.withholdXrefs
          ? { instructions: INSNS }
          : { instructions: INSNS, xrefs: XREFS };
        break;
      case "buildTypedXrefMap":
        if (ScriptedWorker.withholdXrefs) return;
        result = XREFS;
        break;
      default:
        result = null;
    }
    setTimeout(() => this.onmessage?.({ data: { id: msg.id, result } }), 0);
  }
  terminate() {}
}

/**
 * Everything `DisassemblyView` published to the sidebar overview context, in
 * order, plus the last non-null entry.
 *
 * The real provider (`useGraphOverviewState`) keeps the value in state so
 * `Sidebar` can draw it. Nothing renders it here — the sidebar is App's, not
 * this pane's — so this probe only records, which additionally keeps `setData`
 * REFERENTIALLY STABLE. That matters: `DisassemblyView`'s publishing effect
 * lists `setGraphOverview` in its dependency array, so a setter whose identity
 * changed with the data would re-fire the effect on its own output forever.
 */
const overviewPublished: (GraphOverviewData | null)[] = [];
const lastOverview = (): GraphOverviewData => {
  for (let i = overviewPublished.length - 1; i >= 0; i--) {
    const d = overviewPublished[i];
    if (d) return d;
  }
  throw new Error("nothing was ever published to the graph overview context");
};

function GraphOverviewProbe({ children }: { children: ReactNode }) {
  const setData = useCallback((d: GraphOverviewData | null) => {
    overviewPublished.push(d);
  }, []);
  const value = useMemo(() => ({ data: null, setData }), [setData]);
  return <GraphOverviewContext.Provider value={value}>{children}</GraphOverviewContext.Provider>;
}

interface Mounted {
  /** Every action the view dispatched, in order, through the real reducer. */
  actions: AppAction[];
  state: () => AppState;
}

function mount(overrides: Partial<AppState> = {}, extra?: ReactNode) {
  const actions: AppAction[] = [];
  let latest: AppState = initialState;
  const pe = (overrides.peFile ?? X64) as PEFile;
  disasmWorker.setImage(pe.coffHeader.machine);

  function Host() {
    const [state, base] = useReducer(appReducer, {
      ...initialState,
      peFile: pe,
      disasmReady: true,
      analysisPhase: "ready",
      currentAddress: TEXT_VA,
      functions: FUNCS,
      ...overrides,
    });
    latest = state;
    // Identity must be stable: `dispatch` is in the context and in the
    // dependency array of the cursor effect, so a fresh function each render
    // would re-render every consumer and re-fire that effect — which would
    // silently invent the very renders the qvv measurement below counts.
    const sink = useRef(actions);
    // `base` is a `useReducer` dispatch, which React guarantees is stable, so
    // the list is empty rather than `[base]` — Biome's `useExhaustiveDependencies`
    // is at `error` here and reports the extra entry.
    const dispatch = useCallback((a: AppAction) => {
      sink.current.push(a);
      base(a);
    }, []);
    return (
      <AppHarness state={state} dispatch={dispatch}>
        <GraphOverviewProbe>
          <DisassemblyView />
          {extra}
        </GraphOverviewProbe>
      </AppHarness>
    );
  }

  const utils = render(<Host />);
  return { ...utils, actions, state: () => latest } as ReturnType<typeof render> & Mounted;
}

/** Mount and wait for the scripted disassembly to reach the document. */
async function mountReady(overrides: Partial<AppState> = {}, extra?: ReactNode) {
  const r = mount(overrides, extra);
  await waitFor(() => expect(r.container.querySelector(".disasm-row")).toBeTruthy());
  return r;
}

/** Every virtualized row in document order, of whatever kind. */
const allRows = (c: HTMLElement) => Array.from(c.querySelectorAll<HTMLElement>("[data-index]"));
/** Instruction rows only — `DataRow` also carries `.disasm-row`. */
const insnRows = (c: HTMLElement) =>
  Array.from(c.querySelectorAll<HTMLElement>(".disasm-row.disasm-grid"));
const dataRows = (c: HTMLElement) =>
  Array.from(c.querySelectorAll<HTMLElement>(".disasm-row.disasm-grid-data"));
const addressOf = (row: HTMLElement) =>
  row.querySelector<HTMLElement>(".disasm-address")?.textContent ?? "";
const rowAt = (c: HTMLElement, address: number) =>
  insnRows(c).find((r) => addressOf(r) === hex(address)) as HTMLElement;
const hex = (n: number) => n.toString(16).toUpperCase().padStart(16, "0");
/**
 * The toolbar element, found through the one `<select>` it owns (the
 * instruction filter) rather than by its Tailwind classes, so a restyle cannot
 * break it. Scoping matters: the section name appears in the breadcrumb bar as
 * well, so an unscoped `getByText(".text")` finds two.
 */
const toolbar = (c: HTMLElement) => c.firstElementChild?.firstElementChild as HTMLElement;
/** The keyboard-handling pane; `handleKeyDown` is bound here, not on window. */
const pane = () => screen.getByRole("application");

beforeEach(() => {
  ScriptedWorker.posted = [];
  ScriptedWorker.built = 0;
  boomPanel = null;
  ScriptedWorker.withholdXrefs = false;
  buildCFGRuns = 0;
  overviewPublished.length = 0;
  localStorage.clear();
  vi.stubGlobal("Worker", ScriptedWorker);
  // `ErrorBoundary.componentDidCatch` logs the stack, which is the point of it;
  // silenced so the deliberate throws below do not bury the run.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  // The client is a module singleton and its disassembly cache is keyed on
  // (arch, base address, is64) — identical across these tests — so without this
  // the second mount is served from the first and posts nothing.
  disasmWorker.setImage(undefined);
});

describe("the rows", () => {
  it("renders one row per instruction, carrying its address, bytes and mnemonic", async () => {
    const { container } = await mountReady();
    const rows = insnRows(container);
    expect(rows).toHaveLength(INSNS.length);
    for (const [i, insn] of INSNS.entries()) {
      expect(addressOf(rows[i])).toBe(hex(insn.address));
      expect(rows[i].querySelector(".disasm-bytes")?.textContent).toBe(
        Array.from(insn.bytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" "),
      );
      expect(rows[i].querySelector(".disasm-mnemonic")?.textContent).toBe(insn.mnemonic);
    }
    // The operand text reaches the page too, through ColoredOperand's tokeniser.
    expect(rows[1].textContent).toContain("rbp, rsp");
    // 16 digits, because `addrWidth` is `pe.is64 ? 16 : 8`; the only thing
    // between a lined-up address column and a ragged one.
    expect(addressOf(rows[0])).toBe("0000000140001000");
  });

  it("puts a named label above each detected function, and honours a rename", async () => {
    const { container, unmount } = await mountReady();
    const labels = () =>
      Array.from(container.querySelectorAll<HTMLElement>(".func-label")).map(
        (l) => l.textContent ?? "",
      );
    expect(labels()).toHaveLength(2);
    expect(labels()[0]).toContain(FN_A.name);
    expect(labels()[1]).toContain(FN_B.name);
    unmount();

    const renamed = await mountReady({ renames: { [FN_A.address]: "parse_header" } });
    const text = renamed.container.textContent ?? "";
    expect(text).toContain("parse_header");
    expect(text).not.toContain(FN_A.name);
  });

  it("breaks the listing after a `jmp`, but not before a label", async () => {
    // `useDisassemblyRows` inserts a separator after ret/retn/jmp/int3 UNLESS
    // the next instruction begins a function, where the label is the break.
    // Both arms are in this one stream, so the assertion is positional: a count
    // would pass under a rule that broke in both places, or neither.
    const { container } = await mountReady();
    const rows = allRows(container);
    const idx = (address: number) => rows.indexOf(rowAt(container, address));

    const afterJmp = rows[idx(A[4]) + 1];
    expect(afterJmp.className).not.toContain("disasm-row");
    expect(afterJmp.className).not.toContain("func-label");
    expect(afterJmp.textContent).toBe("");

    const afterRet = rows[idx(A[6]) + 1];
    expect(afterRet.className).toContain("func-label");
    expect(afterRet.textContent).toContain(FN_B.name);
  });

  it("offers an xref affordance only where an xref lands", async () => {
    const { container } = await mountReady();
    // The typed xref map is a SECOND worker round trip, posted once the
    // instructions land, so this affordance appears after the rows do.
    await screen.findByText("×1");
    expect(rowAt(container, A[5]).textContent).toContain("×1");
    expect(rowAt(container, A[0]).textContent).not.toContain("×");
  });

  it("marks exactly the cursor row, wherever the cursor is", async () => {
    const { container } = await mountReady({ currentAddress: A[3] });
    const marked = insnRows(container).filter((r) => r.className.includes("bg-blue-900/30"));
    expect(marked).toHaveLength(1);
    expect(addressOf(marked[0])).toBe(hex(A[3]));
  });

  it("draws one jump arrow per branch inside the current function", async () => {
    // JumpArrows is fed the virtualizer's items, so its Y coordinates are
    // arithmetic over ESTIMATED row offsets — not layout, and not asserted here.
    // What IS asserted is the arrow set and each arrow's direction, which is
    // `parseBranchTarget` plus a comparison and which nothing else reaches.
    const { container } = await mountReady();
    const paths = Array.from(container.querySelectorAll("svg path"));
    expect(paths).toHaveLength(2); // the `jne` (forward) and the `jmp` (backward)
    const strokes = paths.map((p) => p.getAttribute("stroke"));
    expect(strokes).toContain("rgb(52 211 153)"); // emerald: forward
    expect(strokes).toContain("rgb(251 146 60)"); // orange: backward
  });
});

/**
 * THE OPERAND TOOLTIP, and the lookup behind it.
 *
 * `InsnRow` resolves every {@link parseOperandTargets} result to a tooltip in
 * four ordered attempts — the IAT map, `pe.strings`, the detected functions,
 * then the containing section. The third of those was a LINEAR SCAN
 * (`functions.find((f) => f.address === addr)`) sitting inside a virtualized
 * row, so it ran once per operand target on every rendered row: a branch or a
 * call target misses the first two attempts by definition, and a target that is
 * not a function at all scanned the whole list before falling through to the
 * section. With `overscan: 50` that is ~150 rows per render, exactly two
 * full-tree renders per cursor move (the `qvv` measurement below), and tens of
 * thousands of functions on a large image.
 *
 * `funcMap` — a `Map<number, DisasmFunction>` keyed on `fn.address` — was
 * ALREADY a prop of this component for two other lookups, so the repair is
 * `funcMap.get(addr)`.
 *
 * WHY THE SPY ROW EXISTS. The behaviour row below cannot see this change at
 * all: a linear scan and a map lookup return the same function, so restoring
 * `.find` leaves it green. The instrument has to be the absence of the scan
 * itself, which is why the second row installs an own-property `.find` on the
 * array handed to the reducer and asserts it is never called — with the tooltip
 * assertion kept beside it as the liveness half, since "never called" is also
 * true of a render that never reached the lookup.
 *
 * The tooltip is a HOVER POPUP behind a 200ms debounce in `ColoredOperand`, not
 * a `title` attribute — when a tooltip exists the title is deliberately
 * `undefined`. So each row advances SHORT of the debounce first: "nothing has
 * appeared yet" is equally true of a timer nobody ticked.
 */
describe("an operand's tooltip", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** The operand target button on `row`, which `ColoredOperand` marks. */
  const opTarget = (c: HTMLElement, address: number) =>
    rowAt(c, address).querySelector<HTMLElement>(".op-target") as HTMLElement;

  /**
   * Hover `btn` and let the debounce elapse, asserting on the way through that
   * it had NOT fired early. Returns the popup's text.
   */
  const hover = (btn: HTMLElement, container: HTMLElement) => {
    vi.useFakeTimers();
    fireEvent.mouseEnter(btn);
    act(() => void vi.advanceTimersByTime(150));
    expect(container.textContent).not.toContain("Function:");
    act(() => void vi.advanceTimersByTime(60));
    return container.textContent ?? "";
  };

  it("names the function an operand targets, and honours a rename", async () => {
    // The `jmp` row: its operand is `FN_A`'s own address, so the function
    // attempt is the one that answers. (The `jne` beside it targets an address
    // mid-function, which falls through to the section attempt.)
    const plain = await mountReady();
    expect(hover(opTarget(plain.container, A[4]), plain.container)).toContain(
      `Function: ${FN_A.name}`,
    );
    plain.unmount();
    vi.useRealTimers();

    const renamed = await mountReady({ renames: { [FN_A.address]: "wound_up" } });
    const text = hover(opTarget(renamed.container, A[4]), renamed.container);
    expect(text).toContain("Function: wound_up");
    expect(text).not.toContain(FN_A.name);
  });

  it("falls through to the containing section where the target is not a function", async () => {
    // The liveness half of the control that deletes the function attempt: this
    // row must keep rendering when that attempt is gone, or "the tooltip
    // disappeared" would say nothing about WHICH attempt answered.
    const { container } = await mountReady();
    vi.useFakeTimers();
    fireEvent.mouseEnter(opTarget(container, A[2]));
    act(() => void vi.advanceTimersByTime(260));
    expect(container.textContent).toContain(".text +0x");
  });

  it("resolves it WITHOUT scanning the function list", async () => {
    // The instrument. `Array.prototype.find` is shadowed by an own property on
    // the very array the reducer holds, so any reader reaching for a linear
    // scan of `state.functions` during the render is recorded. Nothing else on
    // this path calls `.find` on it — `useDisassemblyRows` builds `funcMap`
    // with a `for…of`, and every other reader spreads, maps or sorts.
    const find = vi.fn(function (
      this: DisasmFunction[],
      ...args: Parameters<DisasmFunction[]["find"]>
    ) {
      return Array.prototype.find.apply(this, args);
    });
    const watched = [...FUNCS];
    Object.defineProperty(watched, "find", { value: find, configurable: true, writable: true });

    const { container } = await mountReady({ functions: watched });
    // Liveness: the render really did reach the function attempt and answer
    // from it. Without this the row passes against a listing that never
    // rendered a single operand.
    expect(hover(opTarget(container, A[4]), container)).toContain(`Function: ${FN_A.name}`);
    expect(find).not.toHaveBeenCalled();
  });
});

describe("the toolbar", () => {
  it("states the section, its span and how much was decoded", async () => {
    const { container } = await mountReady();
    const bar = toolbar(container);
    expect(within(bar).getByText(".text")).toBeTruthy();
    expect(within(bar).getByText(`${INSNS.length} instructions`)).toBeTruthy();
    expect(bar.textContent).toContain(
      `VA: 0x${TEXT_VA.toString(16).toUpperCase()} – 0x${TEXT_END.toString(16).toUpperCase()}`,
    );
  });

  it("hides the bytes column when the Bytes toggle is pressed, and restores it", async () => {
    const user = userEvent.setup();
    const { container } = await mountReady();
    expect(container.querySelectorAll(".disasm-bytes")).toHaveLength(INSNS.length);
    await user.click(screen.getByTitle("Toggle bytes column"));
    expect(container.querySelectorAll(".disasm-bytes")).toHaveLength(0);
    await user.click(screen.getByTitle("Toggle bytes column"));
    expect(container.querySelectorAll(".disasm-bytes")).toHaveLength(INSNS.length);
  });

  it("dims the rows an instruction filter excludes, rather than removing them", async () => {
    const user = userEvent.setup();
    const { container } = await mountReady();
    await user.selectOptions(screen.getByRole("combobox"), "jumps");
    // Every row is still on the page — the filter is a highlight, not a hide.
    expect(insnRows(container)).toHaveLength(INSNS.length);
    const lit = insnRows(container).filter((r) => !r.className.includes("opacity-30"));
    expect(lit.map((r) => r.querySelector(".disasm-mnemonic")?.textContent).sort()).toEqual([
      "jmp",
      "jne",
    ]);
  });

  it("enables Graph and Decompile only when the cursor is in a detected function", async () => {
    const disabled = (title: RegExp) => (screen.getByTitle(title) as HTMLButtonElement).disabled;
    const inside = await mountReady();
    expect(disabled(/Toggle graph view/)).toBe(false);
    expect(disabled(/Decompile current function/)).toBe(false);
    inside.unmount();

    // Detection produced nothing: the same bytes, no functions.
    await mountReady({ functions: [] });
    expect(disabled(/Toggle graph view/)).toBe(true);
    expect(disabled(/Decompile current function/)).toBe(true);
  });
});

describe("a data section", () => {
  it("renders decoded data rather than instructions, and asks the worker for nothing", async () => {
    const { container } = await mountReady({ currentAddress: RDATA_VA });
    const bar = toolbar(container);
    expect(within(bar).getByText(".rdata")).toBeTruthy();
    expect(within(bar).getByText("data section")).toBeTruthy();
    expect(insnRows(container)).toHaveLength(0);
    expect(dataRows(container).length).toBeGreaterThan(0);
    expect(addressOf(dataRows(container)[0])).toBe(hex(RDATA_VA));
    // `useDisassemblyRows` returns before posting for a non-executable section,
    // and the xref effect returns for an empty instruction list. So nothing is
    // asked of the worker — and, construction being lazy, none is even built.
    expect(ScriptedWorker.posted).toEqual([]);
    expect(ScriptedWorker.built).toBe(0);
  });
});

/**
 * peek-a-bin-v3uh.2 — a load must not post a whole-section `disassemble` it is
 * about to throw away.
 *
 * On a load `state.functions` is `[]` (RESET), `activeTab` defaults to
 * `"disassembly"` and App mounts the tab in the same commit, so
 * `useDisassemblyRows`' effect fired with an empty function list, posted
 * `disassemble` over the whole section, and posted `hybridDisassemble` again the
 * moment detection landed. The first answer was discarded. It is not free
 * either: `dispatch.ts` deliberately keeps `disassemble` OUT of
 * `WorkerState.x86Sweep` (and `disassembleArm64` out of `arm64Sweep`) because it
 * may be handed a sub-range and would evict the whole-`.text` entry the other
 * three RPCs share — so the throwaway arm is a full Capstone linear pass with no
 * memo, plus a whole `Instruction[]` reply clone, plus a second
 * `buildTypedXrefMap` upload, plus permanent retention of a second
 * 200k-element array in `disasmCache`. And the worker is serial, so the
 * throwaway request was very likely serviced FIRST, with detection queued behind
 * it.
 *
 * The gate is `!ANALYSIS_IN_PROGRESS[state.analysisPhase]` — the ONE
 * declaration, never a hand-written phase chain, which is the defect
 * peek-a-bin-bo3b and peek-a-bin-b3jn both are. The terminal rows below are
 * therefore TABLE-DRIVEN over that record rather than over a list of phase
 * names, so a phase added later that joins on the wrong side fails here as well
 * as at the build.
 *
 * `ScriptedWorker.posted` is the whole instrument: it records every method that
 * crossed `postMessage`, and `built` records whether a thread was constructed at
 * all (the client is lazy, so "posted nothing" and "built nothing" are separate
 * facts and the second is the stronger one).
 */
describe("the load's disassembly request", () => {
  const PHASES = Object.keys(ANALYSIS_IN_PROGRESS) as AnalysisPhase[];
  const IN_FLIGHT = PHASES.filter((p) => ANALYSIS_IN_PROGRESS[p]);
  const SETTLED = PHASES.filter((p) => !ANALYSIS_IN_PROGRESS[p]);

  /** Let every already-scheduled reply and effect land, without asserting on one. */
  const settle = () => act(async () => await new Promise((r) => setTimeout(r, 0)));

  it("posts hybridDisassemble and no `disassemble` once detection has answered", async () => {
    // The ordinary case, and the one the client's own suite asserts the
    // *ordering* half of: `hybridDisassemble` is what fills the sweep slot the
    // xref builds are then served from.
    await mountReady();
    expect(ScriptedWorker.posted).toContain("hybridDisassemble");
    expect(ScriptedWorker.posted).not.toContain("disassemble");
    // AND THE ROUND TRIP IS GONE — the end-to-end half of peek-a-bin-w96b, and
    // the only place the HOOK's side of it is visible. The worker fuses the
    // typed xref map into the reply above and the client seeds its cache with
    // it, but the seed is keyed on the array identity plus the `imageBounds`
    // string — so if `useDisassemblyRows` stops handing `hybridDisassemble` the
    // same two `pe.optionalHeader` numbers its xref effect passes, the seed is
    // written under a key nobody asks for, this row goes red, and the upload
    // happens anyway on top of the fused payload. Nothing in the client's own
    // suite can see that: it is a fact about the two call sites agreeing.
    expect(ScriptedWorker.posted).not.toContain("buildTypedXrefMap");
  });

  it("posts nothing at all while detection is still running, and keeps the spinner", async () => {
    // The state a real load is actually in at first mount. `disassembling` is
    // left TRUE across the early return deliberately, so the pane shows its
    // spinner rather than an empty listing that is about to be replaced.
    mount({ functions: [], analysisPhase: "detecting-functions" });
    await waitFor(() => expect(screen.getByText("Disassembling...")).toBeTruthy());
    await settle();

    expect(ScriptedWorker.posted).not.toContain("disassemble");
    expect(ScriptedWorker.posted).toEqual([]);
    // Construction is lazy, so no thread was even built for the discarded pass.
    expect(ScriptedWorker.built).toBe(0);
    expect(screen.getByText("Disassembling...")).toBeTruthy();
  });

  it("holds the request through EVERY in-flight phase", async () => {
    // Table-driven over the record's `true` side for the same reason the
    // terminal rows below are driven over its `false` side.
    for (const phase of IN_FLIGHT) {
      const r = mount({ functions: [], analysisPhase: phase });
      await settle();
      expect(ScriptedWorker.posted, phase).toEqual([]);
      r.unmount();
      ScriptedWorker.posted = [];
    }
    expect(IN_FLIGHT.length).toBeGreaterThan(0);
  });

  it("still falls back to `disassemble` on every SETTLED phase with no functions", async () => {
    // The four legitimately-no-functions cases, and the reason the gate is the
    // record rather than `phase === "ready"`: a PE32 image detecting nothing and
    // a `"failed"` / `"no-code"` / `"timed-out"` run all have a complete answer
    // of "no functions", and each must still get a linear listing. `"idle"` is
    // on this side too and is included by construction, not by name.
    //
    // `mount()` calls `disasmWorker.setImage`, which clears the client's
    // disassembly cache, so each row posts for itself rather than being served
    // from the row before it.
    for (const phase of SETTLED) {
      const r = mount({ functions: [], analysisPhase: phase });
      await waitFor(() => expect(ScriptedWorker.posted).toContain("disassemble"));
      expect(ScriptedWorker.posted, phase).not.toContain("hybridDisassemble");
      r.unmount();
      ScriptedWorker.posted = [];
      ScriptedWorker.built = 0;
    }
    expect(SETTLED.length).toBeGreaterThan(0);
  });

  it("posts exactly one disassembly for a whole load, when detection lands after the mount", async () => {
    // The sequence end to end, which is the claim: mount while detection is in
    // flight, then let it answer. The old behaviour posted `disassemble` first
    // and `hybridDisassemble` second; the whole point is that the first is gone
    // rather than merely deferred.
    let fire: ((a: AppAction) => void) | null = null;
    function Capture() {
      fire = useAppDispatch();
      return null;
    }
    mount({ functions: [], analysisPhase: "detecting-functions" }, <Capture />);
    await settle();
    expect(ScriptedWorker.posted).toEqual([]);

    await act(async () => {
      fire?.({ type: "SET_FUNCTIONS", functions: FUNCS });
      fire?.({ type: "SET_ANALYSIS_PHASE", phase: "ready" });
    });
    await waitFor(() => expect(ScriptedWorker.posted).toContain("hybridDisassemble"));
    // Fence rather than a second assertion: let the reply and the xref effect it
    // triggers land, so a second disassembly request would have been posted by
    // the time the counts below are read.
    await settle();

    expect(ScriptedWorker.posted.filter((m) => m === "hybridDisassemble")).toHaveLength(1);
    expect(ScriptedWorker.posted).not.toContain("disassemble");
  });
});

/**
 * `useDisassemblyKeyboard`'s `handleKeyDown` is a `useCallback` with a 38-entry
 * dependency array that CLAUDE.md calls "the behaviour", and
 * `hooks/__tests__/disasmHandlerDeps.test.ts` checks that array against the
 * function body over the TypeScript AST. Nothing had ever pressed a key.
 *
 * The two are complementary and neither subsumes the other: the AST guard sees
 * a missing entry whether or not it has an observable effect, and these see a
 * handler that does the wrong thing with a dependency it correctly lists.
 */
describe("the keyboard", () => {
  it("moves the cursor one row per ArrowDown, REPEATEDLY", async () => {
    // Repetition is the assertion. A handler closed over a stale `currentIndex`
    // or a stale `rows` moves once and then stands still — the whole
    // stale-closure class — and one press cannot tell the two apart.
    const user = userEvent.setup();
    const r = await mountReady();
    pane().focus();
    for (const expected of [A[1], A[2], A[3], A[4]]) {
      await user.keyboard("{ArrowDown}");
      expect(r.state().currentAddress).toBe(expected);
    }
    await user.keyboard("{ArrowUp}");
    await user.keyboard("{ArrowUp}");
    expect(r.state().currentAddress).toBe(A[2]);
  });

  it("clamps at the top, and PageDown runs to the end", async () => {
    const user = userEvent.setup();
    const r = await mountReady();
    pane().focus();
    await user.keyboard("{ArrowUp}");
    expect(r.state().currentAddress).toBe(A[0]);
    // PageDown moves 40 rows, well past the end of a 12-row listing — and, as
    // the next test records, it is the ONLY way past a separator.
    await user.keyboard("{PageDown}");
    expect(r.state().currentAddress).toBe(A[INSNS.length - 1]);
  });

  /**
   * A DEFECT, LEFT IN PLACE AND RECORDED (peek-a-bin-a5sw).
   *
   * `rowAddress` answers null for a separator row, and the ArrowDown/ArrowUp
   * branches dispatch only when it does not — with no skip and no retry. So the
   * cursor cannot cross a separator IN EITHER DIRECTION, and because nothing
   * about the state changes, pressing again does exactly the same thing: it is a
   * permanent wall, not a stutter. Measured here: from the `jmp` at A[4],
   * fourteen consecutive ArrowDowns leave the cursor on A[4]; from A[5],
   * five consecutive ArrowUps leave it on A[5].
   *
   * A label row is NOT a wall — `rowAddress` answers a label with its
   * function's address — so this is separators alone. `useDisassemblyRows`
   * inserts one after every ret/retn/jmp/int3 not immediately followed by a
   * function label, which in a real listing is most function tails and every
   * intra-function `jmp`, so everything below the first one is unreachable by
   * arrow key. PageUp/PageDown (40 rows) and clicking still work.
   *
   * FIXED IN 0fbc1e5 (`seekAddressableRow`), one commit after this measurement
   * found it — so this is a plain `it` and it passes. It was written as the
   * repair's specification and is kept as its regression pin: the assertions
   * state what the view must do, and nothing static can see a branch that
   * declines to dispatch (`disasmHandlerDeps.test.ts` walks the dependency
   * array, not the body's early returns).
   */
  it("steps over a separator row instead of stopping dead at it", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[4] }); // the `jmp`
    pane().focus();
    await user.keyboard("{ArrowDown}");
    expect(r.state().currentAddress).toBe(A[5]);
  });

  it("steps back over a separator row as well", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[5] }); // just past the separator
    pane().focus();
    await user.keyboard("{ArrowUp}");
    expect(r.state().currentAddress).toBe(A[4]);
  });

  it("keeps moving across repeated presses, so the cursor cannot wedge", async () => {
    // The companion to the two above, and the reason they cannot both be
    // satisfied by a handler that has merely stopped responding: the ORIGINAL
    // defect was that repeating the key changed nothing, because `currentIndex`
    // never moved and the next press recomputed the same row. Five presses must
    // therefore land five addressable rows away, not one and then nothing.
    const user = userEvent.setup();
    const down = await mountReady({ currentAddress: A[4] });
    pane().focus();
    for (let i = 0; i < 5; i++) await user.keyboard("{ArrowDown}");
    // Five presses is more than the stream has rows below A[4], so this lands on
    // the LAST instruction — a fact about the fixture, not a restatement of the
    // rule under test.
    expect(down.state().currentAddress).toBe(A[A.length - 1]);
    down.unmount();

    const up = await mountReady({ currentAddress: A[5] });
    pane().focus();
    for (let i = 0; i < 5; i++) await user.keyboard("{ArrowUp}");
    expect(up.state().currentAddress).toBe(A[0]);
  });

  it("crosses a LABEL row, which carries its function's address", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[6] }); // the `ret`; next row is FN_B's label
    pane().focus();
    await user.keyboard("{ArrowDown}");
    expect(r.state().currentAddress).toBe(FN_B.address);
    await user.keyboard("{ArrowDown}");
    expect(r.state().currentAddress).toBe(A[8]);
  });

  it("toggles a bookmark on `b`, and the row shows it", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[3] });
    pane().focus();
    await user.keyboard("b");
    expect(r.actions).toContainEqual({ type: "TOGGLE_BOOKMARK" });
    expect(rowAt(r.container, A[3]).textContent).toContain("★");
    await user.keyboard("b");
    expect(rowAt(r.container, A[3]).textContent).not.toContain("★");
  });

  it("does not act on a key while the pane is not focused", async () => {
    // The control for every test above: `handleKeyDown` is bound to the pane,
    // not to window, so a suite that never focused it would pass against a
    // handler that does nothing at all.
    const user = userEvent.setup();
    const r = await mountReady();
    await user.keyboard("{ArrowDown}");
    expect(r.state().currentAddress).toBe(TEXT_VA);
  });
});

/**
 * The four bindings added at peek-a-bin-v3uh.12, all of which had no keyboard
 * route at all before it: walking the function list needed the mouse or the
 * sidebar, nothing reached the top or bottom of a section, and the search
 * cursor advanced only while the search INPUT held focus — which is the one
 * place `handleKeyDown` returns early.
 */
describe("function stepping, Home/End and the search cursor", () => {
  /** SET_ADDRESS actions the view dispatched after `mark`. */
  const movesSince = (r: Mounted, mark: number) =>
    r.actions.slice(mark).filter((a) => a.type === "SET_ADDRESS");

  it("steps to the next and previous function with `]` and `[`", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[1] }); // inside FN_A, not at its head
    pane().focus();
    await user.keyboard("]");
    expect(r.state().currentAddress).toBe(FN_B.address);
    await user.keyboard("[[");
    expect(r.state().currentAddress).toBe(FN_A.address);
  });

  it("does nothing at either end of the function list", async () => {
    // CLAMPING IS A REFUSAL, NOT A RE-DISPATCH. `sortedFuncs[last].address` is
    // below the cursor at every row of the last function but its first, so
    // clamping by dispatching that address would move the cursor BACKWARDS on a
    // forward key — `seekAddressableRow`'s own rule for the arrows, one binding
    // over. The assertion is therefore on the ACTION LOG as well as on the
    // address: a state check alone passes against a handler that re-dispatches
    // the address it already holds, and at A[8] it would not even be the
    // address it already holds.
    const user = userEvent.setup();
    const last = await mountReady({ currentAddress: A[8] }); // FN_B's `ret`
    pane().focus();
    let mark = last.actions.length;
    await user.keyboard("]");
    expect(movesSince(last, mark)).toEqual([]);
    expect(last.state().currentAddress).toBe(A[8]);
    last.unmount();

    const first = await mountReady({ currentAddress: A[1] }); // inside FN_A
    pane().focus();
    mark = first.actions.length;
    await user.keyboard("[[");
    expect(movesSince(first, mark)).toEqual([]);
    expect(first.state().currentAddress).toBe(A[1]);
  });

  it("jumps to the first and last row of the listing with Home and End", async () => {
    const user = userEvent.setup();
    const r = await mountReady({ currentAddress: A[5] });
    pane().focus();
    await user.keyboard("{Home}");
    expect(r.state().currentAddress).toBe(A[0]);
    await user.keyboard("{End}");
    expect(r.state().currentAddress).toBe(A[INSNS.length - 1]);
    // And back, so neither is a one-way key that happened to match the fixture.
    await user.keyboard("{Home}");
    expect(r.state().currentAddress).toBe(A[0]);
  });

  it("dispatches NOTHING for End on the last row", async () => {
    // The discriminating control for going through `seekAddressableRow` rather
    // than indexing `rows[rows.length - 1]` directly: the helper answers null
    // when `to === from`, so the press is a true no-op. A bare index
    // re-dispatches the address the cursor already holds — invisible in
    // `currentAddress`, visible in the action log.
    //
    // HOME HAS NO SUCH CASE AND THAT IS A FACT ABOUT THE ROWS, not an omission:
    // row 0 is FN_A's LABEL, which carries the same address as the instruction
    // below it, and `binarySearchRows` resolves a shared address to the LAST
    // row holding it — so a cursor at A[0] sits at index 1 and Home is a real
    // one-row move. It is asserted positively above.
    //
    // The OTHER half of the helper — skipping an addressless row — is inert at
    // both extremes and cannot be reached from here at all: a separator is the
    // only row `rowAddress` answers null for, and `useDisassemblyRows` emits
    // one only where a further instruction follows, so no listing it builds can
    // begin or end with one. That fallback is covered as arithmetic in
    // `hooks/__tests__/rowSearch.test.ts` instead.
    const user = userEvent.setup();
    const bottom = await mountReady({ currentAddress: A[INSNS.length - 1] });
    pane().focus();
    const mark = bottom.actions.length;
    await user.keyboard("{End}");
    expect(movesSince(bottom, mark)).toEqual([]);
    expect(bottom.state().currentAddress).toBe(A[INSNS.length - 1]);
  });

  /**
   * Open the search box, run `query` through the real debounced input, and hand
   * focus back to the pane — which is what makes F3 reachable at all, since
   * `handleKeyDown` returns above every binding while an INPUT is focused.
   *
   * `fireEvent.change` plus a real 200ms wait rather than `userEvent` under
   * `vi.useFakeTimers()`: both `waitFor` and `userEvent` deadlock against fake
   * timers, and the toolbar debounces the query by 150ms.
   */
  async function searchFor(query: string) {
    const user = userEvent.setup();
    const r = await mountReady();
    pane().focus();
    await user.keyboard("{Control>}f{/Control}");
    const input = await screen.findByPlaceholderText("Search... (/regex/)");
    fireEvent.change(input, { target: { value: query } });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 200));
    });
    pane().focus();
    return { user, r };
  }

  it("advances and reverses the match cursor with F3 and Shift+F3", async () => {
    // `xor eax, eax` appears twice in the stream, at A[3] and A[7].
    const { user, r } = await searchFor("xor");
    expect(r.container.textContent).toContain("1/2");
    const first = r.state().currentAddress;
    expect([A[3], A[7]]).toContain(first);

    await user.keyboard("{F3}");
    const second = r.state().currentAddress;
    expect(second).not.toBe(first);
    expect([A[3], A[7]]).toContain(second);
    expect(r.container.textContent).toContain("2/2");

    // Wraps forward, then walks back — so this is a cursor, not a toggle.
    await user.keyboard("{F3}");
    expect(r.state().currentAddress).toBe(first);
    await user.keyboard("{Shift>}{F3}{/Shift}");
    expect(r.state().currentAddress).toBe(second);
  });

  it("is a no-op when the search found nothing", async () => {
    const { user, r } = await searchFor("nosuchmnemonic");
    expect(r.container.textContent).toContain("No matches");
    const before = r.state().currentAddress;
    const mark = r.actions.length;
    await user.keyboard("{F3}");
    await user.keyboard("{Shift>}{F3}{/Shift}");
    expect(movesSince(r, mark)).toEqual([]);
    expect(r.state().currentAddress).toBe(before);
  });
});

describe("the context menu", () => {
  it("opens on a right-click and names the instruction's own actions", async () => {
    const { container } = await mountReady();
    fireEvent.contextMenu(rowAt(container, A[1]), { clientX: 40, clientY: 80 });
    expect(await screen.findByText("Copy address")).toBeTruthy();
    expect(screen.getByText("Show in Hex")).toBeTruthy();
    expect(screen.getByText("Toggle bookmark")).toBeTruthy();
    // `mov rbp, rsp` is not a branch and nothing refers to it, so neither
    // conditional item is offered.
    expect(screen.queryByText("Follow target")).toBeNull();
    expect(screen.queryByText(/^Show xrefs/)).toBeNull();
    expect(screen.queryByText("Rename function")).toBeNull();
  });

  it("offers Follow target on a branch, and Show xrefs where one lands", async () => {
    const { container } = await mountReady();
    await screen.findByText("×1"); // the xref map is a second round trip
    fireEvent.contextMenu(rowAt(container, A[2]), { clientX: 0, clientY: 0 });
    expect(screen.getByText("Follow target")).toBeTruthy();
    fireEvent.contextMenu(rowAt(container, A[5]), { clientX: 0, clientY: 0 });
    expect(screen.getByText("Show xrefs (1)")).toBeTruthy();
  });

  it("offers Rename function only on a function head", async () => {
    const { container } = await mountReady();
    fireEvent.contextMenu(rowAt(container, A[0]), { clientX: 0, clientY: 0 });
    expect(screen.getByText("Rename function")).toBeTruthy();
    fireEvent.contextMenu(rowAt(container, A[1]), { clientX: 0, clientY: 0 });
    expect(screen.queryByText("Rename function")).toBeNull();
  });

  it("dispatches for the row it was opened on, and closes", async () => {
    const user = userEvent.setup();
    const r = await mountReady();
    fireEvent.contextMenu(rowAt(r.container, A[3]), { clientX: 0, clientY: 0 });
    await user.click(screen.getByText("Show in Hex"));
    expect(r.state().activeTab).toBe("hex");
    expect(r.state().currentAddress).toBe(A[3]);
    expect(screen.queryByText("Copy address")).toBeNull();
  });

  it("copies the address of the row it was opened on", async () => {
    // jsdom has no Clipboard API; `userEvent.setup()` installs its own stub on
    // `navigator`, so the spy goes on after that rather than replacing it —
    // otherwise setup() overwrites the mock and the assertion sees no calls.
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    const { container } = await mountReady();
    fireEvent.contextMenu(rowAt(container, A[5]), { clientX: 0, clientY: 0 });
    await user.click(screen.getByText("Copy address"));
    expect(writeText).toHaveBeenCalledWith(`0x${A[5].toString(16).toUpperCase()}`);
  });

  /**
   * THE PLAIN-HTTP DEPLOYMENT (`peek-a-bin-p0tz`) at the context menu, which is
   * four of the eighteen unguarded sites and the most-used ones.
   *
   * `navigator.clipboard` is `[SecureContext]`: over plain http off localhost
   * the object is absent, so `navigator.clipboard.writeText(...)` threw a
   * TypeError inside the menu item's handler — every copy item in the menu,
   * dead, on the deployment this repo ships an nginx config for. The item now
   * goes through `utils/clipboard.ts` and fails inert.
   *
   * The menu still closing is the second half and not decoration: the
   * `setCtxMenu(null)` sits AFTER the copy in every one of these handlers, so a
   * throw left the menu stuck open over the listing as well as losing the copy.
   * That is also what makes this assertion discriminate at all — see the note
   * in `DecompileView.dom.test.tsx` about a site where nothing follows the copy
   * and `not.toThrow()` is inert.
   *
   * STAND-IN, NOT A BROWSER: the absence is manufactured by deleting the
   * property, after `userEvent.setup()` has installed its own stub.
   */
  it("closes without throwing when there is no clipboard", async () => {
    const user = userEvent.setup();
    const { container } = await mountReady();
    fireEvent.contextMenu(rowAt(container, A[5]), { clientX: 0, clientY: 0 });
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    await user.click(screen.getByText("Copy address"));
    expect(screen.queryByText("Copy address")).toBeNull();
  });

  /**
   * The one site in this panel that has a feedback affordance: double-clicking
   * a row's address copies it and flashes the address green for a second.
   *
   * It used to flash off `writeText(hex).then(...)` with no rejection handler,
   * so on the HTTP deployment it threw before the flash and on a denied
   * permission it would have flashed nothing. `copiedAddr` now carries the
   * OUTCOME (`utils/clipboard.ts`'s `CopyFlash`) rather than just an address,
   * which is what lets the same affordance say "no" — and the type change is
   * what forced both render sites, here and in `CFGView`, to be revisited.
   *
   * BOTH DIRECTIONS, because a flash that is always green and a flash that is
   * always red are equally wrong and a one-directional test sees neither.
   */
  it("flashes the address green on a copy and red on a failed one", async () => {
    userEvent.setup(); // installs the clipboard stub jsdom has not got
    const { container } = await mountReady();
    const addr = () => rowAt(container, A[5]).querySelector<HTMLElement>(".disasm-address");

    fireEvent.doubleClick(addr() as HTMLElement);
    await waitFor(() => expect(addr()?.className).toContain("text-green-400"));
    expect(addr()?.className).not.toContain("text-red-400");
    expect(addr()?.getAttribute("title")).toBeNull();

    // Now take the clipboard away, as a non-secure context does.
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    fireEvent.doubleClick(addr() as HTMLElement);
    await waitFor(() => expect(addr()?.className).toContain("text-red-400"));
    expect(addr()?.className).not.toContain("text-green-400");
    expect(addr()?.getAttribute("title")).toBe(COPY_FAILED_TITLE);
  });

  /**
   * The fourth and last affordance site, and the only one outside this panel's
   * own files: `ColoredOperand` in `components/shared.tsx` flashes an operand's
   * branch target when you double-click it.
   *
   * Reached through the real panel rather than by rendering `ColoredOperand`
   * directly, because the `targets` it flashes come from `parseOperandTargets`
   * over the row's own operand text — a fixture supplying them by hand would be
   * asserting against itself.
   */
  it("flashes an operand's branch target green on a copy and red on a failed one", async () => {
    userEvent.setup();
    const { container } = await mountReady();
    // The `jne` row, whose operand is its target's address.
    const target = () =>
      rowAt(container, A[2]).querySelector<HTMLElement>(
        ".op-target, .text-green-400, .text-red-400",
      );
    const first = target();
    expect(first).toBeTruthy();

    fireEvent.doubleClick(first as HTMLElement);
    await waitFor(() => expect(target()?.className).toContain("text-green-400"));
    expect(target()?.className).not.toContain("text-red-400");

    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    fireEvent.doubleClick(target() as HTMLElement);
    await waitFor(() => expect(target()?.className).toContain("text-red-400"));
    expect(target()?.className).not.toContain("text-green-400");
    expect(target()?.getAttribute("title")).toBe(COPY_FAILED_TITLE);
  });
});

describe("the instruction detail panel", () => {
  const open = async (over: Partial<AppState> = {}) => {
    const user = userEvent.setup();
    const r = await mountReady(over);
    pane().focus();
    expect(screen.queryByText(/Instruction Detail/i)).toBeNull();
    await user.keyboard("i");
    await screen.findByText(/Instruction Detail/i);
    return r;
  };

  it("opens on `i` and describes the instruction under the cursor", async () => {
    const r = await open({ currentAddress: A[1] });
    expect(r.container.textContent).toContain("48 89 e5");
  });

  /**
   * THE RENDER STEP OF peek-a-bin-56q, which had never been executed.
   *
   * `inferSignature` returns null for anything but x86, because
   * `FunctionSignature` cannot say "unknown" and the parameter count is the
   * false half. Before that fix every A64 function was reported here as
   * `fastcall, 0 params`, and this panel is the surface it reached. The two
   * mounts differ in the COFF machine word and in NOTHING else — same fixture,
   * same bytes, same scripted instruction stream — which is `peek-a-bin-8ru3`'s
   * method, for its reason: it isolates the one input under test.
   */
  const CONVENTIONS = ["cdecl", "stdcall", "fastcall", "thiscall", "aapcs"];

  it("names the calling convention for an x86 image", async () => {
    const r = await open();
    expect(r.container.textContent).toMatch(/\| (cdecl|stdcall|fastcall|thiscall), \d+ param/);
  });

  it("says NOTHING about a calling convention for an ARM64 image", async () => {
    const r = await open({ peFile: ARM64 });
    const text = r.container.textContent ?? "";
    for (const c of CONVENTIONS) expect(text).not.toContain(c);
    expect(text).not.toMatch(/param/);
    // The control that the panel is open and WOULD have shown one: the same
    // instruction is described either way.
    expect(text).toContain("55");
  });
});

/**
 * PART TWO — `peek-a-bin-qvv`'s render count, RE-TAKEN AGAINST THE REAL VIEW.
 *
 * `hooks/__tests__/contextRenderCount.dom.test.tsx` settled the count half of
 * that bead at **two full-tree renders per arrow key**, and said in its own
 * docstring that it was a HARNESS — a transcription of `DisassemblyView`'s
 * cursor effect — because "nothing has yet driven the populated panel a render
 * count would have to be counted over". This file drives it, so the number can
 * be taken again with the real component doing the dispatching.
 *
 * The instrument is the same and is the only part that can be: `DisassemblyView`
 * cannot be made to count its own renders without editing it, so what is counted
 * is a set of BYSTANDERS mounted beside it under the same providers. That is
 * exactly the bead's claim anyway — "every dispatched action re-renders every
 * consumer of the context" — and the bystanders are consumers with no props, no
 * state and no effects of their own, so every render of one is a context change
 * and nothing else.
 */
type Counts = Record<string, number>;

function Bystander({ counts, name }: { counts: Counts; name: string }) {
  const state = useAppState();
  const n = useRef(0);
  n.current += 1;
  counts[name] = n.current;
  return <span>{state.activeTab}</span>;
}

/** Stands in for `StatusBar`, the only reader of the two cursor fields. */
function StatusBarish({ counts }: { counts: Counts }) {
  const state = useAppState();
  const n = useRef(0);
  n.current += 1;
  counts.StatusBar = n.current;
  return (
    <span>{`${state.currentInstruction?.size ?? "-"}/${state.currentBlock?.startAddr ?? "-"}`}</span>
  );
}

describe("renders per cursor move, against the real DisassemblyView", () => {
  /** Mount, then let every effect the load kicks off settle before counting. */
  async function settled(counts: Counts) {
    const r = await mountReady(
      {},
      <>
        <StatusBarish counts={counts} />
        <Bystander counts={counts} name="HexView" />
        <Bystander counts={counts} name="Sidebar" />
      </>,
    );
    // The typed xref map rebuilds `rows`, so a baseline taken before it lands
    // would charge the arrow key for it. It USED to be a second worker round
    // trip and this line waited on that RPC; since peek-a-bin-w96b it rides
    // back on `hybridDisassemble` and is served to the xref effect out of the
    // client's cache, so the disassembly reply is the thing to wait for and the
    // settles below carry the cache-served effect. Still keyed on the RPC
    // rather than on the `×N` affordance it produces: keying on the affordance
    // couples this measurement to a rendering detail, and a control that
    // removed the affordance reddened these tests for a reason that has nothing
    // to do with render counts.
    await waitFor(() => expect(ScriptedWorker.posted).toContain("hybridDisassemble"));
    await act(async () => {
      await new Promise((res) => setTimeout(res, 0));
    });
    await act(async () => {
      await new Promise((res) => setTimeout(res, 0));
    });
    return r;
  }

  it("costs TWO full-tree renders per arrow key — the harness number, confirmed", async () => {
    const user = userEvent.setup();
    const counts: Counts = {};
    const r = await settled(counts);
    pane().focus();

    const before = { ...counts };
    const beforeActions = r.actions.length;
    await user.keyboard("{ArrowDown}");

    const perKey = Object.fromEntries(
      Object.entries(counts).map(([k, v]) => [k, v - (before[k] ?? 0)]),
    );
    expect(perKey).toEqual({ StatusBar: 2, HexView: 2, Sidebar: 2 });
    // And the second render is the cursor effect's, exactly as the harness
    // transcribed it: one SET_ADDRESS from the key, then the two fields the
    // status bar wants, batched into one further pass.
    expect(r.actions.slice(beforeActions).map((a) => a.type)).toEqual([
      "SET_ADDRESS",
      "SET_CURRENT_INSTRUCTION",
      "SET_CURRENT_BLOCK",
    ]);
  });

  it("re-renders consumers that read neither cursor field", async () => {
    // The bead's point, and the thing a count of DisassemblyView alone would
    // miss: `HexView` and `Sidebar` here read only `activeTab`, and both wake up
    // twice for a keystroke that changed only the cursor.
    const user = userEvent.setup();
    const counts: Counts = {};
    await settled(counts);
    pane().focus();
    const before = { ...counts };
    await user.keyboard("{ArrowDown}");
    expect(counts.HexView - before.HexView).toBe(2);
    expect(counts.Sidebar - before.Sidebar).toBe(2);
  });

  it("charges nothing for a key the view ignores", async () => {
    // The control: without it, "2 renders per ArrowDown" could be two renders
    // per *keystroke of any kind*, which would be a different finding.
    const user = userEvent.setup();
    const counts: Counts = {};
    await settled(counts);
    pane().focus();
    const before = { ...counts };
    await user.keyboard("{F9}");
    expect(counts.HexView - before.HexView).toBe(0);
  });
});

describe("a throw in a side panel does not take the listing", () => {
  /**
   * `peek-a-bin-p0qw`'s BLAST-RADIUS ARGUMENT ONE LEVEL DOWN (`peek-a-bin-t23y`).
   *
   * The bead lists the AI chat panel and the bottom panel container beside
   * `Sidebar` and the dialogs as regions whose throw is a blank page. MEASURED,
   * THAT IS NOT TRUE OF THESE TWO and the correction is worth keeping: both
   * mount inside `DisassemblyView`, which `App` already wraps in a per-tab
   * boundary — so a throw here replaced the DISASSEMBLY PANE and the other
   * eight tabs carried on. The page was never blank.
   *
   * What it did cost was everything the pane holds: the virtualized listing,
   * the toolbar, the jump arrows, the minimap, the graph and the decompile
   * panel — all replaced to report a fault in a panel the user opened beside
   * them and can close. That is exactly the trade `peek-a-bin-p0qw` refused one
   * level up, so these two get their own boundaries and the assertion is the
   * same one: the neighbour is still on screen.
   *
   * `DecompileView` and `CFGView` deliberately get NO boundary of their own.
   * They are not consulted beside the listing, they ARE the pane in the mode
   * that shows them, so the pane's boundary is already the right blast radius.
   */
  it("keeps the listing when the Detail panel throws", async () => {
    const user = userEvent.setup();
    const { container } = await mountReady({ currentAddress: A[1] });
    const before = insnRows(container).length;
    expect(before).toBe(INSNS.length);

    boomPanel = "detail";
    pane().focus();
    await user.keyboard("i");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Panels failed");
    expect(alert.textContent).toContain("detail panel exploded");

    // THE POINT: every instruction row is still rendered, and so is the
    // toolbar. Under the pane-level boundary alone all of this was replaced.
    expect(insnRows(container)).toHaveLength(before);
    expect(toolbar(container)).toBeTruthy();
  });

  it("keeps the listing when the chat panel throws", async () => {
    const user = userEvent.setup();
    const { container } = await mountReady();
    const before = insnRows(container).length;

    boomPanel = "chat";
    await act(async () => {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-chat"));
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Chat failed");
    expect(insnRows(container)).toHaveLength(before);

    // And the region recovers on its own, without touching the listing: the
    // chat column is the only thing that re-renders.
    boomPanel = null;
    await user.click(within(alert).getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(insnRows(container)).toHaveLength(before);
  });

  it("renders no fallback while both panels are healthy", async () => {
    // The liveness half: both assertions above are about a red row, and a
    // boundary rendering its fallback unconditionally would satisfy them.
    const user = userEvent.setup();
    const { container } = await mountReady({ currentAddress: A[1] });
    pane().focus();
    await user.keyboard("i");
    await screen.findByText(/Instruction Detail/i);
    await act(async () => {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-chat"));
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(insnRows(container)).toHaveLength(INSNS.length);
  });
});

describe("graph mode: one CFG, one layout, one font size", () => {
  /**
   * Mount straight into graph mode and wait for the graph to be drawn.
   *
   * `viewMode` initialises from `peek-a-bin:view-mode`, so this is the mount the
   * user gets when they last left the panel in graph mode — and it means the
   * layout is built during the ordinary load rather than after a toggle.
   */
  async function mountGraph(fontSize?: number) {
    localStorage.setItem("peek-a-bin:view-mode", "graph");
    if (fontSize !== undefined) localStorage.setItem("peek-a-bin:font-size", String(fontSize));
    const r = mount();
    await waitFor(() => expect(r.container.querySelector(".cfg-block")).toBeTruthy());
    return r;
  }

  /** Each drawn block's box, from the inline styles `CFGBlock` writes. */
  const drawnBoxes = (c: HTMLElement) =>
    Array.from(c.querySelectorAll<HTMLElement>(".cfg-block")).map((b) => ({
      left: b.style.left,
      top: b.style.top,
      width: b.style.width,
      height: b.style.height,
    }));

  /** The same four numbers, as the overview context was told them. */
  const publishedBoxes = (d: GraphOverviewData) =>
    d.blocks.map((b) => ({
      left: `${b.x}px`,
      top: `${b.y}px`,
      width: `${b.w}px`,
      height: `${b.h}px`,
    }));

  /**
   * THE BUG-FIX ROW, and it is parameterised for a reason.
   *
   * `layoutCFG(blocks, fontSize = 12)` sizes every node from
   * `getCfgLayout(fontSize)`. `CFGView` passed the real `loadFontSize()`; the
   * minimap memo in `DisassemblyView` PASSED NOTHING. So at any non-default
   * `--mono-font-size` the geometry published to the sidebar overview described
   * a graph the panel was not drawing, and the pan/viewport arithmetic computed
   * against it was arithmetic over the wrong boxes.
   *
   * ASKED AT 12 ALONE THIS TEST IS WORTHLESS: `layoutCFG(cfg)` and
   * `layoutCFG(cfg, 12)` are the same call, so the defect and the fix agree
   * there. Restoring the defect (drop the second argument in
   * `DisassemblyView`'s `graphLayout` memo) leaves the 12 row green and reddens
   * the 16 row — which is the negative control, and the reason both sizes are
   * in the table.
   */
  for (const fontSize of [12, 16]) {
    it(`publishes the geometry the graph actually draws (font size ${fontSize})`, async () => {
      const { container } = await mountGraph(fontSize);

      // THE BLOCKS AND THE PUBLISH ARE TWO DIFFERENT SIGNALS. `mountGraph`
      // waits for a `.cfg-block` to exist; the overview publish is an effect
      // that can still be a frame behind it, and under load it was — this row
      // failed `expected 2 to be 1`-style at fd35678 with three sibling agents
      // running, and passed alone (peek-a-bin-dps4). So wait on the thing being
      // asserted rather than on a proxy for it.
      //
      // Waiting on the COUNTS deliberately, not on the boxes: the box equality
      // below is the actual claim and must not be pre-waited into a tautology,
      // and neither liveness assertion is weakened — `> 1` still says the
      // fixture drew a real graph, and the BLOCK_WIDTH set still says the
      // layout was sized at the font size under test.
      await waitFor(() => {
        expect(overviewPublished.length).toBeGreaterThan(0);
        expect(lastOverview().blocks.length).toBe(
          container.querySelectorAll(".cfg-block").length,
        );
      });
      const published = lastOverview();

      // Liveness, twice over. A green comparison between two empty lists would
      // say nothing, and neither would one taken at a font size the layout
      // ignored: `BLOCK_WIDTH` is `round(320 * fontSize / 12)`, so this pins
      // that the layout really was sized at the size under test.
      expect(published.blocks.length).toBeGreaterThan(1);
      expect(new Set(published.blocks.map((b) => b.w))).toEqual(
        new Set([getCfgLayout(fontSize).BLOCK_WIDTH]),
      );

      expect(drawnBoxes(container)).toEqual(publishedBoxes(published));
    });
  }

  it("lays a larger font out larger, so the two rows above are not the same numbers", async () => {
    // The other half of the liveness argument: without this, both rows could be
    // agreeing about a layout that never looked at the font size at all.
    const small = await mountGraph(12);
    const smallBoxes = drawnBoxes(small.container);
    small.unmount();
    overviewPublished.length = 0;

    const large = await mountGraph(16);
    expect(drawnBoxes(large.container)).not.toEqual(smallBoxes);
  });

  /**
   * THE COUNT ROW. `buildCFG` has one call site now; it had four.
   *
   * THE THREE ARROW PRESSES ARE LOAD-BEARING. `buildCFGForNav` is built lazily
   * inside the arrow/Tab handler, so it ran once per keypress and a mount-only
   * count cannot see it. Reverting it to its own `buildCFG` is the negative
   * control and adds exactly three.
   *
   * XREFS ARE WITHHELD SO THE NUMBER IS A NUMBER. `instructions` and
   * `typedXrefMap` land from two separate worker round trips, so with both in
   * play the shared memo's inputs change once or twice depending on whether the
   * two resolutions batch — measured at 2 running this file alone and 1 under a
   * full `--dir src` run, and worse, the second change can land DURING the
   * keypresses and be miscounted as a keypress build. Holding the xref pass
   * open leaves exactly one input change, so both readings below are exact.
   *
   * Pre-fix, the same mount built the CFG twice at once (the minimap memo and
   * `CFGView`'s own; the `loops` memo declines while the xref map is empty) and
   * once more per press: 1 → 2, and 1 → 5 across the three presses.
   */
  it("builds the CFG once per input change and never on a keypress", async () => {
    ScriptedWorker.withholdXrefs = true;
    const r = await mountGraph();
    await waitFor(() => expect(lastOverview().blocks.length).toBeGreaterThan(1));
    expect(buildCFGRuns).toBe(1);

    // In graph mode there are TWO `role="application"` elements — the pane and
    // the CFG viewport inside it — so the shared `pane()` helper is ambiguous
    // here. `handleKeyDown` is bound to the outer one.
    const user = userEvent.setup();
    const before = r.state().currentAddress;
    screen.getByRole("application", { name: "Disassembly viewer" }).focus();
    await user.keyboard("{ArrowDown}{ArrowDown}{ArrowUp}");

    // Liveness: the presses reached the graph handler. Without this the row
    // passes whenever the keystrokes are absorbed by something else.
    expect(r.state().currentAddress).not.toBe(before);
    expect(buildCFGRuns).toBe(1);
  });

  it("keeps drawing the graph before the xref pass lands", async () => {
    /**
     * THE GUARD THAT MUST NOT BE INHERITED. The `loops` memo declines while
     * `typedXrefMap` is empty — that is the linear view's behaviour and it
     * stays. The shared `cfg` memo must NOT, because `CFGView` is handed a
     * layout now: with the xref guard on the shared build, graph mode renders
     * nothing in the window between the disassembly arriving and
     * `buildAllXrefs` finishing.
     */
    ScriptedWorker.withholdXrefs = true;
    localStorage.setItem("peek-a-bin:view-mode", "graph");
    const r = mount();
    await waitFor(() => expect(r.container.querySelector(".cfg-block")).toBeTruthy());
    expect(lastOverview().blocks.length).toBeGreaterThan(1);
    // ...and the linear view's loop markers still decline, which is the half of
    // the old condition that had to stay behind.
    expect(r.state().functions.length).toBeGreaterThan(0);
  });
});
