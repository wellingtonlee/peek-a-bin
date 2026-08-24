// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useCallback, useReducer, useRef } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DisasmFunction, Instruction, Xref } from "../../disasm/types";
import type { AppAction, AppState } from "../../hooks/usePEFile";
import { appReducer, initialState, useAppState } from "../../hooks/usePEFile";
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
      case "hybridDisassemble":
        result = INSNS;
        break;
      case "buildTypedXrefMap":
        result = XREFS;
        break;
      default:
        result = null;
    }
    setTimeout(() => this.onmessage?.({ data: { id: msg.id, result } }), 0);
  }
  terminate() {}
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
        <DisassemblyView />
        {extra}
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
  vi.stubGlobal("Worker", ScriptedWorker);
});

afterEach(() => {
  vi.unstubAllGlobals();
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
 * `useDisassemblyKeyboard`'s `handleKeyDown` is a `useCallback` with a 37-entry
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
    // The typed xref map is a second worker round trip that rebuilds `rows`, so
    // a baseline taken before it lands would charge the arrow key for it. Waited
    // for through the RPC rather than through the `×N` affordance it produces:
    // keying on the affordance couples this measurement to a rendering detail,
    // and a control that removed the affordance reddened these tests for a
    // reason that has nothing to do with render counts.
    await waitFor(() => expect(ScriptedWorker.posted).toContain("buildTypedXrefMap"));
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
