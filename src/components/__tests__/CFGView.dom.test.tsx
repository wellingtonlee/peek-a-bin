// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { buildCFG, type CFGEdge, type LayoutBlock, layoutCFG } from "../../disasm/cfg";
import type { DisasmFunction, Instruction } from "../../disasm/types";
import type { AppState } from "../../hooks/usePEFile";
import { loadFontSize } from "../../llm/settings";
import { CFGView } from "../CFGView";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * The control-flow graph, as a DOM tree rather than as a picture.
 *
 * WHAT JSDOM CAN AND CANNOT SETTLE HERE, because the split is unusually
 * favourable and it would be easy to overclaim in either direction.
 *
 * It CAN settle the graph's structure. `layoutCFG` runs dagre, and dagre is
 * pure arithmetic — it never measures the DOM, taking its node sizes from
 * `getCfgLayout(fontSize)` instead. So the block set, the edge set, each edge's
 * type, and the coordinates dagre assigns are all exactly what a browser would
 * get. A block's `top`/`left` are written as inline styles from those numbers,
 * so "the entry block is laid out above its successors" is a real, checkable
 * claim about dagre's output and not a claim about rendering.
 *
 * It CANNOT settle anything about appearance. Whether the SVG draws, whether an
 * edge visually connects the boxes it names, whether two blocks overlap on
 * screen, whether the arrowheads point anywhere, whether the graph fits the
 * viewport — none of that is reachable, and jsdom renders no SVG at all. The
 * pan/zoom auto-centring is worse than unreachable: it reads
 * `containerRef.current.clientWidth`, which is a constant 0 here, so the
 * centring arithmetic runs on a viewport that does not exist. Tests below touch
 * pan/zoom only where the component's own callback contract can be checked
 * without believing the numbers.
 *
 * THE LOOP QUESTION IS NOT ASKED HERE. CLAUDE.md's "there is exactly one notion
 * of loop: dominance" gotcha, and the triangle-vs-diamond fixtures that pin it,
 * belong to `disasm/__tests__/cfg.test.ts`, which tests `buildCFG` directly and
 * needs no renderer. Repeating it here would test dagre's input twice and this
 * component not at all.
 */

const B = IMAGE_BASE + 0x1000;

const insn = (address: number, mnemonic: string, opStr: string, size = 2): Instruction => ({
  address,
  mnemonic,
  opStr,
  size,
  bytes: new Uint8Array(size),
});

/**
 * A diamond: `test/jne` at the entry, two arms, and a join. Four blocks and
 * four edges, one of each edge type the renderer colours differently — the
 * smallest shape that exercises the whole legend.
 */
const DIAMOND: Instruction[] = [
  insn(B + 0, "test", "eax, eax"),
  insn(B + 2, "jne", `0x${(B + 8).toString(16)}`),
  insn(B + 4, "mov", "eax, 1"),
  insn(B + 6, "jmp", `0x${(B + 10).toString(16)}`),
  insn(B + 8, "mov", "eax, 2"),
  insn(B + 10, "ret", ""),
];

const FUNC: DisasmFunction = { name: "sub_401000", address: B, size: 12 };

/**
 * THE LAYOUT IS NOW A PROP, and that is the component's contract.
 *
 * `CFGView` used to take `func`/`instructions`/`typedXrefMap`/`jumpTables` and
 * run `buildCFG` + `layoutCFG` itself, while `DisassemblyView` ran the same pair
 * again for the sidebar minimap — with no font size, which is the defect
 * `DisassemblyPanel.dom.test.tsx` pins. The parent now owns both passes.
 *
 * So the default here reproduces exactly what the component used to compute for
 * itself, keeping every structural assertion below a claim about dagre's real
 * output rather than about numbers a test invented. The scripted-layout case in
 * "CFGView layout prop" is the one that shows the prop is actually read.
 */
const DIAMOND_LAYOUT = layoutCFG(buildCFG(FUNC, DIAMOND, new Map()), loadFontSize());

/** `EDGE_COLORS` in CFGView.tsx, by edge type. */
const COLOR = { fallthrough: "#4ade80", branch: "#fb923c", jump: "#ef4444" } as const;

/** The border colour `CFGBlock` gives the block holding the current address. */
const CURRENT_BORDER = "#2563eb";

/**
 * jsdom re-serialises a hex colour in an inline `style` as `rgb(r, g, b)`, so a
 * test cannot compare against the source's own spelling directly. Converting
 * here keeps the constant above named rather than hard-coding a triple that
 * would no longer resemble the code it came from. (SVG *attributes* are not
 * touched by this — `stroke="#4ade80"` comes back verbatim, which is why the
 * edge tests compare hex and these do not.)
 */
function rgb(hex: string): string {
  const n = Number.parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
}

type Props = Parameters<typeof CFGView>[0];

function renderCFG(over: Partial<Props> = {}, state: Partial<AppState> = {}) {
  const spies = {
    onNavigate: vi.fn(),
    onAddressClick: vi.fn(),
    onDoubleClickAddr: vi.fn(),
    onContextMenu: vi.fn(),
    onRegClick: vi.fn(),
    onEditComment: vi.fn(),
    onPanChange: vi.fn(),
    onZoomChange: vi.fn(),
    onToggleCollapse: vi.fn(),
  };
  const dispatch = vi.fn();
  const { container } = render(
    <AppHarness
      state={stateWithPE(harnessPE(), { currentAddress: B, ...state })}
      dispatch={dispatch}
    >
      <CFGView
        layout={DIAMOND_LAYOUT}
        funcAddress={FUNC.address}
        highlightRegs={null}
        copiedAddr={null}
        editingComment={null}
        pan={{ x: 0, y: 0 }}
        zoom={1}
        collapsedBlocks={new Set()}
        restorePanZoom={undefined}
        reCenterTrigger={0}
        searchMatches={new Set()}
        currentSearchMatch={-1}
        {...spies}
        {...over}
      />
    </AppHarness>,
  );
  return { ...spies, dispatch, container, user: userEvent.setup() };
}

/** The block boxes, identified by the `N insn` counter in each header. */
function blockHeaders(): HTMLElement[] {
  return screen.getAllByRole("button").filter((b) => /\d+ insn$/.test(b.textContent ?? ""));
}

/** Each block's positioned wrapper, with dagre's coordinates as inline styles. */
function blockBoxes(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(".cfg-block"));
}

/** The blocks drawn as "current", by the border colour `CFGBlock` sets. */
const currentBoxes = (container: HTMLElement) =>
  blockBoxes(container).filter((b) => b.style.border.includes(rgb(CURRENT_BORDER)));

const edgePaths = (container: HTMLElement) =>
  Array.from(container.querySelectorAll("svg > path")) as SVGPathElement[];

/**
 * Each edge as `sourceBlockAddress -> strokeColour`.
 *
 * A COUNT OF COLOURS IS NOT ENOUGH, and a negative control is what showed it:
 * with one branch edge and one jump edge in the fixture, swapping the two
 * entries of `EDGE_COLORS` leaves both counts at 1 and the test green. So each
 * path is attributed to the block it leaves, by matching the `M x,y` its `d`
 * begins with against the blocks' own bottom edges. Those coordinates are
 * dagre's — real arithmetic, not a browser measurement — and the `<svg>` is
 * shifted by its own inline `top`, which is read from the element rather than
 * assumed so a change to the graph's padding does not silently break the
 * attribution.
 */
function edgesBySource(container: HTMLElement): Record<string, string[]> {
  const svg = container.querySelector("svg") as SVGSVGElement;
  // Only the vertical offset is needed: a block is identified by the bottom
  // edge its outgoing edges start from.
  const dy = -Number.parseFloat(svg.style.top);
  const blocks = blockBoxes(container).map((b) => ({
    addr: (b.firstElementChild?.firstElementChild?.textContent ?? "").replace("▼ ", ""),
    bottom: Number.parseFloat(b.style.top) + Number.parseFloat(b.style.height),
  }));
  const out: Record<string, string[]> = {};
  for (const p of edgePaths(container)) {
    const m = /^M([\d.-]+),([\d.-]+)/.exec(p.getAttribute("d") ?? "");
    if (!m) throw new Error(`unparsed edge path: ${p.getAttribute("d")}`);
    const y = Number.parseFloat(m[2]) - dy;
    const from = blocks.find((b) => Math.abs(b.bottom - y) < 1);
    if (!from) throw new Error(`edge at y=${y} leaves no block`);
    const list = out[from.addr] ?? [];
    list.push(p.getAttribute("stroke") ?? "");
    out[from.addr] = list;
  }
  for (const v of Object.values(out)) v.sort();
  return out;
}

describe("CFGView graph structure", () => {
  it("draws one box per basic block", () => {
    renderCFG();
    // test/jne | mov;jmp | mov | ret — the diamond's four blocks.
    expect(blockHeaders()).toHaveLength(4);
  });

  it("labels each block with its start address and instruction count", () => {
    renderCFG();
    // Read as the two spans the header is built from. Concatenated they run
    // together — "0x1400010002 insn" — and a regex over that text captures the
    // address's own trailing digits as part of the count.
    const rows = blockHeaders().map((h) => ({
      addr: h.firstElementChild?.textContent ?? "",
      count: Number(/^(\d+) insn$/.exec(h.lastElementChild?.textContent ?? "")?.[1]),
    }));
    expect(rows.map((r) => r.addr)).toContain(`▼ 0x${(B + 0).toString(16).toUpperCase()}`);
    expect(rows.map((r) => r.addr)).toContain(`▼ 0x${(B + 8).toString(16).toUpperCase()}`);
    // The counts sum to the instruction stream: no instruction is dropped
    // between blocks and none is rendered twice.
    expect(rows.every((r) => Number.isFinite(r.count))).toBe(true);
    expect(rows.reduce((a, r) => a + r.count, 0)).toBe(DIAMOND.length);
  });

  it("renders every instruction, in address order within its block", () => {
    const { container } = renderCFG();
    const body = container.textContent ?? "";
    for (const i of DIAMOND) expect(body).toContain(i.mnemonic);
    // The entry block holds the compare before the branch it feeds.
    const entry = blockHeaders()[0].parentElement?.textContent ?? "";
    expect(entry.indexOf("test")).toBeLessThan(entry.indexOf("jne"));
  });

  it("draws one edge per CFG edge, coloured by type, leaving the right block", () => {
    const { container } = renderCFG();
    expect(edgePaths(container)).toHaveLength(4);
    const hex = (n: number) => `0x${n.toString(16).toUpperCase()}`;
    // The entry's `jne` produces the taken branch and its fallthrough; the
    // first arm ends in `jmp`; the second falls into the join. Attributing each
    // edge to its source is what makes a swapped colour table fail here —
    // the bare counts survive it, which a negative control demonstrated.
    expect(edgesBySource(container)).toEqual({
      [hex(B + 0)]: [COLOR.fallthrough, COLOR.branch].sort(),
      [hex(B + 4)]: [COLOR.jump],
      [hex(B + 8)]: [COLOR.fallthrough],
    });
  });

  it("points each edge at the arrowhead marker matching its colour", () => {
    const { container } = renderCFG();
    const byColor: Record<string, string> = {
      [COLOR.fallthrough]: "url(#cfg-arrow-green)",
      [COLOR.branch]: "url(#cfg-arrow-orange)",
      [COLOR.jump]: "url(#cfg-arrow-red)",
    };
    for (const p of edgePaths(container)) {
      // A marker id naming a colour the stroke does not use is silent in every
      // other instrument — and in a browser it renders an arrowhead in the
      // wrong colour rather than failing.
      expect(p.getAttribute("marker-end")).toBe(byColor[p.getAttribute("stroke") as string]);
    }
    for (const id of ["cfg-arrow-green", "cfg-arrow-orange", "cfg-arrow-red"]) {
      expect(container.querySelector(`#${id}`)).not.toBeNull();
    }
  });

  it("lays the entry block above the blocks it reaches", () => {
    const { container } = renderCFG();
    const tops = blockBoxes(container).map((b) => Number.parseFloat(b.style.top));
    // dagre's own output, not a browser's: node sizes come from the font size,
    // so these coordinates are the same ones a browser would be given. What is
    // NOT claimed is that anything appears at them.
    expect(tops).toHaveLength(4);
    expect(Math.min(...tops)).toBe(tops[0]);
    expect(new Set(tops).size).toBeGreaterThan(1);
  });
});

describe("CFGView layout prop", () => {
  /**
   * A layout dagre would never produce: two blocks at coordinates that are round
   * numbers, in an order that is not the block order, with widths and heights
   * nothing in `getCfgLayout` would pick. If the component went back to building
   * its own graph these would all be dagre's numbers instead, so this is the
   * assertion that the prop — rather than `func`/`instructions` — is what draws
   * the page.
   */
  const scripted: { blocks: LayoutBlock[]; edges: CFGEdge[] } = {
    blocks: [
      {
        id: 0,
        startAddr: B,
        endAddr: B + 4,
        insns: [insn(B, "nop", "")],
        succs: [1],
        preds: [],
        x: 700,
        y: 300,
        w: 111,
        h: 77,
      },
      {
        id: 1,
        startAddr: B + 4,
        endAddr: B + 6,
        insns: [insn(B + 4, "hlt", "")],
        succs: [],
        preds: [0],
        x: 40,
        y: 900,
        w: 222,
        h: 33,
      },
    ],
    edges: [{ from: 0, to: 1, type: "jump" }],
  };

  it("draws the blocks the layout prop names, at the layout prop's coordinates", () => {
    const { container } = renderCFG({ layout: scripted });
    const boxes = blockBoxes(container);
    expect(boxes).toHaveLength(2);
    // Geometry, verbatim. Anything the component recomputed would disagree:
    // dagre never assigns a 111px node in a 320px-wide layout.
    expect(
      boxes.map((b) => ({
        left: b.style.left,
        top: b.style.top,
        width: b.style.width,
        height: b.style.height,
      })),
    ).toEqual([
      { left: "700px", top: "300px", width: "111px", height: "77px" },
      { left: "40px", top: "900px", width: "222px", height: "33px" },
    ]);
    // ...and the content, so this is not passing on an empty pair of divs.
    const text = container.textContent ?? "";
    expect(text).toContain("nop");
    expect(text).toContain("hlt");
    // The DIAMOND fixture's own mnemonics are absent: nothing here decoded it.
    expect(text).not.toContain("jne");
  });

  it("draws one edge per edge the layout prop names", () => {
    const { container } = renderCFG({ layout: scripted });
    const paths = edgePaths(container);
    expect(paths).toHaveLength(1);
    expect(paths[0].getAttribute("stroke")).toBe(COLOR.jump);
  });
});

describe("CFGView current block", () => {
  it("highlights the block holding the current address, and only it", () => {
    const { container } = renderCFG({}, { currentAddress: B + 8 });
    const highlighted = currentBoxes(container);
    expect(highlighted).toHaveLength(1);
    // 0x…08 is the `jne` target, i.e. the second arm.
    expect(highlighted[0].textContent).toContain((B + 8).toString(16).toUpperCase());
  });

  it("moves the highlight when the current address moves", () => {
    const { container } = renderCFG({}, { currentAddress: B + 10 });
    const highlighted = currentBoxes(container);
    expect(highlighted).toHaveLength(1);
    expect(highlighted[0].textContent).toContain("ret");
  });
});

describe("CFGView collapsing", () => {
  it("hides a collapsed block's instructions but keeps its header", () => {
    const entryId = 0;
    renderCFG({ collapsedBlocks: new Set([entryId]) });
    const headers = blockHeaders();
    expect(headers).toHaveLength(4);
    // The collapsed one flips its disclosure marker and drops its rows.
    const collapsed = headers.filter((h) => h.textContent?.startsWith("▶"));
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].getAttribute("aria-expanded")).toBe("false");
    expect(collapsed[0].parentElement?.textContent).not.toContain("test");
  });

  it("reports a toggle rather than collapsing on its own", async () => {
    const { onToggleCollapse, user } = renderCFG();
    await user.click(blockHeaders()[0]);
    expect(onToggleCollapse).toHaveBeenCalledTimes(1);
    // Still expanded: the parent owns the set, which is what makes the graph's
    // collapse state survive a re-render from elsewhere.
    expect(blockHeaders()[0].getAttribute("aria-expanded")).toBe("true");
  });

  it("marks every expanded block as expanded for a screen reader", () => {
    renderCFG();
    for (const h of blockHeaders()) expect(h.getAttribute("aria-expanded")).toBe("true");
  });
});

describe("CFGView instruction interaction", () => {
  it("reports a click on a branch target address", async () => {
    const { onAddressClick, onNavigate, user } = renderCFG();
    // The `jne`'s operand renders as a clickable target.
    const target = screen.getAllByText(`0x${(B + 8).toString(16).toUpperCase()}`);
    expect(target.length).toBeGreaterThan(0);
    await user.click(target[0]);
    expect(onAddressClick.mock.calls.length + onNavigate.mock.calls.length).toBeGreaterThan(0);
  });

  it("opens the context menu for the instruction under the pointer", async () => {
    const { onContextMenu, user } = renderCFG();
    const row = screen.getByText("test").closest("div") as HTMLElement;
    await user.pointer({ target: row, keys: "[MouseRight]" });
    expect(onContextMenu).toHaveBeenCalled();
    // Second argument is the instruction, so the menu can act on it.
    expect(onContextMenu.mock.calls[0][1]).toMatchObject({ mnemonic: "test" });
  });
});

describe("CFGView empty graph", () => {
  it("survives a function with no instructions", () => {
    const { container } = renderCFG({ layout: { blocks: [], edges: [] } });
    // No blocks and no crash. The panel is mounted from DisassemblyView before
    // a decode has necessarily produced anything for this range.
    expect(blockHeaders()).toHaveLength(0);
    expect(edgePaths(container)).toHaveLength(0);
  });
});
