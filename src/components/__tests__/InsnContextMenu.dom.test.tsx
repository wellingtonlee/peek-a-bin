// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRef } from "react";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockInstance,
  vi,
} from "vitest";
import type { DisasmFunction, Instruction } from "../../disasm/types";
import type { DisplayRow } from "../../hooks/useDisassemblyRows";
import type { ContextMenuState } from "../../hooks/useInsnContextMenu";
import type { PEFile } from "../../pe/types";
import { InsnContextMenu, type InsnContextMenuActions } from "../InsnContextMenu";

/**
 * `InsnContextMenu` — the instruction context menu, which until this file had
 * NO test of any kind. It is rendered twice by `DisassemblyView` (linear mode
 * and graph mode) and so was in the tree of `DisassemblyPanel.dom.test.tsx`,
 * but mounting as somebody's child is not coverage: nothing asserted on this
 * component's own output.
 *
 * WHY IT EXISTS, AND WHAT IT IS GUARDING (peek-a-bin-r8tt).
 *
 * The menu is built from a `menuItem` helper plus bare `sep` entries, and the
 * relationship between the two is PURE CONVENTION — a `sep` is a sibling
 * expression, guarded by whatever condition the item below it is guarded by,
 * written out by hand. Nothing in the type system, nothing in Biome and
 * nothing in `tsc` connects a rule to the item it introduces. So a rule can be
 * left behind when its item goes, or added without one, and the result is a
 * menu that renders two rules in a row, or ends on a rule, or opens on one.
 *
 * That is not hypothetical. Removing the per-function "Scan for
 * vulnerabilities" item (peek-a-bin-1xc5.1, commit 28a4520) meant also deleting
 * the `{isFuncHead && sep}` that sat above it, because that separator existed
 * only to precede it: kept, it renders a TRAILING rule on a function head with
 * no selection, and a DOUBLE rule on a function head with one. The agent who
 * made that change caught it by building a scratch renderer, confirmed both
 * failure shapes, and then threw the instrument away — which is
 * `peek-a-bin-02fa`'s failure mode ("when you build an oracle to verify a
 * change, land the oracle") for the fourth recorded time. This file is that
 * oracle, landed.
 *
 * THE SEPARATOR SHAPE IS CORRECT TODAY. This is not a bug fix; the component is
 * unchanged apart from a docstring. What is new is the guard.
 *
 * WHAT IS NOT COVERED, so a green run is not over-read:
 *
 *  - jsdom performs no layout, so nothing here has seen the menu ON SCREEN. A
 *    rule in the document is not a rule a reader can see, `left`/`top` are
 *    asserted as the numbers the component writes and not as a position, and
 *    whether the menu fits in the viewport at those coordinates is a question
 *    no test in this repo can ask (`peek-a-bin-v2u`).
 *  - Dismissal is not this component's business at all — it renders no backdrop
 *    and installs no listener. `menuRef` is forwarded so the OWNER's
 *    outside-click handler can compare against the element; what that handler
 *    then does is `DisassemblyView`'s and is asserted there.
 *  - The clipboard write goes through `userEvent`'s stub, which is a stand-in
 *    exactly as `test/domSetup.ts`'s `offsetParent` shim is. Nothing here says
 *    a browser's clipboard would accept it, and `utils/clipboard.ts`'s own
 *    absent-clipboard behaviour is asserted in its own suite.
 */

/**
 * NO REACT DIAGNOSTIC, ANYWHERE IN THIS FILE — a file-wide assertion, not a test.
 *
 * File-wide is the load-bearing part and it is a measurement, not a
 * preference: React caches its key warning PER OWNER COMPONENT, so a dedicated
 * `vi.spyOn` placed after any earlier render in the same file sees a clean
 * console with a keyless list still in place. Asserted after every test, the
 * FIRST render that warns is the one that fails.
 *
 * It is worth having here even though this component maps over nothing today,
 * because the shape it would catch is one step away: the "Copy selected" arm
 * already returns a `<>…</>` holding a rule and an item, and a future arm that
 * needed two of those would reach for `.map` over exactly that fragment —
 * `ResourcesView` shipped that defect on a populated tab for months.
 */
let consoleError: MockInstance<typeof console.error>;
beforeEach(() => {
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  const messages = consoleError.mock.calls.map((c) => String(c[0]));
  consoleError.mockRestore();
  expect(messages).toEqual([]);
});

const ADDR = 0x140001000;
const OTHER_ADDR = 0x140002000;
const MENU_X = 137;
const MENU_Y = 42;

function insnAt(over: Partial<Instruction> = {}): Instruction {
  return {
    address: ADDR,
    bytes: new Uint8Array([0x90]),
    mnemonic: "nop",
    opStr: "",
    size: 1,
    ...over,
  };
}

function fn(address: number): DisasmFunction {
  return { name: `sub_${address.toString(16)}`, address, size: 0x20 };
}

/**
 * Every action the menu can fire, as a spy each.
 *
 * Written as an object literal typed by `InsnContextMenuActions` rather than
 * built from a key array, so that adding an action to the interface FAILS THE
 * BUILD here — which is the one part of this suite the compiler can carry.
 */
function makeActions(): { [K in keyof InsnContextMenuActions]: Mock<() => void> } {
  return {
    ctxCopyAddr: vi.fn(),
    ctxCopyInsn: vi.fn(),
    ctxCopyBytes: vi.fn(),
    ctxGoTo: vi.fn(),
    ctxShowInHex: vi.fn(),
    ctxToggleBookmark: vi.fn(),
    ctxAddComment: vi.fn(),
    ctxCopyComment: vi.fn(),
    ctxRenameFunction: vi.fn(),
    ctxFollowTarget: vi.fn(),
    ctxShowXrefs: vi.fn(),
  };
}

/** The five things that decide which entries the menu renders. */
interface Shape {
  /** A resolvable direct branch target, i.e. `parseBranchTarget` answers. */
  branch?: boolean;
  xrefCount?: number;
  /** Where the comment comes from — the annotation map, or the instruction. */
  comment?: "map" | "insn" | false;
  isFuncHead?: boolean;
  selection?: { start: number; end: number } | null;
}

const ROWS: DisplayRow[] = [{ kind: "separator" }, { kind: "insn", insn: insnAt(), blockIdx: 0 }];
const RANGE_TEXT = "0x140001000  nop\n";

function renderMenu(shape: Shape = {}) {
  const {
    branch = false,
    xrefCount = 0,
    comment = false,
    isFuncHead = false,
    selection = null,
  } = shape;
  const actions = makeActions();
  const setCtxMenu = vi.fn();
  const formatRangeCopy = vi.fn(() => RANGE_TEXT);
  const menuRef = createRef<HTMLDivElement>();
  const insn = insnAt({
    ...(branch ? { mnemonic: "jmp", opStr: `0x${OTHER_ADDR.toString(16)}` } : {}),
    ...(comment === "insn" ? { comment: "; from the instruction" } : {}),
  });
  const ctxMenu: ContextMenuState = { x: MENU_X, y: MENU_Y, insn };
  const comments: Record<number, string> = comment === "map" ? { [ADDR]: "from the map" } : {};
  const pe: PEFile | null = null;
  const renames: Record<number, string> = {};
  const { container } = render(
    <InsnContextMenu
      ctxMenu={ctxMenu}
      menuRef={menuRef}
      actions={actions}
      xrefCountMap={new Map(xrefCount > 0 ? [[ADDR, xrefCount]] : [])}
      comments={comments}
      funcMap={new Map(isFuncHead ? [[ADDR, fn(ADDR)]] : [])}
      setCtxMenu={setCtxMenu}
      selectionRange={selection}
      rows={ROWS}
      pe={pe}
      renames={renames}
      formatRangeCopy={formatRangeCopy}
    />,
  );
  const menu = container.firstElementChild as HTMLElement;
  return { actions, setCtxMenu, formatRangeCopy, menuRef, menu, comments, renames, ctxMenu, pe };
}

type Slot = { kind: "item"; label: string; hint: string | null } | { kind: "rule" };

/**
 * The menu's children, classified.
 *
 * STRUCTURAL, not textual: an item is a `<button>` and a rule is the empty
 * `<div>` carrying the `border-t` class. Anything else THROWS rather than
 * being silently bucketed, because the whole point of the sweep below is that
 * the run of rules and items is what is being judged — a node this function
 * did not recognise, quietly dropped, is a hole in exactly the gate that is
 * meant to be watching.
 */
function slots(menu: HTMLElement): Slot[] {
  return Array.from(menu.children).map((el): Slot => {
    if (el.tagName === "BUTTON") {
      const spans = Array.from(el.querySelectorAll("span"));
      return {
        kind: "item",
        label: spans[0]?.textContent ?? "",
        hint: spans[1]?.textContent ?? null,
      };
    }
    if (el.tagName === "DIV" && el.className.includes("border-t") && el.textContent === "") {
      return { kind: "rule" };
    }
    throw new Error(
      `slots() does not recognise <${el.tagName.toLowerCase()} class="${el.className}">. ` +
        "Teach it what the node is — do not let it fall through, or the separator sweep stops seeing it.",
    );
  });
}

const labels = (menu: HTMLElement): string[] =>
  slots(menu).flatMap((s) => (s.kind === "item" ? [s.label] : []));

/** The item whose own label span reads `label`, by structure rather than by accessible name. */
function item(menu: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(menu.children).find(
    (el) => el.tagName === "BUTTON" && el.querySelector("span")?.textContent === label,
  );
  if (!found)
    throw new Error(`no menu item labelled "${label}" — menu reads ${labels(menu).join(" / ")}`);
  return found as HTMLButtonElement;
}

/* ------------------------------------------------------------------------ */

/**
 * THE INVARIANT THE `1xc5.1` HAZARD WOULD HAVE TRIPPED.
 *
 * Swept over every combination of the five conditions that gate an entry, not
 * the two the bead named: a rule's correctness is a fact about its NEIGHBOURS,
 * so `isFuncHead` × `selectionRange` alone would leave the two rules higher up
 * the menu — the one after "Copy bytes" and the conditional one after the
 * xref block — judged in one arrangement each.
 *
 * Three properties, and each is a distinct failure the convention permits:
 * no two rules adjacent (an item removed from between them), no trailing rule
 * (the last item removed from under one — the `1xc5.1` shape), no leading rule
 * (the first item made conditional).
 */
const COMBOS: { name: string; shape: Shape }[] = [];
for (const branch of [false, true]) {
  for (const xrefCount of [0, 3]) {
    for (const comment of [false, "map"] as const) {
      for (const isFuncHead of [false, true]) {
        for (const selection of [null, { start: 2, end: 5 }]) {
          COMBOS.push({
            name:
              `branch=${branch} xrefs=${xrefCount} comment=${comment ? "yes" : "no"} ` +
              `funcHead=${isFuncHead} selection=${selection ? "yes" : "no"}`,
            shape: { branch, xrefCount, comment, isFuncHead, selection },
          });
        }
      }
    }
  }
}

describe("InsnContextMenu separator shape", () => {
  it("sweeps every combination of the five conditions that gate an entry", () => {
    // A liveness half. The sweep is generated, so a dimension collapsed to one
    // value would shrink it silently and every case below would still pass.
    expect(COMBOS.length).toBe(2 * 2 * 2 * 2 * 2);
  });

  for (const { name, shape } of COMBOS) {
    it(`renders no adjacent, leading or trailing rule — ${name}`, () => {
      const { menu } = renderMenu(shape);
      const kinds = slots(menu).map((s) => s.kind);

      // Liveness: a menu with no rules at all satisfies the three properties
      // below vacuously, and an empty one satisfies them by rendering nothing.
      expect(kinds).toContain("rule");
      expect(kinds).toContain("item");

      expect(kinds[0]).toBe("item");
      expect(kinds[kinds.length - 1]).toBe("item");
      const doubled = kinds.filter((k, i) => k === "rule" && kinds[i - 1] === "rule");
      expect(doubled).toEqual([]);
    });
  }

  it("has each of those five conditions actually change what is rendered", () => {
    // The other half of the liveness argument, and the one that matters: 32
    // cases all rendering the same menu would pass the sweep while proving
    // nothing about any of the five dimensions. Every combination must produce
    // a distinct run of rules and items.
    const signatures = COMBOS.map(({ shape }) => {
      const { menu } = renderMenu(shape);
      const sig = slots(menu)
        .map((s) => (s.kind === "rule" ? "---" : s.label))
        .join("|");
      return sig;
    });
    expect(new Set(signatures).size).toBe(COMBOS.length);
  });
});

describe("InsnContextMenu entries", () => {
  it("renders the always-present items, in order, around two rules", () => {
    const { menu } = renderMenu();
    expect(slots(menu)).toEqual([
      { kind: "item", label: "Copy address", hint: null },
      { kind: "item", label: "Copy instruction", hint: null },
      { kind: "item", label: "Copy bytes", hint: null },
      { kind: "rule" },
      { kind: "item", label: "Go to address...", hint: "G" },
      { kind: "item", label: "Show in Hex", hint: null },
      { kind: "rule" },
      { kind: "item", label: "Toggle bookmark", hint: "B" },
      { kind: "item", label: "Add/Edit comment", hint: ";" },
    ]);
  });

  it("offers Rename function on a function head only", () => {
    expect(labels(renderMenu({ isFuncHead: true }).menu)).toContain("Rename function");
    expect(labels(renderMenu({ isFuncHead: false }).menu)).not.toContain("Rename function");
  });

  it("keys Rename function on THIS instruction's address, not on the map being non-empty", () => {
    // The discriminating half of the test above: a populated `funcMap` that
    // does not name the address under the cursor must not offer the item.
    const actions = makeActions();
    render(
      <InsnContextMenu
        ctxMenu={{ x: 0, y: 0, insn: insnAt() }}
        menuRef={createRef<HTMLDivElement>()}
        actions={actions}
        xrefCountMap={new Map()}
        comments={{}}
        funcMap={new Map([[OTHER_ADDR, fn(OTHER_ADDR)]])}
        setCtxMenu={vi.fn()}
        selectionRange={null}
        rows={ROWS}
        pe={null}
        renames={{}}
        formatRangeCopy={vi.fn(() => "")}
      />,
    );
    expect(screen.queryByText("Rename function")).toBeNull();
  });

  it("offers Follow target only for a resolvable direct branch", () => {
    expect(labels(renderMenu({ branch: true }).menu)).toContain("Follow target");
    expect(labels(renderMenu({ branch: false }).menu)).not.toContain("Follow target");
  });

  it("declines Follow target for an indirect jmp, so it really goes through parseBranchTarget", () => {
    // `jmp rax` is a jump whose target no immediate names. A guard written as
    // `mnemonic.startsWith("j")` would offer the item and navigate nowhere.
    const actions = makeActions();
    render(
      <InsnContextMenu
        ctxMenu={{ x: 0, y: 0, insn: insnAt({ mnemonic: "jmp", opStr: "rax" }) }}
        menuRef={createRef<HTMLDivElement>()}
        actions={actions}
        xrefCountMap={new Map()}
        comments={{}}
        funcMap={new Map()}
        setCtxMenu={vi.fn()}
        selectionRange={null}
        rows={ROWS}
        pe={null}
        renames={{}}
        formatRangeCopy={vi.fn(() => "")}
      />,
    );
    expect(screen.queryByText("Follow target")).toBeNull();
  });

  it("offers Show xrefs with its count, and only above zero", () => {
    expect(labels(renderMenu({ xrefCount: 7 }).menu)).toContain("Show xrefs (7)");
    expect(labels(renderMenu({ xrefCount: 0 }).menu).some((l) => l.startsWith("Show xrefs"))).toBe(
      false,
    );
  });

  it("offers Copy comment for a comment from either source", () => {
    expect(labels(renderMenu({ comment: "map" }).menu)).toContain("Copy comment");
    expect(labels(renderMenu({ comment: "insn" }).menu)).toContain("Copy comment");
    expect(labels(renderMenu({ comment: false }).menu)).not.toContain("Copy comment");
  });

  it("treats an empty comment string as no comment", () => {
    const actions = makeActions();
    render(
      <InsnContextMenu
        ctxMenu={{ x: 0, y: 0, insn: insnAt({ comment: "" }) }}
        menuRef={createRef<HTMLDivElement>()}
        actions={actions}
        xrefCountMap={new Map()}
        comments={{ [ADDR]: "" }}
        funcMap={new Map()}
        setCtxMenu={vi.fn()}
        selectionRange={null}
        rows={ROWS}
        pe={null}
        renames={{}}
        formatRangeCopy={vi.fn(() => "")}
      />,
    );
    expect(screen.queryByText("Copy comment")).toBeNull();
  });

  it("forwards menuRef to the menu element and positions it where the state says", () => {
    // The ref is how the OWNER's outside-click handler recognises the menu; a
    // ref that never attaches makes every click outside-the-menu.
    const { menuRef, menu } = renderMenu();
    expect(menuRef.current).toBe(menu);
    expect(menu.style.left).toBe(`${MENU_X}px`);
    expect(menu.style.top).toBe(`${MENU_Y}px`);
  });
});

describe("InsnContextMenu actions", () => {
  /** Every item that delegates straight to one named action, and which one. */
  const DELEGATED: [label: string, key: keyof InsnContextMenuActions][] = [
    ["Copy address", "ctxCopyAddr"],
    ["Copy instruction", "ctxCopyInsn"],
    ["Copy bytes", "ctxCopyBytes"],
    ["Follow target", "ctxFollowTarget"],
    ["Show xrefs (3)", "ctxShowXrefs"],
    ["Go to address...", "ctxGoTo"],
    ["Show in Hex", "ctxShowInHex"],
    ["Toggle bookmark", "ctxToggleBookmark"],
    ["Add/Edit comment", "ctxAddComment"],
    ["Copy comment", "ctxCopyComment"],
    ["Rename function", "ctxRenameFunction"],
  ];

  it("covers every action the interface declares", () => {
    // Liveness, and compiler-adjacent: `makeActions` fails to typecheck if the
    // interface gains a member, and this fails if the new member gains no row.
    expect([...DELEGATED.map(([, k]) => k)].sort()).toEqual(Object.keys(makeActions()).sort());
  });

  for (const [label, key] of DELEGATED) {
    it(`fires ${key} — and nothing else — from "${label}"`, async () => {
      const user = userEvent.setup();
      const { actions, setCtxMenu, menu } = renderMenu({
        branch: true,
        xrefCount: 3,
        comment: "map",
        isFuncHead: true,
        selection: { start: 1, end: 1 },
      });
      await user.click(item(menu, label));
      const fired = Object.entries(actions)
        .filter(([, spy]) => spy.mock.calls.length > 0)
        .map(([k]) => k);
      expect(fired).toEqual([key]);
      expect(actions[key]).toHaveBeenCalledTimes(1);
      // Only "Copy selected" closes the menu itself; the rest leave that to
      // the action they delegate to.
      expect(setCtxMenu).not.toHaveBeenCalled();
    });
  }

  it("offers Copy selected only with a selection, and counts the rows inclusively", () => {
    expect(
      labels(renderMenu({ selection: null }).menu).some((l) => l.startsWith("Copy selected")),
    ).toBe(false);
    expect(labels(renderMenu({ selection: { start: 4, end: 9 } }).menu)).toContain(
      "Copy selected (6 rows)",
    );
  });

  it("counts a backwards selection the same as a forwards one", () => {
    // `start`/`end` are anchor and cursor, so a drag upward has start > end;
    // the count is min/max'd rather than subtracted.
    expect(labels(renderMenu({ selection: { start: 9, end: 4 } }).menu)).toContain(
      "Copy selected (6 rows)",
    );
  });

  it("Copy selected formats the range, puts it on the clipboard and closes the menu", async () => {
    const user = userEvent.setup(); // installs the clipboard stub jsdom has not got
    const selection = { start: 0, end: 1 };
    const { menu, formatRangeCopy, setCtxMenu, actions, comments, renames, pe } = renderMenu({
      selection,
    });
    await user.click(item(menu, "Copy selected (2 rows)"));
    expect(formatRangeCopy).toHaveBeenCalledTimes(1);
    expect(formatRangeCopy).toHaveBeenCalledWith(selection, ROWS, pe, renames, comments);
    expect(await navigator.clipboard.readText()).toBe(RANGE_TEXT);
    expect(setCtxMenu).toHaveBeenCalledWith(null);
    // It is its own handler, not a delegation: no declared action may fire.
    expect(Object.values(actions).every((spy) => spy.mock.calls.length === 0)).toBe(true);
  });
});
