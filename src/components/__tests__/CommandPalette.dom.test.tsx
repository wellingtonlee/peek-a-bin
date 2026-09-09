// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DisasmFunction } from "../../disasm/types";
import { VIEW_TABS, type ViewTab } from "../../hooks/usePEFile";
import { fuzzyMatch } from "../../utils/fuzzyMatch";
import { VIEW_TAB_LABELS } from "../analysisNotice";
import { CommandPalette, PALETTE_COMMANDS } from "../CommandPalette";
import { AppHarness, EXPORT_RVA, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * The command palette's DOM wiring.
 *
 * `listboxIds.test.ts` pins the id arithmetic over plain strings and its own
 * docstring says why that was all there was: "the DOM wiring in `CommandPalette`
 * cannot be [tested], since there is no React renderer in this repo". There is
 * one now, and the wiring is the half that can be wrong on its own — the ids can
 * be computed perfectly and pointed at the wrong element, or at an element that
 * was never rendered, and neither shows up as an error anywhere. A dangling
 * `aria-activedescendant` is silent: no console warning, no failed assertion,
 * just a selection a screen reader never announces. Nothing in this repo could
 * see that before.
 *
 * The other thing only a renderer can settle is `peek-a-bin-v2u` section 3's
 * first item — Tab once should leave the palette rather than walk the result
 * rows. That is a claim about the interaction between three separate decisions
 * (the rows are `role="option"` not `<button>`, they carry `tabIndex={-1}`, and
 * `focusableWithin` excludes exactly that), and no one of them proves it.
 *
 * SCOPE. jsdom performs no layout and runs no browser focus algorithm, so what
 * is checked here is that the component's own logic runs and puts the right
 * attributes and focus where it says. It says nothing about what a screen reader
 * announces — `aria-activedescendant` is asserted as a live reference to a real
 * element, which is the precondition for an announcement and not the
 * announcement — and nothing about scrolling, since `scrollIntoView` is a no-op
 * stand-in here (see `src/test/domSetup.ts`).
 */

/**
 * Twenty functions whose names all contain "handler" and nothing else in the
 * fixture does — so a query for it produces a result list of functions alone,
 * and one long enough to be worth trapping focus out of. Checked against the
 * other four categories: `fuzzyMatch` is a subsequence test, and "handler" is
 * not a subsequence of "kernel32.dll!createfilew", "kernel32.dll!readfile",
 * "parseheader", or any label in `PALETTE_COMMANDS` (checked below, so the
 * claim cannot go stale as the command table grows).
 */
function handlerFuncs(): DisasmFunction[] {
  return Array.from({ length: 20 }, (_, i) => ({
    name: `handler_${String(i).padStart(2, "0")}`,
    address: IMAGE_BASE + 0x1000 + i * 0x10,
    size: 0x10,
  }));
}

const STRINGS: [number, string][] = [
  [IMAGE_BASE + 0x3000, "cannot open %s"],
  [IMAGE_BASE + 0x3020, "unsupported machine type"],
];

function renderPalette(over: Parameters<typeof stateWithPE>[1] = {}) {
  const dispatch = vi.fn();
  const onClose = vi.fn();
  const pe = harnessPE(STRINGS);
  render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <CommandPalette open onClose={onClose} />
    </AppHarness>,
  );
  return { dispatch, onClose, user: userEvent.setup() };
}

const combobox = () => screen.getByRole("combobox");
const options = () => screen.queryAllByRole("option");
const labelsOf = () => options().map((o) => o.textContent ?? "");

/** The element `aria-activedescendant` points at, or null if it points nowhere. */
function activeOption(): HTMLElement | null {
  const id = combobox().getAttribute("aria-activedescendant");
  return id ? document.getElementById(id) : null;
}

describe("CommandPalette results", () => {
  it("shows the prompt and no options until something is typed", () => {
    renderPalette({ functions: handlerFuncs() });
    expect(options()).toHaveLength(0);
    expect(screen.getByText(/Type to search across/)).toBeTruthy();
    expect(combobox().getAttribute("aria-expanded")).toBe("false");
  });

  it("filters to the functions whose names match the query", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler_03");
    // The whole row, address included: the address is the only thing telling a
    // reader which of twenty near-identical names this is.
    expect(labelsOf()).toEqual(["0x140001030handler_03"]);
  });

  it("caps each category and draws from all five of them", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    // "e" is a subsequence of every category's labels here, so this is the one
    // query that exercises the grouping. Functions are capped at CAP=15 out of
    // the 20 supplied, which is what makes the cap observable at all.
    await user.type(combobox(), "e");
    const texts = labelsOf();
    expect(texts.filter((t) => /handler_/.test(t))).toHaveLength(15);
    expect(texts.some((t) => /KERNEL32\.dll!CreateFileW/.test(t))).toBe(true);
    expect(texts.some((t) => /ParseHeader/.test(t))).toBe(true);
    expect(texts.some((t) => /unsupported machine type/.test(t))).toBe(true);
    expect(texts.some((t) => /AI: Open Chat/.test(t))).toBe(true);
    // Every category heading is rendered above its first row.
    for (const heading of ["Functions", "Imports", "Exports", "Strings", "Commands"]) {
      expect(screen.getByText(heading)).toBeTruthy();
    }
  });

  it("says so when a query matches nothing", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    // No 'z' anywhere in the fixture, in any category.
    await user.type(combobox(), "zzz");
    expect(options()).toHaveLength(0);
    expect(screen.getByText("No results")).toBeTruthy();
    expect(combobox().getAttribute("aria-expanded")).toBe("false");
  });

  it("renames win over the detected name, in both directions", async () => {
    const funcs = handlerFuncs();
    const { user } = renderPalette({
      functions: funcs,
      renames: { [funcs[0].address]: "handler_renamed" },
    });
    await user.type(combobox(), "handler_renamed");
    expect(labelsOf().some((t) => /handler_renamed/.test(t))).toBe(true);
    await user.clear(combobox());
    // The old name is gone, not merely shadowed.
    await user.type(combobox(), "handler_00");
    expect(labelsOf().some((t) => /handler_00/.test(t))).toBe(false);
  });
});

describe("CommandPalette listbox wiring", () => {
  it("points aria-controls at the listbox that actually holds the options", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    const listId = combobox().getAttribute("aria-controls");
    expect(listId).toBeTruthy();
    const list = document.getElementById(listId as string);
    expect(list).not.toBeNull();
    expect(list?.getAttribute("role")).toBe("listbox");
    // Not merely a listbox somewhere — the one the options are inside.
    expect(within(list as HTMLElement).getAllByRole("option")).toHaveLength(options().length);
  });

  it("names a REAL option, and the one marked selected", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    const active = activeOption();
    expect(active).not.toBeNull();
    expect(active?.getAttribute("role")).toBe("option");
    expect(active?.getAttribute("aria-selected")).toBe("true");
    expect(active).toBe(options()[0]);
    // Exactly one row claims to be selected.
    expect(options().filter((o) => o.getAttribute("aria-selected") === "true")).toHaveLength(1);
  });

  it("follows the arrow keys, staying on a real element every step", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    const all = options();
    expect(all.length).toBeGreaterThan(3);
    for (let i = 1; i <= 3; i++) {
      await user.keyboard("{ArrowDown}");
      const active = activeOption();
      expect(active).toBe(options()[i]);
      expect(active?.getAttribute("aria-selected")).toBe("true");
    }
    await user.keyboard("{ArrowUp}");
    expect(activeOption()).toBe(options()[2]);
  });

  it("clamps at both ends instead of wrapping or running off", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler_1");
    const count = options().length;
    expect(count).toBeGreaterThan(1);
    await user.keyboard("{ArrowUp}{ArrowUp}");
    expect(activeOption()).toBe(options()[0]);
    for (let i = 0; i < count + 3; i++) await user.keyboard("{ArrowDown}");
    expect(activeOption()).toBe(options()[count - 1]);
  });

  it("omits aria-activedescendant rather than dangling when there is nothing to point at", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    expect(combobox().getAttribute("aria-activedescendant")).toBeNull();
    await user.type(combobox(), "zzz");
    expect(combobox().getAttribute("aria-activedescendant")).toBeNull();
  });

  it("still points at a live option after the list shrinks under the selection", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler_1");
    await user.keyboard("{ArrowDown}{ArrowDown}{ArrowDown}");
    expect(activeOption()).toBe(options()[3]);
    // Narrows 10 rows to 1 with the highlight sitting at index 3, so the reset
    // effect and the id arithmetic have to agree about the new list.
    await user.type(combobox(), "9");
    expect(options()).toHaveLength(1);
    expect(activeOption()).toBe(options()[0]);
    //
    // WHAT THIS DOES NOT REACH, stated because the obvious reading is wrong.
    // `activeDescendantId`'s `selectedIndex >= count` clause is only ever
    // exercised in the render BETWEEN the shrink and the reset effect, and
    // `user.type` flushes effects, so nothing here can observe that frame —
    // measured, by dropping the guard, which leaves this test green and fails
    // only the empty-list one below. That clause is pinned over plain values in
    // `listboxIds.test.ts` ("is undefined when the index is past the end"); what
    // is checked here is the composition's settled result.
  });
});

describe("CommandPalette activation", () => {
  it("navigates to the highlighted result on Enter", async () => {
    const funcs = handlerFuncs();
    const { user, dispatch, onClose } = renderPalette({ functions: funcs });
    await user.type(combobox(), "handler");
    await user.keyboard("{ArrowDown}{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: funcs[1].address });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("sends each category to its own tab", async () => {
    const { user, dispatch } = renderPalette({ functions: [] });
    await user.type(combobox(), "ParseHeader");
    await user.keyboard("{Enter}");
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: IMAGE_BASE + EXPORT_RVA,
    });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "exports" });
  });

  it("fires the window event for an AI command and navigates nowhere", async () => {
    const seen = vi.fn();
    window.addEventListener("peek-a-bin:open-chat", seen);
    try {
      const { user, dispatch, onClose } = renderPalette({ functions: [] });
      await user.type(combobox(), "AI: Open Chat");
      await user.keyboard("{Enter}");
      expect(seen).toHaveBeenCalledTimes(1);
      expect(dispatch).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener("peek-a-bin:open-chat", seen);
    }
  });

  it("activates the row that was clicked, not the highlighted one", async () => {
    const funcs = handlerFuncs();
    const { user, dispatch } = renderPalette({ functions: funcs });
    await user.type(combobox(), "handler");
    await user.click(options()[4]);
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: funcs[4].address });
  });

  it("does nothing on Enter with an empty result list", async () => {
    const { user, dispatch, onClose } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "zzz");
    await user.keyboard("{Enter}");
    expect(dispatch).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("resets the highlight to the top when the result set changes size", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    await user.keyboard("{ArrowDown}{ArrowDown}");
    expect(activeOption()).toBe(options()[2]);
    await user.type(combobox(), "_1");
    expect(activeOption()).toBe(options()[0]);
  });
});

describe("CommandPalette focus", () => {
  it("opens with focus in the search field", () => {
    renderPalette({ functions: handlerFuncs() });
    expect(document.activeElement).toBe(combobox());
    //
    // THIS DOES NOT TEST `initialFocusRef`, and the obvious reading that it does
    // is wrong. Measured: deleting that prop from the palette's `<Modal>` leaves
    // all 24 tests here green, because the search input is ALSO the dialog's
    // first focusable control, which is what `Modal` falls back to. The prop is
    // inert on this dialog. `Modal.dom.test.tsx` covers it where it is not —
    // its harness puts two controls before the referenced one.
  });

  it("does not walk the result rows on Tab", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    const rows = options();
    // 15 rows: this is peek-a-bin-v2u section 3's "not 60 result rows", at the
    // scale the CAP allows. As <button>s every one of them was a tab stop.
    expect(rows).toHaveLength(15);
    for (let i = 0; i < 5; i++) {
      await user.tab();
      expect(rows).not.toContain(document.activeElement);
      // The input is the dialog's only focusable control, so the trap wraps to
      // it. Asserting that rather than merely "not a row" is what would catch a
      // row becoming focusable again AND focus escaping the dialog.
      expect(document.activeElement).toBe(combobox());
    }
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(combobox());
  });

  it("keeps every row out of the tab order explicitly", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    // -1 and not merely absent: the aria-activedescendant pattern wants the rows
    // programmatically focusable, which is a different thing from tabbable.
    for (const row of options()) expect(row.getAttribute("tabindex")).toBe("-1");
  });
});

describe("CommandPalette dialog", () => {
  it("is a named modal dialog", () => {
    renderPalette({ functions: handlerFuncs() });
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.getAttribute("aria-label")).toBe("Command palette");
  });

  it("closes on Escape, which it deliberately leaves to the Modal", async () => {
    const { user, onClose } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders nothing at all when closed", () => {
    render(
      <AppHarness state={stateWithPE(harnessPE(STRINGS))} dispatch={vi.fn()}>
        <CommandPalette open={false} onClose={vi.fn()} />
      </AppHarness>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("CommandPalette without a loaded file", () => {
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warn = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => warn.mockRestore());

  it("offers nothing at all, the command table included", async () => {
    const dispatch = vi.fn();
    render(
      <AppHarness state={{ ...stateWithPE(harnessPE()), peFile: null }} dispatch={dispatch}>
        <CommandPalette open onClose={vi.fn()} />
      </AppHarness>,
    );
    const user = userEvent.setup();
    // `results` short-circuits on a null peFile, so even the commands — several
    // of which (Open Settings) would work perfectly well with no file open —
    // are withheld. Recorded as the behaviour it is, not asserted as desirable;
    // it is unchanged by the command table landing.
    await user.type(combobox(), "Open Settings");
    expect(options()).toHaveLength(0);
    expect(screen.getByText("No results")).toBeTruthy();
  });
});

/** The one command whose action is `SET_TAB` for `tab`. */
function tabCommand(tab: ViewTab) {
  const found = PALETTE_COMMANDS.filter(
    (c) =>
      c.target.kind === "action" &&
      c.target.action.type === "SET_TAB" &&
      c.target.action.tab === tab,
  );
  expect(found).toHaveLength(1);
  return found[0];
}

/** The admission line a cut-short category renders, or null. */
function capNotices(): HTMLElement[] {
  return screen.queryAllByText(/showing the first 15 matches/);
}

describe("CommandPalette commands", () => {
  it("keeps the function fixture out of the command table's way", () => {
    // The claim `handlerFuncs`' docstring makes, asserted rather than asserted
    // in prose: a query of "handler" must reach the Functions category alone,
    // or the cap tests below are counting rows from two categories.
    for (const cmd of PALETTE_COMMANDS) expect(fuzzyMatch("handler", cmd.label)).toBe(false);
  });

  it("lists a matching command under the Commands heading", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "Open Settings");
    expect(labelsOf()).toEqual(["Open Settings"]);
    // No address column for a command: there is no address to go to, and "0x0"
    // is what the single hard-coded entry used to print.
    expect(options()[0].textContent).not.toMatch(/0x/);
    expect(screen.getByText("Commands")).toBeTruthy();
  });

  it("labels every tab command from VIEW_TAB_LABELS, derived", () => {
    // The whole point of the map: no tab name is spelled in the palette, so a
    // tab cannot be called one thing on its button and another here. Spelling
    // any one of them as a literal in the table reddens this row.
    expect(VIEW_TABS.length).toBeGreaterThan(0);
    for (const tab of VIEW_TABS) {
      expect(tabCommand(tab).label).toBe(`Go to ${VIEW_TAB_LABELS[tab]}`);
    }
  });

  it("renders a tab command under the label VIEW_TAB_LABELS gives it", async () => {
    const tab: ViewTab = "sections";
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), `Go to ${VIEW_TAB_LABELS[tab]}`);
    expect(labelsOf()).toEqual([tabCommand(tab).label]);
  });

  it("dispatches the AppAction for a tab command and navigates nowhere", async () => {
    const tab: ViewTab = "sections";
    const { user, dispatch, onClose } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), `Go to ${VIEW_TAB_LABELS[tab]}`);
    await user.keyboard("{Enter}");
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab });
    // A navigation would also have dispatched SET_ADDRESS, for address 0.
    expect(dispatch).not.toHaveBeenCalledWith(expect.objectContaining({ type: "SET_ADDRESS" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("dispatches the AppAction for a plain action command", async () => {
    const { user, dispatch, onClose } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "Toggle Bookmark");
    await user.keyboard("{Enter}");
    // No address on the action: the reducer reads state.currentAddress, which
    // is the cursor, exactly as the B shortcut does.
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(dispatch).toHaveBeenCalledWith({ type: "TOGGLE_BOOKMARK" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("fires the window event for the settings command and dispatches nothing", async () => {
    const seen = vi.fn();
    window.addEventListener("peek-a-bin:open-settings", seen);
    try {
      const { user, dispatch, onClose } = renderPalette({ functions: handlerFuncs() });
      await user.type(combobox(), "Open Settings");
      await user.keyboard("{Enter}");
      expect(seen).toHaveBeenCalledTimes(1);
      expect(dispatch).not.toHaveBeenCalled();
      expect(onClose).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener("peek-a-bin:open-settings", seen);
    }
  });

  it("offers one command per view tab, so a ninth tab is not forgotten", () => {
    for (const tab of VIEW_TABS) expect(tabCommand(tab)).toBeTruthy();
  });
});

describe("CommandPalette cap admission", () => {
  it("admits a category the cap cut short", async () => {
    // 20 functions match, 15 are shown. Before this the other five were simply
    // absent, and a cut-short category looked exactly like a complete one.
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    expect(options()).toHaveLength(15);
    const notices = capNotices();
    expect(notices).toHaveLength(1);
    // Directly after the last row of the category it is talking about.
    const following = options()[14].compareDocumentPosition(notices[0]);
    expect(following & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("says nothing when the whole match list fits", async () => {
    const { user } = renderPalette({ functions: handlerFuncs().slice(0, 3) });
    await user.type(combobox(), "handler");
    expect(options()).toHaveLength(3);
    expect(capNotices()).toHaveLength(0);
  });

  it("is a count line, not a row: unselectable and out of the option list", async () => {
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "handler");
    const notice = capNotices()[0];
    expect(notice.getAttribute("role")).toBe("presentation");
    expect(notice.getAttribute("tabindex")).toBeNull();
    expect(options()).not.toContain(notice);
    // The listbox holds 15 options and no sixteenth thing pretending to be one.
    const list = document.getElementById(combobox().getAttribute("aria-controls") as string);
    expect(within(list as HTMLElement).getAllByRole("option")).toHaveLength(15);
    // Arrowing past the end lands on the last real row, never on the notice.
    for (let i = 0; i < 20; i++) await user.keyboard("{ArrowDown}");
    expect(activeOption()).toBe(options()[14]);
    expect(activeOption()).not.toBe(notice);
  });

  it("admits each cut-short category separately", async () => {
    // "e" matches in every category; only Functions overflows the cap here, so
    // exactly one notice must appear rather than one per category or one for
    // the whole list.
    const { user } = renderPalette({ functions: handlerFuncs() });
    await user.type(combobox(), "e");
    expect(labelsOf().filter((t) => /handler_/.test(t))).toHaveLength(15);
    expect(capNotices()).toHaveLength(1);
  });
});
