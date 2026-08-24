// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DisasmFunction } from "../../disasm/types";
import { type AppState, VIEW_TABS, type ViewTab } from "../../hooks/usePEFile";
import type { AIScanFinding } from "../../llm/types";
import { AddressBar } from "../AddressBar";
import { VIEW_TAB_LABELS } from "../analysisNotice";
import { tabId, tabPanelId } from "../tabIds";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * The tab bar, and the 1–9 shortcuts that are supposed to agree with it.
 *
 * `AddressBar`'s own docstring makes a claim no test could previously reach:
 * the button order and the digit map are both derived from `VIEW_TABS`, "so a
 * digit always selects the button at that position". Both derivations are one
 * line each and obviously correct *in isolation* — what nothing checked is the
 * composition, and the composition is where the claim lives. `TABS` renders the
 * digit `i + 1` into each button's own `title`, and `TAB_KEYS` maps `String(i +
 * 1)` to a tab; the two indexes come from separate `.map`s over the array, so a
 * `slice`, an off-by-one or a reordering in either one produces a bar whose
 * buttons advertise a shortcut that selects a different tab. That is silent in
 * every existing instrument: `VIEW_TABS` is still one declaration, the
 * `Record<ViewTab, string>` still typechecks, and `keyboardShortcuts.test.ts`
 * compares `docs/keyboard.md` against the source text rather than against a
 * rendered button. The headline test here reads the digit out of each button's
 * title and presses it — so the bar is checked against itself, not against a
 * list repeated in the test.
 *
 * The other thing only a renderer settles is peek-a-bin-b3jn's second half.
 * CLAUDE.md records that "the two surfaces that cannot reach the notice — the
 * tab bar renders beside it, the panel's arm is an early return — are told
 * directly, or they keep claiming the engine is loading while the banner says
 * it failed". `StatusBar.dom.test.tsx` and `DisassemblyView.dom.test.tsx` cover
 * the other two surfaces; this is the tab bar's, and it is a claim about the
 * *exclusivity* of two sibling branches, which no source scrape can check.
 *
 * SCOPE. jsdom performs no layout, so nothing here is evidence about where the
 * bar sits, whether the tabs overflow, or whether a dropdown is on screen. The
 * active tab is asserted through the class the component itself sets, which is
 * a proxy for "looks selected" and not a rendering of it — there is no
 * `aria-selected` on these buttons to assert instead (see the note on that test).
 */

function aiFinding(severity: AIScanFinding["severity"], title: string): AIScanFinding {
  return {
    severity,
    title,
    description: "",
    functionAddress: IMAGE_BASE + 0x1000,
    functionName: "sub_401000",
    remediation: "",
    source: "ai-scan",
  };
}

const FUNCS: DisasmFunction[] = [
  { name: "sub_401000", address: IMAGE_BASE + 0x1000, size: 0x40 },
  { name: "sub_401040", address: IMAGE_BASE + 0x1040, size: 0x40 },
];

function renderBar(over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  render(
    <AppHarness state={stateWithPE(harnessPE(), over)} dispatch={dispatch}>
      <AddressBar />
    </AppHarness>,
  );
  return { dispatch, user: userEvent.setup() };
}

/**
 * The tab buttons, in DOM order, identified by carrying a `(N)` in the title.
 *
 * BY TITLE AND NOT BY ROLE, deliberately, even though they are `role="tab"` now:
 * this helper is what the 1-9 headline test below reads the advertised digit out
 * of, and a helper that selected on the role would be assuming the very thing
 * `AddressBar tablist semantics` sets out to check. `document.querySelectorAll`
 * rather than `getAllByRole("button")` for the same reason — the role is what
 * changed, and the previous spelling silently returned an empty list the moment
 * it did, which turns four assertions about the bar into assertions about
 * nothing.
 */
function tabButtons(): HTMLButtonElement[] {
  return Array.from(document.querySelectorAll<HTMLButtonElement>("button")).filter((b) =>
    /\(\d\)$/.test(b.getAttribute("title") ?? ""),
  );
}

const addressInput = () => screen.getByPlaceholderText("Go to address (G)");

describe("AddressBar tab bar", () => {
  it("renders every VIEW_TABS entry once, in order, under its VIEW_TAB_LABELS name", () => {
    renderBar();
    const buttons = tabButtons();
    expect(buttons).toHaveLength(VIEW_TABS.length);
    // The label is read off the button and compared to the map, so a bar that
    // dropped a tab, reordered two, or invented a tenth fails here rather than
    // in a count.
    expect(buttons.map((b) => b.textContent)).toEqual(VIEW_TABS.map((t) => VIEW_TAB_LABELS[t]));
  });

  it("dispatches the tab its own label names when clicked", async () => {
    const { dispatch, user } = renderBar();
    const buttons = tabButtons();
    for (const [i, tab] of VIEW_TABS.entries()) {
      dispatch.mockClear();
      await user.click(buttons[i]);
      expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab });
    }
  });

  it("marks the active tab, and only it", () => {
    renderBar({ activeTab: "strings" });
    const active = tabButtons().filter((b) => b.className.includes("bg-blue-600"));
    // BOTH CHANNELS, and the pairing is the point. The class is what a sighted
    // user sees; `aria-selected` is what a screen reader is told, and until
    // peek-a-bin-w50c the class was the only one of the two that existed — so
    // the selected tab was conveyed exclusively through the one channel
    // assistive technology cannot read. Asserting them together is what fails
    // if a later change moves one and not the other.
    expect(active).toHaveLength(1);
    expect(active[0].textContent).toBe(VIEW_TAB_LABELS.strings);
    expect(active[0].getAttribute("aria-selected")).toBe("true");
  });

  it("badges the anomalies tab with the combined static and AI finding count", () => {
    renderBar({
      anomalies: [{ severity: "warning", title: "a", detail: "d" }],
      aiScanResults: [aiFinding("high", "b"), aiFinding("low", "c")],
    });
    const anomalies = tabButtons()[VIEW_TABS.indexOf("anomalies")];
    // 1 static + 2 AI. The badge is the only place the two lists are summed.
    expect(anomalies.textContent).toBe(`${VIEW_TAB_LABELS.anomalies}3`);
  });
});

describe("AddressBar tablist semantics", () => {
  /**
   * peek-a-bin-w50c. The bar was nine plain buttons: no `role`, no
   * `aria-selected`, no `aria-controls`, and the current tab conveyed only by a
   * CSS class. The bead deliberately did not patch half of it, because the
   * WAI-ARIA pattern is a bargain — the roles promise ONE tab stop and arrow
   * navigation, and roles without the keyboard half tell a user "tab 3 of 9" and
   * then leave the arrows dead.
   *
   * WHAT THESE TESTS ARE AND ARE NOT. Every assertion below is about the DOM the
   * component builds and about where the component puts focus. jsdom runs no
   * screen reader and no browser focus algorithm, so none of this is evidence
   * that a reader announces the bar correctly or that a browser agrees about the
   * tab order — see `src/test/domSetup.ts`. peek-a-bin-v2u (the manual browser
   * pass) is still the only thing that can settle that, and it stays open.
   */
  const tabs = () => screen.getAllByRole("tab") as HTMLButtonElement[];

  it("is one tablist holding exactly the nine view tabs", () => {
    renderBar();
    const list = screen.getByRole("tablist");
    // Named, because a tablist with no accessible name is announced as an
    // anonymous group. And scoped: the toolbar around it holds Open,
    // Back/Forward, Undo/Redo and the AI buttons, none of which switch a view,
    // so a `role="tablist"` on the toolbar itself would claim twenty-odd tabs.
    expect(list.getAttribute("aria-label")).toBe("Views");
    expect(within(list).getAllByRole("tab")).toHaveLength(VIEW_TABS.length);
    expect(tabs().map((b) => b.textContent)).toEqual(VIEW_TABS.map((t) => VIEW_TAB_LABELS[t]));
    // The tab bar and the tablist are the same nine buttons, not two overlapping
    // sets: `tabButtons()` finds them by their `(N)` title and this finds them
    // by role, so a role added to the wrong control fails here.
    expect(tabs()).toEqual(tabButtons());
  });

  it("says which tab is selected in ARIA, not only in CSS", () => {
    renderBar({ activeTab: "hex" });
    const selected = tabs().filter((b) => b.getAttribute("aria-selected") === "true");
    expect(selected).toHaveLength(1);
    expect(selected[0].textContent).toBe(VIEW_TAB_LABELS.hex);
    // The other eight must say `false` rather than omitting the attribute: an
    // absent `aria-selected` on a `role="tab"` reads as "not selected" to most
    // readers but is not the same statement, and the APG spells it on every tab.
    for (const tab of tabs()) {
      expect(tab.getAttribute("aria-selected")).toBe(tab === selected[0] ? "true" : "false");
    }
  });

  it("points each tab at its own panel, and labels nothing else", () => {
    renderBar();
    // CORRESPONDENCE ONLY. This suite renders the bar with no panels at all
    // (`App` owns those), so `aria-controls` here names ids nothing has — which
    // is a property of the harness, not of the app. That the reference RESOLVES
    // is asserted in `src/__tests__/App.dom.test.tsx`, where both halves are on
    // screen together. Both are needed: this one fails if the bar stops using
    // the shared minter, that one fails if App does.
    for (const [i, tab] of VIEW_TABS.entries()) {
      expect(tabs()[i].id).toBe(tabId(tab));
      expect(tabs()[i].getAttribute("aria-controls")).toBe(tabPanelId(tab));
    }
  });

  it("is a single tab stop, on the selected tab", async () => {
    renderBar({ activeTab: "exports" });
    // THE ROVING TABINDEX, stated as the invariant rather than as nine
    // attributes: exactly one 0, all the rest -1. A static tabindex — every tab
    // 0, which is what nine plain buttons were — puts nine stops in the Tab
    // order and is the thing the ARIA pattern exists to remove.
    const zeros = tabs().filter((b) => b.tabIndex === 0);
    expect(zeros).toHaveLength(1);
    expect(zeros[0].textContent).toBe(VIEW_TAB_LABELS.exports);
    expect(tabs().filter((b) => b.tabIndex === -1)).toHaveLength(VIEW_TABS.length - 1);
  });

  it("walks into the bar once, however many tabs there are", async () => {
    const { user } = renderBar({ activeTab: "exports" });
    const seen: HTMLElement[] = [];
    // Enough presses to cross the whole toolbar; what is asserted is how many
    // of the NINE were reached, not where Tab ends up.
    for (let i = 0; i < 14; i++) {
      await user.tab();
      const el = document.activeElement as HTMLElement;
      if (tabs().includes(el as HTMLButtonElement)) seen.push(el);
    }
    expect(seen.map((e) => e.textContent)).toEqual([VIEW_TAB_LABELS.exports]);
  });

  it("moves focus with the arrows, and moves the tab stop with it", async () => {
    const { dispatch, user } = renderBar({ activeTab: "disassembly" });
    await user.click(tabs()[0]);
    dispatch.mockClear();

    await user.keyboard("{ArrowRight}");
    expect(document.activeElement?.textContent).toBe(VIEW_TAB_LABELS[VIEW_TABS[1]]);
    // The stop follows FOCUS, not selection — otherwise shift-tabbing out and
    // back would land somewhere the user did not leave from.
    const zeros = tabs().filter((b) => b.tabIndex === 0);
    expect(zeros).toHaveLength(1);
    expect(zeros[0]).toBe(document.activeElement);

    await user.keyboard("{ArrowLeft}");
    expect(document.activeElement?.textContent).toBe(VIEW_TAB_LABELS[VIEW_TABS[0]]);
  });

  it("wraps at both ends, which is what the APG specifies", async () => {
    const { dispatch, user } = renderBar();
    await user.click(tabs()[0]);
    dispatch.mockClear();
    // "If focus is on the first tab, Left Arrow moves focus to the last tab."
    // A clamp here is not a milder version of the rule, it is a different rule,
    // and it is invisible anywhere but at the two ends.
    await user.keyboard("{ArrowLeft}");
    expect(document.activeElement?.textContent).toBe(
      VIEW_TAB_LABELS[VIEW_TABS[VIEW_TABS.length - 1]],
    );
    await user.keyboard("{ArrowRight}");
    expect(document.activeElement?.textContent).toBe(VIEW_TAB_LABELS[VIEW_TABS[0]]);
  });

  it("jumps to the ends on Home and End", async () => {
    const { dispatch, user } = renderBar();
    await user.click(tabs()[3]);
    dispatch.mockClear();
    await user.keyboard("{End}");
    expect(document.activeElement?.textContent).toBe(
      VIEW_TAB_LABELS[VIEW_TABS[VIEW_TABS.length - 1]],
    );
    await user.keyboard("{Home}");
    expect(document.activeElement?.textContent).toBe(VIEW_TAB_LABELS[VIEW_TABS[0]]);
  });

  it("does NOT select the tab the arrows land on", async () => {
    const { dispatch, user } = renderBar({ activeTab: "disassembly" });
    await user.click(tabs()[0]);
    dispatch.mockClear();
    await user.keyboard("{ArrowRight}{ArrowRight}{End}{Home}");
    // MANUAL ACTIVATION, and the reason is a cost rather than a preference:
    // `App` marks `DisassemblyView` and `HexView` lazy and never unmounts a
    // visited tab, so automatic activation would import and permanently mount
    // both just for arrowing past them. Four moves, no dispatch.
    expect(dispatch).not.toHaveBeenCalled();
    // And selection has not moved either: still the tab it started on.
    expect(tabs().filter((b) => b.getAttribute("aria-selected") === "true")[0].textContent).toBe(
      VIEW_TAB_LABELS.disassembly,
    );
  });

  it("selects the focused tab on Enter and on Space", async () => {
    const { dispatch, user } = renderBar({ activeTab: "disassembly" });
    await user.click(tabs()[0]);
    dispatch.mockClear();
    await user.keyboard("{ArrowRight}");
    await user.keyboard("{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: VIEW_TABS[1] });
    dispatch.mockClear();
    // Both come from the element being a real `<button>`; nothing in the
    // component handles either key. Asserted anyway, because "manual activation"
    // is only half implemented if the arrows move focus nothing can act on.
    await user.keyboard(" ");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: VIEW_TABS[1] });
  });

  it("returns the tab stop to the selected tab once focus leaves", async () => {
    const { dispatch, user } = renderBar({ activeTab: "exports" });
    await user.click(tabs()[0]);
    dispatch.mockClear();
    await user.keyboard("{ArrowRight}");
    expect(tabs().filter((b) => b.tabIndex === 0)[0]).toBe(document.activeElement);

    await user.click(addressInput());
    const zeros = tabs().filter((b) => b.tabIndex === 0);
    // Otherwise tabbing back in lands wherever the arrows were last left, which
    // is not where the user is.
    expect(zeros).toHaveLength(1);
    expect(zeros[0].textContent).toBe(VIEW_TAB_LABELS.exports);
  });

  it("leaves an arrow alone when the bar does not have focus", async () => {
    const { dispatch, user } = renderBar();
    await user.keyboard("{ArrowRight}{ArrowLeft}{Home}{End}");
    // The handler is on the tablist, not on `window`: the disassembly view owns
    // the unmodified arrows and a window-level listener here would steal them.
    expect(dispatch).not.toHaveBeenCalled();
    expect(tabs().some((b) => b === document.activeElement)).toBe(false);
  });

  it("names the anomalies tab with its count instead of running the two together", () => {
    renderBar({
      anomalies: [{ severity: "warning", title: "a", detail: "d" }],
      aiScanResults: [aiFinding("high", "b")],
    });
    const anomalies = tabs()[VIEW_TABS.indexOf("anomalies")];
    // The badge is inside the button with no separator, so the accessible name
    // used to be the single string "Anomalies2" — read as "Anomalies2, button",
    // with nothing whatever saying what the 2 counts (peek-a-bin-w50c, note 1).
    // The glyph is `aria-hidden` now and the count is spelled into the name.
    expect(anomalies.textContent).toBe(`${VIEW_TAB_LABELS.anomalies}2`);
    expect(anomalies.getAttribute("aria-label")).toBe("Anomalies — 2 findings");
    expect(anomalies.getAttribute("aria-label")).not.toMatch(/Anomalies\d/);
  });

  it("leaves a tab with nothing to add unnamed, so its label is its name", () => {
    renderBar();
    const headers = tabs()[VIEW_TABS.indexOf("headers")];
    // An `aria-label` that merely repeats the content is a second declaration of
    // the label; omitting it keeps `VIEW_TAB_LABELS` the only one.
    expect(headers.getAttribute("aria-label")).toBeNull();
    expect(screen.getByRole("tab", { name: VIEW_TAB_LABELS.headers })).toBe(headers);
  });
});

describe("AddressBar 1-9 shortcuts", () => {
  /**
   * THE HEADLINE. Every digit is read out of the button that advertises it and
   * then pressed, so the two `.map`s over `VIEW_TABS` are checked against each
   * other rather than against a list written out here — which is exactly the
   * duplication `peek-a-bin-t40b` removed and that a test must not reintroduce.
   */
  it("selects the tab whose own title advertises that digit", async () => {
    const { dispatch, user } = renderBar();
    const buttons = tabButtons();
    for (const button of buttons) {
      const title = button.getAttribute("title") ?? "";
      const digit = /\((\d)\)$/.exec(title)?.[1];
      expect(digit).toBeTruthy();
      const label = button.textContent;
      dispatch.mockClear();
      await user.keyboard(digit as string);
      // The tab the digit selected must be the tab this button is labelled with.
      const call = dispatch.mock.calls.find(([a]) => a.type === "SET_TAB");
      expect(call, `digit ${digit} dispatched no SET_TAB`).toBeTruthy();
      const selected = (call as [{ tab: ViewTab }])[0].tab;
      expect(VIEW_TAB_LABELS[selected], `digit ${digit} selects the wrong tab`).toBe(label);
    }
  });

  it("covers all nine digits and leaves 0 alone", async () => {
    const { dispatch, user } = renderBar();
    // Nine tabs today, so every digit 1-9 is claimed; the assertion is derived
    // from VIEW_TABS so a tenth tab does not silently go unreachable here.
    expect(VIEW_TABS.length).toBeLessThanOrEqual(9);
    for (let i = 1; i <= VIEW_TABS.length; i++) {
      dispatch.mockClear();
      await user.keyboard(String(i));
      expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: VIEW_TABS[i - 1] });
    }
    dispatch.mockClear();
    await user.keyboard("0");
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("does not fire while a text field has focus", async () => {
    const { dispatch, user } = renderBar();
    await user.click(addressInput());
    expect(document.activeElement).toBe(addressInput());
    await user.keyboard("3");
    // Typing a hex digit into the address box must not navigate away from it.
    expect(dispatch).not.toHaveBeenCalled();
    expect((addressInput() as HTMLInputElement).value).toBe("3");
  });
});

describe("AddressBar navigation shortcuts", () => {
  it("moves through the address history on Alt+Arrow", async () => {
    const { dispatch, user } = renderBar();
    await user.keyboard("{Alt>}{ArrowLeft}{/Alt}");
    expect(dispatch).toHaveBeenCalledWith({ type: "NAV_BACK" });
    await user.keyboard("{Alt>}{ArrowRight}{/Alt}");
    expect(dispatch).toHaveBeenCalledWith({ type: "NAV_FORWARD" });
  });

  it("leaves a bare arrow key to whatever else is listening", async () => {
    const { dispatch, user } = renderBar();
    await user.keyboard("{ArrowLeft}{ArrowRight}");
    // The disassembly view owns the unmodified arrows; a handler that dropped
    // the altKey test would steal them from it.
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("undoes and redoes annotations, telling the two apart by Shift", async () => {
    const { dispatch, user } = renderBar();
    await user.keyboard("{Control>}z{/Control}");
    expect(dispatch).toHaveBeenCalledWith({ type: "UNDO_ANNOTATION" });
    dispatch.mockClear();
    await user.keyboard("{Control>}{Shift>}z{/Shift}{/Control}");
    expect(dispatch).toHaveBeenCalledWith({ type: "REDO_ANNOTATION" });
    expect(dispatch).not.toHaveBeenCalledWith({ type: "UNDO_ANNOTATION" });
  });

  it("puts focus in the address field on G", async () => {
    const { user } = renderBar();
    expect(document.activeElement).not.toBe(addressInput());
    await user.keyboard("g");
    expect(document.activeElement).toBe(addressInput());
    // And the guard now holds: a second G is typed rather than re-triggering.
    await user.keyboard("g");
    expect((addressInput() as HTMLInputElement).value).toBe("g");
  });

  it("disables Back and Forward at the ends of the history", () => {
    renderBar({ addressHistory: [], historyIndex: -1 });
    const back = screen.getByTitle("Back (Alt+Left)");
    const forward = screen.getByTitle("Forward (Alt+Right)");
    expect((back as HTMLButtonElement).disabled).toBe(true);
    expect((forward as HTMLButtonElement).disabled).toBe(true);
  });

  it("enables the direction that has somewhere to go", () => {
    renderBar({ addressHistory: [0x1000, 0x2000, 0x3000], historyIndex: 1 });
    expect((screen.getByTitle("Back (Alt+Left)") as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByTitle("Forward (Alt+Right)") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("AddressBar go-to-address", () => {
  it("navigates on a hex address, with or without the 0x", async () => {
    const { dispatch, user } = renderBar();
    await user.type(addressInput(), "140001000{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001000 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
    dispatch.mockClear();
    await user.type(addressInput(), "0x1234{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x1234 });
  });

  it("clears the field after a successful jump", async () => {
    const { user } = renderBar();
    await user.type(addressInput(), "1000{Enter}");
    expect((addressInput() as HTMLInputElement).value).toBe("");
  });

  it("refuses a non-address and keeps what was typed", async () => {
    const { dispatch, user } = renderBar();
    await user.type(addressInput(), "zzz{Enter}");
    expect(dispatch).not.toHaveBeenCalled();
    // Left in place so it can be corrected rather than retyped.
    expect((addressInput() as HTMLInputElement).value).toBe("zzz");
  });

  it("offers a matching function and jumps to it on Enter", async () => {
    const { dispatch, user } = renderBar({ functions: FUNCS });
    await user.type(addressInput(), "sub_401040");
    // The suggestion list is debounced by 80ms.
    await waitFor(() => expect(screen.getByText("sub_401040")).toBeTruthy());
    await user.keyboard("{ArrowDown}{Enter}");
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: IMAGE_BASE + 0x1040,
    });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("prefers a rename over the detected name in the suggestions", async () => {
    const { user } = renderBar({
      functions: FUNCS,
      renames: { [FUNCS[0].address]: "DriverEntry" },
    });
    await user.type(addressInput(), "DriverEntry");
    await waitFor(() => expect(screen.getByText("DriverEntry")).toBeTruthy());
    expect(screen.queryByText("sub_401000")).toBeNull();
  });
});

describe("AddressBar engine status", () => {
  /**
   * peek-a-bin-b3jn, the tab bar's half. The two branches are siblings keyed on
   * `disasmFailed` and `!disasmReady && !disasmFailed`, and the defect was that
   * a rejection never clears `disasmReady` — so the surface went on saying
   * "Loading engine..." for the rest of the session while the banner above said
   * it had failed. What matters is the EXCLUSIVITY, which is why each test
   * asserts the absence of the other message and not merely the presence of one.
   */
  it("says the engine failed, and stops claiming it is loading", () => {
    renderBar({ disasmFailed: "WASM instantiate failed", disasmReady: false });
    expect(screen.getByText("Engine unavailable")).toBeTruthy();
    expect(screen.queryByText("Loading engine...")).toBeNull();
  });

  it("carries the failure message where it can be read", () => {
    renderBar({ disasmFailed: "WASM instantiate failed", disasmReady: false });
    // The `title` is the only place the reason survives; the visible text is a
    // fixed string. jsdom cannot say whether a tooltip appears — this asserts
    // the attribute that a browser would build one from.
    expect(screen.getByTitle("WASM instantiate failed")).toBeTruthy();
  });

  it("spins only while the engine is genuinely still loading", () => {
    renderBar({ disasmReady: false, disasmFailed: null });
    expect(screen.getByText("Loading engine...")).toBeTruthy();
    expect(screen.queryByText("Engine unavailable")).toBeNull();
  });

  it("says nothing at all once the engine is up", () => {
    renderBar({ disasmReady: true, disasmFailed: null });
    expect(screen.queryByText("Loading engine...")).toBeNull();
    expect(screen.queryByText("Engine unavailable")).toBeNull();
  });
});

describe("AddressBar current address", () => {
  it("pads the VA to the image's own width", () => {
    renderBar({ currentAddress: 0x140001000 });
    // 16 digits for PE32+, which is what the harness fixture is.
    expect(screen.getByText(/VA: 0x/).textContent).toBe("VA: 0x0000000140001000");
  });
});

describe("AddressBar recent addresses", () => {
  it("opens on Alt+H and lists the history newest first", async () => {
    const { user } = renderBar({
      functions: FUNCS,
      addressHistory: [IMAGE_BASE + 0x1000, IMAGE_BASE + 0x1040],
      historyIndex: 1,
    });
    await user.keyboard("{Alt>}h{/Alt}");
    const panel = screen.getByText("Recent Addresses").parentElement as HTMLElement;
    const rows = within(panel).getAllByRole("button");
    // Newest first: the last address visited heads the list.
    expect(rows[0].textContent).toContain("0x140001040");
    // And it is resolved to its containing function, which is the whole reason
    // the dropdown is more useful than the raw history array.
    expect(rows[0].textContent).toContain("sub_401040");
  });

  it("jumps to a row and closes", async () => {
    const { dispatch, user } = renderBar({
      addressHistory: [IMAGE_BASE + 0x1000],
      historyIndex: 0,
    });
    await user.keyboard("{Alt>}h{/Alt}");
    const panel = screen.getByText("Recent Addresses").parentElement as HTMLElement;
    await user.click(within(panel).getAllByRole("button")[0]);
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: IMAGE_BASE + 0x1000,
    });
    expect(screen.queryByText("Recent Addresses")).toBeNull();
  });
});
