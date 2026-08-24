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

/** The tab buttons, in DOM order, identified by carrying a `(N)` in the title. */
function tabButtons(): HTMLButtonElement[] {
  return screen
    .getAllByRole("button")
    .filter((b): b is HTMLButtonElement => /\(\d\)$/.test(b.getAttribute("title") ?? ""));
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
    // Asserted through the component's own class because these buttons carry no
    // `aria-selected` — they are not in a `role="tablist"`, so there is no ARIA
    // state to read. That is a real a11y gap and NOT fixed here; this test
    // records what the component does, and would keep passing if the gap were
    // closed by adding the attribute (the class would remain).
    expect(active).toHaveLength(1);
    expect(active[0].textContent).toBe(VIEW_TAB_LABELS.strings);
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
