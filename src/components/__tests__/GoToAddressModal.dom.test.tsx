// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GoToAddressModal } from "../GoToAddressModal";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * `GoToAddressModal`'s three address modes and what each one dispatches.
 *
 * The arithmetic is the point and it is not pure — VA is the identity, RVA adds
 * the image base, and File Offset has to find the section whose raw window
 * contains the offset and re-add its virtual address. That last one is the only
 * reverse section mapping in the app, it lives inline in the component, and it
 * had no test of any kind: not a unit test, because it is a `useMemo` inside a
 * component, and not a pure-function test, because it was never extracted.
 *
 * The offsets below are read out of the fixture's own parsed section table
 * rather than written down, so a change to the fixture layout cannot leave a
 * test asserting an address that no section contains any more.
 *
 * SCOPE: jsdom, so this is the component's logic and the attributes it emits.
 * Nothing here says a browser agrees about focus, and nothing says anything
 * about how any of it looks.
 */

function setup(over: Parameters<typeof stateWithPE>[1] = {}) {
  const dispatch = vi.fn();
  const onClose = vi.fn();
  const pe = harnessPE();
  render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <GoToAddressModal open onClose={onClose} />
    </AppHarness>,
  );
  return { dispatch, onClose, pe, user: userEvent.setup() };
}

const field = () => screen.getByPlaceholderText("Enter hex address...");
const go = () => screen.getByRole("button", { name: "Go" }) as HTMLButtonElement;
const hex = (n: number) => n.toString(16).toUpperCase();

describe("GoToAddressModal address modes", () => {
  it("treats a VA as itself", async () => {
    const { user, dispatch, onClose } = setup();
    await user.type(field(), "140001234");
    expect(screen.getByText(`Resolves to VA: 0x${hex(0x140001234)}`)).toBeTruthy();
    await user.click(go());
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001234 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("adds the image base to an RVA", async () => {
    const { user, dispatch } = setup();
    await user.click(screen.getByRole("button", { name: "RVA" }));
    await user.type(field(), "1234");
    expect(screen.getByText(`Resolves to VA: 0x${hex(IMAGE_BASE + 0x1234)}`)).toBeTruthy();
    await user.click(go());
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: IMAGE_BASE + 0x1234 });
  });

  it("maps a file offset back through the section that contains it", async () => {
    const { user, dispatch, pe } = setup();
    // Derived from the fixture, never written down: pick a real section and an
    // offset a few bytes into it, so the result exercises the whole formula
    // (base + virtualAddress + offsetInSection) rather than any degenerate case.
    const sec = pe.sections.find((s) => s.sizeOfRawData > 8);
    expect(sec).toBeTruthy();
    if (!sec) return;
    const within = 6;
    const expected = IMAGE_BASE + sec.virtualAddress + within;
    await user.click(screen.getByRole("button", { name: "File Offset" }));
    await user.type(field(), hex(sec.pointerToRawData + within));
    expect(screen.getByText(`Resolves to VA: 0x${hex(expected)}`)).toBeTruthy();
    await user.click(go());
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: expected });
  });

  it("refuses a file offset no section contains", async () => {
    const { user, dispatch, pe } = setup();
    const past = Math.max(...pe.sections.map((s) => s.pointerToRawData + s.sizeOfRawData)) + 0x1000;
    await user.click(screen.getByRole("button", { name: "File Offset" }));
    await user.type(field(), hex(past));
    expect(screen.getByText("No section contains this file offset")).toBeTruthy();
    // Refusing means the Go button is unusable, not that it navigates somewhere
    // wrong — a disabled control is the honest form of "there is no answer".
    expect(go().disabled).toBe(true);
    await user.click(go());
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("re-resolves the same digits when the mode changes under them", async () => {
    const { user } = setup();
    await user.type(field(), "1234");
    expect(screen.getByText(`Resolves to VA: 0x${hex(0x1234)}`)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "RVA" }));
    expect(screen.getByText(`Resolves to VA: 0x${hex(IMAGE_BASE + 0x1234)}`)).toBeTruthy();
  });
});

describe("GoToAddressModal input handling", () => {
  it("drops everything that is not a hex digit as it is typed", async () => {
    const { user } = setup();
    await user.type(field(), "0xZZ12g34!!");
    // Including the `x` of an 0x prefix: what survives is 0, 1, 2, 3, 4.
    expect((field() as HTMLInputElement).value).toBe("01234");
    expect(screen.getByText(`Resolves to VA: 0x${hex(0x1234)}`)).toBeTruthy();
  });

  it("offers nothing and refuses to go while the field is empty", () => {
    setup();
    expect(screen.queryByText(/Resolves to VA/)).toBeNull();
    expect(screen.queryByText("Invalid address")).toBeNull();
    expect(go().disabled).toBe(true);
  });

  it("submits on Enter", async () => {
    const { user, dispatch, onClose } = setup();
    await user.type(field(), "140001000{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001000 });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("keeps ordinary typing away from the window-level hotkeys", async () => {
    const onWindowKey = vi.fn();
    const { user } = setup();
    // App binds its shortcuts on `window`, so a keystroke that reaches it while
    // a dialog is open fires them — Ctrl+G would close the dialog being typed
    // into. The field stops propagation for everything except Tab and Escape.
    window.addEventListener("keydown", onWindowKey);
    try {
      await user.type(field(), "4g");
      expect(onWindowKey).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener("keydown", onWindowKey);
    }
  });

  it("lets Escape and Tab past, because the dialog above needs them", async () => {
    const { user, onClose } = setup();
    // The other half of the rule above, and it cannot be checked at `window`:
    // Modal's own handler calls stopPropagation on Escape deliberately, so
    // nothing outside the dialog sees it either way. What distinguishes
    // "forwarded" from "swallowed" is whether the dialog reacts.
    expect(document.activeElement).toBe(field());
    await user.tab();
    expect(document.activeElement).not.toBe(field());
    expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);

    field().focus();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("cancels without navigating", async () => {
    const { user, dispatch, onClose } = setup();
    await user.type(field(), "140001000");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(dispatch).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("GoToAddressModal with no file loaded", () => {
  it("calls a well-formed address invalid, because there is nothing to resolve against", async () => {
    const dispatch = vi.fn();
    render(
      <AppHarness state={{ ...stateWithPE(harnessPE()), peFile: null }} dispatch={dispatch}>
        <GoToAddressModal open onClose={vi.fn()} />
      </AppHarness>,
    );
    const user = userEvent.setup();
    await user.type(field(), "1234");
    // This is the ONLY route to the "Invalid address" branch: the input filter
    // has already removed every non-hex character, so with a PE loaded VA and
    // RVA can never fail to resolve. Recorded as the behaviour it is.
    expect(screen.getByText("Invalid address")).toBeTruthy();
    expect(go().disabled).toBe(true);
  });
});

describe("GoToAddressModal dialog", () => {
  it("takes its accessible name from its own heading", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-labelledby")).toBe("goto-address-title");
    expect(screen.getByRole("dialog", { name: "Go to Address" })).toBe(dialog);
  });

  it("opens with focus in the address field", () => {
    setup();
    // Unlike the palette this one is load-bearing: three mode buttons are
    // focusable and come first in document order, so without `initialFocusRef`
    // the Modal would focus "VA".
    expect(document.activeElement).toBe(field());
  });

  it("is dismissible — Escape and the backdrop both close it", async () => {
    const { user, onClose } = setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("keeps Tab inside the dialog", async () => {
    const { user } = setup();
    const dialog = screen.getByRole("dialog");
    for (let i = 0; i < 10; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("renders nothing at all when closed", () => {
    render(
      <AppHarness state={stateWithPE(harnessPE())} dispatch={vi.fn()}>
        <GoToAddressModal open={false} onClose={vi.fn()} />
      </AppHarness>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
