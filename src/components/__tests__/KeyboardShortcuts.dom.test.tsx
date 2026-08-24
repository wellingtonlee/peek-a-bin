// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { KeyboardShortcuts, SHORTCUT_GROUPS } from "../KeyboardShortcuts";

/**
 * What rendering `KeyboardShortcuts` adds over `keyboardShortcuts.test.ts`, and
 * deliberately no more.
 *
 * That suite is the substantive one: it reads `SHORTCUT_GROUPS` and checks it
 * against `docs/keyboard.md`, which is the claim worth making about the content.
 * It reads the exported DATA, though, and this component is the only thing that
 * puts the data on a screen — so a dropped `.map`, a filtered category or a
 * `slice` would leave every one of those tests green while the panel showed
 * less than it documents. That gap is what the first test below closes, and it
 * closes it as an invariant over the whole table rather than as a list of
 * shortcuts that would then have to be maintained twice.
 *
 * The second thing only a render can reach is the `key.split(" / ")` display
 * rule, which turns one table entry into several `<kbd>` elements. It is pure
 * presentation, it has never had a test of any kind, and it is the reason the
 * panel shows "↑ / ↓" as two keys and "Ctrl+Shift+Z" as one.
 */

function setup() {
  const onClose = vi.fn();
  render(<KeyboardShortcuts open onClose={onClose} />);
  return { onClose, user: userEvent.setup() };
}

describe("KeyboardShortcuts panel contents", () => {
  it("puts every documented shortcut on the screen", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    // An invariant over the table, so a shortcut added tomorrow is covered
    // today. `getByText` throws on a miss and on an ambiguous match, and several
    // actions repeat across categories ("Follow branch target" is in Navigation
    // and in Graph), so this counts rather than looks up.
    let entries = 0;
    for (const group of SHORTCUT_GROUPS) {
      expect(within(dialog).getAllByText(group.category).length).toBeGreaterThan(0);
      for (const s of group.shortcuts) {
        expect(within(dialog).getAllByText(s.action).length).toBeGreaterThan(0);
        entries++;
      }
    }
    // Liveness: a loop over an empty table asserts nothing at all.
    expect(entries).toBeGreaterThan(20);
    expect(SHORTCUT_GROUPS.length).toBeGreaterThan(5);
  });

  it("renders a combined shortcut as one key per alternative", () => {
    setup();
    const row = screen.getByText("Undo / Redo").parentElement;
    expect(row).toBeTruthy();
    // "Ctrl+Z / Ctrl+Shift+Z" is two alternatives, so two <kbd>s and a separator
    // — not one <kbd> containing a slash.
    const keys = Array.from(row?.querySelectorAll("kbd") ?? []).map((k) => k.textContent);
    expect(keys).toEqual(["Ctrl+Z", "Ctrl+Shift+Z"]);
  });

  it("leaves a shortcut with no alternatives as a single key", () => {
    setup();
    const row = screen.getByText("Toggle AI chat panel").parentElement;
    const keys = Array.from(row?.querySelectorAll("kbd") ?? []).map((k) => k.textContent);
    // The split is on " / " with spaces, so a chord's own "+" is untouched and a
    // key that merely contains a slash is not torn in half.
    expect(keys).toEqual(["Ctrl+Shift+A"]);
  });
});

describe("KeyboardShortcuts dialog", () => {
  it("takes its accessible name from its own heading", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-labelledby")).toBe("keyboard-shortcuts-title");
    expect(screen.getByRole("dialog", { name: "Keyboard Shortcuts" })).toBe(dialog);
  });

  it("closes on Escape, which used to be a window-level listener", async () => {
    const { user, onClose } = setup();
    // The component's own comment records the change: Escape is handled on the
    // dialog now, which only works because Modal puts focus inside it on open.
    expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders nothing at all when closed", () => {
    render(<KeyboardShortcuts open={false} onClose={vi.fn()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
