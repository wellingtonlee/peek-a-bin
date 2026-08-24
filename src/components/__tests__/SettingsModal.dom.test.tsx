// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsModal } from "../SettingsModal";

/**
 * `SettingsModal`, the one dialog in the app that is deliberately NOT
 * dismissible, plus its Ghidra "Test Connection" round trip.
 *
 * `modalScaffold.test.ts` pins `accidentalDismissAllowed` as a rule over two
 * booleans, and `Modal.dom.test.tsx` pins that `closeOnEscape={false}` is
 * honoured. Neither says this dialog passes `false`, which is the part that can
 * be changed by accident — and the reason it passes `false` is a user-facing
 * one: the dialog holds edits (an API key, a model, a font size) that are not
 * committed until Save, so an idle Escape throws them away.
 *
 * The connection test is here because it is the only network call any dialog
 * makes. `fetch` is stubbed; nothing reaches a real server, and a test that did
 * would be a test of whether a Ghidra server happens to be running.
 *
 * SCOPE, and one caveat specific to THIS dialog. jsdom loads no stylesheet and
 * Tailwind is deliberately not part of the test config, so `className="hidden"`
 * carries no `display: none` — the permanently-present `<input type="file">` on
 * the Theme tab is therefore VISIBLE to `focusableWithin` here and invisible to
 * it in a browser. That is the exact case `focusableWithin`'s `offsetParent`
 * filter exists for, so the browser's tab ORDER on that tab is not reproduced
 * below and is not asserted; what is asserted — that focus never leaves the
 * dialog — is true under either reading.
 */

function setup() {
  const onClose = vi.fn();
  render(<SettingsModal open onClose={onClose} />);
  return { onClose, user: userEvent.setup() };
}

const dialog = () => screen.getByRole("dialog");

function stubFetch(impl: () => Promise<Response>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(impl);
}

const jsonResponse = (body: unknown, ok = true, status = 200) =>
  ({ ok, status, json: async () => body }) as Response;

describe("SettingsModal is deliberately non-dismissible", () => {
  it("does not close on Escape", async () => {
    const { user, onClose } = setup();
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("renders no click-to-dismiss backdrop at all", () => {
    setup();
    // Not "a backdrop that ignores clicks" — Modal omits it entirely, so there
    // is no target to click by accident and no stray button in the tree.
    expect(screen.queryByRole("button", { name: "Close dialog" })).toBeNull();
  });

  it("still offers a visible way out, which is what makes the refusal legitimate", async () => {
    const { user, onClose } = setup();
    // WCAG 2.1.2: withholding Escape is only acceptable while an explicit
    // control remains. Both of these leave the dialog.
    expect(screen.getByRole("button", { name: "Save" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("SettingsModal dialog semantics", () => {
  it("takes its accessible name from its own heading", () => {
    setup();
    expect(dialog().getAttribute("aria-labelledby")).toBe("settings-title");
    expect(screen.getByRole("dialog", { name: "Settings" })).toBe(dialog());
    expect(dialog().getAttribute("aria-modal")).toBe("true");
  });

  it("keeps Tab inside the dialog, on every tab panel", async () => {
    const { user } = setup();
    for (const tab of ["AI", "Ghidra", "Display", "Theme"]) {
      await user.click(screen.getByRole("button", { name: tab }));
      for (let i = 0; i < 12; i++) {
        await user.tab();
        expect(dialog().contains(document.activeElement)).toBe(true);
      }
    }
  });

  it("swaps the panel contents when a tab is chosen", async () => {
    const { user } = setup();
    expect(screen.queryByText("Decompilation Server")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Ghidra" }));
    expect(screen.getByText("Decompilation Server")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Display" }));
    expect(screen.queryByText("Decompilation Server")).toBeNull();
  });

  it("renders nothing at all when closed", () => {
    render(<SettingsModal open={false} onClose={vi.fn()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("SettingsModal Ghidra connection test", () => {
  let fetchSpy: ReturnType<typeof stubFetch> | null = null;

  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    fetchSpy?.mockRestore();
    fetchSpy = null;
    localStorage.clear();
  });

  /** Open the dialog, reach the Ghidra panel and enable the server controls. */
  async function ghidraPanel(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("button", { name: "Ghidra" }));
    await user.click(screen.getByRole("checkbox", { name: /Enable Ghidra server/ }));
    return screen.getByRole("button", { name: "Test Connection" });
  }

  it("reports the server version on success", async () => {
    fetchSpy = stubFetch(async () => jsonResponse({ version: "2.1", ghidraVersion: "11.0" }));
    const { user } = setup();
    const button = await ghidraPanel(user);
    await user.click(button);
    await waitFor(() => expect(screen.getByText(/Connected/)).toBeTruthy());
    expect(screen.getByText("Connected — server v2.1 (Ghidra 11.0)")).toBeTruthy();
    // The URL is the one from the settings, and the call really was made.
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0][0])).toMatch(/\/api\/v1\/ping$/);
  });

  it("omits the Ghidra version when the server does not report one", async () => {
    fetchSpy = stubFetch(async () => jsonResponse({ version: "2.1", ghidraVersion: null }));
    const { user } = setup();
    await user.click(await ghidraPanel(user));
    await waitFor(() => expect(screen.getByText("Connected — server v2.1")).toBeTruthy());
  });

  it("shows the server's own message when the request is refused", async () => {
    fetchSpy = stubFetch(async () => jsonResponse({ detail: "bad api key" }, false, 401));
    const { user } = setup();
    await user.click(await ghidraPanel(user));
    // `GhidraClient.throwWithDetail` prefers the body's `detail` over its own
    // status line, and this is the only place that preference is observable.
    await waitFor(() => expect(screen.getByText("bad api key")).toBeTruthy());
    expect(screen.queryByText(/Connected/)).toBeNull();
  });

  it("shows a transport failure rather than swallowing it", async () => {
    fetchSpy = stubFetch(async () => {
      throw new TypeError("Failed to fetch");
    });
    const { user } = setup();
    await user.click(await ghidraPanel(user));
    await waitFor(() => expect(screen.getByText("Failed to fetch")).toBeTruthy());
  });

  it("disables the button while the request is in flight", async () => {
    let release: () => void = () => {};
    const pending = new Promise<void>((r) => {
      release = r;
    });
    fetchSpy = stubFetch(async () => {
      await pending;
      return jsonResponse({ version: "2.1" });
    });
    const { user } = setup();
    const button = (await ghidraPanel(user)) as HTMLButtonElement;
    await user.click(button);
    const testing = screen.getByRole("button", { name: "Testing..." }) as HTMLButtonElement;
    expect(testing.disabled).toBe(true);
    release();
    await waitFor(() => expect(screen.getByText(/Connected/)).toBeTruthy());
  });

  it("hides the connection controls entirely while the server is disabled", async () => {
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: "Ghidra" }));
    expect(screen.queryByRole("button", { name: "Test Connection" })).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: /Enable Ghidra server/ }));
    expect(screen.getByRole("button", { name: "Test Connection" })).toBeTruthy();
  });
});
