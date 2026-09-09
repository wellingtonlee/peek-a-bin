// @vitest-environment jsdom

import "../../test/domSetup";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIChatPanel } from "../../components/AIChatPanel";
import { DecompileView } from "../../components/DecompileView";
import { streamChat, streamEnhance } from "../../llm/client";
import { NO_API_KEY_MESSAGE, saveProfiles } from "../../llm/settings";
import { useAIChat } from "../useAIChat";
import { useDecompileTabs } from "../useDecompileTabs";

/**
 * THE `hasApiKey()` GATE, AS A USER MEETS IT (`peek-a-bin-6jdg`).
 *
 * The defect: every AI entry point opened with
 *
 *     if (!hasApiKey()) {
 *       window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
 *       return;
 *     }
 *
 * so a click on Send or Enhance made the Settings dialog appear and said
 * NOTHING. What was reported was "they just seem to open the Settings panel,
 * which does not seem correct" — the buttons read as broken. Two of those sites
 * survive `peek-a-bin-1xc5` and both are asserted here.
 *
 * WHY THIS FILE RENDERS RATHER THAN CALLING THE HOOK. The claim being made is
 * that *the user is told*, and the only thing that settles it is a string in the
 * document. A spy on `window.dispatchEvent` — or on the reducer — would say the
 * gate fired, which was never in doubt; it was true throughout the defect.
 * CLAUDE.md's `ResizeHandle` entry is the standing statement of that failure
 * mode: "a `vi.fn()` cannot see this class: it says `onResizeEnd` was *called*,
 * never what a real caller would have stored." So each harness below is the
 * real hook wired to the real panel exactly as `DisassemblyView` wires it, and
 * every assertion is on rendered text.
 *
 * `hasApiKey()` is not mocked. It reads `localStorage` through `loadSettings()`,
 * so the precondition is controlled by controlling the store — an empty store
 * yields an empty `apiKey`, which is the state a first-time user is in.
 *
 * `src/llm/client.ts` IS mocked, and only to keep the network out: with a key
 * present the chat path really does reach `streamChat`, and that call is the
 * evidence that the gate opened rather than that the message is simply never
 * rendered.
 *
 * WHAT A GREEN RUN HERE DOES NOT MEAN. jsdom performs no layout, so nothing
 * below says the banner is visible, unclipped, or anywhere in particular on
 * screen; Tailwind is not loaded, so `text-red-400` is a string and not a
 * colour. And the gate still has no retry — saving a key does not resume the
 * action that was refused — which the message deliberately does not promise.
 */

vi.mock("../../llm/client", () => ({
  streamChat: vi.fn(),
  streamEnhance: vi.fn(),
}));

/** The state a user who has never opened Settings is in. */
function withoutApiKey(): void {
  localStorage.clear();
}

/** An active profile holding a key, written through the real store writer. */
function withApiKey(): void {
  localStorage.clear();
  saveProfiles({
    activeId: "p1",
    profiles: [
      {
        id: "p1",
        name: "Default",
        provider: "anthropic",
        apiKey: "sk-test-key",
        model: "claude-test",
        baseUrl: "https://example.invalid",
        enhanceSource: "pseudocode",
      },
    ],
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

afterEach(() => {
  localStorage.clear();
});

// ── Harnesses: the real hooks, wired the way DisassemblyView wires them ──

function ChatHarness() {
  const chat = useAIChat(null, null, null);
  return <AIChatPanel chat={chat} onClose={() => {}} onRename={() => {}} />;
}

function DecompileHarness() {
  const d = useDecompileTabs({
    currentFunc: null,
    pe: null,
    instructions: [],
    xrefMap: new Map(),
    functions: [],
    renames: {},
    buildFunctionAsm: () => "",
  });
  return (
    <DecompileView
      code={d.activeCode}
      loading={d.activeLoading}
      error={d.activeError}
      activeTab={d.tabsState.activeTab}
      onTabChange={(tab) => d.triggerTab(tab)}
      aiMode={d.tabsState.aiMode}
      onEnhance={() => d.triggerAI("enhance")}
      onExplain={() => d.triggerAI("explain")}
      onCancelAI={d.cancelAI}
      onClose={() => {}}
    />
  );
}

/**
 * The same harness plus one out-of-band caller of `triggerAI`.
 *
 * `DecompileView` renders Explain/Enhance only while its AI tab is active, so
 * every caller that exists TODAY is already on that tab and the gate's SET_TAB
 * is a no-op for them. This button is not a path a browser produces; it stands
 * in for any other caller of the hook's public `triggerAI`, and it is here so
 * the half of the fix that makes the message *reachable* — the error goes on
 * one tab, and `activeError` is the ACTIVE tab's — is pinned rather than left
 * as a comment for someone to delete.
 */
function DecompileHarnessWithOutOfBandTrigger() {
  const d = useDecompileTabs({
    currentFunc: null,
    pe: null,
    instructions: [],
    xrefMap: new Map(),
    functions: [],
    renames: {},
    buildFunctionAsm: () => "",
  });
  return (
    <>
      <button type="button" onClick={() => d.triggerAI("enhance")}>
        trigger enhance out of band
      </button>
      <DecompileView
        code={d.activeCode}
        loading={d.activeLoading}
        error={d.activeError}
        activeTab={d.tabsState.activeTab}
        onTabChange={(tab) => d.triggerTab(tab)}
        aiMode={d.tabsState.aiMode}
        onEnhance={() => d.triggerAI("enhance")}
        onExplain={() => d.triggerAI("explain")}
        onCancelAI={d.cancelAI}
        onClose={() => {}}
      />
    </>
  );
}

/** Type a message into the chat box and press Send. */
function sendChat(text: string): void {
  const box = screen.getByPlaceholderText("Ask about this binary...");
  fireEvent.change(box, { target: { value: text } });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
}

/** Switch the decompile panel to its AI tab, where the two buttons live. */
function openAiTab(): void {
  fireEvent.click(screen.getByRole("button", { name: "AI" }));
}

describe("AI chat with no API key configured", () => {
  it("tells the user why, rather than only opening Settings", () => {
    withoutApiKey();
    render(<ChatHarness />);

    sendChat("what does sub_401000 do?");

    // The substance of the fix: a sentence naming the precondition and the
    // remedy is on the page. Asserted as the rendered text, not as a call.
    expect(screen.getByText(NO_API_KEY_MESSAGE)).toBeTruthy();
    expect(NO_API_KEY_MESSAGE).toContain("Settings");
  });

  it("still opens Settings — the dispatch was right and is kept", () => {
    withoutApiKey();
    const seen: Event[] = [];
    const listener = (e: Event) => seen.push(e);
    window.addEventListener("peek-a-bin:open-settings", listener);
    try {
      render(<ChatHarness />);
      sendChat("hello");
      expect(seen).toHaveLength(1);
    } finally {
      window.removeEventListener("peek-a-bin:open-settings", listener);
    }
  });

  it("sends nothing and adds no message to the transcript", () => {
    withoutApiKey();
    render(<ChatHarness />);

    sendChat("hello");

    expect(vi.mocked(streamChat)).not.toHaveBeenCalled();
    // The refused message must not appear as a user bubble: the gate returns
    // before ADD_USER, and the empty-state hint is still the whole transcript.
    expect(screen.getByText("Ask about the current binary or function.")).toBeTruthy();
    expect(screen.queryByText("hello")).toBeNull();
  });

  it("clears the explanation once a key is configured and the send goes through", () => {
    // The discriminator for "is this banner conditioned on the gate at all, or
    // does it just always render?" — with a key the request is made and no
    // banner is on the page.
    withApiKey();
    render(<ChatHarness />);

    sendChat("hello");

    expect(vi.mocked(streamChat)).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(NO_API_KEY_MESSAGE)).toBeNull();
  });
});

describe("decompile Enhance/Explain with no API key configured", () => {
  it("explains the refusal in the panel's own error banner (Enhance)", () => {
    withoutApiKey();
    render(<DecompileHarness />);
    openAiTab();

    fireEvent.click(screen.getByRole("button", { name: "Enhance" }));

    expect(screen.getByText(NO_API_KEY_MESSAGE)).toBeTruthy();
  });

  it("explains the refusal in the panel's own error banner (Explain)", () => {
    withoutApiKey();
    render(<DecompileHarness />);
    openAiTab();

    fireEvent.click(screen.getByRole("button", { name: "Explain" }));

    expect(screen.getByText(NO_API_KEY_MESSAGE)).toBeTruthy();
  });

  it("still opens Settings, and asks for nothing", () => {
    withoutApiKey();
    const seen: Event[] = [];
    const listener = (e: Event) => seen.push(e);
    window.addEventListener("peek-a-bin:open-settings", listener);
    try {
      render(<DecompileHarness />);
      openAiTab();
      fireEvent.click(screen.getByRole("button", { name: "Enhance" }));
      expect(seen).toHaveLength(1);
    } finally {
      window.removeEventListener("peek-a-bin:open-settings", listener);
    }
    expect(vi.mocked(streamEnhance)).not.toHaveBeenCalled();
  });

  it("shows no such banner before anything is asked for", () => {
    // Liveness: the banner is produced by the gate, not by mounting the panel
    // on its AI tab. Without this a test asserting the text could pass against
    // a panel that printed it unconditionally.
    withoutApiKey();
    render(<DecompileHarness />);
    openAiTab();

    expect(screen.queryByText(NO_API_KEY_MESSAGE)).toBeNull();
    expect(screen.getByText(/Choose/)).toBeTruthy();
  });

  it("puts the explanation on the tab that ends up showing", () => {
    // `activeError` is the ACTIVE tab's error, so a message written to a tab
    // that is not on screen is a message nobody reads. Driven from the Low Level
    // tab through the hook's public `triggerAI` — which is why the gate
    // dispatches SET_TAB beside LOAD_ERR. See the harness's own docstring for
    // what this button does and does not stand for.
    withoutApiKey();
    render(<DecompileHarnessWithOutOfBandTrigger />);
    // The panel opens on Low Level and is never switched to AI by the test:
    // the AI tab's empty-state prompt is not on the page yet.
    expect(screen.queryByText(/Choose/)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "trigger enhance out of band" }));

    expect(screen.getByText(NO_API_KEY_MESSAGE)).toBeTruthy();
    // ...and the AI tab is what is now showing, which is what made it readable.
    expect(screen.getByText(/Choose/)).toBeTruthy();
  });
});
