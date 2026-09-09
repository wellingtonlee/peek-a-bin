// @vitest-environment jsdom

import "../../test/domSetup";
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { streamChat } from "../../llm/client";
import { saveProfiles } from "../../llm/settings";
import { useAIChat } from "../useAIChat";

/**
 * `sendMessage`'s ACCEPTANCE CONTRACT (`peek-a-bin-r2u5`).
 *
 * The hook refuses to send in three separate places — blank content, a stream
 * already in flight, and the API-key gate — and used to return `void` from all
 * three, so a caller could not tell a refusal from a send. `AIChatPanel` cleared
 * its textarea unconditionally after calling, so the API-key refusal DESTROYED
 * the question the user had typed.
 *
 * WHY THE THREE REFUSALS ARE TESTED HERE AND NOT THROUGH THE PANEL. Only one of
 * them is reachable from a rendered panel: `AIChatPanel` refuses to call
 * `sendMessage` at all with blank input, and while a stream is in flight it
 * disables the textarea and swaps Send for Stop — so the blank and streaming
 * refusals never destroyed anything, and a rendered test of them would be green
 * both before and after the fix. The bead says the streaming case "ALSO discards
 * the input today"; measured against the panel, it does not. What was actually
 * broken is one path, and what is being pinned here is the CONTRACT all three
 * share, which is the thing a future caller — or a panel whose own guards move —
 * depends on. The rendered end-to-end assertion for the path that was really
 * broken lives in `apiKeyGate.dom.test.tsx`.
 *
 * `src/llm/client.ts` is mocked to keep the network out. `streamChat` never
 * calls back, which is what leaves the hook streaming for the second refusal.
 * `hasApiKey()` is NOT mocked — the precondition is `localStorage`, exactly as a
 * user's is.
 */

vi.mock("../../llm/client", () => ({
  streamChat: vi.fn(),
  streamEnhance: vi.fn(),
}));

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

describe("useAIChat sendMessage reports whether it accepted the message", () => {
  it("accepts an ordinary message, and says so", () => {
    withApiKey();
    const { result } = renderHook(() => useAIChat(null, null, null));

    let accepted: boolean | undefined;
    act(() => {
      accepted = result.current.sendMessage("what does sub_401000 do?");
    });

    // The liveness half: if this row could not go true, every `false` below
    // would be satisfied by a `sendMessage` that had simply stopped working.
    expect(accepted).toBe(true);
    expect(vi.mocked(streamChat)).toHaveBeenCalledTimes(1);
    expect(result.current.messages).toHaveLength(2); // the question, and the empty reply
  });

  it("refuses blank content, and says so", () => {
    withApiKey();
    const { result } = renderHook(() => useAIChat(null, null, null));

    let accepted: boolean | undefined;
    act(() => {
      accepted = result.current.sendMessage("   \n  ");
    });

    expect(accepted).toBe(false);
    expect(vi.mocked(streamChat)).not.toHaveBeenCalled();
    expect(result.current.messages).toHaveLength(0);
  });

  it("refuses a second message while one is still streaming, and says so", () => {
    withApiKey();
    const { result } = renderHook(() => useAIChat(null, null, null));

    act(() => {
      result.current.sendMessage("first");
    });
    // `streamChat` is a mock that never calls back, so the hook is still
    // streaming — the state a real caller is in mid-answer.
    expect(result.current.streaming).toBe(true);

    let accepted: boolean | undefined;
    act(() => {
      accepted = result.current.sendMessage("second");
    });

    expect(accepted).toBe(false);
    expect(vi.mocked(streamChat)).toHaveBeenCalledTimes(1);
    // The refused question is nowhere in the transcript, which is exactly why
    // the caller has to be the one holding on to it.
    expect(result.current.messages.map((m) => m.content)).not.toContain("second");
  });

  it("refuses when no API key is configured, and says so", () => {
    localStorage.clear(); // the state a first-time user is in
    const { result } = renderHook(() => useAIChat(null, null, null));

    let accepted: boolean | undefined;
    act(() => {
      accepted = result.current.sendMessage("what does sub_401000 do?");
    });

    expect(accepted).toBe(false);
    expect(vi.mocked(streamChat)).not.toHaveBeenCalled();
    expect(result.current.messages).toHaveLength(0);
    // ...and the reason is left where the caller already renders it, which is
    // why the caller is told only *that* it was refused.
    expect(result.current.error).toBeTruthy();
  });
});
