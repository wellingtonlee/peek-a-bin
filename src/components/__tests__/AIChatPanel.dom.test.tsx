// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { UseAIChatResult } from "../../hooks/useAIChat";
import type { ChatMessage } from "../../llm/types";
import { AIChatPanel } from "../AIChatPanel";

/**
 * The AI chat panel, rendered for the first time.
 *
 * `AIChatPanel` was one of three surfaces in this app that no human and no test
 * had ever rendered. It is entirely prop-driven — `{ chat, onClose, onRename }`
 * — and `UseAIChatResult` is six fields, three of them callbacks, so the whole
 * component can be exercised against a PLAIN OBJECT. `useAIChat` itself is
 * never called here, which is what keeps `src/llm/client.ts`, `streamChat`, the
 * API key in localStorage and the network out of this file entirely: the hook is
 * `import type` only.
 *
 * SCOPE, and read this before trusting a row below. jsdom does no layout, so
 * nothing here says anything about geometry, overflow, the auto-growing
 * textarea's height, whether the message list scrolls, or whether any of it is
 * *visible*. Tailwind is deliberately not loaded (see `vitest.config.ts`), so
 * `whitespace-pre-wrap` carries no CSS and a newline surviving into a text node
 * is the most this can assert about it. `scrollIntoView` does not exist in jsdom
 * and is a no-op stand-in from `domSetup` — see the auto-scroll block for
 * exactly what that buys and what it does not.
 *
 * The one thing that is *only* observable by rendering is the rename-marker
 * round trip: `parseRenameActions` and the strip are module-private, so neither
 * a unit test nor any static instrument can see that the markers become buttons
 * AND leave the prose. That is the substance of this suite.
 */

function chatStub(over: Partial<UseAIChatResult> = {}): UseAIChatResult {
  return {
    messages: [],
    streaming: false,
    error: null,
    sendMessage: vi.fn(),
    clearChat: vi.fn(),
    cancelStream: vi.fn(),
    ...over,
  };
}

function renderPanel(over: Partial<UseAIChatResult> = {}) {
  const chat = chatStub(over);
  const onClose = vi.fn();
  const onRename = vi.fn();
  const view = render(<AIChatPanel chat={chat} onClose={onClose} onRename={onRename} />);
  return { chat, onClose, onRename, view, user: userEvent.setup() };
}

const assistant = (content: string): ChatMessage => ({ role: "assistant", content });
const user = (content: string): ChatMessage => ({ role: "user", content });

describe("AIChatPanel with nothing said yet", () => {
  it("explains what context is sent, rather than showing an empty box", () => {
    renderPanel();
    expect(screen.getByText("Ask about the current binary or function.")).toBeTruthy();
    expect(screen.getByText(/pseudocode and PE metadata are automatically included/)).toBeTruthy();
  });

  it("drops the hint as soon as there is a message", () => {
    renderPanel({ messages: [user("hi")] });
    expect(screen.queryByText("Ask about the current binary or function.")).toBeNull();
  });

  it("offers no Stop button when nothing is in flight", () => {
    renderPanel();
    expect(screen.queryByRole("button", { name: "Stop" })).toBeNull();
    expect(screen.getByRole("button", { name: "Send" })).toBeTruthy();
  });
});

describe("AIChatPanel message bubbles", () => {
  it("renders a user message verbatim, markdown syntax and all", () => {
    // The user half deliberately does NOT go through MarkdownRenderer: what
    // someone typed is shown back to them as they typed it.
    const { view } = renderPanel({ messages: [user("**not bold** and `not code`")] });
    expect(view.container.textContent).toContain("**not bold** and `not code`");
    expect(view.container.querySelector("strong")).toBeNull();
    expect(view.container.querySelector("code")).toBeNull();
  });

  it("keeps a user message's newlines in the DOM", () => {
    // WHAT THIS PROVES: React put the string in a text node unmangled. It says
    // nothing about the newline being *shown* — that is `whitespace-pre-wrap`,
    // a Tailwind class with no CSS behind it in this config.
    const { view } = renderPanel({ messages: [user("line one\nline two")] });
    expect(view.container.textContent).toContain("line one\nline two");
  });

  it("renders an assistant message as markdown", () => {
    renderPanel({ messages: [assistant("## Findings\n\nCalls `CreateFileW`.")] });
    expect(screen.getByRole("heading", { name: "Findings" })).toBeTruthy();
    const code = screen.getByText("CreateFileW");
    expect(code.tagName).toBe("CODE");
  });

  it("keeps the two roles apart in one conversation", () => {
    const { view } = renderPanel({
      messages: [user("what is **this**?"), assistant("It is **that**.")],
    });
    // Exactly one <strong>: the assistant's. The user's asterisks are literal.
    expect(view.container.querySelectorAll("strong")).toHaveLength(1);
    expect(screen.getByText("that").tagName).toBe("STRONG");
    expect(view.container.textContent).toContain("what is **this**?");
  });
});

describe("AIChatPanel rename markers", () => {
  it("turns a marker into an Apply button and takes it out of the prose", () => {
    // Both halves are behaviour. A marker that became a button but stayed in the
    // text would put raw protocol on screen; one that was stripped without
    // becoming a button would silently lose the model's suggestion.
    const { view } = renderPanel({
      messages: [assistant("This parses the header. [RENAME:0x401000:parse_header]")],
    });
    expect(screen.getByRole("button", { name: "Apply: parse_header" })).toBeTruthy();
    expect(view.container.textContent).toContain("This parses the header.");
    expect(view.container.textContent).not.toContain("[RENAME:");
    expect(view.container.textContent).not.toContain("0x401000");
  });

  it("calls onRename with the parsed address and the trimmed name", async () => {
    const { user: ui, onRename } = renderPanel({
      messages: [assistant("[RENAME:0x401000:  parse_header  ]")],
    });
    // The label is trimmed too — the trim happens in the parse, so the button
    // text and the dispatched name cannot disagree.
    await ui.click(screen.getByRole("button", { name: "Apply: parse_header" }));
    expect(onRename).toHaveBeenCalledTimes(1);
    expect(onRename).toHaveBeenCalledWith(0x401000, "parse_header");
  });

  it("reads the address as hex, in either case", async () => {
    const { user: ui, onRename } = renderPanel({
      messages: [assistant("[RENAME:0x4a1B00:mixed]")],
    });
    await ui.click(screen.getByRole("button", { name: "Apply: mixed" }));
    // 0x4a1B00 is 4857088. Read as decimal it would be 41; read with parseInt's
    // default radix on the "0x" form it would be the same number by luck, which
    // is why the fixture is a hex string no decimal reading can reproduce.
    expect(onRename).toHaveBeenCalledWith(0x4a1b00, "mixed");
  });

  it("names the address in the button's tooltip, uppercased", () => {
    renderPanel({ messages: [assistant("[RENAME:0x4a1b00:mixed]")] });
    const btn = screen.getByRole("button", { name: "Apply: mixed" });
    expect(btn.getAttribute("title")).toBe("Rename 0x4A1B00 → mixed");
  });

  it("offers one button per marker, in the order they appear", () => {
    renderPanel({
      messages: [assistant("Two: [RENAME:0x401000:first] and [RENAME:0x402000:second].")],
    });
    const labels = screen
      .getAllByRole("button")
      .map((b) => b.textContent)
      .filter((t) => t?.startsWith("Apply:"));
    expect(labels).toEqual(["Apply: first", "Apply: second"]);
  });

  it("does not scan a USER message for markers", () => {
    // A user asking about the protocol must not be handed a live rename button,
    // and their text must come back unedited.
    const { view } = renderPanel({ messages: [user("what does [RENAME:0x401000:x] mean?")] });
    expect(screen.queryByRole("button", { name: "Apply: x" })).toBeNull();
    expect(view.container.textContent).toContain("[RENAME:0x401000:x]");
  });

  it("parses markers in every message, not only the first", () => {
    // `RENAME_RE` is a module-level /g/ regex, and `parseRenameActions`
    // deliberately builds a FRESH one from `RENAME_RE.source` — the standard
    // guard against a shared `lastIndex` making the second and later matches of
    // a run start from wherever the previous one stopped.
    //
    // READ THIS BEFORE TRUSTING THE ROW AS A `lastIndex` GUARD. IT IS NOT ONE,
    // and that is measured, not assumed. Two perturbations were tried and BOTH
    // left this row green:
    //   * `const re = RENAME_RE` (drop the fresh copy) — an `exec`-until-null
    //     loop resets `lastIndex` to 0 on the terminating null match;
    //   * adding a `RENAME_RE.test(content)` guard, the classic dirtying call —
    //     the very next statement is `content.replace(RENAME_RE, "")`, and
    //     `RegExp.prototype[Symbol.replace]` sets `lastIndex` to 0 both before
    //     and after when the regex is global, so no dirt survives to the next
    //     message.
    // So the hazard is structurally neutralised by the strip, the fresh copy is
    // defensive rather than load-bearing, and no single-edit control can
    // discriminate. What this row DOES cover is the multi-message population:
    // three assistant turns each contributing their own button, in order.
    renderPanel({
      messages: [
        assistant("one [RENAME:0x401000:alpha]"),
        assistant("two [RENAME:0x402000:beta]"),
        assistant("three [RENAME:0x403000:gamma]"),
      ],
    });
    const labels = screen
      .getAllByRole("button")
      .map((b) => b.textContent)
      .filter((t) => t?.startsWith("Apply:"));
    expect(labels).toEqual(["Apply: alpha", "Apply: beta", "Apply: gamma"]);
  });

  it("shows no Apply row for a message with no markers", () => {
    renderPanel({ messages: [assistant("Just prose.")] });
    expect(screen.queryByRole("button", { name: /^Apply:/ })).toBeNull();
  });
});

describe("AIChatPanel input", () => {
  it("refuses to send until there is something other than whitespace", async () => {
    const { user: ui, chat } = renderPanel();
    const send = screen.getByRole("button", { name: "Send" }) as HTMLButtonElement;
    expect(send.disabled).toBe(true);

    await ui.type(screen.getByPlaceholderText("Ask about this binary..."), "   ");
    expect((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled).toBe(true);
    await ui.keyboard("{Enter}");
    expect(chat.sendMessage).not.toHaveBeenCalled();
  });

  it("sends what was typed and clears the box", async () => {
    const { user: ui, chat } = renderPanel();
    const box = screen.getByPlaceholderText("Ask about this binary...") as HTMLTextAreaElement;
    await ui.type(box, "what does sub_401000 do?");
    await ui.click(screen.getByRole("button", { name: "Send" }));
    expect(chat.sendMessage).toHaveBeenCalledWith("what does sub_401000 do?");
    expect(box.value).toBe("");
  });

  it("sends on Enter", async () => {
    const { user: ui, chat } = renderPanel();
    await ui.type(screen.getByPlaceholderText("Ask about this binary..."), "hello{Enter}");
    expect(chat.sendMessage).toHaveBeenCalledWith("hello");
  });

  it("does NOT send on Shift+Enter — that is a newline", async () => {
    const { user: ui, chat } = renderPanel();
    const box = screen.getByPlaceholderText("Ask about this binary...") as HTMLTextAreaElement;
    await ui.type(box, "first{Shift>}{Enter}{/Shift}second");
    expect(chat.sendMessage).not.toHaveBeenCalled();
    expect(box.value).toBe("first\nsecond");
  });

  it("passes the raw text through — trimming is the hook's job, not the panel's", async () => {
    // The panel only *gates* on `input.trim()`; `useAIChat.sendMessage` is the
    // one that trims before it builds the message. Pinned so a change on either
    // side has to notice the other.
    const { user: ui, chat } = renderPanel();
    await ui.type(screen.getByPlaceholderText("Ask about this binary..."), "  padded  {Enter}");
    expect(chat.sendMessage).toHaveBeenCalledWith("  padded  ");
  });

  it("wires Clear and Close to their own callbacks", async () => {
    const { user: ui, chat, onClose } = renderPanel();
    await ui.click(screen.getByRole("button", { name: "Clear" }));
    expect(chat.clearChat).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
    await ui.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(chat.clearChat).toHaveBeenCalledTimes(1);
  });
});

describe("AIChatPanel while streaming", () => {
  const streaming = (messages: ChatMessage[]) => ({ streaming: true, messages });

  it("locks the input and swaps Send for Stop", () => {
    renderPanel(streaming([user("go"), assistant("")]));
    const box = screen.getByPlaceholderText("Ask about this binary...") as HTMLTextAreaElement;
    expect(box.disabled).toBe(true);
    expect(screen.queryByRole("button", { name: "Send" })).toBeNull();
    expect(screen.getByRole("button", { name: "Stop" })).toBeTruthy();
  });

  it("aborts the stream on Stop", async () => {
    const { user: ui, chat } = renderPanel(streaming([user("go"), assistant("")]));
    await ui.click(screen.getByRole("button", { name: "Stop" }));
    expect(chat.cancelStream).toHaveBeenCalledTimes(1);
  });

  it("shows Thinking... only while the assistant reply is still empty", () => {
    const { view } = renderPanel(streaming([user("go"), assistant("")]));
    expect(view.container.textContent).toContain("Thinking...");
  });

  it("drops Thinking... as soon as the first token lands", () => {
    const { view } = renderPanel(streaming([user("go"), assistant("It ")]));
    expect(view.container.textContent).not.toContain("Thinking...");
    expect(view.container.textContent).toContain("It");
  });

  it("renders partial markdown as it streams, including a half-written fence", () => {
    // A stream is cut at an arbitrary byte, so `marked` is routinely handed
    // unbalanced markdown. It must not throw — an exception here would tear the
    // whole panel down mid-answer.
    const { view } = renderPanel(streaming([assistant("## Half\n\n```c\nint x = ")]));
    expect(screen.getByRole("heading", { name: "Half" })).toBeTruthy();
    expect(view.container.textContent).toContain("int x =");
  });

  it("shows an error without taking the conversation away", () => {
    const { view } = renderPanel({
      messages: [user("go"), assistant("partial")],
      error: "429 rate limited",
    });
    expect(screen.getByText("429 rate limited")).toBeTruthy();
    expect(view.container.textContent).toContain("partial");
    // A failed turn leaves the input usable, so the question can be retried.
    expect(
      (screen.getByPlaceholderText("Ask about this binary...") as HTMLTextAreaElement).disabled,
    ).toBe(false);
  });
});

describe("AIChatPanel auto-scroll", () => {
  it("scrolls the sentinel into view on mount and again when a message arrives", () => {
    // WHAT THIS PROVES, EXACTLY: the effect runs, it targets the trailing
    // sentinel `div`, and both of its change keys are wired — `chat.messages`
    // and `chat.streaming`. `scrollIntoView` in jsdom is a no-op stand-in
    // installed by `domSetup` (jsdom implements no scrolling and every scroll
    // offset there is a constant 0), so this buys NOTHING about whether the
    // newest message ends up on screen.
    const spy = vi.spyOn(HTMLElement.prototype, "scrollIntoView").mockImplementation(() => {});
    try {
      const chat = chatStub();
      const { rerender } = render(<AIChatPanel chat={chat} onClose={vi.fn()} onRename={vi.fn()} />);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][0]).toEqual({ behavior: "smooth" });

      rerender(
        <AIChatPanel
          chat={chatStub({ messages: [user("hi")] })}
          onClose={vi.fn()}
          onRename={vi.fn()}
        />,
      );
      expect(spy).toHaveBeenCalledTimes(2);

      // `streaming` is the second change key: a stream ticking with no new
      // message must still scroll.
      rerender(
        <AIChatPanel
          chat={chatStub({ messages: [user("hi")], streaming: true })}
          onClose={vi.fn()}
          onRename={vi.fn()}
        />,
      );
      expect(spy).toHaveBeenCalledTimes(3);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("AIChatPanel without an onRename", () => {
  it("still renders the Apply buttons, and clicking one is inert", async () => {
    // `onRename` is optional in the props and the buttons are rendered
    // regardless — so a caller that omitted it would show a live-looking control
    // that does nothing. NOT REACHABLE TODAY: `DisassemblyView.tsx` is the sole
    // mount site and always passes one. Pinned so the shape is on the record.
    const ui = userEvent.setup();
    render(
      <AIChatPanel
        chat={chatStub({ messages: [assistant("[RENAME:0x401000:x]")] })}
        onClose={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: "Apply: x" });
    await ui.click(btn);
    expect(btn).toBeTruthy();
  });
});
