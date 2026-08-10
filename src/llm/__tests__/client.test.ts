import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { streamChat, type StreamCallbacks } from "../client";
import type { LLMSettings } from "../settings";
import { sleep, type RetryPolicy } from "../retry";

const ANTHROPIC: LLMSettings = {
  provider: "anthropic",
  apiKey: "sk-test",
  model: "claude-opus-5",
  baseUrl: "https://api.anthropic.com",
  enhanceSource: "pseudocode",
};

const OPENAI: LLMSettings = {
  ...ANTHROPIC,
  provider: "openai",
  model: "gpt-4o",
  baseUrl: "https://api.openai.com",
};

/** No real waiting, and no shared limiter leaking between tests. */
const TEST_POLICY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 1,
  maxDelayMs: 5,
  maxElapsedMs: 60_000,
};
const TEST_OPTS = { policy: TEST_POLICY, limiter: null, sleepFn: async () => {} };

/** `Array.prototype.at` is above this project's TS lib target. */
function last(values: string[]): string | undefined {
  return values.length > 0 ? values[values.length - 1] : undefined;
}

type StreamStep =
  | { kind: "data"; text: string }
  | { kind: "pause"; ms: number }
  | { kind: "fail"; message: string };

function anthropicChunk(text: string): string {
  return `data: ${JSON.stringify({ type: "content_block_delta", delta: { type: "text_delta", text } })}\n\n`;
}

function openaiChunk(text: string): string {
  return `data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`;
}

/** Minimal stand-in for the parts of `Response` that client.ts touches. */
function fakeResponse(steps: StreamStep[], headers: Record<string, string> = {}): Response {
  const encoder = new TextEncoder();
  let i = 0;
  const reader = {
    async read(): Promise<{ done: boolean; value?: Uint8Array }> {
      while (i < steps.length) {
        const step = steps[i++];
        if (step.kind === "pause") {
          await sleep(step.ms);
          continue;
        }
        if (step.kind === "fail") throw new Error(step.message);
        return { done: false, value: encoder.encode(step.text) };
      }
      return { done: true };
    },
  };
  return {
    ok: true,
    status: 200,
    headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
    body: { getReader: () => reader },
  } as unknown as Response;
}

function errorResponse(status: number, headers: Record<string, string> = {}): Response {
  return {
    ok: false,
    status,
    headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
    body: null,
  } as unknown as Response;
}

/** Resolves once the client reports a terminal outcome (or the abort deadline passes). */
function collect(run: (cb: StreamCallbacks) => void, quietMs = 120) {
  return new Promise<{ tokens: string[]; done: boolean; error: string | null }>((resolve) => {
    const tokens: string[] = [];
    let settled = false;
    const finish = (done: boolean, error: string | null) => {
      if (settled) return;
      settled = true;
      resolve({ tokens, done, error });
    };
    run({
      onToken: (acc) => tokens.push(acc),
      onDone: () => finish(true, null),
      onError: (error) => finish(false, error),
    });
    // Aborted requests deliberately report nothing; fall through after a beat.
    setTimeout(() => finish(false, null), quietMs);
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("streamChat — happy path", () => {
  it("accumulates Anthropic text deltas and reports done once", async () => {
    fetchMock.mockResolvedValue(
      fakeResponse([
        { kind: "data", text: anthropicChunk("Hello") },
        { kind: "data", text: anthropicChunk(" world") },
      ]),
    );

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(result.done).toBe(true);
    expect(result.error).toBeNull();
    expect(last(result.tokens)).toBe("Hello world");
  });

  it("accumulates OpenAI deltas", async () => {
    fetchMock.mockResolvedValue(
      fakeResponse([
        { kind: "data", text: openaiChunk("foo") },
        { kind: "data", text: openaiChunk("bar") },
      ]),
    );

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        OPENAI,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(result.done).toBe(true);
    expect(last(result.tokens)).toBe("foobar");
  });

  it("ignores thinking deltas so reasoning text never reaches the UI", async () => {
    const thinking = `data: ${JSON.stringify({
      type: "content_block_delta",
      delta: { type: "thinking_delta", thinking: "internal reasoning" },
    })}\n\n`;

    fetchMock.mockResolvedValue(
      fakeResponse([
        { kind: "data", text: thinking },
        { kind: "data", text: anthropicChunk("answer") },
      ]),
    );

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(last(result.tokens)).toBe("answer");
  });
});

describe("streamChat — token budget", () => {
  function bodyOf(call: number): Record<string, unknown> {
    return JSON.parse(fetchMock.mock.calls[call][1].body);
  }

  it("sends a per-task max_tokens on Anthropic", async () => {
    fetchMock.mockResolvedValue(fakeResponse([]));
    await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "report",
        TEST_OPTS,
      ),
    );
    expect(bodyOf(0).max_tokens).toBe(32768);
  });

  it("sends max_tokens on OpenAI too — the branch previously had no limit at all", async () => {
    fetchMock.mockResolvedValue(fakeResponse([]));
    await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        OPENAI,
        new AbortController().signal,
        cb,
        "vuln-scan",
        TEST_OPTS,
      ),
    );
    expect(bodyOf(0).max_tokens).toBe(8192);
  });

  it("varies the budget by task", async () => {
    fetchMock.mockResolvedValue(fakeResponse([]));
    await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "batch-rename",
        TEST_OPTS,
      ),
    );
    expect(bodyOf(0).max_tokens).toBe(8192);
  });
});

describe("streamChat — retry", () => {
  it("retries a 429 and honours Retry-After", async () => {
    fetchMock
      .mockResolvedValueOnce(errorResponse(429, { "retry-after": "1" }))
      .mockResolvedValueOnce(fakeResponse([{ kind: "data", text: anthropicChunk("ok") }]));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.done).toBe(true);
    expect(last(result.tokens)).toBe("ok");
  });

  it("retries a 500", async () => {
    fetchMock
      .mockResolvedValueOnce(errorResponse(500))
      .mockResolvedValueOnce(fakeResponse([{ kind: "data", text: anthropicChunk("ok") }]));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.done).toBe(true);
  });

  it("retries a transport failure", async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValueOnce(fakeResponse([{ kind: "data", text: anthropicChunk("ok") }]));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.done).toBe(true);
  });

  it("does not retry a 401 and keeps the original message", async () => {
    fetchMock.mockResolvedValue(errorResponse(401));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.error).toBe("Invalid API key");
  });

  it("does not retry a 403", async () => {
    fetchMock.mockResolvedValue(errorResponse(403));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.error).toBe("Access denied");
  });

  it("stops at the attempt cap and says the failure survived retries", async () => {
    fetchMock.mockResolvedValue(errorResponse(503));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(TEST_POLICY.maxAttempts);
    expect(result.error).toBe("API error (503) (after 3 attempts)");
  });
});

describe("streamChat — the streaming retry boundary", () => {
  it("retries a stream that dies BEFORE the first token reaches the UI", async () => {
    fetchMock
      .mockResolvedValueOnce(fakeResponse([{ kind: "fail", message: "connection reset" }]))
      .mockResolvedValueOnce(fakeResponse([{ kind: "data", text: anthropicChunk("recovered") }]));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        new AbortController().signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.done).toBe(true);
    expect(last(result.tokens)).toBe("recovered");
  });

  it("does NOT retry a stream that dies AFTER a token was shown — that would duplicate output", async () => {
    fetchMock
      .mockResolvedValueOnce(
        fakeResponse([
          { kind: "data", text: anthropicChunk("partial answer") },
          // Long enough for the queued flush to run and reach onToken.
          { kind: "pause", ms: 60 },
          { kind: "fail", message: "connection reset" },
        ]),
      )
      .mockResolvedValue(
        fakeResponse([{ kind: "data", text: anthropicChunk("SHOULD NOT APPEAR") }]),
      );

    const result = await collect(
      (cb) =>
        streamChat(
          [{ role: "user", content: "hi" }],
          "sys",
          ANTHROPIC,
          new AbortController().signal,
          cb,
          "chat",
          TEST_OPTS,
        ),
      400,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.error).toBe("connection reset");
    // The partial output the user already saw is preserved, not replayed.
    expect(result.tokens).toContain("partial answer");
    expect(result.tokens.join("")).not.toContain("SHOULD NOT APPEAR");
  });
});

describe("streamChat — abort", () => {
  it("reports neither done nor error when the user cancels mid-stream", async () => {
    const controller = new AbortController();
    fetchMock.mockImplementation(async () =>
      fakeResponse([
        { kind: "data", text: anthropicChunk("start") },
        { kind: "pause", ms: 40 },
        { kind: "fail", message: "aborted" },
      ]),
    );

    const result = await collect((cb) => {
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        controller.signal,
        cb,
        "chat",
        TEST_OPTS,
      );
      setTimeout(() => controller.abort(), 20);
    }, 300);

    expect(result.done).toBe(false);
    expect(result.error).toBeNull();
  });

  it("never issues a request when the signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    fetchMock.mockResolvedValue(fakeResponse([]));

    const result = await collect((cb) =>
      streamChat(
        [{ role: "user", content: "hi" }],
        "sys",
        ANTHROPIC,
        controller.signal,
        cb,
        "chat",
        TEST_OPTS,
      ),
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.done).toBe(false);
    expect(result.error).toBeNull();
  });
});
