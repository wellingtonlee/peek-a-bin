import type { LLMSettings } from "./settings";
import type { ChatMessage } from "./types";
import { SYSTEM_PROMPT, SYSTEM_PROMPT_ASM } from "./prompt";
import { ANTHROPIC_DEFAULT_BASE_URL, maxTokensFor, type LLMTask } from "./models";
import {
  LLMAbortError,
  LLMCommittedError,
  LLMHttpError,
  LLMNetworkError,
  parseRetryAfter,
  runWithRetry,
  type RetryPolicy,
  type RequestLimiter,
} from "./retry";

export interface StreamCallbacks {
  onToken: (accumulated: string) => void;
  onDone: () => void;
  onError: (error: string) => void;
  /**
   * Fired before each backoff sleep so the UI can show that a transient failure
   * is being retried rather than appearing to hang. Optional — callers that do
   * not care about retry state can ignore it.
   */
  onRetry?: (info: { attempt: number; delayMs: number; reason: string }) => void;
}

/** Test seams — production callers never pass these. */
export interface StreamOptions {
  policy?: RetryPolicy;
  limiter?: RequestLimiter | null;
  sleepFn?: (ms: number, signal?: AbortSignal) => Promise<void>;
  random?: () => number;
}

function buildHeaders(config: LLMSettings, isAnthropic: boolean): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (isAnthropic) {
    headers["x-api-key"] = config.apiKey;
    headers["anthropic-version"] = "2023-06-01";
    headers["anthropic-dangerous-direct-browser-access"] = "true";
  } else {
    headers.Authorization = `Bearer ${config.apiKey}`;
  }
  return headers;
}

function buildUrl(config: LLMSettings, isAnthropic: boolean): string {
  if (!isAnthropic) {
    return `${config.baseUrl.replace(/\/+$/, "")}/v1/chat/completions`;
  }
  // The Anthropic URL used to be hardcoded, so `baseUrl` was never read for this
  // provider and its default was left as the (nonsensical) OpenAI host. Existing
  // saved profiles still carry that value, so treat it — and an empty string — as
  // "use the default" rather than posting Anthropic requests at api.openai.com.
  // Anything else is a deliberate custom gateway and is honoured.
  const configured = config.baseUrl?.replace(/\/+$/, "") ?? "";
  const base =
    !configured || /(^|\/\/)api\.openai\.com$/.test(configured)
      ? ANTHROPIC_DEFAULT_BASE_URL
      : configured;
  return `${base}/v1/messages`;
}

// The token flush is coalesced onto animation frames in the browser. Tests and
// the worker have no rAF, so fall back to a timer rather than throwing.
const scheduleFrame: (cb: () => void) => number =
  typeof requestAnimationFrame === "function"
    ? (cb) => requestAnimationFrame(cb)
    : (cb) => setTimeout(cb, 16) as unknown as number;

const cancelFrame: (handle: number) => void =
  typeof cancelAnimationFrame === "function"
    ? (handle) => cancelAnimationFrame(handle)
    : (handle) => clearTimeout(handle as unknown as ReturnType<typeof setTimeout>);

/**
 * Read one SSE response to completion.
 *
 * Resolves when the stream ends cleanly. Rejects with {@link LLMCommittedError}
 * if it fails *after* a token has already reached the UI (see the retry-boundary
 * note in retry.ts) and with {@link LLMNetworkError} if it fails before that.
 */
function streamSSE(
  res: Response,
  isAnthropic: boolean,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
): Promise<void> {
  const { onToken } = callbacks;
  const body = res.body;
  if (!body) return Promise.reject(new LLMNetworkError("No response body"));

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let accumulated = "";
  let buffer = "";
  let pendingFlush = false;
  let rafHandle = 0;
  let emitted = false;

  function flush() {
    pendingFlush = false;
    emitted = true;
    onToken(accumulated);
  }

  function scheduleFlush() {
    if (!pendingFlush) {
      pendingFlush = true;
      // Handle is retained so the final flush can cancel a pending frame; the
      // previous code called cancelAnimationFrame(0), which is never a valid id.
      rafHandle = scheduleFrame(flush);
    }
  }

  function processSSE(chunk: string) {
    buffer += chunk;
    const parts = buffer.split("\n");
    buffer = parts.pop() ?? "";

    for (const line of parts) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(":")) continue;
      if (!trimmed.startsWith("data:")) continue;

      const data = trimmed.slice(5).trim();
      if (data === "[DONE]") continue;

      try {
        const parsed = JSON.parse(data);
        let text = "";
        if (isAnthropic) {
          if (parsed.type === "content_block_delta") {
            // Only `text_delta` carries visible output. Reasoning models also emit
            // `thinking_delta` blocks here, which must not be rendered.
            text = parsed.delta?.text ?? "";
          }
        } else {
          text = parsed.choices?.[0]?.delta?.content ?? "";
        }
        if (text) {
          accumulated += text;
          scheduleFlush();
        }
      } catch {
        /* skip malformed JSON */
      }
    }
  }

  function pump(): Promise<void> {
    return reader.read().then(({ done, value }) => {
      if (done) {
        if (buffer.trim()) processSSE("\n");
        if (pendingFlush) {
          cancelFrame(rafHandle);
          flush();
        }
        return;
      }
      processSSE(decoder.decode(value, { stream: true }));
      return pump();
    });
  }

  return pump().catch((err) => {
    // A user cancel aborts the reader, which rejects here. Reporting that as an
    // error surfaced a spurious "Network error" after every cancellation, since
    // the caller has already dispatched its done/cancelled state.
    if (signal.aborted) throw new LLMAbortError();
    const message = err instanceof Error ? err.message : "Network error";
    // Anything after the first visible token is unsafe to replay.
    throw emitted ? new LLMCommittedError(new Error(message)) : new LLMNetworkError(message);
  });
}

const STATUS_MESSAGES: Record<number, string> = {
  401: "Invalid API key",
  403: "Access denied",
  429: "Rate limited — try again later",
};

function statusMessage(status: number): string {
  return STATUS_MESSAGES[status] ?? `API error (${status})`;
}

/** One connect-and-stream attempt. Throws the typed errors `runWithRetry` classifies. */
async function attemptRequest(
  url: string,
  headers: Record<string, string>,
  body: string,
  signal: AbortSignal,
  isAnthropic: boolean,
  callbacks: StreamCallbacks,
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(url, { method: "POST", headers, body, signal });
  } catch (err) {
    if (signal.aborted) throw new LLMAbortError();
    throw new LLMNetworkError(err instanceof Error ? err.message : "Network error");
  }

  if (!res.ok) {
    throw new LLMHttpError(
      res.status,
      statusMessage(res.status),
      parseRetryAfter(res.headers?.get?.("retry-after") ?? null),
    );
  }

  return streamSSE(res, isAnthropic, signal, callbacks);
}

function describeError(err: unknown): string {
  if (err instanceof LLMCommittedError) return err.message;
  if (err instanceof LLMHttpError) return err.message;
  if (err instanceof Error) return err.message;
  return "Network error";
}

/**
 * Drive one request through the retry policy and report the outcome exactly once
 * via the callbacks. Fire-and-forget, matching the previous signature.
 */
function run(
  url: string,
  headers: Record<string, string>,
  body: string,
  signal: AbortSignal,
  isAnthropic: boolean,
  callbacks: StreamCallbacks,
  options: StreamOptions,
): void {
  let attempts = 0;

  runWithRetry(
    (attempt) => {
      attempts = attempt;
      return attemptRequest(url, headers, body, signal, isAnthropic, callbacks);
    },
    {
      signal,
      policy: options.policy,
      limiter: options.limiter,
      sleepFn: options.sleepFn,
      random: options.random,
      onRetry: ({ attempt, delayMs, error }) =>
        callbacks.onRetry?.({ attempt, delayMs, reason: describeError(error) }),
    },
  )
    .then(() => callbacks.onDone())
    .catch((err) => {
      // An abort is the user's own cancel; the caller has already moved on.
      if (signal.aborted || err instanceof LLMAbortError) return;
      const base = describeError(err);
      // Keep the message at least as informative as before, and say when the
      // failure survived retries so it does not look like a one-off blip.
      callbacks.onError(attempts > 1 ? `${base} (after ${attempts} attempts)` : base);
    });
}

export function streamEnhance(
  pseudocode: string,
  config: LLMSettings,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
  systemPrompt?: string,
  options: StreamOptions = {},
): void {
  const isAnthropic = config.provider === "anthropic";
  const prompt =
    systemPrompt ?? (config.enhanceSource === "assembly" ? SYSTEM_PROMPT_ASM : SYSTEM_PROMPT);
  const url = buildUrl(config, isAnthropic);
  const headers = buildHeaders(config, isAnthropic);
  const maxTokens = maxTokensFor("enhance");

  const body = isAnthropic
    ? JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        stream: true,
        system: prompt,
        messages: [{ role: "user", content: pseudocode }],
      })
    : JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        stream: true,
        messages: [
          { role: "system", content: prompt },
          { role: "user", content: pseudocode },
        ],
      });

  run(url, headers, body, signal, isAnthropic, callbacks, options);
}

export function streamChat(
  messages: ChatMessage[],
  systemPrompt: string,
  config: LLMSettings,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
  task: LLMTask = "chat",
  options: StreamOptions = {},
): void {
  const isAnthropic = config.provider === "anthropic";
  const url = buildUrl(config, isAnthropic);
  const headers = buildHeaders(config, isAnthropic);
  const maxTokens = maxTokensFor(task);

  const body = isAnthropic
    ? JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        stream: true,
        system: systemPrompt,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
      })
    : JSON.stringify({
        model: config.model,
        max_tokens: maxTokens,
        stream: true,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages.map((m) => ({ role: m.role, content: m.content })),
        ],
      });

  run(url, headers, body, signal, isAnthropic, callbacks, options);
}
