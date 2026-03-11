import type { LLMSettings } from "./settings";
import type { ChatMessage } from "./types";
import { SYSTEM_PROMPT, SYSTEM_PROMPT_ASM } from "./prompt";

export interface StreamCallbacks {
  onToken: (accumulated: string) => void;
  onDone: () => void;
  onError: (error: string) => void;
}

function buildHeaders(config: LLMSettings, isAnthropic: boolean): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (isAnthropic) {
    headers["x-api-key"] = config.apiKey;
    headers["anthropic-version"] = "2023-06-01";
    headers["anthropic-dangerous-direct-browser-access"] = "true";
  } else {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  }
  return headers;
}

function buildUrl(config: LLMSettings, isAnthropic: boolean): string {
  return isAnthropic
    ? "https://api.anthropic.com/v1/messages"
    : `${config.baseUrl.replace(/\/+$/, "")}/v1/chat/completions`;
}

function streamSSE(
  res: Response,
  isAnthropic: boolean,
  callbacks: StreamCallbacks,
): void {
  const { onToken, onDone, onError } = callbacks;
  const body = res.body;
  if (!body) { onError("No response body"); return; }

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let accumulated = "";
  let buffer = "";
  let pendingFlush = false;

  function flush() {
    pendingFlush = false;
    onToken(accumulated);
  }

  function scheduleFlush() {
    if (!pendingFlush) {
      pendingFlush = true;
      requestAnimationFrame(flush);
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
            text = parsed.delta?.text ?? "";
          }
        } else {
          text = parsed.choices?.[0]?.delta?.content ?? "";
        }
        if (text) {
          accumulated += text;
          scheduleFlush();
        }
      } catch { /* skip malformed JSON */ }
    }
  }

  function pump(): Promise<void> {
    return reader.read().then(({ done, value }) => {
      if (done) {
        if (buffer.trim()) processSSE("\n");
        if (pendingFlush) {
          cancelAnimationFrame(0);
          flush();
        }
        onDone();
        return;
      }
      processSSE(decoder.decode(value, { stream: true }));
      return pump();
    });
  }

  pump().catch((err) => {
    onError(err instanceof Error ? err.message : "Network error");
  });
}

function doFetch(
  url: string,
  headers: Record<string, string>,
  body: string,
  signal: AbortSignal,
  isAnthropic: boolean,
  callbacks: StreamCallbacks,
): void {
  fetch(url, { method: "POST", headers, body, signal })
    .then((res) => {
      if (!res.ok) {
        const map: Record<number, string> = {
          401: "Invalid API key",
          403: "Access denied",
          429: "Rate limited — try again later",
        };
        throw new Error(map[res.status] ?? `API error (${res.status})`);
      }
      streamSSE(res, isAnthropic, callbacks);
    })
    .catch((err) => {
      if (signal.aborted) return;
      callbacks.onError(err instanceof Error ? err.message : "Network error");
    });
}

export function streamEnhance(
  pseudocode: string,
  config: LLMSettings,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
  systemPrompt?: string,
): void {
  const isAnthropic = config.provider === "anthropic";
  const prompt = systemPrompt ?? (config.enhanceSource === "assembly" ? SYSTEM_PROMPT_ASM : SYSTEM_PROMPT);
  const url = buildUrl(config, isAnthropic);
  const headers = buildHeaders(config, isAnthropic);

  const body = isAnthropic
    ? JSON.stringify({
        model: config.model,
        max_tokens: 8192,
        stream: true,
        system: prompt,
        messages: [{ role: "user", content: pseudocode }],
      })
    : JSON.stringify({
        model: config.model,
        stream: true,
        messages: [
          { role: "system", content: prompt },
          { role: "user", content: pseudocode },
        ],
      });

  doFetch(url, headers, body, signal, isAnthropic, callbacks);
}

export function streamChat(
  messages: ChatMessage[],
  systemPrompt: string,
  config: LLMSettings,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
): void {
  const isAnthropic = config.provider === "anthropic";
  const url = buildUrl(config, isAnthropic);
  const headers = buildHeaders(config, isAnthropic);

  const body = isAnthropic
    ? JSON.stringify({
        model: config.model,
        max_tokens: 8192,
        stream: true,
        system: systemPrompt,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
      })
    : JSON.stringify({
        model: config.model,
        stream: true,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages.map((m) => ({ role: m.role, content: m.content })),
        ],
      });

  doFetch(url, headers, body, signal, isAnthropic, callbacks);
}
