import type { LLMSettings } from "./settings";
import { SYSTEM_PROMPT } from "./prompt";

interface StreamCallbacks {
  onToken: (accumulated: string) => void;
  onDone: () => void;
  onError: (error: string) => void;
}

export function streamEnhance(
  pseudocode: string,
  config: LLMSettings,
  signal: AbortSignal,
  callbacks: StreamCallbacks,
): void {
  const { onToken, onDone, onError } = callbacks;

  const isAnthropic = config.provider === "anthropic";

  const url = isAnthropic
    ? "https://api.anthropic.com/v1/messages"
    : `${config.baseUrl.replace(/\/+$/, "")}/v1/chat/completions`;

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (isAnthropic) {
    headers["x-api-key"] = config.apiKey;
    headers["anthropic-version"] = "2023-06-01";
    headers["anthropic-dangerous-direct-browser-access"] = "true";
  } else {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  }

  const body = isAnthropic
    ? JSON.stringify({
        model: config.model,
        max_tokens: 8192,
        stream: true,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: pseudocode }],
      })
    : JSON.stringify({
        model: config.model,
        stream: true,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: pseudocode },
        ],
      });

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
      return res.body;
    })
    .then((body) => {
      if (!body) throw new Error("No response body");
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
        // Keep the last partial line in the buffer
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
            // Flush any remaining buffer
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

      return pump();
    })
    .catch((err) => {
      if (signal.aborted) return;
      onError(err instanceof Error ? err.message : "Network error");
    });
}
