# AI Features

Peek-a-Bin integrates two AI-powered analysis tools — chat, and enhance/explain in the decompile
panel. Both use SSE streaming via `streamChat()` from `src/llm/client.ts`.

> Three further features — **Batch Auto-Rename**, the **AI Analysis Report** and the
> **Vulnerability Scanner** — were removed on 2026-09-09 (`peek-a-bin-1xc5`) along with the
> Anomalies view tab. Their sections are gone from this document rather than marked deprecated;
> the CHANGELOG entry records what went and what survived it.

## LLM Profile Configuration

### Setup

1. Open **Settings** (gear icon or command palette)
2. Go to the **AI** tab
3. Select a provider: **Anthropic Claude** or **OpenAI-compatible**
4. Enter your API key and select a model
5. Click **Save**

### Multiple Profiles

Create up to 10 named profiles, each with its own provider, API key, model, base URL, and enhance source preference. Quick-switch between profiles from the status bar badge.

### OpenAI-Compatible Endpoints

The **OpenAI** provider option works with any OpenAI-compatible API:

- **OpenAI** — use the default base URL (`https://api.openai.com`)
- **Ollama** — set base URL to `http://localhost:11434/v1`
- **LM Studio** — set base URL to `http://localhost:1234/v1`
- **vLLM** — set base URL to your vLLM server URL

### Security

- API keys are stored in `localStorage` (not encrypted)
- Keys are sent only to the configured endpoint — never to Peek-a-Bin servers (there are none)
- All analysis context is assembled client-side before being sent to the LLM

### localStorage

| Key | Description |
|-----|-------------|
| `peek-a-bin:llm-profiles` | JSON `LLMProfileStore` with all profiles and active ID |
| `peek-a-bin:llm-settings` | Legacy key — auto-migrates to `llm-profiles` on first load |

### Profile Fields

| Field | Description |
|-------|-------------|
| `provider` | `"anthropic"` or `"openai"` |
| `apiKey` | API key for the selected provider |
| `model` | Model identifier (e.g., `claude-opus-5`, `gpt-4o`). Anthropic IDs carry no date suffix — appending one 404s. The canonical list lives in `src/llm/models.ts`; update it there, not here. |
| `baseUrl` | Base URL for OpenAI-compatible endpoints |
| `enhanceSource` | Source for enhance/explain: `"pseudocode"` or `"assembly"` |

## Request Handling

Everything below applies to both AI features on this page, since they both go through
`streamChat()` in `src/llm/client.ts`.

### Token budgets

`src/llm/models.ts` holds a per-task output ceiling, applied via `maxTokensFor(task)` and sent
as `max_tokens` on **both** providers — an 8K ceiling was previously hardcoded twice for
Anthropic and omitted entirely for OpenAI, so a long answer could be truncated on one provider
and unbounded on the other. `TASK_MAX_TOKENS` in that file is the source of truth. `LLMTask` is
now `chat | enhance` and **both budgets are 16384**; `report` (32768), `batch-rename` and
`vuln-scan` (8192 each) went with the features that sent them.

The two surviving values coinciding is not a reason to inline them — read the long docstring on
`TASK_MAX_TOKENS`, which argues the `Record<LLMTask, number>` is what stops a ceiling being
spelled at a call site again. One real reduction follows from it and is recorded in
[verification.md](verification.md): with both values equal, no call to `streamChat` can
distinguish the table from a constant, so nothing at runtime pins that the budget varies by
task — only `typecheck` and the `?? TASK_MAX_TOKENS.chat` fallback do.

These are caps, not reservations. They are sized generously because every call streams, so the
timeout pressure that motivates small ceilings on non-streaming requests does not apply. For
reasoning-capable models, `max_tokens` bounds thinking *and* visible text together — the app
deliberately sends no `thinking` parameter, because an explicit `{"type":"disabled"}` is
rejected by some models and gated on effort level by others, and omitting it is the only
setting valid across the whole range a user can type into the settings box. The visible
tradeoff is that a thinking model may pause before its first token.

### Model IDs

Model IDs, provider default base URLs and the settings dropdown contents all come from
`src/llm/models.ts`. They used to be duplicated across `settings.ts`, `SettingsModal.tsx` and
these docs, which is exactly how they drifted. **Read the current IDs from that file** — the
two named in the profile-field table above are illustrations of the shape, not a list to keep
in sync. Anthropic IDs carry no date suffix; appending one produces a 404.

### Retries and backoff

`src/llm/retry.ts` wraps every request in `runWithRetry`.

| Behaviour | Detail |
|-----------|--------|
| Retried | Network/transport failures, HTTP 408, 429, and any 5xx |
| Not retried | Aborts (the user's own cancel), and every other 4xx |
| Never retried | **Anything that fails after the first token has been shown.** Retrying would replay the response from scratch and duplicate text on screen, so the caller wraps such failures in `LLMCommittedError`, which `shouldRetry` always refuses. Partial output stays on screen |
| Backoff | Exponential with equal jitter — half the window fixed so delays grow monotonically, half random so concurrent clients do not resynchronise |
| `Retry-After` | Honoured when present, in both RFC 9110 forms (delta-seconds and HTTP-date), capped by the policy's max delay. A malformed value falls back to normal backoff rather than retrying immediately |
| Caps | `DEFAULT_RETRY_POLICY` bounds both total attempts and total wall-clock elapsed time. A backoff sleep that would cross the elapsed cap is not started — the real error is reported immediately instead of burning the budget first |
| Aborts | Interrupt a backoff sleep immediately rather than running the timer down |

A failure that survived retries is reported as `<message> (after N attempts)`, so it does not
read as a one-off blip. The `onRetry` callback lets a view show a "retrying…" state.

### Concurrency limiting

A shared `RequestLimiter` (`llmLimiter`) caps how many LLM requests are in flight at once and
enforces a minimum gap between request starts. A slot is held for the whole streamed response,
not just the fetch, and is released before a backoff sleep so a backing-off request does not
hold it. Values live in `src/llm/retry.ts`.

**No bulk caller remains, and the sizing predates that.** The 2-in-flight / 250 ms pair was
chosen against the vulnerability scanner, which fired up to 20 requests, and against batch
rename's batch loop — without spacing, that burst reliably tripped a 429 that then had to be
retried. **That measurement describes a workload this app no longer has and must not be
restated as if it still applied**; nothing has been re-measured against the current one. The
class stays because the defect class does: chat is single-flight, but `useDecompileTabs` can
have a low tab, a high tab and an explain tab in flight at once, and a chat can overlap an
enhance — so concurrent requests are still ordinary, merely *interactive* rather than bulk. The
numbers are deliberately left where the bulk measurement put them rather than adjusted on a
guess; `RequestLimiter`'s and `llmLimiter`'s own docstrings are the current statement of this.

## AI Chat

**Shortcut:** `Ctrl+Shift+A` | **Command palette:** "AI: Open Chat"

Multi-turn streaming conversation with binary context. `buildSystemPrompt` in
`src/hooks/useAIChat.ts` takes exactly three things and sends:

- File name, architecture, entry point, image base, and the section table (name, R/W/X flags,
  virtual size)
- Active function pseudocode, when viewing a function, truncated at 6000 characters

> **This list was wrong before this revision** and is corrected here rather than trimmed: it
> claimed imports/exports, anomalies and driver-detection info were sent as well. None of the
> three ever reached `buildSystemPrompt`, whose whole signature is `(pe, fileName, currentCode)`.
> Read that function, not this table, when it matters.

### Features

- `[RENAME:0xADDR:name]` markers in AI responses render as inline "Apply" rename buttons
- Per-file message persistence in localStorage (capped at 50 messages)
- Resizable chat panel width (persisted)
- Chat history survives page refreshes

### localStorage

| Key | Description |
|-----|-------------|
| `peek-a-bin:chat:${fileName}` | Chat messages for a specific file |
| `peek-a-bin:chat-width` | Chat panel width in pixels |

## Enhance / Explain

Available in the decompile panel's **AI** sub-tab:

- **Enhance:** Sends pseudocode (or assembly) to the LLM to produce improved, annotated pseudocode with better variable names and inline comments
- **Explain:** Sends pseudocode to the LLM and streams back `//` comment explanations prepended to the code

Enhance and Explain are mutually exclusive — starting one cancels the other. Results are cached per function and persist across tab switches.

## Command Palette Integration

One AI command is available in the command palette (`Ctrl+P`):

| Command | Description |
|---------|-------------|
| AI: Open Chat | Open the AI chat panel |

Enhance and Explain have no palette entry — they are buttons on the decompile panel's **AI**
sub-tab. The three commands that were here (Batch Rename Functions, Generate Analysis Report,
Scan Suspicious Functions) went with their features.
