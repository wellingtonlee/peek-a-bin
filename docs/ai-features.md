# AI Features

Peek-a-Bin integrates 4 AI-powered analysis tools, plus enhance/explain functionality. All use SSE streaming via `streamChat()` from `src/llm/client.ts`.

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

Everything below applies to every AI feature on this page, since they all go through
`streamChat()` in `src/llm/client.ts`.

### Token budgets

`src/llm/models.ts` holds a per-task output ceiling, applied via `maxTokensFor(task)` and sent
as `max_tokens` on **both** providers — an 8K ceiling was previously hardcoded twice for
Anthropic and omitted entirely for OpenAI, so a long report could be truncated on one provider
and unbounded on the other. `TASK_MAX_TOKENS` in that file is the source of truth; the tasks
are `chat`, `report`, `enhance`, `batch-rename` and `vuln-scan`, and `report` gets the largest
budget.

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
enforces a minimum gap between request starts. The bulk features — the vulnerability scanner
and batch rename — otherwise fire bursts that reliably trip a 429 that then has to be retried.
A slot is held for the whole streamed response, not just the fetch, and is released before a
backoff sleep so a backing-off request does not hold it. The current setting is small on
purpose: enough for an interactive chat to proceed alongside a running scan, not enough for a
bulk loop to saturate the provider. Values live in `src/llm/retry.ts`.

### Response validation

Features that expect JSON back (batch rename, vulnerability scan) parse it through
`src/llm/responseSchema.ts` rather than a bare `JSON.parse` in a `catch {}`:

- `unwrapJSON()` strips Markdown code fences — one implementation, replacing per-caller regexes
  that both mishandled a fence whose info string was not exactly `json`.
- `parseBatchRenameResponse()` / `parseScanResponse()` validate against zod schemas and return
  a discriminated `ParseResult` (`{ ok: true, value }` or `{ ok: false, error }`). They never
  throw.
- Callers surface the failure. Previously a truncated or malformed response was
  indistinguishable from a legitimate "nothing to report".

## AI Chat

**Shortcut:** `Ctrl+Shift+A` | **Command palette:** "AI: Open Chat"

Multi-turn streaming conversation with full binary context. The AI automatically receives:

- PE metadata (headers, sections, imports/exports, anomalies)
- Active function pseudocode (when viewing a function)
- Driver analysis info (when a driver is detected)

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

## Batch Auto-Rename

**Toolbar:** Rename button | **Command palette:** "AI: Batch Rename Functions"

Automatically generates meaningful names for unnamed functions:

1. Decompiles all unnamed functions (not user-renamed, not thunks, size > 16 bytes) via the worker
2. Batches pseudocode to the LLM in groups of 6
3. Parses JSON rename suggestions from the LLM response
4. Opens a review modal with:
   - Current name vs. suggested name
   - Confidence score (color-coded)
   - Reasoning for each suggestion
   - Accept/reject toggles per function
5. Bulk actions: Accept All, Accept High Confidence, Reject All
6. Accepted renames are dispatched with full undo support

## AI Analysis Report

**Toolbar:** Report button | **Command palette:** "AI: Generate Analysis Report"

Generates a comprehensive Markdown report. `buildReportContext()` in `src/hooks/useAIReport.ts`
assembles:

- PE headers and metadata
- Notable imports (filtered against a 39-entry watchlist, capped at 50; falls back to the first
  30 imports if none match) and the first 20 exports
- Security anomalies
- Driver detection info
- Decompiled key functions
- Interesting strings

> The *request* context is bounded by those per-section item caps, not by a token budget —
> nothing counts or enforces input tokens. The *response* is capped by the per-task budget for
> `"report"` (see [Token budgets](#token-budgets)), which is the most generous of the five.

The report includes:
- Executive summary and binary classification
- Capability analysis
- API and string analysis
- Risk assessment
- Indicators of Compromise (IOCs)

**Features:**
- Streams to a full-page modal with live Markdown rendering
- Cached per file in localStorage with "Regenerate" button
- Downloadable as `.md` file

### localStorage

| Key | Description |
|-----|-------------|
| `peek-a-bin:report:${fileName}` | Cached report for a specific file |

## Vulnerability Scanner

**Context menu:** Right-click function → "Scan for vulnerabilities" | **Command palette:** "AI: Scan Suspicious Functions"

### Single Function Scan

Right-click any function in linear or graph mode to scan it for security issues. The function's pseudocode is sent to the LLM with a vulnerability scanning prompt.

### Bulk Scan

The "Scan" toolbar button or command palette action scans every function that references an API
in the `DANGEROUS_APIS` set in `src/hooks/useVulnScanner.ts` (32 entries). Names are matched with
a trailing `A`/`W` stripped, so `CreateProcessW` matches `CreateProcess`. The categories are:

- Memory: `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx`,
  `NtAllocateVirtualMemory`, `MapViewOfFile`, `NtMapViewOfSection`
- Cross-process: `WriteProcessMemory`, `ReadProcessMemory`, `NtWriteVirtualMemory`,
  `CreateRemoteThread`, `NtCreateThread`, `OpenProcess`, `NtOpenProcess`
- Execution: `CreateProcess`, `ShellExecute`, `WinExec`
- Injection / hooking: `SetWindowsHookEx`, `LoadLibrary`, `GetProcAddress`
- Crypto: `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `BCryptDecrypt`

> This list is **not** the same as the 39-entry `notableAPIs` watchlist used to build the AI
> report context in `src/hooks/useAIReport.ts`. That one is broader (registry, network, file
> I/O, anti-debug) and serves a different purpose; the two sets share only 17 names. **Neither
> contains `NtCreateSection`**, despite earlier revisions of this document listing it. Consult
> the source before relying on either set.

### Results

Findings appear in the **Anomalies** tab under "AI Security Findings":
- Severity badges (Critical, High, Medium, Low)
- Clickable function names navigate to disassembly
- Collapsible descriptions and remediation text

An empty result is **not** the same as a clean binary. Scan progress and outcome are tracked
separately from the finding list, in `AIScanState` (`state.aiScan`), precisely so the two stay
distinguishable — a run that produced nothing usable reports `failed`, and a run that scanned
some functions but not others reports `complete` with a non-zero failure count, meaning the
findings are real but incomplete. See
[Architecture → `AIScanState`](architecture.md#aiscanstate) for the phase table.

## Enhance / Explain

Available in the decompile panel's **AI** sub-tab:

- **Enhance:** Sends pseudocode (or assembly) to the LLM to produce improved, annotated pseudocode with better variable names and inline comments
- **Explain:** Sends pseudocode to the LLM and streams back `//` comment explanations prepended to the code

Enhance and Explain are mutually exclusive — starting one cancels the other. Results are cached per function and persist across tab switches.

## Command Palette Integration

Four AI commands are available in the command palette (`Ctrl+P`):

| Command | Description |
|---------|-------------|
| AI: Open Chat | Open the AI chat panel |
| AI: Batch Rename Functions | Start batch auto-rename workflow |
| AI: Generate Analysis Report | Generate analysis report |
| AI: Scan Suspicious Functions | Bulk scan for vulnerabilities |
