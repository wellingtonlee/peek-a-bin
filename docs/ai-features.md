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
| `model` | Model identifier (e.g., `claude-sonnet-4-20250514`, `gpt-4o`) |
| `baseUrl` | Base URL for OpenAI-compatible endpoints |
| `enhanceSource` | Source for enhance/explain: `"pseudocode"` or `"assembly"` |

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

Generates a comprehensive Markdown report by assembling ~12K tokens of binary context:

- PE headers and metadata
- Notable imports and exports
- Security anomalies
- Driver detection info
- Decompiled key functions
- Interesting strings

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

The "Scan" toolbar button or command palette action scans all functions that call dangerous APIs:
- `VirtualAlloc`, `VirtualProtect`
- `WriteProcessMemory`, `CreateRemoteThread`
- `NtCreateSection`, `NtMapViewOfSection`
- And other commonly abused APIs

### Results

Findings appear in the **Anomalies** tab under "AI Security Findings":
- Severity badges (Critical, High, Medium, Low)
- Clickable function names navigate to disassembly
- Collapsible descriptions and remediation text

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
