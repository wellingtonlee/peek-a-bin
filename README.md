# Peek-a-Bin

![Peek-a-Bin](docs/logo.png)

Browser-based PE disassembler. All analysis client-side via WebAssembly.

[![Deploy to GitHub Pages](https://github.com/wellingtonlee/peek-a-bin/actions/workflows/deploy.yml/badge.svg)](https://github.com/wellingtonlee/peek-a-bin//actions/workflows/deploy.yml)

![Screenshot](docs/screenshot.png)

**[Live Demo](https://wellingtonlee.github.io/peek-a-bin/)**

## Features

**File Loading**
- Drag-and-drop PE files directly into the browser
- Bundled demo binary for quick exploration
- Recent files stored in IndexedDB — click to instantly re-open without re-browsing

**PE Analysis**
- DOS/NT/optional headers with field descriptions
- Section table with characteristics and entropy
- Import and export directory parsing
- Resource directory tree with version info, icon preview, and manifest display

**Disassembly**
- x86 and x64 disassembly via Capstone WASM
- Hybrid recursive descent + linear sweep disassembly
- Gap-fill regions visually dimmed to distinguish from control-flow-reachable code
- Virtual scrolling for large binaries
- Jump arrows showing control flow
- Minimap for navigation overview

**Advanced Analysis**
- Function detection via prologue scanning, call targets, and .pdata (x64 exception directory)
- Precise function boundaries from .pdata when available
- Cross-references (xrefs) — string, import, and data section references
- Callers/callees sidebar panel — shows which functions call the active function and what it calls
- PE anomaly detection — flags suspicious characteristics (WX sections, packer indicators, disabled ASLR/DEP, etc.) with severity-colored banners
- Stack frame reconstruction
- Control flow graph (CFG) — inline graph view togglable with `Space` (IDA-style), with full instruction interaction, collapsible blocks, pan/zoom, and sidebar graph overview minimap
- Decompiler with sub-tabs — **Low Level** (built-in IR-based decompiler), **High Level** (optional Ghidra server), **AI** (LLM-powered enhance/explain); per-tab per-function caching and bidirectional assembly sync

**Kernel Driver Analysis**
- Automatic detection of `.sys` drivers (NATIVE subsystem, WDM flag, kernel module imports)
- Dismissible amber banner and status bar badge for identified drivers
- Suspicious kernel API flagging with color-coded categories (Process/Thread, Callback/Hook, Memory, Registry, Filesystem, Network, Object)
- IOCTL code decoder — annotates device control codes inline in disassembly and decompiler output
- IRP dispatch table detection — identifies MajorFunction handler assignments in DriverEntry and auto-renames handler functions
- Authenticode / digital signature parsing — extracts signer subject, issuer, and validity dates from PKCS#7 SignedData without external ASN.1 libraries

**Navigation**
- Command palette (Ctrl/Cmd+P)
- Keyboard shortcuts panel (press `?`)
- Go-to-address
- Breadcrumb trail

**Annotations**
- Bookmarks, renaming, and comments
- Undo/redo support
- Persisted in localStorage
- Unified export/import (bookmarks, renames, comments, hex patches, functions)

**Data Views**
- Hex dump with data xref indicators — purple badges show cross-reference counts, click to see referencing instructions
- Strings extraction
- Data inspector
- Resource browser with download support

**Offline / PWA**
- Installable as a Progressive Web App
- Full offline support — all assets including the disassembly engine are cached

## Tech Stack

- React 19, TypeScript 5.7, Vite 6
- Tailwind CSS 4
- capstone-wasm (Capstone disassembly engine compiled to WASM)
- @tanstack/react-virtual (virtual scrolling)
- vite-plugin-pwa (service worker and offline caching)
- Vitest (unit testing)
- Web Workers for off-main-thread disassembly

## Prerequisites

- Node.js 20+
- npm

## Getting Started

```bash
git clone https://github.com/wellingtonlee/peek-a-bin.git
cd peek-a-bin
npm install
npm run dev
# http://localhost:5173/peek-a-bin/
```

## Testing

```bash
npm test          # run all tests once
npm run test:watch  # watch mode
```

## Production Build

```bash
npm run build
npm run preview  # http://localhost:4173/peek-a-bin/
```

## Offline / PWA Usage

Peek-a-Bin is a Progressive Web App that works fully offline after the first visit.

1. **Visit the app** in Chrome, Edge, or another PWA-capable browser (either the [live demo](https://wellingtonlee.github.io/peek-a-bin/) or a local `npm run preview` build).
2. **Install it** — click the install icon in the browser address bar, or use the browser menu (e.g. "Install Peek-a-Bin..." in Chrome). On mobile, use "Add to Home Screen".
3. **Use offline** — once installed, the app works without an internet connection. The service worker precaches all assets, including the ~2 MB Capstone WASM disassembly engine.
4. **Updates** — the service worker auto-updates in the background. On the next visit after an update is available, the new version loads automatically.

> **Note:** The PWA only caches the app itself. PE files you analyze are never uploaded or stored outside your browser — all processing is local.

## Docker

```bash
docker build -t peek-a-bin .
docker run -p 8080:80 peek-a-bin
# http://localhost:8080/peek-a-bin/
```

## Ghidra Decompilation Server (Optional)

The **High Level** tab in the decompile panel can use a companion Ghidra server for higher-quality decompilation. The server wraps Ghidra's decompiler via [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra) and exposes a REST API.

### Quick Start

```bash
cd ghidra-server
docker build -t peek-a-bin-ghidra .
docker run -p 8765:8765 peek-a-bin-ghidra
```

To require an API key for authentication:

```bash
docker run -p 8765:8765 peek-a-bin-ghidra --api-key YOUR_SECRET
```

### Running Without Docker

Requires Java 21+ and Python 3.10+:

```bash
cd ghidra-server
pip install -r requirements.txt
python server.py --port 8765
```

On first run, pyhidra will download and install Ghidra automatically.

### Connecting Peek-a-Bin to the Server

1. Open **Settings** in Peek-a-Bin (gear icon or via command palette)
2. Check **Enable Ghidra server**
3. Enter the server URL (default: `http://localhost:8765`)
4. Enter the API key if the server was started with `--api-key`
5. Click **Save**

Once configured, the **High Level** tab in the decompile panel will send the binary to the Ghidra server and display Ghidra's decompiled output. Binaries are uploaded once and cached server-side by SHA-256 hash.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ping` | Health check, returns `{ version }` |
| `POST` | `/api/v1/binary` | Upload PE binary (multipart), returns `{ projectId }` |
| `POST` | `/api/v1/decompile` | Decompile function at address, returns `{ code, lineMap }` |

## Project Structure

```
src/
├── analysis/      # Binary analysis modules (driver detection, IOCTL, IRP, anomaly detection)
├── components/    # React UI components
├── decompile/     # Decompilation clients (Ghidra REST, WASM stub, types)
├── pe/            # PE file format parser (headers, imports, authenticode)
├── disasm/        # Disassembly engine integration and built-in decompiler
├── llm/           # LLM integration (settings, streaming client, prompts)
├── workers/       # Web Worker threads
├── hooks/         # Custom React hooks
├── utils/         # Shared utilities
├── styles/        # Tailwind and global styles
├── App.tsx        # Root application component
└── main.tsx       # Entry point
ghidra-server/     # Optional Ghidra decompilation server (Docker + FastAPI)
```

## Keyboard Shortcuts

Press `?` in the app to see all shortcuts. Key bindings include:

| Key | Action |
|-----|--------|
| `Space` | Toggle linear / graph view |
| `1`–`8` | Switch tabs |
| `G` | Go to address |
| `?` | Keyboard shortcuts panel |
| `Ctrl+P` | Command palette |
| `Ctrl+F` | Search disassembly |
| `B` | Toggle bookmark |
| `0` | Zoom-to-fit (graph mode) |
| `Tab` | Cycle successor blocks (graph mode) |
| `Ctrl+Z` / `Ctrl+Shift+Z` | Undo / Redo |
| `Alt+Left` / `Alt+Right` | Back / Forward |

## Architecture

Peek-a-Bin runs entirely client-side. Files are parsed in the browser using a TypeScript PE parser, then disassembled via Capstone compiled to WebAssembly running in a Web Worker. The WASM binary is cached in IndexedDB after first load. Application state is managed with React Context and `useReducer`. Virtual scrolling (via @tanstack/react-virtual) keeps the UI responsive even for large binaries.

Disassembly uses a hybrid approach: recursive descent from known entry points (exports, .pdata entries, detected prologues, call targets) followed by linear sweep to fill gaps. This avoids decoding embedded data as instructions while still providing full section coverage.

```
File Drop → PE Parser (TS) → Capstone WASM (Worker) → React UI
```

## License

[MIT](LICENSE)
