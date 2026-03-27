# Peek-a-Bin

![Peek-a-Bin](docs/logo.png)

Browser-based PE disassembler. All analysis client-side via WebAssembly.

[![Deploy to GitHub Pages](https://github.com/wellingtonlee/peek-a-bin/actions/workflows/deploy.yml/badge.svg)](https://github.com/wellingtonlee/peek-a-bin//actions/workflows/deploy.yml)

![Screenshot](docs/screenshot.png)

**[Live Demo](https://wellingtonlee.github.io/peek-a-bin/)**

## Features

- **PE Analysis** — headers, sections, imports, exports, resources, authenticode signatures
- **Disassembly** — x86/x64 via Capstone WASM with hybrid recursive descent + linear sweep, jump arrows, minimap
- **Decompiler** — IR-based built-in decompiler with SSA, type inference, and struct synthesis; optional Ghidra server for high-level output
- **Control Flow Graph** — inline IDA-style graph view with collapsible blocks, keyboard navigation, and pan/zoom
- **AI-Powered Analysis** — chat, batch auto-rename, analysis reports, vulnerability scanner (bring your own API key)
- **Kernel Driver Analysis** — `.sys` driver detection, suspicious API flagging, IOCTL decoder, IRP dispatch table
- **Annotations** — bookmarks, renames, comments with undo/redo and export/import
- **Cross-References** — function calls, strings, imports, data section references
- **Anomaly Detection** — flags WX sections, packer indicators, disabled ASLR/DEP, and more
- **Hex View** — hex dump with data xref indicators
- **Offline / PWA** — installable, works fully offline after first visit
- **Theming** — 4 built-in themes + custom theme import/export
- **MCP Server** — AI agent integration via Model Context Protocol

## Quick Start

Requires Node.js 20+.

```bash
git clone https://github.com/wellingtonlee/peek-a-bin.git
cd peek-a-bin
npm install
npm run dev
# http://localhost:5173/peek-a-bin/
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Keyboard Shortcuts](docs/keyboard.md) | All hotkeys and navigation |
| [Theming](docs/theming.md) | Themes, custom colors, font size |
| [AI Features](docs/ai-features.md) | Chat, batch rename, reports, vulnerability scanner |
| [Ghidra Server](docs/ghidra-server.md) | Optional high-level decompilation server |
| [MCP Server](docs/mcp-server.md) | AI agent integration tools and resources |
| [Architecture](docs/architecture.md) | State management, worker, rendering pipeline |
| [Decompiler](docs/decompiler.md) | IR system, SSA, type inference, struct synthesis |
| [Deployment](docs/deployment.md) | Docker, GitHub Pages, PWA, self-hosting |

## Tech Stack

- React 19, TypeScript 5.7, Vite 6
- Tailwind CSS 4
- capstone-wasm (Capstone disassembly engine compiled to WASM)
- @tanstack/react-virtual (virtual scrolling)
- @dagrejs/dagre (graph layout)
- vite-plugin-pwa (service worker and offline caching)
- Vitest (unit testing)
- Web Workers for off-main-thread disassembly

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR guidelines.

## License

[MIT](LICENSE)
