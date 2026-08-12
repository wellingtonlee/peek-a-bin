# Documentation

## User Guides

- [Keyboard Shortcuts](keyboard.md) — all hotkeys for navigation, annotations, graph mode, and AI
- [Theming](theming.md) — built-in themes, custom themes, color token reference
- [AI Features](ai-features.md) — chat, batch rename, reports, vulnerability scanner, LLM profiles

## Server Guides

- [Ghidra Server](ghidra-server.md) — optional high-level decompilation server setup and API
- [MCP Server](mcp-server.md) — MCP tools/resources for AI agent integration

## Developer Guides

- [Architecture](architecture.md) — state management, worker, rendering, pipeline overview
- [Decompiler Internals](decompiler.md) — IR system, SSA, type inference, struct synthesis
- [Deployment](deployment.md) — builds, Docker, GitHub Pages, PWA, self-hosting

## Community

- [Contributing](../CONTRIBUTING.md) — development setup, code style, PR process
- [Security](../SECURITY.md) — vulnerability reporting, security model
- [Changelog](../CHANGELOG.md) — release history

## Which doc do I update?

This table is the canonical copy — `CLAUDE.md` and `CONTRIBUTING.md` point here rather than
repeating it.

| If your change touches… | Update |
|-------------------------|--------|
| Keyboard shortcuts | [keyboard.md](keyboard.md) — and `SHORTCUT_GROUPS` in `src/components/KeyboardShortcuts.tsx`, which is the source of truth the in-app `?` panel renders from |
| Theme system, color tokens, font size | [theming.md](theming.md) |
| AI features (chat, batch rename, report, scanner, LLM profiles) | [ai-features.md](ai-features.md) |
| MCP server tools, resources, or setup CLI | [mcp-server.md](mcp-server.md) |
| Ghidra server API or deployment | [ghidra-server.md](ghidra-server.md) |
| State, workers, rendering, or the analysis pipeline | [architecture.md](architecture.md) |
| Target-architecture support (x86/x64/ARM64), the Capstone window, worker binary arguments | [architecture.md](architecture.md) — and [decompiler.md](decompiler.md) if what a pass *declines* to do changes |
| Decompiler IR, passes, or type system | [decompiler.md](decompiler.md) |
| Anything that moves what is *verified* — a new oracle, a real-binary measurement, or a gap you closed or opened | the **Verification status** section of [../CLAUDE.md](../CLAUDE.md). Keep measured and reasoned claims apart there; it is the section future agents trust |
| Builds, Docker, CI, PWA, self-hosting | [deployment.md](deployment.md) |
| Content Security Policy | edit `build/csp.ts` (the single source of truth for both the meta tag and the nginx header) — then [../SECURITY.md](../SECURITY.md) for directive rationale and [deployment.md](deployment.md) for delivery |
| Security model, filesystem/network surface | [../SECURITY.md](../SECURITY.md) |
| Conventions, gotchas, or anything an AI agent needs | [../CLAUDE.md](../CLAUDE.md) |
| Top-level project description or setup | [../README.md](../README.md) |

Every user-visible change also needs a `CHANGELOG.md` entry under `[Unreleased]` with a
`(YYYY-MM-DD HH:MM)` timestamp.
