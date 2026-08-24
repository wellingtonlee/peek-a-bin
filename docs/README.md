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

## The long-form record

`CLAUDE.md` carries the rules; these three carry the evidence behind them — how each defect was
found, the measurements with the commits they were taken at, the negative controls, and the
alternatives that were tried and refused. Each keeps the same entries in the same order as the
summary section it belongs to, so an entry there lines up with its full record here.

**Read the long-form entry before changing the code it describes**, and add to it when you land a
change: the summary in `CLAUDE.md` states a rule, this is where the reason lives.

- [Gotchas](gotchas.md) — the full record behind `CLAUDE.md`'s Gotchas section
- [Verification](verification.md) — the full audit ledger: every figure, every negative control,
  and what each instrument is structurally blind to
- [Decompiler IR](decompiler-ir.md) — the dispatch census, the struct-grouping history, and the
  measurements behind the pipeline rules

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
| Target-architecture support (x86/x64/ARM64, or refusing a machine type outright), the Capstone window, worker binary arguments | [architecture.md](architecture.md) — and [decompiler.md](decompiler.md) if what a pass *declines* to do changes, and [mcp-server.md](mcp-server.md) if a tool's answer for such a file changes |
| Lint or format rule severity, or anything that changes whether a gate can fail | `biome.json` (strict JSON only) — then the **Commands** section of [../CLAUDE.md](../CLAUDE.md), which is where the expected `npm run lint` baseline and the known-red commands are recorded |
| Decompiler IR, passes, or type system | [decompiler.md](decompiler.md) |
| A component test, the jsdom setup, or the vitest config | the **Component tests** paragraph under Conventions in [../CLAUDE.md](../CLAUDE.md) — and its **Verification status** section if the render closes (or opens) a gap in the "Not verified" list, which a component test usually does |
| Anything that moves what is *verified* — a new oracle, a real-binary measurement, or a gap you closed or opened | the **Verification status** section of [../CLAUDE.md](../CLAUDE.md) for the claim, and [verification.md](verification.md) for the figures and controls. Keep measured and reasoned claims apart; it is the section future agents trust |
| A gotcha — a rule whose reason is not obvious from the code | the **Gotchas** section of [../CLAUDE.md](../CLAUDE.md) for the rule and what breaks without it, and [gotchas.md](gotchas.md) for the evidence. A measured refusal belongs there too: it saves the next session from re-attempting it |
| The decompiler IR, a pipeline stage, or a new `IRExpr`/`IRStmt` kind | [decompiler.md](decompiler.md), and [decompiler-ir.md](decompiler-ir.md) for the dispatch tables you must update |
| How the corpus audits are run or configured — where the binaries are looked for, a new `PEEK_CORPUS_*` variable, a new audit | [../corpus/README.md](../corpus/README.md), and `.env.example` if a new setting can be recorded per machine |
| Builds, Docker, CI, PWA, self-hosting | [deployment.md](deployment.md) |
| Content Security Policy | edit `build/csp.ts` (the single source of truth for both the meta tag and the nginx header) — then [../SECURITY.md](../SECURITY.md) for directive rationale and [deployment.md](deployment.md) for delivery |
| Security model, filesystem/network surface | [../SECURITY.md](../SECURITY.md) |
| Conventions, gotchas, or anything an AI agent needs | [../CLAUDE.md](../CLAUDE.md) |
| Top-level project description or setup | [../README.md](../README.md) |

Every user-visible change also needs a `CHANGELOG.md` entry under `[Unreleased]` with a
`(YYYY-MM-DD HH:MM)` timestamp.
