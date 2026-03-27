# Changelog

## [Unreleased]

### Added

- **Documentation restructuring** — split monolithic README into `docs/` folder with 8 topic-specific guides (keyboard, theming, ghidra-server, mcp-server, ai-features, architecture, decompiler, deployment); added CONTRIBUTING.md, SECURITY.md, and docs/README.md hub; README slimmed to project overview with doc links (2026-03-27 16:00)
- **Ghidra connection test** — "Test Connection" button in Settings → Ghidra tab verifies server reachability and displays server version and Ghidra version (2026-03-27 14:00)
- **MCP auto-discovery** — `.mcp.json` at project root enables Claude Code to automatically discover and use the MCP server without manual configuration (2026-03-27 12:00)
- **MCP setup CLI** — `npx tsx src/mcp/index.ts setup <client>` configures AI clients (claude-code, opencode, continue.dev) with `--dry-run` and `--list` flags; extensible registry pattern in `src/mcp/clients.ts` (2026-03-27 12:00)

### Changed

- **Ghidra 12.0.4** — Docker image updated from Ghidra 11.3.2 to 12.0.4; ping endpoint now returns `ghidraVersion` (2026-03-27 14:00)
- **Browser deps moved to devDependencies** — react, react-dom, marked, @dagrejs/dagre, @tanstack/react-virtual moved to devDependencies; only MCP runtime deps (SDK, capstone-wasm, ws, tsx, zod) remain in dependencies (2026-03-27 12:00)

- **AI Chat panel** — multi-turn streaming conversation with binary context; right sidebar panel toggled via Ctrl+Shift+A or toolbar button; PE metadata + active function pseudocode auto-attached as system context; `[RENAME:0xADDR:name]` markers in AI responses render as inline "Apply" rename buttons; per-file message persistence in localStorage (capped at 50 messages); local useReducer state to avoid app-wide re-renders during streaming (2026-03-11 19:33)
- **AI batch auto-rename** — "Rename" toolbar button or command palette "AI: Batch Rename Functions" decompiles all unnamed functions (no user rename, not thunk, size > 16 bytes) via worker, batches pseudocode to LLM in groups of 6, parses JSON rename suggestions; review modal with current/suggested name, confidence score (color-coded), reasoning, and accept/reject toggles; bulk actions (Accept All, Accept High Confidence, Reject All); accepted renames dispatched as RENAME_FUNCTION with undo support (2026-03-11 19:33)
- **AI analysis report** — "Report" toolbar button or command palette generates comprehensive Markdown report; builds ~12K token context (PE headers, notable imports, exports, anomalies, driver info, decompiled key functions, interesting strings); streams to full-page modal with live MarkdownRenderer; cached per file in localStorage with "Regenerate" button; downloadable as .md file (2026-03-11 19:33)
- **AI vulnerability scanner** — right-click function → "Scan for vulnerabilities" in both linear and graph mode context menus; "Scan" toolbar button or command palette "AI: Scan Suspicious Functions" bulk-scans functions calling dangerous APIs (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, etc.); findings displayed in new "AI Security Findings" section in Anomalies tab with severity badges, clickable function names, collapsible descriptions and remediation text (2026-03-11 19:33)
- **Shared LLM infrastructure** — `streamChat()` multi-turn streaming function extracted from `streamEnhance()` with shared SSE pump; 4 new system prompts (chat, batch rename, report, vuln scan) in `src/llm/prompt.ts`; `ChatMessage`, `BatchRenameResult`, `AIScanFinding` types in `src/llm/types.ts` (2026-03-11 19:33)
- **Markdown renderer** — shared `MarkdownRenderer` component using `marked` library for chat messages and report display; full CSS styling for headers, code blocks, tables, lists, blockquotes; theme-aware variables (2026-03-11 19:33)
- **AI commands in command palette** — 4 new searchable commands: "AI: Open Chat", "AI: Batch Rename Functions", "AI: Generate Analysis Report", "AI: Scan Suspicious Functions" (2026-03-11 19:33)
- **AI toolbar buttons** — Chat, Rename, Report, and Scan buttons in the address bar toolbar for quick access to all AI features (2026-03-11 19:33)

- **Multiple AI provider profiles** — create, switch, and delete up to 10 named LLM profiles (each with its own provider, API key, model, base URL, and enhance source); auto-migrates legacy single-settings on first load; profile selector dropdown and name editor in Settings → AI tab; quick-switch popover badge in StatusBar for fast profile switching; `peek-a-bin:llm-profiles` localStorage key with zero breaking changes to existing consumers (2026-03-11 16:18)
- **CI workflow** — new `.github/workflows/ci.yml` runs `tsc --noEmit` and `npm test` on every push/PR to main (2026-03-11 16:18)
- **Tag-based deployments** — deploy workflow now triggers on `v*.*.*` tags instead of every push to main; adds type-check and test steps before build (2026-03-11 16:18)
- **Gitignore hardening** — added patterns for security-sensitive files (`.pem`, `.key`, `.cert`, `.p12`, `.pfx`, `.jks`) and database files (`.sqlite`, `.db`); added `.env.example` with documented MCP WebSocket port config (2026-03-11 16:18)
- **MCP → Browser live sync** — WebSocket bridge pushes annotation changes (comments, renames, bookmarks) from MCP server to browser in real-time; auto-reconnect with 3s backoff; green "MCP" status dot in StatusBar when connected; configurable port via `PEEK_A_BIN_WS_PORT` env var (default 19283) (2026-03-08 22:51)
- **MCP annotation tools** — add_comment, rename_function, add_bookmark (toggle), list_comments tools for AI-driven annotation; renames overlay into decompile funcMap; decompile_function now returns lineMap for line→address mapping (2026-03-08 09:32)
- **MCP export/import tools** — export_analysis produces ExportSchemaV1 JSON (optionally writes to file); import_analysis reads ExportSchemaV1 JSON and merges annotations into session state (2026-03-08 09:32)
- **MCP server** — Model Context Protocol server for programmatic PE analysis; stdio transport; multi-file sessions; tools: load_pe, list_files, list_functions, decompile_function, disassemble_function, get_xrefs, detect_anomalies; resources: pe://{fileId}/{headers,sections,imports,exports,strings,functions,anomalies,driver}; shared module extraction from worker (functionDetect.ts); run via `npm run mcp` (2026-03-07 18:06)
- **Pseudocode comments** — annotate decompiled code with user comments; inline green `// comment` display on all lines mapping to the same address; right-click context menu (Add/Edit comment, Copy address); `;` hotkey to add comment on highlighted line; inline textarea editor (Enter=save, Shift+Enter=newline, Escape=cancel, empty=delete); shared editing state with disassembly view; comments auto-persist via existing annotation system (2026-03-07 14:17)
- **Comment indicators in minimap** — green markers on the minimap for addresses with user comments; priority between bookmarks and search matches (2026-03-07 14:58)
- **Find all references flow** — xref badge clicks now open the full XrefPanel pre-filtered to the target address instead of a small popup; works for both function label and instruction-level xref badges (2026-03-07 15:39)
- **Command palette tab routing** — selecting an import/export/string result from Ctrl+P now navigates to the correct tab instead of always switching to disassembly (2026-03-07 15:39)
- **Breadcrumb overflow indicators** — gradient fade indicators on left/right edges when breadcrumb trail overflows; auto-scrolls to newest entry; hidden scrollbar (2026-03-07 15:39)
- **Searchable address history** — history dropdown (Alt+H) now includes a filter input; supports filtering by hex address or function name; increased history cap from 15 to 50 entries (2026-03-07 15:39)
- **Tabbed bottom panels** — Detail, Calls, and Xrefs panels now share a tabbed container with a single resize handle; panels can be popped out as draggable/resizable floating overlays and re-docked; height persists to localStorage (2026-03-07 15:39)
- **XrefPanel scoped filter** — scope buttons (All/Addr/Func/Insn) filter cross-references by target address, containing function range, or current instruction; direction toggle (To/From) when scoped to instruction (2026-03-07 15:39)
- **Function list context menu** — right-click functions in the sidebar for Jump to, Rename, Copy address, Toggle bookmark, and Show xrefs actions (2026-03-07 15:39)
- **Anomalies tab** — new tab (key 9) displaying security anomalies sorted by severity with color-coded badges; kernel driver section with IRP dispatch table; clickable handler addresses navigate to disassembly; count badge on tab button colored by max severity (2026-03-07 15:39)
- **Graph mode search** — Ctrl+F or `/` in graph mode opens a search overlay; searches instruction mnemonics+operands with regex support; Enter/Shift+Enter cycles matches; matched instructions highlighted in CFG blocks with current match outlined in orange (2026-03-07 15:39)
- **Persistent AI results** — AI enhance/explain results are cached per function; switching tabs and returning to AI tab restores the cached result without re-running the LLM (2026-03-07 15:39)

### Changed

- **Performance: worker decompile maps** — iatMap, stringMap, and jumpTables are now stored in the worker and reused across decompile calls instead of being re-serialized every invocation (2026-03-07 16:33)
- **Performance: deduplicate buildIATLookup** — IAT lookup map computed once in App.tsx and stored in AppState; DisassemblyView and useDisassemblyRows read from state instead of recomputing (2026-03-07 16:33)
- **Performance: memoize GraphOverviewContext** — context value stabilized with useMemo to prevent unnecessary consumer re-renders (2026-03-07 16:33)
- **Performance: memoize App.tsx callbacks/style** — 4 modal onClose handlers wrapped in useCallback, font-size style object wrapped in useMemo (2026-03-07 16:33)
- **Performance: memoize ImportsView filtering** — filtered imports, totalFunctions, and filteredFuncCount wrapped in useMemo (2026-03-07 16:33)
- **Performance: hoist SUSPICIOUS_MNEMONICS** — moved from useMemo inside component to module-level constant (2026-03-07 16:33)
- **Shortcut legend** — `;` description now clarifies it works in both disassembly and pseudocode views (2026-03-07 14:58)

### Fixed

- **Ghidra NotFoundException on binary import** — Ghidra 12 throws `NotFoundException` (not `IOException`) when `openProject()` fails, breaking pyhidra's fallback to `createProject()`; server now catches `NotFoundException` and falls back to direct Java API calls (`GhidraProject.createProject` + `importProgram` + `analyze`), bypassing pyhidra's broken exception handling; stale project directories also pre-cleaned unconditionally; `WindowsResourceReferenceAnalyzer` disabled in fallback path to prevent NPE from uninitialized OSGi BundleHost, and `analyze()` wrapped in try/except so any analyzer crash is non-fatal (2026-03-27 15:30)
- **`;` hotkey in DecompileView** — `preventDefault` now only fires when a matching address is found; added `stopPropagation` to prevent duplicate comment editor in wrong view (2026-03-07 14:58)
- **`?` duplicate shortcut pane** — added `stopPropagation` to prevent event from bubbling and toggling the overlay twice (2026-03-07 14:58)
- **Graph mode hotkey focus** — `cfgContainerRef` now auto-focuses when entering graph mode and on mousedown clicks, so `;`, `?`, `B`, `N`, `I`, `R` etc. work reliably (2026-03-07 14:58)

- **Theme system** — 4 built-in color themes (Dark, Light, IDA Pro, Terminal) with full CSS variable token system; all ~15 component files migrated from hardcoded Tailwind colors to theme-aware CSS classes; import/export custom themes as JSON; theme picker in Settings → Theme tab; mnemonic, operand, and decompiler syntax colors all themeable (2026-03-07 13:10)
- **CSS grid column alignment** — instruction and data rows use CSS grid with `ch`-based column widths that scale with font size; 32-bit (10ch) and 64-bit (18ch) address columns; toggleable bytes column with toolbar button (2026-03-07 13:10)
- **Context menu enhancements** — "Follow target" item for call/jmp instructions, "Show xrefs (N)" item with xref count; unified menu component for linear and graph modes (removes duplicated code); keyboard shortcut hints on right side; backdrop blur visual polish (2026-03-07 13:10)
- **Scroll-synced split view** — scrolling disassembly auto-scrolls decompile panel to matching code region; separate `scrollSyncAddr` state avoids feedback loops with `SET_ADDRESS`; throttled (100ms) scroll handler; sync toggle button in decompile panel header; persists to localStorage (2026-03-07 13:10)


- **Decompiler output improvements** — cast elimination (double-cast always collapses, cast-on-const folded, same-size cast stripped); De-Morgan's law for `!(a && b)` / `!(a || b)`; comparison canonicalization (const on right); recursive guard clause flattening for deeply nested if/return/else chains; for-loop detection scans all body blocks for increment; do-while with leading break converted to while; string constant propagation into emitted call args; type-based variable naming (HANDLE→hFile, NTSTATUS→status, HRESULT→hr, PVOID→pBuffer, BOOL→bResult) (2026-03-07 12:33)
- **Regex search UI hint** — `?` help icon next to search bar shows tooltip explaining `/regex/` and `/regex/i` syntax (2026-03-07 00:07)
- **Search results grouping** — search matches grouped by function with match counts; clickable function names to navigate; shown when matches span 2+ functions (2026-03-07 00:07)
- **Operand hover tooltips** — hovering clickable operand addresses shows contextual info: import names (`kernel32.dll!CreateFileW`), string previews, function names, section offsets; 200ms delay, auto-dismiss (2026-03-07 00:07)
- **Export analysis report** — "Report" button in sidebar generates comprehensive Markdown report with file summary, anomalies, driver info, functions, imports, exports, strings, and annotations; downloadable as `.md` file (2026-03-07 00:07)
- **Enum type inference** — switch statements with 3+ cases auto-infer enum types (`enum_N`); enum member names (`VAL_0x1`) emitted in case labels and constant references; `meetTypes` supports enum lattice merging; 6 new tests (2026-03-07 00:07)
- **Loop-aware SSA optimizations** — natural loop detection via back-edge analysis; Loop-Invariant Code Motion (LICM) hoists invariant assignments to preheader; induction variable recognition tags phi nodes with step metadata; 3 new tests (2026-03-07 00:07)
- **Exception handling IR** — `IRTry` statement type for `__try/__except` blocks; UNWIND_INFO parsing from `.pdata` extracts exception handler RVAs; exception regions wrapped during structuring; `__try/__except(filter)` emission; all walkers updated (ir, fold, emit, cleanup, promote, structs, typeInfer); 3 new tests (2026-03-07 00:07)

- **Global Value Numbering** — SSA-based GVN pass in `ssaopt.ts` eliminates redundant common subexpressions; commutative op normalization (`a+b == b+a`); conservative handling of calls, derefs, and unknowns (always unique); runs after const prop, before DCE in the optimize loop; 7 new tests (2026-03-06 23:28)
- **Decompiler expression quality** — 7 new fold rules (div/mod, comparison folding, ternary simplification, sign-extend `(x<<24)>>24` → `(int8_t)x`, strength reduction `x*2` → `x<<1`, double-cast removal, negation absorption `!(x==y)` → `x!=y`); `IRArrayAccess` node with `base[index]` emit instead of `*(type*)(base + idx * scale)`; increment/decrement `x++`/`x--` instead of `x = x + 1`; redundant cast suppression via TypeContext; array rewrite in struct synthesis pass (2026-03-06 22:30)
- **Control flow improvements** — `IRContinue` statement; continue detection in loops (goto-to-header → continue); guard clause flattening (`if(cond){return} else{rest}` → `if(cond){return} rest`); redundant goto/empty-block elimination; better loop classification (body-top break → while(!cond)); chained short-circuit `a && b && c` up to 8 blocks; post-structuring `cleanupStructured` pass (2026-03-06 22:30)
- **Expanded type system** — HANDLE, NTSTATUS, HRESULT as distinct DecompType kinds; type-aware idioms (`x == INVALID_HANDLE_VALUE`, `NT_SUCCESS(x)`, `SUCCEEDED(x)`, `FAILED(x)`); ~130 Win32/NT API signatures across memory, string, file I/O, process/thread, sync, exception, crypto, COM, NT/Zw, network, device I/O categories; auto stack-frame synthesis when no stack frame analysis available (2026-03-06 22:30)
- **Fold rule unit tests** — 20 tests covering all new fold rules in `fold.test.ts` (2026-03-06 22:30)

- **Struct synthesis engine** — full struct type system for decompiler: `IRFieldAccess` IR node, `StructRegistry` cross-function state with fingerprint-based deduplication and subset merging, address decomposition (`base + idx*scale + offset`), automatic struct candidate detection from 2+ offset accesses on same base, field type inference (signedness from comparisons, pointer from derefs, float from XMM), alias-aware base grouping, call-site parameter linking for cross-function struct propagation, typedef emission (`typedef struct { ... } struct_N;`), `->fieldName` syntax in emitted pseudocode; replaces old cosmetic `collectStructBases` heuristic (2026-03-06 20:39)

- **Font-size responsive CFG blocks** — graph view block dimensions and text sizes now scale with the font size setting; `CFG_LAYOUT` converted to `getCfgLayout(fontSize)`, hardcoded pixel font sizes replaced with em-relative units (2026-03-06 18:48)
- **Unconstrained decompile panel resize** — removed 800px max width cap and lowered minimum to 100px; panel can now grow as wide as viewport allows (2026-03-06 18:17)
- **Graph re-center on decompile open** — opening the decompile panel in graph mode now re-centers the CFG on the current block after layout adjusts (2026-03-06 18:17)
- **Tabbed settings modal** — settings reorganized into three tabs: AI (provider, key, model, enhance source, base URL), Ghidra (server toggle, URL, API key), Display (font size) (2026-03-06 18:17)

- **SSA-based decompiler** — full Static Single Assignment pass with phi nodes inserted between lift and structure phases; Cooper-Harvey-Kennedy dominator algorithm, pruned phi insertion with liveness, per-register versioning and renaming; SSA optimization passes (simplify phis, copy propagation, constant propagation, dead code elimination); SSA destruction with phi-to-copy lowering; cross-block value propagation now produces cleaner pseudocode with fewer redundant assignments (2026-03-06 17:59)
- **Type inference engine** — forward + backward type propagation over decompiled IR; lattice types (int with signedness, float, ptr, bool, void); signed/unsigned inference from Jcc comparisons, cast annotations, and deref patterns; API-aware typing from ~50 Win32/C function signatures (VirtualAlloc, CreateFile, GetProcAddress, memcpy, etc.) (2026-03-06 17:59)
- **Wider instruction lifting** — sign extensions (cdq, cqo, cdqe, cwde, cbw, cwd), div/idiv (quotient + remainder), single-operand mul (high-part eliminated by SSA DCE), xchg (SSA-correct swap without temp), rep movsb/stosb → memcpy/memset, basic FPU (fld/fst/fstp/fadd/fsub/fmul/fdiv on st0), SSE scalar ops (movss/addss/subss/mulss/divss/comiss on xmm registers) (2026-03-06 17:59)
- **Short-circuit && / || detection** — consecutive conditional blocks sharing a common branch target are now collapsed into compound boolean expressions instead of nested if-else (2026-03-06 17:59)
- **Multi-exit loop break detection** — conditional branches inside loop bodies targeting outside the loop are now emitted as `if (cond) break;` instead of gotos (2026-03-06 17:59)
- **De Morgan negation for && / ||** — condition negation now applies De Morgan's law: `!(a && b)` → `!a || !b` (2026-03-06 17:59)
- **for-loop emission** — `IRFor` statement type with init/condition/update/body emitted as `for (init; cond; update) { body }` (2026-03-06 17:59)

### Changed

- **Minimap hidden in graph mode** — minimap and Map button only shown in linear view mode (2026-03-07 14:17)

### Removed

- **Blocks button** — removed block tinting toggle and alternating block backgrounds from disassembly toolbar (2026-03-07 14:17)
- **Compact button** — removed compact density mode toggle; fixed row height at 20px; removed `.density-compact` CSS (2026-03-07 14:17)

- **Decompiler pipeline** — new pipeline: buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → inferTypes → promoteVars → synthesizeStructs → emitFunction; cleanup pass inserted after structuring; TypeContext threaded to emitter for cast suppression and type idioms (2026-03-06 22:30)

- **Decompile panel sub-tabs** — decompile panel now has three pill tabs: **Low Level** (existing built-in decompiler), **High Level** (Ghidra server with WASM fallback stub), and **AI** (enhance/explain using best available source); active tab remembered across function navigation; per-tab per-function caching; decompile state extracted into `useDecompileTabs` hook
- **Ghidra decompilation server** — companion `ghidra-server/` with Dockerfile, FastAPI REST endpoints (`/ping`, `/binary`, `/decompile`), pyhidra integration; optional bearer token auth; binary uploaded once and cached by SHA-256

### Fixed

- **Ghidra Docker image** — Dockerfile now downloads and installs Ghidra 11.3.2 with JDK 21; forces `linux/amd64` platform (Ghidra has no `linux_arm_64` decompiler binary); fixes container crash on startup due to missing `GHIDRA_INSTALL_DIR`; native decompiler binaries `chmod +x` after unzip; `DecompInterface.openProgram()` return value checked; server error details now surfaced in client UI (2026-03-06 15:40)
- **Decompilation server settings** — new "Decompilation Server" section in Settings modal with enable checkbox, server URL, and optional API key; stored in `peek-a-bin:decompile-server` localStorage key

- **Data section view** — non-executable sections (`.rdata`, `.data`, etc.) now render as structured data directives instead of garbage disassembly: `db` with string literals (green, ASCII/UTF-16LE), `dd`/`dq` with clickable pointer targets and resolved labels (IAT imports, functions, strings), `dup` for padding runs, and raw `db` hex with ASCII preview; jump arrows, graph toggle, and decompiler are hidden for data sections; search and range copy fully supported
- **Font size setting** — configurable monospace font size (10–16px) via slider in Settings modal; applied globally to disassembly, hex view, pseudocode, and CFG blocks via CSS custom property; persisted to localStorage
- **Keyboard shortcuts panel update** — added missing shortcuts: `Space` (graph toggle), `;` (comment), `N` (rename), `X`/`R`/`I`/`D` (panel toggles), `Alt+H` (recent addresses); new Graph category with block navigation, Tab, Enter, and zoom-to-fit shortcuts

- **Explain with AI** — new button in the Pseudocode panel header sends decompiled code to the LLM with an explanation prompt and streams the result back as `//` comments prepended to the pseudocode; mutually exclusive with Enhance (starting one cancels the other)

- **Back-navigation preserves full view state** — pressing `Escape` to go back now restores viewMode (linear/graph), graph pan position, and zoom level, not just the address; works across function jumps (call stack), section changes, and graph↔linear transitions

- **Recent files with instant re-open** — recently opened PE files are stored in IndexedDB (up to 5 entries, 50 MB cap) and shown on the file loader screen with file size, relative timestamp, and annotation summary; click to re-open instantly without re-browsing; remove button clears both IndexedDB and localStorage entries
- **Callers/callees sidebar panel** — collapsible "Call Graph" panel in the sidebar (between Bookmarks and Functions) shows which functions call the active function and what it calls; built from call graph data extracted during xref analysis; click entries to navigate with call stack push
- **PE anomaly detection** — automatic detection of 10 suspicious PE characteristics grouped by severity: critical (entry point in writable section, WX sections), warning (unusual entry point, packer section names, TLS callbacks, checksum mismatch, high code entropy), info (ASLR/DEP disabled, overlay data); shown as colored dismissible banners at the top of the Headers view
- **Data cross-references** — references to `.data`, `.rdata`, and `.bss` addresses (globals, vtables, etc.) are now tracked globally during xref analysis; Hex view shows purple xref count badges on rows containing referenced addresses with click-to-popup listing all referencing instructions
- **Escape navigates back in graph view** — pressing `Escape` in graph view pops the call stack breadcrumb or navigates back in history (same as the back arrow button), works globally without requiring focus on the graph container
- **Leading-whitespace string stripping** — `.rdata` strings starting with whitespace/control characters (`\t`, `\n`, `\r`) are now detected by skipping leading whitespace bytes and extracting from the first printable character, for both ASCII and UTF-16LE scanners
- **Inline graph view** — CFG is now an IDA Pro-style inline view togglable with `Space`, replacing the old modal overlay. Stays in graph mode across function changes; viewMode persisted to localStorage
- **Full interaction parity in graph blocks** — clicking, context menus, keyboard navigation, comments (`;`), register highlighting, operand navigation, and bookmarks all work identically inside graph blocks
- **Graph keyboard navigation** — `Arrow Up/Down` navigate within and across blocks, `Tab` cycles successor blocks, `Enter` follows branch targets, `0` zooms to fit the entire graph
- **Collapsible blocks** — click a block header to collapse/expand it
- **Graph minimap** — minimap transforms to show block rectangles with viewport indicator; click to pan the graph
- **Graph overview in sidebar** — IDA-style graph overview panel at the bottom of the sidebar showing all blocks, edges, and a viewport rectangle; click or drag to pan the main graph view; collapsible with state persisted to localStorage
- **Zoom toward cursor** — mouse wheel zoom centers on the cursor position instead of the origin
- **Copy comment** — context menu option to copy instruction/user comments to clipboard (both linear and graph mode)
- **Collapsible sections panel** — sidebar sections panel can now be collapsed/expanded with state persisted to localStorage
- **Trackpad swipe prevention** — graph view blocks browser back/forward navigation triggered by horizontal two-finger swipe gestures

### Fixed

- **Settings modal no longer dismissible by accident** — removed backdrop click and Escape key handlers; modal now only closes via Save or Cancel buttons

### Changed

- **Compact graph spacing** — reduced vertical spacing (80→40), horizontal spacing (50→30), edge separation (20→10), and instruction line height (16→14px) for denser, more compact graph blocks
- CFG layout constants updated for better readability: wider blocks (320px), taller rows (16px), more spacing between blocks
- Extracted shared disassembly utilities (`ColoredOperand`, `mnemonicClass`, `tokenizeOperand`, `parseBranchTarget`, `REG_NAMES`) into `src/components/shared.tsx` for reuse between linear and graph views
- Toolbar "CFG" button replaced with a "Graph" toggle button that reflects active state

### Removed

- CFG modal overlay — replaced by the inline graph view

---

### Previously Added

- **Kernel driver detection** — automatically identifies `.sys` drivers by checking for NATIVE subsystem, WDM_DRIVER DllCharacteristics flag, and imports from kernel modules (ntoskrnl.exe, hal.dll, ndis.sys, fltmgr.sys, etc.) (`src/analysis/driver.ts`)
- **Driver banner and badge** — dismissible amber banner between address bar and tab content showing driver type, WDM status, and kernel API count; small amber badge in the status bar
- **Suspicious kernel API flagging** — database of 50+ kernel APIs across 7 risk categories (Process/Thread, Callback/Hook, Memory, Registry, Filesystem, Network, Object) with color-coded inline tags in the Imports view
- **IOCTL code decoder** — decodes Windows I/O control codes into device type, access, function number, and transfer method; annotates IOCTL constants inline in both disassembly and decompiler output
- **IRP dispatch table detection** — pattern-matches `mov [reg+offset], handler` instructions in DriverEntry to identify MajorFunction handler assignments (IRP_MJ_CREATE through IRP_MJ_PNP); auto-renames handler functions
- **Authenticode parsing** — parses WIN_CERTIFICATE / PKCS#7 SignedData structures with a minimal DER walker (~200 lines, no ASN.1 library) to extract signer subject CN, issuer CN, and validity dates (`src/pe/authenticode.ts`)
- **Digital Signature section in Headers view** — collapsible section showing signed/unsigned badge, subject, issuer, validity period, signature size, and certificate type
- **Resource Directory parsing** — full recursive tree walk of PE resource directories with support for named and ID-based entries, depth-limited traversal, and circular reference protection (`src/pe/resources.ts`)
- **ResourcesView component** — tree view UI grouped by resource type (Icon, Version Info, Manifest, etc.) with expand/collapse, size/RVA display, and per-entry download button
- **Version Info extraction** — parses VS_VERSIONINFO structures to display FileVersion, ProductName, CompanyName, and other StringFileInfo key-value pairs
- **Icon reconstruction** — reconstructs valid `.ico` files from RT_GROUP_ICON + RT_ICON resource entries with inline preview
- **Manifest display** — renders RT_MANIFEST XML content in a scrollable `<pre>` block
- **Resources tab** — accessible via keyboard shortcut `8`, added to tab bar and routing
- **Keyboard Shortcuts panel** — press `?` to toggle a modal overlay showing all 12 keyboard shortcuts grouped by category (Navigation, Annotations, Search, Clipboard, Disassembly)
- **Unified analysis export** — export now includes hex patches as `[offset, value]` tuples and detected functions alongside bookmarks, renames, and comments (v1 schema with `version` field)
- **Unified analysis import** — imports v1 schema files with full hex patch and annotation merging; maintains backward compatibility with legacy annotation-only JSON files
- **Unit tests** — 27 tests covering PE32/PE64 parsing, DOS/PE signature validation, COFF fields, imageBase, section headers, `rvaToFileOffset`, truncated buffers, and `.pdata` exception directory parsing
- **Test fixture builder** — `buildMinimalPE32()` and `buildMinimalPE64()` construct valid PE buffers programmatically for testing without binary fixture files
- **PWA / offline support** — service worker via `vite-plugin-pwa` precaches all assets including `capstone.wasm` (~2 MB) for full offline functionality; app is installable as a standalone PWA
- **PWA manifest and icons** — `manifest.json` with 192px and 512px icons, theme color `#111827`

### Changed

- Export filename changed from `{fileName}.json` to `{fileName}-analysis.json`
- Export format now uses versioned schema (`version: 1`) for forward compatibility
- Page title in `index.html` updated from "Web Disassembly Viewer" to "Peek-a-Bin"
