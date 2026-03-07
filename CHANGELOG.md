# Changelog

## [Unreleased]

### Added

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
