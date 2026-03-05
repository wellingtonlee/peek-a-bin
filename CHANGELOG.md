# Changelog

## [Unreleased]

### Added

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

### Changed

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
