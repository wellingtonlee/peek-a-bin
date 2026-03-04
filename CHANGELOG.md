# Changelog

## [Unreleased]

### Added

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
