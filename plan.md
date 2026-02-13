# Web Disassembly Viewer — Plan

## Overview
Browser-based PE disassembly viewer. All processing client-side via WASM. React+TS frontend.

## Architecture

```
[File Drop] → [PE Parser (TS)] → [Capstone WASM] → [React Viewer]
```

- **PE Parsing**: Pure TypeScript — parse headers, sections, imports, exports. No WASM needed for this; PE format is well-documented and TS is sufficient.
- **Disassembly Engine**: Capstone.js (capstone-wasm) — mature WASM port of Capstone, supports x86/x64.
- **Frontend**: React + TypeScript + Vite. Virtual scrolling for large binaries.

## Core Features (MVP)

1. **File loader** — drag-and-drop or file picker for `.exe`/`.dll`
2. **PE header view** — DOS header, PE signature, COFF header, optional header, data directories
3. **Section table** — list sections (.text, .data, .rdata, etc.) with RVA, size, characteristics
4. **Disassembly view** — linear disassembly of executable sections
   - Address | Hex bytes | Mnemonic | Operands
   - Virtual scrolling (binaries can have millions of instructions)
5. **Imports/Exports tables** — parsed IAT/EAT with library names + function names
6. **Hex view** — raw hex dump of selected section/range
7. **Navigation** — go-to-address, click on address operands to jump

## Project Structure

```
web-disassembly/
├── index.html
├── vite.config.ts
├── tsconfig.json
├── package.json
├── src/
│   ├── main.tsx                  # Entry point
│   ├── App.tsx                   # Layout + routing between views
│   ├── pe/
│   │   ├── parser.ts             # PE format parser (ArrayBuffer → PEFile)
│   │   ├── types.ts              # PE structs (DOSHeader, COFFHeader, SectionHeader, etc.)
│   │   └── constants.ts          # Magic numbers, flags, characteristic bitfields
│   ├── disasm/
│   │   ├── engine.ts             # Capstone WASM wrapper
│   │   └── types.ts              # Instruction type, operand types
│   ├── components/
│   │   ├── FileLoader.tsx         # Drag-and-drop + file picker
│   │   ├── HeaderView.tsx         # PE headers display
│   │   ├── SectionTable.tsx       # Section list
│   │   ├── DisassemblyView.tsx    # Main disassembly listing (virtualized)
│   │   ├── HexView.tsx            # Hex dump
│   │   ├── ImportsView.tsx        # Import table
│   │   ├── ExportsView.tsx        # Export table
│   │   ├── Sidebar.tsx            # Navigation sidebar (sections, symbols)
│   │   └── AddressBar.tsx         # Go-to-address input
│   ├── hooks/
│   │   └── usePEFile.ts           # State management for loaded PE
│   └── styles/
│       └── index.css              # Dark theme, monospace layout
```

## Tech Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Build | Vite | Fast HMR, WASM support out of box |
| UI | React 19 + TS | Per user preference |
| Disasm | capstone-js (WASM) | Battle-tested, x86/x64, ~400KB WASM |
| Virtualization | @tanstack/react-virtual | Handles millions of rows efficiently |
| Styling | Tailwind CSS | Utility-first, fast iteration, dark theme trivial |
| State | React context + useReducer | Simple enough for single-file viewer, no Redux needed |

## PE Parser Detail

Parse from ArrayBuffer using DataView:
- DOS Header → e_lfanew → PE Signature → COFF Header → Optional Header
- Section headers array
- Walk data directories for imports (RVA → file offset via section mapping)
- Walk export directory for exports
- All offsets computed via RVA-to-file-offset translation using section table

## Disassembly Strategy

- Disassemble on-demand per visible window (not entire binary upfront)
- Cache disassembled regions in a Map<number, Instruction[]>
- Linear sweep within executable sections
- Detect x86 vs x64 from PE Optional Header magic (0x10b = PE32, 0x20b = PE32+)

## Implementation Order

1. Scaffold project (Vite + React + TS + Tailwind)
2. PE parser — types + parser for headers, sections, imports, exports
3. Capstone WASM integration — wrapper that takes bytes + base address → instructions
4. FileLoader component — drag/drop, read as ArrayBuffer
5. HeaderView + SectionTable — display parsed PE metadata
6. DisassemblyView — virtualized instruction listing with on-demand disassembly
7. ImportsView + ExportsView
8. HexView
9. Navigation (go-to-address, click-to-jump)
10. Polish — keyboard shortcuts, search, theming

## Resolved Decisions

1. **Capstone package**: Use `capstone-wasm` npm package. Fall back to vendored Emscripten build if bundler compat issues arise.
2. **Function detection**: YES for MVP. Heuristic prologue scanning — detect `push ebp; mov ebp, esp` (x86) and `sub rsp, ...` (x64) patterns. Populates function list in sidebar.
3. **String references**: YES for MVP. Scan .rdata for null-terminated strings, build address→string map. When an instruction operand references a .rdata address with a known string, annotate as inline comment (e.g. `; "Hello World"`).
