# Keyboard Shortcuts

Press `?` in the app to see an interactive shortcuts panel.

## Navigation

| Key | Action |
|-----|--------|
| `Space` | Toggle linear / graph view |
| `G` | Focus the address input |
| `Ctrl+G` / `Cmd+G` | Go to address dialog |
| `Ctrl+P` / `Cmd+P` | Command palette |
| `?` | Toggle keyboard shortcuts panel |
| `1`–`8` | Switch tabs (Disasm, Headers, Sections, Imports, Exports, Hex, Strings, Resources) |
| `←` / `→` | Move between view tabs — only while the tab bar itself has focus; press `Enter` or `Space` to switch to the focused tab |
| `Home` / `End` | Move to the first or last view tab — only while the tab bar itself has focus. Everywhere else these keys belong to the disassembly listing (see below) |
| `Alt+Left` | Navigate back in history |
| `Alt+Right` | Navigate forward in history |
| `Alt+H` | Recent addresses dropdown (searchable) |
| `Escape` | Navigate back (pops call stack breadcrumb) |

## Search

| Key | Action |
|-----|--------|
| `Ctrl+F` | Search disassembly (supports `/regex/` and `/regex/i` syntax) |
| `/` | Search in graph mode (opens search overlay in CFG view) |
| `F3` / `Shift+F3` | Jump to the next or previous search match, without refocusing the search box |

## Disassembly

| Key | Action |
|-----|--------|
| `Arrow Up/Down` | Navigate instructions |
| `PgUp` / `PgDn` | Scroll 40 instructions |
| `Home` / `End` | Jump to the first or last instruction in the listing — unless focus is inside the view tab bar, which owns these keys for itself |
| `[` / `]` | Move to the previous or next function. A step off either end of the function list does nothing |

## Clipboard

| Key | Action |
|-----|--------|
| `Ctrl+C` | Copy instruction (or the selected range) |
| `Ctrl+Shift+C` | Copy address |

## Mouse

| Action | Result |
|--------|--------|
| Double-click an address | Copy address |
| Double-click a function label | Rename function |
| `Shift`+Click | Select a range of instructions |
| Right-click | Context menu |

## Annotations

| Key | Action |
|-----|--------|
| `B` | Toggle bookmark at current address |
| `N` | Rename function at current address |
| `;` | Add/edit comment (works in both disassembly and pseudocode views) |
| `Ctrl+Z` | Undo |
| `Ctrl+Shift+Z` | Redo |

## Panels

| Key | Action |
|-----|--------|
| `X` | Toggle callers/callees panel |
| `R` | Toggle cross-reference panel |
| `I` | Toggle instruction detail panel |
| `D` | Toggle decompiler panel |

## AI

| Key | Action |
|-----|--------|
| `Ctrl+Shift+A` | Toggle AI Chat panel |

## Graph Mode

These shortcuts are active when the CFG graph view is displayed (toggle with `Space`):

| Key | Action |
|-----|--------|
| `Arrow Up/Down` | Navigate within and across blocks |
| `Tab` | Cycle successor blocks |
| `Enter` | Follow branch target |
| `0` | Zoom-to-fit entire graph |
| `/` or `Ctrl+F` | Search instructions in graph |

All annotation shortcuts (`B`, `N`, `;`) and interaction features (context menus, register highlighting, operand navigation) work identically inside graph blocks.

## Tips

- Pressing `?` in the app always shows the latest shortcuts. The panel is rendered
  from `SHORTCUT_GROUPS` in `src/components/KeyboardShortcuts.tsx`, which is the
  single source of truth — update it and this file together
- The view tabs are a WAI-ARIA tablist: the whole bar is a single `Tab` stop, and
  `←`/`→`/`Home`/`End` move between the eight tabs **once focus is inside it**. `←`/`→`
  do nothing anywhere else — the disassembly view owns the unmodified arrows — which is
  why they are documented here but not listed in the `?` panel, where every other entry
  is a global binding. `Home`/`End` are listed there, because outside the bar they are a
  binding of the disassembly listing; the two scopes never overlap, since only one of
  them can hold focus. `1`–`8` switch tabs from anywhere and need no focus
- Moving between tabs with the arrows moves FOCUS only; `Enter` or `Space` selects the
  focused tab. Two of the eight panes are code-split and mount on first use, so
  selecting one on the way past would load and permanently mount them both
- Graph mode keyboard navigation requires focus on the graph container — click the graph area or press `Space` to enter graph mode
- `Escape` in graph view restores the full view state (linear/graph mode, pan position, zoom level)
- Back navigation (`Alt+Left`, `Escape`) preserves view mode, graph pan position, and zoom level
