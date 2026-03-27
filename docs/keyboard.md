# Keyboard Shortcuts

Press `?` in the app to see an interactive shortcuts panel.

## Navigation

| Key | Action |
|-----|--------|
| `Space` | Toggle linear / graph view |
| `G` | Go to address dialog |
| `Ctrl+P` / `Cmd+P` | Command palette |
| `?` | Toggle keyboard shortcuts panel |
| `1`–`8` | Switch tabs (Headers, Disasm, Hex, Imports, Exports, Strings, Resources, Anomalies) |
| `9` | Anomalies tab |
| `Alt+Left` | Navigate back in history |
| `Alt+Right` | Navigate forward in history |
| `Alt+H` | Recent addresses dropdown (searchable) |
| `Escape` | Navigate back (pops call stack breadcrumb) |

## Search

| Key | Action |
|-----|--------|
| `Ctrl+F` | Search disassembly (supports `/regex/` and `/regex/i` syntax) |
| `/` | Search in graph mode (opens search overlay in CFG view) |

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
| `X` | Toggle Xrefs panel |
| `R` | Toggle Resources panel |
| `I` | Toggle Imports panel |
| `D` | Toggle Detail panel |

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

- Pressing `?` in the app always shows the latest shortcuts
- Graph mode keyboard navigation requires focus on the graph container — click the graph area or press `Space` to enter graph mode
- `Escape` in graph view restores the full view state (linear/graph mode, pan position, zoom level)
- Back navigation (`Alt+Left`, `Escape`) preserves view mode, graph pan position, and zoom level
