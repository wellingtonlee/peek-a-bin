# Theming

Peek-a-Bin supports 4 built-in themes and custom theme import/export.

## Built-in Themes

| Theme | Description |
|-------|-------------|
| **Dark** | Default dark theme with blue accents |
| **Light** | Light background with high-contrast syntax |
| **IDA Pro** | Classic IDA-inspired dark palette |
| **Terminal** | Monochrome green-on-black CRT aesthetic |

## Switching Themes

Open **Settings** (gear icon or command palette) and go to the **Theme** tab. Click any theme to apply it instantly.

## Font Size

Adjustable from 10px to 16px via a slider in **Settings > Display** tab. The font size applies globally to disassembly, hex view, pseudocode, and CFG blocks.

- CSS variable: `--mono-font-size`
- localStorage key: `peek-a-bin:font-size`
- Default: 12px

## Custom Themes

### Creating a Custom Theme

1. Export a built-in theme as a baseline (use the **Export** button in Settings > Theme)
2. Edit the JSON — modify any of the 51 color tokens
3. Import the modified JSON (use the **Import** button)

### JSON Format

```json
{
  "id": "my-custom-theme",
  "name": "My Custom Theme",
  "colors": {
    "bg": "#0f172a",
    "bgSecondary": "#1e293b",
    ...
  }
}
```

All 51 color keys must be present. Missing keys will cause a validation error on import.

### Managing Custom Themes

- Custom themes appear alongside built-in themes in the picker
- Delete a custom theme from the Settings panel
- localStorage key: `peek-a-bin:custom-themes`

## Color Token Reference

All 51 tokens from `src/styles/themes.ts`, grouped by category:

### Backgrounds

| Token | Description |
|-------|-------------|
| `bg` | Primary background |
| `bgSecondary` | Secondary background (panels, sidebars) |
| `bgTertiary` | Tertiary background |
| `bgHover` | Hover state background |
| `bgSelected` | Selected item background |
| `bgCurrent` | Current address highlight |

### Text

| Token | Description |
|-------|-------------|
| `text` | Primary text |
| `textSecondary` | Secondary/dimmed text |
| `textMuted` | Muted/disabled text |

### Disassembly Syntax

| Token | Description |
|-------|-------------|
| `address` | Address column |
| `bytes` | Raw bytes column |
| `mnemonic` | Default instruction mnemonic |
| `mnCall` | Call instructions |
| `mnRet` | Return instructions |
| `mnJump` | Jump/branch instructions |
| `mnNop` | NOP instructions |
| `mnStack` | Stack operations (push/pop) |
| `operands` | Default operand text |
| `opRegister` | Register names |
| `opImmediate` | Immediate values |
| `opMemory` | Memory references |
| `opTarget` | Branch/call targets |
| `comment` | Auto-generated comments |
| `userComment` | User-added comments |

### Decompiler Syntax

| Token | Description |
|-------|-------------|
| `keyword` | C keywords (if, while, return, etc.) |
| `typeName` | Type names (int, void, HANDLE, etc.) |
| `string` | String literals |
| `number` | Numeric constants |
| `decompComment` | Decompiler comments |

### UI Chrome

| Token | Description |
|-------|-------------|
| `border` | Primary borders |
| `borderSubtle` | Subtle/faint borders |
| `accent` | Accent color (buttons, links) |
| `scrollThumb` | Scrollbar thumb |
| `scrollTrack` | Scrollbar track |

### Labels & Badges

| Token | Description |
|-------|-------------|
| `funcLabel` | Function label text |
| `separator` | Section separators |

## CSS Variable Pattern

Theme tokens are applied as CSS custom properties on the document root:

```
--t-{kebab-case-key}
```

Examples:
- `bgSecondary` → `--t-bg-secondary`
- `mnCall` → `--t-mn-call`
- `opRegister` → `--t-op-register`
- `funcLabel` → `--t-func-label`

Use these variables in Tailwind classes or custom CSS:

```css
.my-element {
  color: var(--t-text);
  background: var(--t-bg-secondary);
}
```

## localStorage Keys

| Key | Description |
|-----|-------------|
| `peek-a-bin:theme-id` | Active theme ID (e.g., "dark", "light", "ida", "terminal", or custom ID) |
| `peek-a-bin:custom-themes` | JSON array of custom `Theme` objects |
| `peek-a-bin:font-size` | Font size in pixels (10–16) |
