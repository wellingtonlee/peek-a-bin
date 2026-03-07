// Theme system — color token interface, presets, load/save/export/import

export interface ThemeColors {
  // Backgrounds
  bg: string;
  bgSecondary: string;
  bgTertiary: string;
  bgHover: string;
  bgSelected: string;
  bgCurrent: string;

  // Text
  text: string;
  textSecondary: string;
  textMuted: string;

  // Disasm syntax
  address: string;
  bytes: string;
  mnemonic: string;
  mnCall: string;
  mnRet: string;
  mnJump: string;
  mnNop: string;
  mnStack: string;
  operands: string;
  opRegister: string;
  opImmediate: string;
  opMemory: string;
  opTarget: string;
  comment: string;
  userComment: string;

  // Decompiler syntax
  keyword: string;
  typeName: string;
  string: string;
  number: string;
  decompComment: string;

  // UI chrome
  border: string;
  borderSubtle: string;
  accent: string;
  scrollThumb: string;
  scrollTrack: string;

  // Labels/badges
  funcLabel: string;
  separator: string;
}

export interface Theme {
  name: string;
  id: string;
  colors: ThemeColors;
}

// ── Built-in Presets ──

const DARK_COLORS: ThemeColors = {
  bg: "#0f172a",
  bgSecondary: "#1e293b",
  bgTertiary: "#1e293b",
  bgHover: "rgba(59,130,246,0.1)",
  bgSelected: "rgba(67,56,202,0.25)",
  bgCurrent: "rgba(30,64,175,0.3)",

  text: "#e2e8f0",
  textSecondary: "#9ca3af",
  textMuted: "#6b7280",

  address: "#9ca3af",
  bytes: "#6b7280",
  mnemonic: "#60a5fa",
  mnCall: "#4ade80",
  mnRet: "#f87171",
  mnJump: "#fb923c",
  mnNop: "#4b5563",
  mnStack: "#93c5fd",
  operands: "#d1d5db",
  opRegister: "#22d3ee",
  opImmediate: "#fde047",
  opMemory: "#c084fc",
  opTarget: "#60a5fa",
  comment: "#22c55e",
  userComment: "#6ee7b7",

  keyword: "#c084fc",
  typeName: "#60a5fa",
  string: "#4ade80",
  number: "#fde047",
  decompComment: "#6b7280",

  border: "#374151",
  borderSubtle: "rgba(55,65,81,0.5)",
  accent: "#3b82f6",
  scrollThumb: "#4b5563",
  scrollTrack: "#1f2937",

  funcLabel: "#facc15",
  separator: "rgba(55,65,81,0.4)",
};

const LIGHT_COLORS: ThemeColors = {
  bg: "#ffffff",
  bgSecondary: "#f8fafc",
  bgTertiary: "#f1f5f9",
  bgHover: "rgba(59,130,246,0.08)",
  bgSelected: "rgba(99,102,241,0.12)",
  bgCurrent: "rgba(59,130,246,0.1)",

  text: "#1e293b",
  textSecondary: "#64748b",
  textMuted: "#94a3b8",

  address: "#64748b",
  bytes: "#94a3b8",
  mnemonic: "#2563eb",
  mnCall: "#16a34a",
  mnRet: "#dc2626",
  mnJump: "#ea580c",
  mnNop: "#94a3b8",
  mnStack: "#3b82f6",
  operands: "#334155",
  opRegister: "#0891b2",
  opImmediate: "#ca8a04",
  opMemory: "#9333ea",
  opTarget: "#2563eb",
  comment: "#16a34a",
  userComment: "#059669",

  keyword: "#9333ea",
  typeName: "#2563eb",
  string: "#16a34a",
  number: "#ca8a04",
  decompComment: "#94a3b8",

  border: "#e2e8f0",
  borderSubtle: "rgba(226,232,240,0.8)",
  accent: "#3b82f6",
  scrollThumb: "#cbd5e1",
  scrollTrack: "#f1f5f9",

  funcLabel: "#ca8a04",
  separator: "rgba(226,232,240,0.6)",
};

const IDA_COLORS: ThemeColors = {
  bg: "#1a1a2e",
  bgSecondary: "#16213e",
  bgTertiary: "#16213e",
  bgHover: "rgba(100,120,180,0.12)",
  bgSelected: "rgba(100,120,180,0.2)",
  bgCurrent: "rgba(60,90,150,0.25)",

  text: "#c8c8d0",
  textSecondary: "#8888a0",
  textMuted: "#606078",

  address: "#8888a0",
  bytes: "#606078",
  mnemonic: "#7898c8",
  mnCall: "#78b878",
  mnRet: "#c87878",
  mnJump: "#c8a868",
  mnNop: "#505068",
  mnStack: "#8898b8",
  operands: "#b0b0c0",
  opRegister: "#68b8c8",
  opImmediate: "#c8b868",
  opMemory: "#a878c8",
  opTarget: "#7898c8",
  comment: "#68a868",
  userComment: "#88c8a8",

  keyword: "#a878c8",
  typeName: "#7898c8",
  string: "#78b878",
  number: "#c8b868",
  decompComment: "#606078",

  border: "#2a2a48",
  borderSubtle: "rgba(42,42,72,0.6)",
  accent: "#5878a8",
  scrollThumb: "#3a3a58",
  scrollTrack: "#1a1a2e",

  funcLabel: "#c8b868",
  separator: "rgba(42,42,72,0.5)",
};

const TERMINAL_COLORS: ThemeColors = {
  bg: "#000000",
  bgSecondary: "#0a0a0a",
  bgTertiary: "#0a0a0a",
  bgHover: "rgba(0,255,0,0.06)",
  bgSelected: "rgba(0,255,0,0.1)",
  bgCurrent: "rgba(0,200,0,0.12)",

  text: "#00ff00",
  textSecondary: "#00cc00",
  textMuted: "#008800",

  address: "#00cc00",
  bytes: "#006600",
  mnemonic: "#00ff00",
  mnCall: "#00ffaa",
  mnRet: "#ff4444",
  mnJump: "#ffaa00",
  mnNop: "#004400",
  mnStack: "#00ccff",
  operands: "#00dd00",
  opRegister: "#00ffcc",
  opImmediate: "#ffff00",
  opMemory: "#cc88ff",
  opTarget: "#00aaff",
  comment: "#00aa00",
  userComment: "#00dd88",

  keyword: "#cc88ff",
  typeName: "#00aaff",
  string: "#00ffaa",
  number: "#ffff00",
  decompComment: "#006600",

  border: "#003300",
  borderSubtle: "rgba(0,51,0,0.6)",
  accent: "#00ff00",
  scrollThumb: "#004400",
  scrollTrack: "#001100",

  funcLabel: "#ffff00",
  separator: "rgba(0,51,0,0.5)",
};

export const BUILTIN_THEMES: Theme[] = [
  { id: "dark", name: "Dark", colors: DARK_COLORS },
  { id: "light", name: "Light", colors: LIGHT_COLORS },
  { id: "ida", name: "IDA Pro", colors: IDA_COLORS },
  { id: "terminal", name: "Terminal", colors: TERMINAL_COLORS },
];

// ── Load/Save ──

const THEME_ID_KEY = "peek-a-bin:theme-id";
const CUSTOM_THEMES_KEY = "peek-a-bin:custom-themes";

export function loadThemeId(): string {
  try {
    return localStorage.getItem(THEME_ID_KEY) ?? "dark";
  } catch {
    return "dark";
  }
}

export function saveThemeId(id: string): void {
  try {
    localStorage.setItem(THEME_ID_KEY, id);
  } catch {}
}

export function getCustomThemes(): Theme[] {
  try {
    const raw = localStorage.getItem(CUSTOM_THEMES_KEY);
    if (raw) return JSON.parse(raw);
  } catch {}
  return [];
}

export function saveCustomTheme(theme: Theme): void {
  const themes = getCustomThemes().filter(t => t.id !== theme.id);
  themes.push(theme);
  try {
    localStorage.setItem(CUSTOM_THEMES_KEY, JSON.stringify(themes));
  } catch {}
}

export function deleteCustomTheme(id: string): void {
  const themes = getCustomThemes().filter(t => t.id !== id);
  try {
    localStorage.setItem(CUSTOM_THEMES_KEY, JSON.stringify(themes));
  } catch {}
}

export function getAllThemes(): Theme[] {
  return [...BUILTIN_THEMES, ...getCustomThemes()];
}

export function loadTheme(): Theme {
  const id = loadThemeId();
  const all = getAllThemes();
  return all.find(t => t.id === id) ?? BUILTIN_THEMES[0];
}

export function exportTheme(theme: Theme): string {
  return JSON.stringify(theme, null, 2);
}

export function importTheme(json: string): Theme {
  const parsed = JSON.parse(json);
  if (!parsed.name || !parsed.id || !parsed.colors) {
    throw new Error("Invalid theme format: missing name, id, or colors");
  }
  // Validate all required color keys exist
  const required = Object.keys(DARK_COLORS) as (keyof ThemeColors)[];
  for (const key of required) {
    if (typeof parsed.colors[key] !== "string") {
      throw new Error(`Invalid theme: missing color "${key}"`);
    }
  }
  return parsed as Theme;
}

// ── Apply theme to DOM ──

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  for (const [key, value] of Object.entries(theme.colors)) {
    root.style.setProperty(`--t-${camelToKebab(key)}`, value);
  }
}

function camelToKebab(str: string): string {
  return str.replace(/[A-Z]/g, m => `-${m.toLowerCase()}`);
}
