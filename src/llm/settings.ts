export interface LLMSettings {
  provider: "anthropic" | "openai";
  apiKey: string;
  model: string;
  baseUrl: string;
  enhanceSource: "pseudocode" | "assembly";
}

const STORAGE_KEY = "peek-a-bin:llm-settings";

const DEFAULTS: LLMSettings = {
  provider: "anthropic",
  apiKey: "",
  model: "claude-sonnet-4-20250514",
  baseUrl: "https://api.openai.com",
  enhanceSource: "pseudocode",
};

export function loadSettings(): LLMSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch { /* ignore corrupt */ }
  return { ...DEFAULTS };
}

export function saveSettings(settings: LLMSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

export function hasApiKey(): boolean {
  return loadSettings().apiKey.length > 0;
}

// ── Decompile Server Settings ──

export interface DecompileServerSettings {
  ghidraUrl: string;
  apiKey: string;
  enabled: boolean;
}

const DECOMPILE_SERVER_KEY = "peek-a-bin:decompile-server";

const DECOMPILE_SERVER_DEFAULTS: DecompileServerSettings = {
  ghidraUrl: "http://localhost:8765",
  apiKey: "",
  enabled: false,
};

export function loadDecompileServer(): DecompileServerSettings {
  try {
    const raw = localStorage.getItem(DECOMPILE_SERVER_KEY);
    if (raw) return { ...DECOMPILE_SERVER_DEFAULTS, ...JSON.parse(raw) };
  } catch { /* ignore corrupt */ }
  return { ...DECOMPILE_SERVER_DEFAULTS };
}

export function saveDecompileServer(settings: DecompileServerSettings): void {
  localStorage.setItem(DECOMPILE_SERVER_KEY, JSON.stringify(settings));
}

// ── Font Size ──

const FONT_SIZE_KEY = "peek-a-bin:font-size";

export function loadFontSize(): number {
  try {
    const raw = localStorage.getItem(FONT_SIZE_KEY);
    if (raw) {
      const n = parseInt(raw, 10);
      if (n >= 10 && n <= 16) return n;
    }
  } catch {}
  return 12;
}

export function saveFontSize(size: number): void {
  localStorage.setItem(FONT_SIZE_KEY, String(size));
  window.dispatchEvent(new CustomEvent("peek-a-bin:font-size-changed"));
}
