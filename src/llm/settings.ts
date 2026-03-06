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
