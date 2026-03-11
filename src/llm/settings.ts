export interface LLMSettings {
  provider: "anthropic" | "openai";
  apiKey: string;
  model: string;
  baseUrl: string;
  enhanceSource: "pseudocode" | "assembly";
}

export interface LLMProfile extends LLMSettings {
  id: string;
  name: string;
}

export interface LLMProfileStore {
  profiles: LLMProfile[];
  activeId: string;
}

const STORAGE_KEY = "peek-a-bin:llm-settings";
const PROFILES_KEY = "peek-a-bin:llm-profiles";
const MAX_PROFILES = 10;

const DEFAULTS: LLMSettings = {
  provider: "anthropic",
  apiKey: "",
  model: "claude-sonnet-4-20250514",
  baseUrl: "https://api.openai.com",
  enhanceSource: "pseudocode",
};

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function makeDefaultProfile(): LLMProfile {
  return { ...DEFAULTS, id: generateId(), name: "Default" };
}

export function loadProfiles(): LLMProfileStore {
  try {
    const raw = localStorage.getItem(PROFILES_KEY);
    if (raw) {
      const store: LLMProfileStore = JSON.parse(raw);
      if (store.profiles?.length) return store;
    }
  } catch { /* ignore corrupt */ }

  // Auto-migrate from legacy single-settings key
  try {
    const legacy = localStorage.getItem(STORAGE_KEY);
    if (legacy) {
      const settings: LLMSettings = { ...DEFAULTS, ...JSON.parse(legacy) };
      const profile: LLMProfile = { ...settings, id: generateId(), name: "Default" };
      const store: LLMProfileStore = { profiles: [profile], activeId: profile.id };
      saveProfiles(store);
      localStorage.removeItem(STORAGE_KEY);
      return store;
    }
  } catch { /* ignore corrupt legacy */ }

  const profile = makeDefaultProfile();
  return { profiles: [profile], activeId: profile.id };
}

export function saveProfiles(store: LLMProfileStore): void {
  localStorage.setItem(PROFILES_KEY, JSON.stringify(store));
}

export function getActiveProfile(store?: LLMProfileStore): LLMProfile {
  const s = store ?? loadProfiles();
  return s.profiles.find(p => p.id === s.activeId) ?? s.profiles[0] ?? makeDefaultProfile();
}

export function setActiveProfileId(id: string): void {
  const store = loadProfiles();
  if (store.profiles.some(p => p.id === id)) {
    store.activeId = id;
    saveProfiles(store);
  }
}

export function canAddProfile(store: LLMProfileStore): boolean {
  return store.profiles.length < MAX_PROFILES;
}

export function loadSettings(): LLMSettings {
  const profile = getActiveProfile();
  const { id: _, name: __, ...settings } = profile;
  return settings;
}

export function saveSettings(settings: LLMSettings): void {
  const store = loadProfiles();
  const idx = store.profiles.findIndex(p => p.id === store.activeId);
  if (idx >= 0) {
    store.profiles[idx] = { ...store.profiles[idx], ...settings };
    saveProfiles(store);
  } else {
    // Fallback: write legacy key (shouldn't happen)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  }
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
