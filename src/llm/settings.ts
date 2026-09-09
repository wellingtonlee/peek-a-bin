import { ANTHROPIC_DEFAULT_BASE_URL, ANTHROPIC_DEFAULT_MODEL, type LLMProvider } from "./models";

export interface LLMSettings {
  provider: LLMProvider;
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
  // Model IDs live in models.ts — they were duplicated here and in SettingsModal,
  // which is how they drifted a full generation behind.
  model: ANTHROPIC_DEFAULT_MODEL,
  // Was https://api.openai.com — a leftover from when buildUrl hardcoded the
  // Anthropic endpoint and never read this field. client.ts still treats the old
  // value as "use the default" so saved profiles keep working.
  baseUrl: ANTHROPIC_DEFAULT_BASE_URL,
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
  } catch {
    /* ignore corrupt */
  }

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
  } catch {
    /* ignore corrupt legacy */
  }

  const profile = makeDefaultProfile();
  return { profiles: [profile], activeId: profile.id };
}

export function saveProfiles(store: LLMProfileStore): void {
  localStorage.setItem(PROFILES_KEY, JSON.stringify(store));
}

export function getActiveProfile(store?: LLMProfileStore): LLMProfile {
  const s = store ?? loadProfiles();
  return s.profiles.find((p) => p.id === s.activeId) ?? s.profiles[0] ?? makeDefaultProfile();
}

export function setActiveProfileId(id: string): void {
  const store = loadProfiles();
  if (store.profiles.some((p) => p.id === id)) {
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
  const idx = store.profiles.findIndex((p) => p.id === store.activeId);
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

/**
 * What a user is told when {@link hasApiKey} refuses an AI action.
 *
 * THE ONE DECLARATION, because both remaining gates — `useAIChat`'s
 * `sendMessage` and `useDecompileTabs`' `triggerAI` — must say the same thing,
 * and the sentence belongs beside the predicate it explains rather than being
 * written out at each site.
 *
 * Both gates dispatch `peek-a-bin:open-settings` and return. The dispatch is
 * right — Settings is where the remedy is, and it opens on the AI tab — but on
 * its own it reads as a broken button: a click on Send or Enhance made the
 * Settings dialog appear with nothing saying why, which is exactly what was
 * reported. So each gate now ALSO sets the error state its own panel already
 * renders. There is no toast mechanism in this app and one is deliberately not
 * invented for a bug fix (`peek-a-bin-p0tz`'s rule); both panels already have a
 * red banner fed by an `error` field, and that is the surface reused.
 *
 * It names the precondition and the remedy and stops there. It does NOT promise
 * the action will resume once a key is saved — it will not. The gate has no
 * retry; that needs a queued-intent mechanism and is a separate question.
 */
export const NO_API_KEY_MESSAGE =
  "No API key configured — add one under Settings → AI, then try again.";

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
  } catch {
    /* ignore corrupt */
  }
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
