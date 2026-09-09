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

/** A field of the active profile that a request actually reads. */
export type LLMConfigField = "apiKey" | "model" | "baseUrl";

/** One thing wrong with the active profile, and how to say it. */
export interface LLMConfigIssue {
  field: LLMConfigField;
  /** A noun phrase that reads inside "… is not ready: <detail>, <detail>." */
  detail: string;
}

/** Why the active profile cannot serve an AI request — see {@link llmConfigProblem}. */
export interface LLMConfigProblem {
  /** The active profile's name. It is the ONLY profile a request would use. */
  profileName: string;
  /** Its 1-based position in the store, and how many profiles are configured. */
  profileIndex: number;
  profileCount: number;
  /** What is missing or malformed, in `apiKey`, `model`, `baseUrl` order. */
  issues: LLMConfigIssue[];
  /** The sentence the gates print. THE ONE DECLARATION — see below. */
  message: string;
}

const CUSTOM_URL_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * Is `raw` something `client.ts` could actually post to?
 *
 * `buildUrl` concatenates the configured base with a path, so anything that is
 * not an absolute http(s) URL produces a request against the app's own origin
 * or a malformed one — a failure that surfaces as an HTTP error long after the
 * gate said the configuration was fine.
 */
/**
 * A profile field as a trimmed string, whatever is actually in `localStorage`.
 *
 * `loadProfiles` returns parsed JSON with NO per-field defaulting — only the
 * legacy-migration path spreads `DEFAULTS` — so a profile written by a version
 * of this app that predates a field arrives with it `undefined`, and
 * `LLMProfile` has gained fields more than once. The old `hasApiKey()` would
 * have thrown a TypeError on `.length` for such a store; here it would throw
 * inside a click handler and take the panel to its error boundary. A missing
 * field is exactly a field that is not configured, so it is reported as one.
 */
function trimmedField(value: string | undefined): string {
  return typeof value === "string" ? value.trim() : "";
}

function isUsableBaseUrl(raw: string): boolean {
  try {
    return CUSTOM_URL_PROTOCOLS.has(new URL(raw).protocol);
  } catch {
    return false;
  }
}

/**
 * What stops the ACTIVE profile from serving an AI request, or null if nothing
 * does. The one gate `useAIChat` and `useDecompileTabs` both ask.
 *
 * IT REPLACES `hasApiKey()`, WHICH WAS TWO SEPARATE IMPRECISIONS
 * (`peek-a-bin-lh7o`):
 *
 *  1. IT WAS A LENGTH CHECK, NOT A VALIDITY CHECK — `loadSettings().apiKey
 *     .length > 0`. A profile carrying a key beside a blank model, or a base URL
 *     that is not a URL, passed the gate and failed later as an HTTP error out
 *     of `client.ts`, by which point the user had been told the configuration
 *     was fine. The fields checked here are exactly the fields a request reads,
 *     and the rules are read off `client.ts` rather than invented:
 *     - `apiKey` and `model` are sent verbatim on every request, so both must be
 *       non-blank.
 *     - `baseUrl` is only REQUIRED for a non-Anthropic provider. `buildUrl`
 *       treats an empty base — and the legacy `api.openai.com` default that
 *       saved Anthropic profiles still carry — as "use the default", so
 *       demanding one there would refuse a configuration that works today.
 *       A base that IS set must be an absolute http(s) URL for either provider,
 *       since it is concatenated with a path and posted.
 *     WHAT THIS DELIBERATELY DOES NOT DO IS ASK THE PROVIDER. A network round
 *     trip on a UI gate fails for reasons that are nothing to do with the
 *     configuration — offline, rate-limited, a self-hosted endpoint that is
 *     merely asleep — so a refusal would frequently be wrong and always slow.
 *     The claim made here is only that the fields a request needs are present
 *     and well-formed, and the message is worded to claim no more than that.
 *  2. IT WAS SILENTLY SCOPED TO THE ACTIVE PROFILE. That scope is CORRECT — the
 *     active profile is what a request would use — but "No API key configured"
 *     over a store holding three profiles, two of them keyed, reads as the app
 *     having lost the user's settings. So the profile is named, and its position
 *     is given whenever there is more than one. That is the same condition under
 *     which `StatusBar` shows its profile badge, which is the quick-switch
 *     surface the user then reaches for.
 *
 * THE MESSAGE LIVES ON THE RESULT rather than in a constant beside it, because
 * it is now a function of the profile and a constant cannot be the one
 * declaration of a sentence that varies. Both gates print `problem.message` and
 * neither composes any text of its own.
 *
 * It names the precondition and the remedy and stops there. It does NOT promise
 * the action will resume once the profile is fixed — it will not. The gate has
 * no retry; that needs a queued-intent mechanism and is a separate question
 * (`peek-a-bin-r2u5` half 2).
 */
export function llmConfigProblem(store?: LLMProfileStore): LLMConfigProblem | null {
  const s = store ?? loadProfiles();
  const profile = getActiveProfile(s);
  const idx = s.profiles.findIndex((p) => p.id === profile.id);

  const issues: LLMConfigIssue[] = [];
  if (!trimmedField(profile.apiKey)) issues.push({ field: "apiKey", detail: "no API key" });
  if (!trimmedField(profile.model)) issues.push({ field: "model", detail: "no model" });

  const baseUrl = trimmedField(profile.baseUrl);
  if (!baseUrl) {
    // Empty is a real configuration for Anthropic — buildUrl substitutes the
    // default — and a broken one for anybody else.
    if (profile.provider !== "anthropic") {
      issues.push({ field: "baseUrl", detail: "no base URL" });
    }
  } else if (!isUsableBaseUrl(baseUrl)) {
    issues.push({ field: "baseUrl", detail: "a base URL that is not a web address" });
  }

  if (issues.length === 0) return null;

  const profileCount = s.profiles.length;
  const profileIndex = idx >= 0 ? idx + 1 : 1;
  // The position is worth saying only when there is somewhere else it could
  // have looked; with one profile it is noise.
  const where = profileCount > 1 ? ` (${profileIndex} of ${profileCount})` : "";
  const message =
    `AI profile "${profile.name}"${where} is not ready: ` +
    `${issues.map((i) => i.detail).join(", ")}. ` +
    "Open Settings → AI to fix it, then try again.";

  return { profileName: profile.name, profileIndex, profileCount, issues, message };
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
