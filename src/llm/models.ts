/**
 * Central registry for model IDs, provider endpoints, and per-task token budgets.
 *
 * Model IDs used to be duplicated across settings.ts, SettingsModal.tsx and the
 * docs, which is how they drifted to `claude-sonnet-4-20250514`. Everything that
 * needs a model ID or a provider default should import it from here.
 */

export type LLMProvider = "anthropic" | "openai";

/**
 * Current Anthropic model IDs. These are exact strings — they carry no date
 * suffix, and appending one produces a 404. Verified against the `claude-api`
 * skill's model catalogue rather than written from memory.
 */
export const ANTHROPIC_MODELS = [
  { id: "claude-opus-5", label: "Claude Opus 5", note: "Best for analysis and long reasoning" },
  { id: "claude-sonnet-5", label: "Claude Sonnet 5", note: "Balanced speed and capability" },
  { id: "claude-opus-4-8", label: "Claude Opus 4.8", note: "Previous-generation Opus" },
  { id: "claude-haiku-4-5", label: "Claude Haiku 4.5", note: "Fastest and cheapest" },
] as const;

export const OPENAI_MODELS = [{ id: "gpt-4o", label: "GPT-4o", note: "" }] as const;

export const ANTHROPIC_DEFAULT_MODEL = "claude-opus-5";
export const OPENAI_DEFAULT_MODEL = "gpt-4o";

export const ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com";
export const OPENAI_DEFAULT_BASE_URL = "https://api.openai.com";

/**
 * Model IDs that used to be a provider default here.
 *
 * A stored profile written before the default moved still holds one of these.
 * Treating them as "the default" lets the settings UI recognise an untouched
 * legacy profile and refresh it, instead of mistaking a stale default for a
 * model the user deliberately chose. Add the old value here whenever a default
 * changes; never remove entries, since old profiles persist indefinitely.
 */
export const LEGACY_DEFAULT_MODELS: Record<LLMProvider, readonly string[]> = {
  anthropic: ["claude-sonnet-4-20250514"],
  openai: [],
};

/** Is `model` either the current default for `provider`, or a superseded one? */
export function isDefaultModel(provider: LLMProvider, model: string): boolean {
  return (
    model === PROVIDER_DEFAULTS[provider].model || LEGACY_DEFAULT_MODELS[provider].includes(model)
  );
}

export interface ProviderDefaults {
  model: string;
  baseUrl: string;
}

export const PROVIDER_DEFAULTS: Record<LLMProvider, ProviderDefaults> = {
  anthropic: { model: ANTHROPIC_DEFAULT_MODEL, baseUrl: ANTHROPIC_DEFAULT_BASE_URL },
  openai: { model: OPENAI_DEFAULT_MODEL, baseUrl: OPENAI_DEFAULT_BASE_URL },
};

export function providerDefaults(provider: LLMProvider): ProviderDefaults {
  return PROVIDER_DEFAULTS[provider] ?? PROVIDER_DEFAULTS.anthropic;
}

/**
 * Which feature is making the call. Used to pick a token budget — an 8K ceiling
 * was previously hardcoded twice for Anthropic and omitted entirely for OpenAI,
 * so a long report could be truncated on one provider and unbounded on the other.
 */
export type LLMTask = "chat" | "report" | "enhance" | "batch-rename" | "vuln-scan";

/**
 * Per-task output ceilings.
 *
 * These are caps, not reservations — a short answer costs what it costs. They are
 * sized generously because every call in this app streams, so the SDK/HTTP timeout
 * pressure that motivates small ceilings on non-streaming requests does not apply.
 *
 * Note for reasoning-capable models (Claude Opus 5 and later): `max_tokens` bounds
 * thinking *and* visible text together, and thinking is on by default. The budgets
 * below leave room for both. We deliberately do not send a `thinking` parameter:
 * an explicit `{"type":"disabled"}` is rejected outright by some models and gated
 * on the effort level by others, so omitting it is the only setting that is valid
 * across the whole model range a user can type into the settings box. The visible
 * tradeoff is that a thinking model may pause before its first token, since the
 * stream reader only renders `text` deltas.
 */
export const TASK_MAX_TOKENS: Record<LLMTask, number> = {
  chat: 16384,
  report: 32768,
  enhance: 16384,
  "batch-rename": 8192,
  "vuln-scan": 8192,
};

export function maxTokensFor(task: LLMTask): number {
  return TASK_MAX_TOKENS[task] ?? TASK_MAX_TOKENS.chat;
}
