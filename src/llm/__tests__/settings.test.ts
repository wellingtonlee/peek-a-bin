import { describe, expect, it } from "vitest";
import { type LLMProfile, type LLMProfileStore, llmConfigProblem } from "../settings";

/**
 * `llmConfigProblem` — the AI gate's predicate (`peek-a-bin-lh7o`).
 *
 * It replaces `hasApiKey()`, which was `loadSettings().apiKey.length > 0`: a
 * LENGTH check standing in for a validity one, scoped to the active profile
 * without saying so. Both halves are asked here.
 *
 * This suite passes a store in rather than writing `localStorage`, which is what
 * keeps it a node test: the store parameter exists for `getActiveProfile`'s own
 * reason and the function is otherwise identical either way. The rendered half —
 * that the sentence reaches the two panels' banners — is
 * `hooks/__tests__/apiKeyGate.dom.test.tsx`.
 *
 * THE RULES ARE READ OFF `client.ts`, NOT INVENTED, and the base-URL row is the
 * one where that matters: `buildUrl` substitutes the default for an empty (or
 * legacy `api.openai.com`) base on the Anthropic path only, so demanding one
 * there would refuse a configuration that works today. What a green run here
 * does NOT say is that the key is accepted by anybody — nothing calls the
 * provider, deliberately, and the wording claims no more than that the fields a
 * request reads are present and well-formed.
 */

function profile(over: Partial<LLMProfile> = {}): LLMProfile {
  return {
    id: "p1",
    name: "Default",
    provider: "anthropic",
    apiKey: "sk-test-key",
    model: "claude-test",
    baseUrl: "",
    enhanceSource: "pseudocode",
    ...over,
  };
}

function store(...profiles: LLMProfile[]): LLMProfileStore {
  return { profiles, activeId: profiles[0].id };
}

describe("llmConfigProblem accepts a profile a request could actually use", () => {
  it("finds nothing wrong with a complete Anthropic profile", () => {
    // Liveness: without a configuration that passes, every refusal below would
    // be satisfied by a predicate that had simply started refusing everything.
    expect(llmConfigProblem(store(profile()))).toBeNull();
  });

  it("accepts an EMPTY base URL on the Anthropic path, because buildUrl fills it in", () => {
    expect(llmConfigProblem(store(profile({ baseUrl: "" })))).toBeNull();
  });

  it("accepts the legacy api.openai.com base saved Anthropic profiles still carry", () => {
    // client.ts reads this exact value as "use the default" rather than posting
    // Anthropic requests at OpenAI, so refusing it would break working setups.
    expect(llmConfigProblem(store(profile({ baseUrl: "https://api.openai.com" })))).toBeNull();
  });

  it("accepts a custom gateway", () => {
    expect(llmConfigProblem(store(profile({ baseUrl: "http://localhost:8787" })))).toBeNull();
  });
});

describe("llmConfigProblem checks the fields a request reads, not just the key", () => {
  it("refuses a missing API key", () => {
    const p = llmConfigProblem(store(profile({ apiKey: "" })));
    expect(p?.issues.map((i) => i.field)).toEqual(["apiKey"]);
  });

  it("refuses a key that is only whitespace", () => {
    // `length > 0` was true for this, which is the smallest statement of what
    // was wrong with the old check.
    const p = llmConfigProblem(store(profile({ apiKey: "   " })));
    expect(p?.issues.map((i) => i.field)).toEqual(["apiKey"]);
  });

  it("refuses a blank model, key or no key", () => {
    const p = llmConfigProblem(store(profile({ model: "  " })));
    expect(p?.issues.map((i) => i.field)).toEqual(["model"]);
    expect(p?.message).toContain("no model");
    // ...and the sentence does not claim the key is the problem.
    expect(p?.message).not.toContain("API key");
  });

  it("refuses a base URL that is not an absolute web address", () => {
    for (const bad of ["my-gateway:8080", "localhost:8787", "/relative/path", "not a url"]) {
      const p = llmConfigProblem(store(profile({ baseUrl: bad })));
      expect(
        p?.issues.map((i) => i.field),
        bad,
      ).toEqual(["baseUrl"]);
    }
  });

  it("refuses a base URL whose scheme is not one fetch would post to", () => {
    // A parseable URL is not a usable one: `file:` and `ftp:` both construct.
    const p = llmConfigProblem(store(profile({ baseUrl: "file:///tmp/gateway" })));
    expect(p?.issues.map((i) => i.field)).toEqual(["baseUrl"]);
  });

  it("REQUIRES a base URL for a non-Anthropic provider, where nothing fills it in", () => {
    // buildUrl's OpenAI arm concatenates the base with a path verbatim, so an
    // empty one posts at the app's own origin.
    const p = llmConfigProblem(store(profile({ provider: "openai", baseUrl: "" })));
    expect(p?.issues.map((i) => i.field)).toEqual(["baseUrl"]);
    expect(p?.message).toContain("no base URL");
  });

  it("survives a profile written before a field existed, and reports it missing", () => {
    // `loadProfiles` does no per-field defaulting outside the legacy-migration
    // path, so a profile saved by an older build arrives with a field
    // `undefined` — and `LLMProfile` has gained fields more than once. The old
    // `hasApiKey()` would have thrown on `.length`, inside a click handler.
    const stale = { id: "p1", name: "Old" } as unknown as LLMProfile;
    const p = llmConfigProblem(store(stale));
    // `baseUrl` is in there because `provider` is missing too, and the provider
    // test is spelled `!== "anthropic"` — the same way `client.ts` spells it.
    // Such a profile really would take the OpenAI arm of `buildUrl` and post at
    // the app's own origin, so the gate is predicting what a request would do
    // rather than guessing at a default the request would not apply.
    expect(p?.issues.map((i) => i.field)).toEqual(["apiKey", "model", "baseUrl"]);
  });

  it("reports every field that is wrong, in one sentence", () => {
    const p = llmConfigProblem(store(profile({ apiKey: "", model: "", baseUrl: "nope" })));
    expect(p?.issues.map((i) => i.field)).toEqual(["apiKey", "model", "baseUrl"]);
    expect(p?.message).toContain("no API key, no model, a base URL that is not a web address.");
  });
});

describe("llmConfigProblem says which profile it looked at", () => {
  it("names the active profile", () => {
    const p = llmConfigProblem(store(profile({ name: "Work", apiKey: "" })));
    expect(p?.profileName).toBe("Work");
    expect(p?.message).toContain('AI profile "Work" is not ready');
  });

  it("gives its position only when there is more than one profile", () => {
    const one = llmConfigProblem(store(profile({ apiKey: "" })));
    expect(one?.profileCount).toBe(1);
    expect(one?.message).not.toContain(" of ");

    const many = llmConfigProblem({
      activeId: "p2",
      profiles: [
        profile({ id: "p1", name: "Personal" }),
        profile({ id: "p2", name: "Work", apiKey: "" }),
        profile({ id: "p3", name: "Local" }),
      ],
    });
    expect(many?.profileIndex).toBe(2);
    expect(many?.profileCount).toBe(3);
    expect(many?.message).toContain('AI profile "Work" (2 of 3) is not ready');
  });

  it("judges the ACTIVE profile and no other, however many are keyed", () => {
    // The scope was always this; what changes is that it now says so. A store
    // where every OTHER profile is complete must still refuse.
    const p = llmConfigProblem({
      activeId: "p2",
      profiles: [
        profile({ id: "p1", name: "Personal" }),
        profile({ id: "p2", name: "Work", apiKey: "" }),
      ],
    });
    expect(p?.profileName).toBe("Work");
  });

  it("names the remedy, and does not promise the refused action will resume", () => {
    const p = llmConfigProblem(store(profile({ apiKey: "" })));
    expect(p?.message).toContain("Settings");
    expect(p?.message).toContain("try again");
  });
});
