import { describe, expect, it } from "vitest";
import {
  parseBatchRenameResponse,
  parseJSONResponse,
  parseScanResponse,
  toBatchRenameResult,
  toScanFinding,
  unwrapJSON,
} from "../responseSchema";

describe("unwrapJSON", () => {
  it("passes bare JSON through", () => {
    expect(unwrapJSON('{"a":1}')).toBe('{"a":1}');
    expect(unwrapJSON("  [1, 2]  ")).toBe("[1, 2]");
  });

  it("strips a ```json fence", () => {
    expect(unwrapJSON('```json\n{"a":1}\n```')).toBe('{"a":1}');
  });

  it("strips a bare ``` fence", () => {
    expect(unwrapJSON("```\n[]\n```")).toBe("[]");
  });

  it("strips a fence with an unexpected info string", () => {
    // The two hand-rolled copies of this regex only matched `json`/`jso`.
    expect(unwrapJSON("```JSON\n[]\n```")).toBe("[]");
    expect(unwrapJSON("```javascript\n[]\n```")).toBe("[]");
  });

  it("extracts the first fenced block when the model wraps it in prose", () => {
    const raw = 'Here are the findings:\n```json\n[{"title":"x"}]\n```\nHope that helps.';
    expect(unwrapJSON(raw)).toBe('[{"title":"x"}]');
  });

  it("does not mangle JSON containing backticks inside strings", () => {
    const raw = '{"description":"use `strcpy` carefully"}';
    expect(unwrapJSON(raw)).toBe(raw);
  });
});

describe("parseJSONResponse", () => {
  it("reports empty output rather than returning nothing silently", () => {
    const result = parseJSONResponse("   ");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/empty/i);
  });

  it("reports a truncated document instead of swallowing it", () => {
    const result = parseJSONResponse('[{"title":"unterminated"');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/not valid JSON/i);
  });

  it("never throws on hostile input", () => {
    for (const raw of ["```", "```json\n```", "undefined", "NaN", "<html>500</html>"]) {
      expect(() => parseJSONResponse(raw)).not.toThrow();
    }
  });
});

describe("parseBatchRenameResponse", () => {
  it("accepts a numeric address", () => {
    const result = parseBatchRenameResponse(
      '[{"address": 4198400, "suggestedName": "parse_header", "confidence": 0.9, "reasoning": "reads magic"}]',
    );
    expect(result).toEqual({
      ok: true,
      value: [
        {
          address: 4198400,
          suggestedName: "parse_header",
          confidence: 0.9,
          reasoning: "reads magic",
        },
      ],
    });
  });

  it("accepts a 0x-prefixed hex address string", () => {
    const result = parseBatchRenameResponse('[{"address": "0x401000", "suggestedName": "main"}]');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value[0].address).toBe(0x401000);
  });

  it("accepts a bare hex address string", () => {
    const result = parseBatchRenameResponse('[{"address": "401000", "suggestedName": "main"}]');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value[0].address).toBe(0x401000);
  });

  it("rejects an unparseable address instead of producing NaN", () => {
    const result = parseBatchRenameResponse('[{"address": "zzz", "suggestedName": "main"}]');
    expect(result.ok).toBe(false);
  });

  it("rejects an item with no suggested name", () => {
    expect(parseBatchRenameResponse('[{"address": 1}]').ok).toBe(false);
    expect(parseBatchRenameResponse('[{"address": 1, "suggestedName": ""}]').ok).toBe(false);
  });

  it("rejects a confidence outside 0..1", () => {
    const result = parseBatchRenameResponse(
      '[{"address": 1, "suggestedName": "x", "confidence": 42}]',
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/confidence/);
  });

  it("rejects an object where an array was required", () => {
    const result = parseBatchRenameResponse('{"address": 1, "suggestedName": "x"}');
    expect(result.ok).toBe(false);
  });

  it("accepts an empty array — a genuine 'no suggestions'", () => {
    expect(parseBatchRenameResponse("[]")).toEqual({ ok: true, value: [] });
  });

  it("distinguishes malformed output from an empty result", () => {
    const empty = parseBatchRenameResponse("[]");
    const broken = parseBatchRenameResponse("I could not analyse these functions.");
    expect(empty.ok).toBe(true);
    expect(broken.ok).toBe(false);
  });

  it("fills defaults for the optional fields", () => {
    const parsed = parseBatchRenameResponse('[{"address": 16, "suggestedName": "init"}]');
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(toBatchRenameResult(parsed.value[0], "sub_10")).toEqual({
      address: 16,
      currentName: "sub_10",
      suggestedName: "init",
      confidence: 0.5,
      reasoning: "",
      accepted: null,
    });
  });
});

describe("parseScanResponse", () => {
  it("accepts a well-formed finding", () => {
    const result = parseScanResponse(
      '```json\n[{"severity":"high","title":"Stack overflow","description":"unchecked memcpy","remediation":"bounds-check"}]\n```',
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value[0].severity).toBe("high");
  });

  it("rejects an unknown severity rather than silently downgrading it", () => {
    const result = parseScanResponse('[{"severity":"catastrophic","title":"x"}]');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/severity/);
  });

  it("requires a title", () => {
    expect(parseScanResponse('[{"severity":"low"}]').ok).toBe(false);
  });

  it("accepts an empty array as a real 'no findings'", () => {
    expect(parseScanResponse("[]")).toEqual({ ok: true, value: [] });
  });

  it("reports prose as a failure instead of treating it as no findings", () => {
    const result = parseScanResponse("This function looks fine to me.");
    expect(result.ok).toBe(false);
  });

  it("defaults severity to info and stamps the function identity", () => {
    const parsed = parseScanResponse('[{"title":"Weak RNG"}]');
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(toScanFinding(parsed.value[0], 0x401000, "gen_key")).toEqual({
      severity: "info",
      title: "Weak RNG",
      description: "",
      functionAddress: 0x401000,
      functionName: "gen_key",
      remediation: "",
      source: "ai-scan",
    });
  });
});
