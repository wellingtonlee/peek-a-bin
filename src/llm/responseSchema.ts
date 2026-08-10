/**
 * Validation for the JSON payloads the model returns.
 *
 * Previously each caller stripped code fences with its own copy of a regex and
 * parsed inside a bare `catch {}`, so a truncated or malformed response was
 * indistinguishable from a legitimate "nothing to report". Every parse now
 * returns a discriminated result — mirroring the `validateAnnotations` idiom in
 * `utils/exportSchema.ts`, these functions never throw — and callers surface the
 * failure instead of swallowing it.
 */

import { z } from "zod";
import type { AIScanFinding, BatchRenameResult } from "./types";

export type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

/**
 * Strip Markdown code fences from a model response.
 *
 * This is the single implementation — `useBatchRename` and `useVulnScanner` each
 * carried their own copy, and both mishandled a fence whose info string was not
 * exactly `json`.
 */
export function unwrapJSON(raw: string): string {
  const trimmed = raw.trim();

  // Whole response is one fenced block.
  const whole = trimmed.match(/^```[^\n]*\n?([\s\S]*?)\n?```$/);
  if (whole) return whole[1].trim();

  // Prose around a fenced block — take the first block.
  const inner = trimmed.match(/```[^\n]*\n?([\s\S]*?)```/);
  if (inner) return inner[1].trim();

  return trimmed;
}

/** Parse a JSON document out of a possibly-fenced model response. */
export function parseJSONResponse(raw: string): ParseResult<unknown> {
  const text = unwrapJSON(raw);
  if (!text) return { ok: false, error: "Model returned an empty response" };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    const detail = err instanceof Error ? err.message : "invalid JSON";
    return { ok: false, error: `Model response was not valid JSON (${detail})` };
  }
}

function formatIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 3)
    .map((issue) => {
      const path = issue.path.join(".");
      return path ? `${path}: ${issue.message}` : issue.message;
    })
    .join("; ");
}

// ── Batch rename ──

/** Addresses come back either as a number or as a "0x..." string. */
const addressSchema = z.union([z.number(), z.string()]).transform((value, ctx) => {
  const parsed = typeof value === "number" ? value : Number.parseInt(value.replace(/^0x/i, ""), 16);
  if (!Number.isFinite(parsed)) {
    ctx.addIssue({ code: "custom", message: `not a valid address: ${String(value)}` });
    return z.NEVER;
  }
  return parsed;
});

const batchRenameItemSchema = z.object({
  address: addressSchema,
  suggestedName: z.string().min(1),
  confidence: z.number().min(0).max(1).optional(),
  reasoning: z.string().optional(),
});

const batchRenameSchema = z.array(batchRenameItemSchema);

export type BatchRenameSuggestion = z.infer<typeof batchRenameItemSchema>;

export function parseBatchRenameResponse(raw: string): ParseResult<BatchRenameSuggestion[]> {
  const json = parseJSONResponse(raw);
  if (!json.ok) return json;

  const result = batchRenameSchema.safeParse(json.value);
  if (!result.success) {
    return {
      ok: false,
      error: `Rename suggestions did not match the expected shape (${formatIssues(result.error)})`,
    };
  }
  return { ok: true, value: result.data };
}

/** Fill in the fields the model does not supply, matching the previous defaults. */
export function toBatchRenameResult(
  item: BatchRenameSuggestion,
  currentName: string,
): BatchRenameResult {
  return {
    address: item.address,
    currentName,
    suggestedName: item.suggestedName,
    confidence: item.confidence ?? 0.5,
    reasoning: item.reasoning ?? "",
    accepted: null,
  };
}

// ── Vulnerability scan ──

const severitySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const scanFindingSchema = z.object({
  severity: severitySchema.optional(),
  title: z.string().min(1),
  description: z.string().optional(),
  remediation: z.string().optional(),
});

const scanSchema = z.array(scanFindingSchema);

export type ScanFindingPayload = z.infer<typeof scanFindingSchema>;

export function parseScanResponse(raw: string): ParseResult<ScanFindingPayload[]> {
  const json = parseJSONResponse(raw);
  if (!json.ok) return json;

  const result = scanSchema.safeParse(json.value);
  if (!result.success) {
    return {
      ok: false,
      error: `Scan findings did not match the expected shape (${formatIssues(result.error)})`,
    };
  }
  return { ok: true, value: result.data };
}

export function toScanFinding(
  item: ScanFindingPayload,
  functionAddress: number,
  functionName: string,
): AIScanFinding {
  return {
    severity: item.severity ?? "info",
    title: item.title,
    description: item.description ?? "",
    functionAddress,
    functionName,
    remediation: item.remediation ?? "",
    source: "ai-scan",
  };
}
