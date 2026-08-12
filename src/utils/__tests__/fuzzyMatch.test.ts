/**
 * Subsequence matching for the command palette and search boxes.
 *
 * `fuzzyMatch(q, t)` asks whether every character of `q` appears in `t`, in
 * order, case-insensitively — not whether `q` is a substring.
 */

import { describe, expect, it } from "vitest";
import { fuzzyMatch } from "../fuzzyMatch";

describe("fuzzyMatch — matches", () => {
  it.each([
    ["an exact match", "main", "main"],
    ["a prefix", "ma", "main"],
    ["a suffix", "in", "main"],
    ["a contiguous substring", "ere", "here"],
    ["a gapped subsequence", "mn", "main"],
    ["characters scattered across the target", "cwe", "CreateWindowEx"],
    ["an uppercase query against a lowercase target", "MAIN", "main"],
    ["a lowercase query against an uppercase target", "main", "MAIN"],
    ["a mixed-case query", "CrWi", "createwindow"],
    ["a query equal to the target with different case", "NtOpenFile", "ntopenfile"],
  ])("%s", (_label, query, target) => {
    expect(fuzzyMatch(query, target)).toBe(true);
  });

  it("matches the empty query against anything", () => {
    expect(fuzzyMatch("", "main")).toBe(true);
    expect(fuzzyMatch("", "")).toBe(true);
  });

  it("matches digits and punctuation literally", () => {
    expect(fuzzyMatch("sub_401", "sub_401000")).toBe(true);
    expect(fuzzyMatch("0x40", "0x401000")).toBe(true);
  });

  it("consumes the target greedily from the left", () => {
    // "aa" needs two a's: the second must come from a later position.
    expect(fuzzyMatch("aa", "aba")).toBe(true);
    expect(fuzzyMatch("aa", "ab")).toBe(false);
  });
});

describe("fuzzyMatch — non-matches", () => {
  it.each([
    ["a character the target lacks", "mainz", "main"],
    ["the right characters in the wrong order", "nm", "main"],
    ["a query longer than the target", "mainmain", "main"],
    ["anything against an empty target", "a", ""],
    ["a repeated character the target has only once", "nn", "main"],
  ])("rejects %s", (_label, query, target) => {
    expect(fuzzyMatch(query, target)).toBe(false);
  });

  it("does not treat whitespace as a wildcard", () => {
    expect(fuzzyMatch("ma in", "main")).toBe(false);
    expect(fuzzyMatch("ma in", "ma in")).toBe(true);
  });
});
