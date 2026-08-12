import { describe, expect, it } from "vitest";
import { validateAnnotations } from "../exportSchema";

/**
 * These guard two untrusted inputs that previously reached the reducer unchecked:
 * localStorage (editable by the user or any script on the origin) and the MCP
 * WebSocket bridge (remote input).
 */
describe("validateAnnotations", () => {
  it("accepts a well-formed payload and coerces string keys to numbers", () => {
    const result = validateAnnotations({
      bookmarks: [{ address: 0x401000, label: "entry" }],
      renames: { "4198400": "main" },
      comments: { "4198400": "entry point" },
    });

    expect(result).not.toBeNull();
    expect(result?.bookmarks).toEqual([{ address: 0x401000, label: "entry" }]);
    expect(result?.renames[4198400]).toBe("main");
    expect(result?.comments[4198400]).toBe("entry point");
  });

  it("defaults missing sections rather than rejecting", () => {
    const result = validateAnnotations({});
    expect(result).toEqual({ bookmarks: [], renames: {}, comments: {} });
  });

  it.each([
    ["a non-object", "nope"],
    ["null", null],
    ["bookmarks that are not an array", { bookmarks: { address: 1 } }],
    ["a bookmark without an address", { bookmarks: [{ label: "x" }] }],
    ["a bookmark with a non-numeric address", { bookmarks: [{ address: "0x1000", label: "x" }] }],
    ["a bookmark with a non-string label", { bookmarks: [{ address: 1, label: 42 }] }],
    ["renames as an array", { renames: ["main"] }],
    ["a rename with a non-numeric key", { renames: { notAnAddress: "main" } }],
    ["a rename with a non-string value", { renames: { "4096": 123 } }],
    ["a comment with a non-string value", { comments: { "4096": { nested: true } } }],
  ])("rejects %s", (_label, input) => {
    expect(validateAnnotations(input)).toBeNull();
  });

  it("rejects NaN-producing address keys instead of silently dropping them", () => {
    // Number("") is 0, but Number("abc") is NaN — the latter would previously
    // have become a NaN-keyed entry in app state.
    expect(validateAnnotations({ comments: { abc: "hi" } })).toBeNull();
  });
});
