import { describe, expect, it } from "vitest";
import { activeDescendantId, optionId } from "../listboxIds";

const LIST = "command-palette-results";

describe("optionId", () => {
  it("is stable for the same list and index", () => {
    expect(optionId(LIST, 3)).toBe(optionId(LIST, 3));
  });

  it("distinguishes indices", () => {
    expect(optionId(LIST, 0)).not.toBe(optionId(LIST, 1));
  });

  it("distinguishes lists", () => {
    expect(optionId("a", 0)).not.toBe(optionId("b", 0));
  });
});

describe("activeDescendantId", () => {
  // The attribute is an id REFERENCE. Pointing it at an option that is not
  // rendered is not a no-op — assistive technology looks it up and finds
  // nothing, so the selection goes unannounced while everything still looks
  // correct on screen.
  it("names the selected option when one exists", () => {
    expect(activeDescendantId(LIST, 2, 5)).toBe(optionId(LIST, 2));
  });

  it("is undefined when the list is empty", () => {
    // Not "" — an empty string is still a reference, just a broken one.
    expect(activeDescendantId(LIST, 0, 0)).toBeUndefined();
  });

  it("is undefined when the index is past the end", () => {
    // Reachable in practice: results shrink as the query is typed, and the
    // reset to 0 lands a render later.
    expect(activeDescendantId(LIST, 5, 3)).toBeUndefined();
  });

  it("is undefined for a negative index", () => {
    expect(activeDescendantId(LIST, -1, 3)).toBeUndefined();
  });

  it("accepts the last valid index", () => {
    expect(activeDescendantId(LIST, 2, 3)).toBe(optionId(LIST, 2));
  });
});
