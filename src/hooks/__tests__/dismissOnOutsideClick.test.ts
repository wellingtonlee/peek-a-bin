import { describe, expect, it } from "vitest";
import { isOutsideDismiss } from "../useDismissOnOutsideClick";

/**
 * There is no React renderer in this repo, so the effect that attaches the
 * listeners cannot be exercised. These cover the decision the handler makes
 * once an event has arrived, which is the part that differed between the
 * hand-rolled copies this hook replaced.
 */

/** Minimal stand-in for the popup container element. */
function container(inside: readonly object[]): Pick<HTMLElement, "contains"> {
  return { contains: (node) => inside.includes(node as object) } as Pick<HTMLElement, "contains">;
}

describe("isOutsideDismiss", () => {
  const item = {};
  const elsewhere = {};

  it("dismisses when the event target is outside the container", () => {
    expect(isOutsideDismiss(container([item]), elsewhere as EventTarget)).toBe(true);
  });

  it("does not dismiss when the event target is inside the container", () => {
    expect(isOutsideDismiss(container([item]), item as EventTarget)).toBe(false);
  });

  it("treats a null event target as outside", () => {
    expect(isOutsideDismiss(container([item]), null)).toBe(true);
  });

  // The AddressBar / StatusBar copies used `ref.current && !contains(...)`, so a
  // null ref meant "ignore"; the DisassemblyView copy used `ref.current?.contains`,
  // so a null ref meant "dismiss". Both survive as an option.
  it("ignores the event when the ref is unset and dismissIfRefMissing is false", () => {
    expect(isOutsideDismiss(null, elsewhere as EventTarget, false)).toBe(false);
  });

  it("dismisses when the ref is unset and dismissIfRefMissing is true", () => {
    expect(isOutsideDismiss(null, elsewhere as EventTarget, true)).toBe(true);
  });

  it("defaults dismissIfRefMissing to false", () => {
    expect(isOutsideDismiss(null, elsewhere as EventTarget)).toBe(false);
  });

  it("keeps the ref-missing answer independent of the event target", () => {
    expect(isOutsideDismiss(null, null, true)).toBe(true);
    expect(isOutsideDismiss(null, null, false)).toBe(false);
  });
});
