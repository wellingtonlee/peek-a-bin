/**
 * Keeps context menus and popovers inside the viewport, with an 8px margin on
 * the right and bottom edges. The left and top edges clamp at 0 — a popup
 * pushed off-screen must land at the corner, never at a negative coordinate.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { clampPopup } from "../clampPopup";

/** Install a viewport of the given size (no jsdom in this suite). */
function viewport(innerWidth: number, innerHeight: number) {
  vi.stubGlobal("window", { innerWidth, innerHeight });
}

afterEach(() => vi.unstubAllGlobals());

describe("clampPopup", () => {
  it("leaves a popup that already fits untouched", () => {
    viewport(1000, 800);
    expect(clampPopup(100, 200, 300, 400)).toEqual({ x: 100, y: 200 });
  });

  it("pulls a popup back to the 8px margin when it overflows right and bottom", () => {
    viewport(1000, 800);
    // x: min(990, 1000-300-8) = 692; y: min(790, 800-400-8) = 392.
    expect(clampPopup(990, 790, 300, 400)).toEqual({ x: 692, y: 392 });
  });

  it("places a popup exactly at the margin when it lands on the boundary", () => {
    viewport(1000, 800);
    expect(clampPopup(692, 392, 300, 400)).toEqual({ x: 692, y: 392 });
    expect(clampPopup(693, 393, 300, 400)).toEqual({ x: 692, y: 392 });
  });

  it("clamps negative coordinates to the top-left corner", () => {
    viewport(1000, 800);
    expect(clampPopup(-50, -50, 100, 100)).toEqual({ x: 0, y: 0 });
  });

  it("pins a popup wider or taller than the viewport to the corner", () => {
    viewport(400, 300);
    // 400-500-8 is negative, so the max(0, …) guard decides.
    expect(clampPopup(200, 200, 500, 500)).toEqual({ x: 0, y: 0 });
  });

  it("pins a popup that is exactly viewport-sized to the corner", () => {
    viewport(400, 300);
    expect(clampPopup(0, 0, 400, 300)).toEqual({ x: 0, y: 0 });
  });

  it("clamps each axis independently", () => {
    viewport(1000, 200);
    // Fits horizontally, overflows vertically.
    expect(clampPopup(100, 190, 200, 300)).toEqual({ x: 100, y: 0 });
  });

  it("handles a zero-size popup", () => {
    viewport(1000, 800);
    expect(clampPopup(2000, 2000, 0, 0)).toEqual({ x: 992, y: 792 });
  });

  it("reads the viewport on every call rather than caching it", () => {
    viewport(1000, 800);
    expect(clampPopup(900, 700, 200, 200).x).toBe(792);
    viewport(500, 400);
    expect(clampPopup(900, 700, 200, 200).x).toBe(292);
  });
});
