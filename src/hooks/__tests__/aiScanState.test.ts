import { describe, expect, it } from "vitest";
import type { AIScanFinding } from "../../llm/types";
import { type AppAction, type AppState, appReducer, initialState } from "../usePEFile";

function finding(title: string, address = 0x401000): AIScanFinding {
  return {
    severity: "high",
    title,
    description: "",
    functionAddress: address,
    functionName: "sub_401000",
    remediation: "",
    source: "ai-scan",
  };
}

function run(actions: AppAction[], from: AppState = initialState): AppState {
  return actions.reduce(appReducer, from);
}

describe("AI scan state — the three outcomes stay distinct", () => {
  it("starts idle: never run", () => {
    expect(initialState.aiScan.phase).toBe("idle");
    expect(initialState.aiScanResults).toEqual([]);
  });

  it("a completed scan with no findings is 'complete', not 'idle'", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 3 },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_COMPLETE" },
    ]);

    expect(state.aiScan.phase).toBe("complete");
    expect(state.aiScan.scanned).toBe(3);
    expect(state.aiScan.failed).toBe(0);
    expect(state.aiScan.error).toBeNull();
    expect(state.aiScanResults).toEqual([]);
  });

  // This is the whole point of the fix: a parse failure must not look like a
  // clean binary. Both leave aiScanResults empty, so `phase` is what separates
  // "we checked and it's fine" from "we could not check".
  it("a scan whose response failed to parse is 'failed', NOT an empty clean result", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_FAILED", error: "sub_401000: Model response was not valid JSON" },
      { type: "AI_SCAN_COMPLETE" },
    ]);

    expect(state.aiScan.phase).toBe("failed");
    expect(state.aiScan.failed).toBe(1);
    expect(state.aiScan.scanned).toBe(0);
    expect(state.aiScan.error).toMatch(/not valid JSON/);
    expect(state.aiScanResults).toEqual([]);
  });

  it("the failed and clean states are not equal despite both having zero findings", () => {
    const clean = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_COMPLETE" },
    ]);
    const broken = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_FAILED", error: "unparseable" },
      { type: "AI_SCAN_COMPLETE" },
    ]);

    expect(clean.aiScanResults).toEqual(broken.aiScanResults);
    expect(clean.aiScan.phase).not.toBe(broken.aiScan.phase);
  });

  it("all three outcomes are mutually distinguishable from state alone", () => {
    const notRun = initialState;
    const clean = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_COMPLETE" },
    ]);
    const failed = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_FAILED", error: "boom" },
      { type: "AI_SCAN_COMPLETE" },
    ]);

    const phases = [notRun.aiScan.phase, clean.aiScan.phase, failed.aiScan.phase];
    expect(new Set(phases).size).toBe(3);
  });
});

describe("AI scan state — partial runs", () => {
  it("keeps findings and reports the failure count when only some functions fail", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 3 },
      { type: "AI_SCAN_ADD", findings: [finding("Stack overflow")] },
      { type: "AI_SCAN_FAILED", error: "sub_402000: unparseable" },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_COMPLETE" },
    ]);

    // Something usable came back, so the run completed — but it is incomplete,
    // and `failed` is what lets the UI say so.
    expect(state.aiScan.phase).toBe("complete");
    expect(state.aiScan.scanned).toBe(2);
    expect(state.aiScan.failed).toBe(1);
    expect(state.aiScan.total).toBe(3);
    expect(state.aiScan.error).toMatch(/unparseable/);
    expect(state.aiScanResults).toHaveLength(1);
  });

  it("keeps the first failure message rather than the last", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 2 },
      { type: "AI_SCAN_FAILED", error: "first" },
      { type: "AI_SCAN_FAILED", error: "second" },
    ]);
    expect(state.aiScan.error).toBe("first");
    expect(state.aiScan.failed).toBe(2);
  });

  it("accumulates findings across functions", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 2 },
      { type: "AI_SCAN_ADD", findings: [finding("A")] },
      { type: "AI_SCAN_ADD", findings: [finding("B"), finding("C")] },
      { type: "AI_SCAN_COMPLETE" },
    ]);
    expect(state.aiScanResults.map((f) => f.title)).toEqual(["A", "B", "C"]);
    expect(state.aiScan.scanned).toBe(2);
  });

  it("stays 'scanning' until the run is closed", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 5 },
      { type: "AI_SCAN_ADD", findings: [finding("A")] },
    ]);
    expect(state.aiScan.phase).toBe("scanning");
  });
});

describe("AI scan state — clearing between runs", () => {
  it("AI_SCAN_START wipes findings and the error from the previous run", () => {
    const afterFailure = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_ADD", findings: [finding("stale")] },
      { type: "AI_SCAN_FAILED", error: "stale error" },
      { type: "AI_SCAN_COMPLETE" },
    ]);
    expect(afterFailure.aiScan.error).toBe("stale error");

    const restarted = appReducer(afterFailure, { type: "AI_SCAN_START", total: 4 });
    expect(restarted.aiScan).toEqual({
      phase: "scanning",
      scanned: 0,
      failed: 0,
      total: 4,
      error: null,
    });
    expect(restarted.aiScanResults).toEqual([]);
  });

  it("a clean second run does not inherit the first run's failure", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_FAILED", error: "run 1 broke" },
      { type: "AI_SCAN_COMPLETE" },
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_ADD", findings: [] },
      { type: "AI_SCAN_COMPLETE" },
    ]);
    expect(state.aiScan.phase).toBe("complete");
    expect(state.aiScan.error).toBeNull();
    expect(state.aiScan.failed).toBe(0);
  });

  it("AI_SCAN_CLEAR returns to the never-run state", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 2 },
      { type: "AI_SCAN_ADD", findings: [finding("A")] },
      { type: "AI_SCAN_FAILED", error: "boom" },
      { type: "AI_SCAN_COMPLETE" },
      { type: "AI_SCAN_CLEAR" },
    ]);
    expect(state.aiScan).toEqual(initialState.aiScan);
    expect(state.aiScanResults).toEqual([]);
  });

  it("RESET clears scan state, so findings never carry across binaries", () => {
    const state = run([
      { type: "AI_SCAN_START", total: 1 },
      { type: "AI_SCAN_ADD", findings: [finding("from the previous binary")] },
      { type: "AI_SCAN_COMPLETE" },
      { type: "RESET" },
    ]);
    expect(state.aiScanResults).toEqual([]);
    expect(state.aiScan.phase).toBe("idle");
  });
});

describe("AI scan state — reducer hygiene", () => {
  it("does not mutate the previous state", () => {
    const before = run([{ type: "AI_SCAN_START", total: 1 }]);
    const snapshot = JSON.stringify(before.aiScan);
    appReducer(before, { type: "AI_SCAN_ADD", findings: [finding("X")] });
    appReducer(before, { type: "AI_SCAN_FAILED", error: "Y" });
    expect(JSON.stringify(before.aiScan)).toBe(snapshot);
  });

  it("does not share the initial scan object between resets", () => {
    const a = appReducer(initialState, { type: "AI_SCAN_CLEAR" });
    const b = appReducer(a, { type: "AI_SCAN_FAILED", error: "z" });
    expect(a.aiScan.failed).toBe(0);
    expect(b.aiScan.failed).toBe(1);
  });
});
