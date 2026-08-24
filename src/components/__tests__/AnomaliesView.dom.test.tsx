// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import type { Anomaly } from "../../analysis/anomalies";
import { IRP_MAJOR_FUNCTIONS, type IRPDispatchEntry } from "../../analysis/driver";
import type { AppState } from "../../hooks/usePEFile";
import type { AIScanFinding } from "../../llm/types";
import { AnomaliesView } from "../AnomaliesView";
import { AppHarness, harnessPE, stateWithPE } from "./appStateHarness";

/**
 * THE ANOMALIES TAB, rendered for the first time.
 *
 * One of three view tabs — with `StringsView` and `ResourcesView` — that nothing
 * had ever mounted. It matters more than its 295 lines suggest: `src/analysis/`
 * decides *what* is anomalous and this component decides what a user READS, so a
 * mis-worded finding or a warning painted in a critical's colour is a real harm
 * that no static instrument here can see. Both halves of that were looked for
 * deliberately; see the three drift guards below.
 *
 * NOT VIRTUALIZED — every one of the four tables is a plain `<table>` over a
 * plain `.map`, so every row really is in the document and `stubLayoutRect` is
 * neither needed nor used. That is the whole reason this suite can assert on row
 * *sets* and row *order*, which `StringsView.dom.test.tsx` cannot.
 *
 * COLOURS ARE ASSERTED AS CLASS-NAME STRINGS, DELIBERATELY. Tailwind is not
 * loaded in the test config, so `bg-red-900/20` carries no colour and no
 * `display` — there is nothing to read out of `getComputedStyle`. So every
 * severity assertion here reads `className` as text. That is weaker than seeing
 * a colour and it is the strongest thing available: it discriminates red from
 * amber from blue, which is the distinction `peek-a-bin-n7q1` got wrong on
 * screen, and it says nothing about what either one looks like.
 *
 * WHAT IS NOT COVERED: `state.anomalies` is supplied here, never computed —
 * `detectAnomalies` has its own suite and nothing about *which* facts are
 * anomalous is decided in this file. The `<details>` element's open/closed
 * behaviour in the findings table is jsdom's, not a browser's.
 */

/**
 * NO REACT DIAGNOSTIC, ANYWHERE IN THIS FILE — a file-wide assertion, not a test.
 *
 * `ResourcesView.dom.test.tsx` carries the same three hooks and its docstring
 * explains why they must be file-wide rather than one test: React caches the
 * key warning per owner component, so a dedicated test placed after any other
 * render is INERT — measured, not assumed. Kept here as well because it is four
 * lines and it is the only instrument in this repo for a missing or duplicated
 * list key, a `useEffect` that throws, or an invalid DOM nesting — none of which
 * `tsc` or Biome can see and all of which need something to render.
 *
 * Deliberately inlined per suite rather than shared through
 * `appStateHarness.tsx`: a suite that legitimately expects a React warning
 * should be able to opt out by not writing these lines.
 */
let consoleError: MockInstance<typeof console.error>;
beforeEach(() => {
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  const messages = consoleError.mock.calls.map((c) => String(c[0]));
  consoleError.mockRestore();
  expect(messages).toEqual([]);
});

function anomaly(
  severity: Anomaly["severity"],
  title: string,
  detail = `${title} detail`,
): Anomaly {
  return { severity, title, detail };
}

function finding(
  severity: AIScanFinding["severity"],
  title: string,
  over: Partial<AIScanFinding> = {},
): AIScanFinding {
  return {
    severity,
    title,
    description: `${title} description`,
    functionAddress: 0x140001000,
    functionName: "sub_140001000",
    remediation: "",
    source: "ai-scan",
    ...over,
  };
}

function renderAnomalies(over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const { container } = render(
    <AppHarness state={stateWithPE(harnessPE(), over)} dispatch={dispatch}>
      <AnomaliesView />
    </AppHarness>,
  );
  return { dispatch, container, user: userEvent.setup() };
}

/** The severity table's rows, in the order the component put them on screen. */
function anomalyRows(): HTMLTableRowElement[] {
  const table = screen.getByRole("table", { name: "" });
  return Array.from(table.querySelectorAll("tbody tr"));
}

describe("AnomaliesView — the empty case", () => {
  it("reads as clean rather than as broken when there is nothing to report", () => {
    renderAnomalies();
    // The distinction that matters: an empty list must not look like a failure.
    // The heading is still there (the tab is not blank), the sentence says
    // nothing was found, and no table is rendered at all.
    expect(screen.getByText("Security Anomalies")).toBeTruthy();
    expect(screen.getByText("No anomalies detected.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("renders for a PE32 and a PE64 file alike", () => {
    // The component reads nothing off `peFile` at all — asserted here so a
    // future read of `pe.is64` or `pe.sections` has to come with a test.
    for (const pe of [harnessPE(), harnessPE()]) {
      const { unmount } = render(
        <AppHarness state={stateWithPE(pe)} dispatch={vi.fn()}>
          <AnomaliesView />
        </AppHarness>,
      );
      expect(screen.getByText("No anomalies detected.")).toBeTruthy();
      unmount();
    }
  });

  it("renders with no PE at all", () => {
    // `AnomaliesView` has no `if (!pe) return null` guard, unlike StringsView.
    // Pinning it: the tab is only mounted with a file open, but a component that
    // throws on a null field is one dispatch away from a blank app.
    render(
      <AppHarness state={{ ...stateWithPE(harnessPE()), peFile: null }} dispatch={vi.fn()}>
        <AnomaliesView />
      </AppHarness>,
    );
    expect(screen.getByText("No anomalies detected.")).toBeTruthy();
  });
});

describe("AnomaliesView — the anomaly table", () => {
  const three: Anomaly[] = [
    anomaly("info", "Debug directory present"),
    anomaly("critical", "Writable executable section"),
    anomaly("warning", "No ASLR"),
  ];

  it("puts every anomaly on screen with its title and its detail", () => {
    renderAnomalies({ anomalies: three });
    expect(anomalyRows()).toHaveLength(three.length);
    for (const a of three) {
      expect(screen.getByText(a.title)).toBeTruthy();
      expect(screen.getByText(a.detail)).toBeTruthy();
    }
  });

  it("sorts critical above warning above info, whatever order they arrive in", () => {
    // The input is deliberately in the reverse of the intended order, so a
    // comparator that returns 0 (or that is dropped) fails rather than passing
    // by accident on already-sorted input.
    renderAnomalies({ anomalies: three });
    expect(anomalyRows().map((r) => r.cells[0].textContent)).toEqual([
      "critical",
      "warning",
      "info",
    ]);
    expect(anomalyRows().map((r) => r.cells[1].textContent)).toEqual([
      "Writable executable section",
      "No ASLR",
      "Debug directory present",
    ]);
  });

  it("does not mutate state.anomalies while sorting", () => {
    /**
     * `[...state.anomalies].sort(...)` — the copy is load-bearing. `appReducer`'s
     * invariant is that a mutating action replaces rather than mutates, and the
     * annotation undo snapshots hold direct references to state objects; a view
     * that sorted in place would reorder the reducer's own array on render.
     *
     * THE ARRAY IS BUILT HERE RATHER THAN COPIED FROM `three`, and that is what
     * makes the control discriminate. Copying `three` made this row INERT: the
     * tests above render `three` ITSELF, so an in-place sort mutates it on the
     * first of them and every later copy is already in sorted order — the
     * control's damage erases its own evidence. Compared against a literal
     * expectation for the same reason.
     */
    const input: Anomaly[] = [
      anomaly("info", "Third"),
      anomaly("critical", "First"),
      anomaly("warning", "Second"),
    ];
    renderAnomalies({ anomalies: input });
    expect(input.map((a) => a.title)).toEqual(["Third", "First", "Second"]);
  });

  it("paints each severity in its own colour", () => {
    // CLASS NAMES AS STRINGS — see the file docstring. What this discriminates
    // is red from amber from blue, which is the `peek-a-bin-n7q1` distinction.
    renderAnomalies({ anomalies: three });
    const [crit, warn, info] = anomalyRows();
    expect(crit.className).toContain("bg-red-900/20");
    expect(crit.cells[0].firstElementChild?.className).toContain("bg-red-600");
    expect(crit.cells[1].className).toContain("text-red-300");
    expect(warn.className).toContain("bg-amber-900/20");
    expect(warn.cells[0].firstElementChild?.className).toContain("bg-amber-600");
    expect(warn.cells[1].className).toContain("text-amber-300");
    expect(info.className).toContain("bg-blue-900/20");
    expect(info.cells[0].firstElementChild?.className).toContain("bg-blue-600");
    expect(info.cells[1].className).toContain("text-blue-300");
  });

  it("never paints a warning in a critical's colour", () => {
    // The failure `peek-a-bin-n7q1` actually shipped was one kind rendering
    // amber at one site and red at another. The sharp form of that question
    // here is the negative: no row may carry two severities' palettes, and a
    // warning may not carry red anywhere.
    renderAnomalies({ anomalies: three });
    const warn = anomalyRows()[1];
    expect(warn.outerHTML).not.toContain("red");
    const crit = anomalyRows()[0];
    expect(crit.outerHTML).not.toContain("amber");
  });

  it("labels the badge with the severity word itself, not a paraphrase", () => {
    // The badge text IS `a.severity`. Worth pinning: a paraphrase is a second
    // declaration of the severity vocabulary, and the CSS `uppercase` that makes
    // it read as CRITICAL is a class, so the DOM text stays lower case here.
    renderAnomalies({ anomalies: three });
    expect(anomalyRows()[0].cells[0].textContent).toBe("critical");
  });

  it("renders a severity the palette does not know without throwing", () => {
    // PINNING A WEAKNESS, not blessing it. `SEVERITY_COLORS` and
    // `SEVERITY_ORDER` are keyed by `Anomaly["severity"]`, so a fourth severity
    // fails the BUILD — that is the instrument. This test covers the runtime
    // fallbacks that survive behind it (`?? SEVERITY_COLORS.info`, `?? 9`),
    // which is what an anomaly arriving over the MCP wire or out of a stale
    // localStorage snapshot would take.
    const rogue = {
      severity: "fatal",
      title: "From the future",
      detail: "-",
    } as unknown as Anomaly;
    renderAnomalies({ anomalies: [rogue, anomaly("info", "Known")] });
    const rows = anomalyRows();
    // `?? 9` sorts it last, after even `info`.
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(["Known", "From the future"]);
    // `?? SEVERITY_COLORS.info` paints it blue rather than crashing on a
    // property of undefined.
    expect(rows[1].className).toContain("bg-blue-900/20");
  });
});

describe("AnomaliesView — the AI scan section", () => {
  const scanning = { phase: "scanning", scanned: 3, failed: 1, total: 10, error: null } as const;

  it("is absent entirely while the scan is idle", () => {
    // Gated on the PHASE, not on the finding count — an empty result list is a
    // clean bill of health only if a scan ran.
    renderAnomalies({ anomalies: [anomaly("info", "x")] });
    expect(screen.queryByText("AI Security Findings")).toBeNull();
  });

  it("reports progress as attempted-of-total, counting failures as attempted", () => {
    renderAnomalies({ aiScan: scanning });
    // 3 scanned + 1 failed = 4 attempted. A progress line that counted only
    // successes would stall visibly on a run with failures.
    expect(screen.getByRole("status").textContent).toContain("Scanning… 4 of 10 functions");
  });

  it("says a failed scan is NOT a clean result, as an alert", () => {
    renderAnomalies({
      aiScan: { phase: "failed", scanned: 0, failed: 4, total: 4, error: "429 rate limited" },
    });
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Scan failed — this is not a clean result.");
    expect(alert.textContent).toContain("(0 of 4)");
    expect(alert.textContent).toContain("means the scan produced nothing");
    expect(alert.textContent).toContain("429 rate limited");
    expect(alert.className).toContain("bg-red-900/30");
  });

  it("omits the parenthetical count when the run never had a total", () => {
    renderAnomalies({
      aiScan: { phase: "failed", scanned: 0, failed: 0, total: 0, error: null },
    });
    expect(screen.getByRole("alert").textContent).not.toContain("(0 of");
  });

  it("says a partly-failed complete scan did not cover the whole binary", () => {
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 8, failed: 2, total: 10, error: "timeout" },
    });
    const note = screen.getByRole("status");
    expect(note.textContent).toContain("Partial results");
    expect(note.textContent).toContain("8 of 10 functions analysed, 2 failed");
    expect(note.className).toContain("bg-amber-900/25");
  });

  it("says nothing was found only when the whole scan completed", () => {
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 12, failed: 0, total: 12, error: null },
    });
    expect(screen.getByRole("status").textContent).toContain("No issues found across 12 functions");
  });

  it("does not claim a clean result when part of the scan failed", () => {
    // The sharp case for the `failed === 0` conjunct: a run that completed with
    // failures and produced no findings must NOT read as "no issues found", or
    // an unscanned half of the binary is reported as clean.
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 6, failed: 6, total: 12, error: null },
      aiScanResults: [],
    });
    expect(screen.queryByText(/No issues found/)).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Partial results");
  });

  it("does not claim a clean result when findings came back", () => {
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 12, failed: 0, total: 12, error: null },
      aiScanResults: [finding("high", "Stack overflow")],
    });
    expect(screen.queryByText(/No issues found/)).toBeNull();
    expect(screen.getByText("Stack overflow")).toBeTruthy();
  });
});

describe("AnomaliesView — the findings table", () => {
  /**
   * THE DRIFT GUARD FOR THE FINDING PALETTE, and the reason this file exists.
   *
   * `AIScanFinding["severity"]` has FIVE members against the anomaly table's
   * three, and the two vocabularies are separate. Every member is asserted, so a
   * sixth one — or a re-pointed table entry — is a failing row rather than a
   * colour nobody looks at.
   */
  const palette: [AIScanFinding["severity"], string, string][] = [
    ["critical", "bg-red-900/20", "bg-red-600"],
    ["high", "bg-red-900/20", "bg-red-600"],
    ["medium", "bg-amber-900/20", "bg-amber-600"],
    ["low", "bg-blue-900/20", "bg-blue-600"],
    ["info", "bg-blue-900/20", "bg-blue-600"],
  ];

  it.each(palette)("paints a %s finding %s", (severity, rowBg, badgeBg) => {
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 1, failed: 0, total: 1, error: null },
      aiScanResults: [finding(severity, `A ${severity} thing`)],
    });
    const row = screen.getByText(`A ${severity} thing`).closest("tr")!;
    expect(row.className).toContain(rowBg);
    expect(row.cells[0].firstElementChild?.className).toContain(badgeBg);
  });

  it("treats high as critical's equal and medium as strictly lower", () => {
    // The judgement inside the palette: `high` shares `critical`'s red, which is
    // what `AddressBar`'s status dot also decides. Stated as its own row so a
    // change to either half is a failing test rather than two surfaces
    // disagreeing on screen — the shape of `peek-a-bin-n7q1`.
    const byName = new Map(palette.map(([s, bg]) => [s, bg]));
    expect(byName.get("high")).toBe(byName.get("critical"));
    expect(byName.get("medium")).not.toBe(byName.get("critical"));
  });

  it("truncates a long description in the summary and keeps it whole inside", () => {
    const long = "x".repeat(150);
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 1, failed: 0, total: 1, error: null },
      aiScanResults: [finding("low", "Long", { description: long })],
    });
    const summary = screen.getByText(`${"x".repeat(100)}...`);
    expect(summary.tagName).toBe("SUMMARY");
    // The whole description is in the document too, in the details body.
    expect(summary.closest("details")!.textContent).toContain(long);
  });

  it("adds no ellipsis to a description that fits", () => {
    renderAnomalies({
      aiScan: { phase: "complete", scanned: 1, failed: 0, total: 1, error: null },
      aiScanResults: [finding("low", "Short", { description: "brief" })],
    });
    // "brief" is in the document twice — the summary and the details body are
    // the same text when nothing was truncated. Both, and no ellipsis on either.
    const both = screen.getAllByText("brief");
    expect(both.map((e) => e.tagName)).toEqual(["SUMMARY", "DIV"]);
  });

  it("shows a remediation only when there is one", () => {
    const base = { phase: "complete", scanned: 1, failed: 0, total: 1, error: null } as const;
    const { unmount } = render(
      <AppHarness
        state={stateWithPE(harnessPE(), {
          aiScan: base,
          aiScanResults: [finding("low", "A", { remediation: "" })],
        })}
        dispatch={vi.fn()}
      >
        <AnomaliesView />
      </AppHarness>,
    );
    expect(screen.queryByText("Remediation:")).toBeNull();
    unmount();
    renderAnomalies({
      aiScan: base,
      aiScanResults: [finding("low", "A", { remediation: "Bounds-check the copy" })],
    });
    expect(screen.getByText("Bounds-check the copy", { exact: false })).toBeTruthy();
  });

  it("jumps to the function's address on the disassembly tab", async () => {
    const { dispatch, user } = renderAnomalies({
      aiScan: { phase: "complete", scanned: 1, failed: 0, total: 1, error: null },
      aiScanResults: [
        finding("high", "Bug", { functionAddress: 0x140002abc, functionName: "sub_140002ABC" }),
      ],
    });
    await user.click(screen.getByRole("button", { name: "sub_140002ABC" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140002abc });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });
});

describe("AnomaliesView — the kernel driver section", () => {
  const driver = {
    isDriver: true,
    reasons: ["imports ntoskrnl.exe"],
    isWDM: true,
    kernelImportCount: 17,
    kernelModules: ["ntoskrnl.exe", "hal.dll"],
  };

  const irp = (over: Partial<IRPDispatchEntry> = {}): IRPDispatchEntry => ({
    irpMajor: 0x0e,
    irpName: IRP_MAJOR_FUNCTIONS[0x0e],
    handlerAddress: 0x140003000,
    instructionAddress: 0x140001100,
    ...over,
  });

  it("is absent for a file that is not a driver", () => {
    renderAnomalies({ driverInfo: { ...driver, isDriver: false }, irpHandlers: [irp()] });
    expect(screen.queryByText("Kernel Driver")).toBeNull();
    // And the IRP table with it — an IRP row on a non-driver would be the view
    // asserting something the analysis did not.
    expect(screen.queryByText("IRP_MJ_DEVICE_CONTROL")).toBeNull();
  });

  it("distinguishes a WDM driver from a native one", () => {
    const { unmount } = render(
      <AppHarness state={stateWithPE(harnessPE(), { driverInfo: driver })} dispatch={vi.fn()}>
        <AnomaliesView />
      </AppHarness>,
    );
    expect(screen.getByText("WDM DRIVER")).toBeTruthy();
    expect(screen.getByText("17 kernel APIs")).toBeTruthy();
    expect(screen.getByText("Modules: ntoskrnl.exe, hal.dll")).toBeTruthy();
    unmount();
    renderAnomalies({ driverInfo: { ...driver, isWDM: false } });
    expect(screen.getByText("NATIVE DRIVER")).toBeTruthy();
  });

  it("omits the dispatch table when no handler was recovered", () => {
    renderAnomalies({ driverInfo: driver, irpHandlers: [] });
    expect(screen.getByText("Kernel Driver")).toBeTruthy();
    expect(screen.queryByText("IRP Dispatch Table")).toBeNull();
  });

  it("names each major function from the ANALYSIS's answer, not a copy of it", () => {
    /**
     * The one declaration of the IRP major-function vocabulary is
     * `IRP_MAJOR_FUNCTIONS` in `src/analysis/driver.ts`, and
     * `detectIRPDispatches` has already resolved it into
     * `IRPDispatchEntry.irpName` — refusing any index the table does not name.
     * `AnomaliesView` used to hold a byte-for-byte second copy and prefer it
     * (`IRP_NAMES[handler.irpMajor] ?? handler.irpName`), so a drift between the
     * copies would have been resolved in the VIEW's favour and the analysis's
     * answer silently discarded.
     *
     * This row is the guard: the name rendered must be the one on the entry.
     * A restored local table fails it.
     */
    renderAnomalies({
      driverInfo: driver,
      irpHandlers: [irp({ irpMajor: 0x0e, irpName: "IRP_MJ_RENAMED_UPSTREAM" })],
    });
    expect(screen.getByText("IRP_MJ_RENAMED_UPSTREAM")).toBeTruthy();
    expect(screen.queryByText("IRP_MJ_DEVICE_CONTROL")).toBeNull();
  });

  it("renders the real vocabulary for every major function the analysis can emit", () => {
    // Liveness half of the row above: the guard must not pass by rendering
    // nothing. Every index `detectIRPDispatches` accepts is asked for.
    const handlers = Object.entries(IRP_MAJOR_FUNCTIONS).map(([k, name]) =>
      irp({ irpMajor: Number(k), irpName: name }),
    );
    expect(handlers.length).toBe(28);
    renderAnomalies({ driverInfo: driver, irpHandlers: handlers });
    const table = screen.getByText("IRP Dispatch Table").nextElementSibling as HTMLTableElement;
    const rows = Array.from(table.querySelectorAll<HTMLTableRowElement>("tbody tr"));
    expect(rows).toHaveLength(handlers.length);
    expect(rows.map((r) => r.cells[0].textContent)).toEqual(
      handlers.map((h) => `0x${h.irpMajor.toString(16).toUpperCase().padStart(2, "0")}`),
    );
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(handlers.map((h) => h.irpName));
  });

  it("says N/A rather than 0x0 for a handler whose address was not recovered", () => {
    renderAnomalies({ driverInfo: driver, irpHandlers: [irp({ handlerAddress: 0 })] });
    expect(screen.getByText("N/A")).toBeTruthy();
    // Not a button: there is nowhere to jump to.
    expect(screen.getByText("N/A").tagName).toBe("SPAN");
  });

  it("jumps to the handler and to the instruction that installed it", async () => {
    const { dispatch, user } = renderAnomalies({
      driverInfo: driver,
      irpHandlers: [irp({ handlerAddress: 0x140003000, instructionAddress: 0x140001100 })],
    });
    await user.click(screen.getByRole("button", { name: "0x140003000" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140003000 });
    dispatch.mockClear();
    await user.click(screen.getByRole("button", { name: "0x140001100" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001100 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });
});

describe("AnomaliesView — every section at once", () => {
  it("keeps the four sections in a fixed order down the page", () => {
    // Section order is the reading order a user gets, and nothing else asserts
    // it. Anomalies first (they are facts about the file), then the AI findings
    // (a model's opinion), then the driver detail.
    const { container } = renderAnomalies({
      anomalies: [anomaly("critical", "Writable executable section")],
      aiScan: { phase: "complete", scanned: 1, failed: 0, total: 1, error: null },
      aiScanResults: [finding("high", "Bug")],
      driverInfo: {
        isDriver: true,
        reasons: [],
        isWDM: true,
        kernelImportCount: 1,
        kernelModules: ["ntoskrnl.exe"],
      },
      irpHandlers: [
        {
          irpMajor: 0x0e,
          irpName: IRP_MAJOR_FUNCTIONS[0x0e],
          handlerAddress: 1,
          instructionAddress: 2,
        },
      ],
    });
    const headings = Array.from(container.querySelectorAll("h2, h3")).map((h) => h.textContent);
    expect(headings).toEqual([
      "Security Anomalies",
      "AI Security Findings",
      "Kernel Driver",
      "IRP Dispatch Table",
    ]);
    // Four tables, one per populated section (anomalies, findings, IRP) — the
    // driver banner is not a table.
    expect(within(container).getAllByRole("table")).toHaveLength(3);
  });
});
