/**
 * The "why is there no disassembly, and what is still here" decision.
 *
 * peek-a-bin-8ru3. The engine's refusal for an image with no decoder
 * (peek-a-bin-x7b) is only worth having if the reason reaches the screen and
 * the parser's output stays reachable. Nothing in this repo renders a
 * component, so the decision was extracted into `analysisNotice` and it is this
 * suite — plus the wiring guard at the bottom — that holds the browser half of
 * the refusal up. What no test here can do is *see* the result; see the
 * "unverified" note in the guard's docstring.
 *
 * The machine types come from a parsed image rather than from a literal, so a
 * change to how the COFF header is read is caught here too.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectAnomalies } from "../../analysis/anomalies";
import {
  ANALYSIS_IN_PROGRESS,
  type AnalysisPhase,
  parseViewTab,
  VIEW_TABS,
  type ViewTab,
} from "../../hooks/usePEFile";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import {
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
} from "../../pe/constants";
import { computeImphash } from "../../pe/metadata";
import { extractStrings, parsePE } from "../../pe/parser";
import { findCodeSection } from "../../pe/sections";
import {
  type AnalysisNoticeKind,
  analysisNotice,
  DECODER_DERIVED_TABS,
  DETECT_PASS_LABELS,
  formatPassList,
  formatTabList,
  PARSER_DERIVED_TABS,
  VIEW_TAB_LABELS,
} from "../analysisNotice";

/** IMAGE_FILE_MACHINE_ARMNT — ARM Thumb-2, Windows on ARM32. */
const ARMNT = 0x01c4;
/** IMAGE_FILE_MACHINE_ARM — the original 32-bit little-endian ARM. */
const ARM = 0x01c0;
/** IMAGE_FILE_MACHINE_I386 — the control, an architecture that is supported. */
const I386 = 0x014c;

function machineOf(image: ArrayBuffer): number {
  return parsePE(image).coffHeader.machine;
}

describe("analysisNotice — an image whose architecture has no decoder", () => {
  it.each([
    ["ARMNT (0x01C4)", ARMNT],
    ["ARM (0x01C0)", ARM],
  ])("says so for %s, and names what is still readable", (_label, machine) => {
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine })),
      phase: "failed",
      error: "Analysis failed: Cross-reference analysis is not supported…",
    });

    expect(notice).not.toBeNull();
    expect(notice?.kind).toBe("unsupported-arch");
    // The message the user reads has to say why, what is supported instead, and
    // that the rest of the file was still read. Asserted on content rather than
    // on the exact sentence, which lives in disasm/arch.ts.
    expect(notice?.detail).toMatch(/not supported/i);
    expect(notice?.detail).toMatch(/x86 and ARM64/);
    expect(notice?.detail).toMatch(/headers.*imports.*exports.*strings/i);
  });

  it("does not wait for the chain to fail — the COFF header already answered", () => {
    // The stages throw at different points (detection returns empty, the xref
    // build throws), so tying the notice to `phase === "failed"` would leave the
    // disassembly tab unexplained for as long as the chain takes to get there.
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine: ARMNT })),
      phase: "detecting-functions",
      error: null,
    });
    expect(notice?.kind).toBe("unsupported-arch");
  });

  it("reports the cause, not the symptom, when both are present", () => {
    // `App` dispatches SET_ERROR with whichever stage threw first. For an
    // unsupported image that is "Cross-reference analysis", which is true but
    // is not what the user needs to know.
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine: ARM })),
      phase: "failed",
      error: "Analysis failed: something else entirely",
    });
    expect(notice?.kind).toBe("unsupported-arch");
    expect(notice?.detail).not.toMatch(/something else entirely/);
  });

  it("keeps every parser-derived view available and only withholds disassembly", () => {
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine: ARMNT })),
      phase: "failed",
      error: null,
    });
    // This is the whole point of refusing per stage instead of at load.
    expect(notice?.availableTabs).toEqual(
      expect.arrayContaining(["headers", "sections", "imports", "exports", "strings", "hex"]),
    );
    expect(notice?.availableTabs).not.toContain("disassembly");
    expect(notice?.unavailableTabs).toEqual(["disassembly"]);
  });
});

describe("analysisNotice — supported architectures", () => {
  it.each([
    ["PE32 / i386", () => buildMinimalPE32()],
    ["PE32+ / amd64", () => buildMinimalPE64()],
  ])("says nothing for %s while the analysis is healthy", (_label, build) => {
    for (const phase of ["parsing", "detecting-functions", "building-xrefs", "ready"] as const) {
      expect(analysisNotice({ machine: machineOf(build()), phase, error: null })).toBeNull();
    }
  });

  it("surfaces the chain's own message when a supported image fails", () => {
    // Before this, `state.error` had no render site once a PE had parsed: the
    // only consumer is FileLoader, which is unmounted by then.
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32()),
      phase: "failed",
      error: "Analysis failed: worker terminated",
    });
    expect(notice?.kind).toBe("analysis-failed");
    expect(notice?.detail).toBe("Analysis failed: worker terminated");
    expect(notice?.availableTabs).toBe(PARSER_DERIVED_TABS);
  });

  it("still explains itself when the failure carried no message", () => {
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32()),
      phase: "failed",
      error: null,
    });
    expect(notice?.kind).toBe("analysis-failed");
    expect(notice?.detail.length).toBeGreaterThan(0);
  });

  it("says nothing when the caller does not know the machine type", () => {
    // `archForMachine(undefined)` is "x86" by design — "the caller never told
    // us" must not start refusing on its own.
    expect(analysisNotice({ machine: undefined, phase: "ready", error: null })).toBeNull();
  });
});

/**
 * peek-a-bin-ipzf. `DetectResult.omitted` names the detection passes that could
 * not run — the null-Capstone case being the one that matters, because
 * detection keeps answering from `.pdata`, the exports, the entry point and the
 * unwind handlers, so the function list is *short* rather than empty and looks
 * exactly like a complete one. It reached the console and nothing else.
 */
describe("analysisNotice — a function list that is short rather than wrong", () => {
  const healthy = () => machineOf(buildMinimalPE64());

  it("says so, and names the passes in words rather than wire values", () => {
    const notice = analysisNotice({
      machine: healthy(),
      phase: "ready",
      error: null,
      omitted: ["call-targets", "jump-tables", "thunk-names", "tail-calls"],
    });
    expect(notice?.kind).toBe("partial-detection");
    expect(notice?.label).toBe("Partial function list");
    expect(notice?.detail).toContain("call targets, jump tables, thunk names and tail calls");
    // The identifiers the code switches on must not reach the screen.
    expect(notice?.detail).not.toMatch(/call-targets|jump-tables|thunk-names|tail-calls/);
  });

  it("says what is still trustworthy, not only what is missing", () => {
    // Those four sources are the linker's own record. A notice that only listed
    // the gaps would read as "none of this is reliable", which is false and
    // would cost the user the results that are.
    const notice = analysisNotice({
      machine: healthy(),
      phase: "ready",
      error: null,
      omitted: ["call-targets"],
    });
    expect(notice?.detail).toMatch(/exception table/i);
    expect(notice?.detail).toMatch(/exports/i);
    expect(notice?.detail).toMatch(/entry point/i);
    expect(notice?.detail).toMatch(/unwind handlers/i);
  });

  it("withholds no tab — the disassembly is real, only the function list is short", () => {
    const notice = analysisNotice({
      machine: healthy(),
      phase: "ready",
      error: null,
      omitted: ["jump-tables"],
    });
    expect(notice?.unavailableTabs).toEqual([]);
    expect(notice?.availableTabs).toEqual(expect.arrayContaining(["disassembly", "headers"]));
  });

  it("carries the raw passes alongside the prose", () => {
    const notice = analysisNotice({
      machine: healthy(),
      phase: "ready",
      error: null,
      omitted: ["tail-calls"],
    });
    expect(notice?.omittedPasses).toEqual(["tail-calls"]);
  });

  it("stays silent when detection ran everything", () => {
    expect(analysisNotice({ machine: healthy(), phase: "ready", error: null, omitted: [] })).toBe(
      null,
    );
    // And when the caller has not heard from detection at all yet.
    expect(analysisNotice({ machine: healthy(), phase: "detecting-functions", error: null })).toBe(
      null,
    );
  });

  it("ranks below a failure, and extends it instead of replacing it", () => {
    // Which stage threw and how much of the function list survived are separate
    // facts; neither is recoverable from the other.
    const notice = analysisNotice({
      machine: healthy(),
      phase: "failed",
      error: "Analysis failed: Capstone is unavailable",
      omitted: ["call-targets", "jump-tables"],
    });
    expect(notice?.kind).toBe("analysis-failed");
    expect(notice?.detail).toContain("Analysis failed: Capstone is unavailable");
    expect(notice?.detail).toContain("call targets and jump tables");
    expect(notice?.omittedPasses).toEqual(["call-targets", "jump-tables"]);
  });

  it("does not repeat itself for an image with no decoder", () => {
    // Detection reports all four passes omitted for an ARM32 image, but "there
    // is no decoder for this architecture" already implies every one of them.
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine: ARMNT })),
      phase: "failed",
      error: null,
      omitted: ["call-targets", "jump-tables", "thunk-names", "tail-calls"],
    });
    expect(notice?.kind).toBe("unsupported-arch");
    expect(notice?.detail).not.toMatch(/jump tables/);
    // Still carried, for a surface that wants to list them.
    expect(notice?.omittedPasses).toHaveLength(4);
  });

  it("formats the pass list as prose", () => {
    expect(formatPassList([])).toBe("");
    expect(formatPassList(["tail-calls"])).toBe("tail calls");
    expect(formatPassList(["call-targets", "tail-calls"])).toBe("call targets and tail calls");
  });

  it("labels every pass without leaking a hyphenated identifier", () => {
    for (const [pass, label] of Object.entries(DETECT_PASS_LABELS)) {
      expect(label.length).toBeGreaterThan(0);
      expect(label).not.toContain("-");
      expect(pass).toContain("-");
    }
  });
});

/**
 * peek-a-bin-bo3b. A PE with no executable section — a resource-only DLL, i.e.
 * an ordinary satellite/MUI file — made App's analysis effect return before it
 * dispatched any phase at all, so `analysisPhase` stayed on "extracting-strings"
 * forever and the status bar spun with nothing said. The terminal phase is
 * `"no-code"`, deliberately not `"failed"`: the parse succeeded.
 */
describe("analysisNotice — a file that parsed fine and simply has no code", () => {
  const healthy = () => machineOf(buildMinimalPE32());

  it("is reachable: a resource-only image really has no code section", () => {
    // The premise of the whole notice. `findCodeSection` matches `.text` by name
    // or IMAGE_SCN_MEM_EXECUTE by flag, and a resource-only DLL has neither.
    const image = buildMinimalPE32({
      sections: [
        {
          name: ".rsrc",
          virtualAddress: 0x1000,
          virtualSize: 4,
          data: new Uint8Array([0, 0, 0, 0]),
          // INITIALIZED_DATA | MEM_READ. No MEM_EXECUTE.
          characteristics: 0x00000040 | 0x40000000,
        },
      ],
    });
    expect(findCodeSection(parsePE(image).sections)).toBeUndefined();
  });

  it("says what happened, and says nothing failed", () => {
    const notice = analysisNotice({ machine: healthy(), phase: "no-code", error: null });
    expect(notice?.kind).toBe("no-code-section");
    expect(notice?.label).toBe("No code section");
    expect(notice?.detail).toMatch(/no executable section/i);
    expect(notice?.detail).toMatch(/nothing failed/i);
    // The word that must not appear: this is not a fault, and calling it one
    // sends the user looking for a problem with the tool or the file.
    expect(notice?.detail).not.toMatch(/error|failed to|corrupt/i);
  });

  it("names the case that makes this ordinary rather than adversarial", () => {
    const notice = analysisNotice({ machine: healthy(), phase: "no-code", error: null });
    expect(notice?.detail).toMatch(/resource-only/i);
  });

  it("names the views that are populated, and withholds only the disassembly", () => {
    const notice = analysisNotice({ machine: healthy(), phase: "no-code", error: null });
    expect(notice?.availableTabs).toBe(PARSER_DERIVED_TABS);
    expect(notice?.unavailableTabs).toEqual(["disassembly"]);
    // Derived from the same list the banner renders buttons from, so the prose
    // and the buttons cannot disagree.
    expect(notice?.detail).toContain(formatTabList(PARSER_DERIVED_TABS));
  });

  it("does not borrow the failure's message, even when one is sitting in state", () => {
    // `state.error` survives from an earlier load; nothing here went wrong.
    const notice = analysisNotice({
      machine: healthy(),
      phase: "no-code",
      error: "Analysis failed: worker terminated",
    });
    expect(notice?.kind).toBe("no-code-section");
    expect(notice?.detail).not.toMatch(/worker terminated/);
  });

  it("ranks below the architecture — the machine type is the more useful fact", () => {
    // An ARM32 resource-only DLL is both. "No decoder for this machine type"
    // is true of every such file; "no executable section" only of this one.
    const notice = analysisNotice({
      machine: machineOf(buildMinimalPE32({ machine: ARMNT })),
      phase: "no-code",
      error: null,
    });
    expect(notice?.kind).toBe("unsupported-arch");
  });

  it("is terminal — nothing may still read as analysis in flight", () => {
    // The defect was a spinner that could never resolve, so the phase being
    // terminal is half the fix and the notice is the other half.
    expect(ANALYSIS_IN_PROGRESS["no-code"]).toBe(false);
  });
});

describe("analysisNotice — the decode engine itself never loaded", () => {
  const ENGINE = "Failed to load disassembly engine";

  it("says the engine is the fault, and carries its message", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "detecting-functions",
      error: ENGINE,
      engineError: ENGINE,
    });
    expect(notice?.kind).toBe("engine-unavailable");
    expect(notice?.label).toBe("Engine unavailable");
    expect(notice?.detail).toContain(ENGINE);
  });

  it("is a fault, unlike the two properties of the file", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "detecting-functions",
      error: null,
      engineError: ENGINE,
    });
    expect(notice?.isFault).toBe(true);
  });

  // The distinction that makes this its own kind rather than a message inside
  // the failure kind: reloading the page is a remedy, and nothing about the file
  // is at issue. Both halves are stated in prose, so both are asserted.
  it("says the fault is not this file, and that a reload is the remedy", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "failed",
      error: null,
      engineError: ENGINE,
    });
    expect(notice?.detail).toMatch(/not a property of this file/i);
    expect(notice?.detail).toMatch(/reload/i);
  });

  it("keeps every parser-derived view available and withholds only the disassembly", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "failed",
      error: null,
      engineError: ENGINE,
    });
    expect(notice?.availableTabs).toEqual(PARSER_DERIVED_TABS);
    expect(notice?.unavailableTabs).toEqual(DECODER_DERIVED_TABS);
  });

  // Ranked below both no-fault properties of the file, because each is a
  // sufficient explanation that survives the engine being fixed: an ARM32 image
  // and a resource-only DLL have no disassembly on a healthy engine either, and
  // naming the engine would send the user to reload the page for nothing.
  it.each([
    ["an unsupported architecture", ARMNT, "detecting-functions", "unsupported-arch"],
    ["no code section", I386, "no-code", "no-code-section"],
  ] as const)("ranks below %s", (_label, machine, phase, kind) => {
    const notice = analysisNotice({
      machine,
      phase: phase as AnalysisPhase,
      error: null,
      engineError: ENGINE,
    });
    expect(notice?.kind).toBe(kind);
  });

  // And above the failure, which in this state is the symptom: the chain died
  // at whichever stage first asked the worker for an instruction.
  it("ranks above the analysis failure, whose message is the symptom", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "failed",
      error: "Analysis failed: engine not ready",
      engineError: ENGINE,
    });
    expect(notice?.kind).toBe("engine-unavailable");
    expect(notice?.detail).toContain(ENGINE);
  });

  // `engineError` is optional so that a caller predating it keeps its exact
  // behaviour. Absent and null must therefore be the same as "the engine is
  // fine", and neither may invent a notice for a healthy file.
  it.each([
    ["absent", undefined],
    ["null", null],
  ])("says nothing when the engine error is %s", (_label, engineError) => {
    expect(analysisNotice({ machine: I386, phase: "ready", error: null, engineError })).toBeNull();
  });

  it("does not fire merely because the analysis failed", () => {
    const notice = analysisNotice({
      machine: I386,
      phase: "failed",
      error: "Analysis failed: something else",
      engineError: null,
    });
    expect(notice?.kind).toBe("analysis-failed");
  });
});

describe("isFault separates what went wrong from what the file simply is", () => {
  // A table over every kind, so a sixth kind cannot be added without deciding
  // which side of the banner's red/amber split it belongs on. The four render
  // sites in App.tsx read this field rather than testing the kind, which is the
  // hand-written predicate a new kind used to join on the wrong side of.
  // Typed Record, not an array: a sixth kind fails the build here rather than
  // going untested, the same reason VIEW_TAB_LABELS and DETECT_PASS_LABELS are
  // Records.
  const EXPECTED: Record<AnalysisNoticeKind, boolean> = {
    "unsupported-arch": false,
    "no-code-section": false,
    "engine-unavailable": true,
    "analysis-failed": true,
    "partial-detection": false,
  };

  const REACHED: Record<AnalysisNoticeKind, Parameters<typeof analysisNotice>[0]> = {
    "unsupported-arch": { machine: ARMNT, phase: "failed", error: null },
    "no-code-section": { machine: I386, phase: "no-code", error: null },
    "engine-unavailable": { machine: I386, phase: "failed", error: null, engineError: "dead" },
    "analysis-failed": { machine: I386, phase: "failed", error: "boom" },
    "partial-detection": { machine: I386, phase: "ready", error: null, omitted: ["call-targets"] },
  };

  it.each(Object.keys(EXPECTED) as AnalysisNoticeKind[])("%s", (kind) => {
    const notice = analysisNotice(REACHED[kind]);
    // Both halves matter: the input has to actually reach the kind it claims to,
    // or the fault assertion below is about some other branch entirely.
    expect(notice?.kind).toBe(kind);
    expect(notice?.isFault).toBe(EXPECTED[kind]);
  });
});

describe("ANALYSIS_IN_PROGRESS covers every phase", () => {
  it("is exhaustive, so no phase silently reads as still-analysing", () => {
    // Typed Record<AnalysisPhase, boolean>, so this is really a check that the
    // record has not been widened to a partial/index-signature type — which is
    // how `phaseLabels` in StatusBar quietly stopped covering the union.
    const keys = Object.keys(ANALYSIS_IN_PROGRESS);
    expect(keys.length).toBe(10);
    for (const phase of keys) {
      expect(typeof ANALYSIS_IN_PROGRESS[phase as AnalysisPhase]).toBe("boolean");
    }
  });

  it("treats exactly the terminal phases as done", () => {
    expect(ANALYSIS_IN_PROGRESS.idle).toBe(false);
    expect(ANALYSIS_IN_PROGRESS.ready).toBe(false);
    expect(ANALYSIS_IN_PROGRESS.failed).toBe(false);
    expect(ANALYSIS_IN_PROGRESS["no-code"]).toBe(false);
    for (const phase of [
      "parsing",
      "detecting-functions",
      "recursive-descent",
      "gap-filling",
      "building-xrefs",
      "extracting-strings",
    ] as const) {
      expect(ANALYSIS_IN_PROGRESS[phase]).toBe(true);
    }
  });
});

describe("the tab split accounts for every view", () => {
  it("partitions the whole tab set, so no view is silently unclassified", () => {
    const all = Object.keys(VIEW_TAB_LABELS) as ViewTab[];
    const split = [...PARSER_DERIVED_TABS, ...DECODER_DERIVED_TABS];
    expect([...split].sort()).toEqual([...all].sort());
    expect(new Set(split).size).toBe(split.length);
  });

  it("labels only real tabs — a key that is not a ViewTab would render nowhere", () => {
    for (const key of Object.keys(VIEW_TAB_LABELS)) {
      expect(parseViewTab(key)).toBe(key);
    }
  });

  // peek-a-bin-t40b. The tab bar's order is `VIEW_TABS` and its labels are
  // `VIEW_TAB_LABELS`; the two are declared in different modules, so a tab
  // present in one and absent from the other is the drift to catch. The map is
  // `Record<ViewTab, string>` and fails the build on a missing key — the array
  // is not, and would silently drop the tab from the bar and from the 1–9 keys.
  it("orders exactly the tabs it has labels for", () => {
    expect([...VIEW_TABS].sort()).toEqual(Object.keys(VIEW_TAB_LABELS).sort());
    expect(new Set(VIEW_TABS).size).toBe(VIEW_TABS.length);
  });

  it("formats a tab list as prose", () => {
    expect(formatTabList(["headers"])).toBe("Headers");
    expect(formatTabList(["headers", "imports"])).toBe("Headers and Imports");
    expect(formatTabList(["headers", "imports", "strings"])).toBe("Headers, Imports and Strings");
    expect(formatTabList([])).toBe("");
  });
});

/**
 * Drift guard: the decision is only useful if the surfaces actually consume it.
 *
 * There is no React renderer here — no jsdom, no testing-library — so the
 * rendered result of an ARM32 load has never been observed by any test or by
 * anyone. What this can check is that the three places a user could be told
 * still route through the one decision instead of re-deriving it inline, which
 * is exactly how the status bar came to render a green "Engine ready" over a
 * failed analysis. Matched on the module name only, so a reformat cannot break
 * it.
 */
describe("every surface that reports a failure uses the shared decision", () => {
  const SRC = join(__dirname, "..", "..");

  it.each([
    // The banner: the one place the reason is stated at length, and the only
    // render site `state.error` has once a PE has parsed.
    ["App.tsx", join(SRC, "App.tsx"), /notice\.detail/],
    // The bar that used to show a green "Engine ready" over a dead analysis.
    ["StatusBar.tsx", join(SRC, "components", "StatusBar.tsx"), /notice\.label/],
    // The tab the user is looking at when the file loads.
    ["DisassemblyView.tsx", join(SRC, "components", "DisassemblyView.tsx"), /Notice\.detail/],
  ])("%s renders the notice rather than deriving its own", (_label, path, rendered) => {
    const source = readFileSync(path, "utf8");
    expect(source).toMatch(/from "\.\/(components\/)?analysisNotice"/);
    expect(source).toMatch(rendered);
  });

  // peek-a-bin-ipzf. The partial-detection notice exists only if its input is
  // actually supplied: `omitted` is optional, so dropping it here would compile,
  // pass every test above, and silently return to warning nobody. Not asserted
  // of DisassemblyView, which deliberately reads only the architecture refusal
  // — a short function list is no reason to replace the disassembly panel.
  it.each([
    ["App.tsx", join(SRC, "App.tsx")],
    ["StatusBar.tsx", join(SRC, "components", "StatusBar.tsx")],
  ])("%s feeds the notice the passes detection omitted", (_label, path) => {
    expect(readFileSync(path, "utf8")).toMatch(/omitted:\s*state\.omittedPasses/);
  });

  // peek-a-bin-t40b: the tab bar spelled the nine display names a second time,
  // so a tab could be called one thing on its button and another in the notice
  // telling you to open it. Matched on the import and on the shape of the old
  // literal array, both of which survive a reformat.
  it("the tab bar takes its labels from the map rather than spelling them again", () => {
    const source = readFileSync(join(SRC, "components", "AddressBar.tsx"), "utf8");
    expect(source).toMatch(/VIEW_TAB_LABELS/);
    expect(source).not.toMatch(/label:\s*"/);
  });

  // peek-a-bin-bo3b. The notice above is unreachable unless App's analysis
  // effect actually dispatches the phase at the `findCodeSection` bail-out —
  // and a bare `return` there is what caused the defect. Matched on the phase
  // literal, which survives a reformat; the absence assertion catches a revert.
  it("App dispatches the terminal phase where it used to return silently", () => {
    const source = readFileSync(join(SRC, "App.tsx"), "utf8");
    expect(source).toMatch(/phase:\s*"no-code"/);
    expect(source).not.toMatch(/if \(!textSection\) return;/);
  });

  // The other half: a terminal phase is only terminal if the spinner sites
  // agree. Both read the exhaustive record now, so a phase added later cannot
  // default to "still analysing" the way this one did.
  it.each([
    ["StatusBar.tsx", join(SRC, "components", "StatusBar.tsx")],
    ["Sidebar.tsx", join(SRC, "components", "Sidebar.tsx")],
  ])("%s decides 'still analysing' from the exhaustive record", (_label, path) => {
    const source = readFileSync(path, "utf8");
    expect(source).toMatch(/ANALYSIS_IN_PROGRESS\[/);
    // The hand-written chain this replaces. Re-adding it would compile, pass
    // every other test, and silently re-open the class of defect.
    expect(source).not.toMatch(/analysisPhase !== "ready"/);
    expect(source).not.toMatch(/phase !== "ready"/);
  });

  /**
   * Consuming the decision is not enough — the notice has to be reached.
   *
   * peek-a-bin-8ru3. Both surfaces below are chains of early returns, and in
   * both of them the notice's branch is deliberately first. Move it down and
   * the code still compiles, still imports `analysisNotice`, still satisfies
   * every assertion above, and the user sees the wrong thing: in the status bar
   * a green "Engine ready" or a spinner over a dead analysis, which is the
   * defect that created this module; in the disassembly panel either a spinner
   * that never resolves or — the case with no coverage signal at all — the
   * worker's own decode of ARM bytes as x86, whichever way `configure` and the
   * view's decode request happen to interleave.
   *
   * Positions rather than text: what is asserted is the order of two matches,
   * so reformatting either file cannot break it.
   */
  it("the disassembly panel states the refusal ahead of every branch that waits on the worker", () => {
    const source = readFileSync(join(SRC, "components", "DisassemblyView.tsx"), "utf8");
    const notice = source.search(/archNotice\?\.kind\s*===/);
    expect(notice).toBeGreaterThan(-1);

    for (const later of [/if\s*\(\s*disassembling\s*\)/, /if\s*\(\s*disasmError\s*\)/]) {
      const at = source.search(later);
      expect(at).toBeGreaterThan(-1);
      expect(notice).toBeLessThan(at);
    }
  });

  it("the status bar states the notice ahead of the spinner and the green tick", () => {
    const source = readFileSync(join(SRC, "components", "StatusBar.tsx"), "utf8");
    const notice = source.search(/\{\s*notice\s*\?/);
    const spinner = source.search(/:\s*isAnalyzing\s*\?/);
    const ready = source.search(/:\s*phase\s*===\s*"ready"\s*\?/);

    expect(notice).toBeGreaterThan(-1);
    expect(spinner).toBeGreaterThan(-1);
    expect(ready).toBeGreaterThan(-1);
    expect(notice).toBeLessThan(spinner);
    expect(spinner).toBeLessThan(ready);
  });

  /**
   * peek-a-bin-b3jn, and the same shape as the bo3b guard above.
   *
   * Three separate surfaces key a spinner on `!state.disasmReady`, which a
   * rejected `init()` never clears — so the whole class of defect is a *terminal
   * state that is never entered*. The engine's rejection has to be recorded as
   * its own fact (a bare SET_ERROR renders only in FileLoader, which is
   * unmounted whenever a PE is open), and the analysis effect has to reach a
   * terminal phase for it, or ANALYSIS_IN_PROGRESS keeps the sidebar skeleton
   * and the status bar spinner going for the rest of the session.
   */
  it("App records the engine's rejection rather than only setting the error", () => {
    const source = readFileSync(join(SRC, "App.tsx"), "utf8");
    // Scoped to the init effect, so this is about the action that rejection
    // dispatches and not about SET_ERROR anywhere else in a 900-line file. The
    // bare SET_ERROR it replaces compiles, and says nothing to a user with a
    // file open.
    const from = source.indexOf(".init()");
    expect(from).toBeGreaterThan(-1);
    const region = source.slice(from, source.indexOf("}, []);", from));
    expect(region).toMatch(/type:\s*"SET_DISASM_FAILED"/);
    // The dispatch shape, not the bare token: a comment in this effect names
    // the action it replaces, and a scraper that cannot tell prose from code
    // fails on its own explanation.
    expect(region).not.toMatch(/type:\s*"SET_ERROR"/);
  });

  it("App reaches a terminal phase when the engine is never going to arrive", () => {
    const source = readFileSync(join(SRC, "App.tsx"), "utf8");
    expect(source).toMatch(/state\.disasmFailed/);
    // The silent return this replaces — the exact shape of bo3b's defect, one
    // guard earlier in the same effect.
    expect(source).not.toMatch(
      /if \(!state\.peFile \|\| !state\.disasmReady\) return;\n\s+const pe =/,
    );
  });

  // The other two spinner sites. Neither can reach the notice — the tab bar
  // renders beside it and the panel's own branch is an early return — so each
  // has to be told about the failed engine directly, and each used to claim the
  // engine was still loading while the banner said it had failed.
  it("the tab bar stops claiming the engine is loading once it has failed", () => {
    const source = readFileSync(join(SRC, "components", "AddressBar.tsx"), "utf8");
    const spinner = source.search(/!state\.disasmReady && !state\.disasmFailed/);
    expect(spinner).toBeGreaterThan(-1);
    // The unguarded form, which is what made "Loading engine..." permanent.
    expect(source).not.toMatch(/\{!state\.disasmReady && \(/);
  });

  it("the disassembly panel states the dead engine ahead of its own spinner", () => {
    const source = readFileSync(join(SRC, "components", "DisassemblyView.tsx"), "utf8");
    const notice = source.search(/"engine-unavailable"/);
    const spinner = source.search(/if \(!state\.disasmReady\)/);
    expect(notice).toBeGreaterThan(-1);
    expect(spinner).toBeGreaterThan(-1);
    expect(notice).toBeLessThan(spinner);
  });

  it("the status bar has no label for a phase it cannot render", () => {
    // The exact defect this replaces: `phaseLabels` carried `failed: "Analysis
    // failed"`, but its only render site sits behind `isAnalyzing`, which
    // excludes "failed" — so the label was unreachable and control fell through
    // to the "Engine ready" branch. Anyone re-adding it would be re-adding dead
    // code and, worse, would think the case was covered.
    const source = readFileSync(join(SRC, "components", "StatusBar.tsx"), "utf8");
    const phaseMap = source.slice(
      source.indexOf("const phaseLabels"),
      source.indexOf("const SECTION_CHAR_FLAGS"),
    );
    expect(phaseMap.length).toBeGreaterThan(0);
    expect(phaseMap).not.toMatch(/failed/);
  });
});

/**
 * The notice's promise, checked against what the parser actually produced.
 *
 * peek-a-bin-8ru3, the half of it that is not about text on a screen. The
 * notice tells the user that Headers, Sections, Imports, Exports, Hex, Strings,
 * Resources and Anomalies are "still available" for an image whose machine type
 * has no decoder — but `PARSER_DERIVED_TABS` is a hand-written list, so that
 * sentence is a claim about *other modules* and nothing was checking it. If the
 * refusal reached any of them, the notice would be confidently pointing the
 * user at eight empty tabs, which is a worse answer than the bare failure it
 * replaced. The MCP path needed an explicit `decodable` guard in
 * `FileSession.loadFile` for exactly this, so the assumption is not free.
 *
 * The claim is really an *invariance*: the machine word must change what the
 * disassembler does and nothing else. So the same image is built twice with
 * that word as the only difference between the two buffers, and every
 * parser-derived output has to come back identical. Invariance alone would also
 * hold with both sides empty, so each output is separately required to be
 * non-empty on the ARM32 side.
 *
 * What this cannot do is render any of it. See the guard above.
 */
describe("an image with no decoder keeps every parser-derived view", () => {
  /** A string only this fixture contains, so finding it proves the scan ran. */
  const DATA_STRING = "peek-a-bin-armnt-marker";

  /**
   * One image, parameterised only by its machine word.
   *
   * `.text` is executable so `findCodeSection` succeeds — otherwise the
   * `"no-code"` phase would be doing this suite's work for it and the
   * architecture would never be the reason for anything.
   */
  function image(machine: number): ArrayBuffer {
    const data = new TextEncoder().encode(`${DATA_STRING}\0`);
    return buildMinimalPE32({
      machine,
      sections: [
        {
          name: ".text",
          virtualAddress: 0x1000,
          virtualSize: 8,
          data: new Uint8Array([0x55, 0x8b, 0xec, 0x33, 0xc0, 0x5d, 0xc3, 0x90]),
          characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        },
        {
          name: ".data",
          virtualAddress: 0x2000,
          virtualSize: data.length,
          data,
          characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
      ],
      // Kept after `.data` so the section headers stay in ascending RVA order,
      // which is what a linker emits.
      directoryRVA: 0x3000,
      directories: {
        imports: [
          {
            libraryName: "KERNEL32.dll",
            functions: [{ name: "CreateFileW" }, { name: "CloseHandle" }, { ordinal: 7 }],
          },
        ],
        exports: {
          dllName: "armnt.dll",
          addresses: [0x1000, 0x1004],
          names: [
            { name: "DllMain", addressIndex: 0 },
            { name: "Second", addressIndex: 1 },
          ],
        },
      },
    });
  }

  const armnt = parsePE(image(ARMNT));
  const i386 = parsePE(image(I386));

  it("is genuinely the refused case, and not a supported image in disguise", () => {
    // Guards the whole suite against going vacuous: if `archForMachine` ever
    // accepted 0x01C4, every assertion below would still pass while saying
    // nothing at all about the refusal.
    expect(
      analysisNotice({ machine: armnt.coffHeader.machine, phase: "failed", error: null })?.kind,
    ).toBe("unsupported-arch");
    expect(analysisNotice({ machine: i386.coffHeader.machine, phase: "ready", error: null })).toBe(
      null,
    );
    // And it is not the no-code case wearing the architecture's clothes.
    expect(findCodeSection(armnt.sections)).toBeDefined();
  });

  it("reads the headers, and reads them the same way", () => {
    expect(armnt.optionalHeader).toEqual(i386.optionalHeader);
    expect(armnt.dosHeader).toEqual(i386.dosHeader);
    // Everything in the COFF header except the one field that differs.
    const { machine: _armMachine, ...armntCoff } = armnt.coffHeader;
    const { machine: _x86Machine, ...i386Coff } = i386.coffHeader;
    expect(armntCoff).toEqual(i386Coff);
  });

  it("reads the sections", () => {
    expect(armnt.sections.map((s) => s.name)).toEqual([".text", ".data", ".rdata"]);
    expect(armnt.sections).toEqual(i386.sections);
  });

  it("reads the imports, by name and by ordinal", () => {
    expect(armnt.imports).toHaveLength(1);
    expect(armnt.imports[0].libraryName).toBe("KERNEL32.dll");
    expect(armnt.imports[0].functions).toEqual(["CreateFileW", "CloseHandle", "Ordinal_7"]);
    expect(armnt.imports).toEqual(i386.imports);
  });

  it("reads the exports", () => {
    expect(armnt.exports.map((e) => e.name)).toEqual(["DllMain", "Second"]);
    expect(armnt.exports).toEqual(i386.exports);
  });

  it("computes the imphash, which is a format-level fact and not an x86 one", () => {
    // The Headers tab shows it, and it is derived from the import table rather
    // than from any instruction — an ARM32 sample must still be identifiable by
    // the hash every corpus indexes on.
    expect(computeImphash(armnt.imports)).toBeTruthy();
    expect(computeImphash(armnt.imports)).toBe(computeImphash(i386.imports));
  });

  it("extracts strings — the one parser-derived tab fed by the refusing module", () => {
    // Strings reach the UI through `extractStrings` on the *disasm worker*,
    // which is also the module that refuses. It is a byte scan with no arch
    // gate (`workers/dispatch.ts`), and this is what says so from outside.
    const arm = extractStrings(armnt.buffer, armnt.sections, armnt.optionalHeader.imageBase, false);
    const x86 = extractStrings(i386.buffer, i386.sections, i386.optionalHeader.imageBase, false);

    expect([...arm.strings.values()]).toContain(DATA_STRING);
    expect([...arm.strings.entries()]).toEqual([...x86.strings.entries()]);
    expect([...arm.stringTypes.entries()]).toEqual([...x86.stringTypes.entries()]);
  });

  it("derives anomalies, which are read off the parsed image on the main thread", () => {
    const arm = detectAnomalies(armnt);
    expect(arm.length).toBeGreaterThan(0);
    expect(arm).toEqual(detectAnomalies(i386));
  });

  it("hands the Hex view the whole file either way", () => {
    // Hex renders `pe.buffer`, so what it needs is that nothing on the refusal
    // path truncated or dropped it.
    expect(armnt.buffer.byteLength).toBe(i386.buffer.byteLength);
    expect(new Uint8Array(armnt.buffer)).toEqual(new Uint8Array(image(ARMNT)));
  });

  it("parses the resource directory to the same answer — here, absent from both", () => {
    // The fixture builder cannot synthesize a resource tree, so this is the
    // weakest assertion in the suite and says so: what it rules out is the
    // refusal *changing* the answer, not an empty answer.
    expect(armnt.resources).toBeUndefined();
    expect(armnt.resources).toEqual(i386.resources);
  });

  it("covers every tab the notice offers", () => {
    // The assertions above are only worth something if they are about the same
    // list the user is pointed at. A tab added to PARSER_DERIVED_TABS with no
    // assertion here fails, rather than quietly inheriting a promise nothing
    // checks.
    const asserted: readonly ViewTab[] = [
      "headers",
      "sections",
      "imports",
      "exports",
      "hex",
      "strings",
      "resources",
      "anomalies",
    ];
    const notice = analysisNotice({
      machine: armnt.coffHeader.machine,
      phase: "failed",
      error: null,
    });
    expect([...(notice?.availableTabs ?? [])].sort()).toEqual([...asserted].sort());
    expect([...PARSER_DERIVED_TABS].sort()).toEqual([...asserted].sort());
  });
});
