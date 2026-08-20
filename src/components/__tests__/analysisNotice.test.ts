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
import {
  ANALYSIS_IN_PROGRESS,
  type AnalysisPhase,
  parseViewTab,
  VIEW_TABS,
  type ViewTab,
} from "../../hooks/usePEFile";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { findCodeSection } from "../../pe/sections";
import {
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
