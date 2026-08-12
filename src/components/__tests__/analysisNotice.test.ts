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
import { parseViewTab, type ViewTab } from "../../hooks/usePEFile";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import {
  analysisNotice,
  DECODER_DERIVED_TABS,
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
