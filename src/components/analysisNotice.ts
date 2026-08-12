/**
 * What the user is told when the analysis chain produced no disassembly — and,
 * just as importantly, what is still worth looking at.
 *
 * `disasm/arch.ts` refuses per stage rather than at load: for an image whose
 * machine type has no decoder (ARM32/Thumb, IA-64, RISC-V, MIPS) the worker
 * throws out of `disassemble` / `hybridDisassemble` / `buildAllXrefs` /
 * `decompileFunction`, while the PE parser keeps answering correctly about
 * headers, sections, imports, exports, resources and strings. That asymmetry is
 * only worth anything if the UI reproduces it: a bare "analysis failed" for a
 * file the tool reads perfectly well at the format level is a worse answer than
 * the x86 fiction it replaced.
 *
 * Before this module the browser did neither half. `App`'s analysis chain
 * dispatched `SET_ERROR` with the refusal text, but `state.error` is rendered
 * only by `FileLoader`, which unmounts the moment a PE parses — so the message
 * went nowhere. The status bar's `failed` label was unreachable for a matching
 * reason (its only render site sits behind `isAnalyzing`, which excludes
 * `"failed"`), leaving a green "Engine ready" over an empty function list.
 *
 * The decision lives here, not inline in JSX, because nothing in this repo
 * renders a component — a pure function is the only form of it any test can
 * reach. Same reason as `modalScaffold.ts` and `hooks/decompileTabsState.ts`.
 */

import { archForMachine, unsupportedArchMessage } from "../disasm/arch";
import type { AnalysisPhase, ViewTab } from "../hooks/usePEFile";

/** Display names for the view tabs, for prose that has to name them. */
export const VIEW_TAB_LABELS: Record<ViewTab, string> = {
  disassembly: "Disassembly",
  headers: "Headers",
  sections: "Sections",
  imports: "Imports",
  exports: "Exports",
  hex: "Hex",
  strings: "Strings",
  resources: "Resources",
  anomalies: "Anomalies",
};

/**
 * Tabs whose content comes from `parsePE` and the string scan, neither of which
 * decodes an instruction. Every one of them is populated for an ARM32 image.
 */
export const PARSER_DERIVED_TABS: readonly ViewTab[] = [
  "headers",
  "sections",
  "imports",
  "exports",
  "hex",
  "strings",
  "resources",
  "anomalies",
];

/** Tabs whose entire content is decoded instructions. */
export const DECODER_DERIVED_TABS: readonly ViewTab[] = ["disassembly"];

/**
 * Which of the two situations this is.
 *
 * They are kept apart because the remedies differ: `"unsupported-arch"` is a
 * permanent property of the file and nothing is wrong, whereas
 * `"analysis-failed"` is a genuine fault whose message is worth reading.
 */
export type AnalysisNoticeKind = "unsupported-arch" | "analysis-failed";

export interface AnalysisNotice {
  kind: AnalysisNoticeKind;
  /** A few words, for the status bar. */
  label: string;
  /** The full statement of why there is no disassembly. */
  detail: string;
  /** Tabs still worth opening — what the parser recovered regardless. */
  availableTabs: readonly ViewTab[];
  /** Tabs that cannot be populated in this state. */
  unavailableTabs: readonly ViewTab[];
}

/**
 * The stage name used in the architecture refusal.
 *
 * Singular on purpose: `unsupportedArchMessage` interpolates it as the subject
 * of "<feature> is not supported…", so a list would not agree with its verb.
 * "Code analysis" covers all four stages that refuse.
 */
const REFUSING_STAGES = "Code analysis";

/**
 * The notice to show for the current file and phase, or `null` when there is
 * nothing to say.
 *
 * An unsupported machine type outranks a failed phase, and does not wait for
 * one. It is a fact about the COFF header, known the instant the file parses,
 * and stating it as soon as it is known beats waiting for the chain to reach
 * whichever stage throws first — the user is looking at the disassembly tab
 * from the moment the file loads. The two do coincide in practice: the chain
 * dies in `buildAllXrefs` for such an image, so `phase` is `"failed"` shortly
 * after. Reporting the cause rather than the symptom is the difference.
 */
export function analysisNotice(input: {
  machine: number | undefined;
  phase: AnalysisPhase;
  error: string | null;
}): AnalysisNotice | null {
  if (archForMachine(input.machine) === "unsupported") {
    return {
      kind: "unsupported-arch",
      label: "Unsupported architecture",
      detail: unsupportedArchMessage(REFUSING_STAGES),
      availableTabs: PARSER_DERIVED_TABS,
      unavailableTabs: DECODER_DERIVED_TABS,
    };
  }
  if (input.phase === "failed") {
    return {
      kind: "analysis-failed",
      label: "Analysis failed",
      // The chain's own message when it has one. It is the only description of
      // what actually went wrong, and it had no render site at all before this.
      detail:
        input.error ??
        "Analysis stopped before it finished, so the disassembly is incomplete or missing.",
      availableTabs: PARSER_DERIVED_TABS,
      unavailableTabs: DECODER_DERIVED_TABS,
    };
  }
  return null;
}

/** "Headers, Sections, Imports, Exports, Hex, Strings, Resources and Anomalies". */
export function formatTabList(tabs: readonly ViewTab[]): string {
  const names = tabs.map((t) => VIEW_TAB_LABELS[t]);
  if (names.length === 0) return "";
  if (names.length === 1) return names[0];
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}
