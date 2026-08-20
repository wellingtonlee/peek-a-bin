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
import type { DetectPass } from "../disasm/functionDetect";
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
 * Every tab, for the states where nothing at all is withheld. Assembled from
 * the two halves rather than re-listed, so the partition test covers it too.
 */
const ALL_TABS: readonly ViewTab[] = [...DECODER_DERIVED_TABS, ...PARSER_DERIVED_TABS];

/**
 * `DetectPass` in words a user can read.
 *
 * The wire values are pass names from `disasm/functionDetect.ts`, written for
 * the code that switches on them — "call-targets" in a sentence reads as a
 * typo. Typed `Record<DetectPass, string>`, so a fifth pass fails the build
 * here rather than rendering as its own identifier.
 */
export const DETECT_PASS_LABELS: Record<DetectPass, string> = {
  "call-targets": "call targets",
  "jump-tables": "jump tables",
  "thunk-names": "thunk names",
  "tail-calls": "tail calls",
};

/**
 * Which of the four situations this is.
 *
 * They are kept apart because the remedies differ: `"unsupported-arch"` is a
 * permanent property of the file and nothing is wrong; `"no-code-section"` is
 * likewise a property of the file and likewise not a fault, but a different
 * one — the architecture is fine and there is simply no code; `"analysis-failed"`
 * is a genuine fault whose message is worth reading; `"partial-detection"` is
 * none of those — the analysis finished and the disassembly is there, but the
 * function list is short, which is the one state that looks entirely healthy
 * on screen.
 */
export type AnalysisNoticeKind =
  | "unsupported-arch"
  | "no-code-section"
  | "analysis-failed"
  | "partial-detection";

export interface AnalysisNotice {
  kind: AnalysisNoticeKind;
  /** A few words, for the status bar. */
  label: string;
  /** The full statement of why there is no disassembly, or why it is short. */
  detail: string;
  /** Tabs still worth opening — what the parser recovered regardless. */
  availableTabs: readonly ViewTab[];
  /** Tabs that cannot be populated in this state. Empty when none are. */
  unavailableTabs: readonly ViewTab[];
  /**
   * The detection passes that did not run, verbatim from `DetectResult.omitted`
   * — empty when the function list is whole. `detail` already says this in
   * prose wherever it is worth saying; this is the machine-readable form, for a
   * surface that wants to render them as its own list.
   */
  omittedPasses: readonly DetectPass[];
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
 * What a short function list means, in the terms the user can act on.
 *
 * Deliberately says what *is* trustworthy as well as what is missing: the
 * passes named here are the ones that need a working decoder, and everything
 * detection has left — the exception table, the exports, the entry point, the
 * unwind handlers — is the linker's own record and stays correct. Without that
 * half the notice reads as "these results are wrong", which they are not.
 */
function omittedPassSentence(omitted: readonly DetectPass[]): string {
  return (
    `Function detection ran without ${formatPassList(omitted)}, so the function list is ` +
    `shorter than a complete one — any function only those passes would have found is ` +
    `missing. The functions that are listed come from the exception table, the exports, ` +
    `the entry point and the unwind handlers, and are unaffected.`
  );
}

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
 *
 * `"no-code-section"` ranks directly below the architecture and above the rest.
 * Below it because an image that is both — an ARM32 resource-only DLL — should
 * be told about its machine type: that is the more informative fact, since it
 * withholds the disassembly for *every* such file, whereas "no executable
 * section" is a property this one file would still have on a supported
 * architecture. Above the failure for tidiness only; the two cannot coincide,
 * as `phase` holds one value and App dispatches `"no-code"` in place of
 * reaching any stage that could fail (peek-a-bin-bo3b).
 *
 * `omitted` ranks below all three, and for the same reason: it is a *consequence* of
 * either one, so an image with no decoder would otherwise be told about twice.
 * It stands alone only when the analysis is otherwise healthy — the case that
 * has no other signal at all, a dead Capstone under a supported architecture,
 * where detection keeps answering from `.pdata`/exports/entry/unwind and the
 * short list it returns is shaped exactly like a complete one (peek-a-bin-ipzf).
 */
export function analysisNotice(input: {
  machine: number | undefined;
  phase: AnalysisPhase;
  error: string | null;
  /** `DetectResult.omitted`, once detection has answered. Absent = nothing known yet. */
  omitted?: readonly DetectPass[];
}): AnalysisNotice | null {
  const omitted = input.omitted ?? [];
  if (archForMachine(input.machine) === "unsupported") {
    return {
      kind: "unsupported-arch",
      label: "Unsupported architecture",
      // Not extended with the omitted passes, though detection will have
      // reported all of them: "no decoder for this image" already implies every
      // decoder-fed pass, and naming them would bury the one fact that matters.
      detail: unsupportedArchMessage(REFUSING_STAGES),
      availableTabs: PARSER_DERIVED_TABS,
      unavailableTabs: DECODER_DERIVED_TABS,
      omittedPasses: omitted,
    };
  }
  if (input.phase === "no-code") {
    return {
      kind: "no-code-section",
      label: "No code section",
      // Says the three things the failure banner cannot: that this is a
      // property of the file, that nothing went wrong, and that the rest of the
      // file is there. The tab list is derived rather than spelled out, so it
      // cannot disagree with the buttons the banner renders from
      // `availableTabs`.
      detail:
        `This image has no executable section, so there is nothing to disassemble — ` +
        `a resource-only DLL, such as a satellite or MUI resource file, is the ordinary ` +
        `case. Nothing failed: the file parsed normally, and ${formatTabList(PARSER_DERIVED_TABS)} ` +
        `are all populated.`,
      availableTabs: PARSER_DERIVED_TABS,
      unavailableTabs: DECODER_DERIVED_TABS,
      // Detection never ran, so there is nothing to report here — but carried
      // rather than hardcoded empty, since the caller is the authority on it.
      omittedPasses: omitted,
    };
  }
  if (input.phase === "failed") {
    // The chain's own message when it has one. It is the only description of
    // what actually went wrong, and it had no render site at all before this.
    const base =
      input.error ??
      "Analysis stopped before it finished, so the disassembly is incomplete or missing.";
    return {
      kind: "analysis-failed",
      label: "Analysis failed",
      // Appended rather than replaced: which stage threw and how much of the
      // function list survived are different facts, and the second one is not
      // recoverable from the first.
      detail: omitted.length > 0 ? `${base} ${omittedPassSentence(omitted)}` : base,
      availableTabs: PARSER_DERIVED_TABS,
      unavailableTabs: DECODER_DERIVED_TABS,
      omittedPasses: omitted,
    };
  }
  if (omitted.length > 0) {
    return {
      kind: "partial-detection",
      label: "Partial function list",
      detail: omittedPassSentence(omitted),
      // Nothing is withheld here: the analysis ran, the disassembly is real,
      // and every tab is populated. Only the function list is short.
      availableTabs: ALL_TABS,
      unavailableTabs: [],
      omittedPasses: omitted,
    };
  }
  return null;
}

/** "a, b and c" — the one list-to-prose rule, so two notices cannot punctuate differently. */
function joinProse(names: readonly string[]): string {
  if (names.length === 0) return "";
  if (names.length === 1) return names[0];
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** "Headers, Sections, Imports, Exports, Hex, Strings, Resources and Anomalies". */
export function formatTabList(tabs: readonly ViewTab[]): string {
  return joinProse(tabs.map((t) => VIEW_TAB_LABELS[t]));
}

/** "call targets, jump tables, thunk names and tail calls". */
export function formatPassList(passes: readonly DetectPass[]): string {
  return joinProse(passes.map((p) => DETECT_PASS_LABELS[p]));
}
