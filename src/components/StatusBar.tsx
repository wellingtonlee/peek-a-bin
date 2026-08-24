import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import {
  ANALYSIS_IN_PROGRESS,
  getDisplayName,
  useAppDispatch,
  useAppState,
} from "../hooks/usePEFile";
import {
  getActiveProfile,
  type LLMProfileStore,
  loadProfiles,
  saveProfiles,
} from "../llm/settings";
import { analysisNotice } from "./analysisNotice";
import { Skeleton } from "./Skeleton";

// No entry for "failed": its render site below is behind `isAnalyzing`, which
// excludes it, so a label here was unreachable and the bar fell through to a
// green "Engine ready" over a dead analysis. The failure states are `notice`'s
// now — see ./analysisNotice.ts.
const phaseLabels: Record<string, string> = {
  parsing: "Parsing PE...",
  "extracting-strings": "Extracting strings...",
  "detecting-functions": "Detecting functions...",
  "recursive-descent": "Recursive descent...",
  "gap-filling": "Gap filling...",
  "building-xrefs": "Building xrefs...",
};

const SECTION_CHAR_FLAGS: [number, string][] = [
  [0x00000020, "CODE"],
  [0x00000040, "INITIALIZED_DATA"],
  [0x00000080, "UNINITIALIZED_DATA"],
  [0x20000000, "EXECUTE"],
  [0x40000000, "READ"],
  [0x80000000, "WRITE"],
  [0x02000000, "DISCARDABLE"],
  [0x04000000, "NOT_CACHED"],
  [0x08000000, "NOT_PAGED"],
  [0x10000000, "SHARED"],
];

function decodeSectionChars(characteristics: number): string {
  const flags: string[] = [];
  for (const [bit, name] of SECTION_CHAR_FLAGS) {
    if ((characteristics & bit) !== 0) flags.push(name);
  }
  return flags.join(" | ") || "NONE";
}

function Spinner() {
  return (
    <svg aria-hidden="true" className="animate-spin h-3 w-3 inline-block mr-1" viewBox="0 0 24 24">
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
        fill="none"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

export function StatusBar({ mcpStatus }: { mcpStatus?: "connected" | "disconnected" }) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;

  const containingFunc = useContainingFunc();
  const sectionInfo = useSectionInfo();

  const [profileStore, setProfileStore] = useState<LLMProfileStore>(loadProfiles);
  const [showProfilePopover, setShowProfilePopover] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  const refreshProfiles = useCallback(() => setProfileStore(loadProfiles()), []);

  useEffect(() => {
    window.addEventListener("peek-a-bin:profile-changed", refreshProfiles);
    return () => window.removeEventListener("peek-a-bin:profile-changed", refreshProfiles);
  }, [refreshProfiles]);

  useDismissOnOutsideClick({
    active: showProfilePopover,
    ref: popoverRef,
    onDismiss: () => setShowProfilePopover(false),
  });

  const activeProfile = getActiveProfile(profileStore);

  const handleSwitchProfile = (id: string) => {
    const updated: LLMProfileStore = { ...profileStore, activeId: id };
    saveProfiles(updated);
    setProfileStore(updated);
    setShowProfilePopover(false);
    window.dispatchEvent(new CustomEvent("peek-a-bin:profile-changed"));
  };

  const fileOffset = useMemo(() => {
    if (!pe || !sectionInfo) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    return sectionInfo.pointerToRawData + (rva - sectionInfo.virtualAddress);
  }, [pe, sectionInfo, state.currentAddress]);

  const machine = pe?.coffHeader.machine;
  const notice = useMemo(
    () =>
      analysisNotice({
        machine,
        phase: state.analysisPhase,
        error: state.error,
        omitted: state.omittedPasses,
        engineError: state.disasmFailed,
      }),
    [machine, state.analysisPhase, state.error, state.omittedPasses, state.disasmFailed],
  );

  if (!pe) return null;

  const rva = state.currentAddress - pe.optionalHeader.imageBase;
  const funcName = containingFunc ? getDisplayName(containingFunc, state.renames) : "---";

  const phase = state.analysisPhase;
  // Not a hand-written `!== "idle" && !== "ready" && !== "failed"` chain: that
  // shape defaults every phase added later to "still analysing", which is a
  // spinner that never resolves. The record is exhaustive over AnalysisPhase.
  const isAnalyzing = ANALYSIS_IN_PROGRESS[phase];
  const phaseLabel = phaseLabels[phase];

  const insnBytesStr = state.currentInstruction
    ? `${state.currentInstruction.size}B: ${state.currentInstruction.bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ")}`
    : null;

  const blockStr = state.currentBlock
    ? `Block: 0x${state.currentBlock.startAddr.toString(16).toUpperCase()} – 0x${state.currentBlock.endAddr.toString(16).toUpperCase()}`
    : null;

  const sectionCharsTooltip = sectionInfo
    ? decodeSectionChars(sectionInfo.characteristics)
    : undefined;

  return (
    <div className="h-5 toolbar-bg border-t border-theme text-[10px] flex items-center px-4 text-gray-400 shrink-0 select-none">
      <span className="mr-4">
        <span className="text-gray-500">Function:</span>{" "}
        {isAnalyzing && !containingFunc ? (
          <span className="inline-block align-middle">
            <Skeleton width="60px" height="10px" />
          </span>
        ) : containingFunc ? (
          <button
            type="button"
            className="text-gray-300 hover:text-blue-400 hover:underline"
            onClick={() => {
              dispatch({ type: "SET_ADDRESS", address: containingFunc.address });
              dispatch({ type: "SET_TAB", tab: "disassembly" });
            }}
          >
            {funcName}
          </button>
        ) : (
          <span className="text-gray-300">---</span>
        )}
      </span>
      <span className="mr-4" title={sectionCharsTooltip}>
        <span className="text-gray-500">Section:</span>{" "}
        {isAnalyzing && !sectionInfo ? (
          <span className="inline-block align-middle">
            <Skeleton width="40px" height="10px" />
          </span>
        ) : (
          <span className="text-gray-300">{sectionInfo?.name ?? "---"}</span>
        )}
      </span>
      <span className="mr-4">
        <span className="text-gray-500">RVA:</span>{" "}
        <span className="text-gray-300 font-mono">0x{rva.toString(16).toUpperCase()}</span>
      </span>
      <span className="mr-4">
        <span className="text-gray-500">File:</span>{" "}
        <span className="text-gray-300 font-mono">
          {fileOffset !== null ? `0x${fileOffset.toString(16).toUpperCase()}` : "---"}
        </span>
      </span>
      {insnBytesStr && <span className="mr-4 font-mono text-gray-300">{insnBytesStr}</span>}
      {blockStr && <span className="mr-4 text-gray-500">{blockStr}</span>}
      <div className="flex-1" />
      {profileStore.profiles.length > 1 && (
        <span className="mr-3 relative" ref={popoverRef}>
          <button
            type="button"
            onClick={() => setShowProfilePopover((v) => !v)}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-indigo-900/40 text-indigo-300 border border-indigo-700/50 hover:bg-indigo-800/50 hover:text-indigo-200 transition-colors"
          >
            <svg aria-hidden="true" className="w-2.5 h-2.5" fill="currentColor" viewBox="0 0 20 20">
              <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
            </svg>
            {activeProfile.name}
          </button>
          {showProfilePopover && (
            <div className="absolute bottom-full mb-1 right-0 w-44 bg-gray-800 border border-gray-600 rounded-lg shadow-xl overflow-hidden z-50">
              <div className="px-2 py-1.5 border-b border-gray-700 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                AI Profile
              </div>
              {profileStore.profiles.map((p) => (
                <button
                  type="button"
                  key={p.id}
                  onClick={() => handleSwitchProfile(p.id)}
                  className={`w-full text-left px-2 py-1.5 text-[11px] transition-colors ${
                    p.id === profileStore.activeId
                      ? "bg-indigo-600/20 text-indigo-300"
                      : "text-gray-300 hover:bg-gray-700"
                  }`}
                >
                  <div className="font-medium">{p.name}</div>
                  <div className="text-[9px] text-gray-500">
                    {p.provider} / {p.model}
                  </div>
                </button>
              ))}
            </div>
          )}
        </span>
      )}
      {mcpStatus === "connected" && (
        <span className="mr-3 flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
          <span className="text-green-400">MCP</span>
        </span>
      )}
      {/* The count is the thing a partial detection makes wrong, so it says so
          in place rather than leaving the notice at the far end of the bar to
          be connected to it. */}
      <span
        className="mr-4"
        title={notice && notice.omittedPasses.length > 0 ? notice.detail : undefined}
      >
        <span className="text-gray-500">{state.functions.length}</span> functions
        {notice && notice.omittedPasses.length > 0 && (
          <span className="text-amber-400"> (partial)</span>
        )}
      </span>
      {state.driverInfo?.isDriver && (
        <span className="mr-4 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-900/40 text-amber-400 border border-amber-700/50">
          KERNEL DRIVER
        </span>
      )}
      <span>
        {notice ? (
          // Ahead of every other branch: with the phase "failed" this used to
          // fall through to "Engine ready" in green, which is true of the
          // engine and a lie about the file. It also takes the "ready" branch's
          // place for a partial function list — the analysis did finish, but a
          // green tick beside a short list is the same lie in a quieter form.
          // `title` carries the full sentence — the banner in App.tsx is where
          // it is stated at length.
          <span
            className={notice.isFault ? "text-red-400" : "text-amber-400"}
            title={notice.detail}
          >
            {notice.label}
          </span>
        ) : isAnalyzing ? (
          <span className="text-yellow-400">
            <Spinner />
            {phaseLabel}
          </span>
        ) : phase === "ready" ? (
          <span className="text-green-400">
            <svg
              aria-hidden="true"
              className="h-3 w-3 inline-block mr-0.5"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path
                fillRule="evenodd"
                d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                clipRule="evenodd"
              />
            </svg>
            Ready
          </span>
        ) : (
          <span className={state.disasmReady ? "text-green-400" : "text-yellow-400"}>
            {state.disasmReady ? (
              "Engine ready"
            ) : (
              <>
                <Spinner />
                Loading engine...
              </>
            )}
          </span>
        )}
      </span>
    </div>
  );
}
