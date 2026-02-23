import { useMemo } from "react";
import { useAppState, getDisplayName } from "../hooks/usePEFile";
import { useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";

const phaseLabels: Record<string, string> = {
  parsing: "Parsing PE...",
  "extracting-strings": "Extracting strings...",
  "detecting-functions": "Detecting functions...",
  "building-xrefs": "Building xrefs...",
};

function Spinner() {
  return (
    <svg className="animate-spin h-3 w-3 inline-block mr-1" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

export function StatusBar() {
  const state = useAppState();
  const pe = state.peFile;

  const containingFunc = useContainingFunc();
  const sectionInfo = useSectionInfo();

  const fileOffset = useMemo(() => {
    if (!pe || !sectionInfo) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    return sectionInfo.pointerToRawData + (rva - sectionInfo.virtualAddress);
  }, [pe, sectionInfo, state.currentAddress]);

  if (!pe) return null;

  const rva = state.currentAddress - pe.optionalHeader.imageBase;
  const funcName = containingFunc ? getDisplayName(containingFunc, state.renames) : "---";

  const phase = state.analysisPhase;
  const isAnalyzing = phase !== "idle" && phase !== "ready";
  const phaseLabel = phaseLabels[phase];

  return (
    <div className="h-5 bg-gray-900 border-t border-gray-700 text-[10px] flex items-center px-4 text-gray-400 shrink-0 select-none">
      <span className="mr-4">
        <span className="text-gray-500">Function:</span>{" "}
        <span className="text-gray-300">{funcName}</span>
      </span>
      <span className="mr-4">
        <span className="text-gray-500">Section:</span>{" "}
        <span className="text-gray-300">{sectionInfo?.name ?? "---"}</span>
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
      <div className="flex-1" />
      <span className="mr-4">
        <span className="text-gray-500">{state.functions.length}</span> functions
      </span>
      <span>
        {isAnalyzing ? (
          <span className="text-yellow-400">
            <Spinner />
            {phaseLabel}
          </span>
        ) : phase === "ready" ? (
          <span className="text-green-400">
            <svg className="h-3 w-3 inline-block mr-0.5" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
            Ready
          </span>
        ) : (
          <span className={state.disasmReady ? "text-green-400" : "text-yellow-400"}>
            {state.disasmReady ? "Engine ready" : <><Spinner />Loading engine...</>}
          </span>
        )}
      </span>
    </div>
  );
}
