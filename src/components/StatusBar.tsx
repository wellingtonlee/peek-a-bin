import { useMemo } from "react";
import { useAppState, getDisplayName } from "../hooks/usePEFile";
import { useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";

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
        <span className="text-gray-500">Engine:</span>{" "}
        <span className={state.disasmReady ? "text-green-400" : "text-yellow-400"}>
          {state.disasmReady ? "ready" : "loading"}
        </span>
      </span>
    </div>
  );
}
