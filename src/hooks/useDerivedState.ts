import { useMemo } from "react";
import { useAppState } from "./usePEFile";
import type { DisasmFunction } from "../disasm/types";
import type { SectionHeader } from "../pe/types";

export function useSortedFuncs(): DisasmFunction[] {
  const state = useAppState();
  return useMemo(
    () => [...state.functions].sort((a, b) => a.address - b.address),
    [state.functions],
  );
}

function binarySearchFunc(
  sortedFuncs: DisasmFunction[],
  addr: number,
): DisasmFunction | null {
  let lo = 0;
  let hi = sortedFuncs.length - 1;
  let best: DisasmFunction | null = null;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const fn = sortedFuncs[mid];
    if (fn.address <= addr) {
      if (addr < fn.address + fn.size) best = fn;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

export function useContainingFunc(
  address?: number,
  sortedFuncs?: DisasmFunction[],
): DisasmFunction | null {
  const state = useAppState();
  const funcs = sortedFuncs ?? useSortedFuncs();
  const addr = address ?? state.currentAddress;
  return useMemo(() => binarySearchFunc(funcs, addr), [funcs, addr]);
}

export function useSectionInfo(address?: number): SectionHeader | null {
  const state = useAppState();
  const pe = state.peFile;
  const addr = address ?? state.currentAddress;
  return useMemo(() => {
    if (!pe) return null;
    const rva = addr - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    return null;
  }, [pe, addr]);
}

// Re-export for convenience
export { binarySearchFunc };
