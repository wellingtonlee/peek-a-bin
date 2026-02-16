import { useMemo } from "react";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { getDisplayName } from "../hooks/usePEFile";
import { binarySearchFunc } from "../hooks/useDerivedState";

interface CallPanelProps {
  func: DisasmFunction;
  xrefMap: Map<number, number[]>;
  instructions: Instruction[];
  functions: DisasmFunction[];
  renames: Record<number, string>;
  onNavigate: (addr: number) => void;
  onClose: () => void;
}

export function CallPanel({
  func,
  xrefMap,
  instructions,
  functions,
  renames,
  onNavigate,
  onClose,
}: CallPanelProps) {
  // Build a sorted functions array for binary search
  const sortedFuncs = useMemo(() => {
    return [...functions].sort((a, b) => a.address - b.address);
  }, [functions]);

  const funcMap = useMemo(() => {
    const m = new Map<number, DisasmFunction>();
    for (const fn of functions) m.set(fn.address, fn);
    return m;
  }, [functions]);

  const findContainingFunc = (addr: number) => binarySearchFunc(sortedFuncs, addr);

  // Callers: xrefs to this function's address, resolved to containing function
  const callers = useMemo(() => {
    const sources = xrefMap.get(func.address) || [];
    const seen = new Set<number>();
    const result: { fn: DisasmFunction; sourceAddr: number }[] = [];
    for (const src of sources) {
      const containing = findContainingFunc(src);
      if (containing && !seen.has(containing.address)) {
        seen.add(containing.address);
        result.push({ fn: containing, sourceAddr: src });
      }
    }
    return result;
  }, [func.address, xrefMap, sortedFuncs]);

  // Callees: scan instructions in function range for call targets
  const callees = useMemo(() => {
    const endAddr = func.address + func.size;
    const seen = new Set<number>();
    const result: { fn: DisasmFunction | null; targetAddr: number }[] = [];
    for (const insn of instructions) {
      if (insn.address < func.address) continue;
      if (insn.address >= endAddr) break;
      if (insn.mnemonic === "call") {
        const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m) {
          const target = parseInt(m[1], 16);
          if (!seen.has(target)) {
            seen.add(target);
            const targetFn = funcMap.get(target) ?? null;
            result.push({ fn: targetFn, targetAddr: target });
          }
        }
      }
    }
    return result;
  }, [func, instructions, funcMap]);

  return (
    <div className="h-48 shrink-0 border-t border-gray-700 bg-gray-900 flex flex-col text-xs">
      <div className="flex items-center px-3 py-1 border-b border-gray-700 text-gray-400">
        <span className="font-semibold text-gray-300">
          Call Graph: {getDisplayName(func, renames)}
        </span>
        <div className="flex-1" />
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white px-1"
        >
          ✕
        </button>
      </div>
      <div className="flex flex-1 overflow-hidden">
        {/* Callers */}
        <div className="flex-1 border-r border-gray-700 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">
            Called by ({callers.length})
          </div>
          {callers.length === 0 ? (
            <div className="text-gray-600 italic">No callers found</div>
          ) : (
            callers.map((c) => (
              <button
                key={c.fn.address}
                onClick={() => onNavigate(c.sourceAddr)}
                className="block w-full text-left px-1 py-0.5 rounded hover:bg-gray-800 truncate"
              >
                <span className="text-blue-400">
                  {getDisplayName(c.fn, renames)}
                </span>
                <span className="text-gray-600 ml-1">
                  0x{c.fn.address.toString(16).toUpperCase()}
                </span>
              </button>
            ))
          )}
        </div>
        {/* Callees */}
        <div className="flex-1 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">
            Calls ({callees.length})
          </div>
          {callees.length === 0 ? (
            <div className="text-gray-600 italic">No calls found</div>
          ) : (
            callees.map((c) => (
              <button
                key={c.targetAddr}
                onClick={() => onNavigate(c.targetAddr)}
                className="block w-full text-left px-1 py-0.5 rounded hover:bg-gray-800 truncate"
              >
                <span className="text-blue-400">
                  {c.fn ? getDisplayName(c.fn, renames) : "unknown"}
                </span>
                <span className="text-gray-600 ml-1">
                  0x{c.targetAddr.toString(16).toUpperCase()}
                </span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
