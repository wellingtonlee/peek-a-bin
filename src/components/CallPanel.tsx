import { useMemo } from "react";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { binarySearchFunc } from "../hooks/useDerivedState";
import { getDisplayName } from "../hooks/usePEFile";

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

  // Callers: xrefs to this function's address, resolved to containing function.
  //
  // The array is correct as written but the rule cannot see it: the only thing
  // findContainingFunc closes over is `sortedFuncs`, which is listed, while
  // findContainingFunc itself is a plain arrow rebuilt every render — adding it
  // would recompute this memo on every render and defeat the memoisation.
  // biome-ignore lint/correctness/useExhaustiveDependencies: sortedFuncs is findContainingFunc's only capture; depending on the unmemoised arrow instead would recompute every render.
  const callers = useMemo(() => {
    const sources = xrefMap.get(func.address) || [];
    const seen = new Set<string>();
    const result: { key: string; fn: DisasmFunction | null; sourceAddr: number }[] = [];
    for (const src of sources) {
      const containing = findContainingFunc(src);
      // A source in no detected function is LISTED, not dropped. It used to be
      // skipped outright, so it left neither a row nor a tally mark and
      // "Called by (2)" understated a map holding four xrefs — a narrower
      // answer in exactly the shape of a complete one, which is the thing this
      // codebase will not ship. There is no need to invent a policy for it:
      // the callee column beside this one already answers the same question,
      // labelling a target with no function "unknown" and showing its address.
      //
      // The dedup key differs by side because the identity does: two calls from
      // one function are one caller, but two unattributed sources are two
      // distinct facts with nothing to merge them under.
      //
      // The `f`/`a` prefixes are DEFENSIVE, not a fix — checked, and the
      // collision they exclude is not reachable today. A bare number would mix
      // "the entry of the function containing this source" with "this source",
      // and the two are drawn from one space; but `binarySearchFunc` answers
      // with X for X's own entry address whenever X has a non-zero size, so a
      // source cannot be both unattributed and equal to some entry. The prefix
      // costs nothing and says which space each key is in, which is worth more
      // than the argument reconstructing that.
      const key = containing ? `f${containing.address}` : `a${src}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push({ key, fn: containing ?? null, sourceAddr: src });
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
    <div className="h-full flex flex-col text-xs">
      <div className="flex items-center px-3 py-1 border-b border-gray-700 text-gray-400">
        <span className="font-semibold text-gray-300">
          Call Graph: {getDisplayName(func, renames)}
        </span>
        <div className="flex-1" />
        <button type="button" onClick={onClose} className="text-gray-500 hover:text-white px-1">
          ✕
        </button>
      </div>
      <div className="flex flex-1 overflow-hidden">
        {/* Callers */}
        <div className="flex-1 border-r border-gray-700 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">Called by ({callers.length})</div>
          {callers.length === 0 ? (
            <div className="text-gray-600 italic">No callers found</div>
          ) : (
            callers.map((c) => (
              <button
                type="button"
                key={c.key}
                onClick={() => onNavigate(c.sourceAddr)}
                className="block w-full text-left px-1 py-0.5 rounded hover:bg-gray-800 truncate"
              >
                <span className="text-blue-400">
                  {c.fn ? getDisplayName(c.fn, renames) : "unknown"}
                </span>
                {/* An attributed row shows the function's ENTRY while navigating
                    to the call site; an unattributed one has no entry to show,
                    so it shows the call site it navigates to. */}
                <span className="text-gray-600 ml-1">
                  0x{(c.fn ? c.fn.address : c.sourceAddr).toString(16).toUpperCase()}
                </span>
              </button>
            ))
          )}
        </div>
        {/* Callees */}
        <div className="flex-1 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">Calls ({callees.length})</div>
          {callees.length === 0 ? (
            <div className="text-gray-600 italic">No calls found</div>
          ) : (
            callees.map((c) => (
              <button
                type="button"
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
