import { useState, useEffect, useCallback } from "react";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { disasmEngine } from "../disasm/engine";
import type { Instruction } from "../disasm/types";

interface XrefPopupState {
  x: number;
  y: number;
  funcName: string;
  sources: number[];
}

export function ImportsView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [importXrefs, setImportXrefs] = useState<Map<number, number[]> | null>(null);
  const [xrefLoading, setXrefLoading] = useState(false);
  const [xrefPopup, setXrefPopup] = useState<XrefPopupState | null>(null);

  // Dismiss popup
  useEffect(() => {
    if (!xrefPopup) return;
    const dismiss = () => setXrefPopup(null);
    const keyDismiss = (e: KeyboardEvent) => { if (e.key === "Escape") dismiss(); };
    window.addEventListener("click", dismiss);
    window.addEventListener("keydown", keyDismiss);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("keydown", keyDismiss);
    };
  }, [xrefPopup]);

  const handleLoadXrefs = useCallback(() => {
    if (!pe || xrefLoading) return;
    setXrefLoading(true);
    setTimeout(() => {
      try {
        // Collect all IAT addresses
        const iatAddrs = new Set<number>();
        for (const imp of pe.imports) {
          for (const addr of imp.iatAddresses) iatAddrs.add(addr);
        }

        // Disassemble code sections
        const allInsns: Instruction[] = [];
        for (const sec of pe.sections) {
          if ((sec.characteristics & 0x20000000) === 0 && sec.name !== ".text") continue;
          try {
            const bytes = new Uint8Array(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData);
            const base = pe.optionalHeader.imageBase + sec.virtualAddress;
            const insns = disasmEngine.disassemble(bytes, base, pe.is64, pe.strings);
            allInsns.push(...insns);
          } catch { /* skip */ }
        }

        // Scan for references to IAT addresses
        const xrefs = new Map<number, number[]>();
        for (const insn of allInsns) {
          // Check RIP-relative
          const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
          if (ripMatch) {
            const sign = ripMatch[1] === '+' ? 1 : -1;
            const disp = parseInt(ripMatch[2], 16);
            const target = insn.address + insn.size + sign * disp;
            if (iatAddrs.has(target)) {
              let arr = xrefs.get(target);
              if (!arr) { arr = []; xrefs.set(target, arr); }
              arr.push(insn.address);
            }
          }
          // Check absolute addresses
          const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
          if (addrMatches) {
            for (const addrStr of addrMatches) {
              const addr = parseInt(addrStr, 16);
              if (iatAddrs.has(addr)) {
                let arr = xrefs.get(addr);
                if (!arr) { arr = []; xrefs.set(addr, arr); }
                arr.push(insn.address);
              }
            }
          }
        }
        setImportXrefs(xrefs);
      } catch { /* ignore */ }
      setXrefLoading(false);
    }, 0);
  }, [pe, xrefLoading]);

  if (!pe) return null;

  const filtered = pe.imports
    .map((imp) => ({
      ...imp,
      functions: imp.functions.map((fn, idx) => ({ name: fn, iatAddr: imp.iatAddresses[idx] ?? 0 })).filter((f) =>
        f.name.toLowerCase().includes(filter.toLowerCase()),
      ),
    }))
    .filter(
      (imp) =>
        imp.functions.length > 0 ||
        imp.libraryName.toLowerCase().includes(filter.toLowerCase()),
    );

  const totalFunctions = pe.imports.reduce(
    (sum, imp) => sum + imp.functions.length,
    0,
  );

  const filteredFuncCount = filtered.reduce(
    (sum, imp) => sum + imp.functions.length,
    0,
  );

  const toggleCollapse = (lib: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(lib)) next.delete(lib);
      else next.add(lib);
      return next;
    });
  };

  return (
    <div className="p-4 text-xs overflow-auto h-full relative">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Imports ({pe.imports.length} libraries, {totalFunctions} functions)
        </h2>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter..."
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {filter && (
          <span className="text-gray-500 text-[11px]">
            {filteredFuncCount} match{filteredFuncCount !== 1 ? "es" : ""} in{" "}
            {filtered.length} librar{filtered.length !== 1 ? "ies" : "y"}
          </span>
        )}
        <div className="flex-1" />
        {!importXrefs && (
          <button
            onClick={handleLoadXrefs}
            disabled={xrefLoading}
            className="px-2 py-0.5 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50"
          >
            {xrefLoading ? (
              <span className="flex items-center gap-1">
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Loading...
              </span>
            ) : "Load xrefs"}
          </button>
        )}
        {importXrefs && (
          <span className="text-[10px] text-green-400">Xrefs loaded</span>
        )}
      </div>

      <div className="space-y-1">
        {filtered.map((imp, i) => {
          const isCollapsed = collapsed.has(imp.libraryName);
          return (
            <div key={i}>
              <button
                onClick={() => toggleCollapse(imp.libraryName)}
                className="flex items-center gap-1.5 text-yellow-400 font-semibold hover:text-yellow-300 py-0.5"
              >
                <span className="text-[10px] text-gray-500 w-3 inline-block">
                  {isCollapsed ? "\u25B6" : "\u25BC"}
                </span>
                {imp.libraryName}
                <span className="text-gray-500 font-normal text-[10px]">
                  ({imp.functions.length})
                </span>
              </button>
              {!isCollapsed && (
                <ul className="ml-6 space-y-0.5">
                  {imp.functions.map((fn, j) => {
                    const xrefCount = importXrefs?.get(fn.iatAddr)?.length ?? 0;
                    return (
                      <li key={j} className="text-gray-300 flex items-center gap-2">
                        <span>{fn.name}</span>
                        {importXrefs && xrefCount > 0 && (
                          <span
                            className="text-gray-500 cursor-pointer hover:text-blue-400 text-[10px]"
                            onClick={(e) => {
                              e.stopPropagation();
                              const rect = (e.target as HTMLElement).getBoundingClientRect();
                              setXrefPopup({
                                x: rect.left,
                                y: rect.bottom,
                                funcName: fn.name,
                                sources: importXrefs.get(fn.iatAddr)!,
                              });
                            }}
                          >
                            ({xrefCount} xref{xrefCount !== 1 ? "s" : ""})
                          </span>
                        )}
                        {importXrefs && xrefCount === 0 && (
                          <span className="text-gray-700 text-[10px]">(0 xrefs)</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </div>

      {/* Xref popup */}
      {xrefPopup && (
        <div
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[220px] max-h-60 overflow-auto"
          style={{ left: xrefPopup.x, top: xrefPopup.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 text-gray-400 border-b border-gray-700">
            Xrefs to {xrefPopup.funcName}
          </div>
          {xrefPopup.sources.map((src, i) => (
            <button
              key={i}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-blue-400 font-mono"
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: src });
                dispatch({ type: "SET_TAB", tab: "disassembly" });
                setXrefPopup(null);
              }}
            >
              0x{src.toString(16).toUpperCase()}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
