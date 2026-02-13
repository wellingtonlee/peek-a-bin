import { useState, useMemo } from "react";
import { useAppState } from "../hooks/usePEFile";

export function ImportsView() {
  const { peFile: pe } = useAppState();
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  if (!pe) return null;

  const filtered = useMemo(
    () =>
      pe.imports
        .map((imp) => ({
          ...imp,
          functions: imp.functions.filter((fn) =>
            fn.toLowerCase().includes(filter.toLowerCase()),
          ),
        }))
        .filter(
          (imp) =>
            imp.functions.length > 0 ||
            imp.libraryName.toLowerCase().includes(filter.toLowerCase()),
        ),
    [pe.imports, filter],
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
    <div className="p-4 text-xs overflow-auto h-full">
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
                  {isCollapsed ? "▶" : "▼"}
                </span>
                {imp.libraryName}
                <span className="text-gray-500 font-normal text-[10px]">
                  ({imp.functions.length})
                </span>
              </button>
              {!isCollapsed && (
                <ul className="ml-6 space-y-0.5">
                  {imp.functions.map((fn, j) => (
                    <li key={j} className="text-gray-300">
                      {fn}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
