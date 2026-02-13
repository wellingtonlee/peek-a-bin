import { useState } from "react";
import { useAppState } from "../hooks/usePEFile";

export function ImportsView() {
  const { peFile: pe } = useAppState();
  const [filter, setFilter] = useState("");

  if (!pe) return null;

  const filtered = pe.imports
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
    );

  const totalFunctions = pe.imports.reduce(
    (sum, imp) => sum + imp.functions.length,
    0,
  );

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
      </div>

      <div className="space-y-3">
        {filtered.map((imp, i) => (
          <div key={i}>
            <h3 className="text-yellow-400 font-semibold mb-1">
              {imp.libraryName}
            </h3>
            <ul className="ml-4 space-y-0.5">
              {imp.functions.map((fn, j) => (
                <li key={j} className="text-gray-300">
                  {fn}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
