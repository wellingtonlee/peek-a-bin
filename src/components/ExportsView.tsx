import { useState, useMemo, useCallback, useRef } from "react";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";

type SortKey = "ordinal" | "name" | "address";
type SortDir = "asc" | "desc";

export function ExportsView() {
  const { peFile: pe } = useAppState();
  const dispatch = useAppDispatch();
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  const [sortKey, setSortKey] = useState<SortKey>("ordinal");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  if (!pe) return null;

  const imageBase = pe.optionalHeader.imageBase;

  const filtered = useMemo(() => {
    let exps = pe.exports.filter(
      (exp) =>
        exp.name.toLowerCase().includes(filter.toLowerCase()) ||
        exp.ordinal.toString().includes(filter) ||
        (imageBase + exp.address).toString(16).toLowerCase().includes(filter.toLowerCase()),
    );
    exps = [...exps].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "ordinal") cmp = a.ordinal - b.ordinal;
      else if (sortKey === "name") cmp = a.name.localeCompare(b.name);
      else cmp = a.address - b.address;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return exps;
  }, [pe.exports, filter, sortKey, sortDir, imageBase]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";

  const handleNavigate = (rva: number) => {
    dispatch({ type: "SET_ADDRESS", address: imageBase + rva });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
  };

  return (
    <div className="p-4 text-xs overflow-auto h-full">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Exports ({pe.exports.length})
        </h2>
        <input
          type="text"
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter..."
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {filter && (
          <span className="text-gray-500 text-[11px]">
            {filtered.length} match{filtered.length !== 1 ? "es" : ""}
          </span>
        )}
      </div>

      {filtered.length === 0 ? (
        <p className="text-gray-500">
          {pe.exports.length === 0
            ? "No exports found in this binary."
            : "No exports match the filter."}
        </p>
      ) : (
        <table className="w-full">
          <thead>
            <tr className="text-gray-400 border-b border-gray-700">
              <th
                className="text-left py-2 pr-4 cursor-pointer hover:text-gray-200 select-none"
                onClick={() => toggleSort("ordinal")}
              >
                Ordinal{sortIndicator("ordinal")}
              </th>
              <th
                className="text-left py-2 pr-4 cursor-pointer hover:text-gray-200 select-none"
                onClick={() => toggleSort("name")}
              >
                Name{sortIndicator("name")}
              </th>
              <th
                className="text-left py-2 cursor-pointer hover:text-gray-200 select-none"
                onClick={() => toggleSort("address")}
              >
                VA{sortIndicator("address")}
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((exp, i) => (
              <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50">
                <td className="py-1.5 pr-4 text-gray-400">{exp.ordinal}</td>
                <td className="py-1.5 pr-4 text-gray-200">{exp.name}</td>
                <td className="py-1.5">
                  <button
                    onClick={() => handleNavigate(exp.address)}
                    className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
                  >
                    0x{(imageBase + exp.address).toString(16).toUpperCase()}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
