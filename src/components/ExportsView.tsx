import { useState } from "react";
import { useAppState } from "../hooks/usePEFile";

export function ExportsView() {
  const { peFile: pe } = useAppState();
  const [filter, setFilter] = useState("");

  if (!pe) return null;

  const filtered = pe.exports.filter(
    (exp) =>
      exp.name.toLowerCase().includes(filter.toLowerCase()) ||
      exp.ordinal.toString().includes(filter),
  );

  return (
    <div className="p-4 text-xs overflow-auto h-full">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Exports ({pe.exports.length})
        </h2>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter..."
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
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
              <th className="text-left py-2 pr-4">Ordinal</th>
              <th className="text-left py-2 pr-4">Name</th>
              <th className="text-left py-2">RVA</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((exp, i) => (
              <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50">
                <td className="py-1.5 pr-4 text-gray-400">{exp.ordinal}</td>
                <td className="py-1.5 pr-4 text-gray-200">{exp.name}</td>
                <td className="py-1.5 text-blue-400">
                  0x{exp.address.toString(16).toUpperCase()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
