import { useState, useCallback, useMemo } from "react";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import type { BatchRenameResult } from "../llm/types";

export function BatchRenameModal() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const br = state.batchRename;

  const [localResults, setLocalResults] = useState<BatchRenameResult[]>([]);

  // Sync local results from state when entering review
  useMemo(() => {
    if (br?.status === "review" && br.results.length > 0) {
      setLocalResults(br.results.map(r => ({ ...r, accepted: r.confidence >= 0.8 ? true : null })));
    }
  }, [br?.status, br?.results]);

  const toggleAccept = useCallback((idx: number) => {
    setLocalResults(prev => {
      const next = [...prev];
      const cur = next[idx].accepted;
      next[idx] = { ...next[idx], accepted: cur === true ? false : true };
      return next;
    });
  }, []);

  const acceptAll = useCallback(() => {
    setLocalResults(prev => prev.map(r => ({ ...r, accepted: true })));
  }, []);

  const acceptHighConf = useCallback(() => {
    setLocalResults(prev => prev.map(r => ({ ...r, accepted: r.confidence >= 0.8 ? true : r.accepted })));
  }, []);

  const rejectAll = useCallback(() => {
    setLocalResults(prev => prev.map(r => ({ ...r, accepted: false })));
  }, []);

  const apply = useCallback(() => {
    dispatch({ type: "BATCH_RENAME_ACCEPT", results: localResults });
  }, [dispatch, localResults]);

  const dismiss = useCallback(() => {
    dispatch({ type: "BATCH_RENAME_DISMISS" });
  }, [dispatch]);

  if (!br) return null;

  // Progress overlay during decompiling/running
  if (br.status === "decompiling" || br.status === "running") {
    const pct = br.progress.total > 0 ? Math.round((br.progress.done / br.progress.total) * 100) : 0;
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
        <div className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl p-6 w-96">
          <h3 className="text-sm font-semibold text-gray-200 mb-3">
            {br.status === "decompiling" ? "Decompiling functions..." : "Generating names..."}
          </h3>
          <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="text-xs text-gray-400 flex justify-between">
            <span>{br.progress.done} / {br.progress.total}</span>
            <span>{pct}%</span>
          </div>
          <button
            onClick={dismiss}
            className="mt-4 px-3 py-1.5 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  // Error state
  if (br.error) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
        <div className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl p-6 w-96">
          <h3 className="text-sm font-semibold text-red-400 mb-2">Batch Rename Error</h3>
          <p className="text-xs text-gray-400 mb-4">{br.error}</p>
          <button
            onClick={dismiss}
            className="px-3 py-1.5 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  // Review modal
  if (br.status !== "review") return null;

  const acceptedCount = localResults.filter(r => r.accepted === true).length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl flex flex-col" style={{ width: "min(90vw, 900px)", maxHeight: "80vh" }}>
        {/* Header */}
        <div className="px-4 py-3 border-b border-gray-700 flex items-center gap-3 shrink-0">
          <h3 className="text-sm font-semibold text-gray-200">
            AI Rename Suggestions ({localResults.length})
          </h3>
          <div className="flex-1" />
          <button onClick={acceptAll} className="px-2 py-1 text-[10px] bg-green-800/50 text-green-300 rounded hover:bg-green-700/50">Accept All</button>
          <button onClick={acceptHighConf} className="px-2 py-1 text-[10px] bg-blue-800/50 text-blue-300 rounded hover:bg-blue-700/50">Accept High Conf</button>
          <button onClick={rejectAll} className="px-2 py-1 text-[10px] bg-red-800/50 text-red-300 rounded hover:bg-red-700/50">Reject All</button>
        </div>

        {/* Table */}
        <div className="overflow-auto flex-1">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-800/95">
              <tr className="text-gray-500 text-left border-b border-gray-700">
                <th className="py-2 px-3 w-8"></th>
                <th className="py-2 px-3 w-40">Current Name</th>
                <th className="py-2 px-3 w-40">Suggested Name</th>
                <th className="py-2 px-3 w-16">Conf.</th>
                <th className="py-2 px-3">Reasoning</th>
              </tr>
            </thead>
            <tbody>
              {localResults.map((r, i) => {
                const confColor = r.confidence >= 0.8 ? "text-green-400" : r.confidence >= 0.5 ? "text-yellow-400" : "text-red-400";
                const accepted = r.accepted;
                const rowBg = accepted === true ? "bg-green-900/10" : accepted === false ? "bg-red-900/10" : "";
                return (
                  <tr key={i} className={`border-b border-gray-800/50 ${rowBg} hover:bg-gray-700/30`}>
                    <td className="py-1.5 px-3">
                      <button
                        onClick={() => toggleAccept(i)}
                        className={`w-5 h-5 rounded border text-[10px] flex items-center justify-center ${
                          accepted === true
                            ? "bg-green-600 border-green-500 text-white"
                            : accepted === false
                            ? "bg-red-600/50 border-red-500 text-red-200"
                            : "border-gray-600 text-gray-500 hover:border-gray-400"
                        }`}
                      >
                        {accepted === true ? "\u2713" : accepted === false ? "\u2717" : ""}
                      </button>
                    </td>
                    <td className="py-1.5 px-3 font-mono text-gray-400 truncate">{r.currentName}</td>
                    <td className="py-1.5 px-3 font-mono text-blue-300 truncate">{r.suggestedName}</td>
                    <td className={`py-1.5 px-3 font-mono ${confColor}`}>{Math.round(r.confidence * 100)}%</td>
                    <td className="py-1.5 px-3 text-gray-400 truncate max-w-xs" title={r.reasoning}>{r.reasoning}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-gray-700 flex items-center gap-3 shrink-0">
          <span className="text-xs text-gray-400">{acceptedCount} selected for rename</span>
          <div className="flex-1" />
          <button onClick={dismiss} className="px-3 py-1.5 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600">
            Cancel
          </button>
          <button
            onClick={apply}
            disabled={acceptedCount === 0}
            className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-500 disabled:opacity-30"
          >
            Apply ({acceptedCount})
          </button>
        </div>
      </div>
    </div>
  );
}
