import { useCallback } from "react";
import { useAppState } from "../hooks/usePEFile";
import { MarkdownRenderer } from "./MarkdownRenderer";

interface AIReportPanelProps {
  onClose: () => void;
  onRegenerate: () => void;
}

export function AIReportPanel({ onClose, onRegenerate }: AIReportPanelProps) {
  const state = useAppState();
  const report = state.aiReport;

  const handleDownload = useCallback(() => {
    if (!report?.content) return;
    const blob = new Blob([report.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.fileName ?? "analysis"}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, [report?.content, state.fileName]);

  if (!report) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl flex flex-col" style={{ width: "min(90vw, 800px)", height: "min(90vh, 700px)" }}>
        {/* Header */}
        <div className="px-4 py-3 border-b border-gray-700 flex items-center gap-3 shrink-0">
          <h3 className="text-sm font-semibold text-gray-200">AI Analysis Report</h3>
          {report.status === "streaming" && (
            <span className="flex items-center gap-1.5 text-blue-400 text-[10px]">
              <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Generating...
            </span>
          )}
          <div className="flex-1" />
          {report.status === "done" && (
            <>
              <button
                onClick={onRegenerate}
                className="px-2 py-1 text-[10px] bg-purple-800/50 text-purple-300 rounded hover:bg-purple-700/50"
              >
                Regenerate
              </button>
              <button
                onClick={handleDownload}
                className="px-2 py-1 text-[10px] bg-blue-800/50 text-blue-300 rounded hover:bg-blue-700/50"
              >
                Download .md
              </button>
            </>
          )}
          <button
            onClick={onClose}
            className="px-2 py-1 text-[10px] bg-gray-700 text-gray-400 rounded hover:bg-gray-600 hover:text-gray-200"
          >
            Close
          </button>
        </div>

        {/* Error */}
        {report.error && (
          <div className="px-4 py-2 text-xs text-red-400 bg-red-900/30 border-b border-red-800/50 shrink-0">
            {report.error}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-auto px-5 py-3">
          {report.content ? (
            <MarkdownRenderer content={report.content} />
          ) : report.status === "streaming" ? (
            <div className="flex items-center justify-center h-full text-gray-500 text-sm gap-2">
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Building analysis context...
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
