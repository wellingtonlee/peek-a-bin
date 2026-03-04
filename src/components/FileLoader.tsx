import { useState, useCallback, useRef, useMemo } from "react";
import type { AnalysisPhase } from "../hooks/usePEFile";

interface FileLoaderProps {
  onFile: (buffer: ArrayBuffer, fileName: string) => void;
  loading: boolean;
  error: string | null;
  analysisPhase: AnalysisPhase;
  fileName?: string | null;
}

interface RecentFile {
  name: string;
  bookmarks: number;
  renames: number;
  comments: number;
}

const ANALYSIS_STEPS = [
  { label: "Parsing PE", phases: ["parsing"] },
  { label: "Extracting strings", phases: ["extracting-strings"] },
  { label: "Detecting functions", phases: ["detecting-functions", "recursive-descent", "gap-filling"] },
  { label: "Building xrefs", phases: ["building-xrefs"] },
] as const;

function getStepStatus(stepIndex: number, analysisPhase: AnalysisPhase): "done" | "active" | "pending" {
  const step = ANALYSIS_STEPS[stepIndex];
  if ((step.phases as readonly string[]).includes(analysisPhase)) return "active";

  const activeStepIndex = ANALYSIS_STEPS.findIndex(s => (s.phases as readonly string[]).includes(analysisPhase));
  if (analysisPhase === "ready") return "done";
  if (activeStepIndex === -1) return "pending";
  return stepIndex < activeStepIndex ? "done" : "pending";
}

function getRecentFiles(): RecentFile[] {
  const files: RecentFile[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith("peek-a-bin:")) continue;
    const name = key.slice("peek-a-bin:".length);
    if (name === "sidebar-width") continue;
    try {
      const data = JSON.parse(localStorage.getItem(key)!);
      const bookmarks = Array.isArray(data.bookmarks) ? data.bookmarks.length : 0;
      const renames = data.renames ? Object.keys(data.renames).length : 0;
      const comments = data.comments ? Object.keys(data.comments).length : 0;
      if (bookmarks + renames + comments > 0) {
        files.push({ name, bookmarks, renames, comments });
      }
    } catch { /* skip corrupt entries */ }
  }
  files.sort((a, b) => (b.bookmarks + b.renames + b.comments) - (a.bookmarks + a.renames + a.comments));
  return files.slice(0, 5);
}

export function FileLoader({ onFile, loading, error, analysisPhase, fileName }: FileLoaderProps) {
  const [dragging, setDragging] = useState(false);
  const [loadingExample, setLoadingExample] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const recentFiles = useMemo(getRecentFiles, []);

  const isAnalyzing = analysisPhase !== "idle" && analysisPhase !== "ready";

  const loadExample = useCallback(async () => {
    setLoadingExample(true);
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}crackme100.exe`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buffer = await res.arrayBuffer();
      onFile(buffer, "crackme100.exe");
    } catch (e) {
      console.error("Failed to load example:", e);
    } finally {
      setLoadingExample(false);
    }
  }, [onFile]);

  const handleFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          onFile(reader.result, file.name);
        }
      };
      reader.onerror = () => {
        console.error("FileReader error:", reader.error);
      };
      reader.readAsArrayBuffer(file);
    },
    [onFile],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback(() => setDragging(false), []);

  const onChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div className="flex flex-col items-center justify-center h-screen bg-gray-950">
      {/* Branding */}
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-bold text-gray-100">Peek-a-Bin</h1>
        <p className="text-sm text-gray-500">Browser-based PE disassembler</p>
      </div>

      {/* Drop zone */}
      <div
        className={`flex flex-col items-center justify-center w-[600px] h-[350px] border-2 border-dashed rounded-xl transition-colors ${
          isAnalyzing ? "" : "cursor-pointer"
        } ${
          dragging
            ? "border-blue-400 bg-blue-400/10"
            : "border-gray-600 hover:border-gray-400"
        }`}
        onDrop={isAnalyzing ? undefined : onDrop}
        onDragOver={isAnalyzing ? undefined : onDragOver}
        onDragLeave={isAnalyzing ? undefined : onDragLeave}
        onClick={isAnalyzing ? undefined : () => inputRef.current?.click()}
      >
        {isAnalyzing || loading ? (
          /* Loading progress */
          <div className="flex flex-col items-center gap-4 px-8">
            {fileName && (
              <p className="text-sm text-gray-400 mb-2">
                Analyzing <span className="text-gray-200 font-medium">{fileName}</span>
              </p>
            )}
            <div className="flex flex-col gap-3 w-full">
              {ANALYSIS_STEPS.map((step, i) => {
                const status = getStepStatus(i, analysisPhase);
                return (
                  <div key={step.label} className="flex items-center gap-3">
                    {status === "done" && (
                      <span className="text-green-400 w-5 text-center">✓</span>
                    )}
                    {status === "active" && (
                      <span className="text-yellow-400 w-5 text-center animate-pulse">●</span>
                    )}
                    {status === "pending" && (
                      <span className="text-gray-600 w-5 text-center">○</span>
                    )}
                    <span className={
                      status === "done" ? "text-gray-400" :
                      status === "active" ? "text-gray-200" :
                      "text-gray-600"
                    }>
                      {step.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          /* Normal drop zone content */
          <>
            <svg
              className="w-16 h-16 mb-4 text-gray-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9 8h6m-5 0a3 3 0 110 6H9l3 3m-3-3h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V17a2 2 0 01-2 2z"
              />
            </svg>
            <p className="text-xl text-gray-300 mb-2">Drop a PE file here</p>
            <p className="text-sm text-gray-500">
              or click to browse (.exe, .dll)
            </p>
            {error && (
              <p className="mt-4 text-sm text-red-400 max-w-md text-center">
                {error}
              </p>
            )}

            {/* Divider + Try example */}
            <div className="flex items-center gap-3 mt-5 w-48">
              <hr className="flex-1 border-gray-700" />
              <span className="text-xs text-gray-600">or</span>
              <hr className="flex-1 border-gray-700" />
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                loadExample();
              }}
              disabled={loading || loadingExample}
              className="mt-3 text-sm text-gray-500 hover:text-gray-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loadingExample ? "Loading..." : "Try example: crackme100.exe"}
            </button>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".exe,.dll,.sys,.ocx"
          onChange={onChange}
          className="hidden"
        />
      </div>

      {/* Recent files */}
      {recentFiles.length > 0 && !isAnalyzing && !loading && (
        <div className="mt-6 w-[500px]">
          <p className="text-xs text-gray-600 uppercase tracking-wider mb-2">Recent analyses</p>
          <div className="flex flex-col gap-1">
            {recentFiles.map((f) => {
              const parts: string[] = [];
              if (f.bookmarks > 0) parts.push(`${f.bookmarks} bookmark${f.bookmarks !== 1 ? "s" : ""}`);
              if (f.renames > 0) parts.push(`${f.renames} rename${f.renames !== 1 ? "s" : ""}`);
              if (f.comments > 0) parts.push(`${f.comments} comment${f.comments !== 1 ? "s" : ""}`);
              return (
                <div key={f.name} className="flex items-center justify-between text-sm px-2 py-1">
                  <span className="text-gray-400 font-mono text-xs">{f.name}</span>
                  <span className="text-gray-600 text-xs">{parts.join(", ")}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
