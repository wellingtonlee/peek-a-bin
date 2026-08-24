import type { Anomaly } from "../analysis/anomalies";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import type { AIScanFinding } from "../llm/types";

/**
 * A severity's place in the reading order, and the three class names that paint
 * it.
 *
 * BOTH ARE `Record<Anomaly["severity"], …>` RATHER THAN `Record<string, …>`, and
 * that is the whole instrument for a fourth severity. They used to be keyed by
 * `string`, so adding one to {@link Anomaly} compiled, sorted last behind `info`
 * and rendered in `info`'s blue — a new severity silently painted as the mildest
 * one. Typed this way it fails the build here instead, the way
 * `DETECT_PASS_LABELS` and `VIEW_TAB_LABELS` do for their own unions.
 *
 * The `??` fallbacks at the two read sites are kept even so: an anomaly can
 * reach `AppState` from outside the type system (the MCP wire, a restored
 * snapshot), and the fallback is what keeps that a blue row rather than a
 * property read on `undefined`.
 */
const SEVERITY_ORDER: Record<Anomaly["severity"], number> = { critical: 0, warning: 1, info: 2 };
const SEVERITY_COLORS: Record<Anomaly["severity"], { bg: string; text: string; badge: string }> = {
  critical: { bg: "bg-red-900/20", text: "text-red-300", badge: "bg-red-600" },
  warning: { bg: "bg-amber-900/20", text: "text-amber-300", badge: "bg-amber-600" },
  info: { bg: "bg-blue-900/20", text: "text-blue-300", badge: "bg-blue-600" },
};

/**
 * The AI findings' own palette — a SECOND, wider vocabulary, deliberately kept
 * apart from {@link SEVERITY_COLORS} because the two enumerations differ:
 * `AIScanFinding["severity"]` has five members and no `warning`.
 *
 * DECLARED AS A TABLE RATHER THAN THE NESTED TERNARY IT REPLACED. The old
 * spelling was a hand-written predicate chain over the severity string
 * (`=== "critical" || === "high" ? red : === "medium" ? amber : blue`), which is
 * exactly the shape `peek-a-bin-n7q1` shipped: five render sites each spelling
 * `kind === "analysis-failed"` by hand, the fifth missed, and one notice on
 * screen in two colours at once. A `Record` over the union means a sixth
 * severity fails the build.
 *
 * STILL NOT UNIFIED WITH `AddressBar.tsx`'s status dot, which asks a different
 * question of the same union — the *maximum* severity across anomalies and
 * findings together — and answers it with its own hand-written
 * `severity === "critical" || severity === "high"` chain. The two agree today.
 * Nothing makes them agree tomorrow.
 */
const FINDING_COLORS: Record<
  AIScanFinding["severity"],
  { bg: string; text: string; badge: string }
> = {
  critical: { bg: "bg-red-900/20", text: "text-red-300", badge: "bg-red-600" },
  high: { bg: "bg-red-900/20", text: "text-red-300", badge: "bg-red-600" },
  medium: { bg: "bg-amber-900/20", text: "text-amber-300", badge: "bg-amber-600" },
  low: { bg: "bg-blue-900/20", text: "text-blue-300", badge: "bg-blue-600" },
  info: { bg: "bg-blue-900/20", text: "text-blue-300", badge: "bg-blue-600" },
};

export function AnomaliesView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const anomalies = [...state.anomalies].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );
  const driverInfo = state.driverInfo;
  const irpHandlers = state.irpHandlers;

  return (
    <div className="h-full overflow-auto p-4 text-sm">
      {/* Security Anomalies */}
      <h2 className="text-gray-200 font-semibold text-base mb-3">Security Anomalies</h2>
      {anomalies.length === 0 ? (
        <div className="text-gray-500 text-xs py-4">No anomalies detected.</div>
      ) : (
        <table className="w-full text-xs mb-6">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-700">
              <th className="py-1.5 px-2 w-20">Severity</th>
              <th className="py-1.5 px-2 w-56">Title</th>
              <th className="py-1.5 px-2">Detail</th>
            </tr>
          </thead>
          <tbody>
            {anomalies.map((a: Anomaly, i: number) => {
              const sc = SEVERITY_COLORS[a.severity] ?? SEVERITY_COLORS.info;
              return (
                <tr key={i} className={`${sc.bg} border-b border-gray-800/50`}>
                  <td className="py-1.5 px-2">
                    <span
                      className={`${sc.badge} text-white text-[9px] font-bold px-1.5 py-0.5 rounded uppercase`}
                    >
                      {a.severity}
                    </span>
                  </td>
                  <td className={`py-1.5 px-2 ${sc.text} font-medium`}>{a.title}</td>
                  <td className="py-1.5 px-2 text-gray-400">{a.detail}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {/* AI Security Findings — gated on the scan phase, not on the finding
          count. An empty result list is only a clean bill of health when the
          scan actually completed; a failed scan produces the same empty list. */}
      {state.aiScan.phase !== "idle" && (
        <>
          <h2 className="text-gray-200 font-semibold text-base mb-3 mt-6">AI Security Findings</h2>

          {state.aiScan.phase === "scanning" && (
            <div
              role="status"
              aria-live="polite"
              className="mb-3 px-3 py-2 rounded border border-blue-800 bg-blue-900/20 text-xs text-blue-200"
            >
              Scanning… {state.aiScan.scanned + state.aiScan.failed} of {state.aiScan.total}{" "}
              functions
            </div>
          )}

          {state.aiScan.phase === "failed" && (
            <div
              role="alert"
              className="mb-3 px-3 py-2 rounded border border-red-700 bg-red-900/30 text-xs text-red-200"
            >
              <p className="font-semibold text-red-300">
                Scan failed — this is not a clean result.
              </p>
              <p className="mt-1">
                No functions could be analysed
                {state.aiScan.total > 0 ? ` (0 of ${state.aiScan.total})` : ""}. An empty findings
                list here means the scan produced nothing, not that the binary is free of issues.
              </p>
              {state.aiScan.error && (
                <p className="mt-1 font-mono text-[10px] text-red-300/80 break-words">
                  {state.aiScan.error}
                </p>
              )}
            </div>
          )}

          {state.aiScan.phase === "complete" && state.aiScan.failed > 0 && (
            <div
              role="status"
              className="mb-3 px-3 py-2 rounded border border-amber-700 bg-amber-900/25 text-xs text-amber-200"
            >
              <p className="font-semibold text-amber-300">
                Partial results — the scan did not cover the whole binary.
              </p>
              <p className="mt-1">
                {state.aiScan.scanned} of {state.aiScan.total} functions analysed,{" "}
                {state.aiScan.failed} failed. Nothing in the functions that failed is represented
                below.
              </p>
              {state.aiScan.error && (
                <p className="mt-1 font-mono text-[10px] text-amber-300/80 break-words">
                  {state.aiScan.error}
                </p>
              )}
            </div>
          )}

          {state.aiScan.phase === "complete" &&
            state.aiScan.failed === 0 &&
            state.aiScanResults.length === 0 && (
              <div
                role="status"
                className="mb-3 px-3 py-2 rounded border border-gray-700 bg-gray-800/40 text-xs text-gray-300"
              >
                No issues found across {state.aiScan.scanned} functions.
              </div>
            )}

          {state.aiScanResults.length > 0 && (
            <table className="w-full text-xs mb-6">
              <thead>
                <tr className="text-gray-500 text-left border-b border-gray-700">
                  <th className="py-1.5 px-2 w-20">Severity</th>
                  <th className="py-1.5 px-2 w-40">Title</th>
                  <th className="py-1.5 px-2 w-36">Function</th>
                  <th className="py-1.5 px-2">Description</th>
                </tr>
              </thead>
              <tbody>
                {state.aiScanResults.map((finding, i) => {
                  const sevColor = FINDING_COLORS[finding.severity] ?? FINDING_COLORS.info;
                  return (
                    <tr key={i} className={`${sevColor.bg} border-b border-gray-800/50`}>
                      <td className="py-1.5 px-2">
                        <span
                          className={`${sevColor.badge} text-white text-[9px] font-bold px-1.5 py-0.5 rounded uppercase`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className={`py-1.5 px-2 ${sevColor.text} font-medium`}>
                        {finding.title}
                      </td>
                      <td className="py-1.5 px-2">
                        <button
                          type="button"
                          className="text-blue-400 hover:underline font-mono text-[10px]"
                          onClick={() => {
                            dispatch({ type: "SET_ADDRESS", address: finding.functionAddress });
                            dispatch({ type: "SET_TAB", tab: "disassembly" });
                          }}
                        >
                          {finding.functionName}
                        </button>
                      </td>
                      <td className="py-1.5 px-2 text-gray-400">
                        <details>
                          <summary className="cursor-pointer">
                            {finding.description.substring(0, 100)}
                            {finding.description.length > 100 ? "..." : ""}
                          </summary>
                          <div className="mt-1 text-gray-400">{finding.description}</div>
                          {finding.remediation && (
                            <div className="mt-1 text-green-400/70">
                              <span className="font-medium">Remediation:</span>{" "}
                              {finding.remediation}
                            </div>
                          )}
                        </details>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}

      {/* Kernel Driver Section */}
      {driverInfo?.isDriver && (
        <>
          <h2 className="text-gray-200 font-semibold text-base mb-3 mt-6">Kernel Driver</h2>
          <div className="flex items-center gap-4 text-xs text-gray-400 mb-4 bg-amber-900/20 border border-amber-700/30 rounded px-3 py-2">
            <span className="text-amber-400 font-semibold">
              {driverInfo.isWDM ? "WDM" : "NATIVE"} DRIVER
            </span>
            <span>{driverInfo.kernelImportCount} kernel APIs</span>
            <span>Modules: {driverInfo.kernelModules.join(", ")}</span>
          </div>

          {irpHandlers.length > 0 && (
            <>
              <h3 className="text-gray-300 font-medium text-sm mb-2">IRP Dispatch Table</h3>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 text-left border-b border-gray-700">
                    <th className="py-1.5 px-2 w-16">MJ Code</th>
                    <th className="py-1.5 px-2 w-64">IRP Name</th>
                    <th className="py-1.5 px-2 w-40">Handler Address</th>
                    <th className="py-1.5 px-2 w-40">Instruction Address</th>
                  </tr>
                </thead>
                <tbody>
                  {irpHandlers.map((handler, i) => (
                    <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/50">
                      <td className="py-1.5 px-2 text-gray-400 font-mono">
                        0x{handler.irpMajor.toString(16).toUpperCase().padStart(2, "0")}
                      </td>
                      <td className="py-1.5 px-2 text-gray-300">{handler.irpName}</td>
                      <td className="py-1.5 px-2">
                        {handler.handlerAddress > 0 ? (
                          <button
                            type="button"
                            className="text-blue-400 hover:underline font-mono"
                            onClick={() => {
                              dispatch({ type: "SET_ADDRESS", address: handler.handlerAddress });
                              dispatch({ type: "SET_TAB", tab: "disassembly" });
                            }}
                          >
                            0x{handler.handlerAddress.toString(16).toUpperCase()}
                          </button>
                        ) : (
                          <span className="text-gray-600 font-mono">N/A</span>
                        )}
                      </td>
                      <td className="py-1.5 px-2">
                        <button
                          type="button"
                          className="text-blue-400 hover:underline font-mono"
                          onClick={() => {
                            dispatch({ type: "SET_ADDRESS", address: handler.instructionAddress });
                            dispatch({ type: "SET_TAB", tab: "disassembly" });
                          }}
                        >
                          0x{handler.instructionAddress.toString(16).toUpperCase()}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </div>
  );
}
