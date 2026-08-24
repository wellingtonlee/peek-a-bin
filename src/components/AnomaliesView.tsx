import type { Anomaly } from "../analysis/anomalies";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import { ANOMALY_BADGE, BADGE_RANK, type BadgeLevel, FINDING_BADGE } from "./severity";

/**
 * The three-way palette every severity is painted with, keyed on the shared
 * {@link BadgeLevel} rather than on either severity union.
 *
 * WHAT MOVED, AND WHY. There were two tables here — one over
 * `Anomaly["severity"]` and one over `AIScanFinding["severity"]` — declared as
 * `Record`s rather than the hand-written predicate chains they replaced, because
 * a chain is what `peek-a-bin-n7q1` shipped: one predicate spelled by hand at
 * five sites, the fifth missed, and one notice rendering amber and red at the
 * same time. That docstring then recorded the remaining half of the problem:
 * `AddressBar`'s tab badge asks the *maximum* over both lists at once and
 * answered it with a THIRD chain, `severity === "critical" || === "high"`.
 * "The two agree today. Nothing makes them agree tomorrow."
 *
 * Something does now. `./severity.ts` holds the one mapping from each union onto
 * the three levels the UI actually paints, and the one ranking of those levels;
 * both files read it. The five-member table collapses into this three-member one
 * because it was never five colours — `high` was always `critical`'s red and
 * `medium` always `warning`'s amber — and the class names stay HERE because
 * those really do differ per site: a table row in `-900/20`/`-300`/`-600`
 * against `AddressBar`'s 8px dot in `-500`. What was duplicated was the
 * judgement, not the paint.
 *
 * `Record<BadgeLevel, …>` keeps the instrument a fourth level would trip, and
 * `ANOMALY_BADGE`/`FINDING_BADGE` are the ones a fourth anomaly severity or a
 * sixth finding severity trips. The `??` fallbacks at the read sites are kept
 * even so: a severity can reach `AppState` from outside the type system (the MCP
 * wire, a restored snapshot), and the fallback is what keeps that a blue row
 * rather than a property read on `undefined`. The two fallbacks differ
 * deliberately — unknown sorts LAST (`?? 9`) and paints BLUE (`?? info`) — which
 * is why `severity.ts` exports raw lookups rather than one total function.
 */
const BADGE_COLORS: Record<BadgeLevel, { bg: string; text: string; badge: string }> = {
  critical: { bg: "bg-red-900/20", text: "text-red-300", badge: "bg-red-600" },
  warning: { bg: "bg-amber-900/20", text: "text-amber-300", badge: "bg-amber-600" },
  info: { bg: "bg-blue-900/20", text: "text-blue-300", badge: "bg-blue-600" },
};

export function AnomaliesView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const anomalies = [...state.anomalies].sort(
    (a, b) =>
      (BADGE_RANK[ANOMALY_BADGE[a.severity]] ?? 9) - (BADGE_RANK[ANOMALY_BADGE[b.severity]] ?? 9),
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
              const sc = BADGE_COLORS[ANOMALY_BADGE[a.severity]] ?? BADGE_COLORS.info;
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
                  const sevColor =
                    BADGE_COLORS[FINDING_BADGE[finding.severity]] ?? BADGE_COLORS.info;
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
