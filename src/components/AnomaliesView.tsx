import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import type { Anomaly } from "../analysis/anomalies";

const SEVERITY_ORDER: Record<string, number> = { critical: 0, warning: 1, info: 2 };
const SEVERITY_COLORS: Record<string, { bg: string; text: string; badge: string }> = {
  critical: { bg: "bg-red-900/20", text: "text-red-300", badge: "bg-red-600" },
  warning: { bg: "bg-amber-900/20", text: "text-amber-300", badge: "bg-amber-600" },
  info: { bg: "bg-blue-900/20", text: "text-blue-300", badge: "bg-blue-600" },
};

const IRP_NAMES: Record<number, string> = {
  0x00: "IRP_MJ_CREATE",
  0x01: "IRP_MJ_CREATE_NAMED_PIPE",
  0x02: "IRP_MJ_CLOSE",
  0x03: "IRP_MJ_READ",
  0x04: "IRP_MJ_WRITE",
  0x05: "IRP_MJ_QUERY_INFORMATION",
  0x06: "IRP_MJ_SET_INFORMATION",
  0x07: "IRP_MJ_QUERY_EA",
  0x08: "IRP_MJ_SET_EA",
  0x09: "IRP_MJ_FLUSH_BUFFERS",
  0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
  0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
  0x0C: "IRP_MJ_DIRECTORY_CONTROL",
  0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
  0x0E: "IRP_MJ_DEVICE_CONTROL",
  0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
  0x10: "IRP_MJ_SHUTDOWN",
  0x11: "IRP_MJ_LOCK_CONTROL",
  0x12: "IRP_MJ_CLEANUP",
  0x13: "IRP_MJ_CREATE_MAILSLOT",
  0x14: "IRP_MJ_QUERY_SECURITY",
  0x15: "IRP_MJ_SET_SECURITY",
  0x16: "IRP_MJ_POWER",
  0x17: "IRP_MJ_SYSTEM_CONTROL",
  0x18: "IRP_MJ_DEVICE_CHANGE",
  0x19: "IRP_MJ_QUERY_QUOTA",
  0x1A: "IRP_MJ_SET_QUOTA",
  0x1B: "IRP_MJ_PNP",
};

export function AnomaliesView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const anomalies = [...state.anomalies].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
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
                    <span className={`${sc.badge} text-white text-[9px] font-bold px-1.5 py-0.5 rounded uppercase`}>
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
                      <td className="py-1.5 px-2 text-gray-300">
                        {IRP_NAMES[handler.irpMajor] ?? handler.irpName}
                      </td>
                      <td className="py-1.5 px-2">
                        {handler.handlerAddress > 0 ? (
                          <button
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
