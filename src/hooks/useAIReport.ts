import { useCallback, useRef } from "react";
import type { Dispatch } from "react";
import type { AppAction, AppState } from "./usePEFile";
import { streamChat } from "../llm/client";
import { hasApiKey, loadSettings } from "../llm/settings";
import { SYSTEM_PROMPT_REPORT } from "../llm/prompt";
import { getDisplayName } from "./usePEFile";
import type { PEFile } from "../pe/types";
import type { Anomaly } from "../analysis/anomalies";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { disasmWorker } from "../workers/disasmClient";
import { analyzeStackFrame } from "../disasm/stack";
import { inferSignature } from "../disasm/signatures";

function buildReportContext(
  pe: PEFile,
  fileName: string,
  functions: DisasmFunction[],
  renames: Record<number, string>,
  anomalies: Anomaly[],
  driverInfo: AppState["driverInfo"],
  decompiled: { name: string; code: string }[],
): string {
  const arch = pe.is64 ? "x86-64" : "x86";
  const entry = `0x${(pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase()}`;
  const subsystem = pe.optionalHeader.subsystem;
  const subsystemName = subsystem === 1 ? "NATIVE" : subsystem === 2 ? "WINDOWS_GUI" : subsystem === 3 ? "WINDOWS_CUI" : `${subsystem}`;

  let ctx = `# Binary: ${fileName}
Architecture: ${arch}
Entry Point: ${entry}
Image Base: 0x${pe.optionalHeader.imageBase.toString(16).toUpperCase()}
Subsystem: ${subsystemName}
Sections: ${pe.sections.length}

## Sections
`;
  for (const s of pe.sections) {
    const name = s.name.replace(/\0/g, "").trim();
    const flags: string[] = [];
    if (s.characteristics & 0x20000000) flags.push("X");
    if (s.characteristics & 0x40000000) flags.push("R");
    if (s.characteristics & 0x80000000) flags.push("W");
    ctx += `- ${name}: size=0x${s.virtualSize.toString(16)}, flags=${flags.join("")}\n`;
  }

  // Notable imports (top 50)
  ctx += "\n## Notable Imports\n";
  const notableAPIs = new Set([
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThread", "NtWriteVirtualMemory", "LoadLibrary", "GetProcAddress",
    "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CreateProcess",
    "ShellExecute", "WinExec", "OpenProcess", "TerminateProcess",
    "RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
    "InternetOpen", "HttpOpenRequest", "URLDownloadToFile", "socket", "connect", "send", "recv",
    "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "BCryptEncrypt",
    "CreateService", "StartService", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "SetWindowsHookEx", "VirtualAllocEx",
  ]);
  let importCount = 0;
  for (const imp of pe.imports) {
    for (const funcName of imp.functions) {
      if (importCount >= 50) break;
      if (notableAPIs.has(funcName) || notableAPIs.has(funcName.replace(/[AW]$/, ""))) {
        ctx += `- ${imp.libraryName}!${funcName}\n`;
        importCount++;
      }
    }
  }
  if (importCount === 0) {
    // Just list first 30
    for (const imp of pe.imports) {
      for (const funcName of imp.functions) {
        if (importCount >= 30) break;
        ctx += `- ${imp.libraryName}!${funcName}\n`;
        importCount++;
      }
    }
  }

  // Exports (top 20)
  if (pe.exports.length > 0) {
    ctx += "\n## Exports\n";
    for (const exp of pe.exports.slice(0, 20)) {
      ctx += `- ${exp.name} (0x${exp.address.toString(16).toUpperCase()})\n`;
    }
  }

  // Anomalies
  if (anomalies.length > 0) {
    ctx += "\n## Rule-Based Anomalies\n";
    for (const a of anomalies) {
      ctx += `- [${a.severity}] ${a.title}: ${a.detail}\n`;
    }
  }

  // Driver info
  if (driverInfo?.isDriver) {
    ctx += `\n## Driver Info\nType: ${driverInfo.isWDM ? "WDM" : "NATIVE"}\nKernel APIs: ${driverInfo.kernelImportCount}\nModules: ${driverInfo.kernelModules.join(", ")}\n`;
  }

  // Functions summary
  ctx += `\n## Functions: ${functions.length} total\n`;

  // Decompiled key functions
  if (decompiled.length > 0) {
    ctx += "\n## Key Functions (Decompiled)\n";
    for (const d of decompiled) {
      ctx += `\n### ${d.name}\n\`\`\`c\n${d.code}\n\`\`\`\n`;
    }
  }

  // Interesting strings (top 30)
  if (pe.strings && pe.strings.size > 0) {
    ctx += "\n## Interesting Strings\n";
    const interesting: string[] = [];
    for (const [, str] of pe.strings) {
      if (interesting.length >= 30) break;
      const lower = str.toLowerCase();
      if (lower.includes("http") || lower.includes("://") || lower.includes("\\\\") ||
          lower.includes("hkey_") || lower.includes("cmd") || lower.includes(".exe") ||
          lower.includes(".dll") || lower.includes("password") || lower.includes("mutex") ||
          lower.includes("pipe") || lower.includes("temp") || lower.includes("appdata") ||
          (str.length > 10 && /[A-Z].*[a-z]|[a-z].*[A-Z]/.test(str))) {
        interesting.push(str.length > 100 ? str.substring(0, 97) + "..." : str);
      }
    }
    for (const s of interesting) {
      ctx += `- "${s}"\n`;
    }
  }

  return ctx;
}

export function useAIReport(state: AppState, dispatch: Dispatch<AppAction>) {
  const abortRef = useRef<AbortController | null>(null);

  const generateReport = useCallback(async () => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe || !state.fileName) return;

    // Check cache
    try {
      const cached = localStorage.getItem(`peek-a-bin:report:${state.fileName}`);
      if (cached) {
        dispatch({ type: "AI_REPORT_START" });
        dispatch({ type: "AI_REPORT_TOKEN", content: cached });
        dispatch({ type: "AI_REPORT_DONE" });
        return;
      }
    } catch {}

    dispatch({ type: "AI_REPORT_START" });

    const controller = new AbortController();
    abortRef.current = controller;

    // Decompile key functions for report context
    const decompiled: { name: string; code: string }[] = [];
    const textSection = pe.sections.find(
      s => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
    );

    if (textSection && state.functions.length > 0) {
      const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;
      const entryVA = pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint;

      // Key functions: entry point, first few exports, highest-xref, largest
      const candidates: DisasmFunction[] = [];
      const entryFunc = state.functions.find(f => f.address === entryVA);
      if (entryFunc) candidates.push(entryFunc);

      // Exports (up to 3)
      for (const exp of pe.exports.slice(0, 3)) {
        const addr = pe.optionalHeader.imageBase + exp.address;
        const fn = state.functions.find(f => f.address === addr);
        if (fn && !candidates.includes(fn)) candidates.push(fn);
      }

      // Largest functions (up to 2)
      const bySize = [...state.functions].sort((a, b) => b.size - a.size);
      for (const fn of bySize.slice(0, 2)) {
        if (!candidates.includes(fn)) candidates.push(fn);
      }

      // Decompile each (cap at 8)
      for (const fn of candidates.slice(0, 8)) {
        if (controller.signal.aborted) break;
        const offset = fn.address - baseAddr;
        if (offset < 0 || offset + fn.size > textSection.sizeOfRawData) continue;

        try {
          const sectionBytes = new Uint8Array(pe.buffer, textSection.pointerToRawData, textSection.sizeOfRawData);
          const funcBytes = sectionBytes.subarray(offset, offset + fn.size);
          const instructions = await disasmWorker.disassemble(funcBytes, fn.address, pe.is64);
          if (instructions.length === 0) continue;

          const xrefMap = await disasmWorker.buildTypedXrefMap(instructions);
          const sf = analyzeStackFrame(fn, instructions, pe.is64);
          const sig = inferSignature(fn, instructions, pe.is64);
          const funcEntries: [number, { name: string; address: number }][] =
            state.functions.map(f => [f.address, { name: getDisplayName(f, state.renames), address: f.address }]);
          const result = await disasmWorker.decompileFunction(
            fn, instructions, xrefMap, sf, sig, pe.is64,
            new Map(funcEntries), pe.runtimeFunctions,
          );
          if (result.code) {
            const lines = result.code.split("\n").slice(0, 200);
            decompiled.push({
              name: getDisplayName(fn, state.renames),
              code: lines.join("\n"),
            });
          }
        } catch { /* skip */ }
      }
    }

    const context = buildReportContext(
      pe, state.fileName, state.functions, state.renames,
      state.anomalies, state.driverInfo, decompiled,
    );

    const config = loadSettings();
    let accContent = "";

    streamChat(
      [{ role: "user", content: context }],
      SYSTEM_PROMPT_REPORT,
      config,
      controller.signal,
      {
        onToken: (accumulated) => {
          accContent = accumulated;
          dispatch({ type: "AI_REPORT_TOKEN", content: accumulated });
        },
        onDone: () => {
          dispatch({ type: "AI_REPORT_DONE" });
          // Cache the report
          if (state.fileName && accContent) {
            try {
              localStorage.setItem(`peek-a-bin:report:${state.fileName}`, accContent);
            } catch {}
          }
        },
        onError: (error) => {
          dispatch({ type: "AI_REPORT_ERROR", error });
        },
      },
    );
  }, [state.peFile, state.fileName, state.functions, state.renames, state.anomalies, state.driverInfo, dispatch]);

  const regenerateReport = useCallback(() => {
    if (state.fileName) {
      try { localStorage.removeItem(`peek-a-bin:report:${state.fileName}`); } catch {}
    }
    generateReport();
  }, [state.fileName, generateReport]);

  const cancelReport = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: "AI_REPORT_DISMISS" });
  }, [dispatch]);

  const dismissReport = useCallback(() => {
    dispatch({ type: "AI_REPORT_DISMISS" });
  }, [dispatch]);

  return { generateReport, regenerateReport, cancelReport, dismissReport };
}
