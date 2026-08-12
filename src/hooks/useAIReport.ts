import type { Dispatch } from "react";
import { useCallback, useRef } from "react";
import type { Anomaly } from "../analysis/anomalies";
import type { DisasmFunction } from "../disasm/types";
import { matchesApi, NOTABLE_APIS } from "../llm/apiLists";
import { streamChat } from "../llm/client";
import { decompileForLLM } from "../llm/decompileForLLM";
import { SYSTEM_PROMPT_REPORT } from "../llm/prompt";
import { hasApiKey, loadSettings } from "../llm/settings";
import { IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE } from "../pe/constants";
import { findCodeSection } from "../pe/sections";
import type { PEFile } from "../pe/types";
import type { AppAction, AppState } from "./usePEFile";
import { getDisplayName } from "./usePEFile";

/** Report context is whole-binary, so each function gets a generous but bounded slice. */
const MAX_REPORT_LINES_PER_FUNC = 200;

function buildReportContext(
  pe: PEFile,
  fileName: string,
  functions: DisasmFunction[],
  _renames: Record<number, string>,
  anomalies: Anomaly[],
  driverInfo: AppState["driverInfo"],
  decompiled: { name: string; code: string }[],
): string {
  const arch = pe.is64 ? "x86-64" : "x86";
  const entry = `0x${(pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase()}`;
  const subsystem = pe.optionalHeader.subsystem;
  const subsystemName =
    subsystem === 1
      ? "NATIVE"
      : subsystem === 2
        ? "WINDOWS_GUI"
        : subsystem === 3
          ? "WINDOWS_CUI"
          : `${subsystem}`;

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
    if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) flags.push("X");
    if (s.characteristics & IMAGE_SCN_MEM_READ) flags.push("R");
    if (s.characteristics & IMAGE_SCN_MEM_WRITE) flags.push("W");
    ctx += `- ${name}: size=0x${s.virtualSize.toString(16)}, flags=${flags.join("")}\n`;
  }

  // Notable imports (top 50)
  ctx += "\n## Notable Imports\n";
  let importCount = 0;
  for (const imp of pe.imports) {
    for (const funcName of imp.functions) {
      if (importCount >= 50) break;
      if (matchesApi(NOTABLE_APIS, funcName)) {
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
      if (
        lower.includes("http") ||
        lower.includes("://") ||
        lower.includes("\\\\") ||
        lower.includes("hkey_") ||
        lower.includes("cmd") ||
        lower.includes(".exe") ||
        lower.includes(".dll") ||
        lower.includes("password") ||
        lower.includes("mutex") ||
        lower.includes("pipe") ||
        lower.includes("temp") ||
        lower.includes("appdata") ||
        (str.length > 10 && /[A-Z].*[a-z]|[a-z].*[A-Z]/.test(str))
      ) {
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

    // Abort the previous report before replacing the ref, so a re-generate does
    // not leave the earlier stream running and un-cancellable.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // Decompile key functions for report context
    const decompiled: { name: string; code: string }[] = [];
    const textSection = findCodeSection(pe.sections);

    if (textSection && state.functions.length > 0) {
      const entryVA = pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint;

      // Key functions: entry point, first few exports, highest-xref, largest
      const candidates: DisasmFunction[] = [];
      const entryFunc = state.functions.find((f) => f.address === entryVA);
      if (entryFunc) candidates.push(entryFunc);

      // Exports (up to 3)
      for (const exp of pe.exports.slice(0, 3)) {
        const addr = pe.optionalHeader.imageBase + exp.address;
        const fn = state.functions.find((f) => f.address === addr);
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
        const code = await decompileForLLM(fn, pe, state.functions, state.renames, {
          section: textSection,
          maxLines: MAX_REPORT_LINES_PER_FUNC,
        });
        if (code) {
          decompiled.push({ name: getDisplayName(fn, state.renames), code });
        }
      }
    }

    const context = buildReportContext(
      pe,
      state.fileName,
      state.functions,
      state.renames,
      state.anomalies,
      state.driverInfo,
      decompiled,
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
      "report",
    );
  }, [
    state.peFile,
    state.fileName,
    state.functions,
    state.renames,
    state.anomalies,
    state.driverInfo,
    dispatch,
  ]);

  const regenerateReport = useCallback(() => {
    if (state.fileName) {
      try {
        localStorage.removeItem(`peek-a-bin:report:${state.fileName}`);
      } catch {}
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
