import type { AppState } from "../hooks/usePEFile";
import { getDisplayName } from "../hooks/usePEFile";

export interface ExportSchemaV1 {
  version: 1;
  fileName: string;
  exportedAt: string;
  bookmarks: { address: number; label: string }[];
  renames: Record<string, string>;
  comments: Record<string, string>;
  hexPatches: [number, number][];
  functions?: { address: number; name: string; size: number }[];
}

export function serializeState(state: AppState): ExportSchemaV1 {
  const hexPatches: [number, number][] = [];
  for (const [offset, value] of state.hexPatches) {
    hexPatches.push([offset, value]);
  }

  const result: ExportSchemaV1 = {
    version: 1,
    fileName: state.fileName ?? "",
    exportedAt: new Date().toISOString(),
    bookmarks: state.bookmarks.map((b) => ({ address: b.address, label: b.label })),
    renames: state.renames as Record<string, string>,
    comments: state.comments as Record<string, string>,
    hexPatches,
  };

  if (state.functions.length > 0) {
    result.functions = state.functions.map((f) => ({
      address: f.address,
      name: f.name,
      size: f.size,
    }));
  }

  return result;
}

export function validateImport(data: unknown): ExportSchemaV1 | null {
  if (typeof data !== "object" || data === null) return null;

  const obj = data as Record<string, unknown>;

  // Legacy format: has bookmarks but no version field
  if (!("version" in obj) && "bookmarks" in obj) return null;

  if (obj.version !== 1) return null;

  // Validate required fields
  if (typeof obj.fileName !== "string") return null;
  if (typeof obj.exportedAt !== "string") return null;
  if (!Array.isArray(obj.bookmarks)) return null;
  if (typeof obj.renames !== "object" || obj.renames === null) return null;
  if (typeof obj.comments !== "object" || obj.comments === null) return null;
  if (!Array.isArray(obj.hexPatches)) return null;

  // Validate bookmarks
  for (const b of obj.bookmarks) {
    if (typeof b !== "object" || b === null) return null;
    if (typeof (b as Record<string, unknown>).address !== "number") return null;
    if (typeof (b as Record<string, unknown>).label !== "string") return null;
  }

  // Validate hexPatches: each must be [number, number] with value 0-255
  for (const entry of obj.hexPatches) {
    if (!Array.isArray(entry) || entry.length !== 2) return null;
    if (typeof entry[0] !== "number" || typeof entry[1] !== "number") return null;
    if (entry[1] < 0 || entry[1] > 255) return null;
  }

  // Validate optional functions
  if ("functions" in obj && obj.functions !== undefined) {
    if (!Array.isArray(obj.functions)) return null;
    for (const f of obj.functions) {
      if (typeof f !== "object" || f === null) return null;
      const fn = f as Record<string, unknown>;
      if (typeof fn.address !== "number" || typeof fn.name !== "string" || typeof fn.size !== "number") return null;
    }
  }

  return data as ExportSchemaV1;
}

export function generateMarkdownReport(state: AppState): string {
  const lines: string[] = [];
  const pe = state.peFile;
  const arch = pe?.is64 ? "x64" : "x86";
  const timestamp = new Date().toISOString();

  // Header
  lines.push(`# Analysis Report: ${state.fileName ?? "Unknown"}`);
  lines.push("");
  lines.push(`- **Architecture**: ${arch}`);
  lines.push(`- **Generated**: ${timestamp}`);
  lines.push("");

  // Summary table
  const importCount = pe?.imports.reduce((sum, imp) => sum + imp.functions.length, 0) ?? 0;
  const stringCount = pe?.strings.size ?? 0;
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("|--------|-------|");
  lines.push(`| Functions | ${state.functions.length} |`);
  lines.push(`| Imports | ${importCount} |`);
  lines.push(`| Exports | ${pe?.exports.length ?? 0} |`);
  lines.push(`| Strings | ${stringCount} |`);
  lines.push(`| Anomalies | ${state.anomalies?.length ?? 0} |`);
  lines.push("");

  // Anomalies
  if (state.anomalies?.length) {
    lines.push("## Anomalies");
    lines.push("");
    lines.push("| Severity | Title | Detail |");
    lines.push("|----------|-------|--------|");
    for (const a of state.anomalies) {
      lines.push(`| ${a.severity} | ${a.title} | ${a.detail} |`);
    }
    lines.push("");
  }

  // Driver info
  if (state.driverInfo) {
    lines.push("## Driver Info");
    lines.push("");
    lines.push(`- **Type**: ${state.driverInfo.isWDM ? "WDM" : "Native"} driver`);
    lines.push(`- **Kernel modules**: ${state.driverInfo.kernelModules.join(", ") || "None"}`);
    lines.push(`- **Kernel API count**: ${state.driverInfo.kernelImportCount}`);
    if (state.driverInfo.reasons.length > 0) {
      lines.push(`- **Detection reasons**: ${state.driverInfo.reasons.join("; ")}`);
    }
    if (state.irpHandlers.length > 0) {
      lines.push("");
      lines.push("### IRP Dispatch");
      lines.push("");
      lines.push("| IRP Major | Name | Handler Address |");
      lines.push("|-----------|------|-----------------|");
      for (const h of state.irpHandlers) {
        lines.push(`| ${h.irpMajor} | ${h.irpName} | 0x${h.handlerAddress.toString(16).toUpperCase()} |`);
      }
    }
    lines.push("");
  }

  // Functions
  if (state.functions.length > 0) {
    lines.push("## Functions");
    lines.push("");
    lines.push("| Address | Name | Size |");
    lines.push("|---------|------|------|");
    for (const fn of state.functions) {
      const name = getDisplayName(fn, state.renames);
      lines.push(`| 0x${fn.address.toString(16).toUpperCase()} | ${name} | ${fn.size} |`);
    }
    lines.push("");
  }

  // Imports
  if (pe && pe.imports.length > 0) {
    lines.push("## Imports");
    lines.push("");
    for (const imp of pe.imports) {
      lines.push(`### ${imp.libraryName}`);
      lines.push("");
      for (const func of imp.functions) {
        lines.push(`- ${func}`);
      }
      lines.push("");
    }
  }

  // Exports
  if (pe && pe.exports.length > 0) {
    lines.push("## Exports");
    lines.push("");
    lines.push("| Ordinal | Name | Address |");
    lines.push("|---------|------|---------|");
    for (const exp of pe.exports) {
      lines.push(`| ${exp.ordinal} | ${exp.name} | 0x${exp.address.toString(16).toUpperCase()} |`);
    }
    lines.push("");
  }

  // Strings
  if (pe && pe.strings.size > 0) {
    lines.push("## Strings");
    lines.push("");
    lines.push("| Address | Value |");
    lines.push("|---------|-------|");
    for (const [addr, str] of pe.strings) {
      const truncated = str.length > 60 ? str.slice(0, 60) + "..." : str;
      // Escape pipe characters for markdown table
      const escaped = truncated.replace(/\|/g, "\\|");
      lines.push(`| 0x${addr.toString(16).toUpperCase()} | ${escaped} |`);
    }
    lines.push("");
  }

  // Bookmarks
  if (state.bookmarks.length > 0) {
    lines.push("## Bookmarks");
    lines.push("");
    lines.push("| Address | Label |");
    lines.push("|---------|-------|");
    for (const bm of state.bookmarks) {
      const label = bm.label || `0x${bm.address.toString(16).toUpperCase()}`;
      lines.push(`| 0x${bm.address.toString(16).toUpperCase()} | ${label} |`);
    }
    lines.push("");
  }

  // Comments
  const commentEntries = Object.entries(state.comments);
  if (commentEntries.length > 0) {
    lines.push("## Comments");
    lines.push("");
    lines.push("| Address | Comment |");
    lines.push("|---------|---------|");
    for (const [addr, text] of commentEntries) {
      const escaped = text.replace(/\|/g, "\\|");
      lines.push(`| 0x${Number(addr).toString(16).toUpperCase()} | ${escaped} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
