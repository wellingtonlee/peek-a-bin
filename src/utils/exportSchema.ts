import type { AppState } from "../hooks/usePEFile";

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
