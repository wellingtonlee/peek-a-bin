/**
 * Test harness for the MCP tool layer.
 *
 * `registerTools` is the only export of `src/mcp/tools.ts`, so reaching a tool's
 * behaviour means registering it: this captures the handlers `registerTools`
 * hands to the server and calls them directly.
 *
 * Prefer NOT to route a test through here when the logic under test is a plain
 * helper — `parseAddr` and `resolveExportPath` now live in `src/mcp/paths.ts`
 * and are imported directly by their suites, which keeps them off the whole tool
 * import graph. `importGraph.test.ts` holds that line.
 *
 * Caveat: the captured handlers are invoked WITHOUT the zod schema that the real
 * McpServer applies, so these tests exercise handler logic, not argument
 * validation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AnalyzedFile, FileSession } from "../session";
import { registerTools } from "../tools";

export type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

export type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

/** Register the real tools against a stub server and return their handlers. */
export function captureTools(session: FileSession): Map<string, ToolHandler> {
  const handlers = new Map<string, ToolHandler>();
  const server = {
    tool(name: string, _description: string, _schema: unknown, handler: ToolHandler) {
      handlers.set(name, handler);
    },
  } as unknown as McpServer;

  registerTools(server, session);
  return handlers;
}

/** Calls recorded by {@link stubSession}, so tests can assert on side effects. */
export interface SessionCalls {
  setComment: [string, number, string][];
  deleteComment: [string, number][];
  setRename: [string, number, string][];
  deleteRename: [string, number][];
  addBookmark: [string, number, string][];
  removeBookmark: [string, number][];
  annotationChanges: string[];
}

/**
 * A FileSession stub holding exactly one analyzed file, with every mutator
 * recorded. Only the fields the tool handlers touch are populated.
 */
export function stubSession(overrides: Partial<AnalyzedFile> = {}): {
  session: FileSession;
  file: AnalyzedFile;
  calls: SessionCalls;
} {
  const file = {
    id: "sample",
    fileName: "sample.exe",
    // Spelled out rather than left undefined: the x86-only tools now decline on
    // anything that is not "x86", so a stub that omits this would be refused —
    // which is the right direction for a forgotten field, but makes for
    // confusing failures in suites that are not about architecture at all.
    arch: "x86",
    functions: [],
    instructions: [],
    xrefMap: new Map(),
    // The whole-image xref maps `FileSession.loadFile` now builds. Empty rather
    // than absent: the handlers read them unconditionally, exactly as they read
    // `xrefMap`, and a stub that left them undefined would fail every unrelated
    // suite with a TypeError rather than an empty answer.
    stringXrefs: new Map(),
    importXrefs: new Map(),
    dataXrefs: new Map(),
    callGraph: new Map(),
    stringMap: new Map(),
    iatMap: new Map(),
    stringTypes: new Map(),
    anomalies: [],
    bookmarks: [],
    renames: {},
    comments: {},
    ...overrides,
  } as unknown as AnalyzedFile;

  const calls: SessionCalls = {
    setComment: [],
    deleteComment: [],
    setRename: [],
    deleteRename: [],
    addBookmark: [],
    removeBookmark: [],
    annotationChanges: [],
  };

  const session = {
    getFile: (id: string) => (id === file.id ? file : undefined),
    listFiles: () => [{ id: file.id, fileName: file.fileName }],
    setComment: (f: string, a: number, t: string) => {
      calls.setComment.push([f, a, t]);
      return true;
    },
    deleteComment: (f: string, a: number) => {
      calls.deleteComment.push([f, a]);
      return true;
    },
    setRename: (f: string, a: number, n: string) => {
      calls.setRename.push([f, a, n]);
      return true;
    },
    deleteRename: (f: string, a: number) => {
      calls.deleteRename.push([f, a]);
      return true;
    },
    addBookmark: (f: string, a: number, l: string) => {
      calls.addBookmark.push([f, a, l]);
      return true;
    },
    removeBookmark: (f: string, a: number) => {
      calls.removeBookmark.push([f, a]);
      return true;
    },
    onAnnotationChange: (f: string) => {
      calls.annotationChanges.push(f);
    },
  } as unknown as FileSession;

  return { session, file, calls };
}

/** The single text payload of a tool result. */
export function textOf(result: ToolResult): string {
  return result.content.map((c) => c.text).join("\n");
}
