/**
 * Guards the MCP test suite's import graph.
 *
 * `src/mcp/disasm.ts` calls `loadCapstone()` machinery at module scope, and
 * `src/mcp/session.ts` imports it for value. The MCP tests stay fast and stable
 * only because nothing they load ever reaches those two modules: `tools.ts` and
 * `resources.ts` import `./session` for TYPES ONLY, so the tool handlers can be
 * registered against a stub server without any WASM being fetched.
 *
 * That property is invisible at runtime — flipping one `import type` to a value
 * import still passes every other test, it just makes the suite slow and
 * flaky-in-CI. So it is asserted here, statically, against the source text.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const MCP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SRC_DIR = resolve(MCP_DIR, "..");

interface ImportRecord {
  /** The specifier as written, e.g. `./session`. */
  specifier: string;
  /** True for `import type … from …`, which TypeScript erases entirely. */
  typeOnly: boolean;
}

/** Strip comments so a `//`-quoted example import is not mistaken for a real one. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/** Every `import`/`export … from` in a file, in source order. */
function importsOf(filePath: string): ImportRecord[] {
  const source = stripComments(readFileSync(filePath, "utf-8"));
  const records: ImportRecord[] = [];

  // `import [type] … from 'x'` and `export [type] … from 'x'`.
  const fromRe = /\b(?:import|export)\s+(type\s+)?([^;]*?)\bfrom\s*['"]([^'"]+)['"]/g;
  for (const m of source.matchAll(fromRe)) {
    records.push({ specifier: m[3], typeOnly: Boolean(m[1]) });
  }
  // Bare side-effect imports: `import 'x'`.
  const bareRe = /\bimport\s*['"]([^'"]+)['"]/g;
  for (const m of source.matchAll(bareRe)) {
    records.push({ specifier: m[1], typeOnly: false });
  }
  return records;
}

/** Resolve a relative specifier to a file on disk, or null for a package import. */
function resolveLocal(fromFile: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) return null;
  const base = resolve(dirname(fromFile), specifier);
  for (const candidate of [`${base}.ts`, `${base}.tsx`, join(base, "index.ts")]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Every local module reachable from `entry` through VALUE imports, plus the
 * package specifiers encountered on the way.
 */
function valueClosure(entry: string): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const queue = [entry];

  while (queue.length > 0) {
    const file = queue.pop()!;
    if (files.has(file)) continue;
    files.add(file);

    for (const record of importsOf(file)) {
      if (record.typeOnly) continue;
      const local = resolveLocal(file, record.specifier);
      if (local === null) {
        if (!record.specifier.startsWith(".")) packages.add(record.specifier);
        continue;
      }
      queue.push(local);
    }
  }
  return { files, packages };
}

/** Paths relative to `src/`, for readable failure messages. */
function rel(files: Iterable<string>): string[] {
  return [...files].map((f) => relative(SRC_DIR, f)).sort();
}

describe("MCP import graph — session stays type-only", () => {
  it.each(["tools.ts", "resources.ts"])(
    "%s imports ./session for types only, keeping Capstone WASM out of the test graph",
    (fileName) => {
      const valueImports = importsOf(join(MCP_DIR, fileName)).filter(
        (r) => !r.typeOnly && /\.\/session$/.test(r.specifier),
      );

      expect(
        valueImports,
        `src/mcp/${fileName} value-imports './session'. That pulls in src/mcp/disasm.ts, which ` +
          `loads Capstone WASM at module scope, into every MCP test that registers handlers. ` +
          `Use "import type { … } from './session'" instead.`,
      ).toEqual([]);
    },
  );

  it("does not reach session.ts or disasm.ts from tools.ts or resources.ts", () => {
    const forbidden = [join(MCP_DIR, "session.ts"), join(MCP_DIR, "disasm.ts")];

    for (const entry of ["tools.ts", "resources.ts"]) {
      const { files } = valueClosure(join(MCP_DIR, entry));
      const reached = forbidden.filter((f) => files.has(f));

      expect(
        rel(reached),
        `src/mcp/${entry} now transitively value-imports ${rel(reached).join(", ")}. ` +
          `Something in its import chain switched from "import type" to a value import.`,
      ).toEqual([]);
    }
  });

  it("never reaches capstone-wasm from tools.ts or resources.ts", () => {
    for (const entry of ["tools.ts", "resources.ts"]) {
      const { packages } = valueClosure(join(MCP_DIR, entry));
      expect(
        [...packages].filter((p) => p.includes("capstone")),
        `src/mcp/${entry} now pulls capstone-wasm into the module graph.`,
      ).toEqual([]);
    }
  });
});

describe("MCP import graph — paths.ts stays dependency-free", () => {
  it("imports nothing but node builtins", () => {
    const specifiers = importsOf(join(MCP_DIR, "paths.ts")).map((r) => r.specifier);
    const nonBuiltin = specifiers.filter((s) => !s.startsWith("node:"));

    expect(
      nonBuiltin,
      `src/mcp/paths.ts must stay dependency-free so its tests import only path logic; ` +
        `found: ${nonBuiltin.join(", ")}`,
    ).toEqual([]);
  });

  it("has an empty local import closure", () => {
    const { files } = valueClosure(join(MCP_DIR, "paths.ts"));
    expect(rel(files)).toEqual(["mcp/paths.ts"]);
  });
});

describe("MCP import graph — helper tests call the helpers directly", () => {
  it.each(["parseAddr.test.ts", "exportPath.test.ts"])(
    "%s does not go through the tool-registration harness",
    (fileName) => {
      const specifiers = importsOf(join(MCP_DIR, "__tests__", fileName)).map((r) => r.specifier);

      expect(
        specifiers.filter((s) => s.includes("harness") || s.includes("../tools")),
        `src/mcp/__tests__/${fileName} is a unit test for src/mcp/paths.ts; it should import ` +
          `the helper directly rather than registering every MCP tool to reach it. ` +
          `Handler-level coverage belongs in tools.test.ts.`,
      ).toEqual([]);
    },
  );
});

describe("import parser — self-check", () => {
  it("distinguishes type-only from value imports", () => {
    const records = importsOf(join(MCP_DIR, "tools.ts"));
    const bySpecifier = new Map(records.map((r) => [r.specifier, r]));

    expect(bySpecifier.get("./session")?.typeOnly).toBe(true);
    expect(bySpecifier.get("./paths")?.typeOnly).toBe(false);
    expect(bySpecifier.get("node:fs")?.typeOnly).toBe(false);
  });
});
