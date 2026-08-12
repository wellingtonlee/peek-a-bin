/**
 * Every caller of the typed xref map states where the image is.
 *
 * `buildTypedXrefMap`'s fallback arm reads any large `0x…` token in an operand
 * as a data reference — bitmasks, sentinels and status constants included — and
 * an optional `imageBounds` bounds it (peek-a-bin-jfp). The bound was
 * implemented, tested and then reachable from no caller at all, so the shipped
 * behaviour did not move by a single xref (peek-a-bin-2ap): a fix that nothing
 * calls is indistinguishable from no fix.
 *
 * A drift guard over the *tree* rather than over a list of files, because that
 * is the failure this reproduces. A new call site added anywhere in `src/` that
 * omits the bounds fails here; naming today's five callers would not catch
 * tomorrow's sixth.
 *
 * The parameter stays optional on purpose — "nobody said where the image is" is
 * not the claim "everything is in range" — so the type system cannot ask this
 * question, and nothing else does.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

/** Every non-test source file under `src/`. */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry !== "__tests__") sourceFiles(path, out);
    } else if (/\.tsx?$/.test(entry)) {
      out.push(path);
    }
  }
  return out;
}

/** Comments stripped and whitespace flattened: a guard that a reformat breaks
 *  is worse than no guard, and a mention inside a comment is not a call. */
function flatSource(path: string): string {
  return readFileSync(path, "utf-8")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/\s+/g, " ");
}

/**
 * The top-level arguments of every call to `name` in `text`, skipping the
 * declarations of `name` itself (`function name(`, `async name(`).
 */
function callArguments(text: string, name: string): string[][] {
  const calls: string[][] = [];
  const finder = new RegExp(`(\\w+\\s+)?${name}\\s*\\(`, "g");
  for (let m = finder.exec(text); m !== null; m = finder.exec(text)) {
    const preceding = (m[1] ?? "").trim();
    if (preceding === "function" || preceding === "async") continue;
    let depth = 0;
    let quote: string | null = null;
    let arg = "";
    const args: string[] = [];
    for (let i = m.index + m[0].length - 1; i < text.length; i++) {
      const c = text[i];
      if (quote) {
        if (c === quote) quote = null;
        arg += c;
        continue;
      }
      if (c === '"' || c === "'" || c === "`") quote = c;
      if (c === "(" || c === "[" || c === "{") depth++;
      else if (c === ")" || c === "]" || c === "}") {
        depth--;
        if (depth === 0) {
          if (arg.trim()) args.push(arg.trim());
          break;
        }
      } else if (c === "," && depth === 1) {
        args.push(arg.trim());
        arg = "";
        continue;
      }
      if (!(depth === 1 && arg === "" && c === "(")) arg += c;
    }
    calls.push(args);
  }
  return calls;
}

/** `[relative file, arguments]` for every call to either entry point. */
function xrefMapCalls(): [string, string[]][] {
  const found: [string, string[]][] = [];
  for (const path of sourceFiles(SRC)) {
    const text = flatSource(path);
    for (const name of ["buildTypedXrefMap", "buildXrefMap"]) {
      for (const args of callArguments(text, name)) {
        found.push([relative(SRC, path), args]);
      }
    }
  }
  return found;
}

describe("nothing builds a typed xref map without saying where the image is", () => {
  const calls = xrefMapCalls();

  it("finds the call sites at all", () => {
    // If this drops to nothing the sweep below passes vacuously — which is
    // exactly the state the bug shipped in.
    expect(calls.length).toBeGreaterThanOrEqual(5);
    const files = new Set(calls.map(([file]) => file));
    for (const expected of [
      "mcp/disasm.ts",
      "mcp/session.ts",
      "workers/dispatch.ts",
      "hooks/useDisassemblyRows.ts",
      "llm/decompileForLLM.ts",
    ]) {
      expect(files, `${expected} should still call the xref map builder`).toContain(expected);
    }
  });

  it.each(calls.map(([file, args]) => [file, args] as const))(
    "%s passes the image bounds (%o)",
    (file, args) => {
      expect(
        args.length >= 2,
        `${file} calls the typed xref map builder with only the instructions. Every large ` +
          "0x… token in an operand then becomes a data reference, including bitmasks and " +
          "NTSTATUS constants: 305 references to addresses outside the image on t64.exe " +
          "alone. Pass { base: imageBase, size: sizeOfImage } (peek-a-bin-2ap).",
      ).toBe(true);
    },
  );
});
