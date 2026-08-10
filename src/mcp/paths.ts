/**
 * Path and address helpers for the MCP tool layer.
 *
 * These live outside `tools.ts` so tests can exercise them directly instead of
 * driving a whole tool invocation. Keep this module dependency-free: it must not
 * import `./session` (or anything reaching it), because `./session` pulls in
 * `./disasm`, which loads Capstone WASM at module scope. `importGraph.test.ts`
 * enforces that.
 */

import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, extname, resolve, sep } from "node:path";

/**
 * Parse a tool `address` argument. Hex strings may carry an optional `0x` prefix.
 * Returns null for anything that would otherwise become NaN and surface as `0xNaN`.
 */
export function parseAddr(address: number | string): number | null {
  if (typeof address === "number") {
    return Number.isFinite(address) ? address : null;
  }
  const n = parseInt(address.trim(), 16);
  return Number.isNaN(n) ? null : n;
}

/**
 * Confine `export_analysis` writes to a single root: `PEEK_A_BIN_EXPORT_DIR` if set,
 * otherwise the process working directory. Requires a `.json` extension and rejects
 * traversal (including via symlinked parent directories) outside that root.
 */
export function resolveExportPath(outputPath: string): { path: string } | { error: string } {
  const configured = process.env.PEEK_A_BIN_EXPORT_DIR;
  const rootRaw = resolve(configured || process.cwd());
  let root: string;
  try {
    root = realpathSync(rootRaw);
  } catch {
    return { error: `export root does not exist: ${rootRaw}` };
  }

  const target = resolve(root, outputPath);
  if (extname(target).toLowerCase() !== ".json") {
    return { error: `outputPath must end in .json (got "${outputPath}")` };
  }

  // The parent directory must already exist; resolving it defeats symlink escapes.
  let realDir: string;
  try {
    realDir = realpathSync(dirname(target));
  } catch {
    return { error: `output directory does not exist: ${dirname(target)}` };
  }

  const contained = realDir === root || realDir.startsWith(root + sep);
  if (!contained) {
    return {
      error:
        `outputPath escapes the allowed export directory "${root}". ` +
        `Set PEEK_A_BIN_EXPORT_DIR to write elsewhere.`,
    };
  }

  const finalPath = resolve(realDir, basename(target));

  // Resolving the parent is not enough: the FINAL component can itself be a
  // symlink that writeFileSync would follow straight out of the root. lstat does
  // not follow it, so we can detect and refuse that case. (An attacker needs to
  // pre-plant the link inside the export directory, but the whole point of this
  // function is that a path under the root cannot redirect the write elsewhere.)
  try {
    if (lstatSync(finalPath).isSymbolicLink()) {
      return {
        error:
          `outputPath "${basename(target)}" is a symlink; refusing to follow it out of ` +
          `the export directory. Remove it or choose another name.`,
      };
    }
  } catch {
    // ENOENT is the normal case — the file does not exist yet.
  }

  return { path: finalPath };
}
