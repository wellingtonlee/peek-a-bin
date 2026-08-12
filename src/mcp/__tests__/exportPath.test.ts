/**
 * Export-path confinement, tested directly against `resolveExportPath`.
 *
 * The MCP server writes files on behalf of a model, so `outputPath` is
 * attacker-influenced input. This suite asserts the DECISION (which absolute
 * path, if any, the tool is allowed to write); the end-to-end counterpart in
 * `exportAnalysis.test.ts` asserts the OUTCOME on disk — that no file appears
 * outside the export root.
 */

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveExportPath } from "../paths";

let root: string;
let outside: string;
let sibling: string;
const savedExportDir = process.env.PEEK_A_BIN_EXPORT_DIR;

/** The resolved path of an accepted result; fails loudly on a rejection. */
function acceptedPath(result: ReturnType<typeof resolveExportPath>): string {
  if ("error" in result) throw new Error(`expected acceptance, got: ${result.error}`);
  return result.path;
}

/** The message of a rejected result; fails loudly on an acceptance. */
function rejection(result: ReturnType<typeof resolveExportPath>): string {
  if ("path" in result) throw new Error(`expected rejection, got path: ${result.path}`);
  return result.error;
}

beforeEach(() => {
  // realpathSync: /tmp is a symlink on some platforms, and the confinement check
  // compares against the resolved root.
  root = realpathSync(mkdtempSync(join(tmpdir(), "peek-export-root-")));
  outside = realpathSync(mkdtempSync(join(tmpdir(), "peek-export-outside-")));
  // Shares a string prefix with `root`, so a naive startsWith() would admit it.
  sibling = `${root}-sibling`;
  mkdirSync(sibling, { recursive: true });

  process.env.PEEK_A_BIN_EXPORT_DIR = root;
});

afterEach(() => {
  if (savedExportDir === undefined) delete process.env.PEEK_A_BIN_EXPORT_DIR;
  else process.env.PEEK_A_BIN_EXPORT_DIR = savedExportDir;
  for (const dir of [root, outside, sibling]) rmSync(dir, { recursive: true, force: true });
});

describe("resolveExportPath — accepted", () => {
  it("resolves a relative .json name against the export root", () => {
    expect(acceptedPath(resolveExportPath("analysis.json"))).toBe(join(root, "analysis.json"));
  });

  it("resolves into an existing subdirectory of the export root", () => {
    mkdirSync(join(root, "reports"));
    expect(acceptedPath(resolveExportPath("reports/out.json"))).toBe(
      join(root, "reports", "out.json"),
    );
  });

  it("accepts an absolute path that lands inside the export root", () => {
    const target = join(root, "absolute.json");
    expect(acceptedPath(resolveExportPath(target))).toBe(target);
  });

  it("accepts .JSON case-insensitively", () => {
    expect(acceptedPath(resolveExportPath("Analysis.JSON"))).toBe(join(root, "Analysis.JSON"));
  });

  it("normalizes ../ that stays inside the root", () => {
    mkdirSync(join(root, "reports"));
    expect(acceptedPath(resolveExportPath("reports/../back.json"))).toBe(join(root, "back.json"));
  });

  it("accepts overwriting an existing regular file", () => {
    const target = join(root, "existing.json");
    writeFileSync(target, "{}");
    expect(acceptedPath(resolveExportPath("existing.json"))).toBe(target);
  });

  it("resolves through a symlinked directory that stays inside the root", () => {
    mkdirSync(join(root, "real"));
    symlinkSync(join(root, "real"), join(root, "alias"), "dir");
    // The returned path is the REAL location, not the aliased one.
    expect(acceptedPath(resolveExportPath("alias/out.json"))).toBe(join(root, "real", "out.json"));
  });
});

describe("resolveExportPath — rejected", () => {
  it("rejects ../ traversal", () => {
    expect(rejection(resolveExportPath("../escaped.json"))).toMatch(
      /escapes the allowed export directory/,
    );
  });

  it("rejects deep ../../ traversal", () => {
    expect(rejection(resolveExportPath("../../../../etc/peek.json"))).toMatch(
      /escapes|does not exist/,
    );
  });

  it("rejects an absolute path outside the root", () => {
    expect(rejection(resolveExportPath(join(outside, "stolen.json")))).toMatch(
      /escapes the allowed export directory/,
    );
  });

  it("rejects a sibling directory that merely shares the root name prefix", () => {
    // `${root}-sibling` startsWith(root); only a separator-aware check rejects it.
    expect(rejection(resolveExportPath(join(sibling, "prefix.json")))).toMatch(
      /escapes the allowed export directory/,
    );
  });

  it("rejects a symlinked directory inside the root that points outside it", () => {
    symlinkSync(outside, join(root, "link"), "dir");
    expect(rejection(resolveExportPath("link/via-symlink.json"))).toMatch(
      /escapes the allowed export directory/,
    );
  });

  // Regression: resolveExportPath used to realpath only the PARENT directory, so a
  // symlinked FILE pre-planted inside the export root redirected writeFileSync out
  // of the root while the tool reported success. Confirmed end-to-end against the
  // real MCP server before the lstat check was added.
  it("rejects a symlinked FILE inside the root that points outside it", () => {
    symlinkSync(join(outside, "target.json"), join(root, "out.json"));
    expect(rejection(resolveExportPath("out.json"))).toMatch(/symlink/);
  });

  it("rejects a symlinked FILE inside the root even when it points back inside", () => {
    // The check refuses to follow the final component at all, rather than trying
    // to reason about where a dangling or re-pointed link lands.
    symlinkSync(join(root, "real.json"), join(root, "inner-link.json"));
    expect(rejection(resolveExportPath("inner-link.json"))).toMatch(/symlink/);
  });

  it("rejects a non-.json extension", () => {
    expect(rejection(resolveExportPath("analysis.txt"))).toMatch(/must end in \.json/);
  });

  it("rejects an extensionless path", () => {
    expect(rejection(resolveExportPath("analysis"))).toMatch(/must end in \.json/);
  });

  it("rejects a .json suffix that is only part of the filename", () => {
    expect(rejection(resolveExportPath("analysis.json.sh"))).toMatch(/must end in \.json/);
  });

  it("rejects a directory that does not exist rather than creating it", () => {
    expect(rejection(resolveExportPath("missing/out.json"))).toMatch(
      /output directory does not exist/,
    );
  });

  it("errors when the configured export root does not exist", () => {
    process.env.PEEK_A_BIN_EXPORT_DIR = join(outside, "no-such-dir");
    expect(rejection(resolveExportPath("out.json"))).toMatch(/export root does not exist/);
  });

  it("names the resolved root in the escape error so the caller can fix it", () => {
    const message = rejection(resolveExportPath(join(outside, "x.json")));
    expect(message).toContain(root);
    expect(message).toContain("PEEK_A_BIN_EXPORT_DIR");
  });
});

describe("resolveExportPath — default export root", () => {
  it("falls back to cwd when PEEK_A_BIN_EXPORT_DIR is unset", () => {
    delete process.env.PEEK_A_BIN_EXPORT_DIR;
    expect(acceptedPath(resolveExportPath("cwd-relative.json"))).toBe(
      resolve(realpathSync(process.cwd()), "cwd-relative.json"),
    );
  });

  it("still rejects paths outside cwd", () => {
    delete process.env.PEEK_A_BIN_EXPORT_DIR;
    expect(rejection(resolveExportPath(join(outside, "cwd-escape.json")))).toMatch(
      /escapes the allowed export directory/,
    );
  });

  it("treats an empty PEEK_A_BIN_EXPORT_DIR as unset", () => {
    process.env.PEEK_A_BIN_EXPORT_DIR = "";
    expect(acceptedPath(resolveExportPath("empty-env.json"))).toBe(
      resolve(realpathSync(process.cwd()), "empty-env.json"),
    );
  });

  it("resolves a relative PEEK_A_BIN_EXPORT_DIR against cwd", () => {
    // dirname(root) is absolute; use a relative spelling of an existing dir.
    process.env.PEEK_A_BIN_EXPORT_DIR = ".";
    expect(acceptedPath(resolveExportPath("relative-root.json"))).toBe(
      resolve(realpathSync(process.cwd()), "relative-root.json"),
    );
    expect(rejection(resolveExportPath(join(dirname(root), "nope.json")))).toMatch(
      /escapes the allowed export directory/,
    );
  });
});
