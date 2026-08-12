/**
 * Drift guard: the corpus audits must stay out of `npm test`.
 *
 * They need real PE binaries that are deliberately not in the repo, and a C
 * compiler. If one of them ever lands under a name vitest's DEFAULT include
 * matches — `*.test.ts` or `*.spec.ts` — then every CI run, on every machine,
 * starts trying to disassemble files it does not have. That failure is loud but
 * it is also entirely avoidable, and it would be introduced by something as
 * ordinary as copying an existing test file to start a new audit.
 *
 * This reads the directory rather than importing anything from it: importing a
 * corpus module would pull in `mcp/session` and load Capstone WASM into the
 * ordinary suite, which is the other thing we are trying not to do.
 */
import { readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const corpusDir = fileURLToPath(new URL("../corpus", import.meta.url));

// Vitest's default include, as of vitest 4, matches any file whose name ends
// ".test" or ".spec" followed by a js/ts extension, optionally c- or m-prefixed.
const DEFAULT_INCLUDE = /\.(test|spec)\.(c|m)?[jt]sx?$/;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    // Artifacts are generated output and are gitignored; a run writes .c files
    // in there and we have no interest in their names.
    if (entry === "artifacts" || entry === "node_modules") continue;
    const full = `${dir}/${entry}`;
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe("corpus audits stay out of npm test", () => {
  const files = walk(corpusDir).map((f) => f.slice(corpusDir.length + 1));

  it("has audits to guard in the first place", () => {
    expect(files.filter((f) => f.endsWith(".audit.ts")).length).toBeGreaterThan(0);
  });

  it("names no file so that vitest's default include would run it", () => {
    const offenders = files.filter((f) => DEFAULT_INCLUDE.test(f));
    expect(
      `corpus files matching vitest's default include: ${offenders.join(", ")}`,
    ).toBe("corpus files matching vitest's default include: ");
  });

  it("keeps a dedicated config that names them", () => {
    const raw = readdirSync(fileURLToPath(new URL("..", import.meta.url)));
    expect(raw).toContain("vitest.corpus.config.ts");
  });
});
