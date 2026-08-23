/**
 * `peek-a-bin-56q` item 1 — the architecture reaches the two x86-grammar
 * analyses that had never been told about it.
 *
 * `analyzeStackFrame` and `inferSignature` parse `[rbp - N]`, `[rsp + N]`,
 * `sub rsp, N` and a table of x86 register names. They were selected with
 * `is64` — the PE32+ optional-header magic, which is **true for an ARM64
 * image** — so on A64 they ran the x64 grammar over A64 operand text.
 * `inferSignature` then answered `{ convention: "fastcall", paramCount: 0 }`
 * for all 1033 detected functions of t64-arm.exe and w64-arm.exe (measured at
 * `cc70fe6`), which `InstructionDetail` renders.
 *
 * BOTH FUNCTIONS NOW TAKE `arch: ImageArch` AND THE TYPE SYSTEM ENFORCES IT, so
 * this suite is not about whether the parameter is passed — a missing or
 * boolean-valued argument fails `npm run typecheck`. It is about the one thing
 * the type cannot see: that a caller **derived** the architecture from the
 * image rather than asserting a literal `"x86"`, which would compile and would
 * reinstate the defect at that call site with nothing to notice it by.
 *
 * Asserted against source text for `arch.test.ts`'s reason — importing these
 * call sites would pull in React components and Capstone WASM — and written so
 * a reformat cannot break it: it matches identifiers, never layout.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Every `.ts`/`.tsx` under `src/`, excluding test directories. */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      if (entry !== "__tests__") sourceFiles(p, out);
    } else if (/\.tsx?$/.test(entry)) {
      out.push(p);
    }
  }
  return out;
}

/** The two x86 grammars, by the name a caller has to write to reach them. */
const X86_GRAMMARS = ["analyzeStackFrame", "inferSignature"];

/**
 * How a caller is allowed to have got the architecture: from the machine word
 * through the single interpreter, or from a value some other layer already
 * derived that way (`AnalyzedFile.arch`, `WorkerState.arch`).
 */
const DERIVES_ARCH = /archForMachine\s*\(|\barch\b\s*[,)]|\.arch\b/;

describe("the x86 stack and signature grammars are told which architecture they are for", () => {
  const callers = sourceFiles(SRC).filter((p) => {
    const text = readFileSync(p, "utf-8");
    // A call, not an import or a mention in prose: the name followed by `(`.
    // A module that *declares* one is not a caller of it — `stack.ts` and
    // `signatures.ts` are where the refusal lives, and they are the two files
    // that must not be asked to derive an architecture from an image they have
    // never seen.
    return X86_GRAMMARS.some(
      (fn) =>
        new RegExp(`\\b${fn}\\s*\\(`).test(text) &&
        !new RegExp(`export function ${fn}\\s*\\(`).test(text),
    );
  });

  it("finds the call sites at all", () => {
    // Liveness. A scrape that matches nothing reports a clean tree, so the
    // count is asserted before anything is asserted *about* it. Four production
    // callers existed when this was written; the floor is deliberately below
    // that so removing one is not a failure, while losing the scrape is.
    expect(
      callers.length,
      "no caller of the x86 stack/signature grammars found under src/",
    ).toBeGreaterThanOrEqual(2);
  });

  it("derives the architecture in every file that calls one", () => {
    for (const p of callers) {
      const rel = p.slice(SRC.length + 1);
      expect(
        readFileSync(p, "utf-8"),
        `${rel} calls analyzeStackFrame/inferSignature but never derives an architecture. ` +
          "Pass archForMachine(pe.coffHeader.machine), or an arch a caller already derived " +
          "that way — never a literal, which would run the x86 grammar over ARM64 operands " +
          "(peek-a-bin-56q item 1).",
      ).toMatch(DERIVES_ARCH);
    }
  });
});
