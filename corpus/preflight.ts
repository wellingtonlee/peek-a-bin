/**
 * Where the corpus lives, and whether this machine can run the audits at all.
 *
 * The binaries are real MSVC output and are deliberately NOT in the repo — they
 * are third-party executables, and a disassembler's test corpus is exactly the
 * kind of thing that should not be vendored. So every entry point has to answer
 * "can I run?" before it answers anything else, and answer it by *name*: a
 * caller who gets "skipped" without being told which file was missing and where
 * it was looked for has been told nothing.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

/**
 * The default corpus: pip's vendored `distlib` launchers, as installed in a
 * virtualenv on the machine this project was developed on. Four real MSVC
 * binaries — t32/w32 are PE32, t64/w64 are PE32+ — which is why they are the
 * corpus: between them they cover both widths, both subsystems, SEH, jump
 * tables and hot-patched prologues.
 *
 * Override with PEEK_CORPUS_DIR to point at any directory holding files of
 * these names, or set PEEK_CORPUS_BINS to audit a subset.
 */
export const DEFAULT_CORPUS_DIR =
  "/home/jacob/silver-carnival-demo/.venv/lib/python3.12/site-packages/pip/_vendor/distlib";

/** The four binaries the standing numbers in CLAUDE.md are measured against. */
export const ALL_BINS = ["t32", "t64", "w64", "w32"] as const;

/**
 * The three the documented gcc and offsetof figures use. w32 was added later
 * and is audited too, but it is not in the historical denominators — so a
 * comparison against a number in CLAUDE.md has to use this set, not ALL_BINS.
 */
export const DOC_BINS = ["t32", "t64", "w64"] as const;

export type BinKey = (typeof ALL_BINS)[number];

export function corpusDir(): string {
  return process.env.PEEK_CORPUS_DIR ?? DEFAULT_CORPUS_DIR;
}

export function requestedBins(): BinKey[] {
  const raw = process.env.PEEK_CORPUS_BINS;
  if (!raw) return [...ALL_BINS];
  const want = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const bad = want.filter((w) => !(ALL_BINS as readonly string[]).includes(w));
  if (bad.length > 0) {
    throw new Error(
      `PEEK_CORPUS_BINS names ${bad.join(", ")}, which is not one of ${ALL_BINS.join(", ")}`,
    );
  }
  return want as BinKey[];
}

export function binPath(key: BinKey): string {
  return join(corpusDir(), `${key}.exe`);
}

/**
 * CROSS-SUBSTITUTION. A directory of `jumpTables_<key>.json` artifacts from
 * ANOTHER run, to be used in place of the ones this commit's detection found.
 *
 * This is the experiment that decides "did my change cause this, or merely
 * reveal it": hand one commit's decompiler another commit's recovered tables,
 * and see whether the emitted C moves. At `peek-a-bin-qzrl` it settled the
 * question — the base decompiler, given the change's tables, emitted
 * byte-identical C including every defect, which proved the defects predated
 * the change and were only exposed by it.
 *
 * What it substitutes is ONLY the jump tables. The instruction stream still
 * comes from this commit's own detection and disassembly. That is the point —
 * it isolates the tables as the single variable — but it means a null result
 * says "the tables are not the cause", not "nothing about detection is".
 */
export function substitutedTablesDir(): string | null {
  return process.env.PEEK_CORPUS_TABLES ?? null;
}

export interface Preflight {
  /** Every requested binary is present. */
  haveBins: boolean;
  /** A C compiler that answers `--version` is on PATH. */
  haveCc: boolean;
  /** The compiler to invoke; `CC` overrides, default gcc. */
  cc: string;
  present: BinKey[];
  missing: string[];
  /** One line naming what is missing and where it was looked for, or "". */
  reason: string;
}

export function preflight(): Preflight {
  let bins: BinKey[];
  try {
    bins = requestedBins();
  } catch (e) {
    return {
      haveBins: false,
      haveCc: false,
      cc: "",
      present: [],
      missing: [],
      reason: String(e instanceof Error ? e.message : e),
    };
  }
  const present: BinKey[] = [];
  const missing: string[] = [];
  for (const b of bins) {
    if (existsSync(binPath(b))) present.push(b);
    else missing.push(binPath(b));
  }

  const cc = process.env.CC ?? "gcc";
  let haveCc = false;
  try {
    execFileSync(cc, ["--version"], { stdio: "pipe" });
    haveCc = true;
  } catch {
    haveCc = false;
  }

  const parts: string[] = [];
  if (missing.length > 0) {
    parts.push(
      `${missing.length} of ${bins.length} corpus binaries not found: ${missing.join(", ")}` +
        ` (corpus dir ${corpusDir()}; set PEEK_CORPUS_DIR to relocate, PEEK_CORPUS_BINS to subset)`,
    );
  }
  if (!haveCc) {
    parts.push(`no C compiler: '${cc} --version' failed (set CC to name another)`);
  }

  return {
    haveBins: missing.length === 0,
    haveCc,
    cc,
    present,
    missing,
    reason: parts.join("; "),
  };
}
