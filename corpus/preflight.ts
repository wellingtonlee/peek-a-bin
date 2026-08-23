/**
 * Where the corpus lives, and whether this machine can run the audits at all.
 *
 * The binaries are real MSVC output and are deliberately NOT in the repo — they
 * are third-party executables, and a disassembler's test corpus is exactly the
 * kind of thing that should not be vendored. So every entry point has to answer
 * "can I run?" before it answers anything else, and answer it by *name*: a
 * caller who gets "skipped" without being told which file was missing and where
 * it was looked for has been told nothing.
 *
 * THERE IS NO DEFAULT DIRECTORY, AND THAT IS THE POINT. This file used to carry
 * one — an absolute path inside a virtualenv on the machine the project was
 * developed on. That directory stopped existing, so the DEFAULT path became the
 * skip path: `npm run corpus` with nothing set did nothing on the machine the
 * project actually lives on, while the binaries sat two directories away, and
 * an agent that did not read the skip closely concluded the corpus could not be
 * run here at all. The verification existed and was not being run
 * (`peek-a-bin-alx1`). Replacing it with a different absolute path would trade
 * one machine's home directory for another's.
 *
 * What replaces it is a search over locations that are *conventional* rather
 * than personal — each derived from `$XDG_DATA_HOME`, `$HOME` or this repo —
 * plus the two ways of saying it outright:
 *
 *   1. `PEEK_CORPUS_DIR` in the environment          (this run only)
 *   2. `PEEK_CORPUS_DIR` in `.env` at the repo root  (this machine, durably)
 *   3. `$XDG_DATA_HOME/peek-a-bin-corpus`            (default `~/.local/share`)
 *   4. `~/.peek-a-bin-corpus`
 *   5. `<repo>/corpus/binaries`                      (gitignored)
 *
 * An explicit setting (1 or 2) is the WHOLE search: if you say where they are
 * and they are not there, the run reports that about the directory you named
 * and does not quietly succeed from somewhere else. Only when nothing is set do
 * the conventional locations get probed, and the skip then names every one of
 * them and what was wrong with it.
 *
 * `.env` is the durable half, and it is why documenting an `export` would not
 * have been enough on its own: a shell export has to be retyped by the next
 * shell, the next session and the next agent, where a gitignored line in `.env`
 * is written once per machine. `.env.example` documents the key.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The repo root — this file is `<root>/corpus/preflight.ts`. */
const REPO_ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");

/** The gitignored, per-machine settings file. `.env.example` documents it. */
export const ENV_FILE = join(REPO_ROOT, ".env");

/** The directory name looked for under `$XDG_DATA_HOME` and `$HOME`. */
export const CORPUS_DIR_NAME = "peek-a-bin-corpus";

/** The four binaries the standing numbers in CLAUDE.md are measured against. */
export const ALL_BINS = ["t32", "t64", "w64", "w32"] as const;

/**
 * The three the documented gcc and offsetof figures use. w32 was added later
 * and is audited too, but it is not in the historical denominators — so a
 * comparison against a number in CLAUDE.md has to use this set, not ALL_BINS.
 */
export const DOC_BINS = ["t32", "t64", "w64"] as const;

export type BinKey = (typeof ALL_BINS)[number];

/**
 * The two real ARM64 launchers, which {@link BinKey} deliberately does NOT
 * cover.
 *
 * They live in the same directory as the four x86 binaries and are found by the
 * same search, but they are kept out of `ALL_BINS` on purpose: `npm run corpus`
 * iterates over whatever `requestedBins()` names, so adding them there would
 * silently change the population of every gate and the denominator of every
 * figure in CLAUDE.md's Verification section — the same hazard that section
 * records for putting a Go binary in the corpus directory. Almost nothing in
 * that run has an ARM64 population anyway: the decompiler, the emitter and the
 * x86 operand grammars all refuse on ARM64 by design, so a folded-in ARM64 key
 * would contribute a dozen vacuous zeros.
 *
 * The ARM64 audits are therefore separately invoked — `npm run corpus:arm64`
 * and `npm run corpus:comments` — and this is the one declaration of which two
 * files they mean.
 */
export const ARM_BINS = ["t64-arm", "w64-arm"] as const;

export type ArmBinKey = (typeof ARM_BINS)[number];

/**
 * `.env`, parsed. Deliberately hand-rolled and deliberately tiny: this is one
 * key on a developer machine, not a reason to take a dependency, and nothing
 * else in the repo reads `.env` at runtime. Unparseable lines are ignored
 * rather than raised — a corpus harness must not fail for want of a corpus,
 * and that includes failing on the file that says where one is.
 */
function envFileValues(): Map<string, string> {
  const out = new Map<string, string>();
  let text: string;
  try {
    text = readFileSync(ENV_FILE, "utf8");
  } catch {
    return out;
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const body = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const eq = body.indexOf("=");
    if (eq <= 0) continue;
    const key = body.slice(0, eq).trim();
    let val = body.slice(eq + 1).trim();
    const quoted =
      val.length > 1 &&
      ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'")));
    if (quoted) val = val.slice(1, -1);
    out.set(key, val);
  }
  return out;
}

/** A value from the process environment; empty is treated as unset. */
function fromEnv(name: string): string | undefined {
  const v = process.env[name];
  return v !== undefined && v.trim() !== "" ? v.trim() : undefined;
}

/** A value from `.env`; empty is treated as unset. */
function fromEnvFile(name: string): string | undefined {
  const v = envFileValues().get(name);
  return v !== undefined && v.trim() !== "" ? v.trim() : undefined;
}

/**
 * `PEEK_CORPUS_*` and `CC` may be set in the environment or in `.env`, in that
 * order of precedence. A shell export always wins, so a one-off run can
 * override the machine's recorded setting without editing anything.
 */
function setting(name: string): string | undefined {
  return fromEnv(name) ?? fromEnvFile(name);
}

/** `~` expansion, and a relative path taken against the repo root. */
function normalizeDir(p: string): string {
  const expanded = p === "~" ? homedir() : p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
  return isAbsolute(expanded) ? expanded : resolve(REPO_ROOT, expanded);
}

/** One place the corpus might be, and what makes it a candidate. */
export interface CorpusCandidate {
  /** Human-readable provenance — what would put the binaries here. */
  source: string;
  dir: string;
}

/**
 * The search, in order. An explicit setting is the entire list: see the header.
 */
export function corpusCandidates(): CorpusCandidate[] {
  const explicit = fromEnv("PEEK_CORPUS_DIR");
  if (explicit !== undefined) {
    return [{ source: "PEEK_CORPUS_DIR (environment)", dir: normalizeDir(explicit) }];
  }
  const inFile = fromEnvFile("PEEK_CORPUS_DIR");
  if (inFile !== undefined) {
    return [{ source: `PEEK_CORPUS_DIR in ${ENV_FILE}`, dir: normalizeDir(inFile) }];
  }
  const xdg = fromEnv("XDG_DATA_HOME") ?? join(homedir(), ".local", "share");
  return [
    { source: "$XDG_DATA_HOME", dir: join(normalizeDir(xdg), CORPUS_DIR_NAME) },
    { source: "home directory", dir: join(homedir(), `.${CORPUS_DIR_NAME}`) },
    { source: "this repo (gitignored)", dir: join(REPO_ROOT, "corpus", "binaries") },
  ];
}

/** A candidate, plus what was actually found there. */
export interface CorpusProbe extends CorpusCandidate {
  /** "all present", "missing t32.exe, w64.exe", "no such directory". */
  note: string;
  /** Every requested binary is in this directory. */
  complete: boolean;
}

export interface CorpusResolution {
  /** The directory the audits read. Best effort when nothing matched. */
  dir: string;
  /** Provenance of `dir` — which candidate it came from. */
  source: string;
  /** `dir` holds every requested binary. */
  found: boolean;
  /** Every candidate, in order, with what was wrong with each. */
  probes: CorpusProbe[];
}

const NO_SUCH_DIR = "no such directory";

function probeCandidate(c: CorpusCandidate, bins: readonly string[]): CorpusProbe {
  let isDir = false;
  try {
    isDir = statSync(c.dir).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) return { ...c, note: NO_SUCH_DIR, complete: false };
  const missing = bins.filter((b) => !existsSync(join(c.dir, `${b}.exe`)));
  const note =
    missing.length === 0 ? "all present" : `missing ${missing.map((m) => `${m}.exe`).join(", ")}`;
  return { ...c, note, complete: missing.length === 0 };
}

/**
 * Walk the candidates and pick one. The first directory holding every requested
 * binary wins; failing that, the first directory that exists at all, so
 * `missing` names files in a real place rather than an imaginary one; failing
 * that, the first candidate, so there is always a concrete path to print.
 */
export function resolveCorpus(bins: readonly string[] = ALL_BINS): CorpusResolution {
  const probes = corpusCandidates().map((c) => probeCandidate(c, bins));
  const hit = probes.find((p) => p.complete);
  if (hit) return { dir: hit.dir, source: hit.source, found: true, probes };
  const fallback = probes.find((p) => p.note !== NO_SUCH_DIR) ?? probes[0];
  return { dir: fallback.dir, source: fallback.source, found: false, probes };
}

/** The bins to look for, falling back to all four if the request is invalid. */
function safeBins(): BinKey[] {
  try {
    return requestedBins();
  } catch {
    return [...ALL_BINS];
  }
}

export function corpusDir(): string {
  return resolveCorpus(safeBins()).dir;
}

/** Where `corpusDir()` came from, for the report header. */
export function corpusDirSource(): string {
  return resolveCorpus(safeBins()).source;
}

export function requestedBins(): BinKey[] {
  const raw = setting("PEEK_CORPUS_BINS");
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

/** What an ARM64 harness found, and what it must say when it found nothing. */
export interface ArmCorpus {
  /** Directory the search settled on, for the report header. */
  dir: string;
  /** Provenance of `dir`. */
  source: string;
  /** `[key, path]` for every ARM64 binary that is present. */
  present: [ArmBinKey, string][];
  /** `<key>.exe` for every one that is not. */
  missing: string[];
  /** The multi-line "here is how to say where they are" block, or "". */
  detail: string;
}

/**
 * Locate the ARM64 pair, using the same candidate search as everything else.
 *
 * Deliberately its own entry point rather than a flag on {@link preflight}:
 * `preflight()` answers for the gated run, and its `haveBins` is what makes
 * that run skip. An ARM64 harness must not be able to make the x86 gate skip,
 * and vice versa, so the two questions are asked separately over one search.
 *
 * No C compiler is probed. Nothing on the ARM64 path emits C — the decompiler
 * refuses for any image that is not x86 (`mcp/tools.ts`) — so a missing `gcc`
 * is not a reason to skip here.
 */
export function resolveArmCorpus(): ArmCorpus {
  const res = resolveCorpus(ARM_BINS);
  const present: [ArmBinKey, string][] = [];
  const missing: string[] = [];
  for (const key of ARM_BINS) {
    const p = join(res.dir, `${key}.exe`);
    if (existsSync(p)) present.push([key, p]);
    else missing.push(`${key}.exe`);
  }
  return {
    dir: res.dir,
    source: res.source,
    present,
    missing,
    detail: missing.length === 0 ? "" : discoveryHelp(res, ARM_BINS),
  };
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
  return setting("PEEK_CORPUS_TABLES") ?? null;
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
  /**
   * The same thing at length, for stdout: every directory probed, what was
   * wrong with each, and the two ways to say where the binaries actually are.
   * "" when there is nothing to report. Kept apart from `reason` because
   * `reason` becomes a test NAME, and a test name cannot be a paragraph.
   */
  detail: string;
}

/** The multi-line "here is how to tell me where they are" block. */
function discoveryHelp(res: CorpusResolution, bins: readonly string[]): string {
  const L: string[] = [];
  L.push(`  Looked for ${bins.map((b) => `${b}.exe`).join(", ")} in:`);
  for (const p of res.probes) L.push(`    ${p.dir}  — ${p.note}  [${p.source}]`);
  L.push("");
  L.push("  These are pip's vendored distlib launchers — real MSVC output, and");
  L.push("  deliberately NOT in this repo. If you have a copy, say where:");
  L.push("");
  L.push("    export PEEK_CORPUS_DIR=/path/to/them          # this shell only");
  L.push(`    echo 'PEEK_CORPUS_DIR=/path/to/them' >> ${ENV_FILE}   # this machine, durably`);
  L.push("");
  L.push("  Or put them in any of the directories above. PEEK_CORPUS_BINS=t32,t64");
  L.push("  audits a subset. See corpus/README.md.");
  return L.join("\n");
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
      detail: "",
    };
  }
  const res = resolveCorpus(bins);
  const present: BinKey[] = [];
  const missing: string[] = [];
  for (const b of bins) {
    if (existsSync(join(res.dir, `${b}.exe`))) present.push(b);
    else missing.push(join(res.dir, `${b}.exe`));
  }

  const cc = setting("CC") ?? "gcc";
  let haveCc = false;
  try {
    execFileSync(cc, ["--version"], { stdio: "pipe" });
    haveCc = true;
  } catch {
    haveCc = false;
  }

  const parts: string[] = [];
  const details: string[] = [];
  if (missing.length > 0) {
    // ONE line, because this becomes a test name — but it still has to name
    // every directory that was tried, what was wrong with each, and how to
    // override, or the skip is the "you have been told nothing" kind this file
    // exists to prevent. `detail` says the same at length on stdout.
    parts.push(
      `${missing.length} of ${bins.length} corpus binaries not found (${bins.join(", ")});` +
        ` looked in ${res.probes.map((p) => `${p.dir} [${p.note}]`).join(", ")};` +
        ` set PEEK_CORPUS_DIR, or put PEEK_CORPUS_DIR=<dir> in ${ENV_FILE},` +
        " PEEK_CORPUS_BINS to subset",
    );
    details.push(discoveryHelp(res, bins));
  }
  if (!haveCc) {
    parts.push(`no C compiler: '${cc} --version' failed (set CC to name another)`);
    details.push(`  No C compiler: '${cc} --version' failed. Set CC to name another.`);
  }

  return {
    haveBins: missing.length === 0,
    haveCc,
    cc,
    present,
    missing,
    reason: parts.join("; "),
    detail: details.join("\n\n"),
  };
}
