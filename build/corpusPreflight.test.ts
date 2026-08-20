/**
 * Drift guard: the corpus harness must never again look for the binaries in
 * one particular person's home directory.
 *
 * `corpus/preflight.ts` used to carry a hardcoded absolute default —
 * `/home/jacob/…/pip/_vendor/distlib` — which stopped existing. The audits
 * skip honestly when the corpus is absent, so nothing failed; the DEFAULT path
 * simply became the skip path, and `npm run corpus` did nothing on the machine
 * the project lives on while the binaries sat two directories away
 * (`peek-a-bin-alx1`). A wrong default is invisible precisely because the
 * skip is designed not to fail.
 *
 * So this test asserts the two properties that make that impossible to
 * reintroduce: every candidate directory is derived from `$XDG_DATA_HOME`,
 * `$HOME` or the repo itself, and a skip names every one of them plus how to
 * override. It imports `preflight.ts` — pure node, no Capstone, no session —
 * which is why it can live in the ordinary suite while the audits cannot.
 */
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  ALL_BINS,
  corpusCandidates,
  ENV_FILE,
  preflight,
  resolveCorpus,
} from "../corpus/preflight";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const NOWHERE = "/nonexistent/peek-a-bin-corpus-that-is-not-there";

const savedDir = process.env.PEEK_CORPUS_DIR;
afterEach(() => {
  if (savedDir === undefined) delete process.env.PEEK_CORPUS_DIR;
  else process.env.PEEK_CORPUS_DIR = savedDir;
});

describe("corpus preflight", () => {
  it("roots every candidate directory in $HOME, $XDG_DATA_HOME or the repo", () => {
    delete process.env.PEEK_CORPUS_DIR;
    const home = homedir();
    const xdg = process.env.XDG_DATA_HOME;
    const rooted = (d: string) =>
      d.startsWith(home) || d.startsWith(REPO_ROOT) || (xdg !== undefined && d.startsWith(xdg));
    const stray = corpusCandidates()
      .filter((c) => !rooted(c.dir))
      .map((c) => `${c.dir} [${c.source}]`);
    // A candidate under someone else's home is the exact defect: it can only
    // ever be right on one machine, and wrong is indistinguishable from absent.
    expect(`candidates outside $HOME/$XDG_DATA_HOME/repo: ${stray.join(", ")}`).toBe(
      "candidates outside $HOME/$XDG_DATA_HOME/repo: ",
    );
  });

  it("probes more than one conventional location when nothing is set", () => {
    delete process.env.PEEK_CORPUS_DIR;
    expect(corpusCandidates().length).toBeGreaterThan(1);
  });

  it("takes an explicit PEEK_CORPUS_DIR as the whole search", () => {
    process.env.PEEK_CORPUS_DIR = NOWHERE;
    const cands = corpusCandidates();
    // Not one of several: an override that is wrong must be reported about the
    // directory the caller named, never silently satisfied from elsewhere.
    expect(cands.map((c) => c.dir)).toEqual([NOWHERE]);
    const res = resolveCorpus(ALL_BINS);
    expect(res.found).toBe(false);
    expect(res.dir).toBe(NOWHERE);
  });

  it("skips rather than throws when the corpus is unreachable, and says where it looked", () => {
    process.env.PEEK_CORPUS_DIR = NOWHERE;
    const pre = preflight();
    expect(pre.haveBins).toBe(false);
    expect(pre.present).toEqual([]);
    expect(pre.missing.length).toBe(ALL_BINS.length);
    // The single-line reason becomes a test name and must still be actionable.
    expect(pre.reason).toContain(NOWHERE);
    expect(pre.reason).toContain("PEEK_CORPUS_DIR");
    // The detail block is the discovery half: how to say where they are.
    expect(pre.detail).toContain(NOWHERE);
    expect(pre.detail).toContain("export PEEK_CORPUS_DIR=");
    expect(pre.detail).toContain(ENV_FILE);
    for (const b of ALL_BINS) expect(pre.detail).toContain(`${b}.exe`);
  });
});
