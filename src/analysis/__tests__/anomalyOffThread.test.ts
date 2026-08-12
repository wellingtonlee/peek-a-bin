/**
 * Drift guard: the anomaly pass must keep its two whole-file walks off the main
 * thread.
 *
 * WHY THIS EXISTS: `detectAnomalies(pe)` computes `validateChecksum` and every
 * section's entropy itself; `detectAnomalies(pe, metrics)` is handed them.
 * Measured on a synthetic 253 MiB PE, that is **3881 ms against 0.0 ms** of
 * main-thread work — and both spellings return byte-identical anomalies
 * (peek-a-bin-vrl). So the regression this file exists for is invisible to every
 * assertion about *output*: an edit that drops the second argument, or drops the
 * size-threshold branch, keeps the anomaly list perfectly correct and freezes
 * the tab for several seconds on a large file. There is no renderer in this repo
 * — no jsdom, no @testing-library/react — so App's effect never executes under
 * vitest and nothing else can notice (peek-a-bin-v4s3).
 *
 * Read over the TypeScript AST rather than as text, following
 * `hooks/__tests__/disasmHandlerDeps.test.ts`. CLAUDE.md's warning about
 * source-scraping guards is that they "encode formatting by accident"; parsing
 * sidesteps that entirely, so a reformat, an import reorder or a rename of a
 * local cannot fail the build here. It also buys something a scrape cannot do at
 * all: checking which *side* of the threshold comparison the synchronous call
 * sits on, so an inverted guard is caught rather than merely a deleted one.
 *
 * Every assertion below is preceded by a vacuity check. A drift guard that
 * silently stops matching is worse than no guard, because it reports success.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const APP = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "App.tsx");

/** The size below which the walks are cheaper than the worker hand-off. */
const THRESHOLD = "MAX_SYNC_FILE_METRIC_BYTES";

const sf = ts.createSourceFile(
  APP,
  readFileSync(APP, "utf-8"),
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.TSX,
);

/** `foo(...)` → "foo"; `obj.foo(...)` → "obj.foo"; anything else → "". */
function callName(call: ts.CallExpression): string {
  const e = call.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) {
    return ts.isIdentifier(e.expression) ? `${e.expression.text}.${e.name.text}` : e.name.text;
  }
  return "";
}

function findCalls(root: ts.Node, match: (c: ts.CallExpression) => boolean): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const walk = (n: ts.Node) => {
    if (ts.isCallExpression(n) && match(n)) out.push(n);
    n.forEachChild(walk);
  };
  walk(root);
  return out;
}

function findNodes<T extends ts.Node>(root: ts.Node, is: (n: ts.Node) => n is T): T[] {
  const out: T[] = [];
  const walk = (n: ts.Node) => {
    if (is(n)) out.push(n);
    n.forEachChild(walk);
  };
  walk(root);
  return out;
}

function mentions(node: ts.Node, name: string): boolean {
  return findNodes(node, ts.isIdentifier).some((id) => id.text === name);
}

/** Node containment, by source range — both nodes come from the same file. */
function within(node: ts.Node, container: ts.Node): boolean {
  return node.pos >= container.pos && node.end <= container.end;
}

/**
 * The `useEffect` that runs the anomaly pass.
 *
 * Located by what it calls rather than by position, so moving it within the
 * component, renaming its refs or splitting other effects out cannot break this.
 */
const anomalyEffects = findCalls(sf, (c) => callName(c) === "useEffect").filter(
  (e) => findCalls(e, (c) => callName(c) === "detectAnomalies").length > 0,
);
const effect = anomalyEffects[0];

const detectCalls = effect ? findCalls(effect, (c) => callName(c) === "detectAnomalies") : [];
/** `detectAnomalies(pe)` — the spelling that does the walks itself. */
const inlineCalls = detectCalls.filter((c) => c.arguments.length === 1);
/** `detectAnomalies(pe, metrics)` — the spelling that is handed them. */
const handedCalls = detectCalls.filter((c) => c.arguments.length >= 2);

/**
 * The branch of the threshold `if` taken by files small enough to walk inline.
 *
 * Derived from the comparison rather than assumed to be the `then` arm: all four
 * spellings of "smaller than the threshold" are accepted (`size <= MAX`,
 * `MAX >= size`, and both negations), and anything else returns null so the test
 * fails loudly rather than guessing. Getting this backwards would put every
 * large file on the synchronous path while still looking guarded — the exact
 * shape of the condition-polarity defect this codebase has been bitten by.
 */
type SyncArm =
  /** The branch small files take. */
  | { kind: "arm"; stmt: ts.Statement }
  /** The comparison reads fine, but the arm it selects does not exist. */
  | { kind: "missing" }
  /** Not a size test this guard knows how to read. */
  | { kind: "unrecognised" };

function syncBranch(stmt: ts.IfStatement): SyncArm {
  const cond = stmt.expression;
  if (!ts.isBinaryExpression(cond)) return { kind: "unrecognised" };
  const op = cond.operatorToken.kind;
  const less = op === ts.SyntaxKind.LessThanToken || op === ts.SyntaxKind.LessThanEqualsToken;
  const greater =
    op === ts.SyntaxKind.GreaterThanToken || op === ts.SyntaxKind.GreaterThanEqualsToken;
  const right = mentions(cond.right, THRESHOLD);
  const left = mentions(cond.left, THRESHOLD);

  // `size <= MAX` / `MAX >= size` put the small files in the `then` arm;
  // `size > MAX` / `MAX < size` put them in the `else`.
  const arm =
    (right && less) || (left && greater)
      ? stmt.thenStatement
      : (right && greater) || (left && less)
        ? stmt.elseStatement
        : undefined;
  if (arm === undefined) {
    return right || left ? { kind: "missing" } : { kind: "unrecognised" };
  }
  return { kind: "arm", stmt: arm };
}

const thresholdIfs = effect
  ? findNodes(effect, ts.isIfStatement).filter((s) => mentions(s.expression, THRESHOLD))
  : [];

describe("App's anomaly pass — the guard is actually pointed at something", () => {
  it("finds exactly one useEffect that runs detectAnomalies", () => {
    expect(
      anomalyEffects.length,
      "src/App.tsx no longer has exactly one useEffect calling detectAnomalies. Every " +
        "assertion in this file is scoped to that effect, so they would all pass vacuously. " +
        "Re-point this guard before changing anything else.",
    ).toBe(1);
  });

  it("finds both spellings of the call, so neither assertion is trivially true", () => {
    expect(inlineCalls.length).toBeGreaterThan(0);
    expect(handedCalls.length).toBeGreaterThan(0);
  });
});

describe("App keeps the checksum and entropy walks off the main thread", () => {
  it("routes large files through metricsWorker.fileMetrics", () => {
    const calls = findCalls(effect, (c) => callName(c) === "metricsWorker.fileMetrics");
    expect(
      calls.length,
      "src/App.tsx's anomaly effect no longer calls metricsWorker.fileMetrics. That call is " +
        "the entire fix for peek-a-bin-vrl: it is what moves validateChecksum and every " +
        "section's entropy onto metrics.worker.ts, and its result is cached per ArrayBuffer so " +
        "the Headers tab, the Sections tab and this pass share one walk. Without it the pass " +
        "does 3881 ms of main-thread work on a 253 MiB image while returning identical output.",
    ).toBeGreaterThan(0);
  });

  it("feeds that result into detectAnomalies rather than recomputing", () => {
    // The `.then` whose chain contains the fileMetrics call, and the name it
    // binds the metrics to. Matching the parameter — not just "some two-argument
    // call exists" — is what proves the worker's answer is the one used.
    // Matched on the property access itself rather than through `callName`,
    // which flattens `f().then` to a bare "then" because the receiver is a call
    // rather than an identifier. This also makes the depth of the chain
    // irrelevant: `.then` directly on the call and `.then` after any number of
    // intervening links both match.
    const thens = findCalls(
      effect,
      (c) =>
        ts.isPropertyAccessExpression(c.expression) &&
        c.expression.name.text === "then" &&
        findCalls(c.expression, (inner) => callName(inner) === "metricsWorker.fileMetrics").length >
          0,
    );
    expect(
      thens.length,
      "no .then() attached to the metricsWorker.fileMetrics call in src/App.tsx",
    ).toBeGreaterThan(0);

    const cb = thens[0].arguments[0];
    expect(cb !== undefined && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb))).toBe(true);
    const param = (cb as ts.ArrowFunction).parameters[0]?.name;
    expect(param !== undefined && ts.isIdentifier(param)).toBe(true);
    const metricsName = (param as ts.Identifier).text;

    const uses = findCalls(cb as ts.Node, (c) => callName(c) === "detectAnomalies").filter((c) => {
      const second = c.arguments[1];
      return second !== undefined && ts.isIdentifier(second) && second.text === metricsName;
    });
    expect(
      uses.length,
      `src/App.tsx receives the metrics as "${metricsName}" but never passes them to ` +
        `detectAnomalies. Computing them in the worker and then walking the file again on the ` +
        `main thread is strictly worse than not having the worker at all.`,
    ).toBeGreaterThan(0);
  });
});

describe("the size threshold survives, and points the right way", () => {
  it("still branches on the shared threshold constant", () => {
    expect(
      thresholdIfs.length,
      `src/App.tsx's anomaly effect no longer branches on ${THRESHOLD}. Small files must keep ` +
        `walking inline — below the threshold the walks cost less than the worker hand-off, ` +
        `and every ordinary binary is below it, so making them pay a round trip would put a ` +
        `loading state on files that never needed one.`,
    ).toBe(1);
  });

  it("imports that threshold rather than redeclaring a number", () => {
    const imported = findNodes(sf, ts.isImportDeclaration).some((d) => {
      const spec = d.moduleSpecifier;
      if (!ts.isStringLiteral(spec) || !spec.text.includes("asyncMetricState")) return false;
      const bindings = d.importClause?.namedBindings;
      return (
        bindings !== undefined &&
        ts.isNamedImports(bindings) &&
        bindings.elements.some((el) => el.name.text === THRESHOLD)
      );
    });
    expect(
      imported,
      `${THRESHOLD} must come from hooks/asyncMetricState, which is where the synchronous ` +
        `thresholds are defined and measured. A local copy drifts from the one useFileMetrics ` +
        `uses, and the two would then disagree about which files are large.`,
    ).toBe(true);
  });

  it("puts the inline walk on the small side of it, and only there", () => {
    const small = syncBranch(thresholdIfs[0]);
    expect(
      small.kind,
      small.kind === "missing"
        ? `the ${THRESHOLD} comparison in src/App.tsx selects a branch that does not exist — ` +
            `the test reads as "large file" but has no else arm, so every file now takes the ` +
            `synchronous path. This is an inverted guard, not a missing one: it still looks ` +
            `guarded at a glance, which is why it is worth a test rather than a review.`
        : "the threshold comparison in src/App.tsx is not a recognised size test. Expected " +
            "one of `size <= MAX`, `MAX >= size`, `size > MAX` or `MAX < size` so this guard " +
            "can tell which branch is the small-file path.",
    ).toBe("arm");
    const smallArm = (small as { kind: "arm"; stmt: ts.Statement }).stmt;

    const stray = inlineCalls.filter((c) => !within(c, smallArm));
    expect(
      stray.length,
      `src/App.tsx calls detectAnomalies(pe) with no metrics outside the ${THRESHOLD} branch. ` +
        `That is the peek-a-bin-vrl regression exactly: the call is correct, it returns the ` +
        `same anomalies, and it does the checksum and all-section entropy walks on the main ` +
        `thread — 3881 ms on a 253 MiB image, with nothing on screen to show for it.`,
    ).toBe(0);

    // And the converse: the worker path must not sit inside the small-file arm,
    // which would leave large files with no route to it at all.
    const misplaced = handedCalls.filter((c) => within(c, smallArm));
    expect(misplaced.length).toBe(0);
  });
});
