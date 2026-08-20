/**
 * Drift guard: `useFileMetrics.ts` must keep small inputs on the *synchronous*
 * path, and only large ones on the worker.
 *
 * WHY THIS EXISTS: this is the mirror image of
 * `analysis/__tests__/anomalyOffThread.test.ts`, and the two fail in opposite
 * directions. Dropping the anomaly pass's threshold puts multi-second walks on
 * the main thread for a large file. Dropping *this* one puts a worker round trip
 * on every **small** file — which is every ordinary binary, since the largest
 * real PE on the machine `asyncMetricState.ts`'s table was measured on is 273 KB
 * and both thresholds sit above it. What that buys is a `loading: true` render
 * and a second render on reply, in exchange for microseconds of computation
 * (checksum plus every section's entropy is ~3.3 ms/MiB, and the argument copy
 * the hand-off needs is itself ~0.4 ms/MiB). CLAUDE.md states the property this
 * file exists to hold: "inputs under the thresholds in `asyncMetricState.ts`
 * (256 KiB for the entropy strip, 1 MiB for file metrics) stay synchronous and
 * spawn no worker, so ordinary binaries never show a loading state."
 *
 * The regression is invisible to every assertion about output. Routing a 4 KiB
 * section through `metrics.worker.ts` returns exactly the same entropy blocks;
 * the only difference is a spinner on a file that never needed one, which
 * nothing in this repo renders. `asyncMetricState.test.ts` covers the reducer,
 * `resolveMetric` and the order of magnitude of the two constants — but it
 * cannot see whether the hook still *consults* them, because the branch that
 * does lives in the hook and the hook cannot be mounted (peek-a-bin-yvr1).
 *
 * Read over the TypeScript AST rather than as text, following
 * `anomalyOffThread.test.ts` and `disasmHandlerDeps.test.ts`. CLAUDE.md's
 * warning about source-scraping guards is that they "encode formatting by
 * accident"; parsing sidesteps that, so a reformat, an import reorder or a
 * rename of a local cannot fail the build here. It also buys the thing a scrape
 * cannot do at all: deciding which *side* of the size comparison each callback
 * sits on, so an inverted guard is caught rather than merely a deleted one.
 *
 * WHAT THIS CANNOT CATCH — be clear about it, because the repo does not
 * overclaim verification:
 *
 * - **Nothing here executes the hook.** There is no renderer in this repo (no
 *   jsdom, no @testing-library/react), so `useFileMetrics` and
 *   `useEntropyStrip` never run under vitest. This checks the *shape* of the
 *   source, not the behaviour: it can tell you nobody deleted, inverted or
 *   bypassed the branch, and nothing more.
 * - It says nothing about whether the thresholds are the right *numbers*, only
 *   that each hook branches on one and imports it rather than redeclaring it.
 * - It cannot see a spinner. Whether a small file actually renders with
 *   `loading: false` is `resolveMetric`'s job, tested directly in
 *   `asyncMetricState.test.ts`; whether the effect posts the request twice, or
 *   flashes a loading frame before the memo resolves, is unverified here and
 *   everywhere else.
 *
 * The AST helpers below are deliberately a **copy** of the ones in
 * `anomalyOffThread.test.ts` rather than a shared import. Only the four generic
 * walkers are common to the two files; the load-bearing part — deriving which
 * arm of the size test a call sits in — is not shareable, because the two
 * consumers have structurally different shapes: `App.tsx` writes an
 * `if (size <= MAX) { … } else { … }`, while this file binds the comparison to a
 * boolean that two conditional expressions then consume. Lifting only the
 * walkers would make an existing guard depend on a file outside itself without
 * de-duplicating anything that needs care, and `disasmHandlerDeps.test.ts` sets
 * the precedent that each AST guard here carries its own.
 *
 * Every assertion is preceded by a vacuity check. A drift guard that silently
 * stops matching is worse than no guard, because it reports success.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const HOOK = resolve(dirname(fileURLToPath(import.meta.url)), "..", "useFileMetrics.ts");

const sf = ts.createSourceFile(
  HOOK,
  readFileSync(HOOK, "utf-8"),
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.TS,
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

function unwrap(e: ts.Expression): ts.Expression {
  return ts.isParenthesizedExpression(e) ? unwrap(e.expression) : e;
}

/** The `null` a caller passes for "there is nothing to compute this way". */
function isNothing(e: ts.Expression): boolean {
  const u = unwrap(e);
  return u.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(u) && u.text === "undefined");
}

/**
 * `useAsyncMetric(key, syncCompute, asyncCompute)` — the shell both hooks call.
 *
 * The assertions below read its second and third arguments, so the two argument
 * *positions* have to be derived rather than assumed: swapping the parameters
 * would otherwise leave every assertion here checking the opposite of what it
 * claims, and passing. They are found by the one property that says what a
 * parameter is for rather than what it is called — the asynchronous callback's
 * return type is a `Promise`, the synchronous one's is not — so renaming either
 * parameter cannot break this, while reordering them re-points it correctly.
 */
const shell = findNodes(sf, ts.isFunctionDeclaration).find(
  (d) => d.name?.text === "useAsyncMetric",
);

function callbackParams(fn: ts.FunctionDeclaration | undefined): {
  sync: number;
  async: number;
} {
  const params = fn?.parameters ?? [];
  let sync = -1;
  let async = -1;
  params.forEach((p, i) => {
    if (p.type === undefined || findNodes(p.type, ts.isFunctionTypeNode).length === 0) return;
    if (mentions(p.type, "Promise")) async = i;
    else sync = i;
  });
  return { sync, async };
}

const SLOT = callbackParams(shell);

/**
 * Which side of the size test an expression is reached on.
 *
 * "large" means the worker side, "small" the inline side. `unrecognised` is
 * returned rather than a guess, so an unreadable shape fails loudly.
 */
type Side = "large" | "small" | "unrecognised";

/**
 * Whether `cond` being truthy means the input is larger than `threshold`.
 *
 * Returns null when the question cannot be answered from `cond` alone. All four
 * spellings of the comparison are accepted (`size > MAX`, `MAX < size`,
 * `size <= MAX`, `MAX >= size`), the comparison may be reached through the
 * boolean it was bound to (`offThread`), through a negation of it, or through an
 * `&&` chain that also tests something unrelated — which is what
 * `pe !== null && pe.buffer.byteLength > MAX_SYNC_FILE_METRIC_BYTES` is.
 *
 * Getting this backwards is the defect worth a test rather than a review: an
 * inverted guard still looks guarded at a glance while sending every file the
 * wrong way.
 */
function assertsLarge(
  cond: ts.Expression,
  threshold: string,
  sized: SizeBool | undefined,
): boolean | null {
  const e = unwrap(cond);

  if (ts.isIdentifier(e)) {
    // The boolean is only ever named by `sizeBool`, which records which way its
    // own comparison reads, so reaching it here is not an assumption.
    return sized !== undefined && e.text === sized.name ? sized.meansLarge : null;
  }

  if (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.ExclamationToken) {
    const inner = assertsLarge(e.operand, threshold, sized);
    return inner === null ? null : !inner;
  }

  if (!ts.isBinaryExpression(e)) return null;
  const op = e.operatorToken.kind;

  if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
    // Everything in an `&&` chain is asserted, so one informative operand is
    // enough — but two that disagree are unreadable rather than either answer.
    const l = assertsLarge(e.left, threshold, sized);
    const r = assertsLarge(e.right, threshold, sized);
    if (l !== null && r !== null) return l === r ? l : null;
    return l ?? r;
  }

  return comparisonMeansLarge(e, threshold);
}

/**
 * `x > MAX` → true, `x <= MAX` → false, and the two mirrored spellings; null
 * for anything that is not a size test against `threshold`.
 */
function comparisonMeansLarge(e: ts.BinaryExpression, threshold: string): boolean | null {
  const op = e.operatorToken.kind;
  const less = op === ts.SyntaxKind.LessThanToken || op === ts.SyntaxKind.LessThanEqualsToken;
  const greater =
    op === ts.SyntaxKind.GreaterThanToken || op === ts.SyntaxKind.GreaterThanEqualsToken;
  if (!less && !greater) return null;
  const right = mentions(e.right, threshold);
  const left = mentions(e.left, threshold);
  if (right === left) return null; // neither side, or a comparison of it with itself
  // `size > MAX` and `MAX < size` say "large"; `size <= MAX` and `MAX >= size`
  // say "small". The strict/non-strict pair is deliberately not distinguished:
  // one byte either side of the threshold is not what this guard is about.
  return (right && greater) || (left && less);
}

/** A boolean a hook bound its size test to, and which way that test reads. */
interface SizeBool {
  name: string;
  /** True if the boolean being true means the input is large. */
  meansLarge: boolean;
}

/**
 * The boolean a hook binds its size test to, if it uses one.
 *
 * Both hooks currently write
 * `const offThread = pe !== null && pe.buffer.byteLength > MAX_SYNC_…`, so the
 * comparison reaches the two callbacks through this name. The sense is recorded
 * rather than assumed, so the opposite spelling — `const inline = size <= MAX` —
 * is read correctly instead of being reported as an unknown shape. An inline
 * comparison in the conditional itself needs none of this and is read directly
 * by {@link assertsLarge}.
 */
function sizeBool(fn: ts.Node, threshold: string): SizeBool | undefined {
  for (const d of findNodes(fn, ts.isVariableDeclaration)) {
    if (d.initializer === undefined || !ts.isIdentifier(d.name)) continue;
    const meansLarge = assertsLarge(d.initializer, threshold, undefined);
    if (meansLarge !== null) return { name: d.name.text, meansLarge };
  }
  return undefined;
}

function sideOf(arg: ts.Expression, threshold: string, sized: SizeBool | undefined): Side {
  const e = unwrap(arg);
  if (!ts.isConditionalExpression(e)) return "unrecognised";

  const consNothing = isNothing(e.whenTrue);
  const altNothing = isNothing(e.whenFalse);
  if (consNothing === altNothing) return "unrecognised";

  const large = assertsLarge(e.condition, threshold, sized);
  if (large === null) return "unrecognised";

  // The callback is in the `then` arm: the condition holds where it is reached.
  if (altNothing) return large ? "large" : "small";
  // The callback is in the `else` arm, so what is known there is the condition's
  // *negation* — sound only when the condition is nothing but the size test. An
  // `&&` chain can be false for its other operand, which says nothing at all
  // about the size.
  const c = unwrap(e.condition);
  if (ts.isBinaryExpression(c) && c.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
    return "unrecognised";
  }
  return large ? "small" : "large";
}

interface Case {
  /** The exported hook. */
  hook: string;
  /** The threshold it must branch on, and the one it must not. */
  threshold: string;
  other: string;
  /** The worker method its large-input path must reach. */
  worker: string;
  /** What a small input pays if the branch goes. */
  cost: string;
}

const CASES: Case[] = [
  {
    hook: "useFileMetrics",
    threshold: "MAX_SYNC_FILE_METRIC_BYTES",
    other: "MAX_SYNC_ENTROPY_BLOCK_BYTES",
    worker: "metricsWorker.fileMetrics",
    cost:
      "checksum plus every section's entropy runs at ~3.3 ms/MiB, so under 1 MiB the whole " +
      "computation costs less than the argument copy the worker hand-off needs. Every ordinary " +
      "binary is under it — the Headers and Sections tabs would show a spinner for a file that " +
      "could have been measured before the frame was over.",
  },
  {
    hook: "useEntropyStrip",
    threshold: "MAX_SYNC_ENTROPY_BLOCK_BYTES",
    other: "MAX_SYNC_FILE_METRIC_BYTES",
    worker: "metricsWorker.entropyBlocks",
    cost:
      "the block form runs at ~17 ms/MiB, which is why its threshold is the lower of the two. " +
      "The strip is behind a toggle and recomputes on every window resize (maxBlocks is part of " +
      "the key), so a worker round trip on a small section is paid repeatedly.",
  },
];

describe("useFileMetrics.ts — the guard is actually pointed at something", () => {
  it("still routes both hooks through one useAsyncMetric shell", () => {
    expect(
      shell !== undefined,
      "src/hooks/useFileMetrics.ts no longer declares useAsyncMetric. Every assertion in this " +
        "file reads that function's argument positions, so they would all pass vacuously. " +
        "Re-point this guard before changing anything else.",
    ).toBe(true);
  });

  it("finds the synchronous and asynchronous callback parameters by their types", () => {
    expect(
      SLOT.sync,
      "no parameter of useAsyncMetric is a function type returning something other than a " +
        "Promise. That parameter is the synchronous path; without it this guard cannot tell " +
        "which argument is which.",
    ).toBeGreaterThanOrEqual(0);
    expect(
      SLOT.async,
      "no parameter of useAsyncMetric is a function type returning a Promise.",
    ).toBeGreaterThanOrEqual(0);
    expect(SLOT.sync).not.toBe(SLOT.async);
  });

  it("imports both thresholds rather than redeclaring a number", () => {
    for (const name of [CASES[0].threshold, CASES[1].threshold]) {
      const imported = findNodes(sf, ts.isImportDeclaration).some((d) => {
        const spec = d.moduleSpecifier;
        if (!ts.isStringLiteral(spec) || !spec.text.includes("asyncMetricState")) return false;
        const bindings = d.importClause?.namedBindings;
        return (
          bindings !== undefined &&
          ts.isNamedImports(bindings) &&
          bindings.elements.some((el) => el.name.text === name)
        );
      });
      expect(
        imported,
        `${name} must come from ./asyncMetricState, which is where the synchronous thresholds ` +
          `are defined and measured. A local copy drifts from the one App.tsx's anomaly pass ` +
          `uses, and the two would then disagree about which files are large.`,
      ).toBe(true);
    }
  });
});

for (const c of CASES) {
  const fn = findNodes(sf, ts.isFunctionDeclaration).find((d) => d.name?.text === c.hook);
  const calls = fn ? findCalls(fn, (x) => callName(x) === "useAsyncMetric") : [];
  const call = calls[0];
  const sized = fn ? sizeBool(fn, c.threshold) : undefined;
  const syncArg = call?.arguments[SLOT.sync];
  const asyncArg = call?.arguments[SLOT.async];

  describe(`${c.hook} keeps small inputs off the worker`, () => {
    it("is still one hook making one useAsyncMetric call", () => {
      expect(
        fn !== undefined,
        `src/hooks/useFileMetrics.ts no longer declares ${c.hook}. The assertions below are ` +
          `scoped to it and would pass vacuously.`,
      ).toBe(true);
      expect(
        calls.length,
        `${c.hook} no longer makes exactly one useAsyncMetric call, so this guard cannot say ` +
          `which call it is judging.`,
      ).toBe(1);
      expect(
        syncArg !== undefined && asyncArg !== undefined,
        `${c.hook}'s useAsyncMetric call does not supply both callback arguments.`,
      ).toBe(true);
    });

    it("still branches on exactly one size test against its own threshold", () => {
      const tests = findNodes(fn as ts.Node, ts.isBinaryExpression).filter(
        (e) => comparisonMeansLarge(e, c.threshold) !== null,
      );
      expect(
        tests.length,
        `${c.hook} no longer compares its input's size against ${c.threshold}. That comparison ` +
          `is the whole reason the synchronous path exists: ${c.cost}`,
      ).toBe(1);

      // And it must be its own threshold. Swapping the two would give the block
      // form — the more expensive of the pair per byte — the whole-file budget.
      expect(
        mentions(fn as ts.Node, c.other),
        `${c.hook} mentions ${c.other}, which belongs to the other metric. The two constants ` +
          `differ by 4x because the computations they gate differ by ~5x per byte.`,
      ).toBe(false);
    });

    it("puts the inline computation on the small side of that test", () => {
      const side = sideOf(syncArg as ts.Expression, c.threshold, sized);
      expect(
        side,
        side === "large"
          ? `${c.hook} reaches its synchronous computation only when the input is LARGER than ` +
              `${c.threshold}. That is an inverted guard, not a missing one — it still looks ` +
              `guarded at a glance, and it does the whole-file work on the main thread for ` +
              `exactly the inputs the worker exists for.`
          : `${c.hook}'s synchronous argument is not a conditional this guard can read. ` +
              `Expected one branch to be the callback and the other \`null\`, under a condition ` +
              `derived from a comparison with ${c.threshold} — directly or through a boolean ` +
              `bound to it. If the shape changed deliberately, re-point this guard; if the ` +
              `argument became unconditional, small inputs now ${
                sized === undefined ? "have no size test at all" : "ignore the size test"
              }.`,
      ).toBe("small");
    });

    it("puts the worker on the large side, and reaches it there", () => {
      const side = sideOf(asyncArg as ts.Expression, c.threshold, sized);
      expect(
        side,
        side === "small"
          ? `${c.hook} posts to ${c.worker} for inputs SMALLER than ${c.threshold}. This is the ` +
              `regression peek-a-bin-yvr1 exists for: the value is identical, and every ` +
              `ordinary binary now pays a worker round trip and renders a loading state it ` +
              `never needed.`
          : `${c.hook}'s asynchronous argument is not a conditional this guard can read. If it ` +
              `became unconditional, EVERY input now goes to the worker.`,
      ).toBe("large");
      expect(
        findCalls(asyncArg as ts.Node, (x) => callName(x) === c.worker).length,
        `${c.hook}'s large-input path no longer calls ${c.worker}.`,
      ).toBeGreaterThan(0);
    });

    it("does not touch the worker on the small path", () => {
      expect(
        mentions(syncArg as ts.Node, "metricsWorker"),
        `${c.hook}'s synchronous argument mentions metricsWorker. Computing inline and posting ` +
          `to the worker anyway is strictly worse than either alone: the round trip is paid and ` +
          `a loading state can still appear.`,
      ).toBe(false);
    });
  });
}
