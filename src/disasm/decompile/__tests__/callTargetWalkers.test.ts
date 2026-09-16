/**
 * peek-a-bin-s1f6.1 — every pass that visits a call's ARGUMENTS must also visit
 * its TARGET.
 *
 * `IRCall.targetExpr` (see its docstring in `ir.ts`) carries the value an
 * indirect call transfers through, for a memory operand: `call dword ptr
 * [ebp + 8]` holds `deref(ebp + 8)`. It is an ordinary read — the target is
 * evaluated before the call, exactly like an argument — and the field is
 * OPTIONAL, so a pass that spreads `{ ...call }` and maps only `args` compiles,
 * type-checks, and silently carries the unmapped expression through or,
 * worse, never counts the read at all. The consequence of the second is the
 * `rax = (int64_t)GetLastError()` class one level down: dead-code elimination
 * sees a call that reads nothing through its target, deletes the definition the
 * target names, and the emitted C calls through a value nothing assigns.
 *
 * Nothing else in the repo can fail on that. The population is four functions
 * per PE32 binary in this corpus (t32!sub_40333D, sub_406DCC, sub_40BBDC and
 * their w32 twins) and ZERO on both x64 binaries, so a missed walker is invisible
 * to every gate on half the corpus and to `pipeline.test.ts` unless a fixture
 * happens to exercise that exact pass. Hence a source guard.
 *
 * WHAT IT ASSERTS, over the real TypeScript AST rather than over text, so a
 * reformat cannot break it:
 *
 *  1. Every function that reads `.args` NON-POSITIONALLY — iterating, mapping,
 *     reducing, spreading — mentions `targetExpr` somewhere in its own body.
 *  2. A function whose every `.args` read is POSITIONAL (`args.length`,
 *     `args[i]`) is exempt, and that exemption is a RULE rather than a list: an
 *     index is an argument *position*, and a target has none. Such a function
 *     pairs arguments with a parameter list (`clobberedByCall` with the fastcall
 *     registers, `typeInfer` with an API signature) and a target is not one of
 *     them.
 *  3. The exempt set is pinned BOTH WAYS against `POSITIONAL_ONLY` below, so a
 *     new positional-only reader has to be adjudicated here rather than
 *     silently joining the exemption, and an entry that stops reading `.args`
 *     has to be removed rather than sitting there naming nothing — the
 *     liveness half this repo's audits keep needing.
 *  4. The scan is non-empty and reaches the walkers it is supposed to reach. An
 *     audit that finds nothing passes vacuously, which is this repo's most
 *     frequently recurring mistake.
 *
 * `mapCallOperands` (`ir.ts`) is the other half of the defence: it is the one
 * declaration of "apply this to a call's operands", so the fourteen sites that
 * REBUILD a call do not read `.args` at all any more and cannot drift. This
 * guard covers what is left — the sites that READ one.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const DECOMPILE_DIR = resolve(HERE, "..");
const CORPUS_DIR = resolve(HERE, "..", "..", "..", "..", "corpus");

/**
 * Where a call's operands are walked. `src/disasm/decompile` is the pipeline;
 * the three `corpus/` audits keep their own replicas of the register-read walk
 * deliberately (an audit reading the pipeline's answer stops being independent),
 * and a replica that misses the target under-counts reads — which is how a
 * live definition is reported as lost.
 */
const SCANNED: { dir: string; label: string }[] = [
  { dir: DECOMPILE_DIR, label: "src/disasm/decompile" },
  { dir: CORPUS_DIR, label: "corpus" },
];

/**
 * Functions whose every `.args` read is positional — adjudicated one by one.
 * Each pairs an argument with something that has argument POSITIONS, and a
 * call's target occupies none of them:
 *
 *  - `clobberedByCall` (ssa.ts) walks arguments against `FASTCALL_ARG_REGS`.
 *  - `collectCallArgSlots` (structs.ts) records `{ funcAddr, paramIdx }`.
 *  - `inferFieldTypesFromUsage` (structs.ts) and `inferFromAPICalls`
 *    (typeInfer.ts) pair an argument with the callee's declared parameter type,
 *    from `apitypes.ts`.
 */
const POSITIONAL_ONLY: readonly string[] = [
  "ssa.ts:clobberedByCall",
  "structs.ts:collectCallArgSlots.walk",
  "structs.ts:inferFieldTypesFromUsage.walkStmts",
  "typeInfer.ts:inferFromAPICalls.processStmts",
];

/** One `.args` property access, with the enclosing named function. */
interface ArgsRead {
  file: string;
  fn: string;
  positional: boolean;
}

/**
 * The dotted path of enclosing named functions — `collectCallArgSlots.walk` —
 * or "<top level>". Qualified, because the inner walkers this guard is about
 * are routinely called `walk` and a bare name would not say which one.
 */
function enclosingName(node: ts.Node): string {
  const parts: string[] = [];
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isFunctionDeclaration(n) && n.name) parts.unshift(n.name.text);
    else if (ts.isMethodDeclaration(n) && ts.isIdentifier(n.name)) parts.unshift(n.name.text);
    else if (
      (ts.isFunctionExpression(n) || ts.isArrowFunction(n)) &&
      n.parent &&
      ts.isVariableDeclaration(n.parent) &&
      ts.isIdentifier(n.parent.name)
    ) {
      parts.unshift(n.parent.name.text);
    }
  }
  return parts.length > 0 ? parts.join(".") : "<top level>";
}

/** The enclosing function-like node itself, for the `targetExpr` search. */
function enclosingFunction(node: ts.Node): ts.Node | null {
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n)) return n;
    if (ts.isFunctionExpression(n) || ts.isArrowFunction(n)) {
      if (n.parent && ts.isVariableDeclaration(n.parent) && ts.isIdentifier(n.parent.name)) {
        return n;
      }
    }
  }
  return null;
}

/**
 * Whether this `.args` access is positional — `args.length` or `args[…]`.
 * Anything else reaches every argument, so it must reach the target too.
 */
function isPositional(access: ts.PropertyAccessExpression): boolean {
  const parent = access.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.name.text === "length") return true;
  if (ts.isElementAccessExpression(parent) && parent.expression === access) return true;
  return false;
}

/** Does this subtree mention the identifier `targetExpr` at all? */
function mentionsTargetExpr(root: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n) && n.text === "targetExpr") found = true;
    else n.forEachChild(visit);
  };
  visit(root);
  return found;
}

/** Every `.args` read in the scanned sources, keyed `<file>:<function>`. */
function scan(): { reads: ArgsRead[]; missing: string[]; files: Set<string> } {
  const reads: ArgsRead[] = [];
  const missing = new Set<string>();
  const files = new Set<string>();
  for (const { dir } of SCANNED) {
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".ts") || name.endsWith(".d.ts")) continue;
      const path = join(dir, name);
      const sf = ts.createSourceFile(
        path,
        readFileSync(path, "utf-8"),
        ts.ScriptTarget.Latest,
        true,
      );
      files.add(name);
      const visit = (n: ts.Node): void => {
        if (ts.isPropertyAccessExpression(n) && n.name.text === "args") {
          const fn = enclosingName(n);
          const positional = isPositional(n);
          reads.push({ file: name, fn, positional });
          if (!positional) {
            const owner = enclosingFunction(n);
            if (!owner || !mentionsTargetExpr(owner)) missing.add(`${name}:${fn}`);
          }
        }
        n.forEachChild(visit);
      };
      visit(sf);
    }
  }
  return { reads, missing: [...missing].sort(), files };
}

describe("a call's target is walked wherever its arguments are (peek-a-bin-s1f6.1)", () => {
  const { reads, missing, files } = scan();

  it("scans a non-empty population", () => {
    expect(files.size, "no sources were scanned — the guard would pass vacuously").toBeGreaterThan(
      10,
    );
    expect(
      reads.length,
      "no `.args` read was found — the guard would pass vacuously",
    ).toBeGreaterThan(5);
    // The walkers this guard exists for, named so a broken scan cannot go quiet.
    const named = new Set(reads.map((r) => `${r.file}:${r.fn}`));
    for (const key of ["ir.ts:walkExpr", "ir.ts:mapCallOperands", "fold.ts:readRegs"]) {
      expect(named, `the scan no longer reaches ${key}`).toContain(key);
    }
  });

  it("every non-positional `.args` reader also reads `targetExpr`", () => {
    expect(
      missing,
      "These functions walk a call's arguments without walking IRCall.targetExpr. A call " +
        "evaluates its target before its arguments, so the target is a read: a pass that " +
        "misses it drops the target's renaming/promotion, or lets DCE delete the definition " +
        "the call transfers through (peek-a-bin-s1f6.1). Either walk it, or rebuild the call " +
        "through ir.ts's mapCallOperands.",
    ).toEqual([]);
  });

  it("the positional-only exemptions are exactly the adjudicated ones", () => {
    const byFn = new Map<string, boolean>();
    for (const r of reads) {
      const key = `${r.file}:${r.fn}`;
      byFn.set(key, (byFn.get(key) ?? true) && r.positional);
    }
    const positionalOnly = [...byFn.entries()]
      .filter(([, only]) => only)
      .map(([key]) => key)
      .sort();
    expect(
      positionalOnly,
      "A function that reads `call.args` only by index or length pairs arguments with " +
        "argument POSITIONS, which a call target does not occupy — so it is exempt from the " +
        "targetExpr rule. The set is pinned both ways: a new one must be adjudicated here, " +
        "and an entry that no longer reads `.args` must be removed rather than left naming " +
        "nothing (peek-a-bin-s1f6.1).",
    ).toEqual([...POSITIONAL_ONLY].sort());
  });
});
