/**
 * Drift guard for the two dependency arrays behind the disassembly pane's
 * keyboard handler.
 *
 * WHY THIS EXISTS: `useDisassemblySearch` returns one object that is a single
 * entry in `handleKeyDown`'s 37-entry dependency array. While that object was a
 * bare literal it had a fresh identity every render, so `handleKeyDown`'s
 * `useCallback` memoised nothing and every other entry in its array was inert —
 * a missing entry was harmless because the callback was rebuilt regardless.
 * Memoising the search object (peek-a-bin-imm) flipped all 37 entries from
 * inert to load-bearing at once. From then on a param that is read but not
 * declared freezes at the value it had when the callback was last rebuilt,
 * which is peek-a-bin-ehv exactly (D opened the decompile panel but could not
 * close it, unnoticed for the project's whole history).
 *
 * There is no React renderer in this repo — no jsdom, no
 * @testing-library/react — so nothing mounts these hooks and no runtime test can
 * observe a stale closure. What CAN be checked without a renderer is the
 * relationship between a callback's body and its dependency array, which is
 * where every one of these bugs actually lives. That is what this file does,
 * over the real TypeScript AST rather than over text, so it does not care how
 * the files are formatted.
 *
 * Biome's `useExhaustiveDependencies` checks something similar, but it is
 * configured at "warn" and `npm run lint` does not fail on warnings. These
 * assertions are a gate.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const HOOKS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parse(file: string): ts.SourceFile {
  const path = resolve(HOOKS_DIR, file);
  return ts.createSourceFile(path, readFileSync(path, "utf-8"), ts.ScriptTarget.Latest, true);
}

/** The named top-level function declaration. */
function findFunction(sf: ts.SourceFile, name: string): ts.FunctionDeclaration {
  let found: ts.FunctionDeclaration | undefined;
  sf.forEachChild((node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) found = node;
  });
  if (!found?.body) throw new Error(`${sf.fileName} no longer declares function ${name}`);
  return found;
}

/** Every `useCallback(...)` / `useMemo(...)` call inside a node, in source order. */
function findHookCalls(root: ts.Node, hookName: string): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      if (node.expression.text === hookName) calls.push(node);
    }
    node.forEachChild(visit);
  };
  visit(root);
  return calls;
}

/** The identifier names in a hook call's dependency array (its second argument). */
function depNames(call: ts.CallExpression): string[] {
  const arr = call.arguments[1];
  if (!arr || !ts.isArrayLiteralExpression(arr)) {
    throw new Error("hook call has no array-literal dependency argument");
  }
  return arr.elements.map((el) => {
    if (!ts.isIdentifier(el)) {
      throw new Error(`dependency ${el.getText()} is not a plain identifier`);
    }
    return el.text;
  });
}

/**
 * Names read as values inside `node`.
 *
 * Property *names* are skipped (`search.showSearch` reads `search`, not
 * `showSearch`) but shorthand object properties are NOT — `{ viewMode }` is a
 * genuine read of `viewMode`, and treating it as a property name is how a naive
 * text scan misses three real dependencies.
 */
function valueReads(node: ts.Node): Set<string> {
  const reads = new Set<string>();
  const walk = (n: ts.Node) => {
    if (ts.isPropertyAccessExpression(n)) {
      walk(n.expression); // skip `.name`
      return;
    }
    if (ts.isPropertyAssignment(n)) {
      if (ts.isComputedPropertyName(n.name)) walk(n.name);
      walk(n.initializer); // skip the literal key
      return;
    }
    if (ts.isIdentifier(n)) {
      reads.add(n.text);
      return;
    }
    n.forEachChild(walk);
  };
  walk(node);
  return reads;
}

/**
 * Names a hook body binds that React guarantees are identity-stable: the setter
 * half of `useState`, and anything `useRef` returns.
 *
 * Derived from the bindings rather than hard-coded, so a field that stops being
 * a setter — or a new one that is a value — is caught. Biome's
 * `useExhaustiveDependencies` reports exactly these as unnecessary dependencies,
 * which is why they are allowed to be absent from a dependency array; every
 * other name must be declared.
 */
function stableBindings(fnBody: ts.Node): Set<string> {
  const stable = new Set<string>();
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = node.initializer;
      const callee =
        ts.isCallExpression(init) && ts.isIdentifier(init.expression) ? init.expression.text : "";
      if (callee === "useState" && ts.isArrayBindingPattern(node.name)) {
        const setter = node.name.elements[1];
        if (setter && ts.isBindingElement(setter) && ts.isIdentifier(setter.name)) {
          stable.add(setter.name.text);
        }
      }
      if (callee === "useRef" && ts.isIdentifier(node.name)) stable.add(node.name.text);
    }
    node.forEachChild(visit);
  };
  visit(fnBody);
  return stable;
}

describe("useDisassemblySearch's returned object", () => {
  const sf = parse("useDisassemblySearch.ts");
  const fn = findFunction(sf, "useDisassemblySearch");
  const statements = fn.body?.statements ?? [];
  const returned = statements[statements.length - 1];

  it("is memoised, not a fresh literal each render", () => {
    const isMemoisedReturn =
      returned !== undefined &&
      ts.isReturnStatement(returned) &&
      returned.expression !== undefined &&
      ts.isCallExpression(returned.expression) &&
      ts.isIdentifier(returned.expression.expression) &&
      returned.expression.expression.text === "useMemo";

    expect(
      isMemoisedReturn,
      "useDisassemblySearch must return a useMemo. Returning a bare object literal gives " +
        "`search` a fresh identity every render, which silently makes handleKeyDown's " +
        "useCallback in useDisassemblyKeyboard.ts memoise nothing and turns all 37 of its " +
        "dependency entries back into decoration (peek-a-bin-imm).",
    ).toBe(true);
  });

  it("declares every field it returns as a dependency", () => {
    const memos = findHookCalls(fn.body!, "useMemo");
    const memo = memos[memos.length - 1];
    const literal = memo.arguments[0];
    // () => ({ ... })
    const obj =
      ts.isArrowFunction(literal) && ts.isParenthesizedExpression(literal.body)
        ? literal.body.expression
        : undefined;
    expect(obj !== undefined && ts.isObjectLiteralExpression(obj)).toBe(true);

    const fields = (obj as ts.ObjectLiteralExpression).properties.map((p) => {
      if (!p.name || !ts.isIdentifier(p.name)) throw new Error("unexpected property shape");
      return p.name.text;
    });
    const deps = new Set(depNames(memo));
    const stable = stableBindings(fn.body!);

    // Sanity: the exemption must be earned from the source, not assumed.
    expect(stable.has("setShowSearch")).toBe(true);
    expect(stable.has("searchDebounceRef")).toBe(true);
    expect(stable.has("showSearch")).toBe(false);

    const missing = fields.filter((f) => !deps.has(f) && !stable.has(f));
    expect(
      missing,
      `useDisassemblySearch returns ${missing.join(", ")} but does not list ${
        missing.length === 1 ? "it" : "them"
      } in the useMemo dependency array, and ${
        missing.length === 1 ? "it is" : "they are"
      } not a useState setter or a useRef. The memoised object would keep serving the ` +
        `first value forever, and nothing in this repo can render the hook to notice.`,
    ).toEqual([]);

    const extra = [...deps].filter((d) => !fields.includes(d));
    expect(
      extra,
      `${extra.join(", ")} are listed as dependencies but are not returned. Either the field ` +
        `was dropped from the object and the array was not updated, or the array grew an entry ` +
        `that cannot affect the result.`,
    ).toEqual([]);
  });
});

describe("useDisassemblyKeyboard's handleKeyDown", () => {
  const sf = parse("useDisassemblyKeyboard.ts");
  const fn = findFunction(sf, "useDisassemblyKeyboard");

  const binding = fn.parameters[0]?.name;
  if (!binding || !ts.isObjectBindingPattern(binding)) {
    throw new Error("useDisassemblyKeyboard no longer takes a destructured argument object");
  }
  const params = binding.elements.map((el) => {
    if (!ts.isIdentifier(el.name)) throw new Error("nested destructuring is not handled here");
    return el.name.text;
  });

  const callbacks = findHookCalls(fn.body!, "useCallback");
  const callback = callbacks[callbacks.length - 1];
  const deps = new Set(depNames(callback));
  const reads = valueReads((callback.arguments[0] as ts.ArrowFunction).body);

  it("finds the handler and its array", () => {
    expect(params.length).toBeGreaterThan(20);
    expect(deps.size).toBeGreaterThan(20);
    expect(reads.has("search")).toBe(true);
  });

  it.each(params.map((p) => [p]))("declares %s, which its body reads", (param) => {
    if (!reads.has(param)) return; // covered by the dead-entry test below

    expect(
      deps.has(param),
      `handleKeyDown reads "${param}" but it is absent from the dependency array in ` +
        `src/hooks/useDisassemblyKeyboard.ts. Since the search object is memoised, that array ` +
        `is live: the handler will keep whichever "${param}" it captured when it was last ` +
        `rebuilt. That is peek-a-bin-ehv, and no test can observe it at runtime because ` +
        `nothing in this repo renders a component. Add the entry.`,
    ).toBe(true);
  });

  it("has no dead entries and no unused parameters", () => {
    const unread = params.filter((p) => !reads.has(p));
    expect(
      unread,
      `${unread.join(", ")} ${unread.length === 1 ? "is a parameter" : "are parameters"} of ` +
        `useDisassemblyKeyboard that handleKeyDown never reads. A dead entry (funcMap was one) ` +
        `costs a rebuild of the handler every time it changes identity, for nothing. Drop the ` +
        `parameter and the dependency together.`,
    ).toEqual([]);

    const deadDeps = [...deps].filter((d) => !reads.has(d));
    expect(deadDeps, `${deadDeps.join(", ")} are listed as dependencies but never read.`).toEqual(
      [],
    );
  });
});
