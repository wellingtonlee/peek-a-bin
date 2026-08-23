import type { IRStmt } from "./ir";
import { rewriteBodies } from "./ir";
import { RegState } from "./regstate";

/**
 * Post-structuring cleanup pass.
 * Applied after structureCFG, before inferTypes.
 *
 * - Guard clause flattening: if (cond) { ...; return; } else { rest } → if (cond) { ...; return; } rest
 * - Redundant goto elimination: goto L; L: → remove goto
 * - Empty block elimination: if (cond) {} → remove; if (cond) {} else { body } → if (!cond) { body }
 * - Loop exit spelling: goto L inside a loop that L immediately follows → break
 * - Loop tail: if (c) { continue; } break; → if (!c) { break; }
 */
export function cleanupStructured(body: IRStmt[]): IRStmt[] {
  let result = body;
  // Run cleanup passes until stable (max 5 iterations for deeply nested guards)
  for (let i = 0; i < 5; i++) {
    const prev = result;
    result = cleanupPass(result);
    if (result.length === prev.length && result.every((s, j) => s === prev[j])) break;
  }
  return giveTrailingLabelsAStatement(collapseLoopTailContinue(breakForwardGotos(result)));
}

/**
 * A `goto` out of a loop to the label the loop is immediately followed by is
 * `break`.
 *
 * `structure.ts` names every loop exit with a `goto`, because a loop can leave
 * to several different places and only one of them is where `break` lands — the
 * statement after the loop. Where the target *is* that statement the two say
 * the same thing, and `break` is the one a reader can follow without scrolling.
 * This is a change of spelling and nothing else: the label stays, so any other
 * `goto` aimed at it still works, and a target that is not the loop's own
 * continuation keeps its `goto`.
 *
 * `break` binds to the nearest enclosing loop *or switch*, so the rewrite stops
 * at any of them — a `goto` from inside a nested loop names the outer one's
 * exit and cannot be spelled `break` there.
 */
function breakForwardGotos(stmts: IRStmt[]): IRStmt[] {
  return stmts.map((stmt, i) => {
    if (stmt.kind === "while" || stmt.kind === "do_while" || stmt.kind === "for") {
      const next = stmts[i + 1];
      const body = breakForwardGotos(stmt.body);
      return { ...stmt, body: next?.kind === "label" ? gotoToBreak(body, next.name) : body };
    }
    return rewriteBodies(stmt, breakForwardGotos);
  });
}

/**
 * `if (c) { continue; } break;` at the bottom of a loop body → `if (!c) { break; }`.
 *
 * `structure.ts`'s `armFrom` gives a body-bottom conditional both of its arms —
 * `continue` for the back edge and `break`/`goto` for the exit — and the two
 * together make the reader hold both in mind to learn one thing. 137 pairs over
 * the four corpus binaries at `f3b89ec` (33/38/35/31 on t32/t64/w64/w32, of
 * which 26/26/25/24 close with `break` and 7/12/10/7 with a `goto`); 135 of
 * them are collapsed here.
 *
 * Cosmetic, and identical in every loop construct: `continue` and falling off
 * the end of the body both reach the back edge — the update then the test in a
 * `for`, the test in a `while` or `do/while` — so swapping the arms and negating
 * states the same program. Four restrictions carry that, and none is decoration:
 *
 * - **The pair must be the last two statements of a LOOP's own body.** In a
 *   `switch` arm `break` leaves the switch and falling off the end of the arm
 *   falls into the next case, which is a different program; inside a nested
 *   `if` the fallthrough is the rest of the loop body rather than the back edge.
 *   So this walks loops explicitly rather than going through `rewriteBodies`,
 *   which would hand it every body in the tree.
 * - **The `if` takes no `else` and its `then` is exactly one `continue`.**
 *   `if (c) { S; continue; }` needs `S` moved, which is a different rewrite.
 * - **The negation must be a FLIPPED COMPARISON**, never a `!`-wrapping.
 *   `RegState.negate` falls back to `irUnary("!", …)` for anything it cannot
 *   flip, so `if (!!__unrecovered_1)` would become `if (!!!__unrecovered_1)` —
 *   which states the test less directly than the two-armed form it replaces.
 *   One site per PE32 binary is refused on that ground, and that is the whole
 *   137 → 135 residue. `&&`/`||` are refused too: De Morgan is correct and
 *   harder to read, and there are 0 of them here.
 * - **The exit arm keeps its own spelling.** A `break` stays a `break` and a
 *   `goto L` stays a `goto L`; this pass moves a statement and negates a
 *   condition and decides nothing about either.
 *
 * It runs after `breakForwardGotos`, or a quarter of the population (7/12/10/7)
 * is still spelled `goto` and is missed. The braces stay: an `if` whose body is a single terminator is emitted
 * braced everywhere in this output, `corpus/sweep.ts`'s guard scan requires the
 * `{` to see an `if` at all, and one-lining the shape in `emit.ts` would take
 * all 2077 such guards out of that scan for a rule this pass has no business
 * deciding (peek-a-bin-252).
 */
function collapseLoopTailContinue(stmts: IRStmt[]): IRStmt[] {
  return stmts.map((stmt) => {
    if (stmt.kind === "while" || stmt.kind === "do_while" || stmt.kind === "for") {
      return { ...stmt, body: collapseTail(collapseLoopTailContinue(stmt.body)) };
    }
    return rewriteBodies(stmt, collapseLoopTailContinue);
  });
}

/** The rewrite itself, applied to one loop body's statement list. */
function collapseTail(body: IRStmt[]): IRStmt[] {
  if (body.length < 2) return body;
  const guard = body[body.length - 2];
  const exit = body[body.length - 1];
  if (guard.kind !== "if" || (guard.elseBody?.length ?? 0) !== 0) return body;
  if (guard.thenBody.length !== 1 || guard.thenBody[0].kind !== "continue") return body;
  if (exit.kind !== "break" && exit.kind !== "goto") return body;
  const negated = RegState.negate(guard.condition);
  // A flipped comparison, not a `!`-wrapping — see the docstring.
  if (negated.kind !== "binary" || negated.op === "&&" || negated.op === "||") return body;
  return [...body.slice(0, body.length - 2), { kind: "if", condition: negated, thenBody: [exit] }];
}

/** Replace `goto label` with `break`, not descending into anything `break` would bind to. */
function gotoToBreak(stmts: IRStmt[], label: string): IRStmt[] {
  return stmts.map((stmt) => {
    if (stmt.kind === "goto" && stmt.label === label) return { kind: "break" };
    if (
      stmt.kind === "while" ||
      stmt.kind === "do_while" ||
      stmt.kind === "for" ||
      stmt.kind === "switch"
    ) {
      return stmt;
    }
    return rewriteBodies(stmt, (list) => gotoToBreak(list, label));
  });
}

/**
 * A label at the end of a block needs something to label.
 *
 * `structure.ts` puts a label in front of the statements of any block a `goto`
 * reaches, and that block may lift to nothing, or be the last thing in an arm;
 * the passes above can also remove whatever followed one (an `if` with an empty
 * body goes away entirely). C89 has no statement there to attach the label to —
 * `foo: }` is a syntax error, not a warning — so an empty statement is added.
 * Dropping the label instead would strand every `goto` aimed at it.
 */
function giveTrailingLabelsAStatement(stmts: IRStmt[]): IRStmt[] {
  const out = stmts.map((s) => rewriteBodies(s, giveTrailingLabelsAStatement));
  if (out.length > 0 && out[out.length - 1].kind === "label") out.push({ kind: "raw", text: "" });
  return out;
}

function cleanupPass(stmts: IRStmt[]): IRStmt[] {
  const result: IRStmt[] = [];

  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i];

    // Redundant goto elimination: goto L; L: → remove goto
    if (stmt.kind === "goto" && i + 1 < stmts.length) {
      const next = stmts[i + 1];
      if (next.kind === "label" && next.name === stmt.label) {
        continue; // skip the goto
      }
    }

    // Process if statements
    if (stmt.kind === "if") {
      const cleaned = cleanupIf(stmt, stmts.slice(i + 1));
      if (cleaned) {
        result.push(...cleaned.stmts);
        i += cleaned.consumed; // skip consumed trailing statements
        continue;
      }
    }

    // Recurse into compound statements
    result.push(rewriteBodies(stmt, cleanupPass));
  }

  return result;
}

function cleanupIf(
  stmt: IRStmt & { kind: "if" },
  _trailing: IRStmt[],
): { stmts: IRStmt[]; consumed: number } | null {
  const thenBody = cleanupPass(stmt.thenBody);
  const elseBody = stmt.elseBody ? cleanupPass(stmt.elseBody) : undefined;

  // Empty then block elimination
  if (thenBody.length === 0) {
    if (elseBody && elseBody.length > 0) {
      // if (cond) {} else { body } → if (!cond) { body }
      return {
        stmts: [{ kind: "if", condition: RegState.negate(stmt.condition), thenBody: elseBody }],
        consumed: 0,
      };
    }
    // if (cond) {} → remove entirely
    return { stmts: [], consumed: 0 };
  }

  // Guard clause flattening: if (cond) { ...; return; } else { rest } → if (cond) { ...; return; } rest
  if (elseBody && elseBody.length > 0 && endsWithTerminator(thenBody)) {
    // Recursively clean the flattened result to handle nested guards
    const flatResult = cleanupPass([
      { kind: "if", condition: stmt.condition, thenBody },
      ...elseBody,
    ]);
    return {
      stmts: flatResult,
      consumed: 0,
    };
  }

  // No special cleanup, but pass through cleaned bodies
  return {
    stmts: [{ ...stmt, thenBody, elseBody }],
    consumed: 0,
  };
}

function endsWithTerminator(stmts: IRStmt[]): boolean {
  if (stmts.length === 0) return false;
  const last = stmts[stmts.length - 1];
  return (
    last.kind === "return" ||
    last.kind === "break" ||
    last.kind === "continue" ||
    last.kind === "goto"
  );
}
