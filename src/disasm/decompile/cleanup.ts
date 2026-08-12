import type { IRStmt } from "./ir";
import { RegState } from "./regstate";

/**
 * Post-structuring cleanup pass.
 * Applied after structureCFG, before inferTypes.
 *
 * - Guard clause flattening: if (cond) { ...; return; } else { rest } → if (cond) { ...; return; } rest
 * - Redundant goto elimination: goto L; L: → remove goto
 * - Empty block elimination: if (cond) {} → remove; if (cond) {} else { body } → if (!cond) { body }
 * - Loop exit spelling: goto L inside a loop that L immediately follows → break
 */
export function cleanupStructured(body: IRStmt[]): IRStmt[] {
  let result = body;
  // Run cleanup passes until stable (max 5 iterations for deeply nested guards)
  for (let i = 0; i < 5; i++) {
    const prev = result;
    result = cleanupPass(result);
    if (result.length === prev.length && result.every((s, j) => s === prev[j])) break;
  }
  return giveTrailingLabelsAStatement(breakForwardGotos(result));
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

/** Rebuild `stmt` with `f` applied to each of its nested statement lists. */
function rewriteBodies(stmt: IRStmt, f: (list: IRStmt[]) => IRStmt[]): IRStmt {
  switch (stmt.kind) {
    case "if":
      return { ...stmt, thenBody: f(stmt.thenBody), elseBody: stmt.elseBody && f(stmt.elseBody) };
    case "while":
    case "do_while":
    case "for":
      return { ...stmt, body: f(stmt.body) };
    case "switch":
      return {
        ...stmt,
        cases: stmt.cases.map((c) => ({ ...c, body: f(c.body) })),
        defaultBody: stmt.defaultBody && f(stmt.defaultBody),
      };
    case "try":
      return { ...stmt, body: f(stmt.body), handler: f(stmt.handler) };
    default:
      return stmt;
  }
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
  const out = stmts.map((s) => repairStmt(s));
  if (out.length > 0 && out[out.length - 1].kind === "label") out.push({ kind: "raw", text: "" });
  return out;
}

function repairStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case "if":
      return {
        ...stmt,
        thenBody: giveTrailingLabelsAStatement(stmt.thenBody),
        elseBody: stmt.elseBody ? giveTrailingLabelsAStatement(stmt.elseBody) : undefined,
      };
    case "while":
    case "do_while":
    case "for":
      return { ...stmt, body: giveTrailingLabelsAStatement(stmt.body) };
    case "switch":
      return {
        ...stmt,
        cases: stmt.cases.map((c) => ({ ...c, body: giveTrailingLabelsAStatement(c.body) })),
        defaultBody: stmt.defaultBody ? giveTrailingLabelsAStatement(stmt.defaultBody) : undefined,
      };
    case "try":
      return {
        ...stmt,
        body: giveTrailingLabelsAStatement(stmt.body),
        handler: giveTrailingLabelsAStatement(stmt.handler),
      };
    default:
      return stmt;
  }
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
    result.push(cleanupStmt(stmt));
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

function cleanupStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case "if":
      return {
        ...stmt,
        thenBody: cleanupPass(stmt.thenBody),
        elseBody: stmt.elseBody ? cleanupPass(stmt.elseBody) : undefined,
      };
    case "while":
      return { ...stmt, body: cleanupPass(stmt.body) };
    case "do_while":
      return { ...stmt, body: cleanupPass(stmt.body) };
    case "for":
      return { ...stmt, body: cleanupPass(stmt.body) };
    case "switch":
      return {
        ...stmt,
        cases: stmt.cases.map((c) => ({ ...c, body: cleanupPass(c.body) })),
        defaultBody: stmt.defaultBody ? cleanupPass(stmt.defaultBody) : undefined,
      };
    case "try":
      return { ...stmt, body: cleanupPass(stmt.body), handler: cleanupPass(stmt.handler) };
    default:
      return stmt;
  }
}
