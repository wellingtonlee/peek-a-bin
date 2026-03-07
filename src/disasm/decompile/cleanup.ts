import type { IRStmt } from './ir';
import { RegState } from './regstate';

/**
 * Post-structuring cleanup pass.
 * Applied after structureCFG, before inferTypes.
 *
 * - Guard clause flattening: if (cond) { ...; return; } else { rest } → if (cond) { ...; return; } rest
 * - Redundant goto elimination: goto L; L: → remove goto
 * - Empty block elimination: if (cond) {} → remove; if (cond) {} else { body } → if (!cond) { body }
 */
export function cleanupStructured(body: IRStmt[]): IRStmt[] {
  let result = body;
  // Run cleanup passes until stable (max 5 iterations for deeply nested guards)
  for (let i = 0; i < 5; i++) {
    const prev = result;
    result = cleanupPass(result);
    if (result.length === prev.length && result.every((s, j) => s === prev[j])) break;
  }
  return result;
}

function cleanupPass(stmts: IRStmt[]): IRStmt[] {
  let result: IRStmt[] = [];

  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i];

    // Redundant goto elimination: goto L; L: → remove goto
    if (stmt.kind === 'goto' && i + 1 < stmts.length) {
      const next = stmts[i + 1];
      if (next.kind === 'label' && next.name === stmt.label) {
        continue; // skip the goto
      }
    }

    // Process if statements
    if (stmt.kind === 'if') {
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
  stmt: IRStmt & { kind: 'if' },
  trailing: IRStmt[],
): { stmts: IRStmt[]; consumed: number } | null {
  const thenBody = cleanupPass(stmt.thenBody);
  const elseBody = stmt.elseBody ? cleanupPass(stmt.elseBody) : undefined;

  // Empty then block elimination
  if (thenBody.length === 0) {
    if (elseBody && elseBody.length > 0) {
      // if (cond) {} else { body } → if (!cond) { body }
      return {
        stmts: [{ kind: 'if', condition: RegState.negate(stmt.condition), thenBody: elseBody }],
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
      { kind: 'if', condition: stmt.condition, thenBody },
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
  return last.kind === 'return' || last.kind === 'break' || last.kind === 'continue' || last.kind === 'goto';
}

function cleanupStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case 'if':
      return {
        ...stmt,
        thenBody: cleanupPass(stmt.thenBody),
        elseBody: stmt.elseBody ? cleanupPass(stmt.elseBody) : undefined,
      };
    case 'while':
      return { ...stmt, body: cleanupPass(stmt.body) };
    case 'do_while':
      return { ...stmt, body: cleanupPass(stmt.body) };
    case 'for':
      return { ...stmt, body: cleanupPass(stmt.body) };
    case 'switch':
      return {
        ...stmt,
        cases: stmt.cases.map(c => ({ ...c, body: cleanupPass(c.body) })),
        defaultBody: stmt.defaultBody ? cleanupPass(stmt.defaultBody) : undefined,
      };
    case 'try':
      return { ...stmt, body: cleanupPass(stmt.body), handler: cleanupPass(stmt.handler) };
    default:
      return stmt;
  }
}
