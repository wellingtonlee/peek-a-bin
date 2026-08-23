/**
 * THE ONE GRAMMAR for the shape of an emitted guard line, and the census that
 * makes a silent loss of the guard population impossible.
 *
 * `corpus/sweep.ts`'s polarity audit is a text scrape over the emitted C: it
 * finds every `if`/`while`/`for` header, anchors the arm to a machine block and
 * judges the condition against the originating jcc. CLAUDE.md's standing
 * warning about that whole family of audit — "they are cheap and they catch a
 * whole class of silent regression, but they encode formatting by accident;
 * write the pattern so a reformat cannot break it" — was true of it in the
 * sharpest possible way: the header regex ended `\)\s*\{\s*$`, so **an `if`
 * whose body was moved onto its own line stopped being a guard at all**. Not
 * skipped, not counted, not reported — absent. Measured at `baa7f61`, one-lining
 * only the guards whose body is a single terminator would have taken
 * **572/550/512/515 of them** (t32/t64/w64/w32) out of the scan, of which
 * 19/9/9/19 are anchored and judged today, and `polarity guards audited` would
 * have fallen with nothing saying why (peek-a-bin-vwr5).
 *
 * Two things follow, and the second is the point.
 *
 * **The grammar is depth-counted, not anchored.** The condition is read by
 * matching its own parentheses, so what follows the header is a separate
 * question from whether the header was understood — `if (f(x)) break;` and
 * `if (f(x)) {` differ in their tail and not in their condition. The previous
 * regex could not be widened in place: `/\((.*)\)\s*(.*)$/` is greedy to the
 * *last* `)` on the line, so `if (a == 0) x = f(b);` would read its condition as
 * `a == 0) x = f(b`.
 *
 * **A line this grammar cannot classify is `unparsed`, and that is a GATE at
 * 0.** The failure mode being closed is not "the audit is wrong", it is "the
 * audit is silent", and the only structural defence is to count the lines that
 * look like a guard and were not understood. So a future emitter change to any
 * of these shapes — Allman braces, a condition wrapped over two lines, a
 * one-lined `{ break; }` — is a red gate naming the line rather than a
 * population that quietly shrinks.
 *
 * WHAT IS DELIBERATELY NOT HERE. The `do { … } while (c);` back-edge tail is
 * `doTail` below and is part of the census, because it is a guard whose
 * condition the same audit judges. A function-definition header
 * (`undefinedCallees.ts`'s `DEF_HEADER`) and a `switch (` are not: neither
 * carries a condition anyone judges. `selfAssigns.ts` reads a `for` header for its
 * own reason — the clauses, which are statements a self-assignment can hide in
 * — and it asks `forHeaderCond` and `splitForHeader` below for it
 * (`peek-a-bin-hfsq`): the grammar answers what the LINE is, and what a caller
 * wants out of it stays the caller's business.
 */

/** The three top-tested constructs whose condition the polarity audit judges. */
export type GuardKw = "if" | "while" | "for";

/**
 * What an emitted line is, as far as the guard scan is concerned.
 *
 * `braced` and `inline` differ only in where the body is. `inline` has 0
 * occurrences in the corpus as emitted at `baa7f61` — `emit.ts` always opens a
 * block — so it is a bound on the grammar rather than something measured, and
 * it is pinned by `build/guardShape.test.ts` in both directions.
 */
export type GuardShape =
  | { kind: "braced"; indent: number; kw: GuardKw; cond: string }
  | { kind: "inline"; indent: number; kw: GuardKw; cond: string; body: string }
  | { kind: "doOpen"; indent: number }
  | { kind: "doTail"; indent: number; cond: string }
  | { kind: "unparsed"; indent: number; why: string };

/**
 * A guard keyword at statement position, with the optional `} else ` an
 * else-if chain puts in front of it. Anchored at the start of the line so a
 * keyword inside a comment or an expression is not a candidate.
 */
const HEAD = /^(\s*)(?:\}\s*else\s+)?(if|while|for)\s*\(/;

/** `do {` — the opener the back-edge tail below is matched back to. */
const DO_OPEN = /^(\s*)do\s*\{\s*$/;

/**
 * The `do/while` back edge. Greedy to the last `)` on the line and anchored on
 * `);`, which is exact for this shape: the tail is the whole line.
 */
const DO_TAIL = /^(\s*)\}\s*while\s*\((.*)\)\s*;\s*$/;

/** Anything that opens a block or is itself a guard, so cannot be a lone body. */
const BODY_IS_OPENER = /^(\}|\{|if\b|while\b|for\b|do\b|switch\b|__try\b|__except\b)/;

/**
 * Read one emitted line as a guard shape, or `null` if it is not guard-shaped
 * at all.
 *
 * `unparsed` is returned only for a line that *does* begin with a guard keyword
 * and an open paren — i.e. one the scan is obliged to have an opinion about.
 * Anything else is `null` and is not a candidate, which is what keeps the gate
 * from firing on ordinary statements.
 */
export function guardShape(line: string): GuardShape | null {
  const mDoOpen = DO_OPEN.exec(line);
  if (mDoOpen) return { kind: "doOpen", indent: mDoOpen[1].length };

  const mDoTail = DO_TAIL.exec(line);
  if (mDoTail) return { kind: "doTail", indent: mDoTail[1].length, cond: mDoTail[2] };

  const head = HEAD.exec(line);
  if (!head) return null;
  const indent = head[1].length;
  const kw = head[2] as GuardKw;

  // The condition is bounded by ITS OWN parentheses. A greedy match to the last
  // `)` on the line is what makes the tail unreadable, so depth is counted from
  // the open paren the head consumed.
  let depth = 0;
  let close = -1;
  for (let i = head[0].length - 1; i < line.length; i++) {
    const c = line[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close < 0) return { kind: "unparsed", indent, why: `${kw}-unbalanced-condition` };

  const cond = line.slice(head[0].length, close);
  const tail = line.slice(close + 1).trim();
  if (tail === "{") return { kind: "braced", indent, kw, cond };
  if (tail === "") return { kind: "unparsed", indent, why: `${kw}-header-without-body` };
  // A lone statement on the guard's own line. It must be a whole statement —
  // `if (c) { break; }` carries a brace and is refused, because a body inside a
  // block on one line is a shape this grammar does not model and guessing at it
  // is how a wrong anchor gets produced.
  if (
    !tail.includes("{") &&
    !tail.includes("}") &&
    tail.endsWith(";") &&
    !BODY_IS_OPENER.test(tail)
  )
    return { kind: "inline", indent, kw, cond, body: tail };
  return { kind: "unparsed", indent, why: `${kw}-unrecognised-tail` };
}

/**
 * The statement a line carries, for a scan looking for a STATEMENT rather than
 * for a guard.
 *
 * `if (c) break;` IS a break, and every emitted-C scrape that anchors a
 * terminator at the start of a line stops seeing it the moment a guard is
 * one-lined. Two such scrapes exist and they fail in opposite directions, which
 * is why they both read this one rule rather than each their own: `sweep.ts`'s
 * loop-exit counter would report the exit missing and go RED on correct output
 * (measured at `baa7f61`: 31/32/33/32 loops falsely short on t32/t64/w64/w32),
 * while `emitAudits.ts`'s `gotoCheck` would report 0 dangling gotos out of a
 * population it no longer sees — a gate at 0 passing because it stopped
 * looking, which is the worse of the two (peek-a-bin-vwr5).
 *
 * A braced body is unaffected: with no inline guard on the line this is exactly
 * `line.trim()`, which is what makes wiring it in output-neutral.
 */
export function statementOnLine(line: string): string {
  const shape = guardShape(line);
  return shape !== null && shape.kind === "inline" ? shape.body : line.trim();
}

/**
 * The three clauses of a `for` header, from the condition text `guardShape`
 * returned — `[init, cond, update]`, each with its own whitespace and no
 * trailing semicolon, or null if the header does not hold exactly two top-level
 * `;`.
 *
 * It lives here rather than in either caller because both want it for their own
 * reason and neither is entitled to its own answer: `sweep.ts` judges the middle
 * clause against a jcc, and `selfAssigns.ts` reads the init and the update as
 * statements. `emit.ts` always writes all three, so null is a refusal rather
 * than a shape — and both callers count it, because a clause silently not read
 * is a row leaving a scan.
 *
 * Depth is counted on parentheses only. A `;` cannot occur inside `[...]` in a C
 * expression, so tracking brackets as well would change no answer.
 */
export function splitForHeader(cond: string): [string, string, string] | null {
  let depth = 0;
  const cuts: number[] = [];
  for (let i = 0; i < cond.length; i++) {
    const c = cond[i];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === ";" && depth === 0) cuts.push(i);
  }
  if (cuts.length !== 2) return null;
  return [cond.slice(0, cuts[0]), cond.slice(cuts[0] + 1, cuts[1]), cond.slice(cuts[1] + 1)];
}

/**
 * A `for` header's condition text, of either spelling, or null if the line is
 * not one.
 *
 * A named predicate so that no caller has to re-spell
 * `kind === "braced" && kw === "for"` — which is exactly the shape
 * `selfAssigns.ts` had hand-rolled as `/^\s*for \((.*)\) \{\s*$/`, a pattern
 * that also encoded single-space formatting and a trailing brace and would have
 * gone silent on either.
 */
export function forHeaderCond(shape: GuardShape | null): string | null {
  if (shape === null) return null;
  if (shape.kind !== "braced" && shape.kind !== "inline") return null;
  return shape.kw === "for" ? shape.cond : null;
}

/**
 * The census the gate reads.
 *
 * `topTested` and `doTail` are the liveness halves: a text-scraping audit fails
 * by silently matching nothing, so a run in which either is 0 is not a clean
 * run, it is a run that saw no guards. `unparsed` is the gate.
 */
export interface GuardShapeCensus {
  /** Braced `if`/`while`/`for` headers — the shape `emit.ts` produces today. */
  topTested: number;
  /** Brace-less ones, body on the guard's own line. 0 as emitted at `baa7f61`. */
  inline: number;
  /** `} while (c);` back edges. */
  doTail: number;
  /** Guard-keyword lines the grammar refused. GATED at 0. */
  unparsed: number;
  /** Up to a few refused lines, verbatim, so a red gate names its own cause. */
  unparsedDetail: string[];
}

export function emptyGuardShapeCensus(): GuardShapeCensus {
  return { topTested: 0, inline: 0, doTail: 0, unparsed: 0, unparsedDetail: [] };
}

const MAX_UNPARSED_DETAIL = 20;

/** Fold one line's shape into the census. */
export function noteGuardShape(
  census: GuardShapeCensus,
  shape: GuardShape | null,
  where: string,
  line: string,
): void {
  if (shape === null) return;
  if (shape.kind === "braced") census.topTested++;
  else if (shape.kind === "inline") census.inline++;
  else if (shape.kind === "doTail") census.doTail++;
  else if (shape.kind === "unparsed") {
    census.unparsed++;
    if (census.unparsedDetail.length < MAX_UNPARSED_DETAIL)
      census.unparsedDetail.push(`${where}: ${shape.why}: ${line.trim()}`);
  }
}
