import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  emptyGuardShapeCensus,
  guardShape,
  noteGuardShape,
} from "../corpus/guardShape";

/**
 * `guardShape` is the one grammar `corpus/sweep.ts`'s polarity audit reads a
 * guard line with, and it is corpus-only — the binaries are not in the repo —
 * so these tests pin its RULE on synthetic input, in the manner of
 * `caseBodyAudit.test.ts` beside them.
 *
 * They matter more than most, because the thing being closed is an audit that
 * fails SILENTLY. The header pattern this replaces ended `\)\s*\{\s*$`, so an
 * `if` whose body moved onto the header's own line stopped being a guard at all
 * — not skipped, not counted, absent — and the only trace would have been
 * `polarity guards audited` falling. Measured at `baa7f61`, one-lining the
 * guards whose body is a single terminator alone would have removed
 * 572/550/512/515 of them on t32/t64/w64/w32 (peek-a-bin-vwr5).
 *
 * Three groups, and the middle one is where the work is:
 *   - the shapes `emit.ts` produces today, which must read exactly as before;
 *   - the brace-less shape, which has 0 corpus occurrences and is therefore
 *     pinned HERE or nowhere;
 *   - the refusals, each of which is what makes the gate at 0 mean something.
 */
describe("guardShape", () => {
  describe("the shapes emit.ts produces today", () => {
    it("reads a braced if", () => {
      expect(guardShape("    if (eax == 0) {")).toEqual({
        kind: "braced",
        indent: 4,
        kw: "if",
        cond: "eax == 0",
      });
    });

    it("reads a braced while and for", () => {
      expect(guardShape("        while (ecx != 0) {")).toEqual({
        kind: "braced",
        indent: 8,
        kw: "while",
        cond: "ecx != 0",
      });
      expect(guardShape("    for (eax = 0; eax < 8; eax++) {")).toEqual({
        kind: "braced",
        indent: 4,
        kw: "for",
        cond: "eax = 0; eax < 8; eax++",
      });
    });

    it("reads the else-if chain the emitter writes on one line", () => {
      expect(guardShape("    } else if (eax > 5) {")).toEqual({
        kind: "braced",
        indent: 4,
        kw: "if",
        cond: "eax > 5",
      });
    });

    it("reads the do/while opener and its back edge", () => {
      expect(guardShape("    do {")).toEqual({ kind: "doOpen", indent: 4 });
      expect(guardShape("    } while (eax != 0);")).toEqual({
        kind: "doTail",
        indent: 4,
        cond: "eax != 0",
      });
    });

    /**
     * A bare `} else {` opens a block with no condition, so there is nothing for
     * the polarity audit to judge and it must not be a candidate — counting it
     * as `unparsed` would put the gate permanently red.
     */
    it("is silent about a bare else, a switch and a function header", () => {
      expect(guardShape("    } else {")).toBeNull();
      expect(guardShape("    switch (eax) {")).toBeNull();
      expect(guardShape("int sub_401000(int32_t arg_0) {")).toBeNull();
      expect(guardShape("        eax = sub_401DA4();")).toBeNull();
    });

    /**
     * The keyword must be at statement position. `emit.ts` writes a comment as
     * `// text`, and `commentSafe` does not strip a `if (` out of the text, so a
     * comment mentioning one would otherwise be a candidate the gate fires on.
     */
    it("is silent about a guard keyword inside a comment or an expression", () => {
      expect(guardShape("    // if (eax == 0) skipped")).toBeNull();
      expect(guardShape("    eax = notif (0);")).toBeNull();
    });
  });

  describe("the brace-less shape, which has no corpus occurrence", () => {
    it("reads a one-lined terminator body", () => {
      for (const body of ["break;", "continue;", "goto loc_401234;", "return eax;", "return;"]) {
        expect(guardShape(`        if (eax == 0) ${body}`)).toEqual({
          kind: "inline",
          indent: 8,
          kw: "if",
          cond: "eax == 0",
          body,
        });
      }
    });

    it("reads a one-lined loop body", () => {
      expect(guardShape("    while (eax != 0) eax--;")).toEqual({
        kind: "inline",
        indent: 4,
        kw: "while",
        cond: "eax != 0",
        body: "eax--;",
      });
    });

    /**
     * THE REASON THE CONDITION IS DEPTH-COUNTED. Widening the old pattern in
     * place — `/\((.*)\)\s*(.*)$/` — is greedy to the LAST `)` on the line, so
     * this reads as the condition `a == 0) x = f(b` and a body of `;`. A wrong
     * condition is a wrong verdict, which is worse than the silence being fixed.
     */
    it("bounds the condition by its own parentheses, not the last one on the line", () => {
      expect(guardShape("    if (eax == 0) ebx = sub_401000(ecx);")).toEqual({
        kind: "inline",
        indent: 4,
        kw: "if",
        cond: "eax == 0",
        body: "ebx = sub_401000(ecx);",
      });
      expect(guardShape("    if (sub_401000(ecx) == 0) break;")).toEqual({
        kind: "inline",
        indent: 4,
        kw: "if",
        cond: "sub_401000(ecx) == 0",
        body: "break;",
      });
    });

    it("keeps a nested condition intact in the braced shape too", () => {
      expect(guardShape("    if ((eax & 0xFF) == 0 && sub_1(ecx) != 0) {")).toEqual({
        kind: "braced",
        indent: 4,
        kw: "if",
        cond: "(eax & 0xFF) == 0 && sub_1(ecx) != 0",
      });
    });
  });

  describe("the refusals, which are what the gate at 0 is for", () => {
    it("refuses a header whose body is on the next line", () => {
      expect(guardShape("    if (eax == 0)")).toEqual({
        kind: "unparsed",
        indent: 4,
        why: "if-header-without-body",
      });
    });

    it("refuses a condition wrapped over two lines", () => {
      expect(guardShape("    if (eax == 0 &&")).toEqual({
        kind: "unparsed",
        indent: 4,
        why: "if-unbalanced-condition",
      });
    });

    /**
     * `if (c) { break; }` is a body inside a block on one line. The grammar does
     * not model it, and guessing — reading `{ break; }` as the body — is how a
     * wrong anchor is produced, so it is refused loudly instead.
     */
    it("refuses a whole block on one line", () => {
      expect(guardShape("    if (eax == 0) { break; }")).toEqual({
        kind: "unparsed",
        indent: 4,
        why: "if-unrecognised-tail",
      });
    });

    it("refuses a tail that is not a whole statement", () => {
      expect(guardShape("    if (eax == 0) break")).toEqual({
        kind: "unparsed",
        indent: 4,
        why: "if-unrecognised-tail",
      });
    });

    /** A body that is itself a guard is not a lone statement this can anchor. */
    it("refuses a nested guard as an inline body", () => {
      expect(guardShape("    if (eax == 0) if (ebx == 0) break;")).toEqual({
        kind: "unparsed",
        indent: 4,
        why: "if-unrecognised-tail",
      });
    });
  });

  describe("the census", () => {
    it("counts each shape and names every refusal", () => {
      const c = emptyGuardShapeCensus();
      for (const line of [
        "    if (eax == 0) {",
        "    while (ecx != 0) {",
        "    if (eax == 0) break;",
        "    } while (edx != 0);",
        "    if (eax == 0)",
        "        eax = 1;",
      ])
        noteGuardShape(c, guardShape(line), "sub_1", line);
      expect(c.topTested).toBe(2);
      expect(c.inline).toBe(1);
      expect(c.doTail).toBe(1);
      expect(c.unparsed).toBe(1);
      expect(c.unparsedDetail).toEqual(["sub_1: if-header-without-body: if (eax == 0)"]);
    });

    /**
     * A red gate must name its own cause, but a run in which the emitter changed
     * shape produces thousands of rows. The detail is capped and the COUNT is
     * not, so the gate can never be satisfied by the list being empty.
     */
    it("caps the detail without capping the count", () => {
      const c = emptyGuardShapeCensus();
      for (let i = 0; i < 50; i++) {
        const line = `    if (eax == ${i})`;
        noteGuardShape(c, guardShape(line), "sub_1", line);
      }
      expect(c.unparsed).toBe(50);
      expect(c.unparsedDetail).toHaveLength(20);
    });
  });
});

/**
 * A DRIFT GUARD, in the manner of `capstoneWindow.test.ts`'s `.disasm(` scan.
 *
 * The value of one grammar is entirely that there is one: a second hand-rolled
 * guard-header pattern somewhere under `corpus/` can disagree with this one
 * about what a guard line is, and then the census says the population is intact
 * while some audit reads a different one. The tell is a regex alternation of two
 * or more guard keywords — no ordinary TypeScript contains `if|while` — which is
 * what every previous copy of this pattern in `sweep.ts` was spelled with.
 *
 * `selfAssigns.ts`'s `FOR_HEADER` is deliberately NOT caught by this: it names
 * one keyword, reads a `for` header for its own reason (the update clause), and
 * has the same brittleness with no census behind it. Widening it as a side
 * effect of this change was refused; it is recorded in CLAUDE.md instead.
 */
describe("one grammar", () => {
  it("is the only place under corpus/ that alternates guard keywords", () => {
    const dir = new URL("../corpus/", import.meta.url);
    const offenders: string[] = [];
    for (const name of readdirSync(dir)) {
      if (name === "guardShape.ts") continue;
      if (!/\.(ts|mjs)$/.test(name)) continue;
      const src = readFileSync(new URL(name, dir), "utf8");
      for (const alt of ["if|while", "while|for", "if|for", "while|if", "for|while"])
        if (src.includes(alt)) offenders.push(`${name}: ${alt}`);
    }
    expect(offenders).toEqual([]);
  });
});
