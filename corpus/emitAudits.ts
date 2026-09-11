/**
 * The audits that read only the emitted C, and hand it to a compiler.
 *
 * These are the ones with an oracle genuinely outside this repo: gcc decides
 * whether the C parses, and a program that is compiled AND RUN decides where a
 * struct's fields actually land. Everything else in the corpus set is this
 * project checking its own output against its own disassembly.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { statementOnLine } from "./guardShape";
import type { FuncRec } from "./sweep";

/**
 * Registers, imported APIs and Win32 typedefs are things the decompiler
 * deliberately does not declare, so declaring them is not papering over a
 * defect — anything gcc still objects to after that is a defect in the emitted
 * C. `__try`/`__except` are MSVC extensions gcc has no notion of.
 */
const CC_HEADER = `#include <stdint.h>
#define __try
#define __except(x) if (0)
`;

/** The typedefs the emitted C expects its reader to supply, at Windows widths. */
const OFFSETOF_PRELUDE = `#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
typedef void *PVOID;
typedef void *HANDLE;
typedef int BOOL;
typedef int32_t NTSTATUS;
typedef int32_t HRESULT;
typedef unsigned short wchar_t_;
#define wchar_t wchar_t_
`;

export interface CcResult {
  /** Functions with a non-empty body that were handed to the compiler. */
  compiled: number;
  clean: number;
  /** Failure counts by category, most common first. */
  byCategory: { category: string; n: number; examples: string[] }[];
}

interface Diag {
  msg: string;
}

function compileOnly(cc: string, file: string): Diag[] {
  try {
    execFileSync(cc, ["-std=gnu89", "-fsyntax-only", "-w", file], {
      stdio: "pipe",
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
    });
    return [];
  } catch (e) {
    const err = String((e as { stderr?: Buffer }).stderr ?? "");
    const diags: Diag[] = [];
    for (const line of err.split("\n")) {
      const m = /^[^:]+:\d+:\d+: error: (.*)$/.exec(line);
      if (m) diags.push({ msg: m[1] });
    }
    // A compiler that failed without an "error:" line failed for a reason we
    // must not silently read as success.
    if (diags.length === 0)
      diags.push({ msg: `compiler failed with no parseable error: ${err.slice(0, 200)}` });
    return diags;
  }
}

/** Declarations gcc's own complaints ask for. Null when it cannot help. */
function preludeFor(diags: Diag[]): string | null {
  const decls: string[] = [];
  for (const d of diags) {
    let m = /^unknown type name '([A-Za-z_]\w*)'/.exec(d.msg);
    if (m) {
      decls.push(`typedef long ${m[1]};`);
      continue;
    }
    m = /^'([A-Za-z_]\w*)' undeclared/.exec(d.msg);
    if (m) {
      decls.push(`long ${m[1]};`);
      continue;
    }
    m = /^implicit declaration of function '([A-Za-z_]\w*)'/.exec(d.msg);
    if (m) decls.push(`long ${m[1]}();`);
  }
  return decls.length > 0 ? [...new Set(decls)].join("\n") : null;
}

function categorise(msg: string): string {
  if (/^label '[^']+' used but not defined/.test(msg)) return "dangling goto (label undefined)";
  if (/flexible array member not at end of struct/.test(msg))
    return "flexible array member not at end";
  if (/flexible array member in a struct with no named members/.test(msg))
    return "flexible array member sole member";
  if (/^redefinition of/.test(msg)) return "redefinition";
  if (/^expected /.test(msg)) return "syntax (expected ...)";
  if (/lvalue required/.test(msg)) return "lvalue required";
  if (/^duplicate label/.test(msg)) return "duplicate label";
  return msg.replace(/'[^']*'/g, "'…'").slice(0, 70);
}

/**
 * `cc -std=gnu89 -fsyntax-only` over every emitted function.
 *
 * A failure here means the decompiler emitted something that is not C. Note
 * what this does NOT mean: "clean" is not "recovered" — a large share of these
 * functions compile precisely because the emitter NAMES what it failed to
 * recover, with an `__unrecovered_N` or an "unlifted" comment, instead of
 * printing something plausible.
 */
export function ccSyntaxCheck(
  cc: string,
  workDir: string,
  sets: { tag: string; funcs: FuncRec[] }[],
): CcResult {
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });

  const byCategory = new Map<string, { n: number; examples: string[] }>();
  let compiled = 0;
  let clean = 0;

  for (const { tag, funcs } of sets) {
    for (const r of funcs) {
      const code = r.code;
      if (!code || /^\/\/ /.test(code)) continue;
      compiled++;
      const file = join(workDir, `${tag}_${r.addr.toString(16)}.c`);
      let prelude = "";
      let diags: Diag[] = [];
      // Up to five rounds: each one declares what the previous round's
      // complaints named, which can itself reveal the next layer.
      for (let round = 0; round < 5; round++) {
        writeFileSync(file, `${CC_HEADER}${prelude}\n${code}\n`);
        diags = compileOnly(cc, file);
        if (diags.length === 0) break;
        const more = preludeFor(diags);
        if (!more) break;
        prelude = `${prelude}${more}\n`;
      }
      if (diags.length === 0) {
        clean++;
        continue;
      }
      for (const d of diags) {
        const cat = categorise(d.msg);
        const e = byCategory.get(cat) ?? { n: 0, examples: [] };
        e.n++;
        if (e.examples.length < 3) e.examples.push(`${tag}:0x${r.addr.toString(16)}`);
        byCategory.set(cat, e);
      }
    }
  }

  return {
    compiled,
    clean,
    byCategory: [...byCategory]
      .map(([category, e]) => ({ category, n: e.n, examples: e.examples }))
      .sort((a, b) => b.n - a.n),
  };
}

export interface OffsetofResult {
  /** Struct definitions seen, counted once per distinct preamble. */
  defs: number;
  defsCorrect: number;
  uncompilable: number;
  fields: number;
  fieldsCorrect: number;
  /** Distinct (tag, id, body) definitions, and how many lay out correctly. */
  distinctDefs: number;
  distinctCorrect: number;
  bad: string[];
}

interface StructDef {
  id: string;
  body: string;
  /**
   * `array` is whether the declaration carries `[...]`, which is a different
   * statement from what the *name* says — see `memberNameAgreement`. It is read
   * here so the two audits cannot end up with different denominators.
   */
  fields: { name: string; offset: number; array: boolean }[];
}

/** Everything the emitter put above the function definition line. */
function preambleOf(code: string): string {
  const lines = code.split("\n");
  const at = lines.findIndex((l) => /^\S.*\)\s*\{$/.test(l));
  return at < 0 ? "" : lines.slice(0, at).join("\n");
}

function defsIn(preamble: string): StructDef[] {
  const defs: StructDef[] = [];
  const lines = preamble.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^struct (struct_\w+) \{$/.exec(lines[i]);
    if (!m) continue;
    const body: string[] = [];
    let j = i + 1;
    for (; j < lines.length && lines[j] !== "};"; j++) body.push(lines[j]);
    const fields: { name: string; offset: number; array: boolean }[] = [];
    for (const line of body) {
      const f = /^\s+[A-Za-z_][\w *]*?\b((?:field|array)_0x[0-9A-F]+)\s*(\[[^\]]*\])?;/.exec(line);
      if (f)
        fields.push({
          name: f[1],
          offset: Number.parseInt(f[1].split("_0x")[1], 16),
          array: f[2] !== undefined,
        });
    }
    defs.push({ id: m[1], body: body.join("\n"), fields });
    i = j;
  }
  return defs;
}

/**
 * Compile AND RUN a program that prints offsetof() for every field of every
 * emitted struct definition, and compare with the offset the field's own name
 * records.
 *
 * Reading the declaration is not enough and never was: the field names record
 * the offsets the recovery found (`field_0x18`), so a declaration C would not
 * lay out that way is a declaration that states something false, and every
 * `p->field_0x18` in that body then reads bytes the access never touched. This
 * is why the emitted definitions are `#pragma pack(1)` with explicit
 * `_pad_0xNN` members. A failure here means the emitted struct declarations and
 * the emitted field accesses disagree about where the data is.
 */
export function offsetofCheck(
  cc: string,
  workDir: string,
  sets: { tag: string; funcs: FuncRec[] }[],
): OffsetofResult {
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });

  const defStatus = new Map<string, boolean>();
  const seen = new Set<string>();
  const bad: string[] = [];
  let defs = 0;
  let defsCorrect = 0;
  let uncompilable = 0;
  let fields = 0;
  let fieldsCorrect = 0;

  for (const { tag, funcs } of sets) {
    for (const r of funcs) {
      if (!r.code?.includes("struct ")) continue;
      const preamble = preambleOf(r.code);
      const found = defsIn(preamble);
      if (found.length === 0) continue;
      // One program per distinct preamble; the same struct set recurs across
      // functions and compiling it once is enough.
      const key = `${tag}\n${preamble}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const checks: string[] = [];
      for (const def of found) {
        for (const f of def.fields) {
          checks.push(
            `  { size_t got = offsetof(struct ${def.id}, ${f.name});` +
              ` if (got != ${f.offset}u) printf("BAD ${def.id} ${f.name} want=${f.offset} got=%lu\\n", (unsigned long)got);` +
              ` else printf("OK ${def.id} ${f.name}\\n"); }`,
          );
        }
      }
      const file = join(workDir, `${tag}_${r.addr.toString(16)}.c`);
      const bin = file.replace(/\.c$/, "");
      writeFileSync(
        file,
        `${OFFSETOF_PRELUDE}${preamble}\nint main(void) {\n${checks.join("\n")}\n return 0;\n}\n`,
      );
      let out = "";
      try {
        execFileSync(cc, ["-std=gnu89", "-w", "-o", bin, file], { stdio: "pipe" });
        out = String(execFileSync(bin, { stdio: "pipe" }));
      } catch (e) {
        uncompilable += found.length;
        defs += found.length;
        if (bad.length < 12) {
          const stderr = String((e as { stderr?: Buffer }).stderr ?? e);
          bad.push(`UNCOMPILABLE ${tag}:0x${r.addr.toString(16)} — ${stderr.split("\n")[1] ?? ""}`);
        }
        continue;
      }

      const misplaced = new Set<string>();
      for (const line of out.split("\n")) {
        if (!line.startsWith("BAD ")) continue;
        misplaced.add(line.split(" ")[1]);
        if (bad.length < 12) bad.push(`${tag}:0x${r.addr.toString(16)} ${line}`);
      }
      const okFields = out.split("\n").filter((l) => l.startsWith("OK ")).length;
      const badFields = out.split("\n").filter((l) => l.startsWith("BAD ")).length;
      fields += okFields + badFields;
      fieldsCorrect += okFields;
      for (const def of found) {
        defs++;
        if (!misplaced.has(def.id)) defsCorrect++;
        const dk = `${tag}\n${def.id}\n${def.body}`;
        defStatus.set(dk, (defStatus.get(dk) ?? true) && !misplaced.has(def.id));
      }
    }
  }

  return {
    defs,
    defsCorrect,
    uncompilable,
    fields,
    fieldsCorrect,
    distinctDefs: defStatus.size,
    distinctCorrect: [...defStatus.values()].filter(Boolean).length,
    bad,
  };
}

export interface UnencodableResult {
  /** Mentions of a 64-bit register name in the C of a PE32 image. Expect 0. */
  names: number;
  /** Distinct such names, so one name used forty times is not forty defects. */
  distinct: number;
  funcsAffected: number;
  /** Functions read. Instrument liveness: 0 here means the scan saw nothing. */
  funcs: number;
}

/** The 64-bit register names, which are exactly `canonReg`'s range. */
const SIXTY_FOUR_BIT =
  /\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)(_\d+)?\b/g;

/**
 * A register name the image has no encoding for.
 *
 * This is the only oracle here that can see the defect class `peek-a-bin-1k4`
 * and `peek-a-bin-0s6e` are both instances of, and it is available *only* for a
 * PE32 image — which is what makes it usable at all. `canonReg` maps every alias
 * to the 64-bit parent because that is the register's identity and SSA keys on
 * it, so anything that lets a canonical name reach the page prints `rcx` in a
 * function whose every other line says `ecx`. In a 32-bit image that name is
 * provably wrong: the instruction set has no RCX, so no statement can have
 * written one and no reader can mean one. Every occurrence is therefore
 * `polarity inverted`'s character rather than a baseline's, and it gates at 0.
 *
 * **It cannot be asked of a 64-bit image**, deliberately: there `rcx` is an
 * ordinary correct spelling, and telling a canonical name apart from a real
 * 64-bit read needs the live range's own width, which is the question
 * `ssadestroy.ts`'s `registerSpeller` answers and not something the emitted text
 * records. So a green result on t64/w64 would say nothing, and the audit
 * reports those two as `funcs` scanned with the counts structurally 0.
 *
 * **`gcc` is blind to this** for the reason recorded in CLAUDE.md: `preludeFor`
 * declares every undeclared identifier as its own `long`, so `rcx` and `ecx`
 * compile cleanly as two unrelated variables. So is `corpus/staleReads.ts`,
 * which compares the *name* a read uses — by design, since a correct live-range
 * split emits two names for one register — and therefore reads a canonical name
 * as a legitimate second live range.
 */
export function unencodableNames(sets: { funcs: FuncRec[]; is64: boolean }[]): UnencodableResult {
  const out: UnencodableResult = { names: 0, distinct: 0, funcsAffected: 0, funcs: 0 };
  const seen = new Set<string>();
  for (const { funcs, is64 } of sets) {
    if (is64) continue;
    for (const r of funcs) {
      const code = r.code ?? "";
      out.funcs++;
      let hits = 0;
      for (const m of code.matchAll(SIXTY_FOUR_BIT)) {
        hits++;
        seen.add(m[0]);
      }
      out.names += hits;
      if (hits > 0) out.funcsAffected++;
    }
  }
  out.distinct = seen.size;
  return out;
}

export interface CaseBodyResult {
  /** `switch` statements read. Instrument liveness. */
  switches: number;
  /** `case`/`default` labels read. The denominator, and liveness. */
  labels: number;
  /**
   * Labels whose whole body is `break;` — the case says it does nothing.
   * REPORTED, never gated: see the docstring on why one can be legitimate.
   */
  bare: number;
  /**
   * Labels whose whole body is a single `goto` — `armBody`'s spelling for a
   * block another region already emitted under a label (peek-a-bin-dp6). The
   * population `bare` is told apart from, and the reason a fall in `bare` has
   * to be read beside a rise here.
   */
  gotoOnly: number;
  /** Labels carrying statements or a conditional exit of their own. */
  ownBlock: number;
  funcsAffected: number;
  /** Functions read. A text scrape fails by matching nothing. */
  funcs: number;
  /** Up to a dozen `func case` pairs, so a red row names itself. */
  bad: string[];
}

/** A `case <values>:` or `default:` on a line of its own, with its indent. */
const CASE_LABEL = /^(\s*)(case [^:{}]*:|default:)\s*$/;

/**
 * A CASE LABEL WHOSE WHOLE BODY IS `break;` — the case says it does nothing.
 *
 * This is `peek-a-bin-37az`'s quantity, and it was hand-counted with a
 * throwaway script when the bead was filed because nothing in the run reported
 * it. `corpus/armExits.ts` is the nearest instrument and it asks a different
 * question: it judges the *closure* `armExit` chose, from an observation taken
 * inside `structureSwitch`, so an arm that spells its exit correctly and emits
 * no body passes it — which that file records as `peek-a-bin-pqs5`'s residue.
 * This reads the emitted text instead, which is where a reader meets the class.
 *
 * WHY IT IS NOT A GATE. Two of `armBody`'s three answers are provably right and
 * the third is provably a false claim with no true alternative: where the
 * short-circuit fold consumed the target block without emitting a label there
 * is no name for a `goto` to use, and `break` is all that is left. `armExits.ts`
 * refuses to gate that same population (`unnameable`) for the same reason, and
 * refusing here keeps the two consistent. The count is 0 across the corpus at
 * `d8d2d02` and `unnameable` is 0 with it, so a gate would rest on an empty
 * population — the mistake CLAUDE.md records against `selfAssigns.openOperand`.
 * A RISE is judged in `compare.mjs`.
 *
 * READ IT BESIDE `gotoOnly`. A rule that emitted `goto` for every arm would
 * drive `bare` to 0 by no longer saying anything, so the three buckets are
 * reported together and sum to `labels`.
 *
 * THE DENOMINATOR IS 0 ON BOTH x64 BINARIES. Neither recovers a jump table, so
 * `structureSwitch` never runs there and a green row on those two says nothing
 * at all — the x86 pair is the whole population, exactly as for `armExits`.
 *
 * WHAT IT DOES NOT SEE. It judges the body's *emptiness*, never its contents: an
 * arm that emits half its block passes, as does one that emits the wrong
 * statements. Nothing here can see either — the emitted C is self-consistent
 * and the oracle for it is `objdump` read by hand.
 */
export function emptyCaseBodies(sets: { funcs: FuncRec[] }[]): CaseBodyResult {
  const out: CaseBodyResult = {
    switches: 0,
    labels: 0,
    bare: 0,
    gotoOnly: 0,
    ownBlock: 0,
    funcsAffected: 0,
    funcs: 0,
    bad: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      out.funcs++;
      const src = (r.code ?? "").split("\n");
      let hits = 0;
      for (let i = 0; i < src.length; i++) {
        if (/^\s*switch \(/.test(src[i])) out.switches++;
        const m = src[i].match(CASE_LABEL);
        if (m === null) continue;
        out.labels++;
        const body = caseBody(src, i, m[1].length);
        if (body.length === 1 && body[0] === "break;") {
          out.bare++;
          hits++;
          if (out.bad.length < 12) out.bad.push(`${r.name} ${m[2]}`);
        } else if (body.length === 1 && /^goto \w+;$/.test(body[0])) out.gotoOnly++;
        else out.ownBlock++;
      }
      if (hits > 0) out.funcsAffected++;
    }
  }
  return out;
}

/**
 * The statements under one case label, as trimmed non-empty lines.
 *
 * THE TWO STOP RULES ARE THE WHOLE AUDIT and each was wrong in an early draft.
 * `emit.ts` puts a case label at the SAME indent as its `switch (`, and the
 * switch's own closing brace with it — so a stop at a brace *strictly* shallower
 * than the label runs the last arm's body on into whatever follows the switch,
 * and a genuinely bare final arm then reads as one that does work. And a `loc_`
 * label is emitted at column 0 whatever its nesting, so an indent-only rule
 * treats it as the end of the body; it is skipped by name instead, since a label
 * is not a statement.
 */
function caseBody(src: string[], at: number, indent: number): string[] {
  const body: string[] = [];
  for (let j = at + 1; j < src.length; j++) {
    const line = src[j];
    const text = line.trim();
    if (text.length === 0) continue;
    const col = line.length - line.trimStart().length;
    if (col <= indent && (CASE_LABEL.test(line) || text === "}")) break;
    if (/^loc_[0-9A-Fa-f]+:$/.test(text)) continue;
    body.push(text);
  }
  return body;
}

export interface OffsetArgResult {
  /**
   * Occurrences of an `arg_0x<N>` whose N divides evenly into an argument slot,
   * i.e. a slot that WOULD have been given a positional name had the frame
   * pointer been recognised. Every one is a repairable naming defect.
   */
  aligned: number;
  /** Distinct such names, so one name used forty times is not forty defects. */
  distinct: number;
  funcsAffected: number;
  /**
   * Occurrences whose N does NOT divide evenly — the third byte of argument 0,
   * say. These are correctly offset-named however good the frame recovery gets,
   * and are reported apart so they cannot be mistaken for the repairable half.
   */
  subSlot: number;
  /** Functions read. Instrument liveness: 0 here means the scan saw nothing. */
  funcs: number;
}

/**
 * An argument the emitted C names by its frame offset when its offset says
 * outright which argument it is.
 *
 * `stack.ts` spells a parameter slot `arg_<index>` only once it has verified
 * that the frame register really is a frame pointer, and `arg_0x<offset>`
 * otherwise — because outside that verification the offset carries no index.
 * So an `arg_0x<N>` whose `(N - firstOffset) % slotSize === 0` is a slot the
 * naming would have indexed if the prologue had been recognised, and the
 * offset spelling is down to the recognition and to nothing about the file.
 * That makes the count a direct measure of how much of the argument area the
 * frame recovery is still missing, which is why the sub-slot half is reported
 * separately: those are correctly offset-named at any level of recovery.
 *
 * **REPORT-ONLY, and it is a TARGET rather than a gate — which is the important
 * thing about this row.** It reads **0 on all four binaries** as of
 * `peek-a-bin-g186`, so every future run compares 0 against 0 and the row is now
 * a regression detector: a non-zero reading means frame recovery has lost
 * ground, either because detection over-produced and a prologue fell outside the
 * detected range (the frame register then belongs to the *enclosing* function
 * and no index can be derived from the offset — `peek-a-bin-abv`,
 * `peek-a-bin-emlv`), or because a displacement stopped being recovered
 * (`peek-a-bin-ikd`, `peek-a-bin-sx57`).
 *
 * **It must NOT be gated at 0, and that is measured rather than cautious.** The
 * row cannot tell a right change from a wrong one: `peek-a-bin-g186` reaches 0
 * by declaring no parameter for an unfilled home slot, and the variant
 * `peek-a-bin-sx57` measured and refused reaches the same 0 by *naming* all 35
 * x64 slots `arg_<i>` — moving nothing else in the whole report — while printing
 * eleven declared parameters per x64 binary that a callee-saved register
 * overwrites at entry. A gate here would be satisfied by either. The question
 * asked over the DECLARED PARAMETER LIST does discriminate, and that is
 * `paramClobberedAtEntry` below (`peek-a-bin-15q7`).
 *
 * **Nothing else here can see it.** An offset-named argument is a well-typed
 * identifier that gcc compiles, it states nothing false so polarity,
 * `staleGuards` and `staleReads` are indifferent, it is not an admission so the
 * unrecovered count does not move, and `offsetof` only checks layouts it was
 * given — the point being that a slot named this way never reaches struct
 * synthesis as a parameter at all, since `structs.ts` keys provenance off
 * `^arg_(\d+)$` deliberately.
 */
export function offsetNamedArgs(sets: { funcs: FuncRec[]; is64: boolean }[]): OffsetArgResult {
  const out: OffsetArgResult = {
    aligned: 0,
    distinct: 0,
    funcsAffected: 0,
    subSlot: 0,
    funcs: 0,
  };
  const seen = new Set<string>();
  for (const { funcs, is64 } of sets) {
    // The same geometry `stack.ts`'s ARG_AREA states, written independently so
    // the audit does not agree with the code under test by construction.
    const firstOffset = is64 ? 0x10 : 0x08;
    const slotSize = is64 ? 8 : 4;
    for (const r of funcs) {
      out.funcs++;
      let hits = 0;
      for (const m of (r.code ?? "").matchAll(/\barg_0x([0-9A-Fa-f]+)\b/g)) {
        const offset = Number.parseInt(m[1], 16);
        if ((offset - firstOffset) % slotSize === 0) {
          hits++;
          seen.add(`${is64 ? 64 : 32}:${m[0]}`);
        } else {
          out.subSlot++;
        }
      }
      out.aligned += hits;
      if (hits > 0) out.funcsAffected++;
    }
  }
  out.distinct = seen.size;
  return out;
}

export interface GotoResult {
  gotos: number;
  /** `loc_` labels defined in functions that contain a `goto`. */
  labels: number;
  /** Of those, labels no `goto` in the function names — kept for another reason. */
  labelsUntargeted: number;
  /** A `goto` naming a label the function never defines. Expect 0. */
  dangling: number;
  fnWithGoto: number;
  fnWithDangling: number;
  /**
   * Emitted lines over EVERY function with code, goto or not — the denominator
   * of `gotos per 100 lines`. Liveness for the scan.
   */
  lines: number;
  /** Functions with code read. Liveness. */
  funcs: number;
}

/**
 * Every `goto` the emitted C contains must name a label that same function
 * defines. A dangling goto is C that does not compile and, before that, a
 * transfer the reader cannot follow. gcc catches these too (as "label used but
 * not defined"), but counting them directly says how many rather than how many
 * functions.
 */
export function gotoCheck(sets: { funcs: FuncRec[] }[]): GotoResult {
  const out: GotoResult = {
    gotos: 0,
    labels: 0,
    labelsUntargeted: 0,
    dangling: 0,
    fnWithGoto: 0,
    fnWithDangling: 0,
    lines: 0,
    funcs: 0,
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      if (code === "") continue;
      out.funcs++;
      out.lines += code.split("\n").length;
      // Read per line through `statementOnLine`, not with a multiline anchor: a
      // `goto` that is the body of a one-lined guard is still a goto, and a
      // line-start anchor would take the whole population out of this scan and
      // report `dangling` 0 because it stopped looking (peek-a-bin-vwr5).
      const g: string[] = [];
      for (const line of code.split("\n")) {
        const m = /^goto ([A-Za-z_]\w*);/.exec(statementOnLine(line));
        if (m) g.push(m[1]);
      }
      if (g.length === 0) continue;
      const defined = new Set([...code.matchAll(/^\s*(loc_[0-9A-F]+):$/gm)].map((m) => m[1]));
      out.fnWithGoto++;
      out.gotos += g.length;
      out.labels += defined.size;
      const named = new Set(g);
      for (const l of defined) if (!named.has(l)) out.labelsUntargeted++;
      const bad = g.filter((n) => !defined.has(n)).length;
      out.dangling += bad;
      if (bad > 0) out.fnWithDangling++;
    }
  }
  return out;
}

export interface ParamClobberResult {
  /**
   * Declared parameters whose FIRST appearance in the body is an assignment
   * from a bare callee-saved register. Every one is a slot the emitted C
   * declares as an incoming value and then overwrites before reading, which no
   * calling convention produces. Expect 0.
   */
  clobbered: number;
  /** Distinct `function:parameter` pairs, so one row is one slot. */
  distinct: number;
  funcsAffected: number;
  /** Declared parameters read. Instrument liveness: 0 means the scan saw nothing. */
  params: number;
  /** Functions read. Instrument liveness. */
  funcs: number;
  /** `function:parameter = register` for each row, for the failure message. */
  rows: string[];
}

/**
 * The callee-saved registers, at every width the emitter can spell them.
 *
 * Windows x64 preserves RBX, RBP, RDI, RSI and R12-R15; the 32-bit conventions
 * preserve EBX, ESI, EDI and EBP. Both sets are listed together and the audit is
 * asked of both widths, because the question is about the *shape* of the
 * statement rather than about which convention is in force: a parameter
 * overwritten at entry by a register the callee is obliged to restore is a
 * register save under a parameter's name on either architecture.
 *
 * `rsp`/`esp` are deliberately absent. The stack pointer is preserved too, but
 * nothing here models it (CLAUDE.md: "No read of RSP may be moved to another
 * program point"), so an `arg = esp` is a different defect and not this one.
 */
const CALLEE_SAVED = new RegExp(
  "^(?:" +
    "rbx|rbp|rdi|rsi|r1[2-5]|" +
    "ebx|ebp|edi|esi|r1[2-5]d|" +
    "bx|bp|di|si|r1[2-5]w|" +
    "bl|bpl|dil|sil|r1[2-5]b" +
    ")(?:_\\d+)?$",
);

/**
 * THE ONE DECLARATION OF "WHICH EMITTED LINE IS THE FUNCTION'S OWN SIGNATURE",
 * and of the parameter list on it.
 *
 * Three audits want it and each wanted it for a different reason —
 * `paramClobberedAtEntry` needs the names and where the body starts,
 * `signatureAgreement` needs only how many there are, and `sweep.ts`'s
 * `emittedCallees` needs to NOT read `f(` on that line as a call to `f`. There
 * were two hand-rolled readings before this: this one, and a positional
 * `i < 6 && /^\w[\w *]*\(/` scan in `emittedCallees` that a function with
 * enough emitted `struct` typedefs above its header walks straight past, at
 * which point the function counts as a caller of itself. Same family as
 * `guardShape.ts`: a text-scraping audit fails by matching *nothing*, silently,
 * so the reading has to be written once and read everywhere.
 *
 * The emitter writes the signature as one line ending in `) {`, after the
 * typedefs and struct declarations (`emit.ts`: `${returnType} ${name}(${params}) {`).
 * Anchored on the brace rather than on a return type, so a spelling this audit
 * does not know about cannot skip it, and `[^;{}\n]*` keeps it off a `while (…) {`
 * inside the body by requiring the line to start at column 0 — the emitter
 * indents every statement.
 */
export function declaredParams(
  code: string,
): { names: string[]; bodyAt: number; lineAt: number; line: string } | null {
  const m = /^[A-Za-z_][^;{}\n]*\(([^)]*)\)\s*\{[ \t]*$/m.exec(code);
  if (!m) return null;
  const names: string[] = [];
  for (const part of m[1].split(",")) {
    // `int64_t arg_0x30` -> `arg_0x30`; `void` and `...` yield nothing.
    const name = /([A-Za-z_]\w*)\s*$/.exec(part.trim());
    if (name && name[1] !== "void") names.push(name[1]);
  }
  return { names, bodyAt: m.index + m[0].length, lineAt: m.index, line: m[0] };
}

/**
 * The emitted C after its DECLARATION BLOCK — the lines between the header and
 * the one blank line that closes them, where `emit.ts` declares every local,
 * every register variable, every minted variable, every capture and every
 * `__unrecovered_N` (peek-a-bin-n9cl.4). Returns the code unchanged when there
 * is no block.
 *
 * For the text scans that count MENTIONS of a name: a declaration is not a
 * read, and three of them were counting it as one the moment registers became
 * declared — `auditClobbered` in `sweep.ts` (21 → 38 "clobbered reads" on each
 * x64 binary, exactly + the 17 distinct names), `stackPointerScaffolding`
 * (`int64_t rsp;` read as a stack-pointer READ, taking `writeNoRead` 4/18/17/4
 * → 0) and `copyPairs` (a declaration line between two statements is not a
 * statement). The shape is the emitter's own and is invariant over the corpus
 * — 0 non-declaration lines inside the block over 1072 functions at `2328657`
 * — and the block is recognised by BOTH halves: every line must be
 * declaration-shaped AND a blank line must close it, so a function with no
 * block (93 of 1072) loses nothing and a body line can never be mistaken for a
 * declaration (`return eax;` is a keyword, not a type).
 */
export function stripDeclarationBlock(code: string): string {
  const sig = declaredParams(code);
  if (sig === null) return code;
  const head = code.slice(0, sig.bodyAt);
  const rest = code.slice(sig.bodyAt);
  const lines = rest.split("\n");
  // `rest` begins with the remainder of the header line (empty), so the block
  // starts at index 1.
  const end = lines.indexOf("", 1);
  if (end < 0) return code;
  for (let i = 1; i < end; i++) if (!DECLARATION_LINE.test(lines[i])) return code;
  return head + [lines[0], ...lines.slice(end + 1)].join("\n");
}

/**
 * One declaration line as `emit.ts` prints it: four spaces, a type (one or two
 * words, an optional pointer star on either side), the name, `;`, and for an
 * `__unrecovered_N` a trailing comment. The negative lookahead keeps the C
 * statement keywords out, so `    return eax;` never reads as a declaration.
 */
const DECLARATION_LINE =
  /^ {4}(?!return\b|goto\b|break\b|continue\b)[A-Za-z_]\w*(?: \*+| \w+)? \*?\w+;(?: \/\*.*\*\/)?$/;

/**
 * A declared parameter the body overwrites from a callee-saved register before
 * ever reading it.
 *
 * This exists because **`offsetNamedArgs` cannot tell a right change from a
 * wrong one**, and that is measured rather than argued (`peek-a-bin-15q7`).
 * That row counts `arg_0x<N>` spellings, so it reaches 0 both when a slot is
 * correctly withdrawn from the parameter list (`peek-a-bin-g186`) and when every
 * slot is wrongly *named* `arg_<i>` (the variant `peek-a-bin-sx57` measured and
 * refused). Under the naming variant it reads 0/0/0/0 and moves nothing else in
 * the whole report, while printing four declared parameters that a callee-saved
 * register overwrites at entry. A row a wrong change drives to its best value is
 * a target, not a gate.
 *
 * So the question is asked over the **declared parameter list** instead, where
 * the two answers differ. `void f(int64_t arg_0) { arg_0 = rbx; … }` says the
 * caller passed a value and the callee discarded it unread, which no calling
 * convention produces: the slot is the caller-reserved home space being used as
 * a register save, which is what the Microsoft x64 ABI explicitly permits and
 * what makes "this offset is in the argument area" not imply "this is a
 * parameter". Every row is therefore provably wrong output rather than a count
 * awaiting a threshold, and it gates at 0.
 *
 * **First appearance, not any appearance**, and that is the whole precision of
 * it. A parameter assigned from a callee-saved register *after* being read is
 * ordinary — the callee is free to reuse an argument slot as scratch once it has
 * consumed the argument, and MSVC does. Only a write that precedes every read
 * says the declaration was wrong.
 *
 * **Both counts beside it are liveness.** `params` and `funcs` go to 0 if the
 * signature grammar ever stops matching, which is the way a text-scraping audit
 * fails silently; a gate at 0 over 0 parameters would be green for want of
 * looking (CLAUDE.md's `armExits` lesson).
 *
 * **Nothing else here can see it.** `gcc` compiles an unread parameter happily;
 * `offsetof` only checks layouts it was given; polarity, `staleGuards` and
 * `staleReads` are indifferent to a parameter's provenance; and the unrecovered
 * count does not move because nothing is admitted. `offsetNamedArgs` is the row
 * that looks like it covers this and provably does not.
 */
export function paramClobberedAtEntry(sets: { funcs: FuncRec[] }[]): ParamClobberResult {
  const out: ParamClobberResult = {
    clobbered: 0,
    distinct: 0,
    funcsAffected: 0,
    params: 0,
    funcs: 0,
    rows: [],
  };
  const seen = new Set<string>();
  for (const { funcs } of sets) {
    for (const r of funcs) {
      out.funcs++;
      const sig = declaredParams(r.code ?? "");
      if (!sig) continue;
      const body = (r.code ?? "").slice(sig.bodyAt);
      let hits = 0;
      for (const name of sig.names) {
        out.params++;
        // Written so a reformat cannot break it: the first mention is found by
        // identifier, and the statement shape is then read around that offset
        // rather than by matching a whole line of expected whitespace.
        const first = new RegExp(`\\b${name}\\b`).exec(body);
        if (!first) continue;
        // A read of a sub-register is spelled through the declared variable
        // with a cast — `arg_28 = (uint32_t)rbx;` since peek-a-bin-n9cl.4 — so
        // the cast is optional here or such a row would silently leave the gate.
        const stmt = /^\s*=\s*(?:\((?:u?int(?:8|16|32|64)_t)\))?([A-Za-z_]\w*)\s*;/.exec(
          body.slice(first.index + name.length),
        );
        if (!stmt || !CALLEE_SAVED.test(stmt[1])) continue;
        hits++;
        out.clobbered++;
        seen.add(`${r.name}:${name}`);
        if (out.rows.length < 8) out.rows.push(`${r.name}:${name} = ${stmt[1]}`);
      }
      if (hits > 0) out.funcsAffected++;
    }
  }
  out.distinct = seen.size;
  return out;
}

export interface SigAgreementResult {
  /** Functions read. Instrument liveness. */
  funcs: number;
  /**
   * Functions `inferSignature` answered for at all — THE LIVENESS HALF, and the
   * one that matters. `over` below reaches 0 both when the panel stops
   * over-claiming and when `inferSignature` starts returning `null` for
   * everything, and only this number tells the two apart.
   */
  withSignature: number;
  /** Functions whose emitted signature line was located. Instrument liveness. */
  located: number;
  /** Functions where both answers exist, i.e. the denominator of the rows below. */
  compared: number;
  /** A === B. */
  agree: number;
  /**
   * A > B — the panel claims MORE parameters than the emitted C declares.
   * GATED at 0 on x64. See the docstring on `signatureAgreement`.
   */
  over: number;
  /** A < B. Reported, never gated: see the docstring. */
  under: number;
  /** The largest `A - B` seen, so a single bad function is visible in the row. */
  worstOver: number;
  /** `function: panel=A emitted=B` for the failure message, capped. */
  rows: string[];
}

/**
 * THE PANEL'S PARAMETER COUNT AGAINST THE DECOMPILER'S, FOR THE SAME FUNCTION.
 *
 * `inferSignature` is rendered by `InstructionDetail` and by `getSigForFunc` in
 * `DisassemblyRows`, i.e. beside essentially every function in the list, while
 * the decompile panel one pane over prints a parameter list built by
 * `promote.ts`. Nothing had ever compared the two, and they disagreed: at
 * `0870e14` `t64!sub_140001000` does `sub rsp, 0x848` and then
 * `lea rcx, [rsp + 0x30]`, and `inferSignature64`'s stack-argument rule — which
 * tracked no allocation at all — read that as `floor((0x30 - 0x28) / 8) + 5 = 6`
 * parameters while the decompiler emitted four. Two panels, two answers, one
 * function (`peek-a-bin-j4uk.6`).
 *
 * **A is not an oracle for B and B is not an oracle for A.** This is a
 * differential between two of the tool's own answers, so its independence is
 * the weak kind — `lostDefs`' kind: a regression gate on a relationship, not a
 * question asked from outside. What makes the OVER direction gateable anyway is
 * that on x64 the relationship is one-way by construction. `promote.ts` adds
 * `Math.min(signature.paramCount, 4)` register parameters to whatever the frame
 * recovery already declared, so `B >= min(A, 4)`; the Windows x64 convention
 * passes at most four arguments in registers, so a sound `A` is at most 4 and
 * therefore at most `B`. An `A > B` row is the panel counting something no
 * stage downstream of it believes — which, at `0870e14`, it was.
 *
 * **UNDER IS NOT A DEFECT AND MUST NOT BE GATED.** `B` legitimately exceeds `A`
 * whenever frame recovery names a stack slot the register scan cannot see: an
 * x64 function with a genuine fifth argument declares `arg_0x30` and the panel,
 * which now refuses the whole stack-argument claim, says 4. That is the
 * `f51x` direction — an admitted under-count — and driving it to 0 is exactly
 * the over-claim this change removed.
 *
 * **x86 IS REPORTED AND NOT GATED**, for a different reason: `promote.ts`'s
 * register-parameter arm is `is64`-gated, so nothing on the x86 path carries
 * `A` into `B` at all, and a `ret N` count legitimately exceeds the number of
 * argument slots the body happens to touch (an untouched argument leaves a gap
 * — `stack.ts`'s own note on the numbering). The two answers are independent
 * there rather than related, so a disagreement is information and not a defect.
 *
 * **Nothing else here can see any of it.** `corpus/arity.ts` measures CALL-SITE
 * arity against `apitypes.ts` and cannot see a declared parameter list at all;
 * gcc accepts any parameter list; `offsetNamedArgs` counts spellings, not
 * counts; and `paramClobberedAtEntry` asks whether a declared parameter is
 * immediately overwritten, which an over-claimed `argN` never is.
 */
export function signatureAgreement(sets: { funcs: FuncRec[] }[]): SigAgreementResult {
  const out: SigAgreementResult = {
    funcs: 0,
    withSignature: 0,
    located: 0,
    compared: 0,
    agree: 0,
    over: 0,
    under: 0,
    worstOver: 0,
    rows: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      out.funcs++;
      const a = r.sigParams;
      if (a !== null) out.withSignature++;
      // A function whose decompilation threw, or that had no instructions, has
      // no emitted text to read a parameter list off. Those are excluded from
      // the denominator rather than scored as an agreement at 0 — a row that
      // silently leaves the population is how a gate reads 0 (`selfAssigns`'
      // `unresolved`), so `located` beside `funcs` is what makes the loss
      // visible.
      const sig = r.code === "" ? null : declaredParams(r.code);
      if (sig !== null) out.located++;
      if (a === null || sig === null) continue;
      const b = sig.names.length;
      out.compared++;
      if (a === b) out.agree++;
      else if (a > b) {
        out.over++;
        out.worstOver = Math.max(out.worstOver, a - b);
        if (out.rows.length < 8) out.rows.push(`${r.name}: panel=${a} emitted=${b}`);
      } else out.under++;
    }
  }
  return out;
}

export interface MemberNameResult {
  /** Struct definitions read. A text scrape fails by matching nothing. */
  defs: number;
  /** Member declarations read (padding excluded). The denominator, and liveness. */
  members: number;
  /**
   * Members whose identifier and whose brackets disagree — `field_0x8[]` or
   * `array_0x8;`. GATED at 0: every one is a declaration contradicting itself.
   */
  disagreeing: number;
  /** Of those, the ones named `field_` and declared with `[...]`. */
  fieldNamedArrays: number;
  /** Of those, the ones named `array_` and declared without. */
  arrayNamedScalars: number;
  funcsAffected: number;
  /** Functions read. Instrument liveness. */
  funcs: number;
  /** Up to a dozen `bin:addr struct_N <line>` rows, so a red row names itself. */
  rows: string[];
}

/**
 * A STRUCT MEMBER WHOSE NAME AND WHOSE BRACKETS DISAGREE.
 *
 * The field names carry the recovered offsets *and* what kind of member the
 * recovery found: `candidateFields` spells an indexed access whose stride is the
 * width read there `array_0x8` and everything else `field_0x8`. `declareField`
 * spells the brackets off `isArray` alone. So the two can come apart, and they
 * did — `StructRegistry.mergeFields` promoted a field to an array when a later
 * function's indexed access reached the same offset and kept the name the field
 * was created with, emitting `uint64_t field_0x8[];`: an identifier saying
 * scalar member over an extent saying array (peek-a-bin-tm29).
 *
 * A GATE at 0, and it has `polarity inverted`'s character rather than a
 * baseline's: the two halves of one declaration state different things about the
 * same member, so the row is provably wrong from the emitted text alone with no
 * reference to the machine. Both directions are counted because only one of them
 * has ever been produced — a demotion would be the other, and `mergeFields` has
 * no path to one — so a rule that renamed instead of promoting would be caught
 * here too rather than reading green.
 *
 * NOTHING ELSE HERE CAN SEE IT, and two neighbours are close enough to be
 * mistaken for instruments of it. `gcc -fsyntax-only` compiles
 * `uint64_t field_0x8[];` without comment: a flexible array member is legal C
 * and the identifier is only an identifier. `offsetofCheck` reads the SAME
 * grammar and passes at 1.00, because it derives the expected offset from the
 * name's hex suffix and `offsetof(struct_20, field_0x8)` really is 8 — the
 * layout is right and it is the *kind* of member the declaration lies about. So
 * this is the naming half of the claim `offsetofCheck` makes about the layout
 * half, and it reads the same `defsIn` member list so a definition cannot be in
 * one denominator and out of the other.
 *
 * WHAT IT DOES NOT SEE. Only the two spellings above: a member declared at a
 * width no access measured, an `array_0x4[1]` whose extent the gap to the next
 * field bounded rather than the recovery, and a field the layout refused
 * entirely are each judged elsewhere or not at all.
 */
export function memberNameAgreement(sets: { tag: string; funcs: FuncRec[] }[]): MemberNameResult {
  const out: MemberNameResult = {
    defs: 0,
    members: 0,
    disagreeing: 0,
    fieldNamedArrays: 0,
    arrayNamedScalars: 0,
    funcsAffected: 0,
    funcs: 0,
    rows: [],
  };
  for (const { tag, funcs } of sets) {
    for (const r of funcs) {
      out.funcs++;
      const code = r.code ?? "";
      if (!code.includes("struct ")) continue;
      let hits = 0;
      for (const def of defsIn(preambleOf(code))) {
        out.defs++;
        for (const f of def.fields) {
          out.members++;
          if (f.name.startsWith("array_") === f.array) continue;
          hits++;
          out.disagreeing++;
          if (f.array) out.fieldNamedArrays++;
          else out.arrayNamedScalars++;
          if (out.rows.length < 12)
            out.rows.push(
              `${tag}:0x${r.addr.toString(16)} ${def.id} ${f.name} declared ` +
                `${f.array ? "with []" : "without []"}`,
            );
        }
      }
      if (hits > 0) out.funcsAffected++;
    }
  }
  return out;
}

/**
 * `goto` density, the one figure here that MUST NEVER GATE — in either
 * direction — and the reason is recorded where the number is computed so it
 * travels with it. (i) `goto` is the honest spelling for a transfer the tree
 * cannot model, and the recorded way to drive it down WRONGLY is a false
 * `break`: `armExits` exists because that happened (peek-a-bin-pqs5). (ii) It
 * falls with recovery AND with fabrication, so its direction says nothing.
 * (iii) Its denominator moves with function detection. `compare.mjs` prints it
 * with no `worseIf`.
 */
export function gotosPer100Lines(g: GotoResult): number {
  return g.lines === 0 ? 0 : Math.round((10_000 * g.gotos) / g.lines) / 100;
}

// ── Undeclared identifiers: what the prelude has been inventing ─────────────

export type IdentClass = "register" | "residue" | "minted" | "api" | "other";

/**
 * Every general-purpose register name the emitter can spell, at every width,
 * with an optional SSA version suffix. Written out rather than imported from
 * `ir.ts` so the classification does not agree with the code under test by
 * construction — `build/readabilityCensus.test.ts` holds the differential
 * against `isKnownRegister`/`regAtSize`, which is where the two declarations are
 * made to meet. `SIXTY_FOUR_BIT` above is the same list at one width.
 *
 * The XMM/YMM names are NOT here since `peek-a-bin-n9cl.4`: they are
 * `RESIDUE_NAME`'s, because `emit.ts` declares every GPR the body names and
 * gates on it, while a 16-byte register has no C integer to be declared as.
 */
export const REGISTER_NAME = new RegExp(
  "^(?:" +
    "r(?:ax|bx|cx|dx|si|di|bp|sp)|" +
    "e(?:ax|bx|cx|dx|si|di|bp|sp)|" +
    "(?:ax|bx|cx|dx|si|di|bp|sp)|" +
    "[abcd][lh]|(?:si|di|bp|sp)l|" +
    "r(?:8|9|1[0-5])[bwd]?" +
    ")(?:_\\d+)?$",
);

/**
 * THE RESIDUE: register-shaped names `emit.ts` deliberately does NOT declare,
 * and which therefore stay outside the gate rather than inside it by accident.
 * Each is a `reg`-kind IR node the emitter's `registerVariables` refuses — a
 * name `isKnownRegister` does not admit (`tmp_xchg`, the `stk_<addr>` slot a
 * matched push/pop pair mints) or a width with no C integer (`st0` at 10 bytes,
 * `xmm0`/`ymm0` at 16/32). Counted and reported beside the gate, never folded
 * into it: 12 `stk_` mentions per PE32 binary (6 pairs) and none of the others
 * at `2328657`. `stk_` is checked here BEFORE `MINTED_NAME` and the test in
 * `build/readabilityCensus.test.ts` pins the order.
 */
export const RESIDUE_NAME = /^(?:stk_[0-9a-f]+|tmp_xchg|st[0-7]|[xy]mm(?:[0-9]|1[0-5]))(?:_\d+)?$/;

/**
 * The emitter's own pseudo-variables, each minted from an address or a version.
 * Every one of these is declared by `emit.ts` since `peek-a-bin-n9cl.4`
 * (`flg_` and `__unrecovered_` already were), so one reaching this list is a
 * declaration spelling that moved — or a `flg_` capture READ without its
 * definition, which `collectCapturedOperands` leaves undeclared on purpose.
 */
const MINTED_NAME = /^(?:clobbered_|flg_|__unrecovered_)/;

export function classifyIdentifier(name: string, apiNames: ReadonlySet<string>): IdentClass {
  if (REGISTER_NAME.test(name)) return "register";
  if (RESIDUE_NAME.test(name)) return "residue";
  if (MINTED_NAME.test(name)) return "minted";
  if (apiNames.has(name)) return "api";
  return "other";
}

export interface UndeclaredRec {
  fn: string;
  addr: number;
  name: string;
  cls: IdentClass;
}

export interface UndeclaredResult {
  /**
   * Functions handed to the compiler, under the SAME admission rule as
   * `ccSyntaxCheck` — asserted equal to its `compiled` in the run, so the two
   * gcc passes cannot drift onto different populations.
   */
  compiled: number;
  /** Compiles whose stderr held no parseable diagnostic at all. Expect 0. */
  unparseable: number;
  /** (function, name) pairs gcc reported `undeclared`, by class. `register + minted` GATES at 0. */
  register: number;
  minted: number;
  /** The names the emitter refuses to declare (`RESIDUE_NAME`). Reported, never gated. */
  residue: number;
  api: number;
  other: number;
  distinctRegister: number;
  distinctMinted: number;
  distinctResidue: number;
  distinctApi: number;
  distinctOther: number;
  /** Functions with at least one undeclared identifier of any class. */
  funcsAffected: number;
  /** Functions with at least one REGISTER-class undeclared identifier. */
  funcsWithRegisters: number;
  /** (function, type) pairs gcc reported `unknown type name`. */
  unknownTypes: number;
  distinctUnknownTypes: number;
  /** Up to two dozen distinct `other` names, so the bucket is adjudicable. */
  otherNames: string[];
  rows: UndeclaredRec[];
}

/**
 * THE DECLARATIONS `preludeFor` HAS BEEN INVENTING, CLASSIFIED.
 *
 * `ccSyntaxCheck` compiles each function up to five times, declaring whatever
 * gcc complained about the round before, and reports `clean` once gcc stops
 * complaining. That is the right question for "is this C" and the wrong one for
 * "is this the C a reader gets": every `long rax;` the prelude adds is a
 * variable the emitted function USES AND NEVER DECLARES, and the 100%-clean row
 * measures the harness's completion of the output rather than the output.
 * `peek-a-bin-k8i` counted 1460/2456/2278/1417 such inventions with a throwaway
 * script; nothing in the run recorded it (peek-a-bin-n9cl.1).
 *
 * This compiles each function ONCE, with `CC_HEADER` and no prelude, and
 * classifies every `'X' undeclared` gcc reports:
 *
 *   - **register** — a general-purpose register name at any width, versioned
 *     or not. `emit.ts` declares ONE variable per canonical register per
 *     function since `peek-a-bin-n9cl.4` (`registerVariables`), so this is 0
 *     and `register + minted` is a GATE at 0 in `corpus.audit.ts`. It was
 *     1452/2438/2260/1409 at `2328657`, the first durable k8i measurement, and
 *     the negative control — skip the declaration loop — returns it there.
 *   - **residue** — `stk_<addr>`, `tmp_xchg`, `st0..7`, `xmm`/`ymm`: register-
 *     shaped names the emitter deliberately does not declare (see
 *     `RESIDUE_NAME`). Reported beside the gate, never inside it.
 *   - **minted** — `clobbered_`, `flg_`, `__unrecovered_`: the emitter's own
 *     pseudo-variables, every one declared by the emitter, so an appearance
 *     here means a declaration spelling moved (or a `flg_` capture is read
 *     without its definition, which is left undeclared on purpose).
 *   - **api** — an imported function or an `apitypes.ts` name used as a value
 *     (a function pointer stored, say). The prelude legitimately supplies these
 *     and always will; with `unknownTypes` this is the LIVENESS half — the
 *     prelude still doing the work it exists for.
 *   - **other** — everything else, listed by name so the bucket can be read.
 *
 * `-w` is kept, so an implicit function declaration is silent exactly as it is
 * in `ccSyntaxCheck`; only identifiers used as VALUES reach this list. gcc
 * reports each name once per function ("first use in this function"), so the
 * counts are (function, name) pairs, which is what k8i counted.
 */
export function undeclaredIdentifiers(
  cc: string,
  workDir: string,
  sets: { tag: string; funcs: FuncRec[] }[],
  apiNames: ReadonlySet<string>,
): UndeclaredResult {
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });
  const out: UndeclaredResult = {
    compiled: 0,
    unparseable: 0,
    register: 0,
    minted: 0,
    residue: 0,
    api: 0,
    other: 0,
    distinctRegister: 0,
    distinctMinted: 0,
    distinctResidue: 0,
    distinctApi: 0,
    distinctOther: 0,
    funcsAffected: 0,
    funcsWithRegisters: 0,
    unknownTypes: 0,
    distinctUnknownTypes: 0,
    otherNames: [],
    rows: [],
  };
  const distinct: Record<IdentClass, Set<string>> = {
    register: new Set(),
    residue: new Set(),
    minted: new Set(),
    api: new Set(),
    other: new Set(),
  };
  const unknownTypes = new Set<string>();
  for (const { tag, funcs } of sets) {
    for (const r of funcs) {
      const code = r.code;
      if (!code || /^\/\/ /.test(code)) continue;
      out.compiled++;
      const file = join(workDir, `${tag}_${r.addr.toString(16)}.c`);
      writeFileSync(file, `${CC_HEADER}\n${code}\n`);
      const diags = compileOnly(cc, file);
      if (diags.some((d) => d.msg.startsWith("compiler failed with no parseable error")))
        out.unparseable++;
      const seen = new Set<string>();
      let any = false;
      let regs = false;
      for (const d of diags) {
        let m = /^unknown type name '([A-Za-z_]\w*)'/.exec(d.msg);
        if (m) {
          out.unknownTypes++;
          unknownTypes.add(m[1]);
          continue;
        }
        m = /^'([A-Za-z_]\w*)' undeclared/.exec(d.msg);
        if (!m || seen.has(m[1])) continue;
        seen.add(m[1]);
        const cls = classifyIdentifier(m[1], apiNames);
        out[cls]++;
        distinct[cls].add(m[1]);
        any = true;
        if (cls === "register") regs = true;
        out.rows.push({ fn: r.name, addr: r.addr, name: m[1], cls });
      }
      if (any) out.funcsAffected++;
      if (regs) out.funcsWithRegisters++;
    }
  }
  out.distinctRegister = distinct.register.size;
  out.distinctMinted = distinct.minted.size;
  out.distinctResidue = distinct.residue.size;
  out.distinctApi = distinct.api.size;
  out.distinctOther = distinct.other.size;
  out.distinctUnknownTypes = unknownTypes.size;
  out.otherNames = [...distinct.other].sort().slice(0, 24);
  return out;
}

// ── Unlifted instructions, by base mnemonic ─────────────────────────────────

export interface UnliftedRec {
  fn: string;
  addr: number;
  line: number;
  mnemonic: string;
  text: string;
}

export interface UnliftedResult {
  /** `/* unlifted: … *\/` sites in the emitted C. */
  sites: number;
  funcsAffected: number;
  /** Functions with code read. Liveness. */
  funcs: number;
  /** Sites by BASE mnemonic — a `lock` prefix stripped, a `rep`-family prefix kept as the bucket. */
  byMnemonic: Record<string, number>;
  /** The `rep`-family sites again, by their full two-token spelling. */
  repForms: Record<string, number>;
  rows: UnliftedRec[];
}

/**
 * The comment `emit.ts` writes for an instruction the lifter has no C for.
 * Quote-agnostic and indifferent to the trailing `;` and to indentation.
 */
const UNLIFTED = /\/\*\s*unlifted:\s*(.*?)\s*\*\//g;

/**
 * The mnemonic an unlifted site is filed under.
 *
 * The same rule `flagModel.ts`'s `withoutLockPrefix` applies, written
 * independently: a `lock` prefix changes atomicity and nothing about which
 * instruction went unlifted, so `lock or` files under `or`. A `rep`/`repne`
 * prefix is NOT stripped — the `rep` path in the lifter is what is dead against
 * real Capstone output (`lifter.test.ts`), so the prefix is the bucket the
 * lifts child will look for, and the string operation it wraps is kept beside
 * it in `repForms`.
 */
export function unliftedBaseMnemonic(text: string): { base: string; repForm: string | null } {
  const tokens = text.trim().toLowerCase().split(/\s+/);
  const first = tokens[0] ?? "";
  if (first === "lock" && tokens.length > 1) return { base: tokens[1], repForm: null };
  if (/^rep(?:n?[ez])?$/.test(first) && tokens.length > 1)
    return { base: first, repForm: `${first} ${tokens[1]}` };
  return { base: first, repForm: null };
}

/**
 * EVERY INSTRUCTION THE EMITTED C ADMITS IT DID NOT LIFT, BY MNEMONIC.
 *
 * The census `peek-a-bin-n9cl` was planned from (leave 145, sbb 96, bts 94,
 * movdqa 54, movnti 48, movabs 42, rep 32, btr 18 at `6299113`) was ad hoc;
 * this makes it a row. A RISE in any bucket between two pinned runs is judged
 * a regression in `compare.mjs`: an instruction that was lifted and no longer
 * is hands the reader less than the commit before. The absolute is not gated
 * in the run — nothing says what the right number of unlifted `movdqa` is, and
 * CLAUDE.md records that the 16-byte moves have no C spelling at all.
 *
 * `funcs` is the liveness half. A text scrape fails by matching nothing, and
 * this one's good direction is downward, so a scan that stopped seeing the
 * comment would report the best number in the report.
 */
export function unliftedCensus(sets: { funcs: FuncRec[] }[]): UnliftedResult {
  const out: UnliftedResult = {
    sites: 0,
    funcsAffected: 0,
    funcs: 0,
    byMnemonic: {},
    repForms: {},
    rows: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      if (code === "") continue;
      out.funcs++;
      let hits = 0;
      const lines = code.split("\n");
      for (let i = 0; i < lines.length; i++) {
        UNLIFTED.lastIndex = 0;
        for (const m of lines[i].matchAll(UNLIFTED)) {
          hits++;
          const { base, repForm } = unliftedBaseMnemonic(m[1]);
          out.byMnemonic[base] = (out.byMnemonic[base] ?? 0) + 1;
          if (repForm !== null) out.repForms[repForm] = (out.repForms[repForm] ?? 0) + 1;
          out.rows.push({ fn: r.name, addr: r.addr, line: i + 1, mnemonic: base, text: m[1] });
        }
      }
      out.sites += hits;
      if (hits > 0) out.funcsAffected++;
    }
  }
  return out;
}

// ── A void function that returns a value ────────────────────────────────────

export interface VoidReturnResult {
  /** Signature lines located. Liveness. */
  headers: number;
  voidHeaders: number;
  /** `void` header AND a `return <expr>;` in the body. The row. Expect 0 once gated. */
  voidValued: number;
  /** Non-void header with a valued return — the ordinary case, and liveness. */
  nonVoidValued: number;
  /** `void` header with a bare `return;`. Reported; 0 across this corpus. */
  voidBare: number;
  /** Functions with code read. Liveness. */
  funcs: number;
  rows: string[];
}

/** The return type on a signature line: everything before the function's name. */
export function headerReturnType(line: string): string | null {
  const m = /^(.*?)\s*\b([A-Za-z_]\w*)\s*\(/.exec(line.trim());
  return m ? m[1].trim() : null;
}

const VALUED_RETURN = /\breturn\s+[^;\s][^;]*;/;
const BARE_RETURN = /\breturn\s*;/;

/**
 * A FUNCTION DECLARED `void` WHOSE BODY RETURNS A VALUE.
 *
 * `promote.ts`'s `hasReturnValue` decides the return type by looking for a
 * valued `return` in the structured body, and it recurses into `if`, `while`
 * and `do_while` only — not `for`, `switch`, `try` or a labelled region — so a
 * function whose only valued return sits inside one of those is declared `void`
 * and then says `return rax;`. That is a wrong statement about the function's
 * interface, and gcc accepts it (`return` with a value in a void function is a
 * warning, silenced by `-w`). The return-type child of `peek-a-bin-n9cl` is
 * expected to take `voidValued` to 0, at which point it gates; here it is
 * report-only.
 *
 * Two liveness halves: `nonVoidValued` says the body scan still finds valued
 * returns at all, and `headers` says the signature grammar still matches. The
 * bead also asked for `voidBare > 0` — a void function with a bare `return;` —
 * and that control is INERT on this corpus: the emitter elides a trailing
 * `return;`, so the count is 0 on all four binaries at `6299113`. It is reported
 * rather than asserted, and recorded here so nobody re-adds the assertion.
 */
export function voidReturnsValue(sets: { funcs: FuncRec[] }[]): VoidReturnResult {
  const out: VoidReturnResult = {
    headers: 0,
    voidHeaders: 0,
    voidValued: 0,
    nonVoidValued: 0,
    voidBare: 0,
    funcs: 0,
    rows: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      if (code === "") continue;
      out.funcs++;
      const sig = declaredParams(code);
      if (sig === null) continue;
      out.headers++;
      const rt = headerReturnType(sig.line);
      const isVoid = rt !== null && /(^|\s)void$/.test(rt);
      const body = code.slice(sig.bodyAt);
      const valued = VALUED_RETURN.test(body);
      if (isVoid) {
        out.voidHeaders++;
        if (valued) {
          out.voidValued++;
          if (out.rows.length < 12) out.rows.push(r.name);
        }
        if (BARE_RETURN.test(body)) out.voidBare++;
      } else if (valued) out.nonVoidValued++;
    }
  }
  return out;
}

// ── Stack-pointer scaffolding in the emitted C ──────────────────────────────

export interface StackPointerResult {
  /** Functions with code read. Liveness. */
  funcs: number;
  /** Functions whose body mentions the stack pointer at all. */
  mentioning: number;
  /** Functions with a stack-pointer WRITE and no stack-pointer READ. */
  writeNoRead: number;
  /** Stack-pointer reads, in total — the raw `rspReadsKept` before any reason exists. */
  reads: number;
  writes: number;
  /** `= rsp;` / `= esp;` — a register copy of the stack pointer. */
  copies: number;
  /** `rsp -= ` / `esp -= `. */
  subs: number;
  /** `rsp += ` / `esp += `. */
  adds: number;
  /** `rsp + 0x` / `esp + 0x` — the address of a frame slot. */
  offsets: number;
  /** `^ rsp` / `^ esp` — the /GS cookie mixing. */
  xors: number;
  /** `/* unlifted: leave *\/` sites. */
  unliftedLeave: number;
  rows: string[];
}

const SP_TOKEN = /\b([re]sp)(?:_\d+)?\b/g;

/**
 * HOW MUCH OF THE EMITTED C IS THE STACK POINTER TALKING TO ITSELF.
 *
 * Prologue and epilogue arithmetic (`rsp -= 0x28`), the frame-pointer copy
 * (`rbp = rsp`), the /GS cookie (`rax ^= rsp`) and the address of a slot
 * (`rcx = rsp + 0x30`) are all true statements about the machine and none of
 * them is what a reader wants to see; epic 2's prologue normalisation is sized
 * by this census. REPORT-ONLY: a stack-pointer mention is not a defect, and the
 * shapes are counted so a change can be seen to remove the shape it claims to
 * and no other. `writeNoRead` is the gateable candidate — a function that
 * adjusts RSP and never reads it back is one whose scaffolding could be
 * elided entirely — and it is the report half of a gate that does not exist
 * yet. `reads` is the raw count the future `rspReadsKept`-by-reason row will
 * split; reasons only exist once `prologue.ts` lands.
 *
 * `mentioning` and `funcs` are the liveness halves.
 */
export function stackPointerScaffolding(sets: { funcs: FuncRec[] }[]): StackPointerResult {
  const out: StackPointerResult = {
    funcs: 0,
    mentioning: 0,
    writeNoRead: 0,
    reads: 0,
    writes: 0,
    copies: 0,
    subs: 0,
    adds: 0,
    offsets: 0,
    xors: 0,
    unliftedLeave: 0,
    rows: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      if (code === "") continue;
      out.funcs++;
      // The body without its declaration block: `int64_t rsp;` is not a read
      // (see `stripDeclarationBlock`).
      const stripped = stripDeclarationBlock(code);
      const sig = declaredParams(stripped);
      const body = sig === null ? stripped : stripped.slice(sig.bodyAt);
      let reads = 0;
      let writes = 0;
      SP_TOKEN.lastIndex = 0;
      for (const m of body.matchAll(SP_TOKEN)) {
        const after = body.slice((m.index ?? 0) + m[0].length);
        if (/^\s*(?:-=|\+=|=(?!=))/.test(after)) writes++;
        else reads++;
      }
      if (reads + writes > 0) out.mentioning++;
      if (writes > 0 && reads === 0) {
        out.writeNoRead++;
        if (out.rows.length < 12) out.rows.push(r.name);
      }
      out.reads += reads;
      out.writes += writes;
      // A plain copy, not a compound assignment: `rax ^= rsp;` is the xor row.
      out.copies += (body.match(/(?<![-+*/^&|!<>=])=\s*[re]sp\s*;/g) ?? []).length;
      out.subs += (body.match(/\b[re]sp\s*-=\s/g) ?? []).length;
      out.adds += (body.match(/\b[re]sp\s*\+=\s/g) ?? []).length;
      out.offsets += (body.match(/\b[re]sp\s*\+\s*0x/g) ?? []).length;
      out.xors += (body.match(/\^=?\s*[re]sp\b/g) ?? []).length;
      out.unliftedLeave += (body.match(/unlifted:\s*leave\b/g) ?? []).length;
    }
  }
  return out;
}

// ── Adjacent copy pairs ─────────────────────────────────────────────────────

export interface CopyPairResult {
  /** Adjacent `v = X; r = v;` pairs. */
  pairs: number;
  /** Of those, `r` a bare register and `v` that register's own versioned name — `swapDefWithCopy`'s exact shape. */
  versionToRegister: number;
  funcsAffected: number;
  /** Functions with code read. Liveness. */
  funcs: number;
  /** Statement lines read. Liveness. */
  lines: number;
  rows: string[];
}

const ASSIGN = /^([A-Za-z_]\w*)\s*=(?!=)\s*(.+);$/;
/**
 * The copy's source may carry ONE narrowing cast: since peek-a-bin-n9cl.4 a
 * 32-bit write into a 64-bit register variable is `rax = (uint32_t)eax_3;`, and
 * that is `swapDefWithCopy`'s shape exactly as `eax = eax_3;` is. Without it the
 * row fell 494 → 368 on t64 at `2328657` on a census that had changed nothing.
 */
const COPY = /^([A-Za-z_]\w*)\s*=(?!=)\s*(?:\((?:u?int(?:8|16|32|64)_t)\))?([A-Za-z_]\w*);$/;

/**
 * `v = X;` IMMEDIATELY FOLLOWED BY `r = v;` — A DEFINITION AND ITS COPY.
 *
 * `ssadestroy.ts`'s `swapDefWithCopy` writes a split-out value to its variable
 * first and the register from the variable second, on purpose: appending the
 * copy the other way round lost the register's only assignment to `foldBlock`
 * (its docstring has the measurement). The pair it leaves is correct and is
 * also two lines where a reader would want one. Whether a dead-copy elimination
 * pass (epic 2, A6) is worth a session is decided by this count, so it is a
 * row: REPORT-ONLY, both directions — a fall is the pass landing, a rise is
 * more values being split, and neither is a wrong statement about the machine.
 *
 * `versionToRegister` is the exact `swapDefWithCopy` shape — `ecx_1 = X;
 * ecx = ecx_1;` — and `pairs` is the wider adjacency, so a pass that removes
 * one shape and not the other is visible. `lines` is the liveness half; the
 * pair count itself must not be asserted non-zero, since the pass this sizes
 * would legitimately take it to 0.
 */
export function copyPairs(sets: { funcs: FuncRec[] }[]): CopyPairResult {
  const out: CopyPairResult = {
    pairs: 0,
    versionToRegister: 0,
    funcsAffected: 0,
    funcs: 0,
    lines: 0,
    rows: [],
  };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      if (code === "") continue;
      out.funcs++;
      // Statement lines only: the declaration block is not statements, and a
      // pair straddling it would be one that is not adjacent on the page.
      const lines = stripDeclarationBlock(code)
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      out.lines += lines.length;
      let hits = 0;
      for (let i = 0; i + 1 < lines.length; i++) {
        const a = ASSIGN.exec(lines[i]);
        if (a === null) continue;
        const c = COPY.exec(lines[i + 1]);
        if (c === null || c[2] !== a[1] || c[1] === a[1]) continue;
        hits++;
        // `ecx_1 = X; ecx = ecx_1;` — the copy's destination is a bare register
        // and the definition's is that register's own versioned spelling.
        const bareReg = REGISTER_NAME.test(c[1]) && !/_\d+$/.test(c[1]);
        if (bareReg && new RegExp(`^${c[1]}_\\d+$`).test(a[1])) out.versionToRegister++;
        if (out.rows.length < 8) out.rows.push(`${r.name}: ${lines[i]} ${lines[i + 1]}`);
      }
      out.pairs += hits;
      if (hits > 0) out.funcsAffected++;
    }
  }
  return out;
}
