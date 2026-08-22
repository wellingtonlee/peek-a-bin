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
  fields: { name: string; offset: number }[];
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
    const fields: { name: string; offset: number }[] = [];
    for (const line of body) {
      const f = /^\s+[A-Za-z_][\w *]*?\b((?:field|array)_0x[0-9A-F]+)\s*(?:\[[^\]]*\])?;/.exec(
        line,
      );
      if (f) fields.push({ name: f[1], offset: Number.parseInt(f[1].split("_0x")[1], 16) });
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
  labels: number;
  /** A `goto` naming a label the function never defines. Expect 0. */
  dangling: number;
  fnWithGoto: number;
  fnWithDangling: number;
}

/**
 * Every `goto` the emitted C contains must name a label that same function
 * defines. A dangling goto is C that does not compile and, before that, a
 * transfer the reader cannot follow. gcc catches these too (as "label used but
 * not defined"), but counting them directly says how many rather than how many
 * functions.
 */
export function gotoCheck(sets: { funcs: FuncRec[] }[]): GotoResult {
  const out: GotoResult = { gotos: 0, labels: 0, dangling: 0, fnWithGoto: 0, fnWithDangling: 0 };
  for (const { funcs } of sets) {
    for (const r of funcs) {
      const code = r.code ?? "";
      const g = [...code.matchAll(/^\s*goto ([A-Za-z_]\w*);/gm)].map((m) => m[1]);
      if (g.length === 0) continue;
      const defined = new Set([...code.matchAll(/^\s*(loc_[0-9A-F]+):$/gm)].map((m) => m[1]));
      out.fnWithGoto++;
      out.gotos += g.length;
      out.labels += defined.size;
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

/** The emitted signature's parameter names, or null where the line is not one. */
function declaredParams(code: string): { names: string[]; bodyAt: number } | null {
  // The emitter writes the signature as one line ending in `) {`, after the
  // typedefs and struct declarations. Anchored on the brace rather than on a
  // return type, so a spelling this audit does not know about cannot skip it.
  const m = /^[A-Za-z_][^;{}\n]*\(([^)]*)\)\s*\{[ \t]*$/m.exec(code);
  if (!m) return null;
  const names: string[] = [];
  for (const part of m[1].split(",")) {
    // `int64_t arg_0x30` -> `arg_0x30`; `void` and `...` yield nothing.
    const name = /([A-Za-z_]\w*)\s*$/.exec(part.trim());
    if (name && name[1] !== "void") names.push(name[1]);
  }
  return { names, bodyAt: m.index + m[0].length };
}

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
        const stmt = /^\s*=\s*([A-Za-z_]\w*)\s*;/.exec(body.slice(first.index + name.length));
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
