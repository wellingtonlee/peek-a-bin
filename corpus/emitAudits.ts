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
