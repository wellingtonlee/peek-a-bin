/**
 * WHAT THE EMITTED C CALLS A DEREFERENCED ABSOLUTE ADDRESS, AND WHAT IT LEFT RAW.
 *
 * `emit.ts`'s `globalAt` names a dereferenced constant `g_<HEX>` when the
 * `NamingContext`'s section table places it in a data section, `__imp_<func>`
 * when it is an IAT slot read at the pointer width, and leaves everything else
 * as `*(T*)(0x…)` (peek-a-bin-5b6q.4). This census reads the emitted text and
 * the section table back and reports, per binary:
 *
 *   - **derefsAbsolute** — the `*(T*)(0x…)` sites still on the page, split by
 *     where the address falls: `unplaced` (in NO section — must stay raw, the
 *     emitter's own refusal), `inCode` (a code address read as data — jump
 *     tables, `.text`-resident constants; not this bead's), `inData` (a data
 *     address the emitter declined: a string's address keeps its literal
 *     spelling, a slot read narrower than a pointer, a cookie whose two
 *     readings disagree). The baseline before naming was 1320 sites over 441
 *     functions across the four binaries.
 *   - **named** — distinct `g_` globals declared, `namedSites` their mentions in
 *     the body, `mixedWidth` those declared as byte arrays because the body
 *     read them at more than one width.
 *   - **namedImp** — `__imp_` slots declared, `impSites` their mentions.
 *   - **namedUnplaced** — a `g_` whose address is in no data section. MUST be 0:
 *     a `g_` claims a section, and this is a false claim. Pinned by the
 *     `UNPLACED CONTROL` case in `pipeline.test.ts`; reported here rather than
 *     gated, on the parent bead's instruction, so a rise is read in
 *     `compare.mjs` — treat one as a defect.
 *   - **addressLiterals** — bare hex constants equal to a data-section address
 *     that are NOT dereferenced: the address-taken residue (`lea rcx, [rip+X]`,
 *     a pointer passed on) this stage deliberately leaves literal, because the
 *     value coincidence is exactly the provenance the naming rule refuses.
 *   - **stringDerefs** — `*(T*)("…")`, a deref of a string's address, which keeps
 *     the older literal substitution.
 *   - **pfnDeclared / pfnDistinct / pfnEncoded / pfnSites** — the `pfn_<proc>`
 *     slots (peek-a-bin-5b6q.5): `extern intptr_t pfn_X;` declarations, whose
 *     trailing comment reads `GetProcAddress("X") stored at 0x…` and, where the
 *     value went through `EncodePointer`, `EncodePointer-wrapped`; distinct
 *     addresses (read from that comment), how many are encoded, and body
 *     mentions. **pfnUnplaced** is a `pfn_` whose address is in no data section
 *     — the pre-pass does not consult the section table, so this is the census
 *     asking the question for it; expect 0. **indirectCasts** is every
 *     `((intptr_t (*)())…)` on the page and **pfnCallSites** those whose value
 *     is a `pfn_` name directly — the call site is NOT rewritten, so this rises
 *     only where copy propagation carried the name into the call; a read through
 *     `DecodePointer(pfn_X)` is **pfnDecodeReads**. `BinResult.pfnPrepass`
 *     carries the pre-pass's own recognised/refused-by-reason counts beside
 *     these, so "found by the pass" and "reached the page" are two numbers.
 *
 * **REPORT-ONLY, and the reason is the residue's character.** A raw deref is an
 * incompleteness, not a falsehood — `*(int32_t*)(0x414620)` is what the machine
 * does — so the class has `undefinedCallees`' character and not
 * `unencodableNames`'. Nothing else here can see it: gcc compiles a raw deref
 * as happily as a named one, and `preludeFor`, which used to complete the three
 * `__imp_` thunk names as `long __imp_X;`, now finds them declared — so the
 * `undeclared identifiers` census's `other` class moves DOWN by exactly those
 * (the only movement this bead makes there).
 *
 * **Liveness:** `named > 0` per binary — a text scan fails by matching nothing,
 * and both x86 and x64 MSVC CRTs read `.data` globals in dozens of functions.
 *
 * **What it cannot see.** Whether `g_414620` is ONE object: a stride walk
 * through an array at `0x414620 + eax*4` is an indexed deref and is not named
 * at all (the base is not a bare constant), but two scalars at 0x414620 and
 * 0x414624 are two globals here even if MSVC's source had one struct. Nor the
 * TYPE: `int32_t` is the width the body read, not the declaration MSVC had.
 * The patterns are written out rather than imported from `naming.ts` so the
 * audit does not agree with the emitter by construction.
 */

import type { FuncRec } from "./sweep";

/** A section as the sweep records it: VA extent, name, and whether the naming rule treats it as data. */
export interface SectionRow {
  va: number;
  size: number;
  name: string;
  data: boolean;
}

/** One raw `*(T*)(0x…)` site left on the page. */
export interface RawDerefRec {
  fn: string;
  addr: number;
  va: number;
  /** Where the address falls: see the header. */
  cls: "unplaced" | "inCode" | "inData";
  section: string | null;
  line: number;
  text: string;
}

export interface GlobalsResult {
  derefsAbsolute: number;
  unplaced: number;
  inCode: number;
  inData: number;
  /** Functions with at least one raw absolute deref left. */
  funcsWithRaw: number;
  /** Distinct `g_` declarations (one per function that names the address). */
  named: number;
  /** Distinct `g_` addresses across the binary. */
  namedDistinct: number;
  namedSites: number;
  mixedWidth: number;
  /** `g_` declarations whose address is in no data section. MUST be 0 — see the header. */
  namedUnplaced: number;
  namedImp: number;
  impSites: number;
  addressLiterals: number;
  stringDerefs: number;
  /** `pfn_` declarations (one per function per address), distinct addresses, encoded ones, body mentions. */
  pfnDeclared: number;
  pfnDistinct: number;
  pfnEncoded: number;
  pfnSites: number;
  /** `pfn_` declarations whose address is in no data section. Expect 0 — see the header. */
  pfnUnplaced: number;
  /** Every `((intptr_t (*)())…)` cast on the page, and those whose value is a `pfn_` name. */
  indirectCasts: number;
  pfnCallSites: number;
  /** `DecodePointer(pfn_X)` reads. */
  pfnDecodeReads: number;
  /** Functions with at least one `g_` or `__imp_` declaration. */
  funcsNaming: number;
  /** Functions read — the liveness denominator. */
  funcs: number;
  rows: RawDerefRec[];
  /** Every `g_` declared outside a data section, for adjudication. Expect none. */
  unplacedNamed: { fn: string; addr: number; name: string; va: number }[];
  /** Every `pfn_` declared, with its address and whether the table places it in a data section. */
  pfnRows: {
    fn: string;
    addr: number;
    name: string;
    va: number;
    encoded: boolean;
    section: string | null;
  }[];
}

/** `*(int32_t*)(0x414620)` — the raw spelling, with the address captured. */
const RAW_DEREF = /\*\(u?int\d+_t\*\)\(0x([0-9A-Fa-f]+)\)/g;
/** `*(uint8_t*)("…` — a dereferenced string address. */
const STRING_DEREF = /\*\(u?int\d+_t\*\)\("/g;
/** `extern int32_t g_414620;` or `extern uint8_t g_414620[];` — the declaration, scalar or byte array. */
const G_DECL = /^extern \S+ \*?(g_([0-9A-Fa-f]+))(\[\])?;/;
/** `extern void *__imp_X;` */
const IMP_DECL = /^extern void \*__imp_[A-Za-z_]\w*;/;
/**
 * The `pfn_` declaration line, read UNMASKED because the address is in its
 * comment: `extern intptr_t pfn_X;` followed by a comment reading
 * `GetProcAddress("X") stored at 0x…` and, when encoded, `EncodePointer-wrapped`.
 */
const PFN_DECL =
  /^extern intptr_t (pfn_[A-Za-z0-9_]+); \/\* GetProcAddress\("[^"]*"\) stored at 0x([0-9A-Fa-f]+)(, EncodePointer-wrapped)? \*\//;
const PFN_MENTION = /\bpfn_[A-Za-z0-9_]+\b/g;
const INDIRECT_CAST = /\(\(intptr_t \(\*\)\(\)\)/g;
const PFN_CALL_SITE = /\(\(intptr_t \(\*\)\(\)\)pfn_[A-Za-z0-9_]+\)/g;
const PFN_DECODE_READ = /\bDecodePointer\(pfn_[A-Za-z0-9_]+\)/g;
const G_MENTION = /\bg_[0-9A-Fa-f]+\b/g;
const IMP_MENTION = /\b__imp_[A-Za-z_]\w*/g;
const HEX_LITERAL = /\b0x([0-9A-Fa-f]+)\b/g;

/** Comments and string literals blanked to spaces, so neither is read as code. */
function maskCommentsAndStrings(code: string): string {
  const out = code.split("");
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < out.length; k++) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  while (i < code.length) {
    const two = code.slice(i, i + 2);
    if (two === "//") {
      const end = code.indexOf("\n", i);
      const stop = end === -1 ? code.length : end;
      blank(i, stop);
      i = stop;
    } else if (two === "/*") {
      const end = code.indexOf("*/", i + 2);
      const stop = end === -1 ? code.length : end + 2;
      blank(i, stop);
      i = stop;
    } else if (code[i] === '"' || code[i] === "'") {
      const q = code[i];
      let j = i + 1;
      while (j < code.length && code[j] !== q && code[j] !== "\n") {
        if (code[j] === "\\") j++;
        j++;
      }
      blank(i, Math.min(j + 1, code.length));
      i = Math.min(j + 1, code.length);
    } else {
      i++;
    }
  }
  return out.join("");
}

function sectionAt(sections: readonly SectionRow[], va: number): SectionRow | undefined {
  return sections.find((s) => va >= s.va && va < s.va + s.size);
}

export const emptyGlobals = (): GlobalsResult => ({
  derefsAbsolute: 0,
  unplaced: 0,
  inCode: 0,
  inData: 0,
  funcsWithRaw: 0,
  named: 0,
  namedDistinct: 0,
  namedSites: 0,
  mixedWidth: 0,
  namedUnplaced: 0,
  namedImp: 0,
  impSites: 0,
  addressLiterals: 0,
  stringDerefs: 0,
  pfnDeclared: 0,
  pfnDistinct: 0,
  pfnEncoded: 0,
  pfnSites: 0,
  pfnUnplaced: 0,
  indirectCasts: 0,
  pfnCallSites: 0,
  pfnDecodeReads: 0,
  funcsNaming: 0,
  funcs: 0,
  rows: [],
  unplacedNamed: [],
  pfnRows: [],
});

export function auditGlobals(
  sets: { funcs: FuncRec[] }[],
  sections: readonly SectionRow[],
): GlobalsResult {
  const out = emptyGlobals();
  const distinctNamed = new Set<number>();
  const distinctPfn = new Set<number>();
  for (const { funcs } of sets) {
    for (const f of funcs) {
      const code = f.code ?? "";
      if (code === "" || /^\/\/ /.test(code)) continue;
      out.funcs++;
      STRING_DEREF.lastIndex = 0;
      out.stringDerefs += [...code.matchAll(STRING_DEREF)].length;
      const masked = maskCommentsAndStrings(code);
      const lines = masked.split("\n");
      // Masking preserves newlines, so the two arrays line up.
      const unmasked = code.split("\n");
      let raw = 0;
      let naming = false;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        const pfnDecl = PFN_DECL.exec(unmasked[i]);
        if (pfnDecl) {
          naming = true;
          out.pfnDeclared++;
          const va = Number.parseInt(pfnDecl[2], 16);
          distinctPfn.add(va);
          const encoded = pfnDecl[3] !== undefined;
          if (encoded) out.pfnEncoded++;
          const sec = sectionAt(sections, va);
          if (!sec?.data) out.pfnUnplaced++;
          out.pfnRows.push({
            fn: f.name,
            addr: f.addr,
            name: pfnDecl[1],
            va,
            encoded,
            section: sec?.name ?? null,
          });
          continue;
        }
        const decl = G_DECL.exec(l);
        if (decl) {
          naming = true;
          out.named++;
          const va = Number.parseInt(decl[2], 16);
          distinctNamed.add(va);
          if (decl[3] === "[]") out.mixedWidth++;
          const sec = sectionAt(sections, va);
          if (!sec?.data) {
            out.namedUnplaced++;
            out.unplacedNamed.push({ fn: f.name, addr: f.addr, name: decl[1], va });
          }
          continue;
        }
        if (IMP_DECL.test(l)) {
          naming = true;
          out.namedImp++;
          continue;
        }
        // Body lines from here: mentions, raw derefs, and the literal residue.
        G_MENTION.lastIndex = 0;
        out.namedSites += [...l.matchAll(G_MENTION)].length;
        out.pfnSites += [...l.matchAll(PFN_MENTION)].length;
        out.indirectCasts += [...l.matchAll(INDIRECT_CAST)].length;
        out.pfnCallSites += [...l.matchAll(PFN_CALL_SITE)].length;
        out.pfnDecodeReads += [...l.matchAll(PFN_DECODE_READ)].length;
        IMP_MENTION.lastIndex = 0;
        out.impSites += [...l.matchAll(IMP_MENTION)].length;
        RAW_DEREF.lastIndex = 0;
        let rest = l;
        for (const m of l.matchAll(RAW_DEREF)) {
          raw++;
          out.derefsAbsolute++;
          const va = Number.parseInt(m[1], 16);
          const sec = sectionAt(sections, va);
          const cls: RawDerefRec["cls"] = !sec ? "unplaced" : sec.data ? "inData" : "inCode";
          out[cls]++;
          out.rows.push({
            fn: f.name,
            addr: f.addr,
            va,
            cls,
            section: sec?.name ?? null,
            line: i + 1,
            text: l.trim(),
          });
          // Blank the site so its address is not also counted as a literal.
          rest = rest.replace(m[0], " ".repeat(m[0].length));
        }
        HEX_LITERAL.lastIndex = 0;
        for (const m of rest.matchAll(HEX_LITERAL)) {
          const va = Number.parseInt(m[1], 16);
          if (sectionAt(sections, va)?.data) out.addressLiterals++;
        }
      }
      if (raw > 0) out.funcsWithRaw++;
      if (naming) out.funcsNaming++;
    }
  }
  out.namedDistinct = distinctNamed.size;
  out.pfnDistinct = distinctPfn.size;
  return out;
}
