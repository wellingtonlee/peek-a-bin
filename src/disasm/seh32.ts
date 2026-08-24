/**
 * MSVC's 32-bit SEH scope table, read as a FUNCLET-OF-PARENT RELATION.
 *
 * ## What the table is, and why it is not reachable from the PE headers
 *
 * A 32-bit MSVC function that uses `__try`/`__finally` or `__try`/`__except`
 * opens `push <framesize>; push <scopetable>; call __SEH_prolog4`. The second
 * immediate is the address of an `_EH4_SCOPETABLE` in `.rdata`:
 *
 * ```c
 * struct _EH4_SCOPETABLE {                 // 16 bytes
 *     int GSCookieOffset, GSCookieXOROffset, EHCookieOffset, EHCookieXOROffset;
 *     struct { int EnclosingLevel; void *FilterFunc; void *HandlerFunc; }
 *         ScopeRecord[];                   // 12 bytes each, NO count field
 * };
 * ```
 *
 * Nothing in the PE directories points at it — the only thing that names the
 * table is the `push` in the parent's own prologue — so this is a `src/disasm/`
 * capability rather than a `src/pe/` one, however much it looks like a format
 * structure. It is also x86-only: on x64 the same information is in `.pdata`
 * and `.xdata`, which `pe/pdata.ts` already reads.
 *
 * ## Why a relation and not a set of protected addresses
 *
 * A record names two addresses inside the parent: the `__except` filter (null
 * for `__finally`) and the handler. Both are **funclets of that parent** —
 * emitted inside it, run on its frame with no prologue of their own, reached by
 * a `call` from the parent or by the unwinder. So what the table states is
 * "this address is a funclet OF that function", which is strictly more than
 * "this address is named".
 *
 * That distinction is the whole reason this module exists rather than a line
 * added to `functionDetect.ts`'s `strongStarts`. Putting the handlers in that
 * set would *protect* them from withdrawal, and `t32!sub_4031A4` is the
 * counterexample: its table names handler 0x403270, and 0x403276 sits six bytes
 * inside that funclet, past the register reloads only the unwinder needs.
 * Protecting either address cuts the parent in half again, which is
 * `peek-a-bin-g7yp`. The relation says the opposite thing — the named address
 * is *interior* to the parent — and that is what
 * `interiorBranchedOverStarts` consumes (peek-a-bin-sysf, peek-a-bin-d827).
 *
 * ## What bounds the walk
 *
 * There is no count field, so the records are read until one is malformed. Three
 * things have to hold of a record, and together they stop the walk exactly at
 * the end of every table in the corpus:
 *
 *  * **`EnclosingLevel` is `-2` (TRYLEVEL_NONE) or the index of an earlier
 *    record.** Scope levels nest, so a level can only name a record already
 *    read. Record 0 must therefore be `-2` exactly.
 *  * **`HandlerFunc` is inside the code section.** A handler is code.
 *  * **`FilterFunc` is null or inside the code section.** Null is `__finally`.
 *
 * Measured over t32.exe and w32.exe: 31 and 29 tables, and the walk stops on
 * the first malformed record in every one — at `t32` 0x411370 the next words
 * are `{0, 0xfffffffe, 0}`, whose filter is not an address, and at 0x411450
 * `{70824, 0, 0}`, whose level is neither `-2` nor an index and whose handler is
 * not code. Both were checked by hand against the following table's own
 * address. {@link MAX_SEH32_SCOPE_RECORDS} is hostile-input hygiene: a crafted
 * `.rdata` could make an arbitrarily long chain of well-formed records, and
 * stopping early only ever withdraws fewer starts, which is today's behaviour.
 */

import { loneImmediate } from "./stackIdiom";

/** Little-endian reads at a virtual address, or null where nothing maps it. */
export interface Seh32Reader {
  i32(addr: number): number | null;
  u32(addr: number): number | null;
}

/** One `_EH4_SCOPETABLE_RECORD`. `filter === 0` means `__finally`. */
export interface Seh32ScopeRecord {
  enclosingLevel: number;
  filter: number;
  handler: number;
}

/** `GSCookieOffset` … `EHCookieXOROffset` — four `int`s before the records. */
export const SEH32_SCOPETABLE_HEADER_BYTES = 16;

/** `{ EnclosingLevel; FilterFunc; HandlerFunc; }`. */
export const SEH32_SCOPE_RECORD_BYTES = 12;

/**
 * Ceiling on records read from one table. The tables in this corpus hold one or
 * two; the deepest `__try` nesting MSVC will emit is bounded by the source, not
 * by anything in the file, so this is a hostile-input bound rather than a
 * measured one.
 */
export const MAX_SEH32_SCOPE_RECORDS = 64;

/**
 * How many instructions from a function's entry are read looking for the
 * `push <framesize>; push <scopetable>; call __SEH_prolog4` head. Enough for a
 * hot-patch pad, {@link MAX_SEH32_PROLOG_PUSHES} pushes and the `call`.
 */
export const MAX_SEH32_HEAD_INSNS = 8;

/**
 * How many leading `push <imm>`s are taken as the helper's arguments.
 * `__SEH_prolog4` takes two; the bound keeps this off an ordinary call with a
 * long immediate argument list.
 */
export const MAX_SEH32_PROLOG_PUSHES = 4;

/** Instructions a function may open with before its real prologue. */
const HEAD_PADDING = new Set(["nop", "int3"]);

/** Just enough of an instruction to read a prologue head. */
export interface HeadInsn {
  mnemonic: string;
  opStr: string;
}

/**
 * A prologue head, read one instruction at a time.
 *
 * `undefined` for an index past the end — whether because the head ran out of
 * instructions, out of window, or into a byte the decoder refused; the three
 * are the same answer to this rule and were the same answer when this was an
 * array whose length simply stopped.
 *
 * A PULL rather than an array, and the reason is measured rather than
 * stylistic. The caller decoded {@link MAX_SEH32_HEAD_INSNS} instructions at
 * every candidate start, and {@link seh32PrologImmediates} bails at the first
 * instruction that is not padding and not a pushed immediate — which is nearly
 * all of them, since an ordinary MSVC entry begins `push ebp` and a Go one
 * begins with a stack check. Instrumented over t32/w32 and two Windows/x86 `go`
 * builds at `e9e6eaa`: **8.00 instructions decoded per head against 1.00-1.89
 * consumed**, so 76-88% of the decoding was of instructions no rule ever looked
 * at. Pulling makes those decodes not happen and leaves the ones that do happen
 * identical, in the same order — so it cannot change an answer, which matters
 * more here than the milliseconds: this feeds the fifth withdrawal admission in
 * `functionDetect.ts` and therefore function boundaries (peek-a-bin-6dv3).
 */
export type HeadReader = (index: number) => HeadInsn | undefined;

/**
 * `push 0x411050` → 0x411050; anything else → null.
 *
 * The immediate itself goes through `stackIdiom.ts`'s {@link loneImmediate},
 * which is this repo's one declaration of "a lone immediate operand" and knows
 * that Capstone prints a sign-extended `push imm8` in signed decimal. A
 * negative value is not a table address and is refused by
 * {@link readSeh32ScopeTable}, so nothing here has to know that.
 */
function pushedImm(insn: HeadInsn): number | null {
  if (insn.mnemonic.trim().toLowerCase() !== "push") return null;
  return loneImmediate(insn.opStr);
}

/** `mov edi, edi` — MSVC's two-byte hot-patch pad, not a definition of EDI. */
function isHotPatchPad(insn: HeadInsn): boolean {
  if (insn.mnemonic.trim().toLowerCase() !== "mov") return false;
  const parts = insn.opStr.split(",").map((p) => p.trim().toLowerCase());
  return parts.length === 2 && parts[0] === parts[1] && /^e(di|si|bp|bx|ax|cx|dx)$/.test(parts[0]);
}

/**
 * The immediates a function's entry pushes as arguments to a direct `call`.
 *
 * Deliberately *every* leading pushed immediate rather than "the last one":
 * which argument carries the scope table is a fact about `__SEH_prolog4`'s
 * signature, and the discriminator that does not need to know it is already
 * available — a frame size is a small integer that no section maps, while a
 * scope table resolves to readable data holding a well-formed record. So the
 * caller tries each and the table itself decides.
 */
export function seh32PrologImmediates(head: HeadReader): number[] {
  let i = 0;
  let at = head(0);
  while (
    at !== undefined &&
    (HEAD_PADDING.has(at.mnemonic.trim().toLowerCase()) || isHotPatchPad(at))
  ) {
    i++;
    at = head(i);
  }

  const imms: number[] = [];
  while (at !== undefined && imms.length <= MAX_SEH32_PROLOG_PUSHES) {
    const imm = pushedImm(at);
    if (imm === null) break;
    imms.push(imm);
    i++;
    at = head(i);
  }
  if (imms.length === 0 || imms.length > MAX_SEH32_PROLOG_PUSHES) return [];

  // The pushes have to be the arguments of a direct call, or they are not
  // arguments at all. This is what keeps the search off an ordinary
  // `push <string literal>` in the middle of a prologue-shaped head.
  const call = head(i);
  if (call === undefined || call.mnemonic.trim().toLowerCase() !== "call") return [];
  if (!/^0x[0-9a-fA-F]+$/.test(call.opStr.trim())) return [];
  return imms;
}

/**
 * The records of the `_EH4_SCOPETABLE` at `tableAddr`, or `[]` where the bytes
 * there are not one. See the header for what bounds the walk.
 *
 * `isCodeAddress` is the code section's own extent, and it is the test that
 * makes a handler a handler. `tableAddr` itself must NOT be code: a scope table
 * is read-only data, and requiring that is what makes a frame-size immediate —
 * which maps to nothing at all — cost no work to reject.
 */
export function readSeh32ScopeTable(
  tableAddr: number,
  reader: Seh32Reader,
  isCodeAddress: (addr: number) => boolean,
): Seh32ScopeRecord[] {
  if (!Number.isInteger(tableAddr) || tableAddr <= 0) return [];
  if (isCodeAddress(tableAddr)) return [];
  // The header is not interpreted — the cookie offsets are frame offsets and
  // say nothing about the records — but it must be readable, or `tableAddr`
  // does not name a table.
  if (reader.i32(tableAddr + SEH32_SCOPETABLE_HEADER_BYTES - 4) === null) return [];

  const records: Seh32ScopeRecord[] = [];
  for (let i = 0; i < MAX_SEH32_SCOPE_RECORDS; i++) {
    const at = tableAddr + SEH32_SCOPETABLE_HEADER_BYTES + i * SEH32_SCOPE_RECORD_BYTES;
    const enclosingLevel = reader.i32(at);
    const filter = reader.u32(at + 4);
    const handler = reader.u32(at + 8);
    if (enclosingLevel === null || filter === null || handler === null) break;
    if (enclosingLevel !== -2 && !(enclosingLevel >= 0 && enclosingLevel < i)) break;
    if (!isCodeAddress(handler)) break;
    if (filter !== 0 && !isCodeAddress(filter)) break;
    records.push({ enclosingLevel, filter, handler });
  }
  return records;
}

/**
 * The funclet addresses a function's prologue attributes to itself — the filter
 * and handler of every record of the scope table it passes to `__SEH_prolog4`.
 *
 * Filters are included as well as handlers, and on this corpus that is a
 * widening with **0 occurrences**: the four filter addresses over the two
 * 32-bit binaries are all already folded into their parents. It is included
 * because the record says the same thing about both fields — this is the filter
 * and this is the handler *of this scope, in this function* — and excluding one
 * would be a narrowing with no evidence behind it.
 */
export function seh32FuncletsOfPrologue(
  head: HeadReader,
  reader: Seh32Reader,
  isCodeAddress: (addr: number) => boolean,
): number[] {
  const funclets: number[] = [];
  for (const imm of seh32PrologImmediates(head)) {
    for (const rec of readSeh32ScopeTable(imm, reader, isCodeAddress)) {
      funclets.push(rec.handler);
      if (rec.filter !== 0) funclets.push(rec.filter);
    }
  }
  return funclets;
}
