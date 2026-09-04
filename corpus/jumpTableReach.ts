/**
 * Which indirect dispatches does an image contain, and does the tool read them?
 *
 * THE INSTRUMENT peek-a-bin-2q5 AND peek-a-bin-6rge HAVE BEEN WAITING FOR. Both
 * beads are blocked on the same thing — no x64 PE with a table-dispatched
 * switch is available here — and both are the kind of block that is closed by
 * *pointing at a binary*, not by writing code. So this takes a path and answers
 * the question for whatever is at it: what dispatch shapes the image holds, how
 * many of them `detectFunctions` recovered a table for, and for each one it did
 * not, what evidence was standing there unread.
 *
 * It is deliberately NOT wired into `npm run corpus`. That run's header names
 * the four MSVC binaries every standing figure is measured against, and the
 * whole point here is to look at a binary that is *not* one of them — CLAUDE.md
 * carries a standing instruction never to put such a file in the corpus
 * directory, because the audits iterate over whatever they find there and an
 * extra binary silently changes the population of every gate. Run it with
 * `npm run corpus:jumptables -- <path>`.
 *
 * WHY IT IS DERIVED AND NOT TABULATED. peek-a-bin-ayhj measured this same
 * question with a probe that hard-coded 20 dispatch addresses read off one
 * `go build`, and declined to land it for exactly the right reason: a different
 * compiler version moves every one of them, so the file would have been stale
 * on arrival and could never run without a binary that is deliberately absent.
 * Everything here is computed from the image instead — the census comes out of
 * the decoded instruction stream, the section bounds out of the PE header — so
 * there is no constant to go stale and it runs against any PE at all. That is
 * what makes it durable enough to land, and landing it is the standing rule
 * (`peek-a-bin-02fa` lost an arity oracle to a deleted worktree; a staleness
 * audit later found `peek-a-bin-rjt`'s benchmark gone the same way).
 *
 * WHAT IT IS NOT. It is a census, not a gate and not a reader. It never decides
 * that a table exists — it reports what the tool decided and what the bytes
 * look like beside that decision — so it cannot over-recover, which is the one
 * direction this codebase refuses (`peek-a-bin-y1di`, `peek-a-bin-xqxy`). Its
 * `lea-base` and `bounded` columns are *evidence present*, never *table
 * confirmed*: a `lea` to an array of function pointers plus an unrelated nearby
 * `cmp` has both and is not a switch.
 *
 * CALIBRATION, and read it before treating an UNREAD row as a defect. On the
 * two 32-bit corpus binaries the unread-but-bounded population is 5 apiece, and
 * every one of the ten is a refusal this project made on purpose and wrote down:
 * t32 `0x40b7f1` / `0x40b985` and w32 `0x409491` / `0x409625` are
 * `overlappedTableExtent`'s Shape 1, whose `and <index>, 3` CLAUDE.md
 * deliberately declines to read as a bound because a mask says nothing about
 * which bytes are opcode; t32 `0x40b7f8` and w32 `0x409498` are its Shape 2, the
 * *negative*-index dispatch whose apparent base is a case body and which
 * CLAUDE.md says in terms must not be "fixed". So the correct reading of this
 * row is "here is what the tool declined and what stood beside it", and the
 * adjudication is still a human reading `objdump`.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { canonReg, isKnownRegister } from "../src/disasm/decompile/ir";
import { resolveRipTarget } from "../src/disasm/ripRelative";
import type { Instruction } from "../src/disasm/types";
import { FileSession } from "../src/mcp/session";
import { findCodeSection } from "../src/pe/sections";

/** How far back a bound or a table base may sit. `boundedCaseCount`'s own reach. */
const LOOKBACK = 14;

/**
 * The dispatch shapes, in the terms the readers are written in.
 *
 * The distinction that matters is where the table's ADDRESS comes from, not what
 * its entries look like — `peek-a-bin-ayhj` found the two conflated, and only
 * the former defeats a reader. `readAbsoluteTable` needs the address as a
 * literal in the dispatch operand; `recoverX64RvaChain` needs it in a register
 * the jump then adds to. A scaled operand whose base is a register and whose
 * displacement is absent is neither, and is the one shape nothing here reads.
 */
type Shape =
  /** `jmp [reg*N + 0xIMM]`, or `jmp [rip + N]` on x64 — `readAbsoluteTable`. */
  | "literal-indexed"
  /** `jmp [reg + reg*N]` with no displacement — no reader takes this. */
  | "register-base-indexed"
  /** `jmp reg` — `recoverX64RvaChain`'s entry point. */
  | "register"
  /** `jmp [reg]` or `jmp [rip + N]` with no scale — an import thunk, not a switch. */
  | "unscaled-memory";

/**
 * Which reader in `functionDetect.ts` a shape routes to — the structural answer
 * to "was this path even reached", derived from the operand rather than taken
 * from counters bolted into production code.
 *
 * The dense two-table reader (`readDenseRvaTable` / `recoverDenseByteTable`,
 * which is `peek-a-bin-6rge`'s subject) hangs off `readRvaTable` and is
 * therefore only ever reachable from the `register` shape, and only when
 * `recoverX64RvaChain` resolves a chain there. A `register` count of zero means
 * it did not run. A NON-ZERO ONE WITH NOTHING RECOVERED DOES NOT — measured on
 * fwupdx64.efi.signed at 0x5f6d, where the chain resolves, `boundedCaseCount`
 * returns 0 because the index comes from memory, and `readRvaTable` therefore
 * DOES call `readDenseRvaTable`, which then correctly refuses at its `byte ptr`
 * guard. Entering that reader and reading a table with it are different claims
 * (peek-a-bin-6rge).
 */
const READER: Record<Shape, string> = {
  "literal-indexed": "readAbsoluteTable",
  "register-base-indexed": "none — no reader takes this shape",
  register: "recoverX64RvaChain → readRvaTable → readDenseRvaTable",
  "unscaled-memory": "none — an import thunk, not a switch",
};

interface Site {
  address: number;
  opStr: string;
  shape: Shape;
  /** A rip-relative `lea` writing the operand's base register within reach. */
  leaBase: number | null;
  /** A `cmp`/`and` of an immediate against the subscript register within reach. */
  bound: number | null;
  boundKind: "cmp" | "and" | null;
  /** Did `detectFunctions` recover a table AT THIS DISPATCH? `jumpTables` is
   * keyed by the dispatch address, not by the table base. */
  recovered: boolean;
  /** Where the evidence says the table is: the operand's literal, or the `lea`. */
  tableBase: number | null;
}

/**
 * The 64-bit family a register spelling belongs to, or null if it is not one.
 *
 * `canonReg` is the canonical declaration of this mapping and `isKnownRegister`
 * is the membership test that must go with it — CLAUDE.md records that
 * `regSize()` is not one, because it falls back to 4 for any string. Both come
 * from `decompile/ir.ts` rather than being re-rolled here: the idiom mixes
 * widths on purpose (the bound is compared at 32 bits and the subscript used at
 * 64), so a comparison that is not by family reports nothing.
 */
function family(reg: string): string | null {
  const r = reg.trim().toLowerCase();
  return isKnownRegister(r) ? canonReg(r) : null;
}

/** The register a scaled operand subscripts with, and its base register if any. */
function parseIndexed(
  opStr: string,
): { base: string | null; index: string; disp: number | null } | null {
  // `[base + index*N + 0xIMM]`, `[index*N + 0xIMM]`, `[base + index*N]`
  const m = opStr.match(
    /\[\s*(?:([a-z][a-z0-9]*)\s*\+\s*)?([a-z][a-z0-9]*)\s*\*\s*[1248]\s*(?:\+\s*0x([0-9a-fA-F]+)\s*)?\]/i,
  );
  if (m) {
    const index = family(m[2]);
    if (index === null) return null;
    return {
      base: m[1] ? family(m[1]) : null,
      index,
      disp: m[3] ? parseInt(m[3], 16) : null,
    };
  }
  // `[base + index + 0xIMM]` — Capstone prints a SIB scale of 1 by omission.
  const one = opStr.match(
    /\[\s*([a-z][a-z0-9]*)\s*\+\s*([a-z][a-z0-9]*)\s*(?:\+\s*0x([0-9a-fA-F]+)\s*)?\]/i,
  );
  if (one) {
    const base = family(one[1]);
    const index = family(one[2]);
    if (base === null || index === null) return null;
    return { base, index, disp: one[3] ? parseInt(one[3], 16) : null };
  }
  return null;
}

function classify(insn: Instruction): Shape | null {
  const op = insn.opStr;
  if (!op.includes("[")) {
    // A bare register operand. Anything else — an immediate, a label, a
    // segment — is a direct branch and not a dispatch, and `isKnownRegister` is
    // what separates them; a bare regex would call `0x401000` a register.
    return family(op) !== null ? "register" : null;
  }
  const ix = parseIndexed(op);
  if (!ix) return "unscaled-memory";
  if (ix.disp !== null && ix.base === null) return "literal-indexed";
  if (/rip/i.test(op)) return "literal-indexed";
  if (ix.base !== null) return "register-base-indexed";
  return "literal-indexed";
}

/** The register a two-operand instruction writes: `cmp ecx, 8` → `"rcx"`. */
function firstOperandFamily(opStr: string): string | null {
  const first = opStr.split(",")[0];
  return first === undefined ? null : family(first);
}

function immediate(opStr: string): number | null {
  const hex = opStr.match(/,\s*0x([0-9a-fA-F]+)\s*$/);
  if (hex) return parseInt(hex[1], 16);
  const dec = opStr.match(/,\s*(\d+)\s*$/);
  return dec ? parseInt(dec[1], 10) : null;
}

/**
 * The index register of a `jmp <reg>` RVA-chain dispatch, or null.
 *
 * WHY THIS EXISTS. `parseIndexed` matches a BRACKETED operand, and a `jmp rax`
 * has no brackets — so before this, `indexReg` was null for every `register`
 * site, the `cmp`/`and` scan below was gated off, and the `bounded` column was a
 * STRUCTURAL ZERO rather than a measurement. Worse, the `UNREAD dispatches
 * carrying a bound` list filters on `bound !== null`, so it could never contain
 * an x64 RVA-chain dispatch at all: on a 64-bit image the census reported
 * "nothing to adjudicate" over exactly the population worth adjudicating, and a
 * real bounded miss (peek-a-bin-oovn) sat inside it unseen (peek-a-bin-hwyf).
 *
 * IT IS DELIBERATELY NOT A REIMPLEMENTATION of `recoverX64RvaChain`. It answers
 * one question — which register is the subscript — and it answers it only when
 * the scale-4 load is ANCHORED: the load's base register must be the other
 * operand of the `add` that feeds the jump. That anchor is what keeps this away
 * from the false positives the `tableBase` docstring below records (28 of 32 Go
 * `jmp reg` sites had an irrelevant `lea` in reach). An unanchored load is
 * ignored rather than guessed at.
 *
 * Both `add` operand orders are accepted here, on purpose and independently of
 * whether production accepts them: the census must be able to SEE a dispatch in
 * order to report that the reader missed it. That asymmetry is the point —
 * peek-a-bin-oovn is precisely a shape production refuses and the audit must not.
 *
 * WHAT IT STILL DOES NOT SEE, stated so the column is not over-read: the bound
 * scan below compares the `cmp`/`and` operand against this register directly,
 * where `boundedCaseCount` follows a narrowing `movzx`/`mov` back through
 * `regPair` first. So fwupd's RECOVERED site at 0x65dc contributes no bound to
 * the count — its index reaches `rax` via `movzx eax, dl` and the bound is
 * `cmp dl, 0x5`. The column is therefore a LOWER BOUND on bounded register
 * dispatches, not a census of them. Following the narrowing here would be a
 * second copy of production's rule inside the audit, which is the trade this
 * file declines everywhere else.
 */
function chainIndexReg(insns: readonly Instruction[], jmpAt: number): string | null {
  const jumpReg = family(insns[jmpAt].opStr);
  if (jumpReg === null) return null;

  for (let j = jmpAt - 1; j >= 0 && j >= jmpAt - LOOKBACK; j--) {
    const p = insns[j];
    const mn = p.mnemonic.toLowerCase();
    if (mn === "call") break;
    if (mn !== "add") continue;
    const pair = regPair(p.opStr);
    if (!pair) continue;
    // `add off, base` and `add base, off` both compute base+offset; which one
    // the jump reads is the whole of the difference. Either way the OTHER
    // operand is the register the scale-4 load must be based on.
    if (pair[0] !== jumpReg && pair[1] !== jumpReg) continue;
    const anchor = pair[0] === jumpReg ? pair[1] : pair[0];

    for (let k = j - 1; k >= 0 && k >= jmpAt - LOOKBACK; k--) {
      const q = insns[k];
      const qmn = q.mnemonic.toLowerCase();
      if (qmn === "call") return null;
      if (qmn !== "movsxd" && qmn !== "movsx" && qmn !== "mov") continue;
      const mem = parseIndexed(q.opStr);
      if (!mem) continue;
      // ANCHORED, or ignored: the load must read through the register the add
      // pairs with the jump register.
      if (mem.base !== null && mem.base !== anchor && mem.base !== jumpReg) continue;
      return mem.index;
    }
    return null;
  }
  return null;
}

/** `add a, b` -> the two register families, or null. */
function regPair(opStr: string): [string, string] | null {
  const m = opStr.match(/^\s*([a-z][a-z0-9]*)\s*,\s*([a-z][a-z0-9]*)\s*$/i);
  if (!m) return null;
  const a = family(m[1]);
  const b = family(m[2]);
  return a && b ? [a, b] : null;
}

function survey(insns: readonly Instruction[], tables: ReadonlyMap<number, number[]>): Site[] {
  const sites: Site[] = [];
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    if (insn.mnemonic.toLowerCase() !== "jmp") continue;
    const shape = classify(insn);
    if (shape === null) continue;

    const ix = parseIndexed(insn.opStr);
    const baseReg = shape === "register" ? family(insn.opStr) : (ix?.base ?? null);
    const indexReg = shape === "register" ? chainIndexReg(insns, i) : (ix?.index ?? null);

    let leaBase: number | null = null;
    let bound: number | null = null;
    let boundKind: "cmp" | "and" | null = null;
    for (let j = i - 1; j >= 0 && j >= i - LOOKBACK; j--) {
      const p = insns[j];
      const mn = p.mnemonic.toLowerCase();
      if (mn === "call") break;
      if (leaBase === null && mn === "lea" && baseReg && firstOperandFamily(p.opStr) === baseReg) {
        leaBase = resolveRipTarget(p);
      }
      if (bound === null && (mn === "cmp" || mn === "and") && indexReg) {
        if (firstOperandFamily(p.opStr) === indexReg) {
          const imm = immediate(p.opStr);
          if (imm !== null) {
            bound = imm + 1;
            boundKind = mn as "cmp" | "and";
          }
        }
      }
    }

    // `DetectResult.jumpTables` is keyed by the address of the DISPATCH, not by
    // the table base (`functionDetect.ts` does `jumpTables.set(insn.address,
    // …)`), so this is an exact question and not a base-matching heuristic.
    const recovered = tables.has(insn.address);
    // Where the evidence says the bytes are: a literal in the dispatch's own
    // operand is the 32-bit and rip-relative form, a `lea` is the register-base
    // one. Evidence, never confirmation — see the header.
    //
    // Only an INDEXED dispatch gets one. A bare `jmp reg` needs the whole
    // `recoverX64RvaChain` chain — a `lea`, then a scaled load off it, then an
    // `add` — and this harness does not model the middle two, so calling the
    // nearest `lea` its table base would over-claim: Go materialises an address
    // into a register before almost every indirect call and jump, and 28 of the
    // 32 bare `jmp reg` sites in one such image have a `lea` in reach while not
    // one of them is a table.
    const tableBase =
      shape === "register" || shape === "unscaled-memory" ? null : (ix?.disp ?? leaBase);
    sites.push({
      address: insn.address,
      opStr: insn.opStr,
      shape,
      leaBase,
      bound,
      boundKind,
      recovered,
      tableBase,
    });
  }
  return sites;
}

function main(): void {
  const path = process.argv[2] ?? process.env.PEEK_JT_IMAGE;
  if (!path) {
    console.log("SKIPPED: no image given.");
    console.log("  usage: npm run corpus:jumptables -- <path-to-pe>");
    console.log("         or set PEEK_JT_IMAGE=<path-to-pe>");
    console.log("  Any PE will do. DO NOT put a non-MSVC binary in the corpus");
    console.log("  directory — see CLAUDE.md; point this at it where it lies.");
    return;
  }
  if (!existsSync(path) || !statSync(path).isFile()) {
    console.log(`SKIPPED: no such file: ${path}`);
    return;
  }
  run(path).catch((e) => {
    console.log(`FAILED: ${path}: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  });
}

async function run(path: string): Promise<void> {
  const buf = readFileSync(path);
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
  const session = new FileSession();
  const af = await session.loadFile(path, path, ab);

  const code = findCodeSection(af.pe.sections);
  const codeStart = code ? af.pe.optionalHeader.imageBase + code.virtualAddress : 0;
  const codeEnd = code ? codeStart + code.virtualSize : 0;

  console.log(`image        ${path}`);
  console.log(`arch         ${af.arch}   is64 ${af.pe.is64}`);
  console.log(
    `code section ${code?.name ?? "(none)"} 0x${codeStart.toString(16)}..0x${codeEnd.toString(16)}`,
  );
  console.log(`functions    ${af.functions.length}`);
  console.log(`instructions ${af.instructions.length}`);

  const sites = survey(af.instructions, af.jumpTables);
  const byShape = new Map<Shape, Site[]>();
  for (const s of sites) {
    const list = byShape.get(s.shape) ?? [];
    list.push(s);
    byShape.set(s.shape, list);
  }

  console.log("");
  console.log("indirect dispatch sites by shape (recovered / total)");
  const order: Shape[] = [
    "literal-indexed",
    "register-base-indexed",
    "register",
    "unscaled-memory",
  ];
  for (const shape of order) {
    const list = byShape.get(shape) ?? [];
    if (list.length === 0) continue;
    const rec = list.filter((s) => s.recovered).length;
    const withLea = list.filter((s) => s.leaBase !== null).length;
    const withBound = list.filter((s) => s.bound !== null).length;
    const cmps = list.filter((s) => s.boundKind === "cmp").length;
    const ands = list.filter((s) => s.boundKind === "and").length;
    console.log(
      `  ${shape.padEnd(22)} ${String(rec).padStart(3)} / ${String(list.length).padStart(3)}` +
        `   lea-base ${withLea}   bounded ${withBound} (cmp ${cmps}, and ${ands})` +
        `   reader: ${READER[shape]}`,
    );
  }

  console.log("");
  console.log(`tables recovered  ${af.jumpTables.size}`);
  let cases = 0;
  for (const [, targets] of af.jumpTables) cases += targets.length;
  console.log(`case targets      ${cases}`);
  // Where the tables LIE is the question that decides whether an unread one is
  // harmful: the gap fill only decodes the code section, so a table in `.rdata`
  // is never read as code however badly it is understood (peek-a-bin-ayhj).
  const based = sites.filter((s) => s.tableBase !== null);
  const inCode = based.filter(
    (s) => (s.tableBase as number) >= codeStart && (s.tableBase as number) < codeEnd,
  ).length;
  console.log(
    `table bases located: ${based.length}, of which in the code section ${inCode}` +
      ` (the rest are beyond it, where the gap fill never reaches)`,
  );

  // The unread population, with the evidence that was standing there. This is
  // the half a future agent points at a real MSVC image to read.
  const unread = sites.filter(
    (s) => !s.recovered && s.shape !== "unscaled-memory" && s.bound !== null,
  );
  if (unread.length > 0) {
    console.log("");
    console.log(`UNREAD dispatches carrying a bound: ${unread.length}`);
    const starts = new Set(af.instructions.map((i) => i.address));
    for (const s of unread.slice(0, 40)) {
      const where =
        s.tableBase === null
          ? "no table base located"
          : `base 0x${s.tableBase.toString(16)} ${s.tableBase >= codeStart && s.tableBase < codeEnd ? "IN code section" : "outside code section"}`;
      console.log(
        `  0x${s.address.toString(16)} ${s.shape} bound=${s.bound}(${s.boundKind}) ${where}`,
      );
    }
    if (unread.length > 40) console.log(`  … and ${unread.length - 40} more`);
    // Harm: would recovering these change what is decoded, or only add edges?
    let undecodedTargets = 0;
    for (const s of unread) {
      if (s.tableBase === null || s.bound === null) continue;
      const ptr = af.pe.is64 ? 8 : 4;
      for (let c = 0; c < s.bound; c++) {
        const at = s.tableBase + c * ptr;
        const t = readPtr(af.pe.buffer, af.pe, at, ptr);
        if (t === null || t < codeStart || t >= codeEnd) break;
        if (!starts.has(t)) undecodedTargets++;
      }
    }
    console.log(
      `  case targets of those tables NOT already decoded as instruction starts: ${undecodedTargets}`,
    );
    console.log("  (0 means recovering them adds CFG edges only — no byte of the image is");
    console.log("   currently being read as the wrong thing.)");
  }
}

/** Read a pointer-width word at a virtual address, or null when unmapped. */
function readPtr(
  buffer: ArrayBuffer,
  pe: {
    sections: readonly {
      virtualAddress: number;
      virtualSize: number;
      pointerToRawData: number;
      sizeOfRawData: number;
    }[];
    optionalHeader: { imageBase: number };
  },
  va: number,
  width: number,
): number | null {
  const rva = va - pe.optionalHeader.imageBase;
  for (const s of pe.sections) {
    if (rva >= s.virtualAddress && rva + width <= s.virtualAddress + s.virtualSize) {
      const off = s.pointerToRawData + (rva - s.virtualAddress);
      if (off + width > buffer.byteLength) return null;
      const dv = new DataView(buffer);
      return width === 8 ? Number(dv.getBigUint64(off, true)) : dv.getUint32(off, true);
    }
  }
  return null;
}

main();
