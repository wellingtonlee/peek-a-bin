/**
 * Negative controls for `corpus/selfAssigns.ts`.
 *
 * The corpus run itself can only ever demonstrate the audit's REPORTED half:
 * disabling `peek-a-bin-3axd` takes `openOperand` from 1 to 4 on both PE32
 * binaries and names t32 0x40D23F `add edi, esi` — the exact site that bead
 * records — so the instrument provably sees a real lost operand. What no corpus
 * run here can demonstrate is that its two GATES fire, because both are at 0 on
 * all four binaries and the defects that would move them are not present in the
 * corpus. Asserting a gate that has never been shown to fire is asserting
 * nothing, so the controls are here instead, over the classifier directly.
 *
 * It lives in `build/` for `corpusPreflight.test.ts`'s reason: `selfAssigns.ts`
 * imports only `callSummary.ts`, `flagModel.ts`, `ir.ts` and a type, none of
 * which loads Capstone, so it runs in the ordinary suite while the audits it
 * belongs to cannot.
 *
 * The width rules are pinned here too, because they are the part of the
 * whitelist that is a JUDGEMENT rather than a fit to the rows: `mov r,r` is a
 * true no-op at every width except a 32-bit register in a 64-bit image, where it
 * zero-extends (`peek-a-bin-tez6`), and `add r,r` / `sub r,r` are the reason the
 * same-register rule is a whitelist and not "the operands are equal".
 */
import { describe, expect, it } from "vitest";
import { auditSelfAssigns, emptySelfAssigns } from "../corpus/selfAssigns";
import type { Instruction } from "../src/disasm/types";

function insn(address: number, mnemonic: string, opStr: string): Instruction {
  return { address, mnemonic, opStr, bytes: new Uint8Array(), size: 2 } as Instruction;
}

/**
 * One emitted line at `addr`, prefixed by a brace line so the self-assignment is
 * never line 0 — a line map keyed on 0 would pass by accident.
 */
function run(
  line: string,
  insns: Instruction[],
  addr: number | null,
  is64 = false,
): ReturnType<typeof emptySelfAssigns> {
  const out = emptySelfAssigns();
  const code = `void f() {\n  ${line}\n}`;
  auditSelfAssigns(out, "bin", "f", 0x1000, code, addr === null ? [] : [[1, addr]], insns, is64);
  return out;
}

describe("selfAssigns: what counts as a machine identity", () => {
  it.each([
    ["lea ecx, [ecx]", "lea", "ecx, [ecx]", "ecx = ecx;"],
    ["lea esp, [esp + 0]", "lea", "esp, [esp + 0]", "esp = esp;"],
    ["lea ecx, [ecx + eiz*1]", "lea", "ecx, [ecx + eiz*1]", "ecx = ecx;"],
    ["mov edi, edi", "mov", "edi, edi", "edi = edi;"],
    ["or al, al", "or", "al, al", "al = al;"],
    ["and ebx, ebx", "and", "ebx, ebx", "ebx = ebx;"],
    ["sub eax, 0", "sub", "eax, 0", "eax = eax;"],
    ["add eax, 0x0", "add", "eax, 0x0", "eax = eax;"],
    ["shl ecx, 0", "shl", "ecx, 0", "ecx = ecx;"],
  ])("accepts %s as an unconditional identity", (_label, mn, ops, line) => {
    const out = run(line, [insn(0x2000, mn, ops)], 0x2000);
    expect([out.identity, out.openOperand, out.wrong, out.unresolved]).toEqual([1, 0, 0, 0]);
  });

  it("does not accept a lea whose displacement is non-zero", () => {
    const out = run("ecx = ecx;", [insn(0x2000, "lea", "ecx, [ecx + 4]")], 0x2000);
    expect(out.identity).toBe(0);
    expect(out.openOperand).toBe(1);
  });

  it("does not accept a lea off a different register", () => {
    const out = run("ecx = ecx;", [insn(0x2000, "lea", "ecx, [ebx]")], 0x2000);
    expect(out.identity).toBe(0);
    expect(out.openOperand).toBe(1);
  });

  it.each([
    ["add", "eax, eax"],
    ["sub", "eax, eax"],
    ["xor", "eax, eax"],
  ])(
    "refuses %s <r>,<r>: equal operands are not a licence, only a whitelist of mnemonics is",
    (mn, ops) => {
      const out = run("eax = eax;", [insn(0x2000, mn, ops)], 0x2000);
      expect(out.identity).toBe(0);
      expect(out.openOperand).toBe(1);
    },
  );

  it("accepts mov <r32>,<r32> in a 32-bit image, where there is no upper half", () => {
    const out = run("edi = edi;", [insn(0x2000, "mov", "edi, edi")], 0x2000, false);
    expect(out.identity).toBe(1);
  });

  it("REFUSES mov <r32>,<r32> in a 64-bit image, which zero-extends (peek-a-bin-tez6)", () => {
    const out = run("r8d = r8d;", [insn(0x2000, "mov", "r8d, r8d")], 0x2000, true);
    expect(out.identity).toBe(0);
    expect(out.openOperand).toBe(1);
    expect(out.rows[0].why).toContain("ZERO-EXTEND");
  });

  it.each([
    ["r8", "mov r8, r8 writes what it read"],
    ["al", "mov al, al leaves the parent's upper bits alone"],
    ["ax", "mov ax, ax leaves the parent's upper bits alone"],
  ])("still accepts mov <%s>,<%s> in a 64-bit image", (reg) => {
    const out = run(`${reg} = ${reg};`, [insn(0x2000, "mov", `${reg}, ${reg}`)], 0x2000, true);
    expect(out.identity).toBe(1);
  });
});

describe("selfAssigns: the two gates", () => {
  it("reports a line whose address maps to no instruction as unresolved, not clean", () => {
    const out = run("eax = eax;", [insn(0x2000, "nop", "")], 0x9999);
    expect(out.unresolved).toBe(1);
    expect([out.identity, out.openOperand, out.wrong]).toEqual([0, 0, 0]);
  });

  it("reports a line carrying no address at all as unresolved", () => {
    const out = run("eax = eax;", [insn(0x2000, "nop", "")], null);
    expect(out.unresolved).toBe(1);
  });

  it("reports a name that is not an alias of the instruction's destination as wrong", () => {
    // The instruction is a perfectly good `lea` identity — for ECX. The emitted
    // line is about EDI, so the line and the address it carries are about
    // different registers and no dataflow answer rescues it.
    const out = run("edi = edi;", [insn(0x2000, "lea", "ecx, [ecx]")], 0x2000);
    expect(out.wrong).toBe(1);
    expect(out.identity).toBe(0);
  });

  it("does not raise `wrong` for a memory destination, which has no register name", () => {
    const out = run("var_210 = var_210;", [insn(0x2000, "or", "dword ptr [ebp - 0x210], esi")], 0x2000);
    expect(out.wrong).toBe(0);
    expect(out.openOperand).toBe(1);
  });
});

describe("selfAssigns: the open-operand population and its corroboration hint", () => {
  it("names the operand the emitted line is silent about", () => {
    const out = run("edi = edi;", [insn(0x2000, "add", "edi, esi")], 0x2000);
    expect(out.openOperand).toBe(1);
    expect(out.rows[0].why).toContain("esi");
    expect(out.rows[0].zeroCorroborated).toBe(false);
  });

  it("corroborates when every write of that operand before the site zeroes it", () => {
    const out = run(
      "ecx = ecx;",
      [insn(0x1f00, "xor", "ebx, ebx"), insn(0x2000, "sub", "ecx, ebx")],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(1);
    expect(out.rows[0].zeroCorroborated).toBe(true);
  });

  it("does not corroborate when a non-zeroing write of it precedes the site", () => {
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "xor", "ebx, ebx"),
        insn(0x1f80, "mov", "ebx, dword ptr [ebp + 8]"),
        insn(0x2000, "sub", "ecx, ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(0);
  });

  it("follows a copy chain: `xor eax,eax / mov ebx,eax` is a real zero in EBX", () => {
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "xor", "eax, eax"),
        insn(0x1f10, "mov", "ebx, eax"),
        insn(0x2000, "sub", "ecx, ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(1);
    expect(out.rows[0].zeroCorroborated).toBe(true);
  });

  it("follows a chain more than one link long", () => {
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "xor", "eax, eax"),
        insn(0x1f10, "mov", "edx, eax"),
        insn(0x1f20, "mov", "ebx, edx"),
        insn(0x2000, "sub", "ecx, ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(1);
  });

  /**
   * THE TRAP. If the recursive call dropped the `writes > 0` requirement, a copy
   * from a register the function has not written — its arbitrary ENTRY value —
   * would corroborate vacuously, and the hint would become a rubber stamp. Over
   * the corpus's 1035 arithmetic-with-register-source sites that wrong version
   * corroborates 112 (38/20/20/34 on t32/t64/w64/w32) where the correct one
   * corroborates 0 more than the pre-chain rule did, so this is the assertion
   * that separates the two.
   */
  it("REFUSES a copy whose source has no write before it — that is the entry value", () => {
    const out = run(
      "ecx = ecx;",
      [insn(0x1f10, "mov", "ebx, esi"), insn(0x2000, "sub", "ecx, ebx")],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(0);
    expect(out.rows[0].zeroCorroborated).toBe(false);
  });

  it("REFUSES a source zeroed only AFTER the copy, since the copy read the older value", () => {
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "mov", "ebx, eax"),
        insn(0x1f10, "xor", "eax, eax"),
        insn(0x2000, "sub", "ecx, ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(0);
  });

  it("REFUSES a chain whose source has a non-zeroing write of its own", () => {
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "xor", "eax, eax"),
        insn(0x1f08, "mov", "eax, dword ptr [ebp + 8]"),
        insn(0x1f10, "mov", "ebx, eax"),
        insn(0x2000, "sub", "ecx, ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(0);
  });

  it.each([
    ["a memory load", "mov", "ebx, dword ptr [ebp + 8]"],
    ["a lea off a zeroed register", "lea", "ebx, [eax]"],
    ["a pop", "pop", "ebx"],
    ["an arithmetic result", "add", "ebx, eax"],
  ])("REFUSES %s as a link in the chain: only `mov <r>,<r>` chains", (_label, mn, ops) => {
    const out = run(
      "ecx = ecx;",
      [insn(0x1f00, "xor", "eax, eax"), insn(0x1f10, mn, ops), insn(0x2000, "sub", "ecx, ebx")],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(0);
  });

  /**
   * `peek-a-bin-3axd`'s three sites, in shape: ESI's first write before each of
   * them is `mov esi, [ebp+8]`, a memory load. The chain must not rescue it —
   * measured against the real binaries, all three stay uncorroborated with the
   * chain on, which is what makes the negative control still discriminating.
   */
  it("still refuses peek-a-bin-3axd's shape, whose ESI comes from memory", () => {
    const out = run(
      "edi = edi;",
      [
        insn(0x1f00, "mov", "esi, dword ptr [ebp + 8]"),
        insn(0x1f10, "mov", "esi, eax"),
        insn(0x1f20, "xor", "esi, esi"),
        insn(0x2000, "add", "edi, esi"),
      ],
      0x2000,
    );
    expect(out.openOperand).toBe(1);
    expect(out.rows[0].zeroCorroborated).toBe(false);
  });

  it("ignores the epilogue restore, which is a write only after the site", () => {
    // `sub_402FEF` is exactly this: `xor ebx,ebx` above the site and `pop ebx`
    // below it. Asking the whole function loses the corroboration.
    const out = run(
      "ecx = ecx;",
      [
        insn(0x1f00, "xor", "ebx, ebx"),
        insn(0x2000, "sub", "ecx, ebx"),
        insn(0x2100, "pop", "ebx"),
      ],
      0x2000,
    );
    expect(out.openZeroCorroborated).toBe(1);
  });
});

describe("selfAssigns: the text scan", () => {
  it("is indifferent to indentation and finds nothing in a non-self assignment", () => {
    const out = emptySelfAssigns();
    const code = "void f() {\n\t\t\t  eax = eax;\n      ebx = ecx;\n}";
    auditSelfAssigns(
      out,
      "bin",
      "f",
      0x1000,
      code,
      [
        [1, 0x2000],
        [2, 0x2000],
      ],
      [insn(0x2000, "nop", "")],
      false,
    );
    expect(out.identity).toBe(1);
    expect(out.rows).toHaveLength(1);
  });

  it.each(["  if (eax == eax) {", "  eax |= eax;", "  eax += eax;", "  if (eax >= eax) {"])(
    "does not read %s as an assignment",
    (line) => {
      const out = run(line, [insn(0x2000, "nop", "")], 0x2000);
      expect(out.rows).toHaveLength(0);
    },
  );

  it("finds a self-assignment hidden in a for header, which ends in `{` not `;`", () => {
    const out = emptySelfAssigns();
    const code = "void f() {\n  for (eax = eax; ecx < 4; ecx++) {\n  }\n}";
    auditSelfAssigns(out, "bin", "f", 0x1000, code, [[1, 0x2000]], [insn(0x2000, "nop", "")], false);
    expect(out.inForHeader).toBe(1);
    expect(out.identity).toBe(1);
    expect(out.forHeaders).toBe(1);
    expect(out.forHeadersUnsplit).toBe(0);
  });

  /**
   * THE FOR HEADER IS READ THROUGH `guardShape`, NOT WITH A PATTERN OF ITS OWN
   * (peek-a-bin-hfsq).
   *
   * It used to be `/^\s*for \((.*)\) \{\s*$/` — a second hand-rolled
   * guard-header pattern, in a file whose `wrong` and `unresolved` columns gate
   * at 0, encoding one space after `for` and a trailing brace. A formatting
   * change to either would have taken rows out of a gate silently, and a gate
   * that stops looking reads as a clean tree. The whitespace cases below all
   * FAILED against the old pattern.
   */
  it.each([
    "  for(eax = eax; ecx < 4; ecx++) {",
    "  for  (eax = eax; ecx < 4; ecx++) {",
    "  for (eax = eax; ecx < 4; ecx++)  {",
  ])("reads %s however it is spaced", (line) => {
    const out = run(line, [insn(0x2000, "nop", "")], 0x2000);
    expect(out.forHeaders).toBe(1);
    expect(out.inForHeader).toBe(1);
    expect(out.identity).toBe(1);
  });

  /**
   * A `for` whose clauses cannot be split is a clause the scan did not read, and
   * it is counted rather than dropped — `forHeadersUnsplit` gates at 0 in
   * `corpus.audit.ts` for the same reason `unresolved` does. `emit.ts` always
   * writes three clauses, so this shape does not occur; it is pinned here or
   * nowhere.
   */
  it("counts a for header it recognises and cannot split", () => {
    const out = run("  for (eax = eax) {", [insn(0x2000, "nop", "")], 0x2000);
    expect(out.forHeaders).toBe(1);
    expect(out.forHeadersUnsplit).toBe(1);
    expect(out.rows).toHaveLength(0);
  });

  /**
   * A one-lined guard's body is read as the STATEMENT it is. No such assignment
   * occurs today — `peek-a-bin-0qib` one-lines terminators only — and this is
   * what stops the guard being taken as the destination if that ever widens.
   * With the guard glued on, `stmt[1]` is `if (ecx == 0) eax` and the row is
   * lost from a scan that gates at 0.
   */
  it("reads a one-lined guard's body as its own statement", () => {
    const out = run("  if (ecx == 0) eax = eax;", [insn(0x2000, "nop", "")], 0x2000);
    expect(out.identity).toBe(1);
    expect(out.rows).toHaveLength(1);
    expect(out.rows[0].name).toBe("eax");
    expect(out.forHeaders).toBe(0);
  });

  /** …and a one-lined guard whose body is a terminator is not an assignment. */
  it("finds nothing in a one-lined guard whose body is a terminator", () => {
    const out = run("  if (eax == 0) goto loc_401038;", [insn(0x2000, "nop", "")], 0x2000);
    expect(out.rows).toHaveLength(0);
  });

  it("counts a function once however many self-assignments it has", () => {
    const out = emptySelfAssigns();
    const code = "void f() {\n  eax = eax;\n  ebx = ebx;\n}";
    auditSelfAssigns(
      out,
      "bin",
      "f",
      0x1000,
      code,
      [
        [1, 0x2000],
        [2, 0x2004],
      ],
      [insn(0x2000, "nop", ""), insn(0x2004, "nop", "")],
      false,
    );
    expect(out.funcsAffected).toBe(1);
    expect(out.identity).toBe(2);
  });
});
