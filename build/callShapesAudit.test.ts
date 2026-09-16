/**
 * Negative controls for `corpus/callShapes.ts`, the two report-only sizes for
 * epic 3 of `peek-a-bin-n9cl`. Pinned here because the corpus has one shape per
 * row and a report-only row has no red state:
 *
 *   - a `call` with a bare register operand is indirect AND through a register;
 *     one through memory is indirect only; an immediate is neither.
 *   - an x64 store to `[rsp + 0x20]` or above counts, `[rsp + 0x18]` (the home
 *     area) does not, and "before a call" means the NEXT control transfer is a
 *     `call` — a `ret` or a `jmp` in between disqualifies it.
 *   - the same operand as a SOURCE is a read, not a store.
 *   - on x86 the slot rows are structurally 0 whatever the operands say.
 *   - the emitted-text half counts every `((intptr_t (*)())<target>)(` — the
 *     ONE spelling `emit.ts`'s `calleeText` produces — partitions it by what
 *     the target is, counts `indirect jmp through`, and tells a
 *     `(rsp + 0x20) =` store from a read.
 *
 * **THE CALLEE FIXTURE USED TO BE WRITTEN IN A SPELLING THE EMITTER HAS NEVER
 * PRODUCED** — `(*rax)(rcx, rdx);` and `__unrecovered_3(rcx);` — so the scan it
 * validated was a structural 0 on all four corpus binaries while eight real
 * call sites sat in the population it was supposed to size, and
 * `corpus/README.md` quoted that 0 as evidence that the population was empty
 * (`peek-a-bin-s1f6.1`). The fixture is the emitter's own output now, and the
 * last row below pins that the two fictional spellings count for NOTHING, so
 * the fiction cannot come back as a passing test.
 */
import { describe, expect, it } from "vitest";
import { auditCallShapes, emptyCallShapes } from "../corpus/callShapes";
import type { Instruction } from "../src/disasm/types";

let addr = 0x140001000;
const insn = (mnemonic: string, opStr: string): Instruction => ({
  address: (addr += 4),
  mnemonic,
  opStr,
  size: 4,
  bytes: new Uint8Array(4),
});

describe("call shapes", () => {
  it("classifies calls by operand shape", () => {
    const r = emptyCallShapes();
    auditCallShapes(
      r,
      [insn("call", "0x140002000"), insn("call", "rax"), insn("call", "qword ptr [rip + 0x1234]")],
      "",
      true,
    );
    expect(r.calls).toBe(3);
    expect(r.indirectCalls).toBe(2);
    expect(r.indirectRegCalls).toBe(1);
    expect(r.insns).toBe(3);
    expect(r.funcs).toBe(1);
  });

  it("counts a stack-argument store only at 0x20 and above, and only before a call", () => {
    const r = emptyCallShapes();
    auditCallShapes(
      r,
      [
        insn("mov", "qword ptr [rsp + 0x18], rbx"),
        insn("mov", "qword ptr [rsp + 0x20], r9"),
        insn("mov", "dword ptr [rsp + 0x28], 0"),
        insn("call", "0x140002000"),
        insn("mov", "qword ptr [rsp + 0x30], rax"),
        insn("jmp", "0x140003000"),
        insn("mov", "qword ptr [rsp + 0x38], rax"),
        insn("ret", ""),
      ],
      "",
      true,
    );
    expect(r.slotStores).toBe(4);
    expect(r.slotStoresBeforeCall).toBe(2);
    expect(r.funcsPassingStackArgs).toBe(1);
  });

  it("reads a slot operand that is a source, or a compare, as a read", () => {
    const r = emptyCallShapes();
    auditCallShapes(
      r,
      [insn("mov", "rax, qword ptr [rsp + 0x28]"), insn("cmp", "qword ptr [rsp + 0x20], 0")],
      "",
      true,
    );
    expect(r.slotReads).toBe(2);
    expect(r.slotStores).toBe(0);
  });

  it("reports the slot rows as structurally 0 on x86", () => {
    const r = emptyCallShapes();
    auditCallShapes(r, [insn("mov", "dword ptr [rsp + 0x20], eax"), insn("call", "0x401000")], "", false);
    expect(r.slotStores).toBe(0);
    expect(r.slotReads).toBe(0);
    expect(r.calls).toBe(1);
  });

  it("reads the emitted text's callee spellings and slot stores", () => {
    const r = emptyCallShapes();
    auditCallShapes(
      r,
      [],
      [
        "int f(void) {",
        "    ((intptr_t (*)())rax)(rcx, rdx);",
        "    ((intptr_t (*)())arg_0)();",
        "    ((intptr_t (*)())__imp_RtlUnwindEx)();",
        "    ((intptr_t (*)())*(int32_t*)(eax + 4))(rcx);",
        "    ((intptr_t (*)())((struct_0 *)eax)->field_0x4)();",
        "    ((intptr_t (*)())__unrecovered_3 /* dword ptr [ebp + notareg] */)(rcx);",
        "    /* indirect jmp through esi */",
        "    *(int64_t*)(rsp + 0x20) = r9;",
        "    *(int64_t*)(rsp + 0x18) = r8;",
        "    rcx = *(int64_t*)(rsp + 0x28);",
        "    if (*(int64_t*)(rsp + 0x30) == 0) {",
        "    }",
        "    // ((intptr_t (*)())rbx)(); a commented-out line is not a call",
        "}",
      ].join("\n"),
      true,
    );
    // Two targets carry their own parentheses, which is why the scan is
    // depth-counted rather than anchored on the first `)`.
    expect(r.indirectCallees).toBe(6);
    expect(r.registerCallees).toBe(1);
    expect(r.namedCallees).toBe(2);
    expect(r.exprCallees).toBe(2);
    expect(r.unrecoveredCallees).toBe(1);
    expect(r.registerCallees + r.namedCallees + r.exprCallees + r.unrecoveredCallees).toBe(
      r.indirectCallees,
    );
    expect(r.indirectJmpRaws).toBe(1);
    expect(r.textSlotStores).toBe(1);
    expect(r.textSlotReads).toBe(2);
  });

  /**
   * The spellings the old fixture was written in. `calleeText` wraps EVERY
   * indirect target in `((intptr_t (*)())…)`, so neither can occur in emitted
   * C — and a scan that looks for them reports a confident zero over a
   * non-empty population (`peek-a-bin-s1f6.1`).
   */
  it("counts nothing for the spellings the emitter never produces", () => {
    const r = emptyCallShapes();
    auditCallShapes(r, [], ["    (*rax)(rcx);", "    __unrecovered_3(rcx);"].join("\n"), true);
    expect(r.indirectCallees).toBe(0);
    expect(r.registerCallees).toBe(0);
    expect(r.unrecoveredCallees).toBe(0);
  });
});
