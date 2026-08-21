import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loneImmediate, pushedImmediate, type StackInsn } from "../stackIdiom";

/**
 * The `push <imm>` / `pop <reg>` pairing rule, tested directly.
 *
 * It used to be private to `functionDetect.ts`, where its only exercise was
 * whatever a jump-table test happened to drive through it. It is now shared with
 * `decompile/lifter.ts`, which lifts the `pop` as an assignment — so a wrong
 * answer here no longer sizes a table badly, it writes a value the machine never
 * put in the register. That is a much sharper consequence, and the refusals are
 * the whole safety of it: the rule claims the pairing only where nothing between
 * the two instructions can have moved the stack pointer or written through it.
 *
 * `pushedImmediate` running off the front of the array is also a refusal, and
 * that is what confines THIS function to one basic block — `liftBlock` passes
 * `block.insns`, so a `pop` whose `push` is in another block finds nothing. It
 * is asked a second time, of each predecessor's tail, by `lifter.ts`'s
 * `crossBlockPopImmediates` (peek-a-bin-6ilz), whose own refusals live beside it
 * in `decompile/__tests__/lifter.test.ts`.
 */

/** One instruction. Only `mnemonic` and `opStr` are read; the rest is shape. */
function ins(mnemonic: string, opStr = ""): StackInsn {
  return { address: 0x401000, mnemonic, opStr, size: 1 };
}

describe("loneImmediate", () => {
  it("reads the immediate of a push, hex or decimal", () => {
    expect(loneImmediate("0x16")).toBe(0x16);
    expect(loneImmediate("8")).toBe(8);
    expect(loneImmediate(" 0x7 ")).toBe(7);
  });

  // A lone *register* is `push esi`, which is a copy of a value this rule
  // cannot state, not a constant. The lifter must refuse it: reading it as an
  // immediate would emit an assignment of the string's numeric junk, and
  // reading it as a move is the cross-block/save-restore case that is
  // deliberately out of scope (peek-a-bin-4ynk).
  it("refuses anything that is not a bare immediate", () => {
    expect(loneImmediate("esi")).toBeNull();
    expect(loneImmediate("dword ptr [eax]")).toBeNull();
    expect(loneImmediate("eax, 8")).toBeNull();
    expect(loneImmediate("")).toBeNull();
  });
});

describe("pushedImmediate", () => {
  it("pairs a pop with the push immediately above it", () => {
    const insns = [ins("push", "0x8"), ins("pop", "esi")];
    expect(pushedImmediate(insns, 1)).toBe(8);
  });

  // The two need not be adjacent — MSVC routinely schedules an unrelated
  // instruction between them, and t32 0x40CD31 is exactly that: `push 0x8 /
  // shr eax, 0x4 / pop esi`. Requiring adjacency would refuse the site this
  // whole bead was filed about.
  it("pairs across an instruction that does not touch the stack", () => {
    const insns = [ins("push", "0x8"), ins("shr", "eax, 0x4"), ins("pop", "esi")];
    expect(pushedImmediate(insns, 2)).toBe(8);
  });

  // The NEAREST push wins, because that is the one on top of the stack. Taking
  // the outer one would be one slot out, which is a bound the program never
  // checked or a constant it never loaded.
  it("takes the innermost push when two are stacked", () => {
    const insns = [ins("push", "0x8"), ins("push", "0x1"), ins("pop", "esi")];
    expect(pushedImmediate(insns, 2)).toBe(1);
  });

  it("refuses a push of a register rather than an immediate", () => {
    const insns = [ins("push", "eax"), ins("pop", "esi")];
    expect(pushedImmediate(insns, 1)).toBeNull();
  });

  // Every refusal below is a way the stack pointer can have moved between the
  // push and the pop, which makes the pairing a guess. A `call` is both stack
  // traffic and a clobber; `add esp, 4` is neither a stack mnemonic nor a
  // memory operand, which is why the operand text is scanned as well as the
  // mnemonic set; and `mov eax, [esp]` names the stack without moving it, but a
  // rule that reads through it is one edit away from reading through a write.
  it("refuses across anything that can have moved the stack pointer", () => {
    expect(
      pushedImmediate([ins("push", "0x8"), ins("call", "0x404127"), ins("pop", "esi")], 2),
    ).toBeNull();
    expect(
      pushedImmediate([ins("push", "0x8"), ins("add", "esp, 4"), ins("pop", "esi")], 2),
    ).toBeNull();
    expect(
      pushedImmediate([ins("push", "0x8"), ins("mov", "eax, [esp]"), ins("pop", "esi")], 2),
    ).toBeNull();
    expect(pushedImmediate([ins("push", "0x8"), ins("leave"), ins("pop", "esi")], 2)).toBeNull();
    expect(pushedImmediate([ins("push", "0x8"), ins("pushfd"), ins("pop", "esi")], 2)).toBeNull();
  });

  // rsp as well as esp: the same rule serves both widths, and the x64 spelling
  // must not slip past the operand scan.
  it("refuses across a 64-bit stack-pointer operand", () => {
    const insns = [ins("push", "0x8"), ins("mov", "qword ptr [rsp+0x8], rax"), ins("pop", "rsi")];
    expect(pushedImmediate(insns, 2)).toBeNull();
  });

  // Running off the front is a refusal, not a fallthrough, and that is this
  // function's block-locality guarantee: the lifter passes one basic block's
  // instructions, so a pop whose push is in a predecessor gets no answer HERE.
  // It is not left alone any more — `crossBlockPopImmediates` asks this same
  // function about each predecessor's tail instead (peek-a-bin-6ilz).
  it("refuses when there is no push above the pop at all", () => {
    expect(pushedImmediate([ins("pop", "esi")], 0)).toBeNull();
    expect(pushedImmediate([ins("mov", "eax, 1"), ins("pop", "esi")], 1)).toBeNull();
  });
});

/**
 * The reason this rule lives in its own module rather than staying where it was
 * written, asserted statically because nothing at runtime can see it.
 *
 * `pushedImmediate` was private to `functionDetect.ts`, which imports
 * `./capstoneWindow` — and that module loads Capstone WASM at module scope.
 * `decompile/lifter.ts` needs the same rule and has no Capstone edge, which is
 * load-bearing rather than incidental: `decompileFunction` takes
 * `Instruction[]` rather than bytes, and `decompile/__tests__/pipeline.test.ts`
 * is the end-to-end suite precisely because it needs neither Capstone nor a
 * worker. A value import of `functionDetect.ts` from the lifter would have
 * dragged WASM into every decompiler test — slow, and flaky in CI in the way
 * `mcp/__tests__/importGraph.test.ts` exists to prevent.
 *
 * So the two properties below are the design, and either one silently
 * regressing puts the rule back where it was:
 *
 * - this module imports nothing, which is what makes it safe for both callers;
 * - nothing under `decompile/` reaches Capstone, directly or through
 *   `functionDetect.ts`.
 *
 * The scan is over module specifiers, so reformatting the imports cannot break
 * it; only actually adding one can.
 */
describe("stackIdiom is a leaf, and the decompiler has no Capstone edge", () => {
  const DISASM_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

  /** Every `from "…"` specifier in a file, comments stripped first. */
  function specifiersOf(file: string): string[] {
    const source = readFileSync(file, "utf-8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    return [...source.matchAll(/\bfrom\s+["']([^"']+)["']/g)].map((m) => m[1]);
  }

  it("imports nothing at all", () => {
    expect(specifiersOf(join(DISASM_DIR, "stackIdiom.ts"))).toEqual([]);
  });

  it("keeps every module under decompile/ clear of Capstone", () => {
    const decompileDir = join(DISASM_DIR, "decompile");
    const offenders: string[] = [];
    for (const name of readdirSync(decompileDir)) {
      if (!name.endsWith(".ts")) continue;
      for (const spec of specifiersOf(join(decompileDir, name))) {
        if (/capstone/i.test(spec) || /functionDetect/.test(spec))
          offenders.push(`${name} -> ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

/**
 * Every replica of the lift loop must also run the cross-block pairing.
 *
 * `pipeline.ts` lifts each block and then calls `liftCrossBlockPops`, and three
 * corpus audits replicate that loop because neither side of their question is
 * recoverable from `decompileFunction`'s return value (`popReads.ts`,
 * `staleReads.ts`, `lostDefs.ts`). A replica that skips step 2b measures a
 * program the emitter never sees — and it fails in the *quiet* direction:
 * `corpus/popReads.ts` would keep reporting the very rows peek-a-bin-6ilz fixed,
 * so a future agent would read a green tree as a red one and go looking for a
 * defect that is not there.
 *
 * The scan is over call sites rather than imports, because an unused import is
 * the shape a half-finished edit leaves behind. It deliberately says nothing
 * about ORDER — that `liftCrossBlockPops` must run before `buildSSA`, which is
 * the whole point of it, is not something a text scan can check and is pinned
 * end to end by `decompile/__tests__/pipeline.test.ts` instead.
 */
describe("every caller of liftBlock also runs the whole-CFG pop pairing", () => {
  const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

  /** Every non-test `.ts` under `src/` and `corpus/` that calls `liftBlock(`. */
  function liftBlockCallers(): string[] {
    const hits: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== "__tests__" && entry.name !== "node_modules") walk(full);
          continue;
        }
        if (!entry.name.endsWith(".ts")) continue;
        // The declaration itself is not a call site.
        if (full.endsWith(join("decompile", "lifter.ts"))) continue;
        const source = readFileSync(full, "utf-8");
        if (/\bliftBlock\s*\(/.test(source)) hits.push(full);
      }
    };
    walk(join(REPO, "src"));
    walk(join(REPO, "corpus"));
    return hits;
  }

  it("finds the callers at all", () => {
    // Liveness: a scan that matches nothing passes the assertion below for the
    // wrong reason. `pipeline.ts` plus the three corpus replicas.
    expect(liftBlockCallers().length).toBeGreaterThanOrEqual(4);
  });

  it("leaves none of them without the pairing call", () => {
    const offenders = liftBlockCallers().filter(
      (f) => !/\bliftCrossBlockPops\s*\(/.test(readFileSync(f, "utf-8")),
    );

    expect(offenders.map((f) => f.slice(REPO.length + 1))).toEqual([]);
  });

  /**
   * The same guard for `matchedStackSlots`, and it is here rather than in a
   * second describe block because it is the same defect in the same direction:
   * a replica that lifts blocks without the matched `push <reg>` / `pop <reg>`
   * pairing measures a program the emitter never sees, and `corpus/popReads.ts`
   * keeps reporting the rows peek-a-bin-6f3v fixed.
   *
   * It is a *separate* assertion from the one above because the two facts reach
   * `liftBlock` differently — `liftCrossBlockPops` is a pass over the lifted
   * blocks, `matchedStackSlots` is an argument — so a half-finished edit can
   * carry one and not the other. The argument being optional is what makes the
   * text scan necessary at all: were it required, the typechecker would say so.
   */
  it("leaves none of them without the matched-slot pairing", () => {
    const offenders = liftBlockCallers().filter(
      (f) => !/\bmatchedStackSlots\s*\(/.test(readFileSync(f, "utf-8")),
    );

    expect(offenders.map((f) => f.slice(REPO.length + 1))).toEqual([]);
  });
});
