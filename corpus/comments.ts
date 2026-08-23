/**
 * Who gets an inline comment, and is it a reference or a coincidence?
 *
 * Nothing else in this repo audits `Instruction.comment` at all. Every gate in
 * `corpus.audit.ts` reads emitted C or the IR behind it, and a comment reaches
 * neither — so a wrong comment is invisible to `npm run corpus`, to `gcc`, and
 * to every suite under `src/`, while being one of the few things a reader of the
 * disassembly view takes on trust.
 *
 * Two questions, one per architecture, and they are NOT the same question:
 *
 *  * **ARM64.** `mapInsn` resolves a reference with `resolveRipTarget` and,
 *    failing that, by scanning the operand string for a `0x…` literal that is a
 *    known string or IAT address. On A64 the first never fires and the second is
 *    unsound: an A64 operand's only literals are branch targets and `adrp` PAGE
 *    BASES, so a hit means an address collided with a data address, not that the
 *    instruction refers to it (peek-a-bin-vg3). This audit counts today's
 *    comments and splits them by whether `findArm64AddressRefs` — the real A64
 *    reference reader, and the one `buildArm64Xrefs` already uses — agrees that
 *    the instruction refers to a string or an import.
 *
 *  * **x86/x64.** The same scan is *sound* there, because an x86 operand really
 *    can carry an absolute address (`mov eax, [0x404000]`, `push 0x40a010`). So
 *    there is nothing to judge and the audit prints a DIGEST instead: an md5
 *    over every commented instruction. That is the byte-identity proof for any
 *    change to the ARM64 comment path, which necessarily touches code x86 shares
 *    — run this at the base commit and at the change and compare the digests.
 *
 * Not wired into `npm run corpus`: that run's header names the four x86
 * binaries the standing numbers are measured against, and this needs the two
 * ARM64 ones, which `preflight.ts` does not model. Run it with
 * `npm run corpus:comments`. Missing binaries skip cleanly and say which.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { classifyArm64Branch, findArm64AddressRefs } from "../src/disasm/arm64Operands";
import type { Instruction } from "../src/disasm/types";
import { FileSession } from "../src/mcp/session";
import { ALL_BINS, ARM_BINS, corpusDir, corpusDirSource } from "./preflight";

interface Loaded {
  instructions: Instruction[];
  stringMap: Map<number, string>;
  iatMap: Map<number, { lib: string; func: string }>;
}

async function load(file: string): Promise<Loaded> {
  const buf = readFileSync(file);
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
  const session = new FileSession();
  const af = await session.loadFile(file, file, ab);
  return { instructions: af.instructions, stringMap: af.stringMap, iatMap: af.iatMap };
}

/** One line per commented instruction, in address order. The digest's input. */
function commentLines(insns: readonly Instruction[]): string[] {
  const out: string[] = [];
  for (const i of insns) {
    if (i.comment === undefined) continue;
    out.push(`${i.address.toString(16)}\t${i.mnemonic}\t${i.opStr}\t${i.comment}`);
  }
  return out;
}

function digest(lines: readonly string[]): string {
  return createHash("md5").update(lines.join("\n")).digest("hex").slice(0, 12);
}

/**
 * A comment is JUSTIFIED when `findArm64AddressRefs` says this instruction
 * completes a materialisation of an address the string or IAT map knows.
 * Anything else is a coincidence — the literal in the operand happened to match.
 */
function auditArm64(l: Loaded): {
  commented: number;
  justified: number;
  coincidence: { insn: Instruction; kind: string }[];
  refs: number;
  strHits: number;
  iatHits: number;
  distinctTexts: number;
} {
  const refTargets = new Map<number, number[]>();
  let strHits = 0;
  let iatHits = 0;
  const refs = findArm64AddressRefs(l.instructions);
  for (const r of refs) {
    const arr = refTargets.get(r.from);
    if (arr) arr.push(r.target);
    else refTargets.set(r.from, [r.target]);
    if (l.stringMap.has(r.target)) strHits++;
    else if (l.iatMap.has(r.target)) iatHits++;
  }

  let commented = 0;
  let justified = 0;
  const coincidence: { insn: Instruction; kind: string }[] = [];
  const texts = new Set<string>();
  for (const insn of l.instructions) {
    if (insn.comment === undefined) continue;
    commented++;
    texts.add(insn.comment);
    const targets = refTargets.get(insn.address) ?? [];
    if (targets.some((t) => l.stringMap.has(t) || l.iatMap.has(t))) {
      justified++;
      continue;
    }
    // Name the shape, because the two are different defects: a branch target
    // that collided is a control-flow address read as data, an `adrp` page base
    // that collided is a whole page read as one of its members.
    const branch = classifyArm64Branch(insn.mnemonic, insn.opStr);
    coincidence.push({ insn, kind: branch ? `branch (${insn.mnemonic})` : insn.mnemonic });
  }
  return {
    commented,
    justified,
    coincidence,
    refs: refs.length,
    strHits,
    iatHits,
    distinctTexts: texts.size,
  };
}

async function main(): Promise<void> {
  const dir = corpusDir();
  console.log(`corpus: ${dir}  [${corpusDirSource()}]`);

  const missing: string[] = [];
  const files = new Map<string, string>();
  for (const key of [...ALL_BINS, ...ARM_BINS]) {
    const p = join(dir, `${key}.exe`);
    if (existsSync(p)) files.set(key, p);
    else missing.push(`${key}.exe`);
  }
  if (missing.length > 0) {
    console.log(`SKIPPED for ${missing.join(", ")} — not in ${dir}`);
  }
  if (files.size === 0) {
    console.log("nothing to audit");
    return;
  }

  console.log("\n── ARM64: is a comment a reference, or a collision? ────────────");
  for (const key of ARM_BINS) {
    const file = files.get(key);
    if (!file) continue;
    const l = await load(file);
    const a = auditArm64(l);
    console.log(
      `${key}: ${l.instructions.length} insns, ${a.commented} commented ` +
        `(${a.justified} justified, ${a.coincidence.length} COINCIDENCE), ` +
        `${a.distinctTexts} distinct texts`,
    );
    console.log(
      `  findArm64AddressRefs: ${a.refs} addresses, ${a.strHits} string, ${a.iatHits} import`,
    );
    // Every row here is a comment naming something the instruction does not
    // reference. Gateable at 0 — see the header.
    const byKind = new Map<string, number>();
    for (const c of a.coincidence) byKind.set(c.kind, (byKind.get(c.kind) ?? 0) + 1);
    for (const [kind, n] of [...byKind].sort((x, y) => y[1] - x[1])) {
      console.log(`  coincidence ${kind}: ${n}`);
    }
    for (const c of a.coincidence.slice(0, 5)) {
      console.log(
        `    0x${c.insn.address.toString(16)} ${c.insn.mnemonic} ${c.insn.opStr}` +
          `  => ${JSON.stringify(c.insn.comment)}`,
      );
    }
  }

  console.log("\n── x86/x64: the comment stream, digested ──────────────────────");
  console.log("(compare these across two commits; they must not move)");
  for (const key of ALL_BINS) {
    const file = files.get(key);
    if (!file) continue;
    const l = await load(file);
    const lines = commentLines(l.instructions);
    console.log(
      `${key}: ${l.instructions.length} insns, ${lines.length} commented, md5 ${digest(lines)}`,
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
