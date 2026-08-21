/**
 * A DIRECT BRANCH IN THE FILED INSTRUCTION STREAM WHOSE TARGET IS NOT IN THE IMAGE.
 *
 * `jmp`, `call` and every `Jcc` with a literal target encode a displacement
 * relative to the instruction after them, and a linker resolves that
 * displacement inside the image it is producing. So a filed instruction reading
 * `jmp 0x288402b` in a PE whose image is `0x400000`..`0x40e000` is **not an
 * instruction the file contains**: nothing the loader maps is at that address,
 * the branch could only fault, and no compiler, obfuscator or hand-written
 * prologue emits one. It is a byte string the disassembler walked into and
 * decoded, and the interesting part is always what it walked into: a decode that
 * began at the wrong offset, i.e. `.text` data read as code, or a misaligned
 * walk off the end of it.
 *
 * WHY IT IS A GATE AT 0. Every row is provably fiction, decided against the PE
 * header alone — `polarity inverted`'s character rather than a baseline's. Note
 * what it is *not*: it is not "this branch leaves its function", which is
 * ordinary (a tail call, a `__finally` funclet, an ICF-shared epilogue) and
 * which is the weaker question `peek-a-bin-y1di`'s instrument asked. It is not
 * "this target is outside the code section" either — a `jmp` into `.rdata` would
 * be strange but a thunk table lives in a data section on some toolchains, and
 * the claim would stop being unarguable. The image is the one boundary nothing
 * legitimate crosses.
 *
 * WHY IT IS INDEPENDENT OF WHAT IT CAUGHT. It is written in terms of the
 * emitted instruction stream and `optionalHeader.sizeOfImage`, and it mentions
 * neither jump tables nor `unboundedTableExtent`. That matters because the
 * change it was built for (`peek-a-bin-xqxy`) works by *marking table bytes as
 * data*, and an audit phrased in those terms would be measuring its own input.
 * This one would report the same rows if the same fiction arrived by any other
 * route.
 *
 * IT IS A LOWER BOUND, AND A LOOSE ONE. Fiction only registers here when it
 * happens to decode as a direct branch AND the displacement happens to land
 * outside the image. Of the four jump-table sites `peek-a-bin-xqxy` fixed, this
 * saw **one per binary**: t32 0x40b824 `jmp 0x288402b` and w32 0x40964c
 * `jmp 0x2301953`, both inside the fiction that followed t32 0x40b804 /
 * w32 0x409630, while the fiction over the other two sites produced no such
 * branch at all (measured at `6d5ae92`). So a green reading is weak evidence
 * that no bytes are being read as code; a red one is proof that some are. Every
 * other instrument that could see the class was blind: `gcc` compiles fiction,
 * polarity judges guards that exist, the statement-drop audit counts drops
 * rather than inventions, and the spurious-run census this residue escaped needs
 * a run of four code-pointer words that contains its own dispatch base
 * (`peek-a-bin-7lb9`).
 *
 * WHAT IT DOES NOT LOOK AT. Only a literal, absolute target — `insn.opStr`
 * being exactly `0x…`. An indirect branch names no address to check, and a
 * register or memory operand's value is not a static fact. That is also why the
 * count is per binary rather than per function: the fiction is usually filed
 * under whichever function the byte range fell inside, which says nothing.
 */

import type { Instruction } from "../src/disasm/types";

/** One filed direct branch whose target the image does not contain. */
export interface WildBranchRec {
  bin: string;
  addr: number;
  mnemonic: string;
  target: number;
  /** How the instruction got into the stream — `"gap-fill"` is the telling one. */
  source?: string;
}

export interface WildBranchResult {
  rows: WildBranchRec[];
  /**
   * Direct branches examined. The liveness half: a zero here would mean the
   * stream was empty or the operand spelling changed under the audit, and a gate
   * reading 0 for want of looking is the failure mode this guards against.
   */
  checked: number;
}

export const emptyWildBranches = (): WildBranchResult => ({ rows: [], checked: 0 });

/** A branch or call whose whole operand is one absolute literal. */
const LITERAL_TARGET = /^0x([0-9a-fA-F]+)$/;

/**
 * Scan one binary's whole filed instruction stream.
 *
 * `imageEnd` is `imageBase + sizeOfImage`, i.e. every byte the loader maps —
 * not the code section, deliberately. See the header.
 */
export function auditWildBranches(
  out: WildBranchResult,
  bin: string,
  insns: Instruction[],
  imageBase: number,
  imageEnd: number,
): void {
  for (const i of insns) {
    // `startsWith("j")` is the habit CLAUDE.md warns against on A64, where `brk`
    // is not a `br`. It is sound here and only here: every corpus binary this
    // runs on is x86, and no x86 mnemonic beginning with `j` is anything but a
    // branch — `jmp`, the `Jcc` family, `jecxz`/`jrcxz`/`jcxz`.
    const mn = i.mnemonic;
    if (mn !== "call" && !mn.startsWith("j")) continue;
    const m = LITERAL_TARGET.exec(i.opStr);
    if (!m) continue;
    out.checked++;
    const target = parseInt(m[1], 16);
    if (target >= imageBase && target < imageEnd) continue;
    out.rows.push({ bin, addr: i.address, mnemonic: mn, target, source: i.source });
  }
}
