/**
 * Extra recursive-descent seeds derived from detected jump tables.
 *
 * `hybridDisassemble` walks a BFS from its `seeds` and stops dead at an
 * indirect `jmp` — it has no way to know where the table it reads points. The
 * case bodies therefore fall to phase 2's linear gap fill, and where MSVC emits
 * the table immediately before the first case body (the ordinary x86 layout)
 * that sweep begins *inside the table*, decodes the table entries as
 * instructions, walks off the end misaligned and consumes the first bytes of
 * case 0. Measured on t32.exe: two of sixteen distinct targets — 0x40b900 and
 * 0x40ba9c, each directly after its table — were not instruction starts, and
 * the decompiler emitted `case 0: break;` with the body lost.
 *
 * `detectFunctions` already computes the targets and every caller already holds
 * them in `DetectResult.jumpTables`; this just turns them into seed addresses.
 * A seed is nothing but a BFS work-queue entry, so seeding a case body starts a
 * decode at the correct address without claiming it is a function start (case
 * targets deliberately stopped being registered as functions — see
 * peek-a-bin-jy4).
 */
export function jumpTableTargets(
  jumpTables: Map<number, number[]> | Iterable<[number, number[]]>,
): number[] {
  const out = new Set<number>();
  for (const [, targets] of jumpTables) {
    for (const t of targets) out.add(t);
  }
  return [...out];
}
