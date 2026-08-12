/**
 * Which instruction set a loaded image actually holds.
 *
 * Everything downstream of the PE parser used to pick its Capstone mode from
 * `is64` — the PE32+ optional-header magic. That is a *pointer width*, not an
 * architecture: an ARM64 image is PE32+, so it was disassembled as x86-64 and
 * decoded to nothing at all (peek-a-bin-amu: t64-arm.exe listed 419 correct
 * .pdata function boundaries with zero instructions inside them). The machine
 * field of the COFF header is the thing that answers the question, and this
 * module is the single place that reads it.
 *
 * Only the two architectures the analysis engine can actually handle are named.
 * Anything else — IA-64, ARM32/Thumb, RISC-V, MIPS — maps to `"x86"` and keeps
 * exactly the behaviour it has today. That is deliberate: those images are
 * already mis-analysed, this bead is not about them, and inventing a third
 * state here would mean deciding what every consumer does with it without a
 * single test file to check the answer against. `isKnownMachine` exists so a
 * caller that wants to say "this image is not what it looks like" can.
 *
 * KNOWN LIMITATION — ARM64EC and ARM64X images also carry machine 0xAA64 but
 * contain x64 code (ARM64EC) or both (ARM64X); telling them apart needs the
 * CHPE metadata pointer out of the load-config directory, which the parser does
 * not read. Such an image is treated as pure ARM64 here and its x64 half will
 * decode to garbage. See peek-a-bin follow-up.
 */

export type TargetArch = "x86" | "arm64";

export const IMAGE_FILE_MACHINE_I386 = 0x014c;
export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

/** Machine values this engine has a real disassembler for. */
const KNOWN: ReadonlySet<number> = new Set([
  IMAGE_FILE_MACHINE_I386,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
]);

/**
 * The architecture to analyse an image as, from `coffHeader.machine`.
 *
 * `undefined` means "the caller never told us" — the pre-ARM64 default — and
 * yields x86, so a call site that has not been threaded through cannot silently
 * start decoding as something else.
 */
export function archForMachine(machine: number | undefined): TargetArch {
  return machine === IMAGE_FILE_MACHINE_ARM64 ? "arm64" : "x86";
}

/** False for a machine type this engine has no disassembler for. */
export function isKnownMachine(machine: number | undefined): boolean {
  return machine !== undefined && KNOWN.has(machine);
}

/** Display name, for messages a user reads. */
export const ARCH_LABEL: Record<TargetArch, string> = {
  x86: "x86",
  arm64: "ARM64",
};

/**
 * The message shown where a stage cannot run on this architecture.
 *
 * Centralised so every refusal reads the same way and says which stage refused.
 * A visible "not supported" beats plausible-looking output derived from bytes
 * the stage cannot read: the decompiler's IR lifter, the stack-frame analyser
 * and the operand/xref parsers are all x86 instruction grammars, and fed ARM64
 * they do not fail — they produce confident nonsense.
 */
export function unsupportedOnArch(feature: string, arch: TargetArch): string {
  return `${feature} is not supported for ${ARCH_LABEL[arch]} images — it is implemented for x86 only.`;
}
