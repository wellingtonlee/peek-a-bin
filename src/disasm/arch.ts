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
 * Two architectures the analysis engine can actually handle are named, and
 * everything else — ARM32/Thumb, IA-64, RISC-V, MIPS — is `"unsupported"`.
 *
 * `"unsupported"` used to be `"x86"`, which meant an ARMNT image produced a
 * full screen of plausible-looking x86 instructions that were pure fiction: an
 * x86 linear sweep decodes essentially any byte string, so there is no coverage
 * signal to notice it by, unlike the A64 decode rate that `arm64.ts` refuses
 * on. The stages whose entire output is instructions refuse (peek-a-bin-x7b).
 *
 * Declining is not the same as declining to decode *at all*. `capstone-wasm`
 * does ship `CS_ARCH_ARM`, and both ARM and Thumb decode correctly through it,
 * so this is a statement about the analysis engine and not about Capstone:
 * `pdata.ts` special-cases ARM64 only, so an ARMNT image yields no `.pdata`
 * extents — the evidence the whole ARM64 detector rests on — and the prologue
 * byte tables, the operand and xref grammars, the stack-frame analyser and
 * `cfg.ts`'s mnemonic tests are all x86. Thumb-2 is variable-length, so the
 * linear sweep that makes `arm64.ts` sound does not carry over either. The net
 * of decoding anyway would be replacing loud fiction with quieter fiction.
 *
 * The PE parser is unaffected, and that is the point of refusing per stage
 * rather than at load: headers, sections, imports, exports, resources, strings
 * and Authenticode are all format-level facts this tool reads correctly for an
 * ARM32 image, and a user should still get every one of them.
 *
 * KNOWN LIMITATION — the two hybrid ARM64 formats. This paragraph said for a
 * long time that "ARM64EC and ARM64X images also carry machine 0xAA64", and
 * **the ARM64EC half of that was wrong**; the claim is settled here against
 * Microsoft's own documentation, since no such binary exists on this machine to
 * check it against (peek-a-bin-3ucw):
 *
 *  - A final **ARM64EC** image carries `IMAGE_FILE_MACHINE_AMD64` (0x8664).
 *    Microsoft's Arm64EC overview shows `link /dump /headers` reporting
 *    `8664 machine (x64) (ARM64X)` for one and says only the linked EXE or DLL
 *    carries "the `8664 (x64) (ARM64X)` or `AA64 (ARM64) (ARM64X)` machine
 *    value" — https://learn.microsoft.com/en-us/windows/arm/arm64ec — and lld
 *    writes exactly that (`case ARM64EC: coff->Machine = AMD64`,
 *    https://reviews.llvm.org/D149086).
 *  - An **ARM64X** image carries 0xAA64 by default, so that Windows 10 on Arm,
 *    which does not know the format, still loads it into an Arm64 process:
 *    "By default, Arm64X binaries appear to be Arm64 binaries" —
 *    https://learn.microsoft.com/en-us/windows/arm/arm64x-pe. It may instead be
 *    marked 0x8664, which is what makes it launch as emulated x64 by default.
 *  - `IMAGE_FILE_MACHINE_ARM64EC` (0xA641) and `IMAGE_FILE_MACHINE_ARM64X`
 *    (0xA64E) are in the PE specification's machine table, but 0xA641 is an
 *    **object/lib** marker — "not a valid final PE machine type", same page —
 *    and neither appears in a linked image's machine field. The `(ARM64X)`
 *    annotation `dumpbin` prints comes from the hybrid metadata, not from this
 *    word. So `KNOWN` below deliberately does not list either of them.
 *
 * What follows for this function is that the two hybrids arrive on *different*
 * arms and only one of them is refused:
 *
 *  - **ARM64X marked 0xAA64** takes the `"arm64"` arm and is refused, by decode
 *    rate, in `arm64.ts` — see that module's `Arm64DecodeRateError`.
 *    That refusal's real population is this case plus a mis-detected image; it
 *    never sees an ARM64EC one, which is a narrower claim than the old comment
 *    implied.
 *  - **ARM64EC, and ARM64X marked 0x8664**, take the `"x86"` arm and are
 *    disassembled as x64 with nothing said. That is a real misclassification
 *    and not a benign one: code compiled as Arm64EC is *native A64* following
 *    x64 software conventions, so the x64 decoder reads it as fiction, and an
 *    x86 linear sweep decodes essentially any byte string — the same silent
 *    failure this module's ARMNT paragraph above describes. Only the genuinely
 *    x64 parts of such an image (x64 objects linked in, the entry thunks) come
 *    out right.
 *
 * That second case is **knowingly left alone**, and the reason is evidence
 * rather than caution. The discriminator exists — `PEFile.loadConfig`
 * .chpeMetadataPointer, landed by peek-a-bin-7p5t — but routing on it would be
 * a *decision* taken on a field that has never once been read on an x64 image
 * here: measured at 11408ac, t64.exe and w64.exe have **no load-config data
 * directory at all**, so both read `undefined`, and the only two images on this
 * machine that read the field are the genuine ARM64 pair, which read 0. A wrong
 * reading would begin refusing or re-routing ordinary x64 images, which is
 * strictly worse than today. Filed rather than fixed; `arm64.ts` consumes the
 * same field for *prose only*, where a wrong reading cannot change an answer.
 */

/** An architecture the analysis engine has a decoder and a grammar for. */
export type TargetArch = "x86" | "arm64";

/**
 * What a loaded image turned out to be — a {@link TargetArch}, or the honest
 * third answer.
 *
 * Kept as a widening of `TargetArch` rather than a replacement so the many
 * functions that only ever run *after* a supported architecture was confirmed
 * keep the narrow type, and a stage that has not yet handled `"unsupported"`
 * fails to compile rather than falling through to the x86 path.
 */
export type ImageArch = TargetArch | "unsupported";

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
 * start decoding as something else, and cannot silently start *refusing*
 * either. That is the one place this deliberately differs from
 * {@link isKnownMachine}, which answers `false` for `undefined` because it is
 * asked about a machine value rather than about a caller's state.
 *
 * Every other unrecognised value is `"unsupported"`: an ARM32/Thumb, IA-64,
 * RISC-V or MIPS image is a real image whose instruction set this engine has no
 * grammar for, and saying so is the whole point of the third state.
 */
export function archForMachine(machine: number | undefined): ImageArch {
  if (machine === undefined) return "x86";
  if (machine === IMAGE_FILE_MACHINE_ARM64) return "arm64";
  if (machine === IMAGE_FILE_MACHINE_I386 || machine === IMAGE_FILE_MACHINE_AMD64) return "x86";
  return "unsupported";
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
export function unsupportedOnArch(feature: string, arch: ImageArch): string {
  // Takes the wide type and forwards, rather than making every caller split.
  // A call site that refuses on `arch !== "x86"` — `mcp/tools.ts`'s decompile
  // tool is the one that matters — then covers the unsupported case with no
  // edit at all, and cannot end up naming a decoder the image does not have.
  if (arch === "unsupported") return unsupportedArchMessage(feature);
  return `${feature} is not supported for ${ARCH_LABEL[arch]} images — it is implemented for x86 only.`;
}

/**
 * The message for an image whose architecture this engine has no decoder for.
 *
 * Deliberately worded parallel to {@link unsupportedOnArch}: same shape, same
 * "which stage refused" lead, so the two read as one family. It cannot name the
 * architecture because naming it would claim to have recognised it, and the
 * whole content of `"unsupported"` is that the machine value is not one of the
 * three this engine knows. It names what *is* supported instead, which is the
 * actionable half.
 */
export function unsupportedArchMessage(feature: string): string {
  return (
    `${feature} is not supported for this image's machine type — ` +
    `a disassembler is implemented for x86 and ARM64 only. ` +
    `The file's headers, sections, imports, exports, resources and strings are still read normally.`
  );
}
