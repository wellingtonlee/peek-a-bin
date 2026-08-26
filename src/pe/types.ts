/**
 * PE Format Type Definitions
 * Pure TypeScript types for Windows Portable Executable parsing
 */

export interface DOSHeader {
  e_magic: number; // 0x5A4D "MZ"
  e_lfanew: number; // Offset to PE signature
}

export interface COFFHeader {
  machine: number;
  numberOfSections: number;
  timeDateStamp: number;
  pointerToSymbolTable: number;
  numberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
}

export interface OptionalHeaderCommon {
  magic: number; // 0x10b (PE32) or 0x20b (PE32+)
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  addressOfEntryPoint: number;
  baseOfCode: number;
}

export interface OptionalHeader32 extends OptionalHeaderCommon {
  baseOfData: number;
  imageBase: number;
  sectionAlignment: number;
  fileAlignment: number;
  majorOperatingSystemVersion: number;
  minorOperatingSystemVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  win32VersionValue: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checkSum: number;
  subsystem: number;
  dllCharacteristics: number;
  sizeOfStackReserve: number;
  sizeOfStackCommit: number;
  sizeOfHeapReserve: number;
  sizeOfHeapCommit: number;
  loaderFlags: number;
  numberOfRvaAndSizes: number;
}

export interface OptionalHeader64 extends OptionalHeaderCommon {
  imageBase: bigint;
  sectionAlignment: number;
  fileAlignment: number;
  majorOperatingSystemVersion: number;
  minorOperatingSystemVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  win32VersionValue: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checkSum: number;
  subsystem: number;
  dllCharacteristics: number;
  sizeOfStackReserve: bigint;
  sizeOfStackCommit: bigint;
  sizeOfHeapReserve: bigint;
  sizeOfHeapCommit: bigint;
  loaderFlags: number;
  numberOfRvaAndSizes: number;
}

export type OptionalHeader = OptionalHeader32 | OptionalHeader64;

/** Normalized optional header where imageBase is always a number (safe for PE32+ up to ~2^53) */
export interface NormalizedOptionalHeader {
  magic: number;
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;
  addressOfEntryPoint: number;
  baseOfCode: number;
  imageBase: number;
  sectionAlignment: number;
  fileAlignment: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checksum: number;
  subsystem: number;
  dllCharacteristics: number;
  numberOfRvaAndSizes: number;
}

export function normalizeOptionalHeader(opt: OptionalHeader): NormalizedOptionalHeader {
  return {
    magic: opt.magic,
    majorLinkerVersion: opt.majorLinkerVersion,
    minorLinkerVersion: opt.minorLinkerVersion,
    sizeOfCode: opt.sizeOfCode,
    addressOfEntryPoint: opt.addressOfEntryPoint,
    baseOfCode: opt.baseOfCode,
    imageBase: typeof opt.imageBase === "bigint" ? Number(opt.imageBase) : opt.imageBase,
    sectionAlignment: opt.sectionAlignment,
    fileAlignment: opt.fileAlignment,
    sizeOfImage: opt.sizeOfImage,
    sizeOfHeaders: opt.sizeOfHeaders,
    checksum: opt.checkSum,
    subsystem: opt.subsystem,
    dllCharacteristics: opt.dllCharacteristics,
    numberOfRvaAndSizes: opt.numberOfRvaAndSizes,
  };
}

export interface DataDirectory {
  virtualAddress: number;
  size: number;
}

export interface SectionHeader {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  pointerToRelocations: number;
  pointerToLinenumbers: number;
  numberOfRelocations: number;
  numberOfLinenumbers: number;
  characteristics: number;
}

export interface ImportDescriptor {
  originalFirstThunk: number;
  timeDateStamp: number;
  forwarderChain: number;
  nameRVA: number;
  firstThunk: number;
}

export interface ImportEntry {
  libraryName: string;
  functions: string[];
  iatAddresses: number[];
  /**
   * Set when this entry does not fully describe what the file holds: the thunk
   * walk stopped at a bound rather than at a null thunk, or a name in it could
   * not be read whole. One flag, one meaning — **not whole** — because that is
   * the granularity every consumer needs and the finer distinction between the
   * two causes is not one any of them acts on.
   *
   * `PEFile.importsTruncated` is the whole-table answer and is set whenever any
   * entry carries this.
   */
  truncated?: boolean;
}

export interface ExportEntry {
  /**
   * Exported name. Exports that appear only in the address table (no entry in
   * the name table) get a synthesized `Ordinal#<n>` display name and carry
   * `byOrdinal: true`.
   */
  name: string;
  /** Spec ordinal: the export directory's Base plus the address-table index. */
  ordinal: number;
  /**
   * Export Address Table value. A code/data RVA normally, or — when
   * `forwarder` is set — the RVA of the forwarder string itself.
   */
  address: number;
  /** True when this export has no name of its own. */
  byOrdinal?: boolean;
  /**
   * `"OTHERDLL.Func"` for a forwarder export: the address falls inside the
   * export directory's own range, so it points at a redirect string rather
   * than at code in this image.
   */
  forwarder?: string;
}

export interface TLSDirectory {
  startAddressOfRawData: number;
  endAddressOfRawData: number;
  addressOfIndex: number;
  addressOfCallBacks: number;
  callbacks: number[];
  sizeOfZeroFill: number;
  characteristics: number;
}

/**
 * The part of `IMAGE_LOAD_CONFIG_DIRECTORY` (data directory 10) this parser
 * reads: enough to say whether the image declares CHPE metadata.
 *
 * "CHPE" is Compiled Hybrid PE — the marker an ARM64EC or ARM64X image carries,
 * and the only *declaration* of hybrid-ness in the format. Everything else about
 * such an image is shared with a non-hybrid build of the machine type it is
 * marked with, which is why `disassembleArm64` also weighs its decode rate —
 * evidence about the bytes rather than an answer about the image.
 *
 * The machine type does **not** narrow it to ARM64, and this docstring used to
 * imply it did by naming 0xAA64. Settled against Microsoft's documentation at
 * peek-a-bin-3ucw, since no hybrid binary exists on this machine: a final
 * ARM64EC image is marked `IMAGE_FILE_MACHINE_AMD64` (0x8664), and an ARM64X
 * image is marked 0xAA64 by default and may be marked 0x8664. So a CHPE
 * declaration can appear under either word, and 0xA641/0xA64E — the ARM64EC and
 * ARM64X machine constants — appear in *object* files rather than in a linked
 * image. See `disasm/arch.ts` for the citations and for what each case costs.
 *
 * Two sizes, both reported, because they disagree in practice and the smaller
 * one is what bounds a read. `directorySize` is what the data directory entry
 * claims; `declaredSize` is the `Size` field the structure writes about itself at
 * offset 0. Older linkers emit a structure that stops long before
 * `CHPEMetadataPointer`, so a reader that trusts the offset alone is reading
 * whatever the linker put next.
 */
export interface LoadConfigDirectory {
  /** RVA from the data directory entry. */
  virtualAddress: number;
  /** `Size` in the data directory entry. */
  directorySize: number;
  /** The structure's own `Size` field, at offset 0. */
  declaredSize: number;
  /**
   * `CHPEMetadataPointer` as written — a VA, so subtract `imageBase` to get an
   * RVA. Zero means the field is present and the image is not hybrid.
   *
   * `undefined` is the third answer and a different one: the structure is too
   * short to contain the field, the field is not fully inside the section's raw
   * data, or the image is PE32 with no 32-bit CHPE slot. "Not declared" and "not
   * readable" must not collapse into one value, because only the first is
   * evidence about the image.
   */
  chpeMetadataPointer?: number;
}

export interface RelocationEntry {
  type: number;
  offset: number;
}

export interface RelocationBlock {
  virtualAddress: number;
  entries: RelocationEntry[];
}

export interface RuntimeFunction {
  beginAddress: number; // RVA
  endAddress: number; // RVA
  unwindInfoAddress: number; // RVA
  handlerAddress?: number; // RVA of exception handler (if UNW_FLAG_EHANDLER/UHANDLER)
  handlerFlags?: number; // UNWIND_INFO flags byte
  /**
   * ARM64 only: the stack frame this record describes, decoded from the packed
   * `.pdata` word or from the `.xdata` unwind codes — see `pe/arm64Unwind.ts`.
   *
   * Absent on x64, whose `UNWIND_INFO` is a different structure this project
   * has never needed the frame out of, and absent for an ARM64 record whose
   * codes could not be walked. `undefined` therefore means "the record did not
   * say", never "there is no frame": `disasm/arm64Frame.ts` refuses on it.
   */
  arm64Frame?: import("./arm64Unwind").Arm64UnwindFrame;
}

export interface ResourceNode {
  id: number | string;
  children?: ResourceNode[];
  dataEntry?: { rva: number; size: number; codePage: number };
}

export interface ResourceTree {
  root: ResourceNode[];
  entries: {
    type: number | string;
    name: number | string;
    /**
     * A LANGID, or a NAME — the third level of the directory is identified by
     * the same high bit as the two above it, so `number | string` is the honest
     * type and the three levels now agree.
     *
     * VANISHINGLY RARE AND DELIBERATELY SUPPORTED. `rc.exe` writes a LANGID, so
     * a named language level is the output of a hand-rolled or non-Microsoft
     * resource compiler — which is exactly why a hostile sample reaches for it,
     * and exactly why a tool whose readers open hostile files should not quietly
     * relabel it. No binary on the machine this was written on has one; the
     * evidence is `src/pe/__tests__/fixtures.ts` emitting the bytes.
     */
    lang: number | string;
    rva: number;
    size: number;
  }[];
  /**
   * Set when the walk hit its entry budget and stopped early. Only a crafted
   * (or absurdly large) resource directory can reach it.
   */
  truncated?: boolean;
}

export interface PEFile {
  buffer: ArrayBuffer;
  is64: boolean;
  dosHeader: DOSHeader;
  coffHeader: COFFHeader;
  optionalHeader: NormalizedOptionalHeader;
  rawOptionalHeader: OptionalHeader;
  dataDirectories: DataDirectory[];
  sections: SectionHeader[];
  imports: ImportEntry[];
  /**
   * Set when `imports` is **not the whole import table**: the descriptor walk
   * stopped at a bound rather than at the null descriptor, or some entry is
   * `truncated`. Only a crafted (or absurdly large) import table reaches it.
   *
   * Read it before treating `imports` as a complete description of the file.
   * `computeImphash` refuses outright on it: a digest over a short list is
   * well-formed and wrong, and it is only ever compared with another tool's
   * answer, so it fails by matching nothing. See `parseImports`.
   */
  importsTruncated?: boolean;
  exports: ExportEntry[];
  /**
   * Set when `exports` is **not the whole export table**: a name-pointer,
   * ordinal or address-table walk stopped at a bound rather than at its
   * declared count, or an export name ran past `readCString`'s limit. Only a
   * crafted (or absurdly large) export table reaches it — `MAX_EXPORT_ENTRIES`
   * is the format's own `uint16` ordinal ceiling, so a well-formed file cannot.
   *
   * Read it before treating `exports` as a complete description of the file.
   * There is no export-side digest to withhold (contrast `importsTruncated` and
   * `computeImphash`), so the flag and the Exports tab's heading count are the
   * whole admission. See `parseExports`.
   */
  exportsTruncated?: boolean;
  tlsDirectory?: TLSDirectory;
  loadConfig?: LoadConfigDirectory;
  relocations?: RelocationBlock[];
  runtimeFunctions?: RuntimeFunction[];
  resources?: ResourceTree;
  strings: Map<number, string>; // VA → string from .rdata
  stringTypes: Map<number, "ascii" | "utf16le">;
  certificate?: import("./authenticode").CertificateInfo;
}
