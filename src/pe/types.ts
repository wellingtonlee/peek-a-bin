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
    lang: number;
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
  exports: ExportEntry[];
  tlsDirectory?: TLSDirectory;
  relocations?: RelocationBlock[];
  runtimeFunctions?: RuntimeFunction[];
  resources?: ResourceTree;
  strings: Map<number, string>; // VA → string from .rdata
  stringTypes: Map<number, "ascii" | "utf16le">;
  certificate?: import("./authenticode").CertificateInfo;
}
