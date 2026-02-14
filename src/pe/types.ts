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
}

export interface ExportEntry {
  name: string;
  ordinal: number;
  address: number;
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
  strings: Map<number, string>; // VA → string from .rdata
  stringTypes: Map<number, "ascii" | "utf16le">;
}
