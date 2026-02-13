/**
 * PE Parser
 * Parses Windows Portable Executable files from ArrayBuffer
 */

import type {
  DOSHeader,
  COFFHeader,
  OptionalHeader32,
  OptionalHeader64,
  DataDirectory,
  SectionHeader,
  ImportEntry,
  ExportEntry,
  PEFile,
} from './types';
import { normalizeOptionalHeader } from './types';
import {
  IMAGE_DOS_SIGNATURE,
  IMAGE_NT_SIGNATURE,
  IMAGE_NT_OPTIONAL_HDR32_MAGIC,
  IMAGE_NT_OPTIONAL_HDR64_MAGIC,
  IMAGE_ORDINAL_FLAG32,
  IMAGE_ORDINAL_FLAG64,
  IMAGE_DIRECTORY_ENTRY_IMPORT,
  IMAGE_DIRECTORY_ENTRY_EXPORT,
} from './constants';

/**
 * Read null-terminated ASCII string from buffer
 */
function readCString(view: DataView, offset: number, maxLength = 1024): string {
  const chars: number[] = [];
  for (let i = 0; i < maxLength; i++) {
    if (offset + i >= view.byteLength) break;
    const byte = view.getUint8(offset + i);
    if (byte === 0) break;
    chars.push(byte);
  }
  return String.fromCharCode(...chars);
}

/**
 * Convert RVA (Relative Virtual Address) to file offset
 */
export function rvaToFileOffset(rva: number, sections: SectionHeader[]): number {
  for (const section of sections) {
    const sectionStart = section.virtualAddress;
    const sectionEnd = section.virtualAddress + section.virtualSize;

    if (rva >= sectionStart && rva < sectionEnd) {
      const offset = rva - section.virtualAddress;
      return section.pointerToRawData + offset;
    }
  }

  // If not in any section, assume RVA == file offset (rare case)
  return rva;
}

/**
 * Read DOS Header
 */
function parseDOSHeader(view: DataView): DOSHeader {
  const e_magic = view.getUint16(0, true);

  if (e_magic !== IMAGE_DOS_SIGNATURE) {
    throw new Error(`Invalid DOS signature: 0x${e_magic.toString(16)} (expected 0x5A4D)`);
  }

  const e_lfanew = view.getUint32(60, true);

  return { e_magic, e_lfanew };
}

/**
 * Read COFF Header
 */
function parseCOFFHeader(view: DataView, offset: number): COFFHeader {
  return {
    machine: view.getUint16(offset, true),
    numberOfSections: view.getUint16(offset + 2, true),
    timeDateStamp: view.getUint32(offset + 4, true),
    pointerToSymbolTable: view.getUint32(offset + 8, true),
    numberOfSymbols: view.getUint32(offset + 12, true),
    sizeOfOptionalHeader: view.getUint16(offset + 16, true),
    characteristics: view.getUint16(offset + 18, true),
  };
}

/**
 * Read Optional Header (PE32)
 */
function parseOptionalHeader32(view: DataView, offset: number): OptionalHeader32 {
  return {
    magic: view.getUint16(offset, true),
    majorLinkerVersion: view.getUint8(offset + 2),
    minorLinkerVersion: view.getUint8(offset + 3),
    sizeOfCode: view.getUint32(offset + 4, true),
    sizeOfInitializedData: view.getUint32(offset + 8, true),
    sizeOfUninitializedData: view.getUint32(offset + 12, true),
    addressOfEntryPoint: view.getUint32(offset + 16, true),
    baseOfCode: view.getUint32(offset + 20, true),
    baseOfData: view.getUint32(offset + 24, true),
    imageBase: view.getUint32(offset + 28, true),
    sectionAlignment: view.getUint32(offset + 32, true),
    fileAlignment: view.getUint32(offset + 36, true),
    majorOperatingSystemVersion: view.getUint16(offset + 40, true),
    minorOperatingSystemVersion: view.getUint16(offset + 42, true),
    majorImageVersion: view.getUint16(offset + 44, true),
    minorImageVersion: view.getUint16(offset + 46, true),
    majorSubsystemVersion: view.getUint16(offset + 48, true),
    minorSubsystemVersion: view.getUint16(offset + 50, true),
    win32VersionValue: view.getUint32(offset + 52, true),
    sizeOfImage: view.getUint32(offset + 56, true),
    sizeOfHeaders: view.getUint32(offset + 60, true),
    checkSum: view.getUint32(offset + 64, true),
    subsystem: view.getUint16(offset + 68, true),
    dllCharacteristics: view.getUint16(offset + 70, true),
    sizeOfStackReserve: view.getUint32(offset + 72, true),
    sizeOfStackCommit: view.getUint32(offset + 76, true),
    sizeOfHeapReserve: view.getUint32(offset + 80, true),
    sizeOfHeapCommit: view.getUint32(offset + 84, true),
    loaderFlags: view.getUint32(offset + 88, true),
    numberOfRvaAndSizes: view.getUint32(offset + 92, true),
  };
}

/**
 * Read Optional Header (PE32+)
 */
function parseOptionalHeader64(view: DataView, offset: number): OptionalHeader64 {
  return {
    magic: view.getUint16(offset, true),
    majorLinkerVersion: view.getUint8(offset + 2),
    minorLinkerVersion: view.getUint8(offset + 3),
    sizeOfCode: view.getUint32(offset + 4, true),
    sizeOfInitializedData: view.getUint32(offset + 8, true),
    sizeOfUninitializedData: view.getUint32(offset + 12, true),
    addressOfEntryPoint: view.getUint32(offset + 16, true),
    baseOfCode: view.getUint32(offset + 20, true),
    imageBase: view.getBigUint64(offset + 24, true),
    sectionAlignment: view.getUint32(offset + 32, true),
    fileAlignment: view.getUint32(offset + 36, true),
    majorOperatingSystemVersion: view.getUint16(offset + 40, true),
    minorOperatingSystemVersion: view.getUint16(offset + 42, true),
    majorImageVersion: view.getUint16(offset + 44, true),
    minorImageVersion: view.getUint16(offset + 46, true),
    majorSubsystemVersion: view.getUint16(offset + 48, true),
    minorSubsystemVersion: view.getUint16(offset + 50, true),
    win32VersionValue: view.getUint32(offset + 52, true),
    sizeOfImage: view.getUint32(offset + 56, true),
    sizeOfHeaders: view.getUint32(offset + 60, true),
    checkSum: view.getUint32(offset + 64, true),
    subsystem: view.getUint16(offset + 68, true),
    dllCharacteristics: view.getUint16(offset + 70, true),
    sizeOfStackReserve: view.getBigUint64(offset + 72, true),
    sizeOfStackCommit: view.getBigUint64(offset + 80, true),
    sizeOfHeapReserve: view.getBigUint64(offset + 88, true),
    sizeOfHeapCommit: view.getBigUint64(offset + 96, true),
    loaderFlags: view.getUint32(offset + 104, true),
    numberOfRvaAndSizes: view.getUint32(offset + 108, true),
  };
}

/**
 * Read Data Directories
 */
function parseDataDirectories(
  view: DataView,
  offset: number,
  count: number
): DataDirectory[] {
  const directories: DataDirectory[] = [];

  for (let i = 0; i < count; i++) {
    const dirOffset = offset + i * 8;
    directories.push({
      virtualAddress: view.getUint32(dirOffset, true),
      size: view.getUint32(dirOffset + 4, true),
    });
  }

  return directories;
}

/**
 * Read Section Headers
 */
function parseSectionHeaders(
  view: DataView,
  offset: number,
  count: number
): SectionHeader[] {
  const sections: SectionHeader[] = [];

  for (let i = 0; i < count; i++) {
    const sectionOffset = offset + i * 40;

    // Read section name (8 bytes, null-padded)
    const nameBytes: number[] = [];
    for (let j = 0; j < 8; j++) {
      const byte = view.getUint8(sectionOffset + j);
      if (byte !== 0) nameBytes.push(byte);
    }
    const name = String.fromCharCode(...nameBytes);

    sections.push({
      name,
      virtualSize: view.getUint32(sectionOffset + 8, true),
      virtualAddress: view.getUint32(sectionOffset + 12, true),
      sizeOfRawData: view.getUint32(sectionOffset + 16, true),
      pointerToRawData: view.getUint32(sectionOffset + 20, true),
      pointerToRelocations: view.getUint32(sectionOffset + 24, true),
      pointerToLinenumbers: view.getUint32(sectionOffset + 28, true),
      numberOfRelocations: view.getUint16(sectionOffset + 32, true),
      numberOfLinenumbers: view.getUint16(sectionOffset + 34, true),
      characteristics: view.getUint32(sectionOffset + 36, true),
    });
  }

  return sections;
}

/**
 * Parse Import Table
 */
function parseImports(
  view: DataView,
  importDir: DataDirectory,
  sections: SectionHeader[],
  is64: boolean
): ImportEntry[] {
  if (!importDir.virtualAddress || !importDir.size) {
    return [];
  }

  const imports: ImportEntry[] = [];
  const importTableOffset = rvaToFileOffset(importDir.virtualAddress, sections);

  if (importTableOffset >= view.byteLength) {
    return imports;
  }

  let descriptorOffset = importTableOffset;
  const descriptorSize = 20;

  // Walk import descriptors until null entry
  while (descriptorOffset + descriptorSize <= view.byteLength) {
    const originalFirstThunk = view.getUint32(descriptorOffset, true);
    const timeDateStamp = view.getUint32(descriptorOffset + 4, true);
    const forwarderChain = view.getUint32(descriptorOffset + 8, true);
    const nameRVA = view.getUint32(descriptorOffset + 12, true);
    const firstThunk = view.getUint32(descriptorOffset + 16, true);

    // Null descriptor marks end
    if (!originalFirstThunk && !nameRVA && !firstThunk) {
      break;
    }

    // Read library name
    const nameOffset = rvaToFileOffset(nameRVA, sections);
    if (nameOffset >= view.byteLength) {
      descriptorOffset += descriptorSize;
      continue;
    }

    const libraryName = readCString(view, nameOffset);
    const functions: string[] = [];

    // Read import names from INT (Import Name Table)
    const thunkRVA = originalFirstThunk || firstThunk;
    if (thunkRVA) {
      let thunkOffset = rvaToFileOffset(thunkRVA, sections);
      const thunkSize = is64 ? 8 : 4;

      while (thunkOffset + thunkSize <= view.byteLength) {
        const thunkValue = is64
          ? view.getBigUint64(thunkOffset, true)
          : BigInt(view.getUint32(thunkOffset, true));

        if (thunkValue === 0n) break;

        // Check if import by ordinal
        const ordinalFlag = is64 ? IMAGE_ORDINAL_FLAG64 : BigInt(IMAGE_ORDINAL_FLAG32);
        if (thunkValue & ordinalFlag) {
          const ordinal = Number(thunkValue & 0xFFFFn);
          functions.push(`Ordinal_${ordinal}`);
        } else {
          // Import by name
          const nameTableRVA = Number(thunkValue);
          const nameTableOffset = rvaToFileOffset(nameTableRVA, sections);

          if (nameTableOffset + 2 < view.byteLength) {
            // Skip hint (2 bytes)
            const funcName = readCString(view, nameTableOffset + 2);
            functions.push(funcName);
          }
        }

        thunkOffset += thunkSize;
      }
    }

    imports.push({ libraryName, functions });
    descriptorOffset += descriptorSize;
  }

  return imports;
}

/**
 * Parse Export Table
 */
function parseExports(
  view: DataView,
  exportDir: DataDirectory,
  sections: SectionHeader[]
): ExportEntry[] {
  if (!exportDir.virtualAddress || !exportDir.size) {
    return [];
  }

  const exports: ExportEntry[] = [];
  const exportTableOffset = rvaToFileOffset(exportDir.virtualAddress, sections);

  if (exportTableOffset + 40 > view.byteLength) {
    return exports;
  }

  // Read Export Directory Table
  const numberOfNames = view.getUint32(exportTableOffset + 24, true);
  const addressTableRVA = view.getUint32(exportTableOffset + 28, true);
  const namePointerRVA = view.getUint32(exportTableOffset + 32, true);
  const ordinalTableRVA = view.getUint32(exportTableOffset + 36, true);

  const addressTableOffset = rvaToFileOffset(addressTableRVA, sections);
  const namePointerOffset = rvaToFileOffset(namePointerRVA, sections);
  const ordinalTableOffset = rvaToFileOffset(ordinalTableRVA, sections);

  // Walk name pointer table
  for (let i = 0; i < numberOfNames; i++) {
    const namePointerPos = namePointerOffset + i * 4;
    const ordinalPos = ordinalTableOffset + i * 2;

    if (namePointerPos + 4 > view.byteLength || ordinalPos + 2 > view.byteLength) {
      continue;
    }

    const nameRVA = view.getUint32(namePointerPos, true);
    const ordinal = view.getUint16(ordinalPos, true);

    const nameOffset = rvaToFileOffset(nameRVA, sections);
    if (nameOffset >= view.byteLength) continue;

    const name = readCString(view, nameOffset);

    // Get address from address table
    const addressPos = addressTableOffset + ordinal * 4;
    if (addressPos + 4 > view.byteLength) continue;

    const address = view.getUint32(addressPos, true);

    exports.push({ name, ordinal, address });
  }

  return exports;
}

/**
 * Scan .rdata section for strings
 */
function extractStrings(
  view: DataView,
  sections: SectionHeader[],
  minLength = 4
): Map<number, string> {
  const strings = new Map<number, string>();

  // Find .rdata or .data section
  const rdataSection = sections.find(
    (s) => s.name === '.rdata' || s.name === '.data' || s.name === '.rodata'
  );

  if (!rdataSection) return strings;

  const start = rdataSection.pointerToRawData;
  const end = Math.min(
    start + rdataSection.sizeOfRawData,
    view.byteLength
  );

  let i = start;
  while (i < end) {
    const byte = view.getUint8(i);

    // Check if printable ASCII
    if (byte >= 0x20 && byte <= 0x7e) {
      const strStart = i;
      const chars: number[] = [];

      // Read until null or non-printable
      while (i < end) {
        const b = view.getUint8(i);
        if (b === 0) break;
        if (b < 0x20 || b > 0x7e) break;
        chars.push(b);
        i++;
      }

      if (chars.length >= minLength) {
        const str = String.fromCharCode(...chars);
        const rva =
          rdataSection.virtualAddress + (strStart - rdataSection.pointerToRawData);
        strings.set(rva, str);
      }
    }

    i++;
  }

  return strings;
}

/**
 * Main PE Parser
 */
export function parsePE(buffer: ArrayBuffer): PEFile {
  const view = new DataView(buffer);

  // 1. Parse DOS Header
  const dosHeader = parseDOSHeader(view);

  // 2. Validate PE Signature
  const peOffset = dosHeader.e_lfanew;
  if (peOffset + 4 > view.byteLength) {
    throw new Error('Invalid PE offset');
  }

  const peSignature = view.getUint32(peOffset, true);
  if (peSignature !== IMAGE_NT_SIGNATURE) {
    throw new Error(
      `Invalid PE signature: 0x${peSignature.toString(16)} (expected 0x4550)`
    );
  }

  // 3. Parse COFF Header
  const coffOffset = peOffset + 4;
  const coffHeader = parseCOFFHeader(view, coffOffset);

  // 4. Parse Optional Header
  const optionalHeaderOffset = coffOffset + 20;
  const magic = view.getUint16(optionalHeaderOffset, true);
  const is64 = magic === IMAGE_NT_OPTIONAL_HDR64_MAGIC;

  let optionalHeader: OptionalHeader32 | OptionalHeader64;
  let dataDirectoriesOffset: number;

  if (is64) {
    optionalHeader = parseOptionalHeader64(view, optionalHeaderOffset);
    dataDirectoriesOffset = optionalHeaderOffset + 112;
  } else if (magic === IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    optionalHeader = parseOptionalHeader32(view, optionalHeaderOffset);
    dataDirectoriesOffset = optionalHeaderOffset + 96;
  } else {
    throw new Error(`Invalid optional header magic: 0x${magic.toString(16)}`);
  }

  // 5. Parse Data Directories
  const dataDirectories = parseDataDirectories(
    view,
    dataDirectoriesOffset,
    optionalHeader.numberOfRvaAndSizes
  );

  // 6. Parse Section Headers
  const sectionHeadersOffset =
    optionalHeaderOffset + coffHeader.sizeOfOptionalHeader;
  const sections = parseSectionHeaders(
    view,
    sectionHeadersOffset,
    coffHeader.numberOfSections
  );

  // 7. Parse Imports
  const imports = parseImports(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT] || { virtualAddress: 0, size: 0 },
    sections,
    is64
  );

  // 8. Parse Exports
  const exports = parseExports(
    view,
    dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT] || { virtualAddress: 0, size: 0 },
    sections
  );

  // 9. Extract strings from .rdata
  const strings = extractStrings(view, sections);

  return {
    buffer,
    is64,
    dosHeader,
    coffHeader,
    optionalHeader: normalizeOptionalHeader(optionalHeader),
    rawOptionalHeader: optionalHeader,
    dataDirectories,
    sections,
    imports,
    exports,
    strings,
  };
}
