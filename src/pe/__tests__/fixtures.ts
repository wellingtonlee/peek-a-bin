/**
 * PE test fixture builder.
 * Constructs minimal valid PE ArrayBuffers for testing.
 */

import {
  IMAGE_DOS_SIGNATURE,
  IMAGE_NT_SIGNATURE,
  IMAGE_NT_OPTIONAL_HDR32_MAGIC,
  IMAGE_NT_OPTIONAL_HDR64_MAGIC,
  IMAGE_FILE_MACHINE_I386,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_CNT_CODE,
} from '../constants';

export interface SectionDef {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  data: Uint8Array;
  characteristics: number;
}

export interface PEFixtureOptions {
  machine?: number;
  characteristics?: number;
  imageBase?: number;
  addressOfEntryPoint?: number;
  sections?: SectionDef[];
  numberOfRvaAndSizes?: number;
  /** Override data directory entries: index -> {virtualAddress, size} */
  dataDirectories?: Map<number, { virtualAddress: number; size: number }>;
}

const NUM_DATA_DIRS = 16;
const DATA_DIR_ENTRY_SIZE = 8;

function writeString(view: DataView, offset: number, str: string, maxLen: number): void {
  for (let i = 0; i < maxLen; i++) {
    view.setUint8(offset + i, i < str.length ? str.charCodeAt(i) : 0);
  }
}

function defaultTextSection(fileOffset: number): SectionDef {
  const code = new Uint8Array([0xCC, 0xCC, 0xCC, 0xCC]); // int3 x4
  return {
    name: '.text',
    virtualAddress: 0x1000,
    virtualSize: code.length,
    data: code,
    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
  };
}

/**
 * Build a minimal PE32 (32-bit) buffer.
 */
export function buildMinimalPE32(opts: PEFixtureOptions = {}): ArrayBuffer {
  const machine = opts.machine ?? IMAGE_FILE_MACHINE_I386;
  const peCharacteristics = opts.characteristics ?? 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE
  const imageBase = opts.imageBase ?? 0x00400000;
  const entryPoint = opts.addressOfEntryPoint ?? 0x1000;
  const numDataDirs = opts.numberOfRvaAndSizes ?? NUM_DATA_DIRS;

  // PE32 optional header: 96 bytes fixed + numDataDirs * 8
  const optionalHeaderSize = 96 + numDataDirs * DATA_DIR_ENTRY_SIZE;

  // Layout offsets
  const dosHeaderSize = 64;
  const peSignatureSize = 4;
  const coffHeaderSize = 20;

  const peOffset = dosHeaderSize; // e_lfanew
  const coffOffset = peOffset + peSignatureSize;
  const optionalHeaderOffset = coffOffset + coffHeaderSize;
  const sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

  // Sections
  const sections = opts.sections ?? [defaultTextSection(0)];
  const numSections = sections.length;
  const sectionHeadersSize = numSections * 40;

  // Align section data start to 0x200 boundary
  const headersEnd = sectionHeadersOffset + sectionHeadersSize;
  const fileAlignment = 0x200;
  const sectionDataStart = Math.ceil(headersEnd / fileAlignment) * fileAlignment;

  // Compute file offsets for each section's raw data
  const sectionFileOffsets: number[] = [];
  let currentFileOffset = sectionDataStart;
  for (const sec of sections) {
    sectionFileOffsets.push(currentFileOffset);
    currentFileOffset += Math.ceil(sec.data.length / fileAlignment) * fileAlignment;
  }

  const totalSize = currentFileOffset;
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // --- DOS Header ---
  view.setUint16(0, IMAGE_DOS_SIGNATURE, true); // e_magic = "MZ"
  view.setUint32(0x3C, peOffset, true);          // e_lfanew

  // --- PE Signature ---
  view.setUint32(peOffset, IMAGE_NT_SIGNATURE, true); // "PE\0\0"

  // --- COFF Header ---
  view.setUint16(coffOffset, machine, true);
  view.setUint16(coffOffset + 2, numSections, true);
  view.setUint32(coffOffset + 4, 0, true);  // timeDateStamp
  view.setUint32(coffOffset + 8, 0, true);  // pointerToSymbolTable
  view.setUint32(coffOffset + 12, 0, true); // numberOfSymbols
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffOffset + 18, peCharacteristics, true);

  // --- Optional Header (PE32) ---
  let o = optionalHeaderOffset;
  view.setUint16(o, IMAGE_NT_OPTIONAL_HDR32_MAGIC, true); // magic
  view.setUint8(o + 2, 14);   // majorLinkerVersion
  view.setUint8(o + 3, 0);    // minorLinkerVersion
  view.setUint32(o + 4, 0, true);   // sizeOfCode
  view.setUint32(o + 8, 0, true);   // sizeOfInitializedData
  view.setUint32(o + 12, 0, true);  // sizeOfUninitializedData
  view.setUint32(o + 16, entryPoint, true); // addressOfEntryPoint
  view.setUint32(o + 20, 0x1000, true); // baseOfCode
  view.setUint32(o + 24, 0, true);      // baseOfData
  view.setUint32(o + 28, imageBase, true); // imageBase
  view.setUint32(o + 32, 0x1000, true); // sectionAlignment
  view.setUint32(o + 36, fileAlignment, true); // fileAlignment
  view.setUint32(o + 56, 0x10000, true); // sizeOfImage
  view.setUint32(o + 60, sectionDataStart, true); // sizeOfHeaders
  view.setUint32(o + 92, numDataDirs, true); // numberOfRvaAndSizes

  // --- Data Directories ---
  const dataDirOffset = o + 96;
  if (opts.dataDirectories) {
    for (const [idx, dir] of opts.dataDirectories) {
      if (idx < numDataDirs) {
        const ddOff = dataDirOffset + idx * DATA_DIR_ENTRY_SIZE;
        view.setUint32(ddOff, dir.virtualAddress, true);
        view.setUint32(ddOff + 4, dir.size, true);
      }
    }
  }

  // --- Section Headers ---
  for (let i = 0; i < numSections; i++) {
    const sec = sections[i];
    const shOff = sectionHeadersOffset + i * 40;
    writeString(view, shOff, sec.name, 8);
    view.setUint32(shOff + 8, sec.virtualSize, true);
    view.setUint32(shOff + 12, sec.virtualAddress, true);
    view.setUint32(shOff + 16, sec.data.length, true); // sizeOfRawData
    view.setUint32(shOff + 20, sectionFileOffsets[i], true); // pointerToRawData
    view.setUint32(shOff + 36, sec.characteristics, true);
  }

  // --- Section Data ---
  for (let i = 0; i < numSections; i++) {
    bytes.set(sections[i].data, sectionFileOffsets[i]);
  }

  return buffer;
}

/**
 * Build a minimal PE64 (PE32+) buffer.
 */
export function buildMinimalPE64(opts: PEFixtureOptions = {}): ArrayBuffer {
  const machine = opts.machine ?? IMAGE_FILE_MACHINE_AMD64;
  const peCharacteristics = opts.characteristics ?? 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
  const imageBase = opts.imageBase ?? 0x140000000;
  const entryPoint = opts.addressOfEntryPoint ?? 0x1000;
  const numDataDirs = opts.numberOfRvaAndSizes ?? NUM_DATA_DIRS;

  // PE64 optional header: 112 bytes fixed + numDataDirs * 8
  const optionalHeaderSize = 112 + numDataDirs * DATA_DIR_ENTRY_SIZE;

  const dosHeaderSize = 64;
  const peSignatureSize = 4;
  const coffHeaderSize = 20;

  const peOffset = dosHeaderSize;
  const coffOffset = peOffset + peSignatureSize;
  const optionalHeaderOffset = coffOffset + coffHeaderSize;
  const sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

  const sections = opts.sections ?? [defaultTextSection(0)];
  const numSections = sections.length;
  const sectionHeadersSize = numSections * 40;

  const headersEnd = sectionHeadersOffset + sectionHeadersSize;
  const fileAlignment = 0x200;
  const sectionDataStart = Math.ceil(headersEnd / fileAlignment) * fileAlignment;

  const sectionFileOffsets: number[] = [];
  let currentFileOffset = sectionDataStart;
  for (const sec of sections) {
    sectionFileOffsets.push(currentFileOffset);
    currentFileOffset += Math.ceil(sec.data.length / fileAlignment) * fileAlignment;
  }

  const totalSize = currentFileOffset;
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // --- DOS Header ---
  view.setUint16(0, IMAGE_DOS_SIGNATURE, true);
  view.setUint32(0x3C, peOffset, true);

  // --- PE Signature ---
  view.setUint32(peOffset, IMAGE_NT_SIGNATURE, true);

  // --- COFF Header ---
  view.setUint16(coffOffset, machine, true);
  view.setUint16(coffOffset + 2, numSections, true);
  view.setUint32(coffOffset + 4, 0, true);
  view.setUint32(coffOffset + 8, 0, true);
  view.setUint32(coffOffset + 12, 0, true);
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffOffset + 18, peCharacteristics, true);

  // --- Optional Header (PE64) ---
  let o = optionalHeaderOffset;
  view.setUint16(o, IMAGE_NT_OPTIONAL_HDR64_MAGIC, true);
  view.setUint8(o + 2, 14);
  view.setUint8(o + 3, 0);
  view.setUint32(o + 4, 0, true);
  view.setUint32(o + 8, 0, true);
  view.setUint32(o + 12, 0, true);
  view.setUint32(o + 16, entryPoint, true);
  view.setUint32(o + 20, 0x1000, true); // baseOfCode
  // PE64: imageBase is at offset 24, 8 bytes (bigint)
  view.setBigUint64(o + 24, BigInt(imageBase), true);
  view.setUint32(o + 32, 0x1000, true); // sectionAlignment
  view.setUint32(o + 36, fileAlignment, true); // fileAlignment
  view.setUint32(o + 56, 0x10000, true); // sizeOfImage
  view.setUint32(o + 60, sectionDataStart, true); // sizeOfHeaders
  view.setUint32(o + 108, numDataDirs, true); // numberOfRvaAndSizes

  // --- Data Directories ---
  const dataDirOffset = o + 112;
  if (opts.dataDirectories) {
    for (const [idx, dir] of opts.dataDirectories) {
      if (idx < numDataDirs) {
        const ddOff = dataDirOffset + idx * DATA_DIR_ENTRY_SIZE;
        view.setUint32(ddOff, dir.virtualAddress, true);
        view.setUint32(ddOff + 4, dir.size, true);
      }
    }
  }

  // --- Section Headers ---
  for (let i = 0; i < numSections; i++) {
    const sec = sections[i];
    const shOff = sectionHeadersOffset + i * 40;
    writeString(view, shOff, sec.name, 8);
    view.setUint32(shOff + 8, sec.virtualSize, true);
    view.setUint32(shOff + 12, sec.virtualAddress, true);
    view.setUint32(shOff + 16, sec.data.length, true);
    view.setUint32(shOff + 20, sectionFileOffsets[i], true);
    view.setUint32(shOff + 36, sec.characteristics, true);
  }

  // --- Section Data ---
  for (let i = 0; i < numSections; i++) {
    bytes.set(sections[i].data, sectionFileOffsets[i]);
  }

  return buffer;
}
