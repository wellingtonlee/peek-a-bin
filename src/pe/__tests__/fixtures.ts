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
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_ORDINAL_FLAG32,
  IMAGE_ORDINAL_FLAG64,
  IMAGE_DIRECTORY_ENTRY_EXPORT,
  IMAGE_DIRECTORY_ENTRY_IMPORT,
  IMAGE_DIRECTORY_ENTRY_TLS,
  IMAGE_DIRECTORY_ENTRY_BASERELOC,
} from "../constants";

export interface SectionDef {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  data: Uint8Array;
  characteristics: number;
}

/** One imported symbol: by name (with an optional hint) or by ordinal. */
export interface ImportFunctionDef {
  name?: string;
  hint?: number;
  ordinal?: number;
}

export interface ImportLibraryDef {
  libraryName: string;
  functions: ImportFunctionDef[];
}

export interface ExportDirDef {
  dllName: string;
  /** Written to the directory's Base field. */
  ordinalBase?: number;
  /**
   * Export address table, in slot order. A number is written verbatim as a
   * function RVA; `{ forwarder: 'OTHER.Func' }` emits the string inside the
   * export directory's range and writes its RVA, i.e. a forwarder export.
   */
  addresses: (number | { forwarder: string })[];
  /**
   * Named exports. `addressIndex` is the value written to the ordinal table —
   * the slot in `addresses` that this name resolves to. Slots with no name here
   * become ordinal-only exports.
   */
  names: { name: string; addressIndex: number }[];
}

export interface TLSDef {
  startAddressOfRawData?: number;
  endAddressOfRawData?: number;
  addressOfIndex?: number;
  /** Callback VAs (image-based). Empty/omitted leaves AddressOfCallBacks null. */
  callbacks?: number[];
  /** Write this VA into AddressOfCallBacks verbatim (overrides `callbacks`). */
  addressOfCallBacks?: number;
  sizeOfZeroFill?: number;
  characteristics?: number;
}

export interface RelocBlockDef {
  virtualAddress: number;
  entries: { type: number; offset: number }[];
}

/**
 * Real data directories to synthesize. Everything requested here is laid out
 * into one extra section and the matching data directory entries are filled in.
 */
export interface DirectorySpec {
  imports?: ImportLibraryDef[];
  exports?: ExportDirDef;
  tls?: TLSDef;
  relocations?: RelocBlockDef[];
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
  /** Synthesize real import/export/TLS/relocation directories in an extra section. */
  directories?: DirectorySpec;
  /** RVA of the synthesized directory section (default 0x2000). */
  directoryRVA?: number;
  /** Name of the synthesized directory section (default '.rdata'). */
  directorySectionName?: string;
}

const NUM_DATA_DIRS = 16;
const DATA_DIR_ENTRY_SIZE = 8;
/** Backing size for the synthesized directory section; trimmed to what is used. */
const DIRECTORY_BLOB_SIZE = 0x4000;

function writeString(view: DataView, offset: number, str: string, maxLen: number): void {
  for (let i = 0; i < maxLen; i++) {
    view.setUint8(offset + i, i < str.length ? str.charCodeAt(i) : 0);
  }
}

function defaultTextSection(_fileOffset: number): SectionDef {
  const code = new Uint8Array([0xcc, 0xcc, 0xcc, 0xcc]); // int3 x4
  return {
    name: ".text",
    virtualAddress: 0x1000,
    virtualSize: code.length,
    data: code,
    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
  };
}

/**
 * Lay out import/export/TLS/relocation structures into a single section body.
 *
 * Everything is allocated from one bump pointer, so every internal RVA is real
 * and the parser's rvaToFileOffset walk exercises the same code path it would on
 * a linker-produced binary.
 */
function buildDirectorySection(
  spec: DirectorySpec,
  cfg: { is64: boolean; imageBase: number; rva: number },
): { data: Uint8Array; dirs: Map<number, { virtualAddress: number; size: number }> } {
  const { is64, imageBase, rva: baseRVA } = cfg;
  const backing = new Uint8Array(DIRECTORY_BLOB_SIZE);
  const dv = new DataView(backing.buffer);
  const dirs = new Map<number, { virtualAddress: number; size: number }>();
  const ptrSize = is64 ? 8 : 4;

  let pos = 0;
  const alloc = (n: number, align = 4): number => {
    pos = Math.ceil(pos / align) * align;
    const at = pos;
    pos += n;
    if (pos > DIRECTORY_BLOB_SIZE) throw new Error("fixture directory section overflow");
    return at;
  };
  /** RVA of a byte offset within this section. */
  const rvaOf = (off: number): number => baseRVA + off;
  const putString = (s: string): number => {
    const at = alloc(s.length + 1, 1);
    for (let i = 0; i < s.length; i++) backing[at + i] = s.charCodeAt(i);
    return at;
  };
  const writePtr = (off: number, value: number | bigint): void => {
    if (is64) dv.setBigUint64(off, BigInt(value), true);
    else dv.setUint32(off, Number(value), true);
  };

  // --- Imports ---
  if (spec.imports) {
    const descriptorTable = alloc((spec.imports.length + 1) * 20);
    spec.imports.forEach((lib, i) => {
      const nameOff = putString(lib.libraryName);

      // Hint/name entries are emitted first so the thunk values can point at them.
      const thunkValues = lib.functions.map((fn) => {
        if (fn.ordinal !== undefined) {
          const flag = is64 ? IMAGE_ORDINAL_FLAG64 : BigInt(IMAGE_ORDINAL_FLAG32);
          return flag | BigInt(fn.ordinal);
        }
        const name = fn.name ?? "";
        const hintName = alloc(2 + name.length + 1, 2);
        dv.setUint16(hintName, fn.hint ?? 0, true);
        for (let j = 0; j < name.length; j++) backing[hintName + 2 + j] = name.charCodeAt(j);
        return BigInt(rvaOf(hintName));
      });

      // INT and IAT both hold the same thunk values pre-load; both are null-terminated.
      const intOff = alloc((thunkValues.length + 1) * ptrSize, ptrSize);
      const iatOff = alloc((thunkValues.length + 1) * ptrSize, ptrSize);
      thunkValues.forEach((v, j) => {
        writePtr(intOff + j * ptrSize, v);
        writePtr(iatOff + j * ptrSize, v);
      });

      const d = descriptorTable + i * 20;
      dv.setUint32(d, rvaOf(intOff), true); // OriginalFirstThunk
      dv.setUint32(d + 12, rvaOf(nameOff), true); // Name
      dv.setUint32(d + 16, rvaOf(iatOff), true); // FirstThunk
    });
    dirs.set(IMAGE_DIRECTORY_ENTRY_IMPORT, {
      virtualAddress: rvaOf(descriptorTable),
      size: (spec.imports.length + 1) * 20,
    });
  }

  // --- Exports ---
  if (spec.exports) {
    const e = spec.exports;
    const dirOff = alloc(40);
    const dllNameOff = putString(e.dllName);

    const addrTable = alloc(e.addresses.length * 4);
    e.addresses.forEach((a, i) => {
      // A forwarder's "value" is the RVA of a string that must land inside the
      // directory's declared range — that containment is what marks it as a
      // forwarder, so the string is allocated here, before the size is computed.
      const value = typeof a === "number" ? a : rvaOf(putString(a.forwarder));
      dv.setUint32(addrTable + i * 4, value, true);
    });

    const nameStringOffsets = e.names.map((n) => putString(n.name));
    const namePtrTable = alloc(e.names.length * 4);
    nameStringOffsets.forEach((o, i) => dv.setUint32(namePtrTable + i * 4, rvaOf(o), true));

    const ordinalTable = alloc(e.names.length * 2, 2);
    e.names.forEach((n, i) => dv.setUint16(ordinalTable + i * 2, n.addressIndex, true));

    dv.setUint32(dirOff + 12, rvaOf(dllNameOff), true); // Name
    dv.setUint32(dirOff + 16, e.ordinalBase ?? 1, true); // Base
    dv.setUint32(dirOff + 20, e.addresses.length, true); // NumberOfFunctions
    dv.setUint32(dirOff + 24, e.names.length, true); // NumberOfNames
    dv.setUint32(dirOff + 28, rvaOf(addrTable), true);
    dv.setUint32(dirOff + 32, rvaOf(namePtrTable), true);
    dv.setUint32(dirOff + 36, rvaOf(ordinalTable), true);

    // Real linkers size the export directory to span everything it owns — the
    // header, both tables and every string. Forwarder detection depends on that
    // extent, so cover the whole block rather than just the 40-byte header.
    dirs.set(IMAGE_DIRECTORY_ENTRY_EXPORT, {
      virtualAddress: rvaOf(dirOff),
      size: pos - dirOff,
    });
  }

  // --- TLS ---
  if (spec.tls) {
    const t = spec.tls;
    const callbacks = t.callbacks ?? [];
    let addressOfCallBacks = t.addressOfCallBacks ?? 0;
    if (t.addressOfCallBacks === undefined && callbacks.length > 0) {
      const cbOff = alloc((callbacks.length + 1) * ptrSize, ptrSize);
      callbacks.forEach((c, i) => writePtr(cbOff + i * ptrSize, c));
      addressOfCallBacks = imageBase + rvaOf(cbOff);
    }

    const structSize = is64 ? 40 : 24;
    const tlsOff = alloc(structSize, ptrSize);
    writePtr(tlsOff, t.startAddressOfRawData ?? 0);
    writePtr(tlsOff + ptrSize, t.endAddressOfRawData ?? 0);
    writePtr(tlsOff + ptrSize * 2, t.addressOfIndex ?? 0);
    writePtr(tlsOff + ptrSize * 3, addressOfCallBacks);
    dv.setUint32(tlsOff + ptrSize * 4, t.sizeOfZeroFill ?? 0, true);
    dv.setUint32(tlsOff + ptrSize * 4 + 4, t.characteristics ?? 0, true);

    dirs.set(IMAGE_DIRECTORY_ENTRY_TLS, { virtualAddress: rvaOf(tlsOff), size: structSize });
  }

  // --- Base relocations ---
  if (spec.relocations) {
    // Blocks must be byte-contiguous: the parser advances by each block's own
    // SizeOfBlock, so a padding gap would desynchronize the walk.
    const totalSize = spec.relocations.reduce((s, b) => s + 8 + b.entries.length * 2, 0);
    const relocOff = alloc(totalSize, 4);
    let p = relocOff;
    for (const block of spec.relocations) {
      const blockSize = 8 + block.entries.length * 2;
      dv.setUint32(p, block.virtualAddress, true);
      dv.setUint32(p + 4, blockSize, true);
      block.entries.forEach((en, i) => {
        dv.setUint16(p + 8 + i * 2, ((en.type & 0xf) << 12) | (en.offset & 0xfff), true);
      });
      p += blockSize;
    }
    dirs.set(IMAGE_DIRECTORY_ENTRY_BASERELOC, {
      virtualAddress: rvaOf(relocOff),
      size: totalSize,
    });
  }

  return { data: backing.subarray(0, Math.max(Math.ceil(pos / 4) * 4, 4)), dirs };
}

/**
 * Resolve the final section list and data directory table for a fixture,
 * appending the synthesized directory section when one was requested.
 * Explicit `dataDirectories` overrides win over synthesized entries.
 */
function resolveLayout(
  opts: PEFixtureOptions,
  is64: boolean,
  imageBase: number,
): { sections: SectionDef[]; dirs: Map<number, { virtualAddress: number; size: number }> } {
  const sections = [...(opts.sections ?? [defaultTextSection(0)])];
  const dirs = new Map(opts.dataDirectories ?? []);

  if (opts.directories) {
    const rva = opts.directoryRVA ?? 0x2000;
    const built = buildDirectorySection(opts.directories, { is64, imageBase, rva });
    sections.push({
      name: opts.directorySectionName ?? ".rdata",
      virtualAddress: rva,
      virtualSize: built.data.length,
      data: built.data,
      characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    });
    for (const [idx, dir] of built.dirs) {
      if (!dirs.has(idx)) dirs.set(idx, dir);
    }
  }

  return { sections, dirs };
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
  const { sections, dirs } = resolveLayout(opts, false, imageBase);
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
  view.setUint32(0x3c, peOffset, true); // e_lfanew

  // --- PE Signature ---
  view.setUint32(peOffset, IMAGE_NT_SIGNATURE, true); // "PE\0\0"

  // --- COFF Header ---
  view.setUint16(coffOffset, machine, true);
  view.setUint16(coffOffset + 2, numSections, true);
  view.setUint32(coffOffset + 4, 0, true); // timeDateStamp
  view.setUint32(coffOffset + 8, 0, true); // pointerToSymbolTable
  view.setUint32(coffOffset + 12, 0, true); // numberOfSymbols
  view.setUint16(coffOffset + 16, optionalHeaderSize, true);
  view.setUint16(coffOffset + 18, peCharacteristics, true);

  // --- Optional Header (PE32) ---
  const o = optionalHeaderOffset;
  view.setUint16(o, IMAGE_NT_OPTIONAL_HDR32_MAGIC, true); // magic
  view.setUint8(o + 2, 14); // majorLinkerVersion
  view.setUint8(o + 3, 0); // minorLinkerVersion
  view.setUint32(o + 4, 0, true); // sizeOfCode
  view.setUint32(o + 8, 0, true); // sizeOfInitializedData
  view.setUint32(o + 12, 0, true); // sizeOfUninitializedData
  view.setUint32(o + 16, entryPoint, true); // addressOfEntryPoint
  view.setUint32(o + 20, 0x1000, true); // baseOfCode
  view.setUint32(o + 24, 0, true); // baseOfData
  view.setUint32(o + 28, imageBase, true); // imageBase
  view.setUint32(o + 32, 0x1000, true); // sectionAlignment
  view.setUint32(o + 36, fileAlignment, true); // fileAlignment
  view.setUint32(o + 56, 0x10000, true); // sizeOfImage
  view.setUint32(o + 60, sectionDataStart, true); // sizeOfHeaders
  view.setUint32(o + 92, numDataDirs, true); // numberOfRvaAndSizes

  // --- Data Directories ---
  const dataDirOffset = o + 96;
  for (const [idx, dir] of dirs) {
    if (idx < numDataDirs) {
      const ddOff = dataDirOffset + idx * DATA_DIR_ENTRY_SIZE;
      view.setUint32(ddOff, dir.virtualAddress, true);
      view.setUint32(ddOff + 4, dir.size, true);
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

  const { sections, dirs } = resolveLayout(opts, true, imageBase);
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
  view.setUint32(0x3c, peOffset, true);

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
  const o = optionalHeaderOffset;
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
  for (const [idx, dir] of dirs) {
    if (idx < numDataDirs) {
      const ddOff = dataDirOffset + idx * DATA_DIR_ENTRY_SIZE;
      view.setUint32(ddOff, dir.virtualAddress, true);
      view.setUint32(ddOff + 4, dir.size, true);
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
