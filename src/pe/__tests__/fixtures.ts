/**
 * PE test fixture builder.
 * Constructs minimal valid PE ArrayBuffers for testing.
 */

import {
  IMAGE_DIRECTORY_ENTRY_BASERELOC,
  IMAGE_DIRECTORY_ENTRY_DEBUG,
  IMAGE_DIRECTORY_ENTRY_EXPORT,
  IMAGE_DIRECTORY_ENTRY_IMPORT,
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
  IMAGE_DIRECTORY_ENTRY_SECURITY,
  IMAGE_DIRECTORY_ENTRY_TLS,
  IMAGE_DOS_SIGNATURE,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386,
  IMAGE_NT_OPTIONAL_HDR32_MAGIC,
  IMAGE_NT_OPTIONAL_HDR64_MAGIC,
  IMAGE_NT_SIGNATURE,
  IMAGE_ORDINAL_FLAG32,
  IMAGE_ORDINAL_FLAG64,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
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

/**
 * An `IMAGE_LOAD_CONFIG_DIRECTORY`, with each of the three sizes that bound a
 * read of it settable independently — that divergence is the whole point of the
 * structure's difficulty, so a fixture that cannot express it cannot test it.
 */
export interface LoadConfigDef {
  /**
   * Bytes actually emitted. Defaults to just past `CHPEMetadataPointer` (0xD0 on
   * PE32+, 0x80 on PE32); set it shorter to build the linker-truncated case.
   */
  bytes?: number;
  /** The structure's own `Size` field. Defaults to the emitted byte count. */
  declaredSize?: number;
  /** `Size` written into the data directory entry. Defaults to the emitted byte count. */
  directorySize?: number;
  /** Written at the CHPE offset, if the emitted structure is long enough to hold it. */
  chpeMetadataPointer?: number;
}

export interface RelocBlockDef {
  virtualAddress: number;
  entries: { type: number; offset: number }[];
}

/**
 * One `IMAGE_DEBUG_DIRECTORY` entry, and optionally the payload it points at.
 *
 * `PointerToRawData` is a **file offset**, not an RVA — the one field in this
 * whole builder that cannot be filled in while laying the directory section out,
 * because the section's own file offset is not decided until the outer builder
 * runs. It is emitted as a fixup instead; see {@link SectionFileFixup}.
 */
export interface DebugEntryDef {
  /** `IMAGE_DEBUG_TYPE_*`. 2 is CodeView, which is the only one with a payload. */
  type: number;
  timeDateStamp?: number;
  majorVersion?: number;
  minorVersion?: number;
  /**
   * An RSDS (CV_INFO_PDB70) payload: `"RSDS"`, the 16 GUID bytes verbatim, the
   * age, then a NUL-terminated PDB path.
   *
   * `guid` is written **in file order**, so a test can state the bytes the file
   * holds and the formatted string separately — which is the only way to see a
   * byte-order defect in the formatter, since the two are otherwise derived from
   * one another.
   */
  codeView?: { guid: Uint8Array; age: number; pdbPath: string };
  /** An opaque payload, for a type with no modelled shape. Ignored if `codeView` is set. */
  rawData?: Uint8Array;
}

/**
 * Real data directories to synthesize. Everything requested here is laid out
 * into one extra section and the matching data directory entries are filled in.
 */
export interface DirectorySpec {
  imports?: ImportLibraryDef[];
  exports?: ExportDirDef;
  tls?: TLSDef;
  loadConfig?: LoadConfigDef;
  relocations?: RelocBlockDef[];
  debug?: DebugEntryDef[];
}

/**
 * A `Rich` header — MSVC's undocumented build-provenance block, XOR-obfuscated
 * and sitting between the DOS stub and the PE signature.
 *
 * Requesting one **moves `e_lfanew`**: `parseRichHeader` only looks from 0x80
 * onwards, so the block cannot fit inside the 64-byte DOS header the builders
 * otherwise emit. Everything downstream is computed from `e_lfanew`, so nothing
 * else in the layout has to know.
 */
export interface RichHeaderDef {
  entries: { toolId: number; buildId: number; useCount: number }[];
  /** The key stored after the `Rich` marker; every dword before it is XORed with it. */
  xorKey?: number;
}

/**
 * An attribute certificate (`WIN_CERTIFICATE`) appended past the last section.
 *
 * The security data directory's first field is a **file offset**, not an RVA —
 * the one directory in the PE format that is not an RVA — so this is emitted
 * after the section bodies rather than inside one, and the directory entry is
 * filled in by the outer builder.
 */
export interface CertificateDef {
  /** `WIN_CERT_REVISION_2_0` by default. */
  revision?: number;
  /** `WIN_CERT_TYPE_PKCS_SIGNED_DATA` (2) by default. */
  certificateType?: number;
  /** Emitted verbatim as `bCertificate`, instead of the synthesized PKCS#7 blob. */
  raw?: Uint8Array;
  /** CommonName of the first certificate's subject / issuer. */
  subjectCN?: string;
  issuerCN?: string;
  /** DER `UTCTime` bodies, i.e. `YYMMDDHHMMSSZ`. */
  notBefore?: string;
  notAfter?: string;
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
  /** Emit a `Rich` header, which also moves `e_lfanew`. */
  richHeader?: RichHeaderDef;
  /** Append a `WIN_CERTIFICATE` past the last section and point directory 4 at it. */
  certificate?: CertificateDef;
}

/**
 * "Write `sectionFileOffset + addend` as a uint32 at `sectionFileOffset + at`."
 *
 * The escape hatch for the fields that hold a **file offset**: nothing inside
 * {@link buildDirectorySection} knows where its own section will land, so those
 * are recorded and applied once the outer builder has assigned raw-data
 * pointers. Both ends are section-relative, so the fixup is independent of the
 * layout it will be resolved against.
 */
interface SectionFileFixup {
  sectionIndex: number;
  at: number;
  addend: number;
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
): {
  data: Uint8Array;
  dirs: Map<number, { virtualAddress: number; size: number }>;
  fixups: { at: number; addend: number }[];
} {
  const { is64, imageBase, rva: baseRVA } = cfg;
  const backing = new Uint8Array(DIRECTORY_BLOB_SIZE);
  const dv = new DataView(backing.buffer);
  const dirs = new Map<number, { virtualAddress: number; size: number }>();
  const fixups: { at: number; addend: number }[] = [];
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

  // --- Load config ---
  if (spec.loadConfig) {
    const lc = spec.loadConfig;
    // The 32-bit and 64-bit structures put CHPEMetadataPointer in different
    // places and give it different widths; the fixture follows the same two
    // layouts the parser does rather than a widened copy of one of them.
    const chpeOffset = is64 ? 0xc8 : 0x7c;
    const chpeSize = is64 ? 8 : 4;
    const emitted = lc.bytes ?? chpeOffset + chpeSize;
    const lcOff = alloc(emitted, 8);
    if (emitted >= 4) dv.setUint32(lcOff, lc.declaredSize ?? emitted, true);
    if (lc.chpeMetadataPointer !== undefined && emitted >= chpeOffset + chpeSize) {
      // The field is pointer-width in both layouts, so this is the same write
      // `writePtr` does everywhere else.
      writePtr(lcOff + chpeOffset, lc.chpeMetadataPointer);
    }
    dirs.set(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, {
      virtualAddress: rvaOf(lcOff),
      size: lc.directorySize ?? emitted,
    });
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

  // --- Debug directory ---
  if (spec.debug) {
    const ENTRY = 28;
    const table = alloc(spec.debug.length * ENTRY);
    spec.debug.forEach((d, i) => {
      // Payloads are allocated first so the entry can name them; `alloc` is a
      // bump pointer, so an entry laid out after its own payload is fine.
      let payload: Uint8Array | null = null;
      if (d.codeView) {
        const cv = d.codeView;
        if (cv.guid.length !== 16) throw new Error("fixture CodeView GUID must be 16 bytes");
        payload = new Uint8Array(24 + cv.pdbPath.length + 1);
        const pv = new DataView(payload.buffer);
        pv.setUint32(0, 0x53445352, true); // "RSDS"
        payload.set(cv.guid, 4);
        pv.setUint32(20, cv.age, true);
        for (let j = 0; j < cv.pdbPath.length; j++) {
          payload[24 + j] = cv.pdbPath.charCodeAt(j);
        }
      } else if (d.rawData) {
        payload = d.rawData;
      }

      let payloadOff = 0;
      if (payload) {
        payloadOff = alloc(payload.length, 4);
        backing.set(payload, payloadOff);
      }

      const e = table + i * ENTRY;
      dv.setUint32(e + 4, d.timeDateStamp ?? 0, true);
      dv.setUint16(e + 8, d.majorVersion ?? 0, true);
      dv.setUint16(e + 10, d.minorVersion ?? 0, true);
      dv.setUint32(e + 12, d.type, true);
      dv.setUint32(e + 16, payload ? payload.length : 0, true); // SizeOfData
      if (payload) {
        dv.setUint32(e + 20, rvaOf(payloadOff), true); // AddressOfRawData (an RVA)
        // PointerToRawData is a FILE offset; see SectionFileFixup.
        fixups.push({ at: e + 24, addend: payloadOff });
      }
    });
    dirs.set(IMAGE_DIRECTORY_ENTRY_DEBUG, {
      virtualAddress: rvaOf(table),
      size: spec.debug.length * ENTRY,
    });
  }

  return { data: backing.subarray(0, Math.max(Math.ceil(pos / 4) * 4, 4)), dirs, fixups };
}

// --- Rich header ---

/**
 * The DOS header plus, optionally, a `Rich` block, and the `e_lfanew` that
 * follows it.
 *
 * The block is laid out exactly as `link.exe` writes it and exactly as
 * `parseRichHeader` reads it back: `DanS` and three zero dwords at 0x80, one
 * `(toolId<<16 | buildId, useCount)` pair per entry, then the literal `Rich`
 * marker and the key **unobfuscated**. Everything before the marker is XORed
 * with the key, which is what makes the marker findable by a plain byte scan
 * while nothing before it is.
 *
 * 0x80 is not decorative — `parseRichHeader` starts scanning there and refuses
 * to walk back below it, because the fixed 64-byte DOS header and the standard
 * DOS stub occupy everything under it in a real image.
 */
function buildDosStub(rich: RichHeaderDef | undefined): { bytes: Uint8Array; peOffset: number } {
  const DOS_HEADER_SIZE = 64;
  if (!rich) return { bytes: new Uint8Array(DOS_HEADER_SIZE), peOffset: DOS_HEADER_SIZE };

  const RICH_START = 0x80;
  const key = rich.xorKey ?? 0x5a4d3c2b;
  // DanS + 3 pad dwords + 2 dwords per entry + "Rich" + key.
  const blockDwords = 4 + rich.entries.length * 2 + 2;
  const end = RICH_START + blockDwords * 4;
  // Real linkers align the PE header that follows; 16 is what link.exe uses.
  const peOffset = Math.ceil(end / 16) * 16;

  const bytes = new Uint8Array(peOffset);
  const dv = new DataView(bytes.buffer);
  const put = (off: number, value: number) => dv.setUint32(off, value >>> 0, true);

  put(RICH_START, 0x536e6144 ^ key); // "DanS"
  put(RICH_START + 4, key); // 0 ^ key
  put(RICH_START + 8, key);
  put(RICH_START + 12, key);
  rich.entries.forEach((e, i) => {
    const at = RICH_START + 16 + i * 8;
    put(at, (((e.toolId & 0xffff) << 16) | (e.buildId & 0xffff)) ^ key);
    put(at + 4, e.useCount ^ key);
  });
  const markerAt = RICH_START + 16 + rich.entries.length * 8;
  bytes.set([0x52, 0x69, 0x63, 0x68], markerAt); // "Rich", in the clear
  put(markerAt + 4, key);

  return { bytes, peOffset };
}

// --- Authenticode ---

/** One DER element: a tag byte, a definite length, and the content. */
function der(tag: number, content: Uint8Array): Uint8Array {
  let header: number[];
  if (content.length < 0x80) header = [tag, content.length];
  else if (content.length < 0x100) header = [tag, 0x81, content.length];
  else header = [tag, 0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  const out = new Uint8Array(header.length + content.length);
  out.set(header, 0);
  out.set(content, header.length);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** `Name ::= SEQUENCE OF SET OF SEQUENCE { AttributeType, AttributeValue }` with one CN. */
function derName(cn: string): Uint8Array {
  const OID_CN = new Uint8Array([0x55, 0x04, 0x03]); // 2.5.4.3
  const attr = der(0x30, concat(der(0x06, OID_CN), der(0x13, ascii(cn))));
  return der(0x30, der(0x31, attr));
}

/**
 * A PKCS#7 SignedData blob with exactly the structure `authenticode.ts` walks:
 * ContentInfo → [0] → SignedData → [0] certificates → the first Certificate →
 * TBSCertificate → issuer / validity / subject.
 *
 * It is *shaped* like a signature and is not one — there is no digest and no
 * signature value, because nothing in this tool verifies either. What it does
 * carry is every field the panel prints, so the printed text can be asserted
 * against the bytes rather than against another copy of the same walk.
 */
function buildPKCS7(def: CertificateDef): Uint8Array {
  const subject = def.subjectCN ?? "Contoso Software";
  const issuer = def.issuerCN ?? "Contoso Root CA";
  const notBefore = def.notBefore ?? "230115090000Z";
  const notAfter = def.notAfter ?? "260115085959Z";

  // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption), used only as a placeholder
  // where the walk requires a SEQUENCE it does not read.
  const sigAlg = der(
    0x30,
    der(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])),
  );
  const version = der(0xa0, der(0x02, new Uint8Array([0x02]))); // [0] EXPLICIT v3
  const serial = der(0x02, new Uint8Array([0x10, 0x2a]));
  const validity = der(0x30, concat(der(0x17, ascii(notBefore)), der(0x17, ascii(notAfter))));
  const spki = der(0x30, concat(sigAlg, der(0x03, new Uint8Array([0x00, 0x01]))));

  const tbs = der(
    0x30,
    concat(version, serial, sigAlg, derName(issuer), validity, derName(subject), spki),
  );
  const certificate = der(0x30, concat(tbs, sigAlg, der(0x03, new Uint8Array([0x00, 0x01]))));

  const signedData = der(
    0x30,
    concat(
      der(0x02, new Uint8Array([0x01])), // version
      der(0x31, new Uint8Array(0)), // digestAlgorithms, empty
      der(0x30, der(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]))),
      der(0xa0, certificate), // [0] IMPLICIT certificates
    ),
  );

  // ContentInfo: SEQUENCE { OID 1.2.840.113549.1.7.2 signedData, [0] content }
  return der(
    0x30,
    concat(
      der(0x06, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02])),
      der(0xa0, signedData),
    ),
  );
}

/**
 * A `WIN_CERTIFICATE`: `dwLength`, `wRevision`, `wCertificateType`, then the
 * blob. `dwLength` counts the 8-byte header **and is not padded**, while the
 * entry itself is padded to an 8-byte boundary — a divergence real images have
 * and a reader can trip on, so the fixture reproduces it.
 */
function buildCertificateBlob(def: CertificateDef): Uint8Array {
  const body = def.raw ?? buildPKCS7(def);
  const dwLength = 8 + body.length;
  const padded = Math.ceil(dwLength / 8) * 8;
  const out = new Uint8Array(padded);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, dwLength, true);
  dv.setUint16(4, def.revision ?? 0x0200, true);
  dv.setUint16(6, def.certificateType ?? 0x0002, true);
  out.set(body, 8);
  return out;
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
): {
  sections: SectionDef[];
  dirs: Map<number, { virtualAddress: number; size: number }>;
  fixups: SectionFileFixup[];
} {
  const sections = [...(opts.sections ?? [defaultTextSection(0)])];
  const dirs = new Map(opts.dataDirectories ?? []);
  const fixups: SectionFileFixup[] = [];

  if (opts.directories) {
    const rva = opts.directoryRVA ?? 0x2000;
    const built = buildDirectorySection(opts.directories, { is64, imageBase, rva });
    const sectionIndex = sections.length;
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
    for (const f of built.fixups) fixups.push({ ...f, sectionIndex });
  }

  return { sections, dirs, fixups };
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

  // Layout offsets. A Rich header pushes `e_lfanew` out past 0x80, since that is
  // where `parseRichHeader` starts looking; with none, the 64-byte DOS header is
  // the whole of what precedes the PE signature. Everything below is derived
  // from `peOffset`, so nothing else has to know which of the two it got.
  const dosStub = buildDosStub(opts.richHeader);
  const peSignatureSize = 4;
  const coffHeaderSize = 20;

  const peOffset = dosStub.peOffset; // e_lfanew
  const coffOffset = peOffset + peSignatureSize;
  const optionalHeaderOffset = coffOffset + coffHeaderSize;
  const sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

  // Sections
  const { sections, dirs, fixups } = resolveLayout(opts, false, imageBase);
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

  // The attribute certificate sits past the last section, because the security
  // data directory's first field is a FILE OFFSET rather than an RVA — the one
  // directory in the format that is not an RVA. 8-byte aligned, as the spec
  // requires of every entry in the table.
  const cert = opts.certificate ? buildCertificateBlob(opts.certificate) : null;
  const certOffset = cert ? Math.ceil(currentFileOffset / 8) * 8 : 0;
  if (cert && !dirs.has(IMAGE_DIRECTORY_ENTRY_SECURITY)) {
    dirs.set(IMAGE_DIRECTORY_ENTRY_SECURITY, { virtualAddress: certOffset, size: cert.length });
  }

  const totalSize = cert ? certOffset + cert.length : currentFileOffset;
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // --- DOS Header (and the Rich block behind it, when there is one) ---
  bytes.set(dosStub.bytes, 0);
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

  // File-offset fields, which could not be filled in until raw-data pointers
  // were assigned. See SectionFileFixup.
  for (const f of fixups) {
    const base = sectionFileOffsets[f.sectionIndex];
    view.setUint32(base + f.at, base + f.addend, true);
  }

  if (cert) bytes.set(cert, certOffset);

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

  // See buildMinimalPE32 for why `e_lfanew` is not a constant.
  const dosStub = buildDosStub(opts.richHeader);
  const peSignatureSize = 4;
  const coffHeaderSize = 20;

  const peOffset = dosStub.peOffset;
  const coffOffset = peOffset + peSignatureSize;
  const optionalHeaderOffset = coffOffset + coffHeaderSize;
  const sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

  const { sections, dirs, fixups } = resolveLayout(opts, true, imageBase);
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

  // The attribute certificate sits past the last section, because the security
  // data directory's first field is a FILE OFFSET rather than an RVA — the one
  // directory in the format that is not an RVA. 8-byte aligned, as the spec
  // requires of every entry in the table.
  const cert = opts.certificate ? buildCertificateBlob(opts.certificate) : null;
  const certOffset = cert ? Math.ceil(currentFileOffset / 8) * 8 : 0;
  if (cert && !dirs.has(IMAGE_DIRECTORY_ENTRY_SECURITY)) {
    dirs.set(IMAGE_DIRECTORY_ENTRY_SECURITY, { virtualAddress: certOffset, size: cert.length });
  }

  const totalSize = cert ? certOffset + cert.length : currentFileOffset;
  const buffer = new ArrayBuffer(totalSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // --- DOS Header (and the Rich block behind it, when there is one) ---
  bytes.set(dosStub.bytes, 0);
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

  // File-offset fields, which could not be filled in until raw-data pointers
  // were assigned. See SectionFileFixup.
  for (const f of fixups) {
    const base = sectionFileOffsets[f.sectionIndex];
    view.setUint32(base + f.at, base + f.addend, true);
  }

  if (cert) bytes.set(cert, certOffset);

  return buffer;
}
