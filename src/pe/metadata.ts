import { parseOrdinalImport, resolveOrdinal } from "./ordinalTables";
import type { PEFile } from "./types";

// --- Rich Header ---

export interface RichEntry {
  toolId: number;
  buildId: number;
  useCount: number;
}

export function parseRichHeader(buffer: ArrayBuffer): RichEntry[] | null {
  const bytes = new Uint8Array(buffer);
  // Find "Rich" marker (52 69 63 68)
  let richOffset = -1;
  for (let i = 0x80; i < Math.min(bytes.length, 0x400); i++) {
    if (
      bytes[i] === 0x52 &&
      bytes[i + 1] === 0x69 &&
      bytes[i + 2] === 0x63 &&
      bytes[i + 3] === 0x68
    ) {
      richOffset = i;
      break;
    }
  }
  // The marker only counts if the 4-byte XOR key behind it is actually present:
  // a file ending in "Rich" otherwise threw a RangeError out of the read below,
  // and HeaderView calls this during render, so the whole tab went blank.
  if (richOffset < 0 || richOffset + 8 > bytes.length) return null;

  // XOR key follows "Rich"
  const view = new DataView(buffer);
  const xorKey = view.getUint32(richOffset + 4, true);

  // Find "DanS" marker by XOR-decoding backwards
  let dansOffset = -1;
  for (let i = richOffset - 4; i >= 0x80; i -= 4) {
    const val = view.getUint32(i, true) ^ xorKey;
    if (val === 0x536e6144) {
      // "DanS" little-endian
      dansOffset = i;
      break;
    }
  }
  if (dansOffset < 0) return null;

  // Decode entries (skip DanS + 3 padding dwords = 16 bytes)
  const entries: RichEntry[] = [];
  for (let i = dansOffset + 16; i + 8 <= richOffset; i += 8) {
    const compId = view.getUint32(i, true) ^ xorKey;
    const useCount = view.getUint32(i + 4, true) ^ xorKey;
    entries.push({
      toolId: (compId >> 16) & 0xffff,
      buildId: compId & 0xffff,
      useCount,
    });
  }
  return entries;
}

// --- Debug Directory ---

export interface DebugInfo {
  type: number;
  typeName: string;
  pdbPath?: string;
  guid?: string;
  age?: number;
}

const DEBUG_TYPE_NAMES: Record<number, string> = {
  0: "Unknown",
  1: "COFF",
  2: "CodeView",
  3: "FPO",
  4: "Misc",
  5: "Exception",
  6: "Fixup",
  9: "Borland",
  10: "BBT",
  11: "Clsid",
  12: "VC Feature",
  13: "POGO",
  14: "ILTCG",
  16: "Repro",
};

export function parseDebugDirectory(buffer: ArrayBuffer, pe: PEFile): DebugInfo[] {
  // Data directory index 6 = Debug
  if (pe.dataDirectories.length <= 6) return [];
  const debugDir = pe.dataDirectories[6];
  if (debugDir.virtualAddress === 0 || debugDir.size === 0) return [];

  // Convert RVA to file offset
  const debugRVA = debugDir.virtualAddress;
  let fileOffset = 0;
  for (const sec of pe.sections) {
    if (debugRVA >= sec.virtualAddress && debugRVA < sec.virtualAddress + sec.virtualSize) {
      fileOffset = sec.pointerToRawData + (debugRVA - sec.virtualAddress);
      break;
    }
  }
  if (fileOffset === 0) return [];

  const view = new DataView(buffer);
  const results: DebugInfo[] = [];
  const entrySize = 28;
  const numEntries = Math.floor(debugDir.size / entrySize);

  for (let i = 0; i < numEntries; i++) {
    const off = fileOffset + i * entrySize;
    if (off + entrySize > buffer.byteLength) break;
    const type = view.getUint32(off + 12, true);
    const pointerToRawData = view.getUint32(off + 24, true);
    const info: DebugInfo = {
      type,
      typeName: DEBUG_TYPE_NAMES[type] ?? `Type ${type}`,
    };

    // Parse CodeView (type 2) for PDB path
    if (type === 2 && pointerToRawData > 0 && pointerToRawData + 24 < buffer.byteLength) {
      const sig = view.getUint32(pointerToRawData, true);
      if (sig === 0x53445352) {
        // "RSDS"
        // GUID: 16 bytes at offset 4
        const guidBytes = new Uint8Array(buffer, pointerToRawData + 4, 16);
        const hex = Array.from(guidBytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        info.guid =
          `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`.toUpperCase();
        info.age = view.getUint32(pointerToRawData + 20, true);
        // PDB path: null-terminated string after age
        const pathStart = pointerToRawData + 24;
        let pathEnd = pathStart;
        const bytes = new Uint8Array(buffer);
        while (pathEnd < bytes.length && bytes[pathEnd] !== 0) pathEnd++;
        info.pdbPath = new TextDecoder().decode(bytes.slice(pathStart, pathEnd));
      }
    }

    results.push(info);
  }
  return results;
}

// --- Checksum Validation ---

export interface ChecksumResult {
  expected: number;
  actual: number;
  valid: boolean;
}

/**
 * A `Uint16Array` reads native-endian, so it only stands in for a run of
 * little-endian `getUint16` calls on a little-endian host. Every browser and
 * Node target is one, but a wrong checksum is silent, so this is checked rather
 * than assumed.
 */
const IS_LITTLE_ENDIAN = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;

/**
 * The checksum walk, taking only the two header fields it actually reads.
 *
 * Split out from {@link validateChecksum} so it can run in a worker: a whole
 * `PEFile` cannot be posted cheaply — it holds `buffer`, so cloning it would
 * copy the entire file *nested*, which is precisely what `workers/transfer.ts`
 * only avoids for top-level arguments. See `workers/metricsDispatch.ts`.
 *
 * @param peHeaderOffset `dosHeader.e_lfanew`
 * @param expected `optionalHeader.checksum`, the value stored in the image
 */
export function checksumFile(
  buffer: ArrayBuffer,
  peHeaderOffset: number,
  expected: number,
): ChecksumResult {
  const bytes = new Uint8Array(buffer);
  const limit = bytes.length;

  // Find checksum field offset in the file
  // PE signature at peHeaderOffset, COFF header = 4 + 20 bytes, then optional header
  // Checksum is at offset 64 within the optional header
  const checksumOffset = peHeaderOffset + 4 + 20 + 64;

  // One 16-bit word of the walk: a little-endian read, except at a trailing odd
  // byte where the absent high half reads as zero.
  const wordAt = (i: number): number => (i + 1 < limit ? bytes[i] | (bytes[i + 1] << 8) : bytes[i]);

  // Sum every word in the file, unfolded. This is the whole cost of the
  // function — a 50 MB image is 25M iterations on the main thread — so it stays
  // a bare accumulate over a typed array with no per-word branch or fold, in
  // four independent lanes so the adds do not serialise on one accumulator.
  // The accumulators cannot lose precision: 0xFFFF per word stays exact in a
  // double until ~1.4e11 words, i.e. a 274 GB file.
  let sum = 0;
  const wordCount = limit >>> 1;
  if (IS_LITTLE_ENDIAN) {
    const words = new Uint16Array(buffer, 0, wordCount);
    const quads = wordCount - (wordCount % 4);
    let s0 = 0;
    let s1 = 0;
    let s2 = 0;
    let s3 = 0;
    for (let i = 0; i < quads; i += 4) {
      s0 += words[i];
      s1 += words[i + 1];
      s2 += words[i + 2];
      s3 += words[i + 3];
    }
    sum = s0 + s1 + s2 + s3;
    for (let i = quads; i < wordCount; i++) sum += words[i];
  } else {
    for (let i = 0; i < wordCount; i++) sum += bytes[i * 2] | (bytes[i * 2 + 1] << 8);
  }
  if (limit & 1) sum += bytes[limit - 1];

  // A file does not checksum its own checksum field, so take those two words
  // back out. The walk only ever visited even offsets, so an image with an odd
  // e_lfanew never skipped anything and summed its own field — preserved here,
  // because the value this function writes back has to verify against itself.
  if ((checksumOffset & 1) === 0) {
    if (checksumOffset < limit) sum -= wordAt(checksumOffset);
    if (checksumOffset + 2 < limit) sum -= wordAt(checksumOffset + 2);
  }

  // Fold the carries. Folding after every word and folding once at the end give
  // the same answer: the fold is a reduction modulo 0xFFFF either way, and it
  // lands on 0 only when every word was 0, which is the one case where 0 and
  // 0xFFFF are not interchangeable.
  while (sum > 0xffff) sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  const actual = (sum + limit) >>> 0;

  return { expected, actual, valid: expected === 0 || expected === actual };
}

export function validateChecksum(buffer: ArrayBuffer, pe: PEFile): ChecksumResult {
  return checksumFile(buffer, pe.dosHeader.e_lfanew, pe.optionalHeader.checksum);
}

// --- Imphash (MD5-based) ---

/**
 * Minimal MD5 implementation (RFC 1321).
 *
 * Exported for testing: imphash is a hash nobody cross-checks at runtime, so a
 * wrong digest would look exactly like a right one. `metadata.test.ts` pins it
 * against the RFC 1321 vectors directly.
 */
export function md5(input: Uint8Array): string {
  const K = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  ]);
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  // Padding
  const bitLen = input.length * 8;
  const padLen = (56 - ((input.length + 1) % 64) + 64) % 64;
  const buf = new Uint8Array(input.length + 1 + padLen + 8);
  buf.set(input);
  buf[input.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 8, bitLen >>> 0, true);
  dv.setUint32(buf.length - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301 >>> 0;
  let b0 = 0xefcdab89 >>> 0;
  let c0 = 0x98badcfe >>> 0;
  let d0 = 0x10325476 >>> 0;

  const M = new Uint32Array(16);

  for (let off = 0; off < buf.length; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);

    let A = a0,
      B = b0,
      C = c0,
      D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) {
        F = (B & C) | ((~B >>> 0) & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | ((~D >>> 0) & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | (~D >>> 0));
        g = (7 * i) % 16;
      }

      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const result = new DataView(new ArrayBuffer(16));
  result.setUint32(0, a0, true);
  result.setUint32(4, b0, true);
  result.setUint32(8, c0, true);
  result.setUint32(12, d0, true);
  return Array.from(new Uint8Array(result.buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * pefile strips the extension only when it is one of these — `foo.exe` keeps
 * its extension, `foo.sys` does not. Matching that exactly is the whole point:
 * an imphash that disagrees with pefile cannot be looked up anywhere.
 */
const IMPHASH_STRIPPED_EXTENSIONS = new Set(["dll", "ocx", "sys"]);

export function computeImphash(imports: PEFile["imports"]): string {
  const parts: string[] = [];
  for (const imp of imports) {
    const lib = imp.libraryName.toLowerCase();
    const dot = lib.lastIndexOf(".");
    const libBase =
      dot > 0 && IMPHASH_STRIPPED_EXTENSIONS.has(lib.slice(dot + 1)) ? lib.slice(0, dot) : lib;
    for (const func of imp.functions) {
      // Is this an ordinal-only import? The question is asked through
      // `parseOrdinalImport` rather than by re-deriving the prefix here: the
      // spelling is a wire format written by `parsePE`, and the two sites
      // disagreeing is a silently different imphash (see ORDINAL_IMPORT_PREFIX).
      const ord = parseOrdinalImport(func);
      if (ord !== null) {
        const resolved = resolveOrdinal(lib, ord);
        // pefile renders an unresolved ordinal as "ord<N>"
        // (ordlookup.formatOrdString), never as this parser's "Ordinal_N".
        parts.push(`${libBase}.${resolved ? resolved.toLowerCase() : `ord${ord}`}`);
      } else if (func) {
        // pefile skips imports it could not name at all.
        parts.push(`${libBase}.${func.toLowerCase()}`);
      }
    }
  }
  if (parts.length === 0) return "";
  const str = parts.join(",");
  return md5(new TextEncoder().encode(str));
}

// --- Overlay Detection ---

export interface OverlayInfo {
  offset: number;
  size: number;
}

export function detectOverlay(buffer: ArrayBuffer, pe: PEFile): OverlayInfo | null {
  let maxEnd = 0;
  for (const sec of pe.sections) {
    const end = sec.pointerToRawData + sec.sizeOfRawData;
    if (end > maxEnd) maxEnd = end;
  }
  if (maxEnd < buffer.byteLength) {
    const size = buffer.byteLength - maxEnd;
    if (size > 0) return { offset: maxEnd, size };
  }
  return null;
}
