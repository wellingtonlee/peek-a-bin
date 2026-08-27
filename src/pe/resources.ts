import { rvaToFileOffset } from "./parser";
import { TRUNCATION_MARKER } from "./truncation";
import type { ResourceNode, ResourceTree, SectionHeader } from "./types";

const MAX_DEPTH = 4;

/**
 * Total directory entries the whole walk may process.
 *
 * The depth limit alone does not bound the work: a directory declares its own
 * entry count in two uint16s, so each one can claim 131070 children, and each
 * child can point at a *distinct* subdirectory offset that the `visited` set
 * cannot collapse. A 256 KB crafted .rsrc built that way exhausted a 4 GB heap
 * in under a minute — in the browser that is a dead tab. Real images use a few
 * thousand entries at most.
 */
export const MAX_TOTAL_ENTRIES = 65536;

/** Resource name strings are short in practice; anything longer is junk. */
const MAX_RESOURCE_STRING = 4096;

/**
 * The walk's entry allowance, and WHETHER THE WALK COVERED WHAT THE FILE
 * DECLARES.
 *
 * `incomplete` is not derivable from `remaining`. It used to be read as
 * `remaining > 0`, which is false in two different situations: the walk broke
 * out early (a truncation) and the walk consumed its very last allowed entry and
 * finished (not a truncation). A directory holding EXACTLY {@link
 * MAX_TOTAL_ENTRIES} entries therefore reported `truncated: true` over a
 * complete answer — the wrong direction for a flag whose whole job is to tell a
 * reader the tree they are looking at is short.
 *
 * IT WAS NAMED `stopped` AND THAT NAME COST THREE SITES. It reads as a fact
 * about the BUDGET, so three other places where the walk abandons entries the
 * file declares — an entry array running past the end of the buffer, a
 * subdirectory header past the end, a resource directory whose RVA resolves
 * nowhere — each broke out or returned early without touching it, and the tree
 * they produced was a short one wearing a complete one's shape. That is the
 * defect `ResourceTree.truncated` exists to prevent, reached by routes the flag
 * was not being set on. The field means exactly **"an entry the file declares
 * was not walked"**, whatever stopped the walk, which is the fact a reader needs
 * and the only one the flag can carry.
 *
 * TWO EARLY RETURNS IN {@link walkDirectory} DELIBERATELY DO NOT SET IT, and
 * they are marked at their sites: `depth >= MAX_DEPTH` and a repeat visit. Both
 * are judgements about a MALFORMED shape rather than about an unread entry, and
 * either could be argued the other way — they are left as filed rows rather than
 * swept in with the three that are unambiguous.
 */
interface Budget {
  remaining: number;
  incomplete: boolean;
}

/**
 * Read a UTF-16LE length-prefixed string from the resource section.
 * Format: uint16 length (in chars), then length * uint16 chars.
 *
 * A STRING THIS READER COULD NOT FINISH CARRIES {@link TRUNCATION_MARKER}, and
 * the marker is the WHOLE admission here — the asymmetry with `readCString` is
 * deliberate. That reader additionally marks its entry, so a truncated import
 * name can never reach `computeImphash`; nothing in this file feeds a digest, a
 * hash or any cross-tool comparison (a resource id goes through `ordinalLabel`
 * and a version-info key straight into `ExpandedLeaf`'s table, both printed
 * verbatim), so no refusal accompanies it.
 *
 * Truncation is decided EXACTLY, never by "we reached the bound": what was
 * collected is compared against the character count the string's own uint16
 * header declares, which covers the {@link MAX_RESOURCE_STRING} clip and the
 * buffer ending mid-string with one test. A string of exactly that length which
 * terminated properly is therefore not marked — `peek-a-bin-6qx9`'s off-by-one,
 * in the other reader.
 */
function readResourceString(view: DataView, offset: number): string {
  if (offset + 2 > view.byteLength) return "";
  const declared = view.getUint16(offset, true);
  const len = Math.min(declared, MAX_RESOURCE_STRING);
  const chars: number[] = [];
  for (let i = 0; i < len; i++) {
    const pos = offset + 2 + i * 2;
    if (pos + 2 > view.byteLength) break;
    chars.push(view.getUint16(pos, true));
  }
  // Spreading a 65535-element array into fromCharCode is at or over the
  // argument limit of some engines; the clamp above keeps this well under it.
  const text = String.fromCharCode(...chars);
  // ONE EXACT TEST FOR BOTH CAUSES. `declared` is the character count the
  // string's own header states, so falling short of it is the clip
  // ({@link MAX_RESOURCE_STRING}) *or* the buffer ending inside the string, and
  // reaching it exactly is a complete read either way.
  return chars.length < declared ? text + TRUNCATION_MARKER : text;
}

/**
 * Recursively walk IMAGE_RESOURCE_DIRECTORY structures.
 */
function walkDirectory(
  view: DataView,
  sectionBase: number,
  dirOffset: number,
  depth: number,
  visited: Set<number>,
  entries: ResourceTree["entries"],
  parentPath: (number | string)[],
  budget: Budget,
): ResourceNode[] {
  // NEITHER OF THESE TWO SETS `incomplete`, and that is a decision. Both are
  // properties of a MALFORMED tree rather than of an unread entry: a PE resource
  // directory is three levels by construction, so `MAX_DEPTH` is only reached by
  // a file that nests further than the format allows, and a repeat visit is a
  // cycle. The second has a real cost — a subdirectory legitimately shared by
  // two referrers is emptied for the second one — but calling that "the walk was
  // cut short" is arguable in a way the three sites below are not, so it is
  // filed rather than swept in here.
  if (depth >= MAX_DEPTH) return [];
  if (visited.has(dirOffset)) return [];
  visited.add(dirOffset);

  const absOffset = sectionBase + dirOffset;
  // The PARENT declared this subdirectory and the buffer does not hold its
  // header, so every entry under it is one the file declares and the walk did
  // not read.
  if (absOffset + 16 > view.byteLength) {
    budget.incomplete = true;
    return [];
  }

  // IMAGE_RESOURCE_DIRECTORY: 16 bytes
  const numberOfNamedEntries = view.getUint16(absOffset + 12, true);
  const numberOfIdEntries = view.getUint16(absOffset + 14, true);
  const totalEntries = numberOfNamedEntries + numberOfIdEntries;

  const nodes: ResourceNode[] = [];
  const entriesStart = absOffset + 16;

  for (let i = 0; i < totalEntries; i++) {
    if (budget.remaining <= 0) {
      budget.incomplete = true;
      break;
    }
    budget.remaining--;

    const entryOffset = entriesStart + i * 8;
    // The two uint16 counts read above are the FILE's claim about this
    // directory; the buffer ending inside the array leaves entries `i` onward
    // unwalked exactly as the budget running out does.
    if (entryOffset + 8 > view.byteLength) {
      budget.incomplete = true;
      break;
    }

    const nameOrId = view.getUint32(entryOffset, true);
    const offsetToData = view.getUint32(entryOffset + 4, true);

    // Resolve name or ID
    let id: number | string;
    if (nameOrId & 0x80000000) {
      // Name string: lower 31 bits = offset from section base
      const nameOffset = nameOrId & 0x7fffffff;
      id = readResourceString(view, sectionBase + nameOffset);
    } else {
      id = nameOrId;
    }

    const node: ResourceNode = { id };
    const currentPath = [...parentPath, id];

    if (offsetToData & 0x80000000) {
      // Subdirectory: lower 31 bits = offset from section base
      const subDirOffset = offsetToData & 0x7fffffff;
      node.children = walkDirectory(
        view,
        sectionBase,
        subDirOffset,
        depth + 1,
        visited,
        entries,
        currentPath,
        budget,
      );
    } else {
      // Leaf: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
      const dataEntryOffset = sectionBase + offsetToData;
      if (dataEntryOffset + 16 <= view.byteLength) {
        const dataRva = view.getUint32(dataEntryOffset, true);
        const size = view.getUint32(dataEntryOffset + 4, true);
        const codePage = view.getUint32(dataEntryOffset + 8, true);
        node.dataEntry = { rva: dataRva, size, codePage };

        // Flatten into entries: type (level 0), name (level 1), lang (level 2)
        entries.push({
          type: currentPath[0] ?? 0,
          name: currentPath[1] ?? 0,
          // A NAME AT THE LANGUAGE LEVEL IS CARRIED, NOT FLATTENED TO ZERO.
          // This used to read `typeof … === "number" ? … : 0`, so a third-level
          // entry identified by a name string became `lang: 0` — and 0 is a real
          // LANGID (neutral), so the narrower answer wore a complete one's shape
          // and two named languages of one resource rendered as two rows both
          // claiming language 0, separable only by RVA.
          //
          // `?? 0` is the same spelling the two levels above use, and for the
          // same reason: the fallback is for a leaf that sits SHALLOWER than
          // this level, which is the only case with no id to carry.
          lang: currentPath[2] ?? 0,
          rva: dataRva,
          size,
        });
      }
    }

    nodes.push(node);
  }

  return nodes;
}

/**
 * Parse the PE resource directory tree.
 */
export function parseResourceDirectory(
  buffer: ArrayBuffer,
  resourceDir: { virtualAddress: number; size: number },
  sections: SectionHeader[],
): ResourceTree {
  // A RESOURCE DIRECTORY THE SECTION TABLE CANNOT PLACE IS NOT AN ABSENT ONE.
  // `parsePE` only calls this when the data directory has a non-zero RVA and a
  // non-zero size, so reaching here means the file declares resources and names
  // an address no section holds. Answering a bare empty tree made that
  // indistinguishable from a PE with no resource directory at all, which is the
  // sentence `ResourcesView` prints — a positive claim about the file rather
  // than a narrow one.
  const fileOffset = rvaToFileOffset(resourceDir.virtualAddress, sections);
  if (fileOffset < 0) return { root: [], entries: [], truncated: true };

  const view = new DataView(buffer);
  const entries: ResourceTree["entries"] = [];
  const visited = new Set<number>();
  const budget: Budget = { remaining: MAX_TOTAL_ENTRIES, incomplete: false };

  const root = walkDirectory(view, fileOffset, 0, 0, visited, entries, [], budget);
  return budget.incomplete ? { root, entries, truncated: true } : { root, entries };
}

/**
 * Parse VS_VERSIONINFO structure to extract version string key-value pairs.
 */
export function parseVersionInfo(
  buffer: ArrayBuffer,
  dataRva: number,
  size: number,
  sections: SectionHeader[],
): Record<string, string> {
  const offset = rvaToFileOffset(dataRva, sections);
  if (offset < 0 || size === 0) return {};

  const view = new DataView(buffer);
  const result: Record<string, string> = {};
  const end = Math.min(offset + size, view.byteLength);

  // Helper: read UTF-16LE null-terminated string
  function readWString(pos: number): { str: string; end: number } {
    const chars: number[] = [];
    let dropped = false;
    let p = pos;
    while (p + 2 <= end) {
      const ch = view.getUint16(p, true);
      p += 2;
      if (ch === 0) break;
      // Keep scanning for the terminator so `end` stays right, but stop
      // collecting: an unterminated string spanning a large version resource
      // would otherwise spread hundreds of thousands of arguments into
      // fromCharCode and blow the call stack.
      //
      // `dropped` is the admission, and it is recorded HERE rather than inferred
      // from `chars.length` afterwards: a value of exactly
      // {@link MAX_RESOURCE_STRING} characters that terminated properly is a
      // complete read, and the two are indistinguishable by length alone.
      if (chars.length < MAX_RESOURCE_STRING) chars.push(ch);
      else dropped = true;
    }
    const str = String.fromCharCode(...chars);
    // `end` is deliberately unchanged by the marker: it is a FILE POSITION the
    // caller's walk continues from, and the marker is text for a reader.
    return { str: dropped ? str + TRUNCATION_MARKER : str, end: p };
  }

  // DWORD align
  function align4(pos: number): number {
    return (pos + 3) & ~3;
  }

  try {
    // VS_VERSIONINFO header
    if (offset + 6 > end) return result;
    const viLength = view.getUint16(offset, true);
    const viValueLength = view.getUint16(offset + 2, true);
    // wType at offset+4
    const viEnd = Math.min(offset + viLength, end);

    // szKey: "VS_VERSION_INFO\0"
    const keyResult = readWString(offset + 6);
    if (keyResult.str !== "VS_VERSION_INFO") return result;

    let pos = align4(keyResult.end);

    // VS_FIXEDFILEINFO (52 bytes) if viValueLength > 0
    if (viValueLength >= 52 && pos + 52 <= viEnd) {
      const sig = view.getUint32(pos, true);
      if (sig === 0xfeef04bd) {
        // Extract FileVersion from dwFileVersionMS / dwFileVersionLS
        const fileVerMS = view.getUint32(pos + 8, true);
        const fileVerLS = view.getUint32(pos + 12, true);
        result.FileVersion = `${(fileVerMS >>> 16) & 0xffff}.${fileVerMS & 0xffff}.${(fileVerLS >>> 16) & 0xffff}.${fileVerLS & 0xffff}`;

        // Extract ProductVersion from dwProductVersionMS / dwProductVersionLS
        const prodVerMS = view.getUint32(pos + 16, true);
        const prodVerLS = view.getUint32(pos + 20, true);
        result.ProductVersion = `${(prodVerMS >>> 16) & 0xffff}.${prodVerMS & 0xffff}.${(prodVerLS >>> 16) & 0xffff}.${prodVerLS & 0xffff}`;
      }
      pos += viValueLength;
    }

    pos = align4(pos);

    // Walk children (StringFileInfo, VarFileInfo)
    while (pos + 6 < viEnd) {
      const childLength = view.getUint16(pos, true);
      if (childLength === 0) break;
      const childEnd = Math.min(pos + childLength, viEnd);
      // skip wValueLength, wType
      const childKey = readWString(pos + 6);

      if (childKey.str === "StringFileInfo") {
        // Walk StringTable children
        let stPos = align4(childKey.end);
        while (stPos + 6 < childEnd) {
          const stLength = view.getUint16(stPos, true);
          if (stLength === 0) break;
          const stEnd = Math.min(stPos + stLength, childEnd);
          // skip wValueLength, wType, read szKey (language-codepage)
          const stKey = readWString(stPos + 6);
          let strPos = align4(stKey.end);

          // Walk String entries
          while (strPos + 6 < stEnd) {
            const sLength = view.getUint16(strPos, true);
            if (sLength === 0) break;
            const sEnd = Math.min(strPos + sLength, stEnd);
            const sValueLength = view.getUint16(strPos + 2, true);
            // wType at strPos+4
            const sKey = readWString(strPos + 6);
            const valPos = align4(sKey.end);

            if (sValueLength > 0 && valPos + 2 <= sEnd) {
              const val = readWString(valPos);
              if (sKey.str) {
                result[sKey.str] = val.str;
              }
            }

            strPos = align4(sEnd);
          }

          stPos = align4(stEnd);
        }
      }

      pos = align4(childEnd);
    }
  } catch {
    // Malformed version info — return what we have
  }

  return result;
}

/**
 * Reconstruct a .ico file from a GROUP_ICON resource and individual icon entries.
 */
export function reconstructIcon(
  buffer: ArrayBuffer,
  groupIconData: ArrayBuffer,
  iconEntries: Map<number, { rva: number; size: number }>,
  sections: SectionHeader[],
): Uint8Array | null {
  try {
    const gView = new DataView(groupIconData);
    if (groupIconData.byteLength < 6) return null;

    const reserved = gView.getUint16(0, true);
    const type = gView.getUint16(2, true);
    const count = gView.getUint16(4, true);

    if (type !== 1 || count === 0) return null;

    // Each GRPICONDIRENTRY is 14 bytes
    if (6 + count * 14 > groupIconData.byteLength) return null;

    // Collect icon data
    const iconDataParts: { entry: DataView; data: Uint8Array }[] = [];
    let totalIconDataSize = 0;

    for (let i = 0; i < count; i++) {
      const entryOffset = 6 + i * 14;
      const id = gView.getUint16(entryOffset + 12, true);
      const iconInfo = iconEntries.get(id);
      if (!iconInfo) continue;

      const fileOff = rvaToFileOffset(iconInfo.rva, sections);
      if (fileOff < 0 || fileOff + iconInfo.size > buffer.byteLength) continue;

      iconDataParts.push({
        entry: new DataView(groupIconData, entryOffset, 14),
        data: new Uint8Array(buffer, fileOff, iconInfo.size),
      });
      totalIconDataSize += iconInfo.size;
    }

    if (iconDataParts.length === 0) return null;

    // Build .ico: ICONDIR (6) + ICONDIRENTRY * count (16 each) + icon data
    const headerSize = 6 + iconDataParts.length * 16;
    const icoFile = new Uint8Array(headerSize + totalIconDataSize);
    const icoView = new DataView(icoFile.buffer);

    // ICONDIR
    icoView.setUint16(0, reserved, true);
    icoView.setUint16(2, type, true);
    icoView.setUint16(4, iconDataParts.length, true);

    let dataOffset = headerSize;
    for (let i = 0; i < iconDataParts.length; i++) {
      const { entry, data } = iconDataParts[i];
      const dirOffset = 6 + i * 16;

      // Copy first 12 bytes of GRPICONDIRENTRY (width, height, colorCount, reserved, planes, bitCount, bytesInRes)
      for (let b = 0; b < 12; b++) {
        icoFile[dirOffset + b] = entry.getUint8(b);
      }
      // dwImageOffset (4 bytes) instead of nId (2 bytes)
      icoView.setUint32(dirOffset + 12, dataOffset, true);

      // Copy icon data
      icoFile.set(data, dataOffset);
      dataOffset += data.byteLength;
    }

    return icoFile;
  } catch {
    return null;
  }
}
