import type { SectionHeader, ResourceTree, ResourceNode } from './types';
import { rvaToFileOffset } from './parser';

const MAX_DEPTH = 4;

/**
 * Read a UTF-16LE length-prefixed string from the resource section.
 * Format: uint16 length (in chars), then length * uint16 chars.
 */
function readResourceString(view: DataView, offset: number): string {
  if (offset + 2 > view.byteLength) return '';
  const len = view.getUint16(offset, true);
  const chars: number[] = [];
  for (let i = 0; i < len; i++) {
    const pos = offset + 2 + i * 2;
    if (pos + 2 > view.byteLength) break;
    chars.push(view.getUint16(pos, true));
  }
  return String.fromCharCode(...chars);
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
  entries: ResourceTree['entries'],
  parentPath: (number | string)[],
): ResourceNode[] {
  if (depth >= MAX_DEPTH) return [];
  if (visited.has(dirOffset)) return [];
  visited.add(dirOffset);

  const absOffset = sectionBase + dirOffset;
  if (absOffset + 16 > view.byteLength) return [];

  // IMAGE_RESOURCE_DIRECTORY: 16 bytes
  const numberOfNamedEntries = view.getUint16(absOffset + 12, true);
  const numberOfIdEntries = view.getUint16(absOffset + 14, true);
  const totalEntries = numberOfNamedEntries + numberOfIdEntries;

  const nodes: ResourceNode[] = [];
  const entriesStart = absOffset + 16;

  for (let i = 0; i < totalEntries; i++) {
    const entryOffset = entriesStart + i * 8;
    if (entryOffset + 8 > view.byteLength) break;

    const nameOrId = view.getUint32(entryOffset, true);
    const offsetToData = view.getUint32(entryOffset + 4, true);

    // Resolve name or ID
    let id: number | string;
    if (nameOrId & 0x80000000) {
      // Name string: lower 31 bits = offset from section base
      const nameOffset = nameOrId & 0x7FFFFFFF;
      id = readResourceString(view, sectionBase + nameOffset);
    } else {
      id = nameOrId;
    }

    const node: ResourceNode = { id };
    const currentPath = [...parentPath, id];

    if (offsetToData & 0x80000000) {
      // Subdirectory: lower 31 bits = offset from section base
      const subDirOffset = offsetToData & 0x7FFFFFFF;
      node.children = walkDirectory(
        view, sectionBase, subDirOffset, depth + 1, visited, entries, currentPath,
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
          lang: typeof currentPath[2] === 'number' ? currentPath[2] : 0,
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
  const fileOffset = rvaToFileOffset(resourceDir.virtualAddress, sections);
  if (fileOffset < 0) return { root: [], entries: [] };

  const view = new DataView(buffer);
  const entries: ResourceTree['entries'] = [];
  const visited = new Set<number>();

  const root = walkDirectory(view, fileOffset, 0, 0, visited, entries, []);
  return { root, entries };
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
    let p = pos;
    while (p + 2 <= end) {
      const ch = view.getUint16(p, true);
      p += 2;
      if (ch === 0) break;
      chars.push(ch);
    }
    return { str: String.fromCharCode(...chars), end: p };
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
    if (keyResult.str !== 'VS_VERSION_INFO') return result;

    let pos = align4(keyResult.end);

    // VS_FIXEDFILEINFO (52 bytes) if viValueLength > 0
    if (viValueLength >= 52 && pos + 52 <= viEnd) {
      const sig = view.getUint32(pos, true);
      if (sig === 0xFEEF04BD) {
        // Extract FileVersion from dwFileVersionMS / dwFileVersionLS
        const fileVerMS = view.getUint32(pos + 8, true);
        const fileVerLS = view.getUint32(pos + 12, true);
        result['FileVersion'] = `${(fileVerMS >>> 16) & 0xFFFF}.${fileVerMS & 0xFFFF}.${(fileVerLS >>> 16) & 0xFFFF}.${fileVerLS & 0xFFFF}`;

        // Extract ProductVersion from dwProductVersionMS / dwProductVersionLS
        const prodVerMS = view.getUint32(pos + 16, true);
        const prodVerLS = view.getUint32(pos + 20, true);
        result['ProductVersion'] = `${(prodVerMS >>> 16) & 0xFFFF}.${prodVerMS & 0xFFFF}.${(prodVerLS >>> 16) & 0xFFFF}.${prodVerLS & 0xFFFF}`;
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

      if (childKey.str === 'StringFileInfo') {
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
            let valPos = align4(sKey.end);

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
