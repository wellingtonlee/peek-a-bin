import type { DataDirectory, SectionHeader, RuntimeFunction } from './types';
import { rvaToFileOffset } from './parser';

/**
 * Parse .pdata (Exception Directory) for x64 PE files.
 * Each RUNTIME_FUNCTION entry is 12 bytes: beginAddress (u32), endAddress (u32), unwindInfoAddress (u32).
 */
export function parsePdata(
  buffer: ArrayBuffer,
  exceptionDir: DataDirectory,
  sections: SectionHeader[],
): RuntimeFunction[] {
  if (!exceptionDir.virtualAddress || !exceptionDir.size) return [];

  const offset = rvaToFileOffset(exceptionDir.virtualAddress, sections);
  if (offset < 0) return [];

  const view = new DataView(buffer);
  const count = Math.floor(exceptionDir.size / 12);
  const results: RuntimeFunction[] = [];

  for (let i = 0; i < count; i++) {
    const entryOffset = offset + i * 12;
    if (entryOffset + 12 > view.byteLength) break;

    const beginAddress = view.getUint32(entryOffset, true);
    const endAddress = view.getUint32(entryOffset + 4, true);
    const unwindInfoAddress = view.getUint32(entryOffset + 8, true);

    // Validate: begin < end
    if (beginAddress >= endAddress) continue;

    results.push({ beginAddress, endAddress, unwindInfoAddress });
  }

  return results;
}
