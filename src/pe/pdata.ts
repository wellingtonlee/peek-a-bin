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

    const rf: RuntimeFunction = { beginAddress, endAddress, unwindInfoAddress };

    // Parse UNWIND_INFO to check for exception handler
    const unwindOffset = rvaToFileOffset(unwindInfoAddress, sections);
    if (unwindOffset >= 0 && unwindOffset + 4 <= view.byteLength) {
      const versionFlags = view.getUint8(unwindOffset);
      const flags = (versionFlags >> 3) & 0x1F;
      rf.handlerFlags = flags;

      // UNW_FLAG_EHANDLER (0x1) or UNW_FLAG_UHANDLER (0x2)
      if (flags & 0x3) {
        const countOfCodes = view.getUint8(unwindOffset + 2);
        // Handler RVA follows after the unwind codes (each 2 bytes), aligned to 4 bytes
        const codesSize = countOfCodes * 2;
        const handlerOffset = unwindOffset + 4 + codesSize + (codesSize % 4 ? (4 - codesSize % 4) : 0);
        if (handlerOffset + 4 <= view.byteLength) {
          rf.handlerAddress = view.getUint32(handlerOffset, true);
        }
      }
    }

    results.push(rf);
  }

  return results;
}
