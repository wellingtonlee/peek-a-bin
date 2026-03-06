import type { DataItem } from "./types";

export function buildDataItems(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  strings: Map<number, string>,
  stringTypes: Map<number, "ascii" | "utf16le">,
  iatMap: Map<number, { lib: string; func: string }>,
  funcAddrs: Map<number, string>,
  sectionRanges: { start: number; end: number }[],
): DataItem[] {
  const items: DataItem[] = [];
  const ptrSize = is64 ? 8 : 4;
  let offset = 0;

  while (offset < bytes.length) {
    const addr = baseAddress + offset;

    // 1. String check
    const str = strings.get(addr);
    if (str !== undefined) {
      const sType = stringTypes.get(addr) ?? "ascii";
      const byteLen = sType === "utf16le" ? str.length * 2 + 2 : str.length + 1;
      const safeLen = Math.min(byteLen, bytes.length - offset);
      items.push({
        address: addr,
        directive: "db",
        size: safeLen,
        bytes: bytes.slice(offset, offset + safeLen),
        stringValue: str,
        stringType: sType,
      });
      offset += safeLen;
      continue;
    }

    // 2. Padding: runs of 0x00 or 0xCC >= 4 bytes
    const b = bytes[offset];
    if ((b === 0x00 || b === 0xcc) && offset + 3 < bytes.length) {
      let runLen = 1;
      while (offset + runLen < bytes.length && bytes[offset + runLen] === b) runLen++;
      if (runLen >= 4) {
        items.push({
          address: addr,
          directive: "dup",
          size: runLen,
          bytes: bytes.slice(offset, offset + Math.min(runLen, 8)),
          dupCount: runLen,
          dupByte: b,
        });
        offset += runLen;
        continue;
      }
    }

    // 3. Pointer: read 4/8 bytes, check if value falls in any section range
    if (offset + ptrSize <= bytes.length) {
      let val: number;
      if (is64) {
        const lo = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
        const hi = bytes[offset + 4] | (bytes[offset + 5] << 8) | (bytes[offset + 6] << 16) | (bytes[offset + 7] << 24);
        val = (hi >>> 0) * 0x100000000 + (lo >>> 0);
      } else {
        val = (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
      }

      let isPtr = false;
      for (const range of sectionRanges) {
        if (val >= range.start && val < range.end) {
          isPtr = true;
          break;
        }
      }

      if (isPtr) {
        let label: string | undefined;
        const iat = iatMap.get(val);
        if (iat) {
          label = `${iat.lib}!${iat.func}`;
        } else {
          const fname = funcAddrs.get(val);
          if (fname) {
            label = fname;
          } else {
            const s = strings.get(val);
            if (s) label = `"${s.length > 40 ? s.slice(0, 40) + "..." : s}"`;
          }
        }

        items.push({
          address: addr,
          directive: is64 ? "dq" : "dd",
          size: ptrSize,
          bytes: bytes.slice(offset, offset + ptrSize),
          pointerTarget: val,
          pointerLabel: label,
        });
        offset += ptrSize;
        continue;
      }
    }

    // 4. Default: emit db row with up to 16 raw bytes
    const remaining = bytes.length - offset;
    const chunkLen = Math.min(16, remaining);
    items.push({
      address: addr,
      directive: "db",
      size: chunkLen,
      bytes: bytes.slice(offset, offset + chunkLen),
    });
    offset += chunkLen;
  }

  return items;
}
