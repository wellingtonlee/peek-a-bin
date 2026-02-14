import { useMemo } from "react";

interface DataInspectorProps {
  offset: number;
  bytes: Uint8Array;
  baseAddress: number;
}

export function DataInspector({ offset, bytes, baseAddress }: DataInspectorProps) {
  const data = useMemo(() => {
    const remaining = bytes.length - offset;
    if (remaining <= 0) return null;

    const buf = bytes.buffer.slice(bytes.byteOffset + offset, bytes.byteOffset + offset + Math.min(remaining, 64));
    const view = new DataView(buf);
    const rows: { label: string; value: string }[] = [];

    // Int8
    rows.push({ label: "Int8", value: `${view.getInt8(0)} (u: ${view.getUint8(0)})` });

    // Int16 LE
    if (remaining >= 2) {
      rows.push({ label: "Int16 LE", value: `${view.getInt16(0, true)} (u: ${view.getUint16(0, true)})` });
    }

    // Int32 LE
    if (remaining >= 4) {
      rows.push({ label: "Int32 LE", value: `${view.getInt32(0, true)} (u: ${view.getUint32(0, true)})` });
    }

    // Float32 LE
    if (remaining >= 4) {
      const f = view.getFloat32(0, true);
      rows.push({ label: "Float32 LE", value: f.toPrecision(7) });
    }

    // Float64 LE
    if (remaining >= 8) {
      const d = view.getFloat64(0, true);
      rows.push({ label: "Float64 LE", value: d.toPrecision(15) });
    }

    // ASCII string
    const asciiChars: string[] = [];
    for (let i = 0; i < Math.min(remaining, 64); i++) {
      const b = bytes[offset + i];
      if (b >= 0x20 && b <= 0x7e) asciiChars.push(String.fromCharCode(b));
      else break;
    }
    if (asciiChars.length > 0) {
      rows.push({ label: "ASCII", value: `"${asciiChars.join("")}"` });
    }

    // UTF-16LE string
    if (remaining >= 2) {
      const utf16Chars: string[] = [];
      for (let i = 0; i < Math.min(remaining - 1, 64); i += 2) {
        const lo = bytes[offset + i];
        const hi = bytes[offset + i + 1];
        if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
          utf16Chars.push(String.fromCharCode(lo));
        } else {
          break;
        }
      }
      if (utf16Chars.length > 0) {
        rows.push({ label: "UTF-16LE", value: `"${utf16Chars.join("")}"` });
      }
    }

    return rows;
  }, [offset, bytes, baseAddress]);

  if (!data) return null;

  const va = baseAddress + offset;

  return (
    <div className="h-36 shrink-0 border-t border-gray-700 bg-gray-900/80 p-2 overflow-auto text-xs font-mono">
      <div className="text-gray-400 mb-1">
        Offset: 0x{offset.toString(16).toUpperCase()} (VA: 0x{va.toString(16).toUpperCase()})
      </div>
      <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5">
        {data.map((row) => (
          <div key={row.label} className="contents">
            <span className="text-gray-500">{row.label}</span>
            <span className="text-gray-200 truncate">{row.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
