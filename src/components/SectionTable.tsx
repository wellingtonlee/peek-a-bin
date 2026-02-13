import { useAppState } from "../hooks/usePEFile";
import { sectionCharacteristicsToString } from "../pe/constants";

export function SectionTable() {
  const { peFile: pe } = useAppState();
  if (!pe) return null;

  return (
    <div className="p-4 text-xs overflow-auto h-full">
      <h2 className="text-sm font-semibold text-gray-200 mb-3">
        Section Table
      </h2>
      <table className="w-full">
        <thead>
          <tr className="text-gray-400 border-b border-gray-700">
            <th className="text-left py-2 pr-4">Name</th>
            <th className="text-left py-2 pr-4">Virtual Size</th>
            <th className="text-left py-2 pr-4">Virtual Address</th>
            <th className="text-left py-2 pr-4">Raw Size</th>
            <th className="text-left py-2 pr-4">Raw Offset</th>
            <th className="text-left py-2">Characteristics</th>
          </tr>
        </thead>
        <tbody>
          {pe.sections.map((sec, i) => (
            <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50">
              <td className="py-2 pr-4 text-gray-200 font-semibold">
                {sec.name}
              </td>
              <td className="py-2 pr-4 text-blue-400">
                0x{(sec.virtualSize >>> 0).toString(16).toUpperCase()}
              </td>
              <td className="py-2 pr-4 text-blue-400">
                0x{(sec.virtualAddress >>> 0).toString(16).toUpperCase()}
              </td>
              <td className="py-2 pr-4 text-blue-400">
                0x{(sec.sizeOfRawData >>> 0).toString(16).toUpperCase()}
              </td>
              <td className="py-2 pr-4 text-blue-400">
                0x{(sec.pointerToRawData >>> 0).toString(16).toUpperCase()}
              </td>
              <td className="py-2 text-gray-400">
                <span className="text-blue-400">
                  0x{(sec.characteristics >>> 0).toString(16).toUpperCase()}
                </span>{" "}
                {sectionCharacteristicsToString(sec.characteristics)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
