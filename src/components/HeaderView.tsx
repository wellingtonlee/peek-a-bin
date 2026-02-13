import { useAppState } from "../hooks/usePEFile";
import {
  MachineTypes as MACHINE_TYPES,
  SubsystemNames as SUBSYSTEM_NAMES,
  DataDirectoryNames as DATA_DIR_NAMES,
} from "../pe/constants";

function HexVal({ value, width = 8 }: { value: number; width?: number }) {
  return (
    <span className="text-blue-400">
      0x{(value >>> 0).toString(16).toUpperCase().padStart(width, "0")}
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr className="border-b border-gray-800">
      <td className="py-1 pr-4 text-gray-400 whitespace-nowrap">{label}</td>
      <td className="py-1 text-gray-200">{children}</td>
    </tr>
  );
}

export function HeaderView() {
  const { peFile: pe } = useAppState();
  if (!pe) return null;

  const { coffHeader: coff, optionalHeader: opt } = pe;

  return (
    <div className="p-4 space-y-6 text-xs overflow-auto h-full">
      {/* COFF Header */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">
          COFF Header
        </h2>
        <table>
          <tbody>
            <Row label="Machine">
              <HexVal value={coff.machine} width={4} />{" "}
              <span className="text-gray-400">
                ({MACHINE_TYPES[coff.machine] ?? "Unknown"})
              </span>
            </Row>
            <Row label="Number of Sections">{coff.numberOfSections}</Row>
            <Row label="Timestamp">
              {new Date(coff.timeDateStamp * 1000).toUTCString()}
            </Row>
            <Row label="Size of Optional Header">{coff.sizeOfOptionalHeader}</Row>
            <Row label="Characteristics">
              <HexVal value={coff.characteristics} width={4} />
            </Row>
          </tbody>
        </table>
      </section>

      {/* Optional Header */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">
          Optional Header
        </h2>
        <table>
          <tbody>
            <Row label="Magic">
              <HexVal value={opt.magic} width={4} />{" "}
              <span className="text-gray-400">
                ({pe.is64 ? "PE32+" : "PE32"})
              </span>
            </Row>
            <Row label="Entry Point">
              <HexVal value={opt.addressOfEntryPoint} />
            </Row>
            <Row label="Image Base">
              <HexVal value={opt.imageBase} width={pe.is64 ? 16 : 8} />
            </Row>
            <Row label="Section Alignment">{opt.sectionAlignment}</Row>
            <Row label="File Alignment">{opt.fileAlignment}</Row>
            <Row label="Size of Image">
              <HexVal value={opt.sizeOfImage} />
            </Row>
            <Row label="Size of Headers">
              <HexVal value={opt.sizeOfHeaders} />
            </Row>
            <Row label="Checksum">
              <HexVal value={opt.checksum} />
            </Row>
            <Row label="Subsystem">
              {opt.subsystem}{" "}
              <span className="text-gray-400">
                ({SUBSYSTEM_NAMES[opt.subsystem] ?? "Unknown"})
              </span>
            </Row>
            <Row label="DLL Characteristics">
              <HexVal value={opt.dllCharacteristics} width={4} />
            </Row>
            <Row label="Number of RVA and Sizes">
              {opt.numberOfRvaAndSizes}
            </Row>
          </tbody>
        </table>
      </section>

      {/* Data Directories */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">
          Data Directories
        </h2>
        <table>
          <thead>
            <tr className="text-gray-400 border-b border-gray-700">
              <th className="text-left py-1 pr-6">#</th>
              <th className="text-left py-1 pr-6">Name</th>
              <th className="text-left py-1 pr-6">RVA</th>
              <th className="text-left py-1">Size</th>
            </tr>
          </thead>
          <tbody>
            {pe.dataDirectories.map((dd, i) => (
              <tr key={i} className="border-b border-gray-800">
                <td className="py-1 pr-6 text-gray-500">{i}</td>
                <td className="py-1 pr-6 text-gray-300">
                  {DATA_DIR_NAMES[i] ?? `Directory ${i}`}
                </td>
                <td className="py-1 pr-6">
                  <HexVal value={dd.virtualAddress} />
                </td>
                <td className="py-1">
                  <HexVal value={dd.size} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
