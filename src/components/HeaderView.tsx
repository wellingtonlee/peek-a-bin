import { useState, useCallback } from "react";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import {
  MachineTypes as MACHINE_TYPES,
  SubsystemNames as SUBSYSTEM_NAMES,
  DataDirectoryNames as DATA_DIR_NAMES,
} from "../pe/constants";

const COFF_CHARACTERISTICS: Record<number, string> = {
  0x0001: "RELOCS_STRIPPED",
  0x0002: "EXECUTABLE_IMAGE",
  0x0004: "LINE_NUMS_STRIPPED",
  0x0008: "LOCAL_SYMS_STRIPPED",
  0x0020: "LARGE_ADDRESS_AWARE",
  0x0100: "32BIT_MACHINE",
  0x0200: "DEBUG_STRIPPED",
  0x0400: "REMOVABLE_RUN_FROM_SWAP",
  0x0800: "NET_RUN_FROM_SWAP",
  0x1000: "SYSTEM",
  0x2000: "DLL",
  0x4000: "UP_SYSTEM_ONLY",
};

const DLL_CHARACTERISTICS: Record<number, string> = {
  0x0020: "HIGH_ENTROPY_VA",
  0x0040: "DYNAMIC_BASE",
  0x0080: "FORCE_INTEGRITY",
  0x0100: "NX_COMPAT",
  0x0200: "NO_ISOLATION",
  0x0400: "NO_SEH",
  0x0800: "NO_BIND",
  0x1000: "APPCONTAINER",
  0x2000: "WDM_DRIVER",
  0x4000: "GUARD_CF",
  0x8000: "TERMINAL_SERVER_AWARE",
};

function decodeFlags(value: number, table: Record<number, string>): string[] {
  const flags: string[] = [];
  for (const [bit, name] of Object.entries(table)) {
    if (value & Number(bit)) flags.push(name);
  }
  return flags;
}

function FlagChips({ flags }: { flags: string[] }) {
  if (flags.length === 0) return <span className="text-gray-500">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {flags.map((f) => (
        <span key={f} className="px-1.5 py-0.5 rounded bg-gray-700 text-gray-300 text-[10px]">
          {f}
        </span>
      ))}
    </span>
  );
}

function CopyableHex({ value, width = 8 }: { value: number; width?: number }) {
  const [copied, setCopied] = useState(false);
  const hex = "0x" + (value >>> 0).toString(16).toUpperCase().padStart(width, "0");

  const handleClick = useCallback(() => {
    navigator.clipboard.writeText(hex).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 800);
    });
  }, [hex]);

  return (
    <span
      onClick={handleClick}
      className={`cursor-pointer hover:underline transition-colors ${
        copied ? "text-green-400" : "text-blue-400"
      }`}
      title="Click to copy"
    >
      {hex}
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
  const dispatch = useAppDispatch();
  if (!pe) return null;

  const { coffHeader: coff, optionalHeader: opt } = pe;
  const coffFlags = decodeFlags(coff.characteristics, COFF_CHARACTERISTICS);
  const dllFlags = decodeFlags(opt.dllCharacteristics, DLL_CHARACTERISTICS);
  const entryVA = opt.imageBase + opt.addressOfEntryPoint;

  const navigateToEntry = () => {
    dispatch({ type: "SET_ADDRESS", address: entryVA });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
  };

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
              <CopyableHex value={coff.machine} width={4} />{" "}
              <span className="text-gray-400">
                ({MACHINE_TYPES[coff.machine] ?? "Unknown"})
              </span>
            </Row>
            <Row label="Number of Sections">{coff.numberOfSections}</Row>
            <Row label="Timestamp">
              <CopyableHex value={coff.timeDateStamp} />{" "}
              <span className="text-gray-400">
                ({new Date(coff.timeDateStamp * 1000).toUTCString()})
              </span>
            </Row>
            <Row label="Size of Optional Header">{coff.sizeOfOptionalHeader}</Row>
            <Row label="Characteristics">
              <CopyableHex value={coff.characteristics} width={4} />
              <div className="mt-1">
                <FlagChips flags={coffFlags} />
              </div>
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
              <CopyableHex value={opt.magic} width={4} />{" "}
              <span className="text-gray-400">
                ({pe.is64 ? "PE32+" : "PE32"})
              </span>
            </Row>
            <Row label="Entry Point">
              <button
                onClick={navigateToEntry}
                className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
              >
                0x{entryVA.toString(16).toUpperCase().padStart(pe.is64 ? 16 : 8, "0")}
              </button>
              <span className="text-gray-500 ml-2">
                (RVA: <CopyableHex value={opt.addressOfEntryPoint} />)
              </span>
            </Row>
            <Row label="Image Base">
              <CopyableHex value={opt.imageBase} width={pe.is64 ? 16 : 8} />
            </Row>
            <Row label="Section Alignment">{opt.sectionAlignment}</Row>
            <Row label="File Alignment">{opt.fileAlignment}</Row>
            <Row label="Size of Image">
              <CopyableHex value={opt.sizeOfImage} />
            </Row>
            <Row label="Size of Headers">
              <CopyableHex value={opt.sizeOfHeaders} />
            </Row>
            <Row label="Checksum">
              <CopyableHex value={opt.checksum} />
            </Row>
            <Row label="Subsystem">
              {opt.subsystem}{" "}
              <span className="text-gray-400">
                ({SUBSYSTEM_NAMES[opt.subsystem] ?? "Unknown"})
              </span>
            </Row>
            <Row label="DLL Characteristics">
              <CopyableHex value={opt.dllCharacteristics} width={4} />
              <div className="mt-1">
                <FlagChips flags={dllFlags} />
              </div>
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
                  <CopyableHex value={dd.virtualAddress} />
                </td>
                <td className="py-1">
                  <CopyableHex value={dd.size} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
