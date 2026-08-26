import { useCallback, useMemo, useState } from "react";
import { useFileMetrics } from "../hooks/useFileMetrics";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import {
  DataDirectoryNames as DATA_DIR_NAMES,
  IMAGE_DIRECTORY_ENTRY_SECURITY,
  MachineTypes as MACHINE_TYPES,
  RelocTypeNames as RELOC_TYPE_NAMES,
  SubsystemNames as SUBSYSTEM_NAMES,
} from "../pe/constants";
import { dataDirectoryClamp } from "../pe/dataDirectories";
import {
  computeImphash,
  detectOverlay,
  parseDebugDirectory,
  parseRichHeader,
} from "../pe/metadata";
import { COPY_FAILED_TITLE, copyText } from "../utils/clipboard";

/**
 * Every COFF characteristic the PE format names.
 *
 * The four deprecated bits — 0x0010 AGGRESSIVE_WS_TRIM, 0x0080 BYTES_REVERSED_LO
 * and 0x8000 BYTES_REVERSED_HI, which Windows no longer honours — were missing,
 * so a file setting one rendered no chip for it and said nothing about the
 * omission. Deprecated is not unnamed: a reader asking what this word claims is
 * asking about the file, and "the OS ignores this bit" is a different answer
 * from silence. 0x0040 is genuinely reserved and has no name in the format, so
 * no table can ever be complete here — which is what {@link decodeFlags}'
 * leftover mask is for.
 */
const COFF_CHARACTERISTICS: Record<number, string> = {
  0x0001: "RELOCS_STRIPPED",
  0x0002: "EXECUTABLE_IMAGE",
  0x0004: "LINE_NUMS_STRIPPED",
  0x0008: "LOCAL_SYMS_STRIPPED",
  0x0010: "AGGRESSIVE_WS_TRIM",
  0x0020: "LARGE_ADDRESS_AWARE",
  0x0080: "BYTES_REVERSED_LO",
  0x0100: "32BIT_MACHINE",
  0x0200: "DEBUG_STRIPPED",
  0x0400: "REMOVABLE_RUN_FROM_SWAP",
  0x0800: "NET_RUN_FROM_SWAP",
  0x1000: "SYSTEM",
  0x2000: "DLL",
  0x4000: "UP_SYSTEM_ONLY",
  0x8000: "BYTES_REVERSED_HI",
};

/** The three optional-header magics the PE format defines. */
const OPTIONAL_HEADER_MAGIC: Record<number, string> = {
  0x010b: "PE32",
  0x0107: "ROM",
  0x020b: "PE32+",
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

/**
 * The named bits set in `value`, and — the second return — the bits that are set
 * and that the table does not name.
 *
 * The leftover mask is the whole point of the shape change. Both flag rows used
 * to drop an unnamed bit on the floor: `0x0040` in a COFF characteristics word
 * rendered exactly the same chips as `0x0000` beside it would, so the panel
 * silently claimed the file set nothing it did not recognise. The two rows that
 * decode a *scalar* — Machine and Subsystem — have always admitted an unmapped
 * value with `(Unknown)`, and this is the same admission for a bit field. It
 * cannot be closed by completing the table instead: 0x0040 is reserved by the
 * format and has no name to give it.
 */
function decodeFlags(
  value: number,
  table: Record<number, string>,
): { flags: string[]; unknown: number } {
  const flags: string[] = [];
  let unknown = value;
  for (const [bit, name] of Object.entries(table)) {
    if (value & Number(bit)) flags.push(name);
    unknown &= ~Number(bit);
  }
  // `>>> 0` because `&= ~bit` works on int32 and the top bit would otherwise
  // print as a negative number. Every flag word here is 16 bits, so nothing is
  // truncated by it — contrast `CopyableHex`, where the same spelling on a
  // 64-bit ImageBase was a defect.
  return { flags, unknown: unknown >>> 0 };
}

function FlagChips({ flags, unknown }: { flags: string[]; unknown: number }) {
  if (flags.length === 0 && unknown === 0) return <span className="text-gray-500">none</span>;
  return (
    <span className="flex flex-wrap gap-1 items-center">
      {flags.map((f) => (
        <span key={f} className="px-1.5 py-0.5 rounded bg-gray-700 text-gray-300 text-[10px]">
          {f}
        </span>
      ))}
      {unknown !== 0 && (
        // Deliberately NOT a chip: a chip is this panel's spelling for "the
        // format names this bit and the file set it", and the whole statement
        // here is that it does not. `chips()` in the suite reads
        // `span.rounded`, so an admission wearing a chip's clothes would also
        // start showing up in every flag-list assertion.
        <span
          className="text-gray-400 text-[10px]"
          title="Bits the PE format does not name are set in this word. Reserved bits are normally zero."
        >
          (unknown bits: 0x{unknown.toString(16).toUpperCase().padStart(4, "0")})
        </span>
      )}
    </span>
  );
}

/**
 * A hex value that copies itself on click.
 *
 * `flash` is three-valued rather than the boolean it was: the copy used to be
 * `navigator.clipboard.writeText(hex).then(() => setCopied(true))`, which on a
 * non-secure context (plain `http:` off localhost) threw at the property
 * access, and on a denied permission would have rejected with nothing catching
 * it. Either way the tick was a claim about a copy that had not happened. See
 * `utils/clipboard.ts`.
 */
function CopyableHex({ value, width = 8 }: { value: number; width?: number }) {
  const [flash, setFlash] = useState<"idle" | "ok" | "failed">("idle");
  // `>>> 0` is how a value read as a signed int32 is respelled unsigned — but it
  // is ToUint32, so it also truncates MODULO 2^32, and this component is handed
  // 64-bit quantities: a PE32+ `ImageBase` is 0x140000000 for an MSVC x64 EXE
  // and 0x180000000 for a DLL, and every TLS field below is an image-based VA.
  // Unconditionally, the panel printed `Image Base 0x0000000140000000` as
  // `0x0000000040000000`, two rows under an Entry Point of 0x140001000 it had
  // spelled correctly — self-contradictory on essentially every 64-bit binary.
  // Reinterpret only what is actually negative, which is the one case `>>> 0`
  // was there for.
  const hex =
    "0x" + (value < 0 ? value >>> 0 : value).toString(16).toUpperCase().padStart(width, "0");

  const handleClick = useCallback(async () => {
    const ok = await copyText(hex);
    setFlash(ok ? "ok" : "failed");
    setTimeout(() => setFlash("idle"), 800);
  }, [hex]);

  return (
    <button
      type="button"
      onClick={handleClick}
      className={`inline cursor-pointer hover:underline transition-colors ${
        flash === "ok" ? "text-green-400" : flash === "failed" ? "text-red-400" : "text-blue-400"
      }`}
      title={flash === "failed" ? COPY_FAILED_TITLE : "Click to copy"}
    >
      {hex}
    </button>
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

function SignatureSection() {
  const { peFile: pe } = useAppState();
  const [open, setOpen] = useState(true);

  if (!pe) return null;
  const cert = pe.certificate;

  return (
    <section>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-1 w-full text-left"
      >
        <span className="text-[8px]">{open ? "\u25BC" : "\u25B6"}</span>
        Digital Signature
        {cert?.signed ? (
          <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium bg-green-900/30 text-green-400">
            Signed
          </span>
        ) : (
          <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-700 text-gray-400">
            Unsigned
          </span>
        )}
      </button>
      {open && cert?.signed && (
        <table>
          <tbody>
            {cert.subject && <Row label="Subject">{cert.subject}</Row>}
            {cert.issuer && <Row label="Issuer">{cert.issuer}</Row>}
            {cert.notBefore && <Row label="Valid From">{cert.notBefore}</Row>}
            {cert.notAfter && <Row label="Valid Until">{cert.notAfter}</Row>}
            <Row label="Signature Size">{cert.signatureSize.toLocaleString()} bytes</Row>
            <Row label="Revision">
              0x{cert.revision.toString(16).toUpperCase().padStart(4, "0")}
            </Row>
            <Row label="Certificate Type">
              {cert.certificateType === 0x0002
                ? "PKCS#7 SignedData"
                : `0x${cert.certificateType.toString(16).toUpperCase()}`}
            </Row>
          </tbody>
        </table>
      )}
      {open && !cert?.signed && (
        <p className="text-gray-500 text-xs">No digital signature found in this binary.</p>
      )}
    </section>
  );
}

function TLSSection() {
  const { peFile: pe } = useAppState();
  const dispatch = useAppDispatch();
  const [open, setOpen] = useState(true);

  if (!pe?.tlsDirectory) return null;
  const tls = pe.tlsDirectory;
  const addrWidth = pe.is64 ? 16 : 8;

  const navigateTo = (addr: number) => {
    dispatch({ type: "SET_ADDRESS", address: addr });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
  };

  return (
    <section>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-1 w-full text-left"
      >
        <span className="text-[8px]">{open ? "▼" : "▶"}</span>
        TLS Directory
        <span className="text-gray-500 font-normal ml-1">
          ({tls.callbacks.length} callback{tls.callbacks.length !== 1 ? "s" : ""})
        </span>
      </button>
      {open && (
        <table>
          <tbody>
            <Row label="Raw Data Start">
              <CopyableHex value={tls.startAddressOfRawData} width={addrWidth} />
            </Row>
            <Row label="Raw Data End">
              <CopyableHex value={tls.endAddressOfRawData} width={addrWidth} />
            </Row>
            <Row label="Address of Index">
              <CopyableHex value={tls.addressOfIndex} width={addrWidth} />
            </Row>
            <Row label="Address of Callbacks">
              <CopyableHex value={tls.addressOfCallBacks} width={addrWidth} />
            </Row>
            <Row label="Size of Zero Fill">{tls.sizeOfZeroFill}</Row>
            <Row label="Characteristics">
              <CopyableHex value={tls.characteristics} />
            </Row>
            {tls.callbacks.length > 0 && (
              <Row label="Callbacks">
                <div className="space-y-0.5">
                  {tls.callbacks.map((cb, i) => (
                    <div key={i}>
                      <button
                        type="button"
                        onClick={() => navigateTo(cb)}
                        className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer font-mono"
                      >
                        0x{cb.toString(16).toUpperCase().padStart(addrWidth, "0")}
                      </button>
                    </div>
                  ))}
                </div>
              </Row>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}

function RelocationsSection() {
  const { peFile: pe } = useAppState();
  const [open, setOpen] = useState(false);

  if (!pe?.relocations) return null;
  const blocks = pe.relocations;
  const totalEntries = blocks.reduce((sum, b) => sum + b.entries.length, 0);

  return (
    <section>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="text-sm font-semibold text-gray-200 mb-2 flex items-center gap-1 w-full text-left"
      >
        <span className="text-[8px]">{open ? "▼" : "▶"}</span>
        Base Relocations
        <span className="text-gray-500 font-normal ml-1">
          ({blocks.length} block{blocks.length !== 1 ? "s" : ""}, {totalEntries.toLocaleString()}{" "}
          entries)
        </span>
      </button>
      {open && (
        <div className="space-y-1">
          {blocks.map((block, i) => {
            const typeCounts: Record<number, number> = {};
            for (const entry of block.entries) {
              typeCounts[entry.type] = (typeCounts[entry.type] || 0) + 1;
            }
            const typeStr = Object.entries(typeCounts)
              .map(([t, c]) => `${RELOC_TYPE_NAMES[Number(t)] ?? `Type${t}`}: ${c}`)
              .join(", ");

            return (
              <div key={i} className="border-b border-gray-800 py-1">
                <span className="text-blue-400 font-mono">
                  0x{block.virtualAddress.toString(16).toUpperCase().padStart(8, "0")}
                </span>
                <span className="text-gray-500 ml-2">{block.entries.length} entries</span>
                <div className="text-gray-400 text-[10px] ml-2">{typeStr}</div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function AnomalyBanners() {
  const state = useAppState();
  const [dismissed, setDismissed] = useState<Set<number>>(new Set());
  if (state.anomalies.length === 0) return null;

  const severityConfig = {
    critical: {
      bg: "bg-red-900/40",
      border: "border-red-700/50",
      text: "text-red-300",
      icon: "!!",
      label: "text-red-400",
    },
    warning: {
      bg: "bg-amber-900/40",
      border: "border-amber-700/50",
      text: "text-amber-300",
      icon: "!",
      label: "text-amber-400",
    },
    info: {
      bg: "bg-blue-900/40",
      border: "border-blue-700/50",
      text: "text-blue-300",
      icon: "i",
      label: "text-blue-400",
    },
  };
  const order: ("critical" | "warning" | "info")[] = ["critical", "warning", "info"];

  return (
    <div className="space-y-1 mb-4">
      {order.map((severity) => {
        const items = state.anomalies
          .map((a, i) => ({ ...a, idx: i }))
          .filter((a) => a.severity === severity && !dismissed.has(a.idx));
        if (items.length === 0) return null;
        const cfg = severityConfig[severity];
        return items.map((a) => (
          <div
            key={a.idx}
            className={`${cfg.bg} border-l-4 ${cfg.border} px-3 py-2 flex items-start gap-2 rounded-r text-xs`}
          >
            <span
              className={`${cfg.label} font-bold text-sm leading-none mt-0.5 shrink-0 w-4 text-center`}
            >
              {cfg.icon}
            </span>
            <div className="flex-1 min-w-0">
              <span className={`${cfg.label} font-semibold`}>{a.title}</span>
              <span className={`${cfg.text} ml-2`}>{a.detail}</span>
            </div>
            <button
              type="button"
              onClick={() => setDismissed((prev) => new Set([...prev, a.idx]))}
              className={`${cfg.label} hover:opacity-80 text-sm leading-none shrink-0`}
              title="Dismiss"
            >
              ×
            </button>
          </div>
        ));
      })}
    </div>
  );
}

export function HeaderView() {
  const { peFile: pe } = useAppState();
  const dispatch = useAppDispatch();

  // --- Metadata computations ---
  // Every hook must run before the `!pe` early return below, otherwise the hook
  // count changes between renders and React throws on the transition.
  const richHeader = useMemo(() => (pe ? parseRichHeader(pe.buffer) : null), [pe]);
  const debugInfo = useMemo(() => (pe ? parseDebugDirectory(pe.buffer, pe) : []), [pe]);
  // Off the main thread above a threshold — a large image's checksum is a walk
  // over every byte in the file. See hooks/useFileMetrics.ts.
  const fileMetrics = useFileMetrics(pe);
  const checksum = fileMetrics.value?.checksum ?? null;
  // `null` from `computeImphash` is a REFUSAL, not an absence: the import
  // table is not whole, so a digest over it would be well-formed and wrong.
  // `""` still means the image imports nothing. The row below tells them apart
  // — printing "No imports" for a truncated table would be the narrower answer
  // wearing a complete one's shape, which is the defect this guards.
  const imphash = useMemo(() => (pe ? computeImphash(pe) : null), [pe]);
  const overlay = useMemo(() => (pe ? detectOverlay(pe.buffer, pe) : null), [pe]);

  const [imphashFlash, setImphashFlash] = useState<"idle" | "ok" | "failed">("idle");
  const copyImphash = useCallback(async () => {
    if (!imphash) return;
    const ok = await copyText(imphash);
    setImphashFlash(ok ? "ok" : "failed");
    setTimeout(() => setImphashFlash("idle"), 800);
  }, [imphash]);

  if (!pe) return null;

  const { coffHeader: coff, optionalHeader: opt } = pe;
  const coffFlags = decodeFlags(coff.characteristics, COFF_CHARACTERISTICS);
  const dllFlags = decodeFlags(opt.dllCharacteristics, DLL_CHARACTERISTICS);
  const dirClamp = dataDirectoryClamp(pe);
  const entryVA = opt.imageBase + opt.addressOfEntryPoint;

  const navigateToEntry = () => {
    dispatch({ type: "SET_ADDRESS", address: entryVA });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
  };

  return (
    <div className="p-4 space-y-6 text-xs overflow-auto h-full">
      {/* Anomaly Banners */}
      <AnomalyBanners />

      {/* COFF Header */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">COFF Header</h2>
        <table>
          <tbody>
            <Row label="Machine">
              <CopyableHex value={coff.machine} width={4} />{" "}
              <span className="text-gray-400">({MACHINE_TYPES[coff.machine] ?? "Unknown"})</span>
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
                <FlagChips flags={coffFlags.flags} unknown={coffFlags.unknown} />
              </div>
            </Row>
          </tbody>
        </table>
      </section>

      {/* Optional Header */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">Optional Header</h2>
        <table>
          <tbody>
            {/*
              The label comes from the MAGIC, not from `pe.is64`. `is64` is
              `magic === 0x020B`, so the old ternary printed `(PE32)` for every
              value that is not PE32+ — including 0x0107, a ROM image, which is
              neither. That is a derived label claiming more than the value
              supports, the class the Machine and Subsystem rows above and below
              already refuse by admitting `(Unknown)`.

              UNREACHABLE THROUGH `parsePE` TODAY, and stated rather than
              implied: the parser throws on any magic but 0x010B and 0x020B, so
              nothing that reaches this panel can carry a third value. This is a
              guard against a widening there, not a repair of something on
              screen — which is why the row is spelled the way the two rows that
              can be wrong are spelled, rather than given a special case.
            */}
            <Row label="Magic">
              <CopyableHex value={opt.magic} width={4} />{" "}
              <span className="text-gray-400">
                ({OPTIONAL_HEADER_MAGIC[opt.magic] ?? "Unknown"})
              </span>
            </Row>
            <Row label="Entry Point">
              <button
                type="button"
                onClick={navigateToEntry}
                className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
              >
                0x
                {entryVA
                  .toString(16)
                  .toUpperCase()
                  .padStart(pe.is64 ? 16 : 8, "0")}
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
              <span className="text-gray-400">({SUBSYSTEM_NAMES[opt.subsystem] ?? "Unknown"})</span>
            </Row>
            <Row label="DLL Characteristics">
              <CopyableHex value={opt.dllCharacteristics} width={4} />
              <div className="mt-1">
                <FlagChips flags={dllFlags.flags} unknown={dllFlags.unknown} />
              </div>
            </Row>
            {/*
              THE DECLARED COUNT AND THE TABLE BELOW IT ARE THE SAME PAIR AS THE
              Certificate Table row above: neither number is false alone. The raw
              count is what the file says, and `parseDataDirectories` clamps what
              it reads to `Math.min(count, 16, fits)` because the field is
              attacker-controlled — so a PE32+ declaring 40 printed
              `Number of RVA and Sizes: 40` directly above a table of SIXTEEN
              rows, with nothing on screen saying so. This is the
              adversarial-input direction of it: a count of 40 is a crafted-PE
              tell the parser noticed deliberately, and the panel was the one
              surface a human reads and the one place it disappeared.

              Spelled in the panel's own muted-parenthetical idiom — `0x014C
              (x86)`, `0x010B (PE32)`, `(file offset)` — rather than as a banner,
              because the reader who needs it is the one already looking at this
              number. `analysis/anomalies.ts` raises the same fact for the reader
              who is not: the Anomalies tab is where "this file claims something
              implausible" belongs, and the two surfaces answer different
              questions. Both derive the fact from `dataDirectoryClamp`, which is
              the one declaration of it. (peek-a-bin-dd94)
            */}
            <Row label="Number of RVA and Sizes">
              {opt.numberOfRvaAndSizes}
              {dirClamp && (
                <span
                  className="text-gray-400 ml-2"
                  title={
                    dirClamp.reason === "short-header"
                      ? `The declared ${dirClamp.declared} entries do not fit in the file, so the table below holds the ${dirClamp.present} that do.`
                      : `The PE format defines sixteen data directories. This file declares ${dirClamp.declared}, so the table below holds the ${dirClamp.present} the format allows.`
                  }
                >
                  (clamped to {dirClamp.present})
                </span>
              )}
            </Row>
          </tbody>
        </table>
      </section>

      {/* Data Directories */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">Data Directories</h2>
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
                <td className="py-1 pr-6 text-gray-300">{DATA_DIR_NAMES[i] ?? `Directory ${i}`}</td>
                <td className="py-1 pr-6">
                  <CopyableHex value={dd.virtualAddress} />
                  {/*
                    The Certificate Table is the ONE directory whose address
                    field is not an RVA — the attribute certificates sit outside
                    every section, so the field is a raw file offset, and
                    `pe/authenticode.ts`'s `parseSecurityDirectory` uses it as
                    one. Only this table disagreed, and only on this row.

                    The correction goes on the ROW rather than in the heading
                    because the exception is a property of the row: heading the
                    column "RVA / offset" would make all sixteen rows ambiguous
                    in order to disambiguate one, and would leave a reader
                    coming from `dumpbin` — which prints the same value under
                    the same "RVA" heading — with less information, not more.
                    The spelling is the panel's own existing idiom for "what
                    this number actually is": a muted parenthetical beside the
                    number, exactly as in `0x014C (x86)`, `0x010B (PE32)` and
                    `(RVA: 0x…)` above. So no footnote mechanism is invented
                    for one row, and nothing is hidden behind a hover.

                    Shown UNCONDITIONALLY, including where the directory is
                    empty (0/0, i.e. every unsigned binary). The statement is
                    about the FIELD, not about the value: suppressing it when
                    zero would make it read as a property of this file, and
                    would mean the table still says "RVA" over that row on most
                    of the binaries anyone opens. (peek-a-bin-xnne)
                  */}
                  {i === IMAGE_DIRECTORY_ENTRY_SECURITY && (
                    <span
                      className="text-gray-500 ml-2"
                      title="The attribute certificates lie outside every section, so this directory's address field is a raw file offset rather than an RVA."
                    >
                      (file offset)
                    </span>
                  )}
                </td>
                <td className="py-1">
                  <CopyableHex value={dd.size} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Metadata */}
      <section>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">Metadata</h2>
        <table>
          <tbody>
            <Row label="Checksum Validation">
              {fileMetrics.loading ? (
                <span className="text-gray-500">Computing…</span>
              ) : fileMetrics.error ? (
                <span className="text-yellow-400" title={fileMetrics.error}>
                  Unavailable ({fileMetrics.error})
                </span>
              ) : !checksum ? (
                <span className="text-gray-500">Unavailable</span>
              ) : checksum.expected === 0 ? (
                <span className="text-gray-500">Not set (0x00000000)</span>
              ) : checksum.valid ? (
                <span className="text-green-400">Valid</span>
              ) : (
                <span className="text-red-400">
                  Invalid (expected <CopyableHex value={checksum.expected} />, actual{" "}
                  <CopyableHex value={checksum.actual} />)
                </span>
              )}
            </Row>
            <Row label="Imphash">
              {imphash ? (
                <button
                  type="button"
                  onClick={copyImphash}
                  className={`inline font-mono cursor-pointer hover:underline transition-colors ${
                    imphashFlash === "ok"
                      ? "text-green-400"
                      : imphashFlash === "failed"
                        ? "text-red-400"
                        : "text-blue-400"
                  }`}
                  title={imphashFlash === "failed" ? COPY_FAILED_TITLE : "Click to copy"}
                >
                  {imphash}
                </button>
              ) : imphash === null ? (
                <span className="text-yellow-400">
                  Unavailable &mdash; the import table is incomplete
                </span>
              ) : (
                <span className="text-gray-500">No imports</span>
              )}
            </Row>
            <Row label="Overlay">
              {overlay ? (
                <span>
                  <span className="text-yellow-400">Detected</span>{" "}
                  <span className="text-gray-400">
                    at offset 0x{overlay.offset.toString(16).toUpperCase()},{" "}
                    {overlay.size.toLocaleString()} bytes
                  </span>
                </span>
              ) : (
                <span className="text-gray-500">None</span>
              )}
            </Row>
          </tbody>
        </table>

        {/* Debug Info */}
        {debugInfo.length > 0 && (
          <div className="mt-3">
            <h3 className="text-xs font-semibold text-gray-300 mb-1">Debug Info</h3>
            <table>
              <tbody>
                {debugInfo.map((d, i) => (
                  <tr key={i} className="border-b border-gray-800">
                    <td className="py-1 pr-4 text-gray-400">{d.typeName}</td>
                    <td className="py-1 text-gray-200">
                      {d.pdbPath && <div className="text-green-400 font-mono">{d.pdbPath}</div>}
                      {d.guid && (
                        <div className="text-gray-500 text-[10px]">
                          GUID: {d.guid} Age: {d.age}
                        </div>
                      )}
                      {!d.pdbPath && !d.guid && <span className="text-gray-500">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Rich Header */}
        {richHeader && richHeader.length > 0 && (
          <div className="mt-3">
            <h3 className="text-xs font-semibold text-gray-300 mb-1">
              Rich Header ({richHeader.length} entries)
            </h3>
            <table className="w-full">
              <thead>
                <tr className="text-gray-400 border-b border-gray-700">
                  <th className="text-left py-1 pr-4">Tool ID</th>
                  <th className="text-left py-1 pr-4">Build ID</th>
                  <th className="text-left py-1">Use Count</th>
                </tr>
              </thead>
              <tbody>
                {richHeader.map((entry, i) => (
                  <tr key={i} className="border-b border-gray-800">
                    <td className="py-1 pr-4 text-blue-400 font-mono">
                      0x{entry.toolId.toString(16).toUpperCase()}
                    </td>
                    <td className="py-1 pr-4 text-gray-300 font-mono">{entry.buildId}</td>
                    <td className="py-1 text-gray-400">{entry.useCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Digital Signature */}
      <SignatureSection />

      {/* TLS Directory */}
      <TLSSection />

      {/* Base Relocations */}
      <RelocationsSection />
    </div>
  );
}
