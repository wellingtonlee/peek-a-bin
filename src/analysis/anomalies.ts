import {
  IMAGE_DIRECTORY_ENTRY_RESOURCE,
  IMAGE_DIRECTORY_ENTRY_SECURITY,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_WRITE,
} from "../pe/constants";
import {
  certificateUnreadable,
  dataDirectoryClamp,
  resourcesUnreadable,
} from "../pe/dataDirectories";
import { type ChecksumResult, detectOverlay, validateChecksum } from "../pe/metadata";
import type { PEFile } from "../pe/types";
import { computeSectionEntropies } from "../utils/entropy";
import { sectionRanges } from "../workers/metricsDispatch";

export interface Anomaly {
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
}

/**
 * The two whole-file walks {@link detectAnomalies} needs, computed elsewhere.
 *
 * Both are linear passes over the entire image — measured together at ~910 ms on
 * a 253 MiB PE — and both are already computed by `metrics.worker.ts` for the
 * Headers and Sections tabs, cached per `ArrayBuffer`. Passing them in is how
 * the browser keeps that work off the main thread; omit the argument and this
 * module does the walks itself, which is what the MCP server (no worker) and
 * small files still do.
 *
 * Either member may be `null` for "could not be computed". The checks that need
 * it are then skipped and one `info` anomaly says so, rather than the whole
 * anomaly pass failing or — worse — silently reporting a clean file.
 */
export interface AnomalyMetrics {
  checksum: ChecksumResult | null;
  /** One entropy per section, in section-table order. */
  sectionEntropies: number[] | null;
}

// Section characteristics flags come from pe/constants — this file used to
// redeclare IMAGE_SCN_MEM_EXECUTE/WRITE/CNT_CODE with its own literals.

// DLL characteristics flags
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;

const SUSPICIOUS_SECTION_NAMES = new Set([
  "UPX0",
  "UPX1",
  "UPX2",
  ".upx",
  ".packed",
  ".aspack",
  ".adata",
  ".nsp0",
  ".nsp1",
  ".nsp2",
  ".perplex",
  ".themida",
  ".vmp0",
  ".vmp1",
  ".enigma1",
  ".enigma2",
]);

// The private `computeSectionEntropy` that used to live here is gone: it was a
// second copy of `utils/entropy`'s walk that had drifted from it in three ways.
// It clamped a section overrunning EOF and scored the bytes that were there
// (the shared one scored 0), and it threw `RangeError` for an offset past EOF,
// a negative offset or a negative length — all three straight out of an
// attacker-controlled section table, and all three fatal to the whole load,
// since `App.tsx` calls this inside the try around `parsePE`. The clamping
// behaviour was the right one and moved into `computeSectionEntropies`; the
// throwing is gone.

export function detectAnomalies(pe: PEFile, metrics?: AnomalyMetrics): Anomaly[] {
  const anomalies: Anomaly[] = [];
  // Compute the whole-file walks here only if the caller did not. See
  // {@link AnomalyMetrics}.
  const checksum = metrics ? metrics.checksum : validateChecksum(pe.buffer, pe);
  const sectionEntropies = metrics
    ? metrics.sectionEntropies
    : computeSectionEntropies(pe.buffer, sectionRanges(pe));
  const opt = pe.optionalHeader;
  const entryRVA = opt.addressOfEntryPoint;

  // Find section containing entry point
  const entrySection = pe.sections.find(
    (s) => entryRVA >= s.virtualAddress && entryRVA < s.virtualAddress + s.virtualSize,
  );

  // Critical: Entry point in writable section
  if (entrySection && (entrySection.characteristics & IMAGE_SCN_MEM_WRITE) !== 0) {
    anomalies.push({
      severity: "critical",
      title: "Entry point in writable section",
      detail: `Entry point (RVA 0x${entryRVA.toString(16).toUpperCase()}) is in ${entrySection.name} which has WRITE permission. Common packer indicator.`,
    });
  }

  // Critical: Section with WRITE + EXECUTE
  for (const sec of pe.sections) {
    if (
      (sec.characteristics & IMAGE_SCN_MEM_WRITE) !== 0 &&
      (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0
    ) {
      anomalies.push({
        severity: "critical",
        title: `WX section: ${sec.name}`,
        detail: `Section ${sec.name} has both WRITE and EXECUTE permissions. Potential code injection risk.`,
      });
    }
  }

  // Warning: Entry point not in first code section
  const firstCodeSection = pe.sections.find((s) => (s.characteristics & IMAGE_SCN_CNT_CODE) !== 0);
  if (
    firstCodeSection &&
    entrySection &&
    entrySection.virtualAddress !== firstCodeSection.virtualAddress
  ) {
    anomalies.push({
      severity: "warning",
      title: "Unusual entry point location",
      detail: `Entry point is in ${entrySection.name} instead of the first code section (${firstCodeSection.name}).`,
    });
  }

  // Warning: Suspicious section names
  for (const sec of pe.sections) {
    const trimmed = sec.name.replace(/\0/g, "").trim();
    if (SUSPICIOUS_SECTION_NAMES.has(trimmed)) {
      anomalies.push({
        severity: "warning",
        title: `Suspicious section: ${trimmed}`,
        detail: `Section name "${trimmed}" is commonly associated with packers or protectors.`,
      });
    }
  }

  // Warning: TLS callbacks present
  if (pe.tlsDirectory && pe.tlsDirectory.callbacks.length > 0) {
    anomalies.push({
      severity: "warning",
      title: "TLS callbacks detected",
      detail: `${pe.tlsDirectory.callbacks.length} TLS callback(s) found. These execute before the entry point and can be used for anti-debug or pre-entry execution.`,
    });
  }

  // Warning: the file declares more data directories than the parser would read.
  //
  // `numberOfRvaAndSizes` is attacker-controlled, so `parseDataDirectories`
  // clamps to `Math.min(count, 16, fits)` — and every real linker writes exactly
  // 16, so a declared count above that is not a rounding error, it is a
  // deliberate claim the format cannot honour. This pass is where "the file
  // claims something implausible" lives, and it is the surface an analyst reads
  // rather than the one they have to notice: the Headers panel marks the same
  // fact on the row itself (`HeaderView`'s Number of RVA and Sizes), from the
  // same `dataDirectoryClamp`, because the two answer different questions.
  //
  // Warning rather than critical: the file is malformed and the malformation is
  // deliberate, but nothing here says code will run — `critical` in this pass is
  // reserved for WX sections and an entry point in writable memory. And warning
  // rather than info: unlike ASLR/DEP, which are ordinary build settings, no
  // toolchain produces this by accident. (peek-a-bin-dd94)
  const dirClamp = dataDirectoryClamp(pe);
  if (dirClamp) {
    anomalies.push(
      dirClamp.reason === "short-header"
        ? {
            severity: "warning",
            title: "Data directory table is cut short",
            detail: `The optional header declares ${dirClamp.declared} data ${dirClamp.declared === 1 ? "directory" : "directories"} but the file ends after ${dirClamp.present}. The header is truncated, so any directory past ${dirClamp.present} is not in the file at all.`,
          }
        : {
            severity: "warning",
            title: "Data directory count exceeds the format maximum",
            detail: `The optional header declares ${dirClamp.declared} data directories. The PE format defines 16, and linkers write exactly 16, so ${dirClamp.present} were read and the rest ignored. A count this size is a common crafted-PE tell.`,
          },
    );
  }

  // Warning: the file declares a directory whose reader gave up on it.
  //
  // These two are on this pass for `dataDirectoryClamp`'s reason and not by
  // symmetry: each panel marks the same fact where a reader looking at that
  // directory would see it (the Digital Signature pill, the Resources pane's
  // whole body), and this is the surface an analyst reads rather than the one
  // they have to think to open — a user who never opens the Resources tab never
  // learns the file declares resources this tool could not walk.
  //
  // Both predicates are exact — a declared directory with nothing parsed out of
  // it — so neither can fire on a well-formed image, which is what makes them
  // admissible here at `warning`: the file is malformed (a certificate table
  // outside the file, or a resource walk that threw), and like the clamp above,
  // no toolchain produces either by accident. Nothing here says code will run,
  // so not `critical`. (peek-a-bin-wo8g)
  if (certificateUnreadable(pe)) {
    anomalies.push({
      severity: "warning",
      title: "Certificate table could not be read",
      detail: `The optional header declares an attribute certificate of ${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].size.toLocaleString()} bytes at file offset 0x${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].virtualAddress.toString(16).toUpperCase()}, and the reader stopped on it — the certificate lies outside the file, or its structure did not parse. The file is not unsigned; its signature is unreadable, which a truncated or carved sample produces and so does a crafted one.`,
    });
  }
  if (resourcesUnreadable(pe)) {
    anomalies.push({
      severity: "warning",
      title: "Resource directory could not be read",
      detail: `The file declares a resource directory of ${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].size.toLocaleString()} bytes at RVA 0x${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].virtualAddress.toString(16).toUpperCase()}, and the reader stopped on it. Nothing is known about the resources in this image — not that there are none.`,
    });
  }

  // Warning: Checksum mismatch
  if (checksum !== null && checksum.expected !== 0 && !checksum.valid) {
    anomalies.push({
      severity: "warning",
      title: "Checksum mismatch",
      detail: `PE checksum is invalid (expected 0x${checksum.expected.toString(16).toUpperCase()}, actual 0x${checksum.actual.toString(16).toUpperCase()}). Binary may have been tampered with.`,
    });
  }

  // Warning: High entropy in code section
  //
  // `sectionEntropies` is indexed by section-table position — see
  // `sectionRanges`, the one function every caller builds the ranges with.
  for (const [i, sec] of pe.sections.entries()) {
    if ((sec.characteristics & IMAGE_SCN_CNT_CODE) !== 0 && sec.sizeOfRawData > 0) {
      const entropy = sectionEntropies?.[i] ?? 0;
      if (entropy > 7.0) {
        anomalies.push({
          severity: "warning",
          title: `High entropy: ${sec.name}`,
          detail: `Code section ${sec.name} has entropy ${entropy.toFixed(2)} (>7.0). May indicate packed or encrypted code.`,
        });
      }
    }
  }

  // Info: No DYNAMIC_BASE (ASLR disabled)
  if ((opt.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) === 0) {
    anomalies.push({
      severity: "info",
      title: "ASLR disabled",
      detail:
        "DYNAMIC_BASE is not set. The binary does not support Address Space Layout Randomization.",
    });
  }

  // Info: No NX_COMPAT (DEP disabled)
  if ((opt.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) === 0) {
    anomalies.push({
      severity: "info",
      title: "DEP disabled",
      detail: "NX_COMPAT is not set. The binary does not opt-in to Data Execution Prevention.",
    });
  }

  // Info: a check could not run.
  //
  // Only reachable when a caller passed metrics with a null member — i.e. the
  // metrics worker failed. Saying so beats an anomaly list that looks clean:
  // "no checksum warning" and "checksum not checked" are different answers, and
  // this pass is the one place a user goes to find out whether a file is
  // suspicious.
  const skipped: string[] = [];
  if (checksum === null) skipped.push("checksum validation");
  if (sectionEntropies === null) skipped.push("section entropy");
  if (skipped.length > 0) {
    anomalies.push({
      severity: "info",
      title: "Some checks did not run",
      detail: `${skipped.join(" and ")} could not be computed for this file, so any anomaly they would have reported is missing. See the browser console for the underlying error.`,
    });
  }

  // Info: Overlay data
  const overlay = detectOverlay(pe.buffer, pe);
  if (overlay) {
    anomalies.push({
      severity: "info",
      title: "Overlay data detected",
      detail: `${overlay.size.toLocaleString()} bytes of appended data found after PE at offset 0x${overlay.offset.toString(16).toUpperCase()}.`,
    });
  }

  return anomalies;
}
