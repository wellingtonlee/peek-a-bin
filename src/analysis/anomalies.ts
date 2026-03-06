import type { PEFile } from "../pe/types";
import { validateChecksum, detectOverlay } from "../pe/metadata";

export interface Anomaly {
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
}

// Section characteristics flags
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const IMAGE_SCN_CNT_CODE = 0x00000020;

// DLL characteristics flags
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;

const SUSPICIOUS_SECTION_NAMES = new Set([
  "UPX0", "UPX1", "UPX2", ".upx", ".packed", ".aspack",
  ".adata", ".nsp0", ".nsp1", ".nsp2", ".perplex",
  ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
]);

function computeSectionEntropy(buffer: ArrayBuffer, offset: number, size: number): number {
  if (size === 0) return 0;
  const bytes = new Uint8Array(buffer, offset, Math.min(size, buffer.byteLength - offset));
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function detectAnomalies(pe: PEFile): Anomaly[] {
  const anomalies: Anomaly[] = [];
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
  const firstCodeSection = pe.sections.find(
    (s) => (s.characteristics & IMAGE_SCN_CNT_CODE) !== 0,
  );
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

  // Warning: Checksum mismatch
  const checksum = validateChecksum(pe.buffer, pe);
  if (checksum.expected !== 0 && !checksum.valid) {
    anomalies.push({
      severity: "warning",
      title: "Checksum mismatch",
      detail: `PE checksum is invalid (expected 0x${checksum.expected.toString(16).toUpperCase()}, actual 0x${checksum.actual.toString(16).toUpperCase()}). Binary may have been tampered with.`,
    });
  }

  // Warning: High entropy in code section
  for (const sec of pe.sections) {
    if ((sec.characteristics & IMAGE_SCN_CNT_CODE) !== 0 && sec.sizeOfRawData > 0) {
      const entropy = computeSectionEntropy(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData);
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
      detail: "DYNAMIC_BASE is not set. The binary does not support Address Space Layout Randomization.",
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
