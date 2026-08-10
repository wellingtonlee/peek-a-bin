/**
 * Win32/NT API name lists shared by the AI features.
 *
 * These were previously two hand-maintained literals — `DANGEROUS_APIS` in
 * `useVulnScanner.ts` and `notableAPIs` in `useAIReport.ts` — that had drifted
 * apart. Seven APIs the scanner treated as dangerous were absent from the
 * report's list, so an analyst could be told a function was worth scanning for
 * vulnerabilities while the generated report never mentioned the import that
 * made it interesting. The two lists also normalised the ANSI/wide suffix
 * differently, so a `CreateProcessW` import matched in one feature and not the
 * other depending on which spelling happened to be enumerated by hand.
 *
 * The two concepts are genuinely different and stay separate — "notable in a
 * report" is broader than "worth a vulnerability scan", covering file, registry
 * and network APIs that are unremarkable on their own. What is now guaranteed
 * is the containment: every dangerous API is also notable. `apiLists.test.ts`
 * pins that.
 */

/**
 * APIs whose presence makes a calling function worth scanning for
 * vulnerabilities: memory manipulation, process injection, execution and
 * crypto.
 *
 * Do not enumerate `A`/`W` suffix variants here — `matchesApi` strips them.
 * Listing them by hand is what produced the original inconsistency.
 */
export const DANGEROUS_APIS: ReadonlySet<string> = new Set([
  // Memory
  "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
  "WriteProcessMemory", "ReadProcessMemory",
  "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
  "NtMapViewOfSection", "MapViewOfFile",
  // Process and thread
  "CreateRemoteThread", "NtCreateThread", "CreateProcess",
  "OpenProcess", "NtOpenProcess",
  // Execution
  "ShellExecute", "WinExec", "LoadLibrary", "GetProcAddress",
  "SetWindowsHookEx",
  // Crypto
  "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
]);

/** Notable but not inherently dangerous: file, registry, network, service and
 *  anti-debug APIs that are worth surfacing in a report for context. */
const CONTEXTUAL_APIS: readonly string[] = [
  // File
  "CreateFile", "ReadFile", "WriteFile", "DeleteFile",
  // Registry
  "RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
  // Network
  "InternetOpen", "HttpOpenRequest", "URLDownloadToFile",
  "socket", "connect", "send", "recv",
  // Service and persistence
  "CreateService", "StartService",
  // Anti-debug
  "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
  // Process control
  "TerminateProcess",
  // Crypto (hashing is contextual; encryption is in DANGEROUS_APIS)
  "CryptCreateHash",
];

/**
 * Every API worth calling out in a generated report. A superset of
 * `DANGEROUS_APIS` by construction, so the report can never omit an import the
 * scanner considers dangerous.
 */
export const NOTABLE_APIS: ReadonlySet<string> = new Set([
  ...DANGEROUS_APIS,
  ...CONTEXTUAL_APIS,
]);

/**
 * Whether an imported symbol is in `set`, ignoring the ANSI/wide suffix.
 *
 * Both the raw name and the stripped name are tested, because a handful of real
 * APIs legitimately end in `A` or `W` (`CryptGenRandomA` is not a thing, but
 * `RtlInitStringA`-style names and plain lowercase socket exports like `recv`
 * must not be mangled into a false miss).
 */
export function matchesApi(set: ReadonlySet<string>, name: string): boolean {
  return set.has(name) || set.has(name.replace(/[AW]$/, ""));
}
