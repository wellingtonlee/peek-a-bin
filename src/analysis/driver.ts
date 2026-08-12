/**
 * Kernel Driver Analysis
 * Detection, suspicious API flagging, IOCTL decoding, IRP dispatch detection
 */

import type { PEFile } from "../pe/types";
import type { Instruction } from "../disasm/types";

// ── Driver Detection ──

export interface DriverInfo {
  isDriver: boolean;
  reasons: string[];
  isWDM: boolean;
  kernelImportCount: number;
  kernelModules: string[];
}

const KERNEL_MODULES = new Set([
  "ntoskrnl.exe",
  "hal.dll",
  "ndis.sys",
  "fltmgr.sys",
  "wdfldr.sys",
  "netio.sys",
  "fwpkclnt.sys",
  "classpnp.sys",
  "storport.sys",
  "scsiport.sys",
  "ksecdd.sys",
  "cng.sys",
  "ci.dll",
  "clfs.sys",
  "tm.sys",
  "wdmsec.sys",
  "ataport.sys",
  "drmk.sys",
  "portcls.sys",
  "ks.sys",
  "wmilib.sys",
  "tdi.sys",
  "wdf01000.sys",
  "wdfldr.sys",
]);

/** Whether a library name is one of the kernel-mode modules only a driver links against. */
export function isKernelModule(libraryName: string): boolean {
  return KERNEL_MODULES.has(libraryName.toLowerCase());
}

/**
 * Whether an import table links a kernel-mode module — driver evidence for the
 * places that have imports but not the `PEFile`.
 *
 * This is one of `detectDriver`'s three reasons, and deliberately the only one
 * reachable here: the NATIVE subsystem and the WDM characteristics bit live in
 * the optional header, which the decompiler is never handed. So this is
 * strictly narrower than `detectDriver` — a driver that imports nothing from
 * ntoskrnl is not recognised — and narrower is the safe direction for anything
 * that decides whether to *annotate*. Answering true where `detectDriver` would
 * answer false is not possible; the module set is the same one.
 */
export function importsKernelModule(imports: Iterable<{ lib: string }>): boolean {
  for (const entry of imports) if (isKernelModule(entry.lib)) return true;
  return false;
}

export function detectDriver(pe: PEFile): DriverInfo {
  const reasons: string[] = [];
  const kernelModules: string[] = [];
  let kernelImportCount = 0;

  // Check subsystem
  if (pe.optionalHeader.subsystem === 1) {
    reasons.push("Subsystem: NATIVE");
  }

  // Check WDM flag
  const isWDM = (pe.optionalHeader.dllCharacteristics & 0x2000) !== 0;
  if (isWDM) reasons.push("DllCharacteristics: WDM_DRIVER");

  // Check kernel module imports
  for (const imp of pe.imports) {
    if (isKernelModule(imp.libraryName)) {
      kernelModules.push(imp.libraryName);
      kernelImportCount += imp.functions.length;
    }
  }
  if (kernelModules.length > 0) {
    reasons.push(`Imports from: ${kernelModules.join(", ")}`);
  }

  const isDriver = reasons.length > 0;
  return { isDriver, reasons, isWDM, kernelImportCount, kernelModules };
}

// ── Suspicious Kernel API Database ──

interface ApiRiskInfo {
  category: string;
  colorClass: string;
}

const SUSPICIOUS_APIS = new Map<string, ApiRiskInfo>([
  // Process/Thread manipulation
  [
    "PsCreateSystemThread",
    { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" },
  ],
  [
    "PsSetCreateProcessNotifyRoutine",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "PsSetCreateProcessNotifyRoutineEx",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "PsSetCreateThreadNotifyRoutine",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "PsSetLoadImageNotifyRoutine",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "PsLookupProcessByProcessId",
    { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" },
  ],
  [
    "PsLookupThreadByThreadId",
    { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" },
  ],
  [
    "PsGetCurrentProcessId",
    { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" },
  ],
  ["ZwOpenProcess", { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" }],
  ["ZwTerminateProcess", { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" }],
  ["KeAttachProcess", { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" }],
  [
    "KeStackAttachProcess",
    { category: "Process/Thread", colorClass: "text-red-400 bg-red-900/30" },
  ],

  // Callback/Hook
  [
    "ObRegisterCallbacks",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "CmRegisterCallback",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "CmRegisterCallbackEx",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "IoRegisterShutdownNotification",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],
  [
    "KeRegisterBugCheckCallback",
    { category: "Callback/Hook", colorClass: "text-orange-400 bg-orange-900/30" },
  ],

  // Memory
  ["MmMapIoSpace", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["MmMapLockedPages", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  [
    "MmMapLockedPagesSpecifyCache",
    { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" },
  ],
  ["MmCopyVirtualMemory", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  [
    "MmGetSystemRoutineAddress",
    { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" },
  ],
  [
    "ZwAllocateVirtualMemory",
    { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" },
  ],
  [
    "ZwProtectVirtualMemory",
    { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" },
  ],
  ["ZwReadVirtualMemory", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["ZwWriteVirtualMemory", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["ExAllocatePool", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["ExAllocatePoolWithTag", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["ExAllocatePool2", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["MmProbeAndLockPages", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],
  ["KeInsertQueueApc", { category: "Memory", colorClass: "text-purple-400 bg-purple-900/30" }],

  // Registry
  ["ZwCreateKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],
  ["ZwOpenKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],
  ["ZwSetValueKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],
  ["ZwDeleteKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],
  ["ZwQueryValueKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],
  ["ZwEnumerateKey", { category: "Registry", colorClass: "text-yellow-400 bg-yellow-900/30" }],

  // Filesystem
  ["ZwCreateFile", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["ZwReadFile", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["ZwWriteFile", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["ZwDeleteFile", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["ZwQueryDirectoryFile", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["IoCreateFileEx", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],
  ["FltRegisterFilter", { category: "Filesystem", colorClass: "text-blue-400 bg-blue-900/30" }],

  // Network
  ["WskSocket", { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" }],
  ["WskBind", { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" }],
  ["WskConnect", { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" }],
  ["WskSend", { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" }],
  ["WskReceive", { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" }],
  [
    "NdisRegisterProtocolDriver",
    { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" },
  ],
  [
    "NdisMRegisterMiniportDriver",
    { category: "Network", colorClass: "text-cyan-400 bg-cyan-900/30" },
  ],

  // Object manipulation
  ["ObReferenceObjectByHandle", { category: "Object", colorClass: "text-pink-400 bg-pink-900/30" }],
  ["ObOpenObjectByPointer", { category: "Object", colorClass: "text-pink-400 bg-pink-900/30" }],
  ["ObfDereferenceObject", { category: "Object", colorClass: "text-pink-400 bg-pink-900/30" }],
  ["ZwDuplicateObject", { category: "Object", colorClass: "text-pink-400 bg-pink-900/30" }],
]);

export function getApiRiskTag(name: string): ApiRiskInfo | null {
  return SUSPICIOUS_APIS.get(name) ?? null;
}

// ── IOCTL Decoder ──

export interface IOCTLDecode {
  deviceType: number;
  deviceTypeName: string;
  access: number;
  accessName: string;
  function: number;
  method: number;
  methodName: string;
}

const DEVICE_TYPE_NAMES: Record<number, string> = {
  0x01: "BEEP",
  0x02: "CD_ROM",
  0x03: "CD_ROM_FILE_SYSTEM",
  0x04: "CONTROLLER",
  0x05: "DATALINK",
  0x06: "DFS",
  0x07: "DISK",
  0x08: "DISK_FILE_SYSTEM",
  0x09: "FILE_SYSTEM",
  0x0a: "INPORT_PORT",
  0x0b: "KEYBOARD",
  0x0c: "MAILSLOT",
  0x0d: "MIDI_IN",
  0x0e: "MIDI_OUT",
  0x0f: "MOUSE",
  0x10: "MULTI_UNC_PROVIDER",
  0x11: "NAMED_PIPE",
  0x12: "NETWORK",
  0x13: "NETWORK_BROWSER",
  0x14: "NETWORK_FILE_SYSTEM",
  0x15: "NULL",
  0x16: "PARALLEL_PORT",
  0x17: "PHYSICAL_NETCARD",
  0x18: "PRINTER",
  0x19: "SCANNER",
  0x1a: "SERIAL_MOUSE_PORT",
  0x1b: "SERIAL_PORT",
  0x1c: "SCREEN",
  0x1d: "SOUND",
  0x1e: "STREAMS",
  0x1f: "TAPE",
  0x20: "TAPE_FILE_SYSTEM",
  0x21: "TRANSPORT",
  0x22: "UNKNOWN",
  0x23: "VIDEO",
  0x24: "VIRTUAL_DISK",
  0x25: "WAVE_IN",
  0x26: "WAVE_OUT",
  0x27: "8042_PORT",
  0x28: "NETWORK_REDIRECTOR",
  0x29: "BATTERY",
  0x2a: "BUS_EXTENDER",
  0x2b: "MODEM",
  0x2c: "VDM",
  0x2d: "MASS_STORAGE",
  0x2e: "SMB",
  0x2f: "KS",
  0x30: "CHANGER",
  0x31: "SMARTCARD",
  0x32: "ACPI",
  0x33: "DVD",
  0x34: "FULLSCREEN_VIDEO",
  0x35: "DFS_FILE_SYSTEM",
  0x36: "DFS_VOLUME",
  0x37: "SERENUM",
  0x38: "TERMSRV",
  0x39: "KSEC",
  0x3a: "FIPS",
  0x3b: "INFINIBAND",
  0x3e: "VMBUS",
  0x3f: "CRYPT_PROVIDER",
  0x40: "WPD",
  0x41: "BLUETOOTH",
  0x42: "MT_COMPOSITE",
  0x43: "MT_TRANSPORT",
  0x44: "BIOMETRIC",
  0x45: "PMI",
};

const METHOD_NAMES: Record<number, string> = {
  0: "BUFFERED",
  1: "IN_DIRECT",
  2: "OUT_DIRECT",
  3: "NEITHER",
};

const ACCESS_NAMES: Record<number, string> = {
  0: "ANY",
  1: "READ",
  2: "WRITE",
  3: "READ|WRITE",
};

export function decodeIOCTL(value: number): IOCTLDecode | null {
  const deviceType = (value >>> 16) & 0xffff;
  const access = (value >>> 14) & 0x3;
  const func = (value >>> 2) & 0xfff;
  const method = value & 0x3;

  if (!isPlausibleIOCTL(value)) return null;

  return {
    deviceType,
    deviceTypeName: DEVICE_TYPE_NAMES[deviceType] ?? `0x${deviceType.toString(16)}`,
    access,
    accessName: ACCESS_NAMES[access] ?? `${access}`,
    function: func,
    method,
    methodName: METHOD_NAMES[method] ?? `${method}`,
  };
}

export function isPlausibleIOCTL(value: number): boolean {
  // An IOCTL code is a 32-bit value. Without this, a wider immediate (x64 movabs
  // constants reach here) is silently truncated by the shifts below and can
  // decode as a plausible code — a false IOCTL annotation on an unrelated value.
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) return false;
  if (value === 0 || value < 0x10000) return false;
  const deviceType = (value >>> 16) & 0xffff;
  const func = (value >>> 2) & 0xfff;
  const method = value & 0x3;
  // Known device type range or custom range
  const knownRange = deviceType >= 0x01 && deviceType <= 0x45;
  const customRange = deviceType >= 0x8000;
  if (!knownRange && !customRange) return false;
  if (func > 0xfff) return false;
  if (method > 3) return false;
  return true;
}

export function formatIOCTL(value: number): string | null {
  const decoded = decodeIOCTL(value);
  if (!decoded) return null;
  return `IOCTL: ${decoded.deviceTypeName} | Fn=0x${decoded.function.toString(16)} | ${decoded.methodName}`;
}

/**
 * Which argument of an API carries a control code, for the APIs that take one.
 *
 * `isPlausibleIOCTL` accepts a large share of all 32-bit constants by
 * construction — device type `0x01..0x45` or `>= 0x8000`, and any function code
 * and method — so on its own it is a shape test, not evidence. `0xFFFFFFFF` and
 * every `0x41xxxx` data address in a user-mode image pass it. What makes a
 * constant an IOCTL is that it is *passed as the control code* to one of these,
 * so callers should require the position as well as the shape.
 *
 * Positions are argument indices in the documented prototypes:
 *   DeviceIoControl(hDevice, dwIoControlCode, ...)
 *   Nt/ZwDeviceIoControlFile(File, Event, Apc, ApcCtx, IoStatusBlock, IoControlCode, ...)
 *   Nt/ZwFsControlFile(File, Event, Apc, ApcCtx, IoStatusBlock, FsControlCode, ...)
 *   IoBuildDeviceIoControlRequest(IoControlCode, ...)
 *   WdfIoTargetSendIoctlSynchronously(IoTarget, Request, IoctlCode, ...)
 *   WdfIoTargetFormatRequestForIoctl(IoTarget, Request, IoctlCode, ...)
 */
const IOCTL_CODE_ARG_INDEX: Record<string, number> = {
  DeviceIoControl: 1,
  NtDeviceIoControlFile: 5,
  ZwDeviceIoControlFile: 5,
  NtFsControlFile: 5,
  ZwFsControlFile: 5,
  IoBuildDeviceIoControlRequest: 0,
  WdfIoTargetSendIoctlSynchronously: 2,
  WdfIoTargetFormatRequestForIoctl: 2,
};

/**
 * The control-code argument index for `name`, or null if it takes none.
 *
 * Names arrive decorated in several ways depending on where they were read
 * from: an import thunk (`__imp_DeviceIoControl`), a 32-bit stdcall symbol
 * (`_DeviceIoControl@32`), or a plain export.
 */
export function ioctlCodeArgIndex(name: string): number | null {
  const bare = name
    .replace(/^_{0,2}imp_{0,2}/, "")
    .replace(/^_+/, "")
    .replace(/@\d+$/, "");
  return IOCTL_CODE_ARG_INDEX[bare] ?? null;
}

// ── IRP Major Function Table ──

export const IRP_MAJOR_FUNCTIONS: Record<number, string> = {
  0x00: "IRP_MJ_CREATE",
  0x01: "IRP_MJ_CREATE_NAMED_PIPE",
  0x02: "IRP_MJ_CLOSE",
  0x03: "IRP_MJ_READ",
  0x04: "IRP_MJ_WRITE",
  0x05: "IRP_MJ_QUERY_INFORMATION",
  0x06: "IRP_MJ_SET_INFORMATION",
  0x07: "IRP_MJ_QUERY_EA",
  0x08: "IRP_MJ_SET_EA",
  0x09: "IRP_MJ_FLUSH_BUFFERS",
  0x0a: "IRP_MJ_QUERY_VOLUME_INFORMATION",
  0x0b: "IRP_MJ_SET_VOLUME_INFORMATION",
  0x0c: "IRP_MJ_DIRECTORY_CONTROL",
  0x0d: "IRP_MJ_FILE_SYSTEM_CONTROL",
  0x0e: "IRP_MJ_DEVICE_CONTROL",
  0x0f: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
  0x10: "IRP_MJ_SHUTDOWN",
  0x11: "IRP_MJ_LOCK_CONTROL",
  0x12: "IRP_MJ_CLEANUP",
  0x13: "IRP_MJ_CREATE_MAILSLOT",
  0x14: "IRP_MJ_QUERY_SECURITY",
  0x15: "IRP_MJ_SET_SECURITY",
  0x16: "IRP_MJ_POWER",
  0x17: "IRP_MJ_SYSTEM_CONTROL",
  0x18: "IRP_MJ_DEVICE_CHANGE",
  0x19: "IRP_MJ_QUERY_QUOTA",
  0x1a: "IRP_MJ_SET_QUOTA",
  0x1b: "IRP_MJ_PNP",
};

// ── IRP Dispatch Detection ──

export interface IRPDispatchEntry {
  irpMajor: number;
  irpName: string;
  handlerAddress: number;
  instructionAddress: number;
}

export function detectIRPDispatches(
  instructions: Instruction[],
  is64: boolean,
): IRPDispatchEntry[] {
  const results: IRPDispatchEntry[] = [];
  const seen = new Set<number>(); // avoid duplicate IRP entries

  const baseOffset = is64 ? 0x70 : 0x38;
  const step = is64 ? 8 : 4;
  const maxOffset = is64 ? 0x148 : 0xa8;

  for (const insn of instructions) {
    if (insn.mnemonic !== "mov") continue;

    // Pattern: mov [reg+offset], imm or mov [reg+offset], reg
    // x64: mov qword ptr [rcx + 0x70], rax — sets IRP_MJ_CREATE handler
    const match = insn.opStr.match(
      /\[(\w+)\s*\+\s*0x([0-9a-fA-F]+)\],\s*(?:0x([0-9a-fA-F]+)|(\w+))/,
    );
    if (!match) continue;

    const offset = parseInt(match[2], 16);
    if (offset < baseOffset || offset > maxOffset) continue;
    if ((offset - baseOffset) % step !== 0) continue;

    const irpIndex = (offset - baseOffset) / step;
    if (irpIndex > 0x1b) continue;
    if (seen.has(irpIndex)) continue;

    const irpName = IRP_MAJOR_FUNCTIONS[irpIndex];
    if (!irpName) continue;

    // Extract handler address (immediate value)
    let handlerAddress = 0;
    if (match[3]) {
      handlerAddress = parseInt(match[3], 16);
    }

    seen.add(irpIndex);
    results.push({
      irpMajor: irpIndex,
      irpName,
      handlerAddress,
      instructionAddress: insn.address,
    });
  }

  return results;
}
