/**
 * Kernel driver detection, IOCTL decoding and IRP dispatch-table recovery.
 */

import { describe, it, expect } from "vitest";
import {
  detectDriver,
  getApiRiskTag,
  decodeIOCTL,
  isPlausibleIOCTL,
  formatIOCTL,
  detectIRPDispatches,
  IRP_MAJOR_FUNCTIONS,
} from "../driver";
import type { PEFile, ImportEntry } from "../../pe/types";
import type { Instruction } from "../../disasm/types";

/** Just enough of a PEFile for detectDriver, which reads three fields. */
function fakePE(opts: {
  subsystem?: number;
  dllCharacteristics?: number;
  imports?: ImportEntry[];
}): PEFile {
  return {
    optionalHeader: {
      subsystem: opts.subsystem ?? 3, // WINDOWS_CUI
      dllCharacteristics: opts.dllCharacteristics ?? 0,
    },
    imports: opts.imports ?? [],
  } as unknown as PEFile;
}

const lib = (libraryName: string, functions: string[]): ImportEntry => ({
  libraryName,
  functions,
  iatAddresses: [],
});

describe("detectDriver", () => {
  it("reports a plain user-mode binary as not a driver", () => {
    const info = detectDriver(fakePE({ imports: [lib("KERNEL32.dll", ["Sleep"])] }));
    expect(info).toEqual({
      isDriver: false,
      reasons: [],
      isWDM: false,
      kernelImportCount: 0,
      kernelModules: [],
    });
  });

  it("flags the NATIVE subsystem", () => {
    const info = detectDriver(fakePE({ subsystem: 1 }));
    expect(info.isDriver).toBe(true);
    expect(info.reasons).toContain("Subsystem: NATIVE");
  });

  it("flags the WDM_DRIVER DllCharacteristics bit", () => {
    const info = detectDriver(fakePE({ dllCharacteristics: 0x2000 }));
    expect(info.isWDM).toBe(true);
    expect(info.isDriver).toBe(true);
    expect(info.reasons).toContain("DllCharacteristics: WDM_DRIVER");
  });

  it("does not set isWDM for other DllCharacteristics bits", () => {
    // 0x0040 DYNAMIC_BASE / 0x0100 NX_COMPAT must not be mistaken for 0x2000.
    const info = detectDriver(fakePE({ dllCharacteristics: 0x0140 }));
    expect(info.isWDM).toBe(false);
    expect(info.isDriver).toBe(false);
  });

  it("counts imported functions from kernel modules, case-insensitively", () => {
    const info = detectDriver(
      fakePE({
        imports: [
          lib("NTOSKRNL.exe", ["ExAllocatePoolWithTag", "IoCreateDevice", "IoDeleteDevice"]),
          lib("HAL.dll", ["KeStallExecutionProcessor"]),
          lib("KERNEL32.dll", ["Sleep"]), // user-mode: not counted
        ],
      }),
    );
    expect(info.isDriver).toBe(true);
    expect(info.kernelImportCount).toBe(4);
    // The original casing is preserved for display.
    expect(info.kernelModules).toEqual(["NTOSKRNL.exe", "HAL.dll"]);
    expect(info.reasons).toContain("Imports from: NTOSKRNL.exe, HAL.dll");
  });

  it("recognises WDF and filter-manager modules", () => {
    for (const module of ["wdf01000.sys", "wdfldr.sys", "fltmgr.sys", "ndis.sys", "storport.sys"]) {
      const info = detectDriver(fakePE({ imports: [lib(module, ["SomeExport"])] }));
      expect(info.isDriver, module).toBe(true);
      expect(info.kernelModules, module).toEqual([module]);
    }
  });

  it("accumulates every reason", () => {
    const info = detectDriver(
      fakePE({
        subsystem: 1,
        dllCharacteristics: 0x2000,
        imports: [lib("ntoskrnl.exe", ["IoCreateDevice"])],
      }),
    );
    expect(info.reasons).toHaveLength(3);
  });
});

describe("getApiRiskTag", () => {
  it("tags known suspicious kernel APIs with a category", () => {
    expect(getApiRiskTag("MmMapIoSpace")?.category).toBe("Memory");
    expect(getApiRiskTag("PsSetLoadImageNotifyRoutine")?.category).toBe("Callback/Hook");
    expect(getApiRiskTag("ZwCreateFile")?.category).toBe("Filesystem");
    expect(getApiRiskTag("WskSocket")?.category).toBe("Network");
    expect(getApiRiskTag("ObReferenceObjectByHandle")?.category).toBe("Object");
    expect(getApiRiskTag("ZwOpenKey")?.category).toBe("Registry");
  });

  it("returns a Tailwind class pair for every tagged API", () => {
    const tag = getApiRiskTag("PsCreateSystemThread");
    expect(tag?.colorClass).toMatch(/^text-\w+-400 bg-\w+-900\/30$/);
  });

  it("returns null for unknown and near-miss names", () => {
    expect(getApiRiskTag("memcpy")).toBeNull();
    expect(getApiRiskTag("")).toBeNull();
    expect(getApiRiskTag("mmmapiospace")).toBeNull(); // lookup is case-sensitive
    expect(getApiRiskTag("toString")).toBeNull(); // Map, not a bare object
  });
});

describe("decodeIOCTL", () => {
  it("decodes a real IOCTL_DISK_GET_DRIVE_GEOMETRY code", () => {
    // CTL_CODE(FILE_DEVICE_DISK, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS)
    expect(decodeIOCTL(0x00070000)).toEqual({
      deviceType: 0x07,
      deviceTypeName: "DISK",
      access: 0,
      accessName: "ANY",
      function: 0,
      method: 0,
      methodName: "BUFFERED",
    });
  });

  it("decodes a storage query with a non-zero function code", () => {
    // CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
    const decoded = decodeIOCTL(0x002d1400);
    expect(decoded?.deviceTypeName).toBe("MASS_STORAGE");
    expect(decoded?.function).toBe(0x500);
    expect(decoded?.methodName).toBe("BUFFERED");
  });

  it("decodes vendor-custom device types above 0x8000", () => {
    // CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
    const value = ((0x8000 << 16) | (3 << 14) | (0x800 << 2) | 3) >>> 0;
    const decoded = decodeIOCTL(value);
    expect(decoded?.deviceType).toBe(0x8000);
    expect(decoded?.deviceTypeName).toBe("0x8000"); // unnamed: rendered as hex
    expect(decoded?.accessName).toBe("READ|WRITE");
    expect(decoded?.function).toBe(0x800);
    expect(decoded?.methodName).toBe("NEITHER");
  });

  it("names every transfer method", () => {
    const names = [0, 1, 2, 3].map((m) => decodeIOCTL((0x07 << 16) | m)?.methodName);
    expect(names).toEqual(["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"]);
  });

  it("rejects values that cannot be IOCTL codes", () => {
    for (const value of [0, 1, 0xffff, 0x460000, 0x7fff0000]) {
      expect(isPlausibleIOCTL(value), `0x${value.toString(16)}`).toBe(false);
      expect(decodeIOCTL(value), `0x${value.toString(16)}`).toBeNull();
    }
  });

  it("rejects device types between the known and custom ranges", () => {
    // 0x46..0x7FFF is neither a documented device type nor the custom range.
    expect(isPlausibleIOCTL((0x46 << 16) | 0x4)).toBe(false);
    expect(isPlausibleIOCTL(((0x7fff << 16) | 0x4) >>> 0)).toBe(false);
    expect(isPlausibleIOCTL(((0x8000 << 16) | 0x4) >>> 0)).toBe(true);
  });

  it("does not throw on non-finite input", () => {
    expect(decodeIOCTL(Number.NaN)).toBeNull();
    expect(decodeIOCTL(-1)).toBeNull();
    expect(decodeIOCTL(Number.MAX_SAFE_INTEGER)).toBeNull();
  });

  it("formats a decoded code and returns null for an implausible one", () => {
    expect(formatIOCTL(0x00070000)).toBe("IOCTL: DISK | Fn=0x0 | BUFFERED");
    expect(formatIOCTL(0x002d1400)).toBe("IOCTL: MASS_STORAGE | Fn=0x500 | BUFFERED");
    expect(formatIOCTL(0x1234)).toBeNull();
  });
});

describe("detectIRPDispatches", () => {
  const insn = (address: number, mnemonic: string, opStr: string): Instruction => ({
    address,
    bytes: new Uint8Array(0),
    mnemonic,
    opStr,
    size: 4,
  });

  it("recovers x64 dispatch entries from MajorFunction writes", () => {
    // DriverObject->MajorFunction[IRP_MJ_CREATE] is at +0x70 on x64, and each
    // slot is a pointer.
    const found = detectIRPDispatches(
      [
        insn(0x1000, "mov", "qword ptr [rcx + 0x70], 0x140001000"),
        insn(0x1008, "mov", "qword ptr [rcx + 0x78], 0x140002000"), // IRP_MJ_CREATE_NAMED_PIPE
        insn(0x1010, "mov", "qword ptr [rcx + 0x80], rax"), // IRP_MJ_CLOSE, register source
        insn(0x1018, "mov", "qword ptr [rcx + 0xe0], rdx"), // IRP_MJ_DEVICE_CONTROL
      ],
      true,
    );

    expect(found.map((f) => f.irpName)).toEqual([
      "IRP_MJ_CREATE",
      "IRP_MJ_CREATE_NAMED_PIPE",
      "IRP_MJ_CLOSE",
      "IRP_MJ_DEVICE_CONTROL",
    ]);
    expect(found[0]).toEqual({
      irpMajor: 0,
      irpName: "IRP_MJ_CREATE",
      handlerAddress: 0x140001000,
      instructionAddress: 0x1000,
    });
    // A register source leaves the handler unknown rather than guessing.
    expect(found[2].handlerAddress).toBe(0);
  });

  it("uses the 32-bit table layout when is64 is false", () => {
    // x86: MajorFunction starts at +0x38 with 4-byte slots, so +0x38 and +0x70
    // mean different IRPs than they do on x64.
    const found = detectIRPDispatches(
      [
        insn(0x1000, "mov", "dword ptr [ecx + 0x38], 0x401000"),
        insn(0x1006, "mov", "dword ptr [ecx + 0x70], 0x402000"),
      ],
      false,
    );
    expect(found.map((f) => f.irpName)).toEqual(["IRP_MJ_CREATE", "IRP_MJ_DEVICE_CONTROL"]);
  });

  it("ignores offsets outside or misaligned within the table", () => {
    const found = detectIRPDispatches(
      [
        insn(0x1000, "mov", "qword ptr [rcx + 0x68], rax"), // before the table
        insn(0x1008, "mov", "qword ptr [rcx + 0x74], rax"), // misaligned
        insn(0x1010, "mov", "qword ptr [rcx + 0x150], rax"), // past the table
        insn(0x1018, "lea", "rax, [rcx + 0x70]"), // not a mov
        insn(0x1020, "mov", "rax, rcx"), // no memory operand
      ],
      true,
    );
    expect(found).toEqual([]);
  });

  it("keeps only the first write to a given IRP slot", () => {
    const found = detectIRPDispatches(
      [
        insn(0x1000, "mov", "qword ptr [rcx + 0x70], 0x140001000"),
        insn(0x1008, "mov", "qword ptr [rdx + 0x70], 0x140009000"),
      ],
      true,
    );
    expect(found).toHaveLength(1);
    expect(found[0].handlerAddress).toBe(0x140001000);
  });

  it("covers the whole IRP_MJ range and stops at IRP_MJ_PNP", () => {
    const instructions: Instruction[] = [];
    for (let i = 0; i <= 0x1d; i++) {
      instructions.push(
        insn(0x1000 + i * 8, "mov", `qword ptr [rcx + 0x${(0x70 + i * 8).toString(16)}], rax`),
      );
    }
    const found = detectIRPDispatches(instructions, true);
    // 0x00..0x1B are defined; 0x1C and 0x1D are past the end of the table.
    expect(found).toHaveLength(0x1c);
    expect(found[found.length - 1].irpName).toBe("IRP_MJ_PNP");
    expect(Object.keys(IRP_MAJOR_FUNCTIONS)).toHaveLength(0x1c);
  });

  it("returns nothing for an empty instruction list", () => {
    expect(detectIRPDispatches([], true)).toEqual([]);
    expect(detectIRPDispatches([], false)).toEqual([]);
  });
});
