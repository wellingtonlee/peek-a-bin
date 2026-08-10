import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { API_TYPES } from "../apitypes";
import { typeToString, type DecompType } from "../typeInfer";

const entries = Object.entries(API_TYPES);
const names = Object.keys(API_TYPES);

const LATTICE_KINDS = new Set([
  "unknown",
  "int",
  "float",
  "ptr",
  "bool",
  "void",
  "struct",
  "array",
  "handle",
  "ntstatus",
  "hresult",
  "enum",
]);

function everyType(t: DecompType, fn: (t: DecompType) => void): void {
  fn(t);
  if (t.kind === "ptr") everyType(t.pointee, fn);
  if (t.kind === "array") everyType(t.element, fn);
}

/** Collapse wchar_t* → char* so an A/W pair can be compared structurally. */
function narrowChars(t: DecompType): DecompType {
  if (t.kind === "ptr") {
    if (t.pointee.kind === "int" && t.pointee.size === 2 && !t.pointee.signed) {
      return { kind: "ptr", pointee: { kind: "int", size: 1, signed: true } };
    }
    return { kind: "ptr", pointee: narrowChars(t.pointee) };
  }
  return t;
}

function returnKinds(pred: (name: string) => boolean): string[] {
  return entries.filter(([n]) => pred(n)).map(([, t]) => t.returnType.kind);
}

describe("API_TYPES table", () => {
  it("has no duplicate keys in the source literal", () => {
    // A duplicate key would be silently overwritten at runtime, so count the
    // declarations in the file rather than trusting the built object.
    const src = readFileSync(fileURLToPath(new URL("../apitypes.ts", import.meta.url)), "utf8");
    const body = src.slice(src.indexOf("export const API_TYPES"));
    // Match the key alone. Requiring `{ returnType:` on the same line assumed
    // one entry per line, which a formatter breaks the moment an entry passes
    // the line-width limit and gets wrapped.
    const declared = [...body.matchAll(/^ {2}(\w+): \{/gm)].map((m) => m[1]);
    const dupes = declared.filter((n, i) => declared.indexOf(n) !== i);
    expect(dupes).toEqual([]);
    expect(declared.length).toBe(names.length);
  });

  it("holds a substantial table", () => {
    // 209 entries at the time of writing — a large drop means the literal was
    // truncated by a bad merge rather than deliberately pruned.
    expect(names.length).toBeGreaterThan(150);
  });

  it("uses only kinds from the type lattice", () => {
    for (const [name, sig] of entries) {
      everyType(sig.returnType, (t) =>
        expect(LATTICE_KINDS.has(t.kind), `${name} return`).toBe(true),
      );
      for (const p of sig.params) {
        everyType(p, (t) => expect(LATTICE_KINDS.has(t.kind), `${name} param`).toBe(true));
      }
    }
  });

  it("never declares a void parameter", () => {
    for (const [name, sig] of entries) {
      expect(
        sig.params.map((p) => p.kind),
        name,
      ).not.toContain("void");
    }
  });

  it("gives every int type a concrete power-of-two size", () => {
    for (const [name, sig] of entries) {
      const check = (t: DecompType) => {
        if (t.kind === "int")
          expect([1, 2, 4, 8], `${name}: ${JSON.stringify(t)}`).toContain(t.size);
      };
      everyType(sig.returnType, check);
      for (const p of sig.params) everyType(p, check);
    }
  });

  it("emits a C-style string for every declared type", () => {
    for (const [name, sig] of entries) {
      expect(typeToString(sig.returnType), name).toBeTruthy();
      for (const p of sig.params) expect(typeToString(p), name).toBeTruthy();
    }
  });
});

describe("return type conventions", () => {
  it("returns NTSTATUS from every Nt*/Zw* API", () => {
    const kinds = returnKinds((n) => /^(Nt|Zw)[A-Z]/.test(n));
    expect(kinds.length).toBeGreaterThan(5);
    expect(new Set(kinds)).toEqual(new Set(["ntstatus"]));
  });

  it("returns NTSTATUS from every BCrypt* API", () => {
    const kinds = returnKinds((n) => n.startsWith("BCrypt"));
    expect(kinds.length).toBeGreaterThan(0);
    expect(new Set(kinds)).toEqual(new Set(["ntstatus"]));
  });

  it("returns BOOL from every legacy Crypt* API", () => {
    const kinds = returnKinds((n) => n.startsWith("Crypt"));
    expect(kinds.length).toBeGreaterThan(5);
    expect(new Set(kinds)).toEqual(new Set(["bool"]));
  });

  it("returns LSTATUS (int32) from every Reg* API", () => {
    const sigs = entries.filter(([n]) => n.startsWith("Reg"));
    expect(sigs.length).toBeGreaterThan(5);
    for (const [name, sig] of sigs) {
      expect(sig.returnType, name).toEqual({ kind: "int", size: 4, signed: true });
    }
  });

  it("reserves HRESULT for the COM entry points", () => {
    const hresultApis = entries.filter(([, t]) => t.returnType.kind === "hresult").map(([n]) => n);
    expect(hresultApis.sort()).toEqual(["CoCreateInstance", "CoInitialize", "CoInitializeEx"]);
  });

  it("only returns HANDLE from APIs that acquire one", () => {
    const handleApis = entries.filter(([, t]) => t.returnType.kind === "handle").map(([n]) => n);
    expect(handleApis.length).toBeGreaterThan(10);
    for (const name of handleApis) {
      expect(name, `${name} returns HANDLE`).toMatch(/(Create|Open|Get|Load|Find|Internet|Http)/);
    }
  });

  it("never returns HANDLE from a releasing API", () => {
    for (const [name, sig] of entries) {
      if (/^(Close|Free|Delete|Release|Destroy)/.test(name)) {
        expect(sig.returnType.kind, name).not.toBe("handle");
      }
    }
  });

  it("matches known handle-producing APIs", () => {
    for (const name of [
      "CreateFileW",
      "LoadLibraryA",
      "GetProcessHeap",
      "OpenProcess",
      "CreateThread",
    ]) {
      expect(API_TYPES[name].returnType, name).toEqual({ kind: "handle" });
    }
  });

  it("takes a HANDLE as the first argument of handle-consuming APIs", () => {
    const consumers = [
      "CloseHandle",
      "FindClose",
      "FindNextFileW",
      "ReadFile",
      "WriteFile",
      "GetFileSize",
      "SetFilePointer",
      "GetProcAddress",
      "FreeLibrary",
      "TerminateProcess",
      "ResumeThread",
      "SuspendThread",
      "RegCloseKey",
      "ReleaseMutex",
      "SetEvent",
      "WaitForSingleObject",
      "HeapAlloc",
      "HeapFree",
      "NtClose",
      "ZwClose",
      "InternetCloseHandle",
      "DeviceIoControl",
      "CryptReleaseContext",
    ];
    for (const name of consumers) {
      expect(API_TYPES[name], name).toBeDefined();
      expect(API_TYPES[name].params[0], name).toEqual({ kind: "handle" });
    }
  });
});

describe("ANSI/wide API pairs", () => {
  const pairs = names
    .filter((n) => n.endsWith("A") && API_TYPES[`${n.slice(0, -1)}W`])
    .map((n) => [n, `${n.slice(0, -1)}W`] as const);

  it("finds a meaningful number of pairs", () => {
    expect(pairs.length).toBeGreaterThan(15);
  });

  it("declares the same arity for both variants", () => {
    const mismatched = pairs.filter(
      ([a, w]) => API_TYPES[a].params.length !== API_TYPES[w].params.length,
    );
    expect(mismatched).toEqual([]);
  });

  it("declares matching types once char width is normalised", () => {
    const mismatched: string[] = [];
    for (const [a, w] of pairs) {
      const sa = API_TYPES[a];
      const sw = API_TYPES[w];
      if (
        JSON.stringify(narrowChars(sa.returnType)) !== JSON.stringify(narrowChars(sw.returnType))
      ) {
        mismatched.push(`${a}/${w} return`);
      }
      sa.params.forEach((p, i) => {
        const q = sw.params[i];
        if (q && JSON.stringify(narrowChars(p)) !== JSON.stringify(narrowChars(q))) {
          mismatched.push(`${a}/${w} param ${i}`);
        }
      });
    }
    expect(mismatched).toEqual([]);
  });

  it("never declares a narrow char* in a *W API", () => {
    // A wide API that still mentions char* is a copy-paste that forgot to widen.
    const offenders: string[] = [];
    for (const name of names.filter((n) => /[a-z]W$/.test(n))) {
      const sig = API_TYPES[name];
      const strs = [sig.returnType, ...sig.params].map(typeToString);
      if (strs.includes("char*")) offenders.push(name);
    }
    expect(offenders).toEqual([]);
  });

  it("never declares a wide wchar_t* in an *A API", () => {
    const offenders: string[] = [];
    for (const name of names.filter((n) => /[a-z]A$/.test(n))) {
      const sig = API_TYPES[name];
      const strs = [sig.returnType, ...sig.params].map(typeToString);
      if (strs.includes("wchar_t*")) offenders.push(name);
    }
    expect(offenders).toEqual([]);
  });
});

describe("parameter counts match the documented Win32/NT prototypes", () => {
  const ARITY: Record<string, number> = {
    VirtualAlloc: 4,
    VirtualFree: 3,
    VirtualProtect: 4,
    memcpy: 3,
    memset: 3,
    strlen: 1,
    strncmp: 3,
    CreateFileA: 7,
    ReadFile: 5,
    WriteFile: 5,
    CloseHandle: 1,
    GetProcAddress: 2,
    LoadLibraryExA: 3,
    OpenProcess: 3,
    CreateThread: 6,
    CreateRemoteThread: 7,
    GetLastError: 0,
    GetCurrentProcess: 0,
    HeapAlloc: 3,
    RegOpenKeyExA: 5,
    RegQueryValueExA: 6,
    RegCreateKeyExA: 9,
    WaitForSingleObject: 2,
    WaitForMultipleObjects: 4,
    MultiByteToWideChar: 6,
    WideCharToMultiByte: 8,
    CoCreateInstance: 5,
    CoInitializeEx: 2,
    CryptEncrypt: 7,
    CryptDecrypt: 6,
    BCryptGenRandom: 4,
    NtCreateFile: 11,
    NtAllocateVirtualMemory: 6,
    NtQuerySystemInformation: 4,
    DeviceIoControl: 8,
    IoCreateDevice: 7,
    WSAStartup: 2,
    socket: 3,
    connect: 3,
    send: 4,
    recvfrom: 6,
    select: 5,
    getaddrinfo: 4,
    InternetOpenA: 5,
    HttpOpenRequestA: 8,
    InternetReadFile: 4,
    Sleep: 1,
  };

  for (const [name, count] of Object.entries(ARITY)) {
    it(`${name} takes ${count} parameter${count === 1 ? "" : "s"}`, () => {
      expect(API_TYPES[name]).toBeDefined();
      expect(API_TYPES[name].params).toHaveLength(count);
    });
  }
});
