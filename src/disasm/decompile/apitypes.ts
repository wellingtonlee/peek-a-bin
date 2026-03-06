import type { DecompType } from './typeInfer';

export interface ApiFuncType {
  returnType: DecompType;
  params: DecompType[];
}

/** Map of well-known Win32/C API function names → type signatures. */
export const API_TYPES: Record<string, ApiFuncType> = {
  // Memory
  VirtualAlloc: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 8, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
    ],
  },
  VirtualFree: {
    returnType: { kind: 'bool' },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 8, signed: false },
      { kind: 'int', size: 4, signed: false },
    ],
  },
  VirtualProtect: {
    returnType: { kind: 'bool' },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 8, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'int', size: 4, signed: false } },
    ],
  },
  malloc: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'int', size: 8, signed: false }],
  },
  calloc: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'int', size: 8, signed: false }, { kind: 'int', size: 8, signed: false }],
  },
  realloc: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'ptr', pointee: { kind: 'unknown' } }, { kind: 'int', size: 8, signed: false }],
  },
  free: {
    returnType: { kind: 'void' },
    params: [{ kind: 'ptr', pointee: { kind: 'unknown' } }],
  },
  memcpy: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 8, signed: false },
    ],
  },
  memset: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: true },
      { kind: 'int', size: 8, signed: false },
    ],
  },
  memmove: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 8, signed: false },
    ],
  },
  strlen: {
    returnType: { kind: 'int', size: 8, signed: false },
    params: [{ kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } }],
  },
  strcmp: {
    returnType: { kind: 'int', size: 4, signed: true },
    params: [
      { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } },
      { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } },
    ],
  },
  // File I/O
  CreateFileA: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  CreateFileW: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'int', size: 2, signed: false } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  ReadFile: {
    returnType: { kind: 'bool' },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'int', size: 4, signed: false } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  WriteFile: {
    returnType: { kind: 'bool' },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'int', size: 4, signed: false } },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  CloseHandle: {
    returnType: { kind: 'bool' },
    params: [{ kind: 'ptr', pointee: { kind: 'unknown' } }],
  },
  // Module/Proc
  GetProcAddress: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } },
    ],
  },
  LoadLibraryA: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } }],
  },
  LoadLibraryW: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'ptr', pointee: { kind: 'int', size: 2, signed: false } }],
  },
  GetModuleHandleA: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } }],
  },
  GetModuleHandleW: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [{ kind: 'ptr', pointee: { kind: 'int', size: 2, signed: false } }],
  },
  // Process/Thread
  ExitProcess: {
    returnType: { kind: 'void' },
    params: [{ kind: 'int', size: 4, signed: false }],
  },
  GetCurrentProcessId: {
    returnType: { kind: 'int', size: 4, signed: false },
    params: [],
  },
  GetLastError: {
    returnType: { kind: 'int', size: 4, signed: false },
    params: [],
  },
  SetLastError: {
    returnType: { kind: 'void' },
    params: [{ kind: 'int', size: 4, signed: false }],
  },
  // Heap
  HeapAlloc: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 8, signed: false },
    ],
  },
  HeapFree: {
    returnType: { kind: 'bool' },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  GetProcessHeap: {
    returnType: { kind: 'ptr', pointee: { kind: 'unknown' } },
    params: [],
  },
  // Registry
  RegOpenKeyExA: {
    returnType: { kind: 'int', size: 4, signed: true },
    params: [
      { kind: 'ptr', pointee: { kind: 'unknown' } },
      { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } },
      { kind: 'int', size: 4, signed: false },
      { kind: 'int', size: 4, signed: false },
      { kind: 'ptr', pointee: { kind: 'unknown' } },
    ],
  },
  RegCloseKey: {
    returnType: { kind: 'int', size: 4, signed: true },
    params: [{ kind: 'ptr', pointee: { kind: 'unknown' } }],
  },
};
