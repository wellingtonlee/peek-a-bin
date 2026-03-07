import type { DecompType } from './typeInfer';

export interface ApiFuncType {
  returnType: DecompType;
  params: DecompType[];
}

// ── Type shorthands ──
const PVOID: DecompType = { kind: 'ptr', pointee: { kind: 'unknown' } };
const PCHAR: DecompType = { kind: 'ptr', pointee: { kind: 'int', size: 1, signed: true } };
const PWCHAR: DecompType = { kind: 'ptr', pointee: { kind: 'int', size: 2, signed: false } };
const DWORD: DecompType = { kind: 'int', size: 4, signed: false };
const INT32: DecompType = { kind: 'int', size: 4, signed: true };
const SIZE_T: DecompType = { kind: 'int', size: 8, signed: false };
const BOOL_T: DecompType = { kind: 'bool' };
const VOID_T: DecompType = { kind: 'void' };
const HANDLE_T: DecompType = { kind: 'handle' };
const NTSTATUS_T: DecompType = { kind: 'ntstatus' };
const HRESULT_T: DecompType = { kind: 'hresult' };
const PDWORD: DecompType = { kind: 'ptr', pointee: DWORD };

/** Map of well-known Win32/C API function names → type signatures. */
export const API_TYPES: Record<string, ApiFuncType> = {
  // ── Memory ──
  VirtualAlloc: { returnType: PVOID, params: [PVOID, SIZE_T, DWORD, DWORD] },
  VirtualFree: { returnType: BOOL_T, params: [PVOID, SIZE_T, DWORD] },
  VirtualProtect: { returnType: BOOL_T, params: [PVOID, SIZE_T, DWORD, PDWORD] },
  VirtualQuery: { returnType: SIZE_T, params: [PVOID, PVOID, SIZE_T] },
  malloc: { returnType: PVOID, params: [SIZE_T] },
  calloc: { returnType: PVOID, params: [SIZE_T, SIZE_T] },
  realloc: { returnType: PVOID, params: [PVOID, SIZE_T] },
  free: { returnType: VOID_T, params: [PVOID] },
  memcpy: { returnType: PVOID, params: [PVOID, PVOID, SIZE_T] },
  memset: { returnType: PVOID, params: [PVOID, INT32, SIZE_T] },
  memmove: { returnType: PVOID, params: [PVOID, PVOID, SIZE_T] },
  memcmp: { returnType: INT32, params: [PVOID, PVOID, SIZE_T] },

  // ── String ──
  strlen: { returnType: SIZE_T, params: [PCHAR] },
  strcmp: { returnType: INT32, params: [PCHAR, PCHAR] },
  strncmp: { returnType: INT32, params: [PCHAR, PCHAR, SIZE_T] },
  strcpy: { returnType: PCHAR, params: [PCHAR, PCHAR] },
  strncpy: { returnType: PCHAR, params: [PCHAR, PCHAR, SIZE_T] },
  strcat: { returnType: PCHAR, params: [PCHAR, PCHAR] },
  strchr: { returnType: PCHAR, params: [PCHAR, INT32] },
  strstr: { returnType: PCHAR, params: [PCHAR, PCHAR] },
  lstrcpyA: { returnType: PCHAR, params: [PCHAR, PCHAR] },
  lstrcpyW: { returnType: PWCHAR, params: [PWCHAR, PWCHAR] },
  lstrcmpA: { returnType: INT32, params: [PCHAR, PCHAR] },
  lstrcmpW: { returnType: INT32, params: [PWCHAR, PWCHAR] },
  lstrlenA: { returnType: INT32, params: [PCHAR] },
  lstrlenW: { returnType: INT32, params: [PWCHAR] },
  wcslen: { returnType: SIZE_T, params: [PWCHAR] },
  wcscpy: { returnType: PWCHAR, params: [PWCHAR, PWCHAR] },
  wcsncpy: { returnType: PWCHAR, params: [PWCHAR, PWCHAR, SIZE_T] },
  wcscmp: { returnType: INT32, params: [PWCHAR, PWCHAR] },
  MultiByteToWideChar: { returnType: INT32, params: [DWORD, DWORD, PCHAR, INT32, PWCHAR, INT32] },
  WideCharToMultiByte: { returnType: INT32, params: [DWORD, DWORD, PWCHAR, INT32, PCHAR, INT32, PCHAR, PVOID] },
  RtlInitUnicodeString: { returnType: VOID_T, params: [PVOID, PWCHAR] },

  // ── File I/O ──
  CreateFileA: { returnType: HANDLE_T, params: [PCHAR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE_T] },
  CreateFileW: { returnType: HANDLE_T, params: [PWCHAR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE_T] },
  ReadFile: { returnType: BOOL_T, params: [HANDLE_T, PVOID, DWORD, PDWORD, PVOID] },
  WriteFile: { returnType: BOOL_T, params: [HANDLE_T, PVOID, DWORD, PDWORD, PVOID] },
  CloseHandle: { returnType: BOOL_T, params: [HANDLE_T] },
  DeleteFileA: { returnType: BOOL_T, params: [PCHAR] },
  DeleteFileW: { returnType: BOOL_T, params: [PWCHAR] },
  MoveFileA: { returnType: BOOL_T, params: [PCHAR, PCHAR] },
  MoveFileW: { returnType: BOOL_T, params: [PWCHAR, PWCHAR] },
  CopyFileA: { returnType: BOOL_T, params: [PCHAR, PCHAR, BOOL_T] },
  CopyFileW: { returnType: BOOL_T, params: [PWCHAR, PWCHAR, BOOL_T] },
  FindFirstFileA: { returnType: HANDLE_T, params: [PCHAR, PVOID] },
  FindFirstFileW: { returnType: HANDLE_T, params: [PWCHAR, PVOID] },
  FindNextFileA: { returnType: BOOL_T, params: [HANDLE_T, PVOID] },
  FindNextFileW: { returnType: BOOL_T, params: [HANDLE_T, PVOID] },
  FindClose: { returnType: BOOL_T, params: [HANDLE_T] },
  GetFileSize: { returnType: DWORD, params: [HANDLE_T, PDWORD] },
  GetFileSizeEx: { returnType: BOOL_T, params: [HANDLE_T, PVOID] },
  SetFilePointer: { returnType: DWORD, params: [HANDLE_T, INT32, PVOID, DWORD] },
  GetTempPathA: { returnType: DWORD, params: [DWORD, PCHAR] },
  GetTempPathW: { returnType: DWORD, params: [DWORD, PWCHAR] },
  CreateDirectoryA: { returnType: BOOL_T, params: [PCHAR, PVOID] },
  CreateDirectoryW: { returnType: BOOL_T, params: [PWCHAR, PVOID] },

  // ── Module/Proc ──
  GetProcAddress: { returnType: PVOID, params: [HANDLE_T, PCHAR] },
  LoadLibraryA: { returnType: HANDLE_T, params: [PCHAR] },
  LoadLibraryW: { returnType: HANDLE_T, params: [PWCHAR] },
  LoadLibraryExA: { returnType: HANDLE_T, params: [PCHAR, HANDLE_T, DWORD] },
  LoadLibraryExW: { returnType: HANDLE_T, params: [PWCHAR, HANDLE_T, DWORD] },
  FreeLibrary: { returnType: BOOL_T, params: [HANDLE_T] },
  GetModuleHandleA: { returnType: HANDLE_T, params: [PCHAR] },
  GetModuleHandleW: { returnType: HANDLE_T, params: [PWCHAR] },
  GetModuleFileNameA: { returnType: DWORD, params: [HANDLE_T, PCHAR, DWORD] },
  GetModuleFileNameW: { returnType: DWORD, params: [HANDLE_T, PWCHAR, DWORD] },

  // ── Process/Thread ──
  ExitProcess: { returnType: VOID_T, params: [DWORD] },
  TerminateProcess: { returnType: BOOL_T, params: [HANDLE_T, DWORD] },
  GetCurrentProcess: { returnType: HANDLE_T, params: [] },
  GetCurrentProcessId: { returnType: DWORD, params: [] },
  GetCurrentThread: { returnType: HANDLE_T, params: [] },
  GetCurrentThreadId: { returnType: DWORD, params: [] },
  OpenProcess: { returnType: HANDLE_T, params: [DWORD, BOOL_T, DWORD] },
  CreateThread: { returnType: HANDLE_T, params: [PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD] },
  CreateRemoteThread: { returnType: HANDLE_T, params: [HANDLE_T, PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD] },
  ExitThread: { returnType: VOID_T, params: [DWORD] },
  ResumeThread: { returnType: DWORD, params: [HANDLE_T] },
  SuspendThread: { returnType: DWORD, params: [HANDLE_T] },
  Sleep: { returnType: VOID_T, params: [DWORD] },
  SleepEx: { returnType: DWORD, params: [DWORD, BOOL_T] },

  // ── Error ──
  GetLastError: { returnType: DWORD, params: [] },
  SetLastError: { returnType: VOID_T, params: [DWORD] },

  // ── Heap ──
  HeapAlloc: { returnType: PVOID, params: [HANDLE_T, DWORD, SIZE_T] },
  HeapFree: { returnType: BOOL_T, params: [HANDLE_T, DWORD, PVOID] },
  HeapReAlloc: { returnType: PVOID, params: [HANDLE_T, DWORD, PVOID, SIZE_T] },
  HeapSize: { returnType: SIZE_T, params: [HANDLE_T, DWORD, PVOID] },
  GetProcessHeap: { returnType: HANDLE_T, params: [] },
  HeapCreate: { returnType: HANDLE_T, params: [DWORD, SIZE_T, SIZE_T] },
  HeapDestroy: { returnType: BOOL_T, params: [HANDLE_T] },
  LocalAlloc: { returnType: PVOID, params: [DWORD, SIZE_T] },
  LocalFree: { returnType: PVOID, params: [PVOID] },
  GlobalAlloc: { returnType: PVOID, params: [DWORD, SIZE_T] },
  GlobalFree: { returnType: PVOID, params: [PVOID] },

  // ── Registry ──
  RegOpenKeyExA: { returnType: INT32, params: [HANDLE_T, PCHAR, DWORD, DWORD, PVOID] },
  RegOpenKeyExW: { returnType: INT32, params: [HANDLE_T, PWCHAR, DWORD, DWORD, PVOID] },
  RegCloseKey: { returnType: INT32, params: [HANDLE_T] },
  RegQueryValueExA: { returnType: INT32, params: [HANDLE_T, PCHAR, PDWORD, PDWORD, PVOID, PDWORD] },
  RegQueryValueExW: { returnType: INT32, params: [HANDLE_T, PWCHAR, PDWORD, PDWORD, PVOID, PDWORD] },
  RegSetValueExA: { returnType: INT32, params: [HANDLE_T, PCHAR, DWORD, DWORD, PVOID, DWORD] },
  RegSetValueExW: { returnType: INT32, params: [HANDLE_T, PWCHAR, DWORD, DWORD, PVOID, DWORD] },
  RegCreateKeyExA: { returnType: INT32, params: [HANDLE_T, PCHAR, DWORD, PCHAR, DWORD, DWORD, PVOID, PVOID, PDWORD] },
  RegDeleteValueA: { returnType: INT32, params: [HANDLE_T, PCHAR] },
  RegDeleteValueW: { returnType: INT32, params: [HANDLE_T, PWCHAR] },

  // ── Synchronization ──
  CreateMutexA: { returnType: HANDLE_T, params: [PVOID, BOOL_T, PCHAR] },
  CreateMutexW: { returnType: HANDLE_T, params: [PVOID, BOOL_T, PWCHAR] },
  OpenMutexA: { returnType: HANDLE_T, params: [DWORD, BOOL_T, PCHAR] },
  OpenMutexW: { returnType: HANDLE_T, params: [DWORD, BOOL_T, PWCHAR] },
  ReleaseMutex: { returnType: BOOL_T, params: [HANDLE_T] },
  CreateEventA: { returnType: HANDLE_T, params: [PVOID, BOOL_T, BOOL_T, PCHAR] },
  CreateEventW: { returnType: HANDLE_T, params: [PVOID, BOOL_T, BOOL_T, PWCHAR] },
  SetEvent: { returnType: BOOL_T, params: [HANDLE_T] },
  ResetEvent: { returnType: BOOL_T, params: [HANDLE_T] },
  WaitForSingleObject: { returnType: DWORD, params: [HANDLE_T, DWORD] },
  WaitForMultipleObjects: { returnType: DWORD, params: [DWORD, PVOID, BOOL_T, DWORD] },
  InitializeCriticalSection: { returnType: VOID_T, params: [PVOID] },
  EnterCriticalSection: { returnType: VOID_T, params: [PVOID] },
  LeaveCriticalSection: { returnType: VOID_T, params: [PVOID] },
  DeleteCriticalSection: { returnType: VOID_T, params: [PVOID] },
  CreateSemaphoreA: { returnType: HANDLE_T, params: [PVOID, INT32, INT32, PCHAR] },
  CreateSemaphoreW: { returnType: HANDLE_T, params: [PVOID, INT32, INT32, PWCHAR] },
  ReleaseSemaphore: { returnType: BOOL_T, params: [HANDLE_T, INT32, PVOID] },

  // ── Exception/SEH ──
  RaiseException: { returnType: VOID_T, params: [DWORD, DWORD, DWORD, PVOID] },
  SetUnhandledExceptionFilter: { returnType: PVOID, params: [PVOID] },
  AddVectoredExceptionHandler: { returnType: PVOID, params: [DWORD, PVOID] },
  RemoveVectoredExceptionHandler: { returnType: DWORD, params: [PVOID] },

  // ── Crypto ──
  CryptAcquireContextA: { returnType: BOOL_T, params: [PVOID, PCHAR, PCHAR, DWORD, DWORD] },
  CryptAcquireContextW: { returnType: BOOL_T, params: [PVOID, PWCHAR, PWCHAR, DWORD, DWORD] },
  CryptReleaseContext: { returnType: BOOL_T, params: [HANDLE_T, DWORD] },
  CryptGenRandom: { returnType: BOOL_T, params: [HANDLE_T, DWORD, PVOID] },
  CryptCreateHash: { returnType: BOOL_T, params: [HANDLE_T, DWORD, HANDLE_T, DWORD, PVOID] },
  CryptHashData: { returnType: BOOL_T, params: [HANDLE_T, PVOID, DWORD, DWORD] },
  CryptDeriveKey: { returnType: BOOL_T, params: [HANDLE_T, DWORD, HANDLE_T, DWORD, PVOID] },
  CryptEncrypt: { returnType: BOOL_T, params: [HANDLE_T, HANDLE_T, BOOL_T, DWORD, PVOID, PDWORD, DWORD] },
  CryptDecrypt: { returnType: BOOL_T, params: [HANDLE_T, HANDLE_T, BOOL_T, DWORD, PVOID, PDWORD] },
  CryptDestroyHash: { returnType: BOOL_T, params: [HANDLE_T] },
  CryptDestroyKey: { returnType: BOOL_T, params: [HANDLE_T] },
  BCryptOpenAlgorithmProvider: { returnType: NTSTATUS_T, params: [PVOID, PWCHAR, PWCHAR, DWORD] },
  BCryptCloseAlgorithmProvider: { returnType: NTSTATUS_T, params: [HANDLE_T, DWORD] },
  BCryptGenRandom: { returnType: NTSTATUS_T, params: [HANDLE_T, PVOID, DWORD, DWORD] },

  // ── COM ──
  CoInitialize: { returnType: HRESULT_T, params: [PVOID] },
  CoInitializeEx: { returnType: HRESULT_T, params: [PVOID, DWORD] },
  CoUninitialize: { returnType: VOID_T, params: [] },
  CoCreateInstance: { returnType: HRESULT_T, params: [PVOID, PVOID, DWORD, PVOID, PVOID] },
  CoTaskMemAlloc: { returnType: PVOID, params: [SIZE_T] },
  CoTaskMemFree: { returnType: VOID_T, params: [PVOID] },
  SysAllocString: { returnType: PWCHAR, params: [PWCHAR] },
  SysFreeString: { returnType: VOID_T, params: [PWCHAR] },
  SysStringLen: { returnType: DWORD, params: [PWCHAR] },

  // ── NT/Zw ──
  NtQueryInformationProcess: { returnType: NTSTATUS_T, params: [HANDLE_T, DWORD, PVOID, DWORD, PDWORD] },
  NtQuerySystemInformation: { returnType: NTSTATUS_T, params: [DWORD, PVOID, DWORD, PDWORD] },
  NtCreateFile: { returnType: NTSTATUS_T, params: [PVOID, DWORD, PVOID, PVOID, PVOID, DWORD, DWORD, DWORD, DWORD, PVOID, DWORD] },
  NtClose: { returnType: NTSTATUS_T, params: [HANDLE_T] },
  NtAllocateVirtualMemory: { returnType: NTSTATUS_T, params: [HANDLE_T, PVOID, SIZE_T, PVOID, DWORD, DWORD] },
  NtFreeVirtualMemory: { returnType: NTSTATUS_T, params: [HANDLE_T, PVOID, PVOID, DWORD] },
  NtWriteVirtualMemory: { returnType: NTSTATUS_T, params: [HANDLE_T, PVOID, PVOID, SIZE_T, PVOID] },
  NtReadVirtualMemory: { returnType: NTSTATUS_T, params: [HANDLE_T, PVOID, PVOID, SIZE_T, PVOID] },
  RtlAllocateHeap: { returnType: PVOID, params: [HANDLE_T, DWORD, SIZE_T] },
  RtlFreeHeap: { returnType: BOOL_T, params: [HANDLE_T, DWORD, PVOID] },
  ZwQueryInformationProcess: { returnType: NTSTATUS_T, params: [HANDLE_T, DWORD, PVOID, DWORD, PDWORD] },
  ZwClose: { returnType: NTSTATUS_T, params: [HANDLE_T] },

  // ── Network ──
  WSAStartup: { returnType: INT32, params: [DWORD, PVOID] },
  WSACleanup: { returnType: INT32, params: [] },
  WSAGetLastError: { returnType: INT32, params: [] },
  socket: { returnType: SIZE_T, params: [INT32, INT32, INT32] },
  connect: { returnType: INT32, params: [SIZE_T, PVOID, INT32] },
  bind: { returnType: INT32, params: [SIZE_T, PVOID, INT32] },
  listen: { returnType: INT32, params: [SIZE_T, INT32] },
  accept: { returnType: SIZE_T, params: [SIZE_T, PVOID, PVOID] },
  send: { returnType: INT32, params: [SIZE_T, PCHAR, INT32, INT32] },
  recv: { returnType: INT32, params: [SIZE_T, PCHAR, INT32, INT32] },
  sendto: { returnType: INT32, params: [SIZE_T, PCHAR, INT32, INT32, PVOID, INT32] },
  recvfrom: { returnType: INT32, params: [SIZE_T, PCHAR, INT32, INT32, PVOID, PVOID] },
  closesocket: { returnType: INT32, params: [SIZE_T] },
  select: { returnType: INT32, params: [INT32, PVOID, PVOID, PVOID, PVOID] },
  getaddrinfo: { returnType: INT32, params: [PCHAR, PCHAR, PVOID, PVOID] },
  freeaddrinfo: { returnType: VOID_T, params: [PVOID] },
  gethostbyname: { returnType: PVOID, params: [PCHAR] },
  inet_addr: { returnType: DWORD, params: [PCHAR] },
  inet_ntoa: { returnType: PCHAR, params: [DWORD] },
  htons: { returnType: { kind: 'int', size: 2, signed: false }, params: [{ kind: 'int', size: 2, signed: false }] },
  ntohs: { returnType: { kind: 'int', size: 2, signed: false }, params: [{ kind: 'int', size: 2, signed: false }] },
  InternetOpenA: { returnType: HANDLE_T, params: [PCHAR, DWORD, PCHAR, PCHAR, DWORD] },
  InternetOpenW: { returnType: HANDLE_T, params: [PWCHAR, DWORD, PWCHAR, PWCHAR, DWORD] },
  InternetConnectA: { returnType: HANDLE_T, params: [HANDLE_T, PCHAR, { kind: 'int', size: 2, signed: false }, PCHAR, PCHAR, DWORD, DWORD, SIZE_T] },
  InternetCloseHandle: { returnType: BOOL_T, params: [HANDLE_T] },
  HttpOpenRequestA: { returnType: HANDLE_T, params: [HANDLE_T, PCHAR, PCHAR, PCHAR, PCHAR, PVOID, DWORD, SIZE_T] },
  HttpSendRequestA: { returnType: BOOL_T, params: [HANDLE_T, PCHAR, DWORD, PVOID, DWORD] },
  InternetReadFile: { returnType: BOOL_T, params: [HANDLE_T, PVOID, DWORD, PDWORD] },

  // ── Misc ──
  OutputDebugStringA: { returnType: VOID_T, params: [PCHAR] },
  OutputDebugStringW: { returnType: VOID_T, params: [PWCHAR] },
  IsDebuggerPresent: { returnType: BOOL_T, params: [] },
  QueryPerformanceCounter: { returnType: BOOL_T, params: [PVOID] },
  QueryPerformanceFrequency: { returnType: BOOL_T, params: [PVOID] },
  GetTickCount: { returnType: DWORD, params: [] },
  GetTickCount64: { returnType: { kind: 'int', size: 8, signed: false }, params: [] },
  GetSystemTimeAsFileTime: { returnType: VOID_T, params: [PVOID] },
  GetCommandLineA: { returnType: PCHAR, params: [] },
  GetCommandLineW: { returnType: PWCHAR, params: [] },
  GetEnvironmentVariableA: { returnType: DWORD, params: [PCHAR, PCHAR, DWORD] },
  GetEnvironmentVariableW: { returnType: DWORD, params: [PWCHAR, PWCHAR, DWORD] },
  GetSystemDirectoryA: { returnType: DWORD, params: [PCHAR, DWORD] },
  GetSystemDirectoryW: { returnType: DWORD, params: [PWCHAR, DWORD] },
  GetWindowsDirectoryA: { returnType: DWORD, params: [PCHAR, DWORD] },
  GetWindowsDirectoryW: { returnType: DWORD, params: [PWCHAR, DWORD] },

  // ── Device I/O ──
  DeviceIoControl: { returnType: BOOL_T, params: [HANDLE_T, DWORD, PVOID, DWORD, PVOID, DWORD, PDWORD, PVOID] },
  IoCreateDevice: { returnType: NTSTATUS_T, params: [PVOID, DWORD, PVOID, DWORD, DWORD, BOOL_T, PVOID] },
  IoDeleteDevice: { returnType: VOID_T, params: [PVOID] },
  IoCreateSymbolicLink: { returnType: NTSTATUS_T, params: [PVOID, PVOID] },
  IofCompleteRequest: { returnType: VOID_T, params: [PVOID, { kind: 'int', size: 1, signed: true }] },
};
