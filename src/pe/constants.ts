/**
 * PE Format Constants
 * Machine types, section flags, data directory indices, subsystems
 */

// Machine Types
export const IMAGE_FILE_MACHINE_I386 = 0x14c;
export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const IMAGE_FILE_MACHINE_ARM = 0x1c0;
export const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
export const IMAGE_FILE_MACHINE_IA64 = 0x200;

export const MachineTypes: Record<number, string> = {
  [IMAGE_FILE_MACHINE_I386]: 'x86',
  [IMAGE_FILE_MACHINE_AMD64]: 'x64',
  [IMAGE_FILE_MACHINE_ARM]: 'ARM',
  [IMAGE_FILE_MACHINE_ARM64]: 'ARM64',
  [IMAGE_FILE_MACHINE_IA64]: 'IA64',
};

// Section Characteristics
export const IMAGE_SCN_CNT_CODE = 0x00000020;
export const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
export const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
export const IMAGE_SCN_LNK_INFO = 0x00000200;
export const IMAGE_SCN_LNK_REMOVE = 0x00000800;
export const IMAGE_SCN_LNK_COMDAT = 0x00001000;
export const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
export const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
export const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
export const IMAGE_SCN_MEM_SHARED = 0x10000000;
export const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
export const IMAGE_SCN_MEM_READ = 0x40000000;
export const IMAGE_SCN_MEM_WRITE = 0x80000000;

export function sectionCharacteristicsToString(flags: number): string {
  const parts: string[] = [];

  if (flags & IMAGE_SCN_CNT_CODE) parts.push('CODE');
  if (flags & IMAGE_SCN_CNT_INITIALIZED_DATA) parts.push('INIT_DATA');
  if (flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) parts.push('UNINIT_DATA');
  if (flags & IMAGE_SCN_MEM_EXECUTE) parts.push('X');
  if (flags & IMAGE_SCN_MEM_READ) parts.push('R');
  if (flags & IMAGE_SCN_MEM_WRITE) parts.push('W');
  if (flags & IMAGE_SCN_MEM_DISCARDABLE) parts.push('DISCARD');
  if (flags & IMAGE_SCN_MEM_SHARED) parts.push('SHARED');
  if (flags & IMAGE_SCN_LNK_COMDAT) parts.push('COMDAT');

  return parts.join(' | ');
}

// Data Directory Indices
export const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
export const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
export const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
export const IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
export const IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
export const IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
export const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
export const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
export const IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
export const IMAGE_DIRECTORY_ENTRY_TLS = 9;
export const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
export const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
export const IMAGE_DIRECTORY_ENTRY_IAT = 12;
export const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
export const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

export const DataDirectoryNames: Record<number, string> = {
  [IMAGE_DIRECTORY_ENTRY_EXPORT]: 'Export Table',
  [IMAGE_DIRECTORY_ENTRY_IMPORT]: 'Import Table',
  [IMAGE_DIRECTORY_ENTRY_RESOURCE]: 'Resource Table',
  [IMAGE_DIRECTORY_ENTRY_EXCEPTION]: 'Exception Table',
  [IMAGE_DIRECTORY_ENTRY_SECURITY]: 'Certificate Table',
  [IMAGE_DIRECTORY_ENTRY_BASERELOC]: 'Base Relocation Table',
  [IMAGE_DIRECTORY_ENTRY_DEBUG]: 'Debug',
  [IMAGE_DIRECTORY_ENTRY_ARCHITECTURE]: 'Architecture',
  [IMAGE_DIRECTORY_ENTRY_GLOBALPTR]: 'Global Ptr',
  [IMAGE_DIRECTORY_ENTRY_TLS]: 'TLS Table',
  [IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]: 'Load Config Table',
  [IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]: 'Bound Import',
  [IMAGE_DIRECTORY_ENTRY_IAT]: 'IAT',
  [IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]: 'Delay Import Descriptor',
  [IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]: 'CLR Runtime Header',
};

// Subsystem
export const IMAGE_SUBSYSTEM_NATIVE = 1;
export const IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
export const IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;
export const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9;
export const IMAGE_SUBSYSTEM_EFI_APPLICATION = 10;
export const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11;
export const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12;
export const IMAGE_SUBSYSTEM_EFI_ROM = 13;
export const IMAGE_SUBSYSTEM_XBOX = 14;

export const SubsystemNames: Record<number, string> = {
  [IMAGE_SUBSYSTEM_NATIVE]: 'Native',
  [IMAGE_SUBSYSTEM_WINDOWS_GUI]: 'Windows GUI',
  [IMAGE_SUBSYSTEM_WINDOWS_CUI]: 'Windows CUI',
  [IMAGE_SUBSYSTEM_WINDOWS_CE_GUI]: 'Windows CE GUI',
  [IMAGE_SUBSYSTEM_EFI_APPLICATION]: 'EFI Application',
  [IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER]: 'EFI Boot Service Driver',
  [IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER]: 'EFI Runtime Driver',
  [IMAGE_SUBSYSTEM_EFI_ROM]: 'EFI ROM',
  [IMAGE_SUBSYSTEM_XBOX]: 'Xbox',
};

// Optional Header Magic
export const IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
export const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

// DOS Header Magic
export const IMAGE_DOS_SIGNATURE = 0x5a4d; // "MZ"

// PE Signature
export const IMAGE_NT_SIGNATURE = 0x4550; // "PE\0\0"

// Import Flags
export const IMAGE_ORDINAL_FLAG32 = 0x80000000;
export const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n;
