/**
 * Multi-file session state for the MCP server.
 * Manages loaded PE files and their analysis results.
 */

import { parsePE, extractStrings } from '../pe/parser';
import type { PEFile } from '../pe/types';
import type { Instruction, DisasmFunction, Xref } from '../disasm/types';
import { buildIATLookup } from '../disasm/operands';
import { detectAnomalies, type Anomaly } from '../analysis/anomalies';
import { detectDriver, type DriverInfo } from '../analysis/driver';
import { StructRegistry } from '../disasm/decompile/structs';
import {
  initCapstone,
  disassembleBytes,
  detectFunctionsFromBytes,
  hybridDisassembleBytes,
  buildXrefMap,
  buildXrefs,
} from './disasm';

export interface AnalyzedFile {
  id: string;
  fileName: string;
  pe: PEFile;
  instructions: Instruction[];
  functions: DisasmFunction[];
  xrefMap: Map<number, Xref[]>;
  iatMap: Map<number, { lib: string; func: string }>;
  stringMap: Map<number, string>;
  stringTypes: Map<number, 'ascii' | 'utf16le'>;
  jumpTables: Map<number, number[]>;
  anomalies: Anomaly[];
  driverInfo: DriverInfo;
  structRegistry: StructRegistry;
  /** text section bytes + base for disassembly */
  textBytes: Uint8Array;
  textBase: number;
}

export class FileSession {
  files = new Map<string, AnalyzedFile>();

  async loadFile(id: string, fileName: string, buffer: ArrayBuffer): Promise<AnalyzedFile> {
    await initCapstone();

    // 1. Parse PE
    const pe = parsePE(buffer);
    const imageBase = pe.optionalHeader.imageBase;
    const is64 = pe.is64;

    // 2. Build IAT lookup
    const iatMap = buildIATLookup(pe.imports);

    // 3. Extract strings
    const { strings: stringMap, stringTypes } = extractStrings(buffer, pe.sections, imageBase, is64);

    // 4. Detect driver mode
    const driverInfo = detectDriver(pe);
    const driverMode = driverInfo.isDriver;

    // 5. Find text section
    const textSection = pe.sections.find(
      s => s.name === '.text' || (s.characteristics & 0x20000000) !== 0,
    );

    let textBytes: Uint8Array;
    let textBase: number;
    if (textSection) {
      const start = textSection.pointerToRawData;
      const size = Math.min(textSection.sizeOfRawData, buffer.byteLength - start);
      textBytes = new Uint8Array(buffer, start, size);
      textBase = imageBase + textSection.virtualAddress;
    } else {
      // No text section — use entire buffer as fallback
      textBytes = new Uint8Array(buffer);
      textBase = imageBase;
    }

    // 6. Detect functions
    const pdataFunctions = pe.runtimeFunctions?.map(rf => ({
      beginAddress: imageBase + rf.beginAddress,
      endAddress: imageBase + rf.endAddress,
    }));
    const handlerAddresses = pe.runtimeFunctions
      ?.filter(rf => rf.handlerAddress !== undefined)
      .map(rf => imageBase + rf.handlerAddress!);

    const detectResult = detectFunctionsFromBytes(
      textBytes, textBase, is64, stringMap, iatMap, driverMode,
      {
        exports: pe.exports.map(e => ({ name: e.name, address: e.address })),
        entryPoint: imageBase + pe.optionalHeader.addressOfEntryPoint,
        pdataFunctions,
        handlerAddresses,
      },
    );
    const functions = detectResult.functions;
    const jumpTables = new Map(detectResult.jumpTables);

    // 7. Hybrid disassemble
    const seeds = functions.map(f => f.address);
    const instructions = hybridDisassembleBytes(
      textBytes, textBase, is64, seeds, stringMap, iatMap, driverMode,
      pdataFunctions,
    );

    // 8. Build xref map
    const xrefEntries = buildXrefMap(instructions);
    const xrefMap = new Map(xrefEntries);

    // 9. Detect anomalies
    const anomalies = detectAnomalies(pe);

    // 10. Create struct registry
    const structRegistry = new StructRegistry();

    const analyzed: AnalyzedFile = {
      id,
      fileName,
      pe,
      instructions,
      functions,
      xrefMap,
      iatMap,
      stringMap,
      stringTypes,
      jumpTables,
      anomalies,
      driverInfo,
      structRegistry,
      textBytes,
      textBase,
    };

    this.files.set(id, analyzed);
    return analyzed;
  }

  getFile(id: string): AnalyzedFile | undefined {
    return this.files.get(id);
  }

  listFiles(): { id: string; fileName: string }[] {
    return Array.from(this.files.values()).map(f => ({ id: f.id, fileName: f.fileName }));
  }

  removeFile(id: string): boolean {
    return this.files.delete(id);
  }
}
