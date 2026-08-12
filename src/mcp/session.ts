/**
 * Multi-file session state for the MCP server.
 * Manages loaded PE files and their analysis results.
 */

import { type Anomaly, detectAnomalies } from "../analysis/anomalies";
import { type DriverInfo, detectDriver } from "../analysis/driver";
import { archForMachine, type ImageArch } from "../disasm/arch";
import { buildDataWindows } from "../disasm/dataWindows";
import { StructRegistry } from "../disasm/decompile/structs";
import { buildIATLookup } from "../disasm/operands";
import { jumpTableTargets } from "../disasm/seeds";
import type { DisasmFunction, Instruction, Xref } from "../disasm/types";
import { extractStrings, parsePE } from "../pe/parser";
import { dataSectionRanges, findCodeSection } from "../pe/sections";
import type { PEFile } from "../pe/types";
import {
  buildXrefMap,
  buildXrefs,
  detectFunctionsFromBytes,
  hybridDisassembleBytes,
  initCapstone,
} from "./disasm";

export interface AnalyzedFile {
  id: string;
  fileName: string;
  pe: PEFile;
  instructions: Instruction[];
  functions: DisasmFunction[];
  xrefMap: Map<number, Xref[]>;
  /**
   * Whole-image reference maps, each keyed by the address being referenced and
   * valued with the addresses of the instructions that reference it.
   *
   * `xrefMap` above is a different question: it is per-instruction, built from
   * the decoded operands of one instruction at a time, and answers "what points
   * at this code address". These four are the sweep the browser runs
   * (`disasmWorker.buildAllXrefs`) and answer "who uses this string / this
   * import / this data address", plus the call graph. They were computed by
   * `buildXrefs` and thrown away — nothing called it — so an MCP client saw none
   * of it.
   */
  stringXrefs: Map<number, number[]>;
  importXrefs: Map<number, number[]>;
  dataXrefs: Map<number, number[]>;
  /** Function entry → the entries it calls. */
  callGraph: Map<number, number[]>;
  iatMap: Map<number, { lib: string; func: string }>;
  stringMap: Map<number, string>;
  stringTypes: Map<number, "ascii" | "utf16le">;
  jumpTables: Map<number, number[]>;
  /**
   * The instruction set this image was analysed as, from `coffHeader.machine`.
   *
   * Not the same question as `pe.is64`. Consumers that run an x86-only stage —
   * the decompiler, the stack-frame analyser, operand parsing — must check this
   * and decline for anything but `"x86"`, because those stages produce
   * confident nonsense rather than an error when handed ARM64 instructions.
   *
   * `"unsupported"` — ARM32/Thumb, IA-64, RISC-V, MIPS — is the third answer,
   * and it is not a decoder but the absence of one: `instructions` and
   * `functions` are empty for such an image and the xref maps hold nothing,
   * while everything the PE parser produces is as complete as ever. A check
   * that already reads `arch !== "x86"` covers it without change.
   */
  arch: ImageArch;
  anomalies: Anomaly[];
  driverInfo: DriverInfo;
  structRegistry: StructRegistry;
  /** text section bytes + base for disassembly */
  textBytes: Uint8Array;
  textBase: number;
  /** Annotations — string address keys for ExportSchemaV1 compat */
  comments: Record<string, string>;
  renames: Record<string, string>;
  bookmarks: { address: number; label: string }[];
}

export class FileSession {
  files = new Map<string, AnalyzedFile>();
  onAnnotationChange?: (fileId: string, af: AnalyzedFile) => void;

  async loadFile(id: string, fileName: string, buffer: ArrayBuffer): Promise<AnalyzedFile> {
    await initCapstone();

    // 1. Parse PE
    const pe = parsePE(buffer);
    const imageBase = pe.optionalHeader.imageBase;
    const is64 = pe.is64;
    // `is64` is the PE32+ magic — a pointer width. The machine type is what
    // says which decoder to open; an ARM64 image is PE32+ too, and picking by
    // `is64` alone disassembled it as x86-64 and produced nothing at all.
    const arch = archForMachine(pe.coffHeader.machine);

    // 2. Build IAT lookup
    const iatMap = buildIATLookup(pe.imports);

    // 3. Extract strings
    const { strings: stringMap, stringTypes } = extractStrings(
      buffer,
      pe.sections,
      imageBase,
      is64,
    );

    // 4. Detect driver mode
    const driverInfo = detectDriver(pe);
    const driverMode = driverInfo.isDriver;

    // 5. Find text section
    const textSection = findCodeSection(pe.sections);

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
    const pdataFunctions = pe.runtimeFunctions?.map((rf) => ({
      beginAddress: imageBase + rf.beginAddress,
      endAddress: imageBase + rf.endAddress,
    }));
    const handlerAddresses = pe.runtimeFunctions
      ?.filter((rf) => rf.handlerAddress !== undefined)
      .map((rf) => imageBase + rf.handlerAddress!);

    const detectResult = detectFunctionsFromBytes(
      textBytes,
      textBase,
      is64,
      arch,
      stringMap,
      iatMap,
      driverMode,
      {
        exports: pe.exports.map((e) => ({ name: e.name, address: e.address })),
        entryPoint: imageBase + pe.optionalHeader.addressOfEntryPoint,
        pdataFunctions,
        handlerAddresses,
        // `.rdata` and the other readable data sections. Without them an x64
        // switch is invisible: the compiler puts its RVA table there, so the
        // detector can recover the dispatch chain and still read no entries.
        // Views onto `buffer`, so this copies nothing.
        dataWindows: buildDataWindows(buffer, pe.sections, imageBase),
      },
    );
    const functions = detectResult.functions;
    const jumpTables = new Map(detectResult.jumpTables);

    // 7. Hybrid disassemble
    //
    // Jump-table targets are seeds as well as function starts. The recursive
    // descent gives up at an indirect `jmp`, so without them the case bodies of
    // a switch are reached only by phase 2's linear gap fill — and where MSVC
    // puts the table immediately before its first case body (the normal x86
    // layout) that sweep starts *on the table*, walks off its end misaligned
    // and swallows the head of case 0. `seeds` is only a BFS work queue, so
    // adding a target here starts a decode at the right address without
    // claiming it is a function.
    const seeds = [...functions.map((f) => f.address), ...jumpTableTargets(jumpTables)];
    // Not called at all for an image this engine has no decoder for.
    //
    // `hybridDisassembleBytes` and `buildXrefs` *throw* for such an image, and
    // deliberately: their entire output is instructions, so a short or empty
    // return is the silent-failure mode peek-a-bin-cen removed. But a throw
    // here would fail the whole load, and everything above this point is
    // correct for an ARM32 image — headers, sections, imports, exports,
    // resources, the entropy and driver analysis, and the strings. Losing all
    // of that to say "no disassembler" is a worse answer than saying it while
    // keeping it. `arch` on the returned file is how a consumer tells this
    // apart from an image that genuinely has no code (peek-a-bin-x7b).
    const decodable = arch !== "unsupported";
    const instructions = decodable
      ? hybridDisassembleBytes(
          textBytes,
          textBase,
          is64,
          arch,
          seeds,
          stringMap,
          iatMap,
          driverMode,
          pdataFunctions,
        )
      : [];

    // 8. Build xref map
    //
    // Bounded by the image the optional header describes. `buildTypedXrefMap`'s
    // fallback arm reads any large `0x…` operand token as a data reference, so
    // without these two numbers `or edx, 0xffffffff` and `cmp dword ptr [rax],
    // 0xc0000005` were reported to MCP clients as references to addresses that
    // do not exist in the file — 305 of t64.exe's 856 data xrefs, 318 of
    // t32.exe's 881 (peek-a-bin-jfp). Every in-image reference is unaffected.
    const xrefEntries = buildXrefMap(instructions, {
      base: imageBase,
      size: pe.optionalHeader.sizeOfImage,
    });
    const xrefMap = new Map(xrefEntries);

    // 8b. Whole-image xrefs: string, import and data references plus the call
    // graph. The browser has had these since it existed (App.tsx calls
    // `disasmWorker.buildAllXrefs`); on this side `buildXrefs` was written and
    // then never called, so `get_xrefs` answered with per-instruction refs only
    // and no MCP client could ask who used a string or an import.
    //
    // Cost, measured through this function on the five real test images (median
    // of 5): 72/74/57 ms on t32/t64/w64 against a 389/297/264 ms load, and — with
    // `instructions` handed over so the A64 sweep is not repeated — 19/16 ms on
    // t64-arm/w64-arm against 475/334 ms. Roughly a fifth of a load on x86 and a
    // twentieth on ARM64, for four maps the client otherwise cannot obtain at
    // all: there is no tool that would let it rebuild them.
    const iatAddrs: number[] = [];
    for (const imp of pe.imports) {
      for (const addr of imp.iatAddresses) iatAddrs.push(addr);
    }
    const allXrefs = !decodable
      ? // Same reasoning as step 7: `buildXrefs` throws rather than report four
        // empty maps, so it is not called. These four *are* empty, and honestly
        // so — there are no instructions to read a reference out of.
        { stringXrefs: [], importXrefs: [], dataXrefs: [], callGraph: [] }
      : buildXrefs(
          textBytes,
          textBase,
          is64,
          arch,
          Array.from(stringMap.keys()),
          iatAddrs,
          functions.map((f) => [f.address, f.size] as [number, number]),
          dataSectionRanges(pe.sections, imageBase),
          // ARM64 only, and the reason that arch is the cheap one here: the sweep
          // this would otherwise redo is the one step 7 just did over the same bytes
          // at the same base. Handing the array over costs nothing without a worker
          // boundary in the way.
          instructions,
        );

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
      stringXrefs: new Map(allXrefs.stringXrefs),
      importXrefs: new Map(allXrefs.importXrefs),
      dataXrefs: new Map(allXrefs.dataXrefs),
      callGraph: new Map(allXrefs.callGraph),
      iatMap,
      stringMap,
      stringTypes,
      jumpTables,
      arch,
      anomalies,
      driverInfo,
      structRegistry,
      textBytes,
      textBase,
      comments: {},
      renames: {},
      bookmarks: [],
    };

    this.files.set(id, analyzed);
    return analyzed;
  }

  getFile(id: string): AnalyzedFile | undefined {
    return this.files.get(id);
  }

  listFiles(): { id: string; fileName: string }[] {
    return Array.from(this.files.values()).map((f) => ({ id: f.id, fileName: f.fileName }));
  }

  removeFile(id: string): boolean {
    return this.files.delete(id);
  }

  setComment(fileId: string, address: number, text: string): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    af.comments[String(address)] = text;
    this.onAnnotationChange?.(fileId, af);
    return true;
  }

  deleteComment(fileId: string, address: number): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    delete af.comments[String(address)];
    this.onAnnotationChange?.(fileId, af);
    return true;
  }

  setRename(fileId: string, address: number, name: string): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    af.renames[String(address)] = name;
    this.onAnnotationChange?.(fileId, af);
    return true;
  }

  deleteRename(fileId: string, address: number): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    delete af.renames[String(address)];
    this.onAnnotationChange?.(fileId, af);
    return true;
  }

  addBookmark(fileId: string, address: number, label: string): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    af.bookmarks.push({ address, label });
    this.onAnnotationChange?.(fileId, af);
    return true;
  }

  removeBookmark(fileId: string, address: number): boolean {
    const af = this.files.get(fileId);
    if (!af) return false;
    af.bookmarks = af.bookmarks.filter((b) => b.address !== address);
    this.onAnnotationChange?.(fileId, af);
    return true;
  }
}
