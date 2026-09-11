/**
 * Multi-file session state for the MCP server.
 * Manages loaded PE files and their analysis results.
 */

import { type Anomaly, detectAnomalies } from "../analysis/anomalies";
import { type DriverInfo, detectDriver } from "../analysis/driver";
import { archForMachine, type ImageArch } from "../disasm/arch";
import { buildCallSummaries, type CalleeClobbers } from "../disasm/callSummary";
import { recogniseCrtIdioms } from "../disasm/crtIdioms";
import { buildDataWindows } from "../disasm/dataWindows";
import type { NamingContext } from "../disasm/decompile/naming";
import { StructRegistry } from "../disasm/decompile/structs";
import { buildFuncInsnMap } from "../disasm/funcInsns";
import { buildIATLookup } from "../disasm/operands";
import { jumpTableTargets } from "../disasm/seeds";
import type { DisasmFunction, Instruction, Xref } from "../disasm/types";
import { extractStrings, parsePE } from "../pe/parser";
import { dataSectionRanges, dataSectionTable, findCodeSection } from "../pe/sections";
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
  /**
   * What each detected function is known to write, closed over the call graph —
   * `disasm/callSummary.ts`. Handed to `decompileFunction`, where it is the
   * evidence `clobberedByCall` unions with the argument registers it already
   * reports.
   *
   * Empty on anything but `"x86"`: the scan reads x86 mnemonics, so on ARM64 it
   * would recognise nothing and report nothing, and every stage that could use
   * it declines on that architecture anyway.
   */
  calleeClobbers: CalleeClobbers;
  /**
   * What the emitter names a dereferenced constant address from — the data
   * section table, the IAT and the load config's cookie address
   * (`decompile/naming.ts`). Built once per file from `pe` and handed to every
   * `decompileFunction` this session and `corpus/sweep.ts` make, so the MCP
   * server and the harness name globals from one table.
   */
  naming: NamingContext;
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
    const {
      strings: stringMap,
      stringTypes,
      stringScan,
    } = extractStrings(buffer, pe.sections, imageBase, is64);
    // Recorded on `pe`, because `pe` is what every consumer of this session
    // reads — `parseAdmissions` turns it into the sentence `load_pe` and
    // `pe://{id}/strings` print, and without it both state a clipped list's
    // length as a fact about the file. Assigned rather than spread because this
    // object is local to the load and is the one the AnalyzedFile below holds;
    // the browser's reducer replaces instead, for its own reason
    // (peek-a-bin-2py5).
    if (stringScan) pe.stringScan = stringScan;

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
        // `ExportEntry.address` is an **RVA** (see its docstring in
        // `pe/types.ts`), and every address in this bag is a **VA** — the
        // `entryPoint` on the next line converts, and so do `pdataFunctions`
        // and `handlerAddresses` above. This one did not, for as long as the
        // option has existed, so every export seed landed outside
        // `[textBase, textBase + len)` and the detector dropped it: no seed and
        // no name, on the MCP path AND on `npm run corpus`, which loads through
        // this same `FileSession`. The browser converts correctly in
        // `App.tsx`, so the harness and the app were detecting functions from
        // different seed sets — invisible because all six corpus binaries are
        // EXEs with zero exports and no DLL exists on this machine
        // (peek-a-bin-j4uk.2).
        exports: pe.exports.map((e) => ({ name: e.name, address: imageBase + e.address })),
        entryPoint: imageBase + pe.optionalHeader.addressOfEntryPoint,
        pdataFunctions,
        handlerAddresses,
        // Already VAs, so NO arithmetic — the opposite of the line above, and
        // the reason both are commented: `parseTLSDirectory` keeps the callback
        // array's pointers as the format writes them, image-based.
        tlsCallbacks: pe.tlsDirectory?.callbacks,
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
          // The bytes of the tables those targets came out of. Seeding the case
          // bodies starts the decode in the right places; this stops phase 2
          // from decoding the table itself as instructions (peek-a-bin-y1di).
          detectResult.jumpTableSpans,
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

    // 8c. Per-callee written-register summaries, closed over the call graph.
    //
    // Computed here rather than inside `decompileFunction` because it is
    // interprocedural and that function is handed one function's instructions:
    // the callee's body is not in scope there, which is the whole reason the
    // ABI set was ever used as a stand-in (peek-a-bin-hj1). A whole-image pass
    // over `funcInsnMap` costs one walk of the instruction stream.
    //
    // `unresolved` is deliberately empty. An import, an indirect call and a
    // jump into unrecovered code are callees whose body this analysis never
    // read, and the ABI's volatile set is what such a callee is *permitted* to
    // destroy rather than an observation of what it does — which is precisely
    // the assumption hj1's measurements refuted. Measured both ways over the
    // corpus: the ABI answer moved the emitted C by 7 lines and 2 clobbered
    // reads per x64 binary, so it buys nothing that would justify re-admitting
    // it. See `corpus/README.md`.
    //
    // The CRT idiom map rides beside it (`crtIdioms.ts`): the same pass, the
    // same `funcInsnMap`, and the same consumer — a `call` in the lifter — so
    // that the MCP server, `corpus/sweep.ts` and the browser
    // (`CallSummaryCache.forToken`) all answer "does this callee define the
    // accumulator" from one recogniser. Built for both widths, since the `/GS`
    // check is an x86 routine too.
    const funcInsnMap = arch === "x86" ? buildFuncInsnMap(functions, instructions) : undefined;
    const calleeClobbers: CalleeClobbers = {
      // Both widths, as before: the PE32 closure is unread by the lifter but is
      // the `callee summaries` liveness row `corpus/sweep.ts` reports.
      byAddress: funcInsnMap
        ? buildCallSummaries({
            functionAddresses: functions.map((f) => f.address),
            funcInsnMap,
            iatMap,
          })
        : new Map(),
      unresolved: [],
      idioms: funcInsnMap ? recogniseCrtIdioms(funcInsnMap, is64) : undefined,
    };

    // 8d. The naming evidence for the emitter — see `decompile/naming.ts`.
    const naming: NamingContext = {
      dataRanges: dataSectionTable(pe.sections, imageBase),
      iatMap,
      securityCookie: pe.loadConfig?.securityCookie,
    };

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
      calleeClobbers,
      naming,
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
