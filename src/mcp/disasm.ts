/**
 * Capstone wrapper for Node.js (no Web Worker, no IndexedDB caching).
 * Used by the MCP server for direct disassembly.
 */

import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { type ImageArch, unsupportedArchMessage } from "../disasm/arch";
import { type Arm64Context, detectArm64Functions, disassembleArm64 } from "../disasm/arm64";
import { buildArm64Xrefs } from "../disasm/arm64Xref";
import type { DataWindow } from "../disasm/dataWindows";
import {
  buildAllXrefs,
  buildTypedXrefMap,
  type DetectResult,
  type DisasmContext,
  detectFunctions,
  disassemble,
  hybridDisassemble,
  type ImageBounds,
} from "../disasm/functionDetect";
import type { Instruction, Xref } from "../disasm/types";

let cs32: any;
let cs64: any;
let csArm64: any;
let initialized = false;

export async function initCapstone(): Promise<void> {
  if (initialized) return;
  await loadCapstone();
  cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  // One more handle on the same WASM module — `Capstone` is a `cs_open`, not a
  // second engine, so this costs no extra download and no measurable time.
  csArm64 = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
  initialized = true;
}

function makeCtx(
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): DisasmContext {
  return { cs32, cs64, stringMap, iatMap, driverMode };
}

function makeArm64Ctx(
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): Arm64Context {
  return { cs: csArm64, stringMap, iatMap, driverMode };
}

export function disassembleBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  arch: ImageArch,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): Instruction[] {
  // Refuse rather than invent, for the reason `arch.ts` documents: an x86
  // linear sweep decodes essentially any byte string, so an ARM32/Thumb image
  // came back as a screenful of plausible instructions that were pure fiction,
  // with no coverage signal to notice it by. This whole return value is
  // instructions, so a short or empty answer would be the same silent failure
  // peek-a-bin-cen removed (peek-a-bin-x7b).
  if (arch === "unsupported") throw new Error(unsupportedArchMessage("Disassembly"));
  if (arch === "arm64") {
    return disassembleArm64(bytes, baseAddress, makeArm64Ctx(stringMap, iatMap, driverMode));
  }
  return disassemble(bytes, baseAddress, is64, makeCtx(stringMap, iatMap, driverMode));
}

export function detectFunctionsFromBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  arch: ImageArch,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: { beginAddress: number; endAddress: number }[];
    handlerAddresses?: number[];
    /**
     * Readable spans outside the code section — `.rdata` above all — so the
     * x64 RVA jump tables that live there can be read. Built by
     * `buildDataWindows`; passed straight through, since there is no worker
     * boundary on this path and nothing to pack.
     */
    dataWindows?: DataWindow[];
  },
) {
  // Keeps answering rather than throwing, unlike its neighbours — that is the
  // contract `DetectResult.omitted` states, and the reason is that detection's
  // evidence is mostly not instructions. Here there is none of it left: every
  // pass x86 detection has is an x86 pass, and `pdata.ts` reads extents for
  // ARM64 and x64 only, so an ARMNT image has no `.pdata` function boundaries
  // either. Empty with all four passes named is the true answer; throwing would
  // fail `FileSession.loadFile` outright and throw away the headers, imports,
  // exports and strings this tool *does* read correctly for such an image.
  if (arch === "unsupported") {
    return {
      functions: [],
      jumpTables: [],
      jumpTableSpans: [],
      omitted: ["call-targets", "jump-tables", "thunk-names", "tail-calls"],
    } satisfies DetectResult;
  }
  if (arch === "arm64") {
    return detectArm64Functions(
      bytes,
      baseAddress,
      makeArm64Ctx(stringMap, iatMap, driverMode),
      options,
    );
  }
  return detectFunctions(bytes, baseAddress, is64, makeCtx(stringMap, iatMap, driverMode), options);
}

export function hybridDisassembleBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  arch: ImageArch,
  seeds: number[],
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
  pdataRanges?: { beginAddress: number; endAddress: number }[],
  jumpTableSpans?: [number, number][],
): Instruction[] {
  if (arch === "unsupported") throw new Error(unsupportedArchMessage("Disassembly"));
  if (arch === "arm64") {
    // No seeds: recursive descent is what resolves a variable-length encoding's
    // ambiguous boundaries, and A64 has none. See disassembleArm64.
    return disassembleArm64(
      bytes,
      baseAddress,
      makeArm64Ctx(stringMap, iatMap, driverMode),
      pdataRanges,
    );
  }
  return hybridDisassemble(
    bytes,
    baseAddress,
    is64,
    seeds,
    makeCtx(stringMap, iatMap, driverMode),
    pdataRanges,
    jumpTableSpans,
  );
}

/**
 * Per-instruction reference map.
 *
 * `imageBounds` is where the loader maps the image, and it bounds one arm of
 * `buildTypedXrefMap` only: the fallback scan that reads any large `0x…` token
 * in an operand as a data reference. Without it that arm reports bitmasks and
 * sentinels as references to addresses the image does not contain — 305 of
 * t64.exe's 856 data xrefs, 318 of t32.exe's 881 (peek-a-bin-jfp). Optional
 * here for the same reason it is optional there: a caller that does not know
 * where the image is has not said that everything is in range.
 */
export function buildXrefMap(
  instructions: Instruction[],
  imageBounds?: ImageBounds,
): [number, Xref[]][] {
  return buildTypedXrefMap(instructions, imageBounds);
}

export function buildXrefs(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  arch: ImageArch,
  stringAddrs: number[],
  iatAddrs: number[],
  funcEntries?: [number, number][],
  dataSections?: { va: number; size: number }[],
  /**
   * The caller's decode of exactly `bytes` at exactly `baseAddress`, when it has
   * one. ARM64 only: it is what `buildArm64Xrefs` takes, so supplying it skips a
   * second sweep of `.text` (measured 155 ms on t64-arm.exe, 121 ms on
   * w64-arm.exe). Ignored on x86, where `buildAllXrefs` owns its own decode.
   *
   * There is no worker boundary on this path, so this costs nothing to pass —
   * the array is handed over by reference. That is exactly why the browser's
   * worker cannot do the same; see `src/workers/transfer.ts`.
   */
  instructions?: Instruction[],
) {
  // Every xref here is read out of a decoded instruction, so with no decoder
  // there is nothing to read — and the x86 grammar over non-x86 bytes does not
  // fail, it reports references that are not there.
  if (arch === "unsupported") throw new Error(unsupportedArchMessage("Cross-reference analysis"));
  if (arch === "arm64") {
    // buildAllXrefs is an x86 operand grammar end to end — `[rip ± 0x..]`,
    // `mov reg, imm`, `call 0x…`. Run over ARM64 bytes it would not fail, it
    // would report references that are not there. An ARM64 reference is an
    // adrp/add or adrp/ldr pair, so this goes to the A64 reader instead.
    //
    // That reader takes decoded instructions; without `instructions` the sweep
    // is redone here from the bytes, exactly as the x86 branch below re-decodes
    // them inside `buildAllXrefs`. Empty annotation maps: they only set
    // `Instruction.comment`, which no xref looks at.
    const insns =
      instructions ??
      disassembleArm64(bytes, baseAddress, makeArm64Ctx(new Map(), new Map(), false));
    return buildArm64Xrefs(insns, stringAddrs, iatAddrs, funcEntries, dataSections);
  }
  const cs = is64 ? cs64 : cs32;
  return buildAllXrefs(
    bytes,
    baseAddress,
    is64,
    stringAddrs,
    iatAddrs,
    cs,
    funcEntries,
    dataSections,
  );
}

export { cs32, cs64 };
