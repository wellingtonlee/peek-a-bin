/**
 * The worker's RPC method dispatch, separated from the worker shell.
 *
 * `disasm.worker.ts` cannot be imported outside a worker: it touches `self` and
 * `indexedDB`, and it starts loading Capstone WASM at module evaluation time.
 * That left the dispatch — including the `default` branch that turns an unknown
 * method into an error instead of a silently-undefined reply — with no runtime
 * test at all. Everything here is importable and side-effect free at module
 * scope, so it can be driven directly; the WASM bootstrap stays in the worker.
 *
 * Nothing in this module's import graph reaches `capstone-wasm`: the Capstone
 * handles arrive through {@link WorkerState}, already constructed.
 */

import type { Instruction, DisasmFunction, Xref, StackFrame } from "../disasm/types";
import type { FunctionSignature } from "../disasm/signatures";
import { extractStrings } from "../pe/parser";
import type { SectionHeader } from "../pe/types";
import { decompileFunction } from "../disasm/decompile/pipeline";
import { StructRegistry } from "../disasm/decompile/structs";
import { detectIRPDispatches } from "../analysis/driver";
import {
  type ImageArch,
  archForMachine,
  unsupportedArchMessage,
  unsupportedOnArch,
} from "../disasm/arch";
import { unpackDataWindows } from "../disasm/dataWindows";
import { type Arm64Context, detectArm64Functions, disassembleArm64 } from "../disasm/arm64";
import { buildArm64Xrefs } from "../disasm/arm64Xref";
import {
  type DisasmContext,
  disassemble as _disassemble,
  detectFunctions as _detectFunctions,
  hybridDisassemble as _hybridDisassemble,
  buildTypedXrefMap,
  type DetectResult,
  buildAllXrefs as _buildAllXrefs,
} from "../disasm/functionDetect";

/**
 * Every method the worker answers.
 *
 * Adding a member here is a compile error until {@link dispatch} handles it —
 * see the `never` binding in its `default` branch.
 */
export type WorkerMethod =
  | "init"
  | "configure"
  | "configureDecompileMaps"
  | "disassemble"
  | "hybridDisassemble"
  | "detectFunctions"
  | "buildTypedXrefMap"
  | "buildAllXrefs"
  | "extractStrings"
  | "decompileFunction"
  | "detectIRPDispatches"
  | "resetStructRegistry";

export interface WorkerRequest {
  id: number;
  method: WorkerMethod;
  args: any;
}

/**
 * The worker's mutable session state. Owned by the worker module; passed in so
 * the dispatch itself holds nothing across calls.
 *
 * `structRegistry` deliberately persists between `decompileFunction` calls —
 * struct synthesis is cross-function — and is replaced only by `configure` and
 * `resetStructRegistry`.
 */
export interface WorkerState {
  /** Capstone handles, undefined until the WASM bootstrap finishes. */
  cs32: any;
  cs64: any;
  /** ARM64 handle. Same WASM module as the two above, just another `cs_open`. */
  csArm64: any;
  /**
   * Which decoder the loaded image needs, set by `configure` from the COFF
   * machine type. Defaults to `"x86"`, so a caller that never sends one gets
   * exactly the behaviour it had before ARM64 support existed.
   *
   * `"unsupported"` — ARM32/Thumb, IA-64, RISC-V, MIPS — is not a decoder but
   * the absence of one, and the methods below split on it *before* the ARM64
   * check so a new machine type can never fall through to the x86 path.
   */
  arch: ImageArch;
  stringMap: Map<number, string>;
  iatMap: Map<number, { lib: string; func: string }>;
  driverMode: boolean;
  funcMap: Map<number, { name: string; address: number }>;
  jumpTableMap: Map<number, number[]>;
  structRegistry: StructRegistry;
  /** Resolves once Capstone is ready; awaited by the `init` method. */
  ready: Promise<void>;
}

/** The state a freshly started worker begins with. */
export function createWorkerState(ready: Promise<void>): WorkerState {
  return {
    cs32: undefined,
    cs64: undefined,
    csArm64: undefined,
    arch: "x86",
    stringMap: new Map(),
    iatMap: new Map(),
    driverMode: false,
    funcMap: new Map(),
    jumpTableMap: new Map(),
    structRegistry: new StructRegistry(),
    ready,
  };
}

/** Build a DisasmContext from current worker state. */
function ctx(state: WorkerState): DisasmContext {
  return {
    cs32: state.cs32,
    cs64: state.cs64,
    stringMap: state.stringMap,
    iatMap: state.iatMap,
    driverMode: state.driverMode,
  };
}

/** The same, for the ARM64 path — one handle instead of a 32/64 pair. */
function armCtx(state: WorkerState): Arm64Context {
  return {
    cs: state.csArm64,
    stringMap: state.stringMap,
    iatMap: state.iatMap,
    driverMode: state.driverMode,
  };
}

/**
 * Run one RPC method. Resolves with the value to post back, or rejects — the
 * caller turns a rejection into an `{ id, error }` reply.
 */
export async function dispatch(
  method: WorkerMethod,
  args: any,
  state: WorkerState,
): Promise<unknown> {
  switch (method) {
    case "init":
      await state.ready;
      return true;

    case "configure":
      // Receive maps as entries arrays (Maps don't survive structured clone)
      state.stringMap = new Map(args.stringEntries);
      state.iatMap = new Map(args.iatEntries);
      if (args.driverMode !== undefined) state.driverMode = args.driverMode;
      // Only when told. `configure` is called more than once per file — the
      // second time from the effect that re-sends the strings once they have
      // been extracted, which knows nothing about the machine type — so a bare
      // assignment here would reset an ARM64 session to x86 mid-analysis.
      if (args.machine !== undefined) state.arch = archForMachine(args.machine);
      state.structRegistry = new StructRegistry();
      return true;

    case "configureDecompileMaps": {
      const fEntries: [number, { name: string; address: number }][] = args.funcEntries ?? [];
      state.funcMap = new Map(fEntries);
      const jtEntries: [number, number[]][] = args.jumpTableEntries ?? [];
      state.jumpTableMap = new Map(jtEntries);
      return true;
    }

    case "disassemble":
      // Refuse rather than invent. An x86 linear sweep decodes essentially any
      // byte string, so an ARM32 image came back as a full screen of plausible
      // instructions with no signal that any of it was fiction — the same
      // silent-failure shape peek-a-bin-cen removed from the Capstone-dead
      // path, and the reason this throws instead of returning a short list
      // (peek-a-bin-x7b).
      if (state.arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Disassembly"));
      }
      if (state.arch === "arm64") {
        return disassembleArm64(args.bytes, args.baseAddress, armCtx(state));
      }
      return _disassemble(args.bytes, args.baseAddress, args.is64, ctx(state));

    case "hybridDisassemble":
      if (state.arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Disassembly"));
      }
      if (state.arch === "arm64") {
        // Seeds are dropped deliberately. Recursive descent exists to resolve
        // the instruction boundaries a variable-length encoding leaves
        // ambiguous; A64 has none, so the linear sweep IS the answer, and it
        // covers the whole section rather than only what a BFS could reach.
        // `pdataRanges` still arrives, and marks which words the image itself
        // vouches for.
        return disassembleArm64(args.bytes, args.baseAddress, armCtx(state), args.pdataRanges);
      }
      return _hybridDisassemble(
        args.bytes,
        args.baseAddress,
        args.is64,
        args.seeds,
        ctx(state),
        args.pdataRanges,
      );

    case "detectFunctions": {
      // Answers, rather than throwing, for the reason `DetectResult.omitted`
      // documents: detection's evidence is mostly not instructions. But every
      // pass this architecture has *is* an x86 pass — the prologue byte tables,
      // the call-target scan, the `readRvaTable` jump-table reader, the thunk
      // and tail-call passes — and `pdata.ts` extracts no extents for anything
      // but ARM64 and x64, so there is nothing left to answer *with*. Empty
      // with every pass named beats a plausible list built from x86 byte
      // patterns found in ARM code (peek-a-bin-x7b).
      if (state.arch === "unsupported") {
        return {
          functions: [],
          jumpTables: [],
          omitted: ["call-targets", "jump-tables", "thunk-names", "tail-calls"],
        } satisfies DetectResult;
      }
      if (state.arch === "arm64") {
        // No jump-table reader on ARM64 — a `br` through a table is not the
        // pattern `readRvaTable` models — so the windows would go unread.
        return detectArm64Functions(args.bytes, args.baseAddress, armCtx(state), args.options);
      }
      // `.rdata` and friends arrive flattened (see ../disasm/dataWindows.ts):
      // one top-level buffer the client could transfer, plus its spans. Rebuilt
      // here as views into that buffer, which is what the detector's image
      // reader wants and costs no further copy.
      const dataWindows = unpackDataWindows(args.dataBytes, args.dataSpans);
      const options = dataWindows ? { ...args.options, dataWindows } : args.options;
      return _detectFunctions(args.bytes, args.baseAddress, args.is64, ctx(state), options);
    }

    case "buildTypedXrefMap":
      // `imageBounds` is `{ base, size }` from the optional header, two plain
      // numbers that survive structured clone as-is (nothing in ./transfer.ts
      // touches them — they are not binary). It bounds the fallback operand
      // scan, which otherwise reads bitmasks and sentinels as data references
      // to addresses outside the image; `undefined` keeps the old unbounded
      // behaviour for any caller that does not know where the image is.
      return buildTypedXrefMap(args.instructions, args.imageBounds);

    case "buildAllXrefs": {
      // Every xref here is read out of a decoded instruction, so with no
      // decoder there is no answer to give — and the x86 grammar handed ARM
      // bytes does not fail, it reports references that are not there.
      if (state.arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Cross-reference analysis"));
      }
      if (state.arch === "arm64") {
        // `_buildAllXrefs` is an x86 operand grammar from end to end —
        // `[rip ± 0x..]`, `mov reg, imm`, `call 0x…`. Over ARM64 bytes it does
        // not fail, it invents references. `buildArm64Xrefs` reads the real
        // thing: an adrp/add or adrp/ldr pair, plus `bl` for the call graph.
        //
        // It takes decoded instructions rather than bytes, and the sweep is
        // redone here from the bytes this call already carries — the same thing
        // the x86 branch does, which re-decodes the section inside
        // `buildAllXrefs`. Measured: 155 ms for t64-arm.exe's 110 KiB / 27428
        // instructions. Shipping the caller's `Instruction[]` instead would put
        // a per-instruction `bytes` view in every message, which is what
        // ./transfer.ts exists to keep out.
        //
        // The annotation maps are deliberately left empty for that sweep: they
        // only ever set `Instruction.comment`, and xrefs read nothing but
        // address, mnemonic and opStr.
        const insns = disassembleArm64(args.bytes, args.baseAddress, {
          cs: state.csArm64,
          stringMap: new Map(),
          iatMap: new Map(),
          driverMode: false,
        });
        return buildArm64Xrefs(
          insns,
          args.stringAddrs,
          args.iatAddrs,
          args.funcEntries,
          args.dataSections,
        );
      }
      const cs = args.is64 ? state.cs64 : state.cs32;
      return _buildAllXrefs(
        args.bytes,
        args.baseAddress,
        args.is64,
        args.stringAddrs,
        args.iatAddrs,
        cs,
        args.funcEntries,
        args.dataSections,
      );
    }

    case "extractStrings": {
      const { strings, stringTypes } = extractStrings(
        args.buffer,
        args.sections as SectionHeader[],
        args.imageBase,
        args.is64 as boolean | undefined,
      );
      return {
        strings: Array.from(strings.entries()),
        stringTypes: Array.from(stringTypes.entries()),
      };
    }

    case "detectIRPDispatches":
      // Matches `mov [reg + 0x70 + i*8], offset handler` in a driver's
      // DriverEntry — x86 mnemonics and x86 operand syntax. An ARM64 driver
      // stores its dispatch table with str/adrp and would simply never match,
      // so returning nothing here changes no answer; it just says so.
      // Same argument for an image with no decoder at all: it matches x86
      // mnemonics against instructions that are not x86, and there are none to
      // match against in the first place, since `disassemble` refused.
      if (state.arch === "arm64" || state.arch === "unsupported") return [];
      return detectIRPDispatches(args.instructions as Instruction[], args.is64 as boolean);

    case "resetStructRegistry":
      state.structRegistry = new StructRegistry();
      return true;

    case "decompileFunction": {
      // Refuse rather than emit. The IR lifter reads x86 mnemonics and x86
      // operands; handed ARM64 instructions it does not throw, it lifts almost
      // nothing and emits a small, confident, wrong C function. The panel shows
      // this message instead, which is the true state of affairs.
      if (state.arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Decompilation"));
      }
      if (state.arch === "arm64") {
        throw new Error(unsupportedOnArch("Decompilation", state.arch));
      }
      const xrefEntries: [number, Xref[]][] = args.xrefEntries ?? [];
      const xMap = new Map<number, Xref[]>(xrefEntries);
      // Use per-call funcMap if provided (includes renames), else fall back to stored
      const fEntries: [number, { name: string; address: number }][] | undefined = args.funcEntries;
      const fMap = fEntries ? new Map(fEntries) : state.funcMap;
      return decompileFunction(
        args.func as DisasmFunction,
        args.instructions as Instruction[],
        xMap,
        args.stackFrame as StackFrame | null,
        args.signature as FunctionSignature | null,
        args.is64 as boolean,
        state.jumpTableMap,
        state.iatMap,
        state.stringMap,
        fMap,
        state.structRegistry,
        args.runtimeFunctions,
      );
    }

    default: {
      // Without this an unrecognized method posts `{ id, result: undefined }`
      // and the caller's promise resolves with undefined instead of failing.
      // The `never` binding makes a newly added method a compile error here.
      const _exhaustive: never = method;
      throw new Error(`Unknown worker method: ${String(_exhaustive)}`);
    }
  }
}
