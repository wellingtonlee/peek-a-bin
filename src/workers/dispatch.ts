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

import { detectIRPDispatches } from "../analysis/driver";
import {
  archForMachine,
  type ImageArch,
  unsupportedArchMessage,
  unsupportedOnArch,
} from "../disasm/arch";
import {
  type Arm64Context,
  Arm64SweepCache,
  detectArm64Functions,
  disassembleArm64,
} from "../disasm/arm64";
import { buildArm64Xrefs } from "../disasm/arm64Xref";
import { CallSummaryCache } from "../disasm/callSummary";
import { unpackDataWindows } from "../disasm/dataWindows";
import { decompileFunction } from "../disasm/decompile/pipeline";
import { StructRegistry } from "../disasm/decompile/structs";
import {
  buildAllXrefs as _buildAllXrefs,
  detectFunctions as _detectFunctions,
  disassemble as _disassemble,
  hybridDisassemble as _hybridDisassemble,
  buildTypedXrefMap,
  type DetectResult,
  type DisasmContext,
} from "../disasm/functionDetect";
import type { FunctionSignature } from "../disasm/signatures";
import type { DisasmFunction, Instruction, StackFrame, Xref } from "../disasm/types";
import { extractStrings } from "../pe/parser";
import type { SectionHeader } from "../pe/types";

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
   * The **fallback**, not the authority: a decode request that names its own
   * machine type is answered from that, and only a request that names none
   * falls back to here — see {@link archFor}. Session state cannot decide the
   * architecture of a message that was posted before the `configure` that set
   * it (peek-a-bin-x4o2).
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
  /**
   * The ARM64 linear sweep of one code section, remembered across RPCs.
   *
   * Three methods decode the same `.text` on every ARM64 file load —
   * `detectFunctions`, `hybridDisassemble` and `buildAllXrefs` — because the
   * sweep is the only way any of them gets instructions and none of them can be
   * handed the previous one's array: an `Instruction[]` carries a `bytes` view
   * per element, which is the case `./transfer.ts` exists to keep out of a
   * message. Sharing it *inside* the worker costs nothing, and the worker is
   * where all three run (peek-a-bin-kis).
   *
   * Keyed on the section's bytes, so it cannot answer for a different file; see
   * {@link Arm64SweepCache}. Never consulted on the x86 path.
   */
  arm64Sweep: Arm64SweepCache;
  /**
   * Per-callee written-register summaries for the loaded image, built on the
   * first `decompileFunction` that asks for them.
   *
   * Not built by `hybridDisassemble`, which is where the instructions are
   * produced, and that is the point: the decompile request already carries the
   * whole-image `Instruction[]` and every function's extents, so the summary is
   * derived from the same message that consumes it and there is no sender to
   * race. Building it at disassembly time instead would reintroduce
   * peek-a-bin-x4o2's shape — a decompile serviced before the message that
   * announced its file — and the client's decompile cache would then serve a
   * summary-less answer for the rest of the session (peek-a-bin-s2ws).
   *
   * Keyed on the client's instruction-array token; see {@link CallSummaryCache}.
   */
  callSummaries: CallSummaryCache;
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
    arm64Sweep: new Arm64SweepCache(),
    callSummaries: new CallSummaryCache(),
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

/**
 * Which decoder answers *this* request.
 *
 * A request that names a COFF machine type decides for itself; `state.arch` —
 * whatever the last `configure` said — is only the fallback for a caller that
 * names none. That inversion is the fix for peek-a-bin-x4o2: `configure` and
 * the decode calls are posted from different React effects with no ordering
 * between them, and a worker that services messages serially decoded an ARM64
 * section with the x86 handle whenever the decode arrived first. A request that
 * states its own architecture cannot be answered by the wrong one no matter
 * when it is serviced.
 *
 * `archForMachine` is the only interpreter of a machine value in the app, so
 * the client sends the raw number and the reading happens here, once.
 */
function archFor(args: { machine?: number }, state: WorkerState): ImageArch {
  return args?.machine !== undefined ? archForMachine(args.machine) : state.arch;
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
      // Memory hygiene only. A declared machine type is the load handshake, so
      // this is where one file's instructions stop being worth holding — but
      // the cache is keyed on the bytes, not on this, precisely because a
      // decode can be serviced *before* the `configure` that announces its file
      // (peek-a-bin-x4o2). Dropping it late costs a re-sweep; it can never
      // produce a wrong answer.
      if (args.machine !== undefined) {
        state.arm64Sweep.clear();
        // Same guard, same reason: `configure` is sent twice per file and only
        // the first names a machine, so clearing unconditionally would drop a
        // summary the second call has no reason to invalidate. Hygiene only —
        // the token key already makes a hit for another image impossible.
        state.callSummaries.clear();
      }
      return true;

    case "configureDecompileMaps": {
      const fEntries: [number, { name: string; address: number }][] = args.funcEntries ?? [];
      state.funcMap = new Map(fEntries);
      const jtEntries: [number, number[]][] = args.jumpTableEntries ?? [];
      state.jumpTableMap = new Map(jtEntries);
      return true;
    }

    case "disassemble": {
      // Refuse rather than invent. An x86 linear sweep decodes essentially any
      // byte string, so an ARM32 image came back as a full screen of plausible
      // instructions with no signal that any of it was fiction — the same
      // silent-failure shape peek-a-bin-cen removed from the Capstone-dead
      // path, and the reason this throws instead of returning a short list
      // (peek-a-bin-x7b).
      const arch = archFor(args, state);
      if (arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Disassembly"));
      }
      if (arch === "arm64") {
        // Deliberately not routed through `state.arm64Sweep`. This method is
        // the one that may be handed a *sub-range* — one function's bytes —
        // and the cache holds a single section, so a small decode would evict
        // the whole-`.text` entry the other three share. The client caches this
        // answer on its own side anyway.
        return disassembleArm64(args.bytes, args.baseAddress, armCtx(state));
      }
      return _disassemble(args.bytes, args.baseAddress, args.is64, ctx(state));
    }

    case "hybridDisassemble": {
      const arch = archFor(args, state);
      if (arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Disassembly"));
      }
      if (arch === "arm64") {
        // Seeds are dropped deliberately. Recursive descent exists to resolve
        // the instruction boundaries a variable-length encoding leaves
        // ambiguous; A64 has none, so the linear sweep IS the answer, and it
        // covers the whole section rather than only what a BFS could reach.
        // `pdataRanges` still arrives, and marks which words the image itself
        // vouches for.
        // The annotation and the `.pdata` marking are redone here whether or
        // not the sweep itself came from the cache, so what the view gets is
        // byte-identical either way; only the Capstone pass is skipped.
        return disassembleArm64(
          args.bytes,
          args.baseAddress,
          armCtx(state),
          args.pdataRanges,
          state.arm64Sweep,
        );
      }
      return _hybridDisassemble(
        args.bytes,
        args.baseAddress,
        args.is64,
        args.seeds,
        ctx(state),
        args.pdataRanges,
        // Byte ranges detection recovered as jump tables. Data, so the gap fill
        // leaves them alone rather than decoding case addresses as code.
        args.jumpTableSpans,
      );
    }

    case "detectFunctions": {
      // Answers, rather than throwing, for the reason `DetectResult.omitted`
      // documents: detection's evidence is mostly not instructions. But every
      // pass this architecture has *is* an x86 pass — the prologue byte tables,
      // the call-target scan, the `readRvaTable` jump-table reader, the thunk
      // and tail-call passes — and `pdata.ts` extracts no extents for anything
      // but ARM64 and x64, so there is nothing left to answer *with*. Empty
      // with every pass named beats a plausible list built from x86 byte
      // patterns found in ARM code (peek-a-bin-x7b).
      const arch = archFor(args, state);
      if (arch === "unsupported") {
        return {
          functions: [],
          jumpTables: [],
          jumpTableSpans: [],
          omitted: ["call-targets", "jump-tables", "thunk-names", "tail-calls"],
        } satisfies DetectResult;
      }
      if (arch === "arm64") {
        // No jump-table reader on ARM64 — a `br` through a table is not the
        // pattern `readRvaTable` models — so the windows would go unread.
        return detectArm64Functions(
          args.bytes,
          args.baseAddress,
          armCtx(state),
          args.options,
          state.arm64Sweep,
        );
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
      const arch = archFor(args, state);
      if (arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Cross-reference analysis"));
      }
      if (arch === "arm64") {
        // `_buildAllXrefs` is an x86 operand grammar from end to end —
        // `[rip ± 0x..]`, `mov reg, imm`, `call 0x…`. Over ARM64 bytes it does
        // not fail, it invents references. `buildArm64Xrefs` reads the real
        // thing: an adrp/add or adrp/ldr pair, plus `bl` for the call graph.
        //
        // It takes decoded instructions rather than bytes. Shipping the
        // caller's `Instruction[]` in the message is not the answer — every
        // element carries a `bytes` view, which is what ./transfer.ts exists to
        // keep out — so the sweep is shared through `state.arm64Sweep` instead,
        // which the `detectFunctions` for this same section already filled.
        // Measured on t64-arm.exe: 130 ms of Capstone, now 0 (peek-a-bin-kis).
        //
        // Undecorated on purpose, and it does not matter which caller filled
        // the cache: xrefs read nothing but address, mnemonic and opStr, and
        // the annotation maps only ever set `Instruction.comment`.
        const insns = state.arm64Sweep.sweep(args.bytes, args.baseAddress, state.csArm64);
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

    case "detectIRPDispatches": {
      // Matches `mov [reg + 0x70 + i*8], offset handler` in a driver's
      // DriverEntry — x86 mnemonics and x86 operand syntax. An ARM64 driver
      // stores its dispatch table with str/adrp and would simply never match,
      // so returning nothing here changes no answer; it just says so.
      // Same argument for an image with no decoder at all: it matches x86
      // mnemonics against instructions that are not x86, and there are none to
      // match against in the first place, since `disassemble` refused.
      const arch = archFor(args, state);
      if (arch === "arm64" || arch === "unsupported") return [];
      return detectIRPDispatches(args.instructions as Instruction[], args.is64 as boolean);
    }

    case "resetStructRegistry":
      state.structRegistry = new StructRegistry();
      return true;

    case "decompileFunction": {
      // Refuse rather than emit. The IR lifter reads x86 mnemonics and x86
      // operands; handed ARM64 instructions it does not throw, it lifts almost
      // nothing and emits a small, confident, wrong C function. The panel shows
      // this message instead, which is the true state of affairs.
      const arch = archFor(args, state);
      if (arch === "unsupported") {
        throw new Error(unsupportedArchMessage("Decompilation"));
      }
      if (arch === "arm64") {
        throw new Error(unsupportedOnArch("Decompilation", arch));
      }
      const xrefEntries: [number, Xref[]][] = args.xrefEntries ?? [];
      const xMap = new Map<number, Xref[]>(xrefEntries);
      // Use per-call funcMap if provided (includes renames), else fall back to stored
      const fEntries: [number, { name: string; address: number }][] | undefined = args.funcEntries;
      const fMap = fEntries ? new Map(fEntries) : state.funcMap;
      const insns = args.instructions as Instruction[];
      // What each callee writes, so a call clobbers that rather than the whole
      // ABI volatile set — see `clobberedByCall` in decompile/ssa.ts for why the
      // wide answer is worse. Two gates, and both mean "exactly the behaviour
      // this path had before the summary existed":
      //
      //   * no extents sent — an older client, or a caller that never had them;
      //   * not a 64-bit image — `calleeClobbersFor` returns undefined unless
      //     `is64`, because on x86 nothing is passed in a register, so building
      //     a summary a PE32 lift cannot consult is pure cost.
      const extents = args.funcExtents as [number, number][] | undefined;
      const token = args.insnsToken as number | undefined;
      const calleeClobbers =
        extents && token !== undefined && args.is64
          ? state.callSummaries.forToken(
              token,
              extents.map(([address, size]) => ({ address, size })),
              insns,
              state.iatMap,
            )
          : undefined;
      return decompileFunction(
        args.func as DisasmFunction,
        insns,
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
        undefined,
        calleeClobbers,
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
