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
  type DisasmContext,
  disassemble as _disassemble,
  detectFunctions as _detectFunctions,
  hybridDisassemble as _hybridDisassemble,
  buildTypedXrefMap,
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
      return _disassemble(args.bytes, args.baseAddress, args.is64, ctx(state));

    case "hybridDisassemble":
      return _hybridDisassemble(
        args.bytes,
        args.baseAddress,
        args.is64,
        args.seeds,
        ctx(state),
        args.pdataRanges,
      );

    case "detectFunctions":
      return _detectFunctions(args.bytes, args.baseAddress, args.is64, ctx(state), args.options);

    case "buildTypedXrefMap":
      return buildTypedXrefMap(args.instructions);

    case "buildAllXrefs": {
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
      return detectIRPDispatches(args.instructions as Instruction[], args.is64 as boolean);

    case "resetStructRegistry":
      state.structRegistry = new StructRegistry();
      return true;

    case "decompileFunction": {
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
