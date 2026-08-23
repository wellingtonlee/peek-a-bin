/** Fixtures shared by the ARM64 frame and dispatcher suites. */
import type { Arm64UnwindFrame } from "../../pe/arm64Unwind";
import type { RuntimeFunction } from "../../pe/types";
import type { DisasmFunction, Instruction } from "../types";

export type { DisasmFunction, Instruction };
export type RuntimeFunctionLike = RuntimeFunction;

export function func(size: number, address = 0x1000): DisasmFunction {
  return { name: `sub_${address.toString(16)}`, address, size };
}

/** Instructions at consecutive four-byte addresses from the function entry. */
export function body(...ops: ([string, string] | undefined | number)[]): Instruction[] {
  const base = typeof ops[ops.length - 1] === "number" ? (ops.pop() as number) : 0x1000;
  const pairs = ops.filter((o): o is [string, string] => Array.isArray(o));
  return pairs.map(([mnemonic, opStr], i) => ({
    address: base + i * 4,
    bytes: new Uint8Array(),
    mnemonic,
    opStr,
    size: 4,
  }));
}

/** A `.pdata` entry carrying a decoded ARM64 frame. */
export function record(o: {
  begin: number;
  end?: number;
  delta?: number | null;
  size?: number;
}): RuntimeFunction {
  const frame: Arm64UnwindFrame = {
    frameDelta: o.delta === undefined ? 0x10 : o.delta,
    frameSize: o.size ?? 0x10,
    savedIntRegs: 0,
    savedFpRegs: 0,
    homesParams: false,
    source: "packed",
  };
  return {
    beginAddress: o.begin,
    endAddress: o.end ?? o.begin + 0x10,
    unwindInfoAddress: 0,
    arm64Frame: frame,
  };
}
