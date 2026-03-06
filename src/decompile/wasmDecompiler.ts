export interface WasmDecompileResult {
  code: string;
  lineMap: [number, number][];
  engine: string;
}

/**
 * Client-side WASM decompiler stub.
 * Future: integrate Snowman, r2dec, or RetDec compiled to WASM.
 */
export async function decompileWithWasm(
  _bytes: Uint8Array,
  _funcAddr: number,
  _is64: boolean,
): Promise<WasmDecompileResult> {
  return {
    code: "// Client-side decompiler not yet available.\n// Configure a Ghidra server in Settings for high-level decompilation.",
    lineMap: [],
    engine: "none",
  };
}
