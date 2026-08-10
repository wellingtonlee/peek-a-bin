/**
 * Decompile a single function to C-like pseudocode for use as LLM context.
 *
 * This was written out three times — in `useBatchRename`, `useVulnScanner` and
 * `useAIReport` — with identical worker calls and identical bounds arithmetic.
 * The only genuine divergence was the line cap, which is per-caller because the
 * three features have different token budgets; it stays a parameter.
 */
import type { DisasmFunction } from '../disasm/types';
import type { PEFile, SectionHeader } from '../pe/types';
import { findCodeSection } from '../pe/sections';
import { disasmWorker } from '../workers/disasmClient';
import { analyzeStackFrame } from '../disasm/stack';
import { inferSignature } from '../disasm/signatures';
import { getDisplayName } from '../hooks/usePEFile';
import { functionByteRange, truncateCode } from './decompileTarget';

export interface DecompileForLLMOptions {
  /** Cap the returned pseudocode at this many lines. Omit for no cap. */
  maxLines?: number;
  /**
   * Code section to slice from. Callers that already located it (to compute a
   * base address, or to bail out before opening a progress dispatch) pass it in
   * so it is not re-found per function; otherwise it is looked up here.
   */
  section?: SectionHeader;
}

/**
 * Returns the pseudocode, or `null` if the function could not be decompiled —
 * no code section, function outside the section's raw data, nothing
 * disassembled, or any worker error. Callers distinguish those cases only by
 * whether they get a string back; every failure is non-fatal by design, since
 * these run in loops over many functions.
 */
export async function decompileForLLM(
  fn: DisasmFunction,
  pe: PEFile,
  functions: DisasmFunction[],
  renames: Record<number, string>,
  options: DecompileForLLMOptions = {},
): Promise<string | null> {
  const section = options.section ?? findCodeSection(pe.sections);
  if (!section) return null;

  const range = functionByteRange(fn, section, pe.optionalHeader.imageBase);
  if (!range) return null;

  try {
    const sectionBytes = new Uint8Array(pe.buffer, section.pointerToRawData, section.sizeOfRawData);
    const funcBytes = sectionBytes.subarray(range.start, range.end);
    const instructions = await disasmWorker.disassemble(funcBytes, fn.address, pe.is64);
    if (instructions.length === 0) return null;

    const xrefMap = await disasmWorker.buildTypedXrefMap(instructions);
    const sf = analyzeStackFrame(fn, instructions, pe.is64);
    const sig = inferSignature(fn, instructions, pe.is64);
    const funcEntries: [number, { name: string; address: number }][] =
      functions.map(f => [f.address, { name: getDisplayName(f, renames), address: f.address }]);
    const result = await disasmWorker.decompileFunction(
      fn, instructions, xrefMap, sf, sig, pe.is64,
      new Map(funcEntries), pe.runtimeFunctions,
    );
    if (!result.code) return null;
    return truncateCode(result.code, options.maxLines);
  } catch {
    return null;
  }
}
