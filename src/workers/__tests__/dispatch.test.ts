/**
 * The worker's RPC dispatch.
 *
 * Extracted from `disasm.worker.ts` precisely so it can be tested: the worker
 * module itself touches `self` and `indexedDB` and starts loading Capstone WASM
 * at module scope, which left the `default` branch — the one that stops an
 * unknown method from resolving as `undefined` — with no runtime coverage at
 * all, only a compile-time `never` check.
 *
 * Methods needing a live Capstone handle (`disassemble`, `hybridDisassemble`,
 * `detectFunctions`, `decompileFunction`) are exercised elsewhere; what is
 * tested here is the dispatch's own job — routing, argument defaulting, state
 * mutation, and error propagation.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dispatch, createWorkerState, type WorkerMethod, type WorkerState } from '../dispatch';
import { StructRegistry } from '../../disasm/decompile/structs';
import type { Instruction } from '../../disasm/types';

/** A ready-to-use state whose Capstone bootstrap has already resolved. */
function state(overrides: Partial<WorkerState> = {}): WorkerState {
  return Object.assign(createWorkerState(Promise.resolve()), overrides);
}

/** A minimal instruction record. */
function insn(address: number, mnemonic: string, opStr: string, size = 5): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

describe('dispatch — unknown method', () => {
  it('rejects instead of resolving undefined', async () => {
    // The regression this guards: a silent `{ id, result: undefined }` reply
    // resolves the caller's promise with undefined, so a typo'd method looks
    // like a successful call that returned nothing.
    const promise = dispatch('bogus' as WorkerMethod, {}, state());

    await expect(promise).rejects.toThrow('Unknown worker method: bogus');
  });

  it('names the offending method so the caller can identify it', async () => {
    await expect(dispatch('disassembler' as WorkerMethod, {}, state()))
      .rejects.toThrow(/disassembler/);
  });

  it.each([
    ['an empty string', ''],
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['a near-miss of a real method', 'Init'],
    ['an object', { method: 'init' }],
  ])('rejects %s rather than falling through', async (_label, method) => {
    await expect(dispatch(method as WorkerMethod, {}, state())).rejects.toThrow(/Unknown worker method/);
  });

  it('leaves worker state untouched', async () => {
    const s = state();
    const registry = s.structRegistry;

    await expect(dispatch('nope' as WorkerMethod, {}, s)).rejects.toThrow();

    expect(s.structRegistry).toBe(registry);
    expect(s.stringMap.size).toBe(0);
    expect(s.driverMode).toBe(false);
  });
});

describe('dispatch — init', () => {
  it('resolves true once the Capstone bootstrap finishes', async () => {
    let ready!: () => void;
    const s = state({ ready: new Promise<void>(r => { ready = r; }) });

    const pending = dispatch('init', {}, s);
    let settled = false;
    void pending.then(() => { settled = true; });

    await Promise.resolve();
    expect(settled).toBe(false); // still waiting on the bootstrap

    ready();
    await expect(pending).resolves.toBe(true);
  });

  it('propagates a failed bootstrap instead of hanging the caller', async () => {
    // If this resolved, the UI would proceed to disassemble with no Capstone.
    const s = state({ ready: Promise.reject(new Error('WASM load failed')) });

    await expect(dispatch('init', {}, s)).rejects.toThrow('WASM load failed');
  });

  it('can be awaited more than once', async () => {
    const s = state();
    await expect(dispatch('init', {}, s)).resolves.toBe(true);
    await expect(dispatch('init', {}, s)).resolves.toBe(true);
  });
});

describe('dispatch — configure', () => {
  it('rebuilds the string and IAT maps from entry arrays', async () => {
    // Maps do not survive structured clone, so they cross the wire as entries.
    const s = state();
    const result = await dispatch('configure', {
      stringEntries: [[0x1000, 'hello'], [0x2000, 'world']],
      iatEntries: [[0x3000, { lib: 'kernel32.dll', func: 'CreateFileW' }]],
    }, s);

    expect(result).toBe(true);
    expect(s.stringMap.get(0x1000)).toBe('hello');
    expect(s.stringMap.size).toBe(2);
    expect(s.iatMap.get(0x3000)).toEqual({ lib: 'kernel32.dll', func: 'CreateFileW' });
  });

  it('replaces rather than merges the previous maps', async () => {
    const s = state({ stringMap: new Map([[0xdead, 'stale']]) });
    await dispatch('configure', { stringEntries: [[0x1000, 'fresh']], iatEntries: [] }, s);

    expect(s.stringMap.has(0xdead)).toBe(false);
  });

  it('sets driverMode when supplied', async () => {
    const s = state();
    await dispatch('configure', { stringEntries: [], iatEntries: [], driverMode: true }, s);
    expect(s.driverMode).toBe(true);
  });

  it('leaves driverMode alone when omitted', async () => {
    const s = state({ driverMode: true });
    await dispatch('configure', { stringEntries: [], iatEntries: [] }, s);
    expect(s.driverMode).toBe(true);
  });

  it('accepts an explicit false for driverMode', async () => {
    const s = state({ driverMode: true });
    await dispatch('configure', { stringEntries: [], iatEntries: [], driverMode: false }, s);
    expect(s.driverMode).toBe(false);
  });

  it('starts a fresh struct registry for the new file', async () => {
    // Struct synthesis is cross-function but must not leak between binaries.
    const s = state();
    const previous = s.structRegistry;

    await dispatch('configure', { stringEntries: [], iatEntries: [] }, s);

    expect(s.structRegistry).toBeInstanceOf(StructRegistry);
    expect(s.structRegistry).not.toBe(previous);
  });
});

describe('dispatch — configureDecompileMaps', () => {
  it('installs the function and jump-table maps', async () => {
    const s = state();
    const result = await dispatch('configureDecompileMaps', {
      funcEntries: [[0x401000, { name: 'main', address: 0x401000 }]],
      jumpTableEntries: [[0x402000, [0x403000, 0x404000]]],
    }, s);

    expect(result).toBe(true);
    expect(s.funcMap.get(0x401000)).toEqual({ name: 'main', address: 0x401000 });
    expect(s.jumpTableMap.get(0x402000)).toEqual([0x403000, 0x404000]);
  });

  it('defaults to empty maps when the args are omitted', async () => {
    const s = state({ funcMap: new Map([[1, { name: 'old', address: 1 }]]) });
    await dispatch('configureDecompileMaps', {}, s);

    expect(s.funcMap.size).toBe(0);
    expect(s.jumpTableMap.size).toBe(0);
  });
});

describe('dispatch — resetStructRegistry', () => {
  it('swaps in a new registry', async () => {
    const s = state();
    const previous = s.structRegistry;

    await expect(dispatch('resetStructRegistry', {}, s)).resolves.toBe(true);
    expect(s.structRegistry).not.toBe(previous);
  });

  it('leaves the other maps intact', async () => {
    const s = state({ stringMap: new Map([[1, 'keep']]), driverMode: true });
    await dispatch('resetStructRegistry', {}, s);

    expect(s.stringMap.get(1)).toBe('keep');
    expect(s.driverMode).toBe(true);
  });
});

describe('dispatch — buildTypedXrefMap', () => {
  it('returns call and branch xrefs as entry pairs', async () => {
    const result = await dispatch('buildTypedXrefMap', {
      instructions: [
        insn(0x401000, 'call', '0x401100'),
        insn(0x401005, 'je', '0x401020'),
      ],
    }, state());

    const map = new Map(result as [number, { from: number; type: string }[]][]);
    expect(map.get(0x401100)).toEqual([{ from: 0x401000, type: 'call' }]);
    expect(map.get(0x401020)).toEqual([{ from: 0x401005, type: 'branch' }]);
  });

  it('returns an empty list for no instructions', async () => {
    expect(await dispatch('buildTypedXrefMap', { instructions: [] }, state())).toEqual([]);
  });
});

describe('dispatch — detectIRPDispatches', () => {
  it('returns an empty list when there is nothing to find', async () => {
    const result = await dispatch('detectIRPDispatches', { instructions: [], is64: true }, state());
    expect(result).toEqual([]);
  });

  it('passes the bitness through to the detector', async () => {
    // 32-bit and 64-bit use different MajorFunction table offsets, so the flag
    // has to reach the detector rather than defaulting.
    const instructions = [insn(0x401000, 'mov', 'qword ptr [rdi + 0x70], rax')];
    const as64 = await dispatch('detectIRPDispatches', { instructions, is64: true }, state());
    const as32 = await dispatch('detectIRPDispatches', { instructions, is64: false }, state());

    expect(as64).not.toEqual(as32);
  });
});

describe('dispatch — extractStrings', () => {
  it('returns strings and their types as entry arrays', async () => {
    // Maps cannot be structured-cloned back to the main thread.
    const buffer = new ArrayBuffer(0x200);
    const bytes = new Uint8Array(buffer);
    const text = 'CreateFileW';
    for (let i = 0; i < text.length; i++) bytes[0x100 + i] = text.charCodeAt(i);

    const result = await dispatch('extractStrings', {
      buffer,
      sections: [{
        name: '.rdata',
        virtualAddress: 0x1000,
        virtualSize: 0x200,
        pointerToRawData: 0,
        sizeOfRawData: 0x200,
        characteristics: 0x40000040,
      }],
      imageBase: 0x400000,
      is64: false,
    }, state());

    const { strings, stringTypes } = result as {
      strings: [number, string][];
      stringTypes: [number, string][];
    };
    expect(Array.isArray(strings)).toBe(true);
    expect(strings.map(([, s]) => s)).toContain('CreateFileW');
    expect(stringTypes.length).toBe(strings.length);
  });

  it('returns empty entry arrays for a section with no strings', async () => {
    const result = await dispatch('extractStrings', {
      buffer: new ArrayBuffer(0x100),
      sections: [],
      imageBase: 0x400000,
    }, state()) as { strings: unknown[]; stringTypes: unknown[] };

    expect(result.strings).toEqual([]);
    expect(result.stringTypes).toEqual([]);
  });
});

describe('dispatch — buildAllXrefs', () => {
  /** A Capstone stand-in that records that it was the one asked to disassemble. */
  function fakeCapstone(tag: string, used: string[]) {
    return { disasm: () => { used.push(tag); return []; } };
  }

  it('uses the 64-bit Capstone handle when is64 is set', async () => {
    const used: string[] = [];
    const s = state({ cs32: fakeCapstone('cs32', used), cs64: fakeCapstone('cs64', used) });

    await dispatch('buildAllXrefs', {
      bytes: new Uint8Array(64), baseAddress: 0x401000, is64: true,
      stringAddrs: [], iatAddrs: [],
    }, s);

    expect(used).toContain('cs64');
    expect(used).not.toContain('cs32');
  });

  it('uses the 32-bit handle otherwise', async () => {
    const used: string[] = [];
    const s = state({ cs32: fakeCapstone('cs32', used), cs64: fakeCapstone('cs64', used) });

    await dispatch('buildAllXrefs', {
      bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false,
      stringAddrs: [], iatAddrs: [],
    }, s);

    expect(used).toContain('cs32');
    expect(used).not.toContain('cs64');
  });

  it('returns empty xrefs — not an error — when Capstone is not ready', async () => {
    // Characterization of a sharp edge, NOT an endorsement. cs32/cs64 are
    // undefined until the WASM bootstrap finishes, and buildAllXrefs wraps its
    // `cs.disasm()` call in a per-chunk `try {} catch { offset += 1 }`
    // (src/disasm/functionDetect.ts:777-850). So a caller that skipped `init`
    // gets a well-formed result with no string, import or call-graph xrefs at
    // all, and nothing anywhere reports that Capstone was missing.
    const result = await dispatch('buildAllXrefs', {
      bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false,
      stringAddrs: [0x401000], iatAddrs: [0x402000],
    }, state());

    expect(result).toEqual({
      stringXrefs: [], importXrefs: [], callGraph: [], dataXrefs: [],
    });
  });
});

describe('dispatch — state is per-call, not module-level', () => {
  it('keeps two worker states independent', async () => {
    const a = state();
    const b = state();

    await dispatch('configure', { stringEntries: [[1, 'a']], iatEntries: [], driverMode: true }, a);

    expect(b.stringMap.size).toBe(0);
    expect(b.driverMode).toBe(false);
  });
});

describe('dispatch module — stays importable outside a worker', () => {
  const source = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../dispatch.ts'),
    'utf-8',
  ).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

  it.each(['capstone-wasm', 'self.', 'indexedDB', 'postMessage'])(
    'does not reference %s',
    (forbidden) => {
      expect(
        source.includes(forbidden),
        `src/workers/dispatch.ts references "${forbidden}". It was split out of `
          + `disasm.worker.ts specifically so it could be imported under vitest's node `
          + `environment — anything worker-only or WASM-loading belongs in the worker `
          + `module, with the value passed in through WorkerState.`,
      ).toBe(false);
    },
  );
});
