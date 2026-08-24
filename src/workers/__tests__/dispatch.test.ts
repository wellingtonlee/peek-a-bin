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

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { StructRegistry } from "../../disasm/decompile/structs";
import type { Instruction } from "../../disasm/types";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { createWorkerState, dispatch, type WorkerMethod, type WorkerState } from "../dispatch";

/** A ready-to-use state whose Capstone bootstrap has already resolved. */
function state(overrides: Partial<WorkerState> = {}): WorkerState {
  return Object.assign(createWorkerState(Promise.resolve()), overrides);
}

/** A minimal instruction record. */
function insn(address: number, mnemonic: string, opStr: string, size = 5): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

describe("dispatch — unknown method", () => {
  it("rejects instead of resolving undefined", async () => {
    // The regression this guards: a silent `{ id, result: undefined }` reply
    // resolves the caller's promise with undefined, so a typo'd method looks
    // like a successful call that returned nothing.
    const promise = dispatch("bogus" as WorkerMethod, {}, state());

    await expect(promise).rejects.toThrow("Unknown worker method: bogus");
  });

  it("names the offending method so the caller can identify it", async () => {
    await expect(dispatch("disassembler" as WorkerMethod, {}, state())).rejects.toThrow(
      /disassembler/,
    );
  });

  it.each([
    ["an empty string", ""],
    ["undefined", undefined],
    ["null", null],
    ["a number", 42],
    ["a near-miss of a real method", "Init"],
    ["an object", { method: "init" }],
  ])("rejects %s rather than falling through", async (_label, method) => {
    await expect(dispatch(method as WorkerMethod, {}, state())).rejects.toThrow(
      /Unknown worker method/,
    );
  });

  it("leaves worker state untouched", async () => {
    const s = state();
    const registry = s.structRegistry;

    await expect(dispatch("nope" as WorkerMethod, {}, s)).rejects.toThrow();

    expect(s.structRegistry).toBe(registry);
    expect(s.stringMap.size).toBe(0);
    expect(s.driverMode).toBe(false);
  });
});

describe("dispatch — init", () => {
  it("resolves true once the Capstone bootstrap finishes", async () => {
    let ready!: () => void;
    const s = state({
      ready: new Promise<void>((r) => {
        ready = r;
      }),
    });

    const pending = dispatch("init", {}, s);
    let settled = false;
    void pending.then(() => {
      settled = true;
    });

    await Promise.resolve();
    expect(settled).toBe(false); // still waiting on the bootstrap

    ready();
    await expect(pending).resolves.toBe(true);
  });

  it("propagates a failed bootstrap instead of hanging the caller", async () => {
    // If this resolved, the UI would proceed to disassemble with no Capstone.
    const s = state({ ready: Promise.reject(new Error("WASM load failed")) });

    await expect(dispatch("init", {}, s)).rejects.toThrow("WASM load failed");
  });

  it("can be awaited more than once", async () => {
    const s = state();
    await expect(dispatch("init", {}, s)).resolves.toBe(true);
    await expect(dispatch("init", {}, s)).resolves.toBe(true);
  });
});

describe("dispatch — configure", () => {
  it("rebuilds the string and IAT maps from entry arrays", async () => {
    // Maps do not survive structured clone, so they cross the wire as entries.
    const s = state();
    const result = await dispatch(
      "configure",
      {
        stringEntries: [
          [0x1000, "hello"],
          [0x2000, "world"],
        ],
        iatEntries: [[0x3000, { lib: "kernel32.dll", func: "CreateFileW" }]],
      },
      s,
    );

    expect(result).toBe(true);
    expect(s.stringMap.get(0x1000)).toBe("hello");
    expect(s.stringMap.size).toBe(2);
    expect(s.iatMap.get(0x3000)).toEqual({ lib: "kernel32.dll", func: "CreateFileW" });
  });

  it("replaces rather than merges the previous maps", async () => {
    const s = state({ stringMap: new Map([[0xdead, "stale"]]) });
    await dispatch("configure", { stringEntries: [[0x1000, "fresh"]], iatEntries: [] }, s);

    expect(s.stringMap.has(0xdead)).toBe(false);
  });

  it("sets driverMode when supplied", async () => {
    const s = state();
    await dispatch("configure", { stringEntries: [], iatEntries: [], driverMode: true }, s);
    expect(s.driverMode).toBe(true);
  });

  it("leaves driverMode alone when omitted", async () => {
    const s = state({ driverMode: true });
    await dispatch("configure", { stringEntries: [], iatEntries: [] }, s);
    expect(s.driverMode).toBe(true);
  });

  it("accepts an explicit false for driverMode", async () => {
    const s = state({ driverMode: true });
    await dispatch("configure", { stringEntries: [], iatEntries: [], driverMode: false }, s);
    expect(s.driverMode).toBe(false);
  });

  it("starts a fresh struct registry for the new file", async () => {
    // Struct synthesis is cross-function but must not leak between binaries.
    const s = state();
    const previous = s.structRegistry;

    await dispatch("configure", { stringEntries: [], iatEntries: [] }, s);

    expect(s.structRegistry).toBeInstanceOf(StructRegistry);
    expect(s.structRegistry).not.toBe(previous);
  });
});

describe("dispatch — configureDecompileMaps", () => {
  it("installs the function and jump-table maps", async () => {
    const s = state();
    const result = await dispatch(
      "configureDecompileMaps",
      {
        funcEntries: [[0x401000, { name: "main", address: 0x401000 }]],
        jumpTableEntries: [[0x402000, [0x403000, 0x404000]]],
      },
      s,
    );

    expect(result).toBe(true);
    expect(s.funcMap.get(0x401000)).toEqual({ name: "main", address: 0x401000 });
    expect(s.jumpTableMap.get(0x402000)).toEqual([0x403000, 0x404000]);
  });

  it("defaults to empty maps when the args are omitted", async () => {
    const s = state({ funcMap: new Map([[1, { name: "old", address: 1 }]]) });
    await dispatch("configureDecompileMaps", {}, s);

    expect(s.funcMap.size).toBe(0);
    expect(s.jumpTableMap.size).toBe(0);
  });
});

describe("dispatch — resetStructRegistry", () => {
  it("swaps in a new registry", async () => {
    const s = state();
    const previous = s.structRegistry;

    await expect(dispatch("resetStructRegistry", {}, s)).resolves.toBe(true);
    expect(s.structRegistry).not.toBe(previous);
  });

  it("leaves the other maps intact", async () => {
    const s = state({ stringMap: new Map([[1, "keep"]]), driverMode: true });
    await dispatch("resetStructRegistry", {}, s);

    expect(s.stringMap.get(1)).toBe("keep");
    expect(s.driverMode).toBe(true);
  });
});

describe("dispatch — buildTypedXrefMap", () => {
  it("returns call and branch xrefs as entry pairs", async () => {
    const result = await dispatch(
      "buildTypedXrefMap",
      {
        instructions: [insn(0x401000, "call", "0x401100"), insn(0x401005, "je", "0x401020")],
      },
      state(),
    );

    const map = new Map(result as [number, { from: number; type: string }[]][]);
    expect(map.get(0x401100)).toEqual([{ from: 0x401000, type: "call" }]);
    expect(map.get(0x401020)).toEqual([{ from: 0x401005, type: "branch" }]);
  });

  it("returns an empty list for no instructions", async () => {
    expect(await dispatch("buildTypedXrefMap", { instructions: [] }, state())).toEqual([]);
  });

  // The bound exists in `buildTypedXrefMap` and is reachable only if this
  // dispatch forwards it. It did not, so every browser-side caller got the
  // unbounded scan no matter what it asked for (peek-a-bin-2ap).
  describe("the image bound reaches the scan", () => {
    /** t64.exe's actual mapping: 0x140000000, 0x1e000 bytes. */
    const imageBounds = { base: 0x140000000, size: 0x1e000 };
    const targets = async (i: Instruction, bounds?: { base: number; size: number }) => {
      const entries = (await dispatch(
        "buildTypedXrefMap",
        { instructions: [i], imageBounds: bounds },
        state(),
      )) as [number, unknown][];
      return entries.map(([addr]) => addr);
    };

    it("drops a bitmask immediate that lies outside the image", async () => {
      const or = insn(0x140001000, "or", "edx, 0xffffffff");
      // Unbounded — what shipped: 0xffffffff reported as a referenced address.
      expect(await targets(or)).toEqual([0xffffffff]);
      expect(await targets(or, imageBounds)).toEqual([]);
    });

    it("drops an NTSTATUS compared against, not pointed at", async () => {
      const cmp = insn(0x140001010, "cmp", "dword ptr [rax], 0xc0000005");
      expect(await targets(cmp)).toEqual([0xc0000005]);
      expect(await targets(cmp, imageBounds)).toEqual([]);
    });

    it("keeps an in-image data reference", async () => {
      const mov = insn(0x140001020, "mov", "eax, dword ptr [0x140002000]");
      expect(await targets(mov, imageBounds)).toEqual([0x140002000]);
    });

    it("keeps a call outside the image — a stated destination, not a guess", async () => {
      // Only the fallback scan is bounded. A direct call target is computed
      // from a real instruction, so one landing outside the image is a fact
      // about the file.
      const call = insn(0x140001030, "call", "0x7ffe0100");
      expect(await targets(call, imageBounds)).toEqual([0x7ffe0100]);
    });

    it("is unbounded when no bounds are sent, exactly as before", async () => {
      const insns = [
        insn(0x140001000, "or", "edx, 0xffffffff"),
        insn(0x140001020, "mov", "eax, dword ptr [0x140002000]"),
      ];
      const entries = (await dispatch("buildTypedXrefMap", { instructions: insns }, state())) as [
        number,
        unknown,
      ][];
      expect(entries.map(([a]) => a).sort((a, b) => a - b)).toEqual([0xffffffff, 0x140002000]);
    });
  });
});

describe("dispatch — detectIRPDispatches", () => {
  it("returns an empty list when there is nothing to find", async () => {
    const result = await dispatch("detectIRPDispatches", { instructions: [], is64: true }, state());
    expect(result).toEqual([]);
  });

  it("passes the bitness through to the detector", async () => {
    // 32-bit and 64-bit use different MajorFunction table offsets, so the flag
    // has to reach the detector rather than defaulting.
    const instructions = [insn(0x401000, "mov", "qword ptr [rdi + 0x70], rax")];
    const as64 = await dispatch("detectIRPDispatches", { instructions, is64: true }, state());
    const as32 = await dispatch("detectIRPDispatches", { instructions, is64: false }, state());

    expect(as64).not.toEqual(as32);
  });
});

describe("dispatch — extractStrings", () => {
  it("returns strings and their types as entry arrays", async () => {
    // Maps cannot be structured-cloned back to the main thread.
    const buffer = new ArrayBuffer(0x200);
    const bytes = new Uint8Array(buffer);
    const text = "CreateFileW";
    for (let i = 0; i < text.length; i++) bytes[0x100 + i] = text.charCodeAt(i);

    const result = await dispatch(
      "extractStrings",
      {
        buffer,
        sections: [
          {
            name: ".rdata",
            virtualAddress: 0x1000,
            virtualSize: 0x200,
            pointerToRawData: 0,
            sizeOfRawData: 0x200,
            characteristics: 0x40000040,
          },
        ],
        imageBase: 0x400000,
        is64: false,
      },
      state(),
    );

    const { strings, stringTypes } = result as {
      strings: [number, string][];
      stringTypes: [number, string][];
    };
    expect(Array.isArray(strings)).toBe(true);
    expect(strings.map(([, s]) => s)).toContain("CreateFileW");
    expect(stringTypes.length).toBe(strings.length);
  });

  it("returns empty entry arrays for a section with no strings", async () => {
    const result = (await dispatch(
      "extractStrings",
      {
        buffer: new ArrayBuffer(0x100),
        sections: [],
        imageBase: 0x400000,
      },
      state(),
    )) as { strings: unknown[]; stringTypes: unknown[] };

    expect(result.strings).toEqual([]);
    expect(result.stringTypes).toEqual([]);
  });
});

describe("dispatch — buildAllXrefs", () => {
  /**
   * A Capstone stand-in that records that it was the one asked to disassemble.
   *
   * It decodes the whole window as one instruction rather than returning
   * nothing. A stub that never decodes anything is indistinguishable from an
   * exhausted WASM decoder, which `capstoneWindow.ts` now reports as a
   * `CapstoneUnavailableError` rather than as an empty xref map.
   */
  function fakeCapstone(tag: string, used: string[]) {
    return {
      disasm: (bytes: Uint8Array, options?: { address?: number }) => {
        used.push(tag);
        return [
          {
            address: options?.address ?? 0,
            bytes,
            mnemonic: "nop",
            opStr: "",
            size: bytes.length,
          },
        ];
      },
    };
  }

  it("uses the 64-bit Capstone handle when is64 is set", async () => {
    const used: string[] = [];
    const s = state({ cs32: fakeCapstone("cs32", used), cs64: fakeCapstone("cs64", used) });

    await dispatch(
      "buildAllXrefs",
      {
        bytes: new Uint8Array(64),
        baseAddress: 0x401000,
        is64: true,
        stringAddrs: [],
        iatAddrs: [],
      },
      s,
    );

    expect(used).toContain("cs64");
    expect(used).not.toContain("cs32");
  });

  it("uses the 32-bit handle otherwise", async () => {
    const used: string[] = [];
    const s = state({ cs32: fakeCapstone("cs32", used), cs64: fakeCapstone("cs64", used) });

    await dispatch(
      "buildAllXrefs",
      {
        bytes: new Uint8Array(64),
        baseAddress: 0x401000,
        is64: false,
        stringAddrs: [],
        iatAddrs: [],
      },
      s,
    );

    expect(used).toContain("cs32");
    expect(used).not.toContain("cs64");
  });

  it("rejects — rather than returning empty xrefs — when Capstone is not ready", async () => {
    // peek-a-bin-cen. This used to be a characterization of the opposite
    // behaviour: cs32/cs64 are undefined until the WASM bootstrap finishes, and
    // `buildAllXrefs` returned four empty maps for a missing handle. Four empty
    // maps is a well-formed answer meaning "this image references no strings,
    // no imports and nothing in its data sections", which is false of every
    // real image and which nothing downstream could tell apart from the truth.
    await expect(
      dispatch(
        "buildAllXrefs",
        {
          bytes: new Uint8Array(64),
          baseAddress: 0x401000,
          is64: false,
          stringAddrs: [0x401000],
          iatAddrs: [0x402000],
        },
        state(),
      ),
    ).rejects.toThrow(/Capstone is not initialised/);
  });
});

describe("dispatch — state is per-call, not module-level", () => {
  it("keeps two worker states independent", async () => {
    const a = state();
    const b = state();

    await dispatch("configure", { stringEntries: [[1, "a"]], iatEntries: [], driverMode: true }, a);

    expect(b.stringMap.size).toBe(0);
    expect(b.driverMode).toBe(false);
  });
});

describe("dispatch module — stays importable outside a worker", () => {
  const source = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../dispatch.ts"),
    "utf-8",
  )
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");

  it.each(["capstone-wasm", "self.", "indexedDB", "postMessage"])(
    "does not reference %s",
    (forbidden) => {
      expect(
        source.includes(forbidden),
        `src/workers/dispatch.ts references "${forbidden}". It was split out of ` +
          `disasm.worker.ts specifically so it could be imported under vitest's node ` +
          `environment — anything worker-only or WASM-loading belongs in the worker ` +
          `module, with the value passed in through WorkerState.`,
      ).toBe(false);
    },
  );
});

/**
 * peek-a-bin-amu: the worker chose its Capstone handle with `is64`, the PE32+
 * magic, so an ARM64 image — PE32+ like any other x64 one — was decoded as
 * x86-64 and produced zero instructions. The machine type now selects the
 * decoder, and the stages that are x86 grammars refuse instead of running.
 *
 * The Capstone handles here are stubs that record which one was used; what is
 * under test is the routing, not the decoding (see disasm/__tests__/arm64.test.ts).
 */
describe("dispatch — architecture routing", () => {
  const ARM64_MACHINE = 0xaa64;
  const AMD64_MACHINE = 0x8664;

  /** A handle that answers every request with one 4-byte instruction. */
  function stubCs(tag: string) {
    const seen: number[] = [];
    return {
      tag,
      seen,
      disasm(bytes: Uint8Array, options: { address: number }) {
        seen.push(options.address);
        if (bytes.length < 4) throw new Error("Failed to disassemble");
        return [
          {
            address: options.address,
            bytes: bytes.subarray(0, 4),
            mnemonic: tag,
            opStr: "",
            size: 4,
          },
        ];
      },
    };
  }

  function armState() {
    return state({ cs32: stubCs("x86-32"), cs64: stubCs("x86-64"), csArm64: stubCs("arm64") });
  }

  async function configureAs(s: WorkerState, machine: number | undefined) {
    await dispatch("configure", { stringEntries: [], iatEntries: [], machine }, s);
  }

  it("starts out as x86, so an un-threaded caller keeps its old behaviour", () => {
    expect(state().arch).toBe("x86");
  });

  it("switches to the ARM64 decoder when configure is told the machine type", async () => {
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    expect(s.arch).toBe("arm64");
  });

  it("switches back for an x86 image loaded afterwards", async () => {
    const s = armState();
    await configureAs(s, ARM64_MACHINE);
    await configureAs(s, AMD64_MACHINE);

    expect(s.arch).toBe("x86");
  });

  it("leaves the architecture alone when configure omits the machine type", async () => {
    // configure runs twice per file — the second time from the effect that
    // re-sends the strings once extraction finishes, which knows nothing about
    // the machine. Resetting here would drop an ARM64 session back to x86
    // halfway through its own analysis.
    const s = armState();
    await configureAs(s, ARM64_MACHINE);
    await configureAs(s, undefined);

    expect(s.arch).toBe("arm64");
  });

  /**
   * peek-a-bin-3ucw. The refusal below is the only consumer of
   * `PEFile.loadConfig.chpeMetadataPointer` in the tree, and the fact has to
   * survive the client → worker hop to reach it. Verified through the real
   * `dispatch`, since nothing else drives the worker's session state.
   *
   * NOT VERIFIED against a real file: no ARM64EC or ARM64X binary exists on this
   * machine, and the only two images here that read the field at all read 0
   * (measured at 11408ac). The non-zero branch is fixture-only.
   */
  describe("a declared CHPE pointer reaches the ARM64 decode-rate refusal", () => {
    /** A handle that decodes one word in four, so a section refuses on rate. */
    function sparseArm64() {
      const seen: number[] = [];
      return {
        tag: "arm64",
        seen,
        disasm(bytes: Uint8Array, options: { address: number }) {
          seen.push(options.address);
          if (bytes.length < 4 || (options.address & 0xf) !== 0) {
            throw new Error("Failed to disassemble");
          }
          return [
            {
              address: options.address,
              bytes: bytes.subarray(0, 4),
              mnemonic: "arm64",
              opStr: "",
              size: 4,
            },
          ];
        },
      };
    }

    const refuse = async (chpeMetadataPointer?: number) => {
      const s = state({ cs64: stubCs("x86-64"), csArm64: sparseArm64() });
      await dispatch(
        "configure",
        {
          stringEntries: [],
          iatEntries: [],
          machine: ARM64_MACHINE,
          chpeMetadataPointer,
        },
        s,
      );
      // 2048 words, well past ARM64_MIN_MEASURED_WORDS, a quarter of which
      // decode — the shape of a hybrid image swept as pure A64.
      const err = await dispatch(
        "disassemble",
        { bytes: new Uint8Array(0x2000), baseAddress: 0x140001000, is64: true },
        s,
      ).then(
        () => undefined,
        (e: Error) => e,
      );
      expect(err).toBeDefined();
      expect(err?.name).toBe("Arm64DecodeRateError");
      return err as Error;
    };

    it("says so when configure declared one", async () => {
      const err = await refuse(0x140020000);
      expect(err.message).toContain("declares CHPE metadata");
      expect(err.message).toContain("0x140020000");
    });

    it("keeps the pre-existing message when configure declared none", async () => {
      // The narrowing must not become a dependency: an image with no
      // load-config directory, or a caller that was never threaded, has to get
      // exactly the message this threw before.
      expect((await refuse(undefined)).message).not.toContain("CHPE");
      expect((await refuse(0)).message).not.toContain("CHPE");
    });

    it("does not carry one file's pointer into the next file's refusal", async () => {
      // A declared machine type is the load handshake, so the CHPE fact is
      // replaced by whatever *that* message said — including nothing. Guarding
      // on the pointer's own presence instead would leave a hybrid image's
      // declaration attached to the next image loaded in the session.
      const s = state({ cs64: stubCs("x86-64"), csArm64: sparseArm64() });
      const conf = (args: Record<string, unknown>) =>
        dispatch("configure", { stringEntries: [], iatEntries: [], ...args }, s);

      await conf({ machine: ARM64_MACHINE, chpeMetadataPointer: 0x140020000 });
      expect(s.chpeMetadataPointer).toBe(0x140020000);
      // The second configure of the *same* file re-sends only the strings and
      // must leave it alone.
      await conf({});
      expect(s.chpeMetadataPointer).toBe(0x140020000);
      // A new file, with no load config of its own.
      await conf({ machine: ARM64_MACHINE });
      expect(s.chpeMetadataPointer).toBeUndefined();
    });
  });

  it("disassembles with the ARM64 handle, not the x86-64 one", async () => {
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    const insns = (await dispatch(
      "disassemble",
      { bytes: new Uint8Array(4), baseAddress: 0x140001000, is64: true },
      s,
    )) as Instruction[];

    expect(insns.map((i) => i.mnemonic)).toEqual(["arm64"]);
    expect(s.cs64.seen).toEqual([]);
  });

  it("routes hybridDisassemble to the ARM64 sweep, ignoring the x86 seeds", async () => {
    // The sweep covers the whole section; the BFS seeds exist only to resolve
    // x86's ambiguous instruction boundaries.
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    const insns = (await dispatch(
      "hybridDisassemble",
      { bytes: new Uint8Array(8), baseAddress: 0x140001000, is64: true, seeds: [0x140001004] },
      s,
    )) as Instruction[];

    expect(insns.map((i) => i.address)).toEqual([0x140001000, 0x140001004]);
    expect(s.cs64.seen).toEqual([]);
  });

  it("detects ARM64 functions from .pdata instead of x86 prologue bytes", async () => {
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    const result = (await dispatch(
      "detectFunctions",
      {
        bytes: new Uint8Array(64),
        baseAddress: 0x140001000,
        is64: true,
        options: {
          pdataFunctions: [{ beginAddress: 0x140001000, endAddress: 0x140001010 }],
        },
      },
      s,
    )) as { functions: { address: number; size: number }[]; jumpTables: unknown[] };

    expect(result.functions).toEqual([{ name: "sub_140001000", address: 0x140001000, size: 16 }]);
    expect(s.cs64.seen).toEqual([]);
  });

  it("refuses to decompile an ARM64 function rather than emitting C for it", async () => {
    // The IR lifter is an x86 grammar. Handed ARM64 instructions it does not
    // throw — it lifts almost nothing and emits a short, confident, wrong
    // function. The panel shows this message instead.
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    await expect(
      dispatch(
        "decompileFunction",
        {
          func: { name: "sub_140001000", address: 0x140001000, size: 16 },
          instructions: [],
          is64: true,
        },
        s,
      ),
    ).rejects.toThrow(/Decompilation is not supported for ARM64/);
  });

  it("invents no xrefs from an instruction stream with no address idiom in it", async () => {
    // The stub decodes everything as one meaningless mnemonic, so there is no
    // adrp/add pair and no `bl` — and the answer is nothing, not a reference
    // scraped out of an operand string. The x86 builder run over these bytes is
    // what would produce those; see the positive case below for the A64 reader
    // actually finding something.
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    const xrefs = await dispatch(
      "buildAllXrefs",
      {
        bytes: new Uint8Array(64),
        baseAddress: 0x140001000,
        is64: true,
        stringAddrs: [0x140002000],
        iatAddrs: [0x140003000],
      },
      s,
    );

    expect(xrefs).toEqual({ stringXrefs: [], importXrefs: [], callGraph: [], dataXrefs: [] });
    expect(s.cs64.seen).toEqual([]);
  });

  it("reports no IRP dispatch table for an ARM64 driver", async () => {
    const s = armState();
    await configureAs(s, ARM64_MACHINE);

    const handlers = await dispatch(
      "detectIRPDispatches",
      { instructions: [insn(0x140001000, "mov", "x0, x1", 4)], is64: true },
      s,
    );

    expect(handlers).toEqual([]);
  });

  it("leaves every x86 route untouched", async () => {
    // The regression that matters most: nothing above may change what an x86
    // image does. With no machine ever sent, every call goes to the x86 handles.
    const s = armState();
    await configureAs(s, undefined);

    await dispatch(
      "disassemble",
      { bytes: new Uint8Array(4), baseAddress: 0x401000, is64: false },
      s,
    );
    await dispatch(
      "hybridDisassemble",
      { bytes: new Uint8Array(4), baseAddress: 0x401000, is64: true, seeds: [0x401000] },
      s,
    );

    expect(s.cs32.seen).toEqual([0x401000]);
    expect(s.cs64.seen).toEqual([0x401000]);
    expect(s.csArm64.seen).toEqual([]);
  });

  /**
   * peek-a-bin-x7b — the third answer. `archForMachine` used to map every
   * machine but ARM64 to `"x86"`, so an ARM32/Thumb image went down the x86
   * routes above and came back a screenful of plausible instructions that were
   * pure fiction. An x86 linear sweep decodes essentially any byte string, so
   * unlike ARM64 (which decoded to nothing, loudly) there was no signal at all.
   *
   * The split is not uniform, and deliberately: the stages whose *entire* output
   * is instructions throw, because a short or empty answer from them is the
   * silent-failure mode peek-a-bin-cen removed; detection answers empty with
   * `omitted` set, because that field exists to say "this is less than the whole
   * answer" and a caller can still use everything the parser read.
   */
  describe("an image with no decoder at all", () => {
    const ARMNT_MACHINE = 0x01c4; // IMAGE_FILE_MACHINE_ARMNT — ARM Thumb-2

    async function armntState() {
      const s = armState();
      await configureAs(s, ARMNT_MACHINE);
      return s;
    }

    it("records the machine type as unsupported rather than as x86", async () => {
      expect((await armntState()).arch).toBe("unsupported");
    });

    it.each([
      ["disassemble", { bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false }],
      [
        "hybridDisassemble",
        { bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false, seeds: [0x401000] },
      ],
    ] as [WorkerMethod, Record<string, unknown>][])(
      "rejects %s instead of returning invented instructions",
      async (method, args) => {
        const s = await armntState();

        await expect(dispatch(method, args, s)).rejects.toThrow(
          /Disassembly is not supported for this image's machine type/,
        );
        // And touched no decoder at all on the way out.
        expect(s.cs32.seen).toEqual([]);
        expect(s.cs64.seen).toEqual([]);
        expect(s.csArm64.seen).toEqual([]);
      },
    );

    it("rejects buildAllXrefs instead of inventing references from x86 operands", async () => {
      const s = await armntState();

      await expect(
        dispatch(
          "buildAllXrefs",
          {
            bytes: new Uint8Array(64),
            baseAddress: 0x401000,
            is64: false,
            stringAddrs: [0x402000],
            iatAddrs: [0x403000],
          },
          s,
        ),
      ).rejects.toThrow(/Cross-reference analysis is not supported for this image's machine type/);
      expect(s.cs32.seen).toEqual([]);
    });

    it("rejects decompileFunction without naming an architecture it did not recognise", async () => {
      const s = await armntState();

      await expect(
        dispatch(
          "decompileFunction",
          {
            func: { name: "sub_401000", address: 0x401000, size: 16 },
            instructions: [],
            is64: false,
          },
          s,
        ),
      ).rejects.toThrow(/Decompilation is not supported for this image's machine type/);
    });

    it("answers detectFunctions empty, with every pass it could not run named", async () => {
      const s = await armntState();

      const result = (await dispatch(
        "detectFunctions",
        {
          bytes: new Uint8Array(64),
          baseAddress: 0x401000,
          is64: false,
          options: { entryPoint: 0x401000, exports: [{ name: "DllMain", address: 0x401000 }] },
        },
        s,
      )) as { functions: unknown[]; jumpTables: unknown[]; omitted: string[] };

      expect(result.functions).toEqual([]);
      expect(result.jumpTables).toEqual([]);
      // Not `[]`: an empty `omitted` means "this is the whole answer", which
      // would be the same silent claim the field was added to prevent.
      expect(result.omitted).toEqual(["call-targets", "jump-tables", "thunk-names", "tail-calls"]);
      expect(s.cs32.seen).toEqual([]);
    });

    it("reports no IRP dispatch table, because there are no instructions to match", async () => {
      const s = await armntState();

      expect(
        await dispatch(
          "detectIRPDispatches",
          { instructions: [insn(0x401000, "push", "{r7, lr}", 2)], is64: false },
          s,
        ),
      ).toEqual([]);
    });

    it("still answers the methods that never needed a decoder", async () => {
      // The point of refusing per stage rather than per file: extractStrings
      // and buildTypedXrefMap read the buffer and the caller's own array, so an
      // ARM32 image keeps everything it was always entitled to.
      const s = await armntState();

      expect(
        await dispatch("buildTypedXrefMap", { instructions: [], imageBounds: undefined }, s),
      ).toEqual([]);
      expect(await dispatch("resetStructRegistry", {}, s)).toBe(true);
    });

    /**
     * peek-a-bin-8ru3. Strings are the one *parser-derived* view whose content
     * comes back over this RPC rather than off the main thread, so the notice's
     * "Still available: … Strings …" is a claim about this very switch. An arch
     * gate added here — the natural-looking symmetry with the four above — would
     * empty the tab the user was just told to open, and no other test would
     * notice: every assertion in the suite above is about a method that refuses.
     */
    it("extracts strings, which is the parser-derived view this RPC still owes", async () => {
      const s = await armntState();
      const marker = "peek-a-bin-armnt-marker";
      const data = new TextEncoder().encode(`${marker}\0`);
      const image = buildMinimalPE32({
        machine: ARMNT_MACHINE,
        sections: [
          {
            name: ".rdata",
            virtualAddress: 0x1000,
            virtualSize: data.length,
            data,
            // Not executable: the string scan reads data sections, and this
            // fixture is about the scan rather than about code.
            characteristics: 0x40000040,
          },
        ],
      });
      const pe = parsePE(image);

      const result = (await dispatch(
        "extractStrings",
        {
          buffer: pe.buffer,
          sections: pe.sections,
          imageBase: pe.optionalHeader.imageBase,
          is64: false,
        },
        s,
      )) as { strings: [number, string][]; stringTypes: [number, string][] };

      expect(result.strings.map(([, v]) => v)).toContain(marker);
      expect(result.stringTypes).not.toEqual([]);
      // And it reached no decoder to do it.
      expect(s.cs32.seen).toEqual([]);
      expect(s.csArm64.seen).toEqual([]);
    });

    it("goes back to the x86 routes when an x86 image is loaded next", async () => {
      const s = await armntState();
      await configureAs(s, AMD64_MACHINE);

      expect(s.arch).toBe("x86");
      await dispatch(
        "disassemble",
        { bytes: new Uint8Array(4), baseAddress: 0x401000, is64: true },
        s,
      );
      expect(s.cs64.seen).toEqual([0x401000]);
    });
  });

  /**
   * peek-a-bin-x4o2: session state cannot be the authority on the architecture,
   * because the message that sets it and the messages that read it are posted
   * from unrelated React effects and the worker services them in arrival order.
   * A request that names its own COFF machine type is answered from that; only
   * one that names none falls back to `state.arch`.
   */
  describe("a request that names its own machine type", () => {
    const ARMNT_MACHINE = 0x01c4;

    it("routes to ARM64 while the session still says x86", async () => {
      const s = armState();
      expect(s.arch).toBe("x86");

      const insns = (await dispatch(
        "disassemble",
        { bytes: new Uint8Array(4), baseAddress: 0x140001000, is64: true, machine: ARM64_MACHINE },
        s,
      )) as Instruction[];

      expect(insns.map((i) => i.mnemonic)).toEqual(["arm64"]);
      expect(s.cs64.seen).toEqual([]);
      // And it did not quietly rewrite the session either: the request speaks
      // for itself and for nothing else.
      expect(s.arch).toBe("x86");
    });

    it("routes to x86 while the session says ARM64", async () => {
      // The second-file case: the worker is mid-ARM64 session when an x86
      // image's decode arrives ahead of its own configure.
      const s = armState();
      await configureAs(s, ARM64_MACHINE);

      const insns = (await dispatch(
        "hybridDisassemble",
        {
          bytes: new Uint8Array(4),
          baseAddress: 0x401000,
          is64: true,
          seeds: [0x401000],
          machine: AMD64_MACHINE,
        },
        s,
      )) as Instruction[];

      expect(insns.map((i) => i.mnemonic)).toEqual(["x86-64"]);
      expect(s.csArm64.seen).toEqual([]);
    });

    it("refuses an unsupported machine while the session says x86", async () => {
      // The one that is not masked by a coverage signal: an x86 sweep decodes
      // A32/T32 bytes into a screenful of plausible fiction.
      const s = armState();

      await expect(
        dispatch(
          "disassemble",
          { bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false, machine: ARMNT_MACHINE },
          s,
        ),
      ).rejects.toThrow(/Disassembly is not supported for this image's machine type/);
      expect(s.cs32.seen).toEqual([]);
    });

    it.each([
      ["detectFunctions", { bytes: new Uint8Array(64), baseAddress: 0x140001000, is64: true }],
      [
        "buildAllXrefs",
        {
          bytes: new Uint8Array(64),
          baseAddress: 0x140001000,
          is64: true,
          stringAddrs: [],
          iatAddrs: [],
        },
      ],
    ] as [WorkerMethod, Record<string, unknown>][])(
      "keeps %s off the x86 handles too",
      async (method, args) => {
        // Every decode-fed method reads the request's machine, not the session.
        // One left behind would keep the race, silently and only for itself.
        const s = armState();

        await dispatch(method, { ...args, machine: ARM64_MACHINE }, s);

        expect(s.cs32.seen).toEqual([]);
        expect(s.cs64.seen).toEqual([]);
      },
    );

    it("refuses to decompile it without consulting the session either", async () => {
      const s = armState();

      await expect(
        dispatch(
          "decompileFunction",
          {
            func: { name: "sub_140001000", address: 0x140001000, size: 16 },
            instructions: [],
            is64: true,
            machine: ARM64_MACHINE,
          },
          s,
        ),
      ).rejects.toThrow(/Decompilation is not supported for ARM64/);
    });

    /**
     * peek-a-bin-gb40. `detectFunctions` publishes the byte extents of the
     * dispatch tables it recovered; this branch is what turns them into words
     * the view never sees. The corpus harness drives `FileSession`, i.e. the
     * `mcp/disasm.ts` path, so nothing there covers this forwarding — without
     * this test the worker could stop passing them and every gate would stay
     * green.
     */
    it("withholds recovered jump-table bytes from the ARM64 view", async () => {
      const s = armState();
      const args = {
        bytes: new Uint8Array(16),
        baseAddress: 0x140001000,
        is64: true,
        seeds: [],
        machine: ARM64_MACHINE,
      };

      const all = (await dispatch("hybridDisassemble", args, s)) as Instruction[];
      const masked = (await dispatch(
        "hybridDisassemble",
        { ...args, jumpTableSpans: [[0x140001004, 0x140001008]] as [number, number][] },
        s,
      )) as Instruction[];

      expect(all.map((i) => i.address)).toEqual([
        0x140001000, 0x140001004, 0x140001008, 0x14000100c,
      ]);
      expect(masked.map((i) => i.address)).toEqual([0x140001000, 0x140001008, 0x14000100c]);
    });

    it("falls back to the session for a request that names none", async () => {
      // The pre-existing contract, and what every un-threaded caller relies on.
      const s = armState();
      await configureAs(s, ARM64_MACHINE);

      const insns = (await dispatch(
        "disassemble",
        { bytes: new Uint8Array(4), baseAddress: 0x140001000, is64: true },
        s,
      )) as Instruction[];

      expect(insns.map((i) => i.mnemonic)).toEqual(["arm64"]);
    });

    it("reads machine 0 as a machine type, not as an absent one", async () => {
      // IMAGE_FILE_MACHINE_UNKNOWN is a value a file can really carry, and `0`
      // is falsy — a truthiness test here would silently decode it as x86.
      const s = armState();

      await expect(
        dispatch(
          "disassemble",
          { bytes: new Uint8Array(64), baseAddress: 0x401000, is64: false, machine: 0 },
          s,
        ),
      ).rejects.toThrow(/not supported for this image's machine type/);
    });
  });
});

describe("dispatch — an exhausted decoder reaches the caller as a rejection", () => {
  /**
   * A handle that has stopped decoding, which is what capstone-wasm looks like
   * once its fixed 16 MiB linear memory is spent: `disasm` throws on every
   * call, including on the one-byte `nop` used as a liveness probe.
   */
  const dead = {
    disasm() {
      throw new Error("Failed to disassemble, error: OK (CS_ERR_OK)");
    },
  };

  /** Bytes big enough for the scan to notice a run of failures. */
  const bytes = () => new Uint8Array(0x1000);

  it.each([
    ["disassemble", { bytes: bytes(), baseAddress: 0x401000, is64: true }],
    ["hybridDisassemble", { bytes: bytes(), baseAddress: 0x401000, is64: true, seeds: [] }],
    ["detectFunctions", { bytes: bytes(), baseAddress: 0x401000, is64: true }],
    [
      "buildAllXrefs",
      { bytes: bytes(), baseAddress: 0x401000, is64: true, stringAddrs: [], iatAddrs: [] },
    ],
  ])("%s rejects instead of resolving with a partial answer", async (method, args) => {
    // This is the whole point of the bead. The worker turns a rejection into
    // `{ id, error }` and the analysis chain turns that into
    // `analysisPhase: "failed"`. A resolved value here is a `.text` that came
    // back 97% empty with nothing anywhere saying so.
    const s = state({ cs32: dead, cs64: dead });

    await expect(dispatch(method as WorkerMethod, args, s)).rejects.toThrow(/Capstone/);
  });

  it("rejects on the ARM64 sweep too", async () => {
    const s = state({ arch: "arm64", csArm64: dead });

    await expect(
      dispatch("hybridDisassemble", { bytes: bytes(), baseAddress: 0x140001000, seeds: [] }, s),
    ).rejects.toThrow(/Capstone/);
  });
});

/**
 * peek-a-bin-g17: the RVA jump table an x64 switch dispatches through lives in
 * `.rdata`, and `detectFunctions` is handed `.text`. The detector has taken
 * `options.dataWindows` for those bytes since peek-a-bin-ydh; nothing sent
 * them. They cross the worker boundary flattened — one top-level buffer plus
 * plain-number spans — because `transfer.ts` only transfers top-level binary
 * arguments and every window is a view onto the whole loaded file. This is the
 * far end of that wire.
 *
 * The Capstone stand-in returns a canned x86-64 dispatch chain rather than
 * decoding: what is under test is whether the windows arrive and are read, not
 * the decoding (`src/disasm/__tests__/functionDetect.test.ts` owns that), and
 * keeping real Capstone out of this file is what keeps it importable and fast.
 */
describe("dispatch — detectFunctions data windows", () => {
  const BASE = 0x140001000;
  const IMAGE_BASE = 0x140000000;
  const TABLE_VA = 0x140002000;
  const CASES = [0x140001020, 0x140001028, 0x140001030];

  /**
   * The MSVC x64 spelling: the `lea` names __ImageBase, the load's
   * displacement carries the table's RVA, and the entries are image-relative.
   *
   *   cmp eax, 2                                  ; the only statement of length
   *   lea r8, [rip - 0x100a]                      ; -> 0x140000000
   *   mov ecx, dword ptr [r8 + rax*4 + 0x2000]    ; -> table at 0x140002000
   *   add rcx, r8
   *   jmp rcx
   */
  const CHAIN = [
    { address: 0x140001000, mnemonic: "cmp", opStr: "eax, 2", size: 3 },
    { address: 0x140001003, mnemonic: "lea", opStr: "r8, [rip - 0x100a]", size: 7 },
    {
      address: 0x14000100a,
      mnemonic: "mov",
      opStr: "ecx, dword ptr [r8 + rax*4 + 0x2000]",
      size: 8,
    },
    { address: 0x140001012, mnemonic: "add", opStr: "rcx, r8", size: 3 },
    { address: 0x140001015, mnemonic: "jmp", opStr: "rcx", size: 2 },
  ];
  const JMP_AT = 0x140001015;

  /** A handle that replays {@link CHAIN}, then pads with `int3`. */
  function cannedCs() {
    return {
      disasm(_bytes: Uint8Array, options: { address: number }) {
        const rest = CHAIN.filter((i) => i.address >= options.address);
        if (rest.length > 0) return rest.map((i) => ({ ...i, bytes: new Uint8Array(i.size) }));
        return [
          {
            address: options.address,
            mnemonic: "int3",
            opStr: "",
            size: 1,
            bytes: new Uint8Array(1),
          },
        ];
      },
    };
  }

  /** Table entries as the file holds them: image-relative dwords. */
  function entries(targets: number[]): Uint8Array {
    const out = new Uint8Array(targets.length * 4);
    const view = new DataView(out.buffer);
    targets.forEach((t, i) => view.setUint32(i * 4, t - IMAGE_BASE, true));
    return out;
  }

  async function detect(extra: Record<string, unknown>) {
    return (await dispatch(
      "detectFunctions",
      {
        bytes: new Uint8Array(0x40).fill(0xcc),
        baseAddress: BASE,
        is64: true,
        options: { entryPoint: BASE },
        ...extra,
      },
      state({ cs64: cannedCs() }),
    )) as { functions: unknown[]; jumpTables: [number, number[]][] };
  }

  it("reads a table that lives outside the code section", async () => {
    // The bead in one assertion: before this, the dispatch dropped `dataBytes`
    // and `dataSpans` on the floor and every x64 switch was invisible.
    const { jumpTables } = await detect({
      dataBytes: entries(CASES),
      dataSpans: [{ base: TABLE_VA, offset: 0, length: 12 }],
    });

    expect(jumpTables).toEqual([[JMP_AT, CASES]]);
  });

  it("finds nothing without them — the limit the windows exist to lift", async () => {
    const { jumpTables } = await detect({});

    expect(jumpTables).toEqual([]);
  });

  it("keys each span by its own base rather than concatenation order", async () => {
    // Two windows in one buffer, the table in the second. Reading the spans as
    // one flat region, or ignoring `base`, resolves the table to junk.
    const decoy = new Uint8Array(16).fill(0xff);
    const table = entries(CASES);
    const dataBytes = new Uint8Array(decoy.length + table.length);
    dataBytes.set(decoy, 0);
    dataBytes.set(table, decoy.length);

    const { jumpTables } = await detect({
      dataBytes,
      dataSpans: [
        { base: 0x140009000, offset: 0, length: decoy.length },
        { base: TABLE_VA, offset: decoy.length, length: table.length },
      ],
    });

    expect(jumpTables).toEqual([[JMP_AT, CASES]]);
  });

  it("reads nothing from a window that does not cover the table", async () => {
    const { jumpTables } = await detect({
      dataBytes: entries(CASES),
      dataSpans: [{ base: 0x140009000, offset: 0, length: 12 }],
    });

    expect(jumpTables).toEqual([]);
  });

  it("ignores a span that runs past the bytes it was sent with", async () => {
    // A worker message is data. A span claiming more than arrived is dropped,
    // not read out of whatever follows in memory.
    const { jumpTables } = await detect({
      dataBytes: entries(CASES),
      dataSpans: [{ base: TABLE_VA, offset: 0, length: 4096 }],
    });

    expect(jumpTables).toEqual([]);
  });

  it("leaves the detector's other options alone", async () => {
    const { functions } = (await detect({
      dataBytes: entries(CASES),
      dataSpans: [{ base: TABLE_VA, offset: 0, length: 12 }],
    })) as { functions: { address: number }[]; jumpTables: [number, number[]][] };

    // `entryPoint` still arrives: the windows are merged into the options
    // object, not substituted for it.
    expect(functions.map((f) => f.address)).toContain(BASE);
  });
});

/**
 * peek-a-bin-aq5: `buildArm64Xrefs` returns exactly what `buildAllXrefs`
 * returns and had no caller — the ARM64 branch here answered with four empty
 * arrays, so an ARM64 image had no string xrefs, no import xrefs, no call graph
 * and no data xrefs at all.
 *
 * The A64 reader takes decoded instructions, so the dispatch re-sweeps the
 * bytes this call already carries; the stub below stands in for that decode.
 * Measured on the real files once wired: t64-arm.exe 81 string refs over 65
 * strings, 194 import refs over 86 IAT slots, 1259 call edges from 373 callers,
 * 378 data refs over 138 targets.
 */
describe("dispatch — buildAllXrefs routes ARM64 to the A64 reader", () => {
  const TEXT_BASE = 0x140001000;
  const STRING_VA = 0x140002480;
  const IAT_VA = 0x140003020;
  const DATA_VA = 0x140004008;
  const CALLEE = 0x140001100;

  /** adrp/add for a string, adrp/ldr for an import, a `bl`, adrp/add for data. */
  const A64 = [
    { address: 0x140001000, mnemonic: "adrp", opStr: "x8, #0x140002000" },
    { address: 0x140001004, mnemonic: "add", opStr: "x1, x8, #0x480" },
    { address: 0x140001008, mnemonic: "adrp", opStr: "x9, #0x140003000" },
    { address: 0x14000100c, mnemonic: "ldr", opStr: "x8, [x9, #0x20]" },
    { address: 0x140001010, mnemonic: "bl", opStr: "#0x140001100" },
    { address: 0x140001014, mnemonic: "adrp", opStr: "x10, #0x140004000" },
    { address: 0x140001018, mnemonic: "add", opStr: "x2, x10, #0x8" },
  ];

  /** Replays {@link A64} from the requested address, then `nop`s. */
  function cannedArm() {
    return {
      disasm(_bytes: Uint8Array, options: { address: number }) {
        const rest = A64.filter((i) => i.address >= options.address);
        const list =
          rest.length > 0 ? rest : [{ address: options.address, mnemonic: "nop", opStr: "" }];
        return list.map((i) => ({ ...i, size: 4, bytes: new Uint8Array(4) }));
      },
    };
  }

  async function xrefs(args: Record<string, unknown> = {}) {
    const s = state({ arch: "arm64", csArm64: cannedArm(), cs64: cannedArm() });
    return (await dispatch(
      "buildAllXrefs",
      {
        bytes: new Uint8Array(0x20),
        baseAddress: TEXT_BASE,
        is64: true,
        stringAddrs: [STRING_VA],
        iatAddrs: [IAT_VA],
        funcEntries: [
          [TEXT_BASE, 0x20],
          [CALLEE, 0x10],
        ],
        dataSections: [{ va: 0x140004000, size: 0x1000 }],
        ...args,
      },
      s,
    )) as {
      stringXrefs: [number, number[]][];
      importXrefs: [number, number[]][];
      callGraph: [number, number[]][];
      dataXrefs: [number, number[]][];
    };
  }

  it("resolves an adrp/add pair to a string reference", async () => {
    expect((await xrefs()).stringXrefs).toEqual([[STRING_VA, [0x140001004]]]);
  });

  it("resolves an adrp/ldr pair to an import reference", async () => {
    expect((await xrefs()).importXrefs).toEqual([[IAT_VA, [0x14000100c]]]);
  });

  it("attributes a direct bl to the function containing it", async () => {
    expect((await xrefs()).callGraph).toEqual([[TEXT_BASE, [CALLEE]]]);
  });

  it("reports an address landing in a data section as a data reference", async () => {
    expect((await xrefs()).dataXrefs).toEqual([[DATA_VA, [0x140001018]]]);
  });

  it("still reports nothing when the caller supplied no strings or imports", async () => {
    const r = await xrefs({ stringAddrs: [], iatAddrs: [] });

    expect(r.stringXrefs).toEqual([]);
    expect(r.importXrefs).toEqual([]);
    // The call graph does not depend on either.
    expect(r.callGraph).toEqual([[TEXT_BASE, [CALLEE]]]);
  });

  it("leaves the x86 branch on the x86 builder", async () => {
    // Nothing above may change what an x86 image does: `arch` stays "x86" and
    // the call goes to buildAllXrefs with the 64-bit handle.
    const used: string[] = [];
    const cs = {
      disasm: (bytes: Uint8Array, options?: { address?: number }) => {
        used.push("cs64");
        return [
          {
            address: options?.address ?? 0,
            bytes,
            mnemonic: "nop",
            opStr: "",
            size: bytes.length,
          },
        ];
      },
    };

    await dispatch(
      "buildAllXrefs",
      {
        bytes: new Uint8Array(64),
        baseAddress: 0x401000,
        is64: true,
        stringAddrs: [],
        iatAddrs: [],
      },
      state({ cs64: cs }),
    );

    expect(used).toContain("cs64");
  });
});

/**
 * peek-a-bin-kis — the ARM64 linear sweep is shared across the RPCs of one file
 * load instead of being redone by each.
 *
 * Three methods need instructions for the same `.text`: `detectFunctions` (for
 * `bl` targets and switch dispatches), `hybridDisassemble` (for the view) and
 * `buildAllXrefs` (for the adrp pairs). None can be handed the previous one's
 * array — an `Instruction[]` carries a `bytes` view per element, which is what
 * ../transfer.ts keeps out of a message — so the sharing happens inside the
 * worker, through `WorkerState.arm64Sweep`. Measured on t64-arm.exe: 3 sweeps /
 * 4083 `cs.disasm` calls / ~390 ms of Capstone, down to 1 / 1361 / ~130 ms.
 *
 * The key is the section's bytes. Both real ARM64 binaries in the corpus base
 * `.text` at 0x140001000, so keying on the address would be unsound on the only
 * two files that exist to test with.
 */
describe("dispatch — the ARM64 sweep is shared across one file's RPCs", () => {
  const TEXT_BASE = 0x140001000;
  const MACHINE_ARM64 = 0xaa64;
  /** Inside the 0x40-byte section, so detection registers it as a function and
   *  the call graph has somewhere to point. */
  const CALLEE = 0x140001020;

  /** An A64 decoder stub that counts how many times it is entered. */
  function countingArm() {
    const stub = {
      calls: 0,
      disasm(bytes: Uint8Array, options: { address: number }) {
        stub.calls++;
        const out: {
          address: number;
          mnemonic: string;
          opStr: string;
          size: number;
          bytes: Uint8Array;
        }[] = [];
        for (let i = 0; i + 4 <= bytes.length; i += 4) {
          out.push({
            address: options.address + i,
            mnemonic: i === 0 ? "bl" : "nop",
            opStr: i === 0 ? `#0x${CALLEE.toString(16)}` : "",
            size: 4,
            bytes: bytes.subarray(i, i + 4),
          });
        }
        return out;
      },
    };
    return stub;
  }

  /** A fresh view of the same section, as `prepareBinaryArgs` gives each RPC. */
  const section = () => new Uint8Array(0x40).fill(0x5a);

  async function load(cs: ReturnType<typeof countingArm>, s: WorkerState) {
    const common = { baseAddress: TEXT_BASE, is64: true, machine: MACHINE_ARM64 };
    const det = (await dispatch(
      "detectFunctions",
      { ...common, bytes: section(), options: { entryPoint: TEXT_BASE } },
      s,
    )) as { functions: { address: number; size: number }[] };
    const insns = (await dispatch(
      "hybridDisassemble",
      { ...common, bytes: section(), seeds: [] },
      s,
    )) as Instruction[];
    const xr = (await dispatch(
      "buildAllXrefs",
      {
        ...common,
        bytes: section(),
        stringAddrs: [],
        iatAddrs: [],
        funcEntries: det.functions.map((f) => [f.address, f.size]),
      },
      s,
    )) as { callGraph: [number, number[]][] };
    return { det, insns, xr, decodes: cs.calls };
  }

  /** Decodes one sweep of the section costs, via the one method that is
   *  deliberately never cached. */
  async function oneSweep(): Promise<number> {
    const cs = countingArm();
    await dispatch(
      "disassemble",
      { bytes: section(), baseAddress: TEXT_BASE, is64: true, machine: MACHINE_ARM64 },
      state({ arch: "arm64", csArm64: cs }),
    );
    return cs.calls;
  }

  it("decodes the section once for detect, hybrid and xrefs together", async () => {
    const cs = countingArm();

    const shared = await load(cs, state({ arch: "arm64", csArm64: cs }));

    // Three RPCs, one sweep — this was 3 x the sweep before the cache.
    expect(shared.decodes).toBe(await oneSweep());
  });

  it("returns the same answers it did when each RPC swept for itself", async () => {
    // The sweep is cached undecorated and every caller re-annotates, so nothing
    // any of the three returns may change. The `hybridDisassemble` array is the
    // one the view renders, and it is compared element by element.
    const cs = countingArm();
    const shared = await load(cs, state({ arch: "arm64", csArm64: cs }));

    const csA = countingArm();
    const detAlone = await dispatch(
      "detectFunctions",
      {
        bytes: section(),
        baseAddress: TEXT_BASE,
        is64: true,
        machine: MACHINE_ARM64,
        options: { entryPoint: TEXT_BASE },
      },
      state({ arch: "arm64", csArm64: csA }),
    );
    const csB = countingArm();
    const insnsAlone = await dispatch(
      "hybridDisassemble",
      { bytes: section(), baseAddress: TEXT_BASE, is64: true, machine: MACHINE_ARM64, seeds: [] },
      state({ arch: "arm64", csArm64: csB }),
    );

    expect(shared.det).toEqual(detAlone);
    expect(shared.insns).toEqual(insnsAlone);
  });

  it("still finds the call graph the shared sweep was needed for", async () => {
    const cs = countingArm();
    const { xr } = await load(cs, state({ arch: "arm64", csArm64: cs }));

    expect(xr.callGraph).toEqual([[TEXT_BASE, [CALLEE]]]);
  });

  it("re-decodes for a second file whose section differs", async () => {
    const cs = countingArm();
    const s = state({ arch: "arm64", csArm64: cs });
    const common = { baseAddress: TEXT_BASE, is64: true, machine: MACHINE_ARM64, seeds: [] };

    await dispatch("hybridDisassemble", { ...common, bytes: new Uint8Array(0x40).fill(0x5a) }, s);
    const afterFirst = cs.calls;
    // Same base address and same length — both real ARM64 binaries are like
    // this — but different bytes, so this must not be answered from memory.
    await dispatch("hybridDisassemble", { ...common, bytes: new Uint8Array(0x40).fill(0xa5) }, s);

    expect(cs.calls).toBeGreaterThan(afterFirst);
  });

  it("drops the held sweep when configure declares a machine type", async () => {
    const cs = countingArm();
    const s = state({ arch: "arm64", csArm64: cs });
    const args = {
      baseAddress: TEXT_BASE,
      is64: true,
      machine: MACHINE_ARM64,
      seeds: [],
      bytes: section(),
    };

    await dispatch("hybridDisassemble", args, s);
    const afterFirst = cs.calls;
    await dispatch("configure", { stringEntries: [], iatEntries: [], machine: MACHINE_ARM64 }, s);
    await dispatch("hybridDisassemble", { ...args, bytes: section() }, s);

    expect(cs.calls).toBeGreaterThan(afterFirst);
  });

  it("keeps the held sweep across a configure that declares no machine type", async () => {
    // The second `configure` of a load re-sends the strings and knows nothing
    // about the machine; it is not a new file and must not cost a re-sweep.
    const cs = countingArm();
    const s = state({ arch: "arm64", csArm64: cs });
    const args = {
      baseAddress: TEXT_BASE,
      is64: true,
      machine: MACHINE_ARM64,
      seeds: [],
      bytes: section(),
    };

    await dispatch("hybridDisassemble", args, s);
    const afterFirst = cs.calls;
    await dispatch("configure", { stringEntries: [], iatEntries: [] }, s);
    await dispatch("hybridDisassemble", { ...args, bytes: section() }, s);

    expect(cs.calls).toBe(afterFirst);
  });

  it("never consults the cache on the x86 path", async () => {
    // The x86 branches decode inside functionDetect.ts and must be untouched.
    const cs = countingArm();
    const s = state({ arch: "x86", csArm64: cs, cs64: cs, cs32: cs });
    let consulted = 0;
    const real = s.arm64Sweep.sweep.bind(s.arm64Sweep);
    s.arm64Sweep.sweep = (...a: Parameters<typeof real>) => {
      consulted++;
      return real(...a);
    };
    const common = { baseAddress: 0x401000, is64: true, bytes: new Uint8Array(0x40), seeds: [] };

    await dispatch("hybridDisassemble", common, s);
    await dispatch("buildAllXrefs", { ...common, stringAddrs: [], iatAddrs: [] }, s);
    await dispatch("detectFunctions", { ...common, options: {} }, s);

    expect(consulted).toBe(0);
  });

  it("does not put a single-function decode in the section's slot", async () => {
    // `disassemble` is the one method that may be handed a sub-range. The cache
    // holds one section, so caching a 16-byte decode would evict the whole
    // `.text` the other three share.
    const cs = countingArm();
    const s = state({ arch: "arm64", csArm64: cs });
    const common = { baseAddress: TEXT_BASE, is64: true, machine: MACHINE_ARM64 };

    await dispatch("hybridDisassemble", { ...common, bytes: section(), seeds: [] }, s);
    const afterSection = cs.calls;
    await dispatch("disassemble", { ...common, bytes: new Uint8Array(0x10).fill(0x5a) }, s);
    await dispatch("hybridDisassemble", { ...common, bytes: section(), seeds: [] }, s);

    // The sub-range decoded (so it grew), but the section was still remembered
    // (so the third call added nothing beyond that one decode).
    expect(cs.calls).toBeGreaterThan(afterSection);
    expect(cs.calls).toBe(afterSection + 1);
  });
});

/**
 * peek-a-bin-y1di — the bytes of a recovered jump table are data, and the
 * worker is where that gets said: `detectFunctions` finds the spans, the client
 * carries them, and this dispatch hands them to the sweep. Dropped here, the
 * gap fill decodes each table's case addresses as instructions again.
 */
describe("dispatch — hybridDisassemble is told which bytes are jump tables", () => {
  /** Decodes any four bytes, so every uncovered byte becomes a gap-fill insn. */
  function everyFourBytes() {
    return {
      disasm(bytes: Uint8Array, options: { address: number }) {
        if (bytes.length < 4) throw new Error("Failed to disassemble");
        return [
          {
            address: options.address,
            bytes: bytes.subarray(0, 4),
            mnemonic: "nop",
            opStr: "",
            size: 4,
          },
        ];
      },
    };
  }

  const sweep = async (jumpTableSpans?: [number, number][]) =>
    (await dispatch(
      "hybridDisassemble",
      {
        bytes: new Uint8Array(16),
        baseAddress: 0x401000,
        is64: true,
        seeds: [],
        jumpTableSpans,
      },
      state({ cs64: everyFourBytes() }),
    )) as Instruction[];

  it("decodes the whole range when no spans are given", async () => {
    expect((await sweep()).map((i) => i.address)).toEqual([0x401000, 0x401004, 0x401008, 0x40100c]);
  });

  it("leaves a span's bytes undecoded", async () => {
    const addrs = (await sweep([[0x401004, 0x40100c]])).map((i) => i.address);

    expect(addrs).toEqual([0x401000, 0x40100c]);
  });
});

/**
 * peek-a-bin-s2ws — the browser gets the per-callee clobber summary.
 *
 * `callSummary.ts` and `IRCall.clobbers` landed with only the MCP/FileSession
 * path wired (`mcp/session.ts` builds it, `mcp/tools.ts` passes it) and
 * `corpus/sweep.ts` measuring it, so the feature was committed and documented
 * while no user could reach it. The argument is optional and absent means
 * byte-identical output, which is exactly what made it invisible.
 *
 * The bead filed it as needing a browser to verify, on the premise that
 * `decompileFunction` "is handed one function's instructions" so a summary must
 * arrive out of band and would race the first decompile. That premise is true of
 * the MCP path and false of this one: `useDecompileTabs` passes the *whole*
 * section's `Instruction[]` — the array `hybridDisassemble` returned — plus every
 * detected function, on every decompile call. So the summary is derived from the
 * same message that consumes it. There is no sender to race, no ordering
 * dependency on `configureDecompileMaps`, and no way for the client's decompile
 * cache to hold an answer computed before the summary existed.
 *
 * Which also makes it testable here rather than only in a browser: the pipeline
 * takes instructions, not bytes, so none of this needs Capstone.
 */
describe("dispatch — decompileFunction builds the callee-clobber summary", () => {
  /** `mov r10, rcx` / `call sub_401100` / `mov [rsi], r10` / `ret`. */
  const CALLER = 0x401000;
  /** `xor r10d, r10d` / `ret` — provably leaves R10 destroyed. */
  const CALLEE = 0x401100;

  const caller = { name: "sub_401000", address: CALLER, size: 0x10 };
  const callee = { name: "sub_401100", address: CALLEE, size: 0x8 };

  /** Address-ascending, as `hybridDisassemble` returns and `funcInsns` needs. */
  const instructions = (): Instruction[] => [
    insn(CALLER, "mov", "r10, rcx", 3),
    insn(CALLER + 3, "call", `0x${CALLEE.toString(16)}`, 5),
    insn(CALLER + 8, "mov", "qword ptr [rsi], r10", 4),
    insn(CALLER + 12, "ret", "", 1),
    insn(CALLEE, "xor", "r10d, r10d", 3),
    insn(CALLEE + 3, "ret", "", 1),
  ];

  const EXTENTS_BOTH: [number, number][] = [
    [caller.address, caller.size],
    [callee.address, callee.size],
  ];
  /** The caller only: the callee's body is then outside the summary's reach. */
  const EXTENTS_CALLER_ONLY: [number, number][] = [[caller.address, caller.size]];

  async function decompile(s: WorkerState, extra: Record<string, unknown> = {}): Promise<string> {
    const r = (await dispatch(
      "decompileFunction",
      {
        func: caller,
        instructions: instructions(),
        stackFrame: null,
        signature: null,
        is64: true,
        funcEntries: [
          [caller.address, { name: caller.name, address: caller.address }],
          [callee.address, { name: callee.name, address: callee.address }],
        ],
        ...extra,
      },
      s,
    )) as { code: string };
    return r.code;
  }

  /** The line that stores R10 through RSI — the one read that is at issue. */
  const storeLine = (code: string) => code.split("\n").find((l) => l.includes("(rsi)"));

  it("names what the callee destroys, not the value the caller left in R10", async () => {
    // R10 is volatile under the ABI and is NOT an argument register, so the
    // narrow model deliberately lets it survive a call — MSVC parks live values
    // there across helpers it has analysed, and clobbering the whole volatile
    // set deleted a guard outright (peek-a-bin-hj1). What makes R10 a clobber
    // *here* is evidence rather than the ABI: sub_401100 contains `xor r10d,
    // r10d`, so the value RCX had is provably gone by the time RSI is stored to.
    // Without the summary this same store is emitted as `= rcx` — see below.
    const code = await decompile(state(), {
      funcExtents: EXTENTS_BOTH,
      insnsToken: 1,
    });

    expect(storeLine(code)).toMatch(/clobbered_r10_\d+/);
    // The pre-call value must not be what the store claims to write.
    expect(storeLine(code)).not.toMatch(/=\s*r10\s*;/);
  });

  it("leaves the answer exactly as it was when no extents are sent", async () => {
    // The pre-summary behaviour, and the reason the wiring could be landed at
    // all: a caller that sends no extents gets byte-identical output.
    //
    // Worth recording what that output *is*, because it is worse than a stale
    // register name and it is what the test above repairs. R10 survives the call
    // under the narrow model, so copy propagation is entitled to forward `mov
    // r10, rcx` straight through it, and the store is emitted as `= rcx` — C
    // that names the caller's incoming RCX at a point where the callee has
    // provably zeroed the register holding it. The value is not merely unnamed,
    // it is confidently wrong; with the summary it becomes an admitted
    // `clobbered_r10_N`. "Clean is not recovered" in both directions.
    const code = await decompile(state());

    expect(storeLine(code)).toMatch(/=\s*rcx\s*;/);
    expect(code).not.toContain("clobbered_");
  });

  it("builds nothing for a 32-bit image, whose lift could not consult it", async () => {
    // `calleeClobbersFor` returns undefined unless `is64`: on x86 nothing is
    // passed in a register, so every register a summary could add would be new
    // evidence the narrow model never had. Building it there is pure cost, and
    // the two PE32 corpus binaries are the control that stays byte-identical.
    const s = state();
    const code = (
      (await dispatch(
        "decompileFunction",
        {
          func: caller,
          instructions: instructions(),
          stackFrame: null,
          signature: null,
          is64: false,
          funcExtents: EXTENTS_BOTH,
          insnsToken: 1,
        },
        s,
      )) as { code: string }
    ).code;

    expect(code).not.toContain("clobbered_");
    // Nothing was cached either, so a later 64-bit request under the same token
    // is answered from a real build rather than from a PE32 leftover.
    expect(await decompile(s, { funcExtents: EXTENTS_BOTH, insnsToken: 1 })).toMatch(
      /clobbered_r10_\d+/,
    );
  });

  it("builds the summary once per instruction array, not once per request", async () => {
    // The summary is a property of the whole image — it is closed over the call
    // graph — while a request is about one function, so rebuilding it per
    // request costs a whole-image walk per click. Measured at ~18 ms over 16.8k
    // instructions and linear in instruction count, on a worker that services
    // messages serially.
    //
    // Observed behaviourally rather than by counting calls: the second request
    // reuses the token but withdraws the callee's extents. A rebuild would then
    // have no body for sub_401100 and no clobber to report, so the clobber
    // surviving *is* the cache hit.
    const s = state();
    await decompile(s, { funcExtents: EXTENTS_BOTH, insnsToken: 7 });

    const again = await decompile(s, { funcExtents: EXTENTS_CALLER_ONLY, insnsToken: 7 });

    expect(again).toMatch(/clobbered_r10_\d+/);
  });

  it("keys the cache on the token, so a new disassembly is not answered from the old one", async () => {
    // The other half of the test above: same withdrawn extents, fresh token, and
    // the answer changes. Without this the previous test would also pass on a
    // cache that never looked at its key at all.
    const s = state();
    await decompile(s, { funcExtents: EXTENTS_BOTH, insnsToken: 7 });

    const other = await decompile(s, { funcExtents: EXTENTS_CALLER_ONLY, insnsToken: 8 });

    expect(other).not.toContain("clobbered_r10");
  });

  it("drops the held summary when configure names a machine", async () => {
    // Hygiene rather than correctness — the client's token counter never resets,
    // so a hit for a different image cannot arise — but it must not keep one
    // file's summaries alive across a load of the next.
    const s = state();
    await decompile(s, { funcExtents: EXTENTS_BOTH, insnsToken: 7 });

    await dispatch("configure", { stringEntries: [], iatEntries: [], machine: 0x8664 }, s);
    const after = await decompile(s, { funcExtents: EXTENTS_CALLER_ONLY, insnsToken: 7 });

    expect(after).not.toContain("clobbered_r10");
  });
});
