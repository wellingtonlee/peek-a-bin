/**
 * The COFF machine type → analysis architecture decision, on a real image.
 *
 * peek-a-bin-x7b. `archForMachine` used to answer `"x86"` for every machine
 * except ARM64, so an ARM32/Thumb PE was handed to the x86 decoder and came
 * back as a full screen of plausible-looking instructions that were pure
 * fiction. There is no coverage signal that catches it: an x86 linear sweep
 * decodes essentially any byte string, unlike the fixed-width A64 decode rate
 * that `arm64.ts` can refuse on. The machine field is the only thing that
 * answers the question, so this pins it against images the parser really read.
 *
 * Synthesized rather than checked in — there is no ARM32 PE on this machine and
 * no binary belongs in the repo (see `fixtures.ts`). What a fixture can prove is
 * exactly what matters here: that the byte at the COFF machine offset reaches
 * the decision, and that refusing costs the parser nothing.
 */

import { describe, expect, it } from "vitest";
import {
  archForMachine,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_I386,
  isKnownMachine,
} from "../../disasm/arch";
import { parsePE } from "../parser";
import { buildMinimalPE32, buildMinimalPE64 } from "./fixtures";

/** IMAGE_FILE_MACHINE_ARMNT — ARM Thumb-2, the machine Windows on ARM32 used. */
const IMAGE_FILE_MACHINE_ARMNT = 0x01c4;
/** IMAGE_FILE_MACHINE_ARM — the original 32-bit little-endian ARM. */
const IMAGE_FILE_MACHINE_ARM = 0x01c0;

describe("an ARM32/Thumb image is recognised as one, not decoded as x86", () => {
  it.each([
    ["ARMNT (0x01C4)", IMAGE_FILE_MACHINE_ARMNT],
    ["ARM (0x01C0)", IMAGE_FILE_MACHINE_ARM],
  ])("reports %s as unsupported", (_label, machine) => {
    const pe = parsePE(buildMinimalPE32({ machine }));

    expect(pe.coffHeader.machine).toBe(machine);
    expect(archForMachine(pe.coffHeader.machine)).toBe("unsupported");
    expect(isKnownMachine(pe.coffHeader.machine)).toBe(false);
  });

  it("is PE32, so nothing about is64 could have distinguished it", () => {
    // The trap this replaces: `is64` is the optional-header magic, a pointer
    // width. An ARM32 image is PE32 exactly like an x86 one, and an ARM64 image
    // is PE32+ exactly like an x64 one, so neither is answerable from `is64`.
    const arm32 = parsePE(buildMinimalPE32({ machine: IMAGE_FILE_MACHINE_ARMNT }));
    const x86 = parsePE(buildMinimalPE32({ machine: IMAGE_FILE_MACHINE_I386 }));

    expect(arm32.is64).toBe(false);
    expect(x86.is64).toBe(false);
    expect(archForMachine(arm32.coffHeader.machine)).not.toBe(
      archForMachine(x86.coffHeader.machine),
    );
  });

  it("still parses everything the format states", () => {
    // The reason the refusal is per analysis stage rather than at load: headers,
    // sections, imports and exports are format-level facts, correct for an ARM32
    // file, and a user should keep all of them. `FileSession.loadFile` therefore
    // skips disassembly instead of letting it throw the whole load away.
    const pe = parsePE(
      buildMinimalPE32({
        machine: IMAGE_FILE_MACHINE_ARMNT,
        directories: {
          imports: [
            {
              libraryName: "KERNEL32.dll",
              functions: [{ name: "Sleep" }, { name: "GetLastError" }],
            },
          ],
          exports: {
            dllName: "arm32.dll",
            addresses: [0x1000],
            names: [{ name: "DllMain", addressIndex: 0 }],
          },
        },
      }),
    );

    expect(pe.sections.map((s) => s.name)).toContain(".text");
    expect(pe.imports).toHaveLength(1);
    expect(pe.imports[0].libraryName).toBe("KERNEL32.dll");
    expect(pe.imports[0].functions).toEqual(["Sleep", "GetLastError"]);
    expect(pe.exports.map((e) => e.name)).toEqual(["DllMain"]);
    expect(pe.optionalHeader.imageBase).toBe(0x00400000);
  });
});

describe("the architectures with a decoder are unaffected", () => {
  it.each([
    ["I386", IMAGE_FILE_MACHINE_I386, "x86"],
    ["AMD64", IMAGE_FILE_MACHINE_AMD64, "x86"],
    ["ARM64", IMAGE_FILE_MACHINE_ARM64, "arm64"],
  ])("still analyses a %s image as %s", (_label, machine, expected) => {
    const build = machine === IMAGE_FILE_MACHINE_I386 ? buildMinimalPE32 : buildMinimalPE64;
    const pe = parsePE(build({ machine }));

    expect(archForMachine(pe.coffHeader.machine)).toBe(expected);
    expect(isKnownMachine(pe.coffHeader.machine)).toBe(true);
  });

  it("keeps the default of the fixture builders on the supported path", () => {
    // The builders default to I386 / AMD64, so every other suite in the repo is
    // on the x86 path and this change cannot have moved any of them.
    expect(archForMachine(parsePE(buildMinimalPE32()).coffHeader.machine)).toBe("x86");
    expect(archForMachine(parsePE(buildMinimalPE64()).coffHeader.machine)).toBe("x86");
  });
});
