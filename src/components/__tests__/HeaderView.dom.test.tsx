// @vitest-environment jsdom

import "../../test/domSetup";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Anomaly } from "../../analysis/anomalies";
import { MAX_SYNC_FILE_METRIC_BYTES } from "../../hooks/asyncMetricState";
import type { AppState } from "../../hooks/usePEFile";
import {
  buildMinimalPE32,
  buildMinimalPE64,
  type PEFixtureOptions,
} from "../../pe/__tests__/fixtures";
import {
  IMAGE_REL_BASED_DIR64,
  IMAGE_REL_BASED_HIGHLOW,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_READ,
} from "../../pe/constants";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { COPY_FAILED_TITLE } from "../../utils/clipboard";
import { metricsWorker } from "../../workers/metricsClient";
import type { FileMetricsResult } from "../../workers/metricsDispatch";
import { HeaderView } from "../HeaderView";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE HEADERS TAB, rendered for the first time.
 *
 * `HeaderView.tsx` is 611 lines and every one of them is formatting: a machine
 * word, two flag words, a subsystem constant, a timestamp, sixteen data
 * directory rows, the metadata block, the signature block, TLS and the
 * relocation blocks. Until this file nothing — no test and no human — had
 * rendered any of it. CLAUDE.md's "Still NOT rendered" list did not even name
 * it.
 *
 * WHY IT MATTERS MORE THAN ITS LINE COUNT. `analysisNotice()`'s
 * `"no-code-section"` kind exists to tell a user that the disassembler has
 * nothing to work with *but these tabs are populated* — and `headers` is the
 * first name in `PARSER_DERIVED_TABS`. A resource-only DLL is an ordinary
 * satellite/MUI file, so that promise is made routinely. It had never been
 * checked that the tab renders anything at all.
 *
 * WHAT THIS SUITE IS FOR, and it is not "a table appeared": every assertion
 * about a value is written against the bytes the fixture actually contains, so
 * a hex/decimal slip, an endianness slip, a wrong bit in a flag table or a
 * truncating formatter fails. That class is invisible to `typecheck` (both
 * spellings are `number`) and to every corpus gate (the corpus never renders).
 * It found one defect on the first run — see `IMAGE BASE`, below.
 *
 * NOT VIRTUALIZED. `HeaderView` renders plain `<table>`s, so every row is in the
 * document and `stubLayoutRect` is deliberately NOT called here. What is on
 * screen is still unanswerable — jsdom does no layout — and nothing below reads
 * as a claim about visibility, geometry or overflow.
 *
 * THE FOUR BLOCKS THAT USED TO BE UNREACHABLE ARE NOW RENDERED. This suite's
 * earlier revision listed the signature block's populated arm, the debug info
 * block, the Rich header and both async arms of the Checksum Validation row as
 * holes the fixture builder could not reach. `src/pe/__tests__/fixtures.ts` now
 * builds all three structures (opt-in, so no existing caller changes), and the
 * async arms are reached by a fixture that is genuinely over
 * `MAX_SYNC_FILE_METRIC_BYTES` rather than by mocking the threshold.
 *
 * IT FOUND A SECOND DEFECT DOING SO — see `Debug Info`, below: `parseDebugDirectory`
 * printed the CodeView PDB GUID in file order, so the first three fields of a
 * `GUID` struct were byte-swapped on every binary with symbols.
 *
 * WHAT IS STILL NOT REACHED, stated rather than skipped:
 *
 *  - **A real signature.** The PKCS#7 blob is DER built by hand and carries no
 *    digest and no signature value, because nothing in this tool verifies
 *    either. What is asserted is the panel printing the fields the DER walk
 *    recovers — never that any of it is cryptographically anything.
 *  - **The metrics worker itself.** The async arms drive the real
 *    `useFileMetrics` and the real reducer, but the reply is either a spy's or
 *    a rejection from `Worker` being absent under jsdom. Nothing here has
 *    watched a real `postMessage`.
 *
 * {@link patchHeader} is how the fields the fixture builder does not expose are
 * set. That was a deliberate choice over extending `src/pe/__tests__/fixtures.ts`
 * — the builder is shared with a dozen suites and the four fields wanted here
 * are one `DataView` write each at offsets the PE spec fixes for both PE32 and
 * PE32+. The three structures above went into the builder instead, because each
 * is a nested layout with internal pointers rather than one field.
 */

/**
 * Set the COFF/optional header fields `buildMinimalPE*` leaves at zero or fixed.
 *
 * The offsets are derived from `e_lfanew` rather than written down: the COFF
 * header starts four bytes past it and the optional header twenty past that.
 * `CheckSum` (64), `Subsystem` (68) and `DllCharacteristics` (70) sit at the
 * SAME optional-header offsets in PE32 and PE32+ — the two layouts diverge at
 * `ImageBase` and re-converge at `SizeOfImage` — which is what makes one helper
 * correct for both, and is asserted by using it on both below.
 *
 * `machine` is the COFF header's first field, so it needs no such argument. It
 * is a *rewrite* rather than a fill: the builders set it, and overwriting it is
 * how an image whose architecture this engine has no decoder for is produced
 * here at all — see `machineArch.test.ts`, which does the same thing to check
 * `archForMachine`. Nothing in `parsePE` routes on it below PE32+ `.pdata`, so
 * a PE32 fixture parses identically whatever is written here.
 */
function patchHeader(
  buf: ArrayBuffer,
  fields: {
    machine?: number;
    timeDateStamp?: number;
    coffCharacteristics?: number;
    checksum?: number;
    subsystem?: number;
    dllCharacteristics?: number;
  },
): ArrayBuffer {
  const dv = new DataView(buf);
  const coff = dv.getUint32(0x3c, true) + 4;
  const opt = coff + 20;
  if (fields.machine !== undefined) dv.setUint16(coff, fields.machine, true);
  if (fields.timeDateStamp !== undefined) dv.setUint32(coff + 4, fields.timeDateStamp, true);
  if (fields.coffCharacteristics !== undefined)
    dv.setUint16(coff + 18, fields.coffCharacteristics, true);
  if (fields.checksum !== undefined) dv.setUint32(opt + 64, fields.checksum, true);
  if (fields.subsystem !== undefined) dv.setUint16(opt + 68, fields.subsystem, true);
  if (fields.dllCharacteristics !== undefined)
    dv.setUint16(opt + 70, fields.dllCharacteristics, true);
  return buf;
}

function renderHeaders(pe: PEFile, over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const view = render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <HeaderView />
    </AppHarness>,
  );
  return { ...view, dispatch, user: userEvent.setup() };
}

/** The `<td>` beside a `Row`'s label — every scalar assertion goes through this. */
function rowValue(label: string): HTMLElement {
  const cell = screen.getByText(label, { selector: "td" });
  const value = cell.nextElementSibling;
  if (!(value instanceof HTMLElement)) throw new Error(`no value cell for row ${label}`);
  return value;
}

/** The chip labels inside one flag row, in render order. */
function chips(label: string): string[] {
  return Array.from(rowValue(label).querySelectorAll("span.rounded")).map((s) =>
    (s.textContent ?? "").trim(),
  );
}

describe("HeaderView on a minimal PE32", () => {
  const pe = () => parsePE(buildMinimalPE32());

  it("prints the COFF header against the fixture's own bytes", () => {
    renderHeaders(pe());
    expect(screen.getByText("COFF Header")).toBeTruthy();
    // 0x014C, four hex digits, and the name out of `MachineTypes`. A raw
    // unmapped number here would read "(Unknown)".
    expect(rowValue("Machine").textContent).toBe("0x014C (x86)");
    // Two sections: the default `.text` plus nothing else.
    expect(rowValue("Number of Sections").textContent).toBe("1");
    expect(rowValue("Size of Optional Header").textContent).toBe("224");
  });

  it("prints the optional header, PE32-width", () => {
    renderHeaders(pe());
    expect(rowValue("Magic").textContent).toBe("0x010B (PE32)");
    // Eight hex digits for a 32-bit image, sixteen for a 64-bit one; the width
    // is `pe.is64`, so this row and the PE64 one below are the pair that checks
    // it.
    expect(rowValue("Image Base").textContent).toBe("0x00400000");
    expect(rowValue("Section Alignment").textContent).toBe("4096");
    expect(rowValue("File Alignment").textContent).toBe("512");
    expect(rowValue("Size of Image").textContent).toBe("0x00010000");
    expect(rowValue("Size of Headers").textContent).toBe("0x00000200");
    expect(rowValue("Number of RVA and Sizes").textContent).toBe("16");
  });

  it("spells the entry point as a VA and the RVA beside it", async () => {
    const { dispatch, user } = renderHeaders(pe());
    const row = rowValue("Entry Point");
    // imageBase 0x00400000 + entry RVA 0x1000.
    // No space in `textContent`: the gap between the two is an `ml-2` margin,
    // not a text node. Asserting the concatenation is what keeps this honest
    // about what the DOM holds rather than about what the screen looks like.
    expect(row.textContent).toBe("0x00401000(RVA: 0x00001000)");
    await user.click(within(row).getByRole("button", { name: "0x00401000" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x401000 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });
});

describe("HeaderView on a minimal PE64", () => {
  const pe = () => parsePE(buildMinimalPE64());

  it("prints the COFF header and the PE32+ magic", () => {
    renderHeaders(pe());
    expect(rowValue("Machine").textContent).toBe("0x8664 (x64)");
    expect(rowValue("Magic").textContent).toBe("0x020B (PE32+)");
  });

  it("prints an ImageBase above 4 GiB WITHOUT truncating it", () => {
    // THE DEFECT THIS SUITE FOUND, and the reason a render test earns its keep
    // here. `CopyableHex` spelled its value `(value >>> 0).toString(16)`.
    // `>>> 0` is ToUint32: it is the right way to respell a negative int32
    // unsigned, and it also silently reduces MODULO 2^32. The fixture's
    // ImageBase is 0x140000000 — the MSVC default for an x64 EXE, 0x180000000
    // for a DLL — so the row read `0x0000000040000000`, two rows under an Entry
    // Point of 0x140001000 the same panel had spelled correctly.
    //
    // Live on essentially every 64-bit binary the tool opens: `HeaderView` is
    // mounted unconditionally by `App.tsx`'s `tabComponents` for the `headers`
    // tab, with no gate in front of it.
    //
    // Nothing static could see it. `value` is `number` either way, so typecheck
    // is silent; the corpus never renders; and `>>> 0` beside a `padStart(16)`
    // reads as deliberate.
    renderHeaders(pe());
    expect(rowValue("Image Base").textContent).toBe("0x0000000140000000");
    expect(rowValue("Entry Point").textContent).toBe("0x0000000140001000(RVA: 0x00001000)");
  });
});

describe("HeaderView flag and constant tables", () => {
  it("decodes COFF characteristics on the right bits, and only those", () => {
    // 0x3122 = DLL(0x2000) | SYSTEM(0x1000) | 32BIT_MACHINE(0x0100) |
    // LARGE_ADDRESS_AWARE(0x0020) | EXECUTABLE_IMAGE(0x0002). `decodeFlags`
    // walks the table testing `value & bit`, so a table entry on the wrong bit
    // shows up as a missing or an extra chip and nowhere else. The ORDER is the
    // table's insertion order, i.e. ascending bit, which is worth pinning too:
    // a reader compares this column against `dumpbin /headers`.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { coffCharacteristics: 0x3122 })));
    expect(rowValue("Characteristics").textContent).toContain("0x3122");
    expect(chips("Characteristics")).toEqual([
      "EXECUTABLE_IMAGE",
      "LARGE_ADDRESS_AWARE",
      "32BIT_MACHINE",
      "SYSTEM",
      "DLL",
    ]);
  });

  it("decodes DLL characteristics on the right bits, including bit 15", () => {
    // 0x8160 = TERMINAL_SERVER_AWARE | NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA.
    // Bit 15 is the one an `& `-based decode gets wrong if anything upstream
    // ever narrows the word, so it is in the fixture on purpose.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { dllCharacteristics: 0x8160 })));
    expect(rowValue("DLL Characteristics").textContent).toContain("0x8160");
    expect(chips("DLL Characteristics")).toEqual([
      "HIGH_ENTROPY_VA",
      "DYNAMIC_BASE",
      "NX_COMPAT",
      "TERMINAL_SERVER_AWARE",
    ]);
  });

  it("says `none` rather than an empty row when a flag word is zero", () => {
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { coffCharacteristics: 0 })));
    expect(chips("Characteristics")).toEqual([]);
    expect(rowValue("Characteristics").textContent).toContain("none");
  });

  it("names a known subsystem and admits an unknown one", () => {
    const { unmount } = renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { subsystem: 3 })));
    // Printed in DECIMAL with the name beside it — not hex; a reader comparing
    // this against `dumpbin` sees `3 (Windows CUI)`.
    expect(rowValue("Subsystem").textContent).toBe("3 (Windows CUI)");
    unmount();

    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { subsystem: 42 })));
    // The honest arm: an unmapped constant must say so rather than print a bare
    // number that reads as a decoded answer.
    expect(rowValue("Subsystem").textContent).toBe("42 (Unknown)");
  });

  it("formats the timestamp in UTC, not in the reader's timezone", () => {
    // 0x5F0E4B00 = 1594772224 = 2020-07-15 00:17:04 UTC. `toUTCString()` is
    // what makes this assertion stable, and the exact GMT spelling is pinned
    // rather than a substring so that swapping it for `toString()` or
    // `toLocaleString()` fails.
    //
    // This machine's TZ is UTC, so the obvious worry was that a local-time
    // control would be inert here. MEASURED, and it is not: swapping
    // `toUTCString()` for `toString()` turns this red even at offset zero,
    // because the two spell the same instant differently ("Wed, 15 Jul 2020
    // 00:17:04 GMT" against "Wed Jul 15 2020 00:17:04 GMT+0000 (…)"). Pinning
    // the exact string rather than a substring is what buys that.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { timeDateStamp: 0x5f0e4b00 })));
    expect(rowValue("Timestamp").textContent).toBe("0x5F0E4B00 (Wed, 15 Jul 2020 00:17:04 GMT)");
  });

  it("dates a zero timestamp at the epoch rather than leaving the cell blank", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(rowValue("Timestamp").textContent).toBe("0x00000000 (Thu, 01 Jan 1970 00:00:00 GMT)");
  });
});

/**
 * THE MACHINE ROW, and the one word this table used to be misleading about.
 *
 * `MachineTypes` carried `IMAGE_FILE_MACHINE_ARM` (0x01C0) — the obsolete,
 * pre-Thumb-2 value that essentially never appears in a linked image — and not
 * ARMNT (0x01C4), which is the word every 32-bit ARM Windows binary actually
 * carries. So the Headers tab of exactly the image `unsupportedArchMessage`
 * exists for printed `0x01C4 (Unknown)` two rows from an `ARM` entry naming a
 * machine the reader will never meet (peek-a-bin-0cct).
 *
 * These assertions are the pair that makes the fix a *fix* rather than a
 * widening: the named arm must print the name, and the fallback arm must still
 * say `(Unknown)`, or the row would be printing a name for everything and the
 * first assertion would say nothing.
 */
describe("HeaderView machine names", () => {
  it("names ARMNT, the machine word a real 32-bit ARM image carries", () => {
    const { unmount } = renderHeaders(
      parsePE(patchHeader(buildMinimalPE32(), { machine: 0x01c4 })),
    );
    expect(rowValue("Machine").textContent).toBe("0x01C4 (ARM Thumb-2)");
    unmount();

    // Its obsolete sibling keeps its own name and its own spelling — the two are
    // different machines and the table must not fold them together.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { machine: 0x01c0 })));
    expect(rowValue("Machine").textContent).toBe("0x01C0 (ARM)");
  });

  it("still admits a machine word the table does not name", () => {
    // 0x5064 = IMAGE_FILE_MACHINE_RISCV64, deliberately NOT in `MachineTypes`:
    // `(Unknown)` beside a correct hex word is an honest statement about the
    // table, and the table's rule is to name what would otherwise be misleading
    // rather than to be complete. This is the liveness half of the assertion
    // above — a table that named everything would pass that one vacuously.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { machine: 0x5064 })));
    expect(rowValue("Machine").textContent).toBe("0x5064 (Unknown)");
  });

  it("prints the machine word at four hex digits, not eight", () => {
    // `width={4}` on the `CopyableHex`. 0x01C4 has a leading zero, so a default
    // width would read `0x000001C4` and a missing `padStart` `0x1C4`.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { machine: 0x01c4 })));
    const hex = within(rowValue("Machine")).getByRole("button").textContent;
    expect(hex).toBe("0x01C4");
  });
});

describe("HeaderView data directories", () => {
  it("names all sixteen and admits the one the table does not name", () => {
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "ExitProcess" }] }],
        },
      }),
    );
    const { container } = renderHeaders(pe);
    const table = screen.getByText("Data Directories").nextElementSibling as HTMLElement;
    const rows = Array.from(table.querySelectorAll("tbody tr"));
    expect(rows).toHaveLength(16);
    expect(rows).toHaveLength(pe.dataDirectories.length);

    // Row 1 is the one the fixture filled in; RVA and size come off the parsed
    // directory rather than being restated, so an endianness slip in either
    // half of the 8-byte entry fails here.
    const imports = rows[1];
    expect(imports.textContent).toContain("Import Table");
    const rva = pe.dataDirectories[1].virtualAddress;
    expect(imports.textContent).toContain(`0x${rva.toString(16).toUpperCase().padStart(8, "0")}`);
    expect(rva).toBeGreaterThan(0);

    // `DataDirectoryNames` stops at 14 (the reserved last entry has no name),
    // so index 15 must fall back rather than render an empty cell.
    expect(rows[15].textContent).toContain("Directory 15");
    expect(container.textContent).toContain("CLR Runtime Header");
  });

  /**
   * THE ONE ROW THE COLUMN HEADING IS WRONG ABOUT.
   *
   * Directory 4's address field is a raw FILE OFFSET, not an RVA — the
   * attribute certificates sit outside every section — and
   * `parseSecurityDirectory` reads it as one. The heading said "RVA" over all
   * sixteen rows, so that row was correctly read and incorrectly labelled
   * (peek-a-bin-xnne).
   *
   * The correction is a muted parenthetical on the row, in the panel's own
   * idiom. These three assertions are what make it a marker rather than
   * decoration: it is ON the certificate row, ABSENT from an ordinary one, and
   * appears EXACTLY ONCE in the table — a marker on every row is no marker.
   */
  it("marks the certificate row's address as a file offset, and only that row", () => {
    const pe = parsePE(buildMinimalPE64());
    const { container } = renderHeaders(pe);
    const table = screen.getByText("Data Directories").nextElementSibling as HTMLElement;
    const rows = Array.from(table.querySelectorAll("tbody tr"));

    // The heading is unchanged and still says "RVA". Weakening it to
    // "RVA / offset" would make fifteen correct rows ambiguous to disambiguate
    // one, and `dumpbin` prints this value under "RVA" too.
    const heads = Array.from(table.querySelectorAll("thead th")).map((h) => h.textContent);
    expect(heads).toEqual(["#", "Name", "RVA", "Size"]);

    expect(rows[4].textContent).toContain("Certificate Table");
    expect(rows[4].textContent).toContain("(file offset)");

    // UNCONDITIONAL: this fixture is unsigned, so directory 4 is 0/0. The
    // statement is about the field, not about the value — suppressing it when
    // empty would make it read as a property of this file, and would leave the
    // table saying "RVA" over that row on nearly every binary anyone opens.
    expect(pe.dataDirectories[4].virtualAddress).toBe(0);
    expect(rows[4].textContent).toContain("0x00000000");
    expect(container.textContent).toContain("(file offset)");
  });

  // The two halves of "and only that row", kept in SEPARATE tests on purpose:
  // in one `it` the first failure hides the second, so a control that puts the
  // marker everywhere would only ever be seen to redden whichever came first.
  // Split, each is independently demonstrated.
  it("counts exactly one file-offset marker in the sixteen rows", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    const table = screen.getByText("Data Directories").nextElementSibling as HTMLElement;
    const marked = Array.from(table.querySelectorAll("tbody tr")).filter((r) =>
      (r.textContent ?? "").includes("(file offset)"),
    );
    expect(marked).toHaveLength(1);
  });

  it("leaves an ordinary directory row unmarked", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    const table = screen.getByText("Data Directories").nextElementSibling as HTMLElement;
    const imports = Array.from(table.querySelectorAll("tbody tr"))[1];
    expect(imports.textContent).toContain("Import Table");
    expect(imports.textContent).not.toContain("(file offset)");
  });
});

describe("HeaderView metadata block", () => {
  it("computes an imphash when there are imports and says so when there are none", () => {
    const withImports = parsePE(
      buildMinimalPE64({
        directories: {
          imports: [
            { libraryName: "KERNEL32.dll", functions: [{ name: "ExitProcess" }, { ordinal: 4 }] },
          ],
        },
      }),
    );
    const { unmount } = renderHeaders(withImports);
    // 32 lowercase hex digits, and the same digest `computeImphash` produced —
    // `pe/__tests__/metadata.test.ts` is what pins the digest itself against
    // pefile; this only checks it reached the page.
    expect(rowValue("Imphash").textContent).toMatch(/^[0-9a-f]{32}$/);
    unmount();

    renderHeaders(parsePE(buildMinimalPE64()));
    expect(rowValue("Imphash").textContent).toBe("No imports");
  });

  it("withholds the imphash for a truncated import table, and does not call it absent", () => {
    // THE REFUSAL, ON SCREEN. `computeImphash` returns null rather than a
    // digest when the import table could not be read whole, because a hash over
    // a short list is well-formed, wrong, and only ever compared with another
    // tool's answer — so it fails by matching nothing (`peek-a-bin-tmo9`).
    //
    // `null` and `""` are both falsy and the row must NOT collapse them: an
    // image that imports nothing and an image whose import table was cut short
    // are different facts, and printing "No imports" for the second is exactly
    // the narrower answer wearing a complete one's shape. That is the whole
    // reason this row exists — the two branches are one `?:` apart in the
    // source and nothing static can tell them apart.
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "ExitProcess" }] }],
        },
      }),
    );
    pe.importsTruncated = true;
    renderHeaders(pe);
    const text = rowValue("Imphash").textContent ?? "";
    expect(text).toContain("Unavailable");
    expect(text).toContain("incomplete");
    expect(text).not.toBe("No imports");
    expect(text).not.toMatch(/[0-9a-f]{32}/);
  });

  it("distinguishes an unset checksum from a wrong one", () => {
    // The fixtures never write CheckSum, which is the common real case for a
    // freshly linked non-signed image and must NOT read as "Invalid".
    const { unmount } = renderHeaders(parsePE(buildMinimalPE64()));
    expect(rowValue("Checksum Validation").textContent).toBe("Not set (0x00000000)");
    unmount();

    // A non-zero checksum that is not the file's real one. Both numbers must be
    // on the page: "Invalid" with no expected/actual pair is unactionable.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { checksum: 0xdeadbeef })));
    const cell = rowValue("Checksum Validation").textContent ?? "";
    expect(cell).toContain("Invalid");
    expect(cell).toContain("0xDEADBEEF");
  });

  it("reports an overlay with its offset and size, in hex and decimal", () => {
    // A FIXTURE ARTEFACT, pinned deliberately rather than worked around: the
    // builder writes `SizeOfRawData = data.length` (4) while padding the file to
    // `FileAlignment` (0x200), so 508 bytes sit past the last section's declared
    // raw data and `detectOverlay` is right to call them an overlay. A real
    // linker aligns SizeOfRawData, which is why this row usually reads "None".
    //
    // Worth having anyway: it is the only arm of this row a fixture reaches, it
    // checks the hex/decimal mixture in the sentence (offset hex, size decimal
    // with separators), and the "None" arm is one `??`.
    const pe = parsePE(buildMinimalPE64());
    renderHeaders(pe);
    expect(rowValue("Overlay").textContent).toBe("Detected at offset 0x204, 508 bytes");
    // Derived, so the row cannot agree with a wrong walk: 0x200 + 4.
    expect(pe.sections[pe.sections.length - 1]).toMatchObject({
      pointerToRawData: 0x200,
      sizeOfRawData: 4,
    });
  });

  it("copies a hex value to the clipboard and flags it, briefly", async () => {
    const { user } = renderHeaders(parsePE(buildMinimalPE64()));
    const button = within(rowValue("Size of Image")).getByRole("button");
    await user.click(button);
    // `userEvent.setup()` installs the clipboard stub jsdom has not got. What
    // this proves is that the handler runs and writes the SAME text the row
    // shows — not that a browser's clipboard would accept it.
    expect(await navigator.clipboard.readText()).toBe("0x00010000");
    // ...and that the success flash is the one that appears. The value is
    // unchanged either way, so the colour is the whole of the feedback.
    await waitFor(() => expect(button.className).toContain("text-green-400"));
    expect(button.className).not.toContain("text-red-400");
    expect(button.getAttribute("title")).toBe("Click to copy");
  });

  /**
   * THE PLAIN-HTTP DEPLOYMENT (`peek-a-bin-p0tz`), as far as jsdom can reach it.
   *
   * `navigator.clipboard` is a secure-context API, so over plain `http:` off
   * localhost the whole object is absent — and this handler used to be
   * `navigator.clipboard.writeText(hex).then(() => setCopied(true))`, which
   * throws a TypeError at the property access before the `.then` is ever
   * reached. Two separate claims here, and both are the point:
   *
   *  1. the click does not throw, and
   *  2. it does not flash GREEN, which is what a naive `catch` would have left
   *     — a tick over a copy that never happened is worse than a throw,
   *     because the user believes it worked and moves on.
   *
   * STAND-IN, NOT A BROWSER: the absence is manufactured by deleting the
   * property. Nothing here has served this app over http to a browser, so what
   * is verified is the component's behaviour GIVEN the absence, not that a
   * browser produces it.
   */
  it("flashes a failure, not a tick, when there is no clipboard", async () => {
    const { user } = renderHeaders(parsePE(buildMinimalPE64()));
    const button = within(rowValue("Size of Image")).getByRole("button");
    // AFTER `renderHeaders`, which calls `userEvent.setup()` — that installs a
    // clipboard stub of its own, so deleting first would simply be undone.
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });

    await user.click(button);

    await waitFor(() => expect(button.className).toContain("text-red-400"));
    expect(button.className).not.toContain("text-green-400");
    // The value the row is for is untouched: this changes what the user is
    // told, never what the site copies.
    expect(button.textContent).toBe("0x00010000");
    expect(button.getAttribute("title")).toBe(COPY_FAILED_TITLE);
  });
});

describe("HeaderView collapsible sections", () => {
  it("reports an unsigned binary as unsigned, and folds away", async () => {
    const { user } = renderHeaders(parsePE(buildMinimalPE64()));
    expect(screen.getByText("Unsigned")).toBeTruthy();
    expect(screen.getByText("No digital signature found in this binary.")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: /Digital Signature/ }));
    expect(screen.queryByText("No digital signature found in this binary.")).toBeNull();
    // The badge is in the toggle itself, so it survives collapsing.
    expect(screen.getByText("Unsigned")).toBeTruthy();
  });

  it("omits TLS and Base Relocations entirely when the directories are absent", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(screen.queryByText(/TLS Directory/)).toBeNull();
    expect(screen.queryByText(/Base Relocations/)).toBeNull();
  });

  it("renders TLS callbacks as untruncated 64-bit VAs", async () => {
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          tls: {
            startAddressOfRawData: 0x140003000,
            endAddressOfRawData: 0x140003100,
            addressOfIndex: 0x140004000,
            sizeOfZeroFill: 0x20,
            callbacks: [0x140001500, 0x140001600],
          },
        },
      }),
    );
    const { dispatch, user } = renderHeaders(pe);
    expect(screen.getByText(/TLS Directory/).textContent).toContain("(2 callbacks)");
    // Same defect class as Image Base: these are image-based VAs, so every one
    // of them was reduced mod 2^32 before the fix.
    expect(rowValue("Raw Data Start").textContent).toBe("0x0000000140003000");
    expect(rowValue("Raw Data End").textContent).toBe("0x0000000140003100");
    expect(rowValue("Address of Index").textContent).toBe("0x0000000140004000");
    expect(rowValue("Size of Zero Fill").textContent).toBe("32");

    // The callback list is spelled by the section itself, not by `CopyableHex`.
    const cb = within(rowValue("Callbacks")).getByRole("button", {
      name: "0x0000000140001500",
    });
    await user.click(cb);
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001500 });
  });

  it("counts relocation blocks and entries, and names the types on expand", async () => {
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          relocations: [
            {
              virtualAddress: 0x1000,
              entries: [
                { type: IMAGE_REL_BASED_DIR64, offset: 0x10 },
                { type: IMAGE_REL_BASED_DIR64, offset: 0x18 },
                { type: IMAGE_REL_BASED_HIGHLOW, offset: 0x20 },
              ],
            },
            { virtualAddress: 0x2000, entries: [{ type: IMAGE_REL_BASED_HIGHLOW, offset: 4 }] },
          ],
        },
      }),
    );
    const { user } = renderHeaders(pe);
    const toggle = screen.getByRole("button", { name: /Base Relocations/ });
    expect(toggle.textContent).toContain("(2 blocks, 4 entries)");
    // Collapsed by default — the block list can be thousands of rows.
    expect(screen.queryByText(/DIR64/)).toBeNull();

    await user.click(toggle);
    // Type counts per block, named out of `RelocTypeNames`. `Object.entries`
    // over a numeric-keyed object walks ascending, so HIGHLOW (3) precedes
    // DIR64 (10) whatever order the entries were written in.
    expect(screen.getByText("HIGHLOW: 1, DIR64: 2")).toBeTruthy();
    expect(screen.getByText("HIGHLOW: 1")).toBeTruthy();
    // Scoped: "0x00001000" is also the entry-point RVA higher up the page, so a
    // document-wide query here would be ambiguous rather than wrong.
    const list = toggle.nextElementSibling as HTMLElement;
    expect(within(list).getByText("0x00001000")).toBeTruthy();
    expect(within(list).getByText("0x00002000")).toBeTruthy();
  });
});

describe("HeaderView anomaly banners", () => {
  const ANOMALIES: Anomaly[] = [
    { severity: "info", title: "Info thing", detail: "info detail" },
    { severity: "critical", title: "Critical thing", detail: "critical detail" },
    { severity: "warning", title: "Warning thing", detail: "warning detail" },
  ];

  it("orders banners by severity regardless of detection order", () => {
    const { container } = renderHeaders(parsePE(buildMinimalPE64()), { anomalies: ANOMALIES });
    const titles = Array.from(container.querySelectorAll("span.font-semibold"))
      .map((s) => (s.textContent ?? "").trim())
      .filter((t) => t.endsWith("thing"));
    // The component's `order` array, not the array it was handed.
    expect(titles).toEqual(["Critical thing", "Warning thing", "Info thing"]);
  });

  it("dismisses one banner without disturbing the others", async () => {
    const { user } = renderHeaders(parsePE(buildMinimalPE64()), { anomalies: ANOMALIES });
    const dismissers = screen.getAllByTitle("Dismiss");
    expect(dismissers).toHaveLength(3);
    await user.click(dismissers[0]);
    expect(screen.queryByText("Critical thing")).toBeNull();
    expect(screen.getByText("Warning thing")).toBeTruthy();
    expect(screen.getByText("Info thing")).toBeTruthy();
  });

  it("renders no banner region at all when there are no anomalies", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(screen.queryAllByTitle("Dismiss")).toEqual([]);
  });
});

describe("HeaderView with nothing to show", () => {
  it("renders every fixed section for a PE with no optional directory at all", () => {
    // The resource-only-DLL shape as far as this fixture builder reaches: one
    // section, no imports, no exports, no TLS, no relocations, no certificate.
    // An empty state that THROWS is the defect class these four tabs exist to
    // rule out, since `analysisNotice`'s `"no-code-section"` prose sends the
    // user here.
    const { container } = renderHeaders(parsePE(buildMinimalPE64()));
    for (const heading of ["COFF Header", "Optional Header", "Data Directories", "Metadata"]) {
      expect(screen.getByText(heading)).toBeTruthy();
    }
    expect(container.textContent).not.toBe("");
  });

  it("renders nothing at all with no PE loaded", () => {
    const { container } = render(
      <AppHarness state={stateWithPE(null as unknown as PEFile)} dispatch={vi.fn()}>
        <HeaderView />
      </AppHarness>,
    );
    expect(container.innerHTML).toBe("");
  });
});

/**
 * The 16 GUID bytes as they sit in the file, chosen so every one of the four
 * `GUID` fields is distinguishable from the others: a swap applied to the wrong
 * field, or to all sixteen bytes, cannot produce the same string.
 */
const CV_GUID = new Uint8Array([
  0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
]);

/**
 * The canonical text form of {@link CV_GUID}, derived here from the bytes
 * rather than written out, so this assertion is not a second copy of the
 * production formatter's answer.
 *
 * `GUID` is `{ DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8] }` in native
 * (little-endian) order, and the text form prints the first three as integers.
 */
function guidTextOf(bytes: Uint8Array): string {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const hex = (n: number, w: number) => n.toString(16).toUpperCase().padStart(w, "0");
  const tail = Array.from(bytes.subarray(8))
    .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
    .join("");
  return `${hex(dv.getUint32(0, true), 8)}-${hex(dv.getUint16(4, true), 4)}-${hex(
    dv.getUint16(6, true),
    4,
  )}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}

describe("HeaderView debug info", () => {
  it("is absent entirely when the image has no debug directory", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(screen.queryByText("Debug Info")).toBeNull();
  });

  /**
   * THE SECOND DEFECT THIS SUITE FOUND, and it is the `Ordinal_<n>` class
   * rather than the `>>> 0` class: a value nothing inside the tool ever compares
   * with anything, so a wrong spelling is well-formed and simply matches nothing
   * outside it.
   *
   * `CV_INFO_PDB70.Signature` is a `GUID` struct — `DWORD Data1; WORD Data2;
   * WORD Data3; BYTE Data4[8]` — stored in native byte order, and the canonical
   * text form prints the first three fields as integers. `parseDebugDirectory`
   * hex-joined all sixteen bytes in file order, so the first three groups came
   * out byte-swapped. That string is the symbol-server key for the PDB
   * (`foo.pdb/<GUID><Age>/foo.pdb`), so what reached the page could never be
   * used to fetch symbols for the binary it was read out of.
   *
   * THE ORACLE IS REAL MSVC OUTPUT, not this fixture. `CoCreateGuid` mints
   * version-4 UUIDs, and the version nibble is the first hex digit of the THIRD
   * group — the one this swap moves. Across the four x86 corpus binaries plus
   * `t64-arm.exe` the corrected reading gives version 4 five times out of five;
   * the file-order reading gave E, 4, 7 and B. The RFC 4122 variant bits live in
   * `Data4`, which does not move, and read `10` under both.
   *
   * Nothing static could see it: both spellings are `string`, the corpus never
   * renders, and `pe/__tests__/metadata.test.ts` had PINNED THE DEFECT AS THE
   * RULE under the comment "Bytes 01..10 in file order, formatted as a GUID
   * string" — a restatement of the implementation rather than of the format.
   */
  it("prints the CodeView GUID as a GUID struct, not as sixteen bytes in file order", () => {
    const pdbPath = "C:\\src\\peekabin\\Release\\sample.pdb";
    renderHeaders(
      parsePE(
        buildMinimalPE64({
          directories: {
            debug: [{ type: 2, codeView: { guid: CV_GUID, age: 11, pdbPath } }],
          },
        }),
      ),
    );

    expect(screen.getByText("Debug Info")).toBeTruthy();
    const cell = rowValue("CodeView");
    expect(cell.textContent).toBe(`${pdbPath}GUID: ${guidTextOf(CV_GUID)} Age: 11`);
    // Spelled out once, so that a change to `guidTextOf` cannot quietly make the
    // line above agree with a wrong formatter: Data1/2/3 swapped, Data4 not.
    expect(cell.textContent).toContain("DDCCBBAA-2211-4433-5566-778899AABBCC");
    // ...and the byte string this used to print. `toContain`, because the
    // uppercase run would otherwise be easy to match by accident.
    expect(cell.textContent).not.toContain("AABBCCDD-1122-3344");
  });

  it("names each debug type and says so when an entry carries nothing to show", () => {
    // 12 = "VC Feature", 13 = "POGO", 999 = unmapped. All three are real
    // neighbours of the CodeView entry in an MSVC image — `t64-arm.exe` in the
    // corpus carries exactly CodeView + VC Feature + POGO.
    renderHeaders(
      parsePE(
        buildMinimalPE64({
          directories: {
            debug: [
              { type: 2, codeView: { guid: CV_GUID, age: 1, pdbPath: "a.pdb" } },
              { type: 12 },
              { type: 13 },
              { type: 999 },
            ],
          },
        }),
      ),
    );
    // Located through the block rather than off the heading's next sibling: the
    // heading now carries an inline admission when the walk was cut short
    // (`DebugDirectory.truncated`), so "the element after the h3" is not always
    // the table.
    const block = screen.getByText("Debug Info").closest("div") as HTMLElement;
    const rows = Array.from(block.querySelectorAll("table tbody tr"));
    expect(rows.map((r) => r.children[0].textContent)).toEqual([
      "CodeView",
      "VC Feature",
      "POGO",
      "Type 999",
    ]);
    // An entry with no payload gets an em dash rather than an empty cell: a
    // blank there reads as a value the parser lost.
    expect(rows.slice(1).map((r) => r.children[1].textContent)).toEqual(["—", "—", "—"]);
  });

  /**
   * THE ENTRY LIST'S OWN ADMISSION, which `MAX_DEBUG_DIRECTORY_ENTRIES`'
   * docstring named as a known hole for two sessions: a record whose PATH was
   * cut short says so in the value, but a directory whose ENTRY LIST was cut
   * short said nothing, because the return type was a bare `DebugInfo[]`. A list
   * cannot carry a marker — an invented row would be a falsehood inside the data
   * — so the channel is the type and the heading. (peek-a-bin-wo8g)
   *
   * `size` here declares 64 entries where the fixture wrote one, so 63 the file
   * claims went unread. The number is not asserted from the heading text: the
   * heading says the walk was short, and the title carries the arithmetic.
   */
  it("says so when the directory declares more entries than were read", () => {
    const buf = buildMinimalPE64({
      directories: { debug: [{ type: 2, codeView: { guid: CV_GUID, age: 1, pdbPath: "a.pdb" } }] },
    });
    const pe = parsePE(buf);
    // Overwrite the synthesized directory's size in place, so everything else
    // about the fixture — including the record the one entry points at — is
    // unchanged and the only difference is the count the file declares.
    const declared = { ...pe.dataDirectories[6], size: 28 * 64 };
    renderHeaders({
      ...pe,
      dataDirectories: pe.dataDirectories.map((d, i) => (i === 6 ? declared : d)),
    });

    expect(screen.getByText("Debug Info")).toBeTruthy();
    expect(screen.getByText(/not every declared entry was read/)).toBeTruthy();
    // The row that WAS read is still on the page: an admission that replaces the
    // answer is the mistake `analysisNotice`'s timeout kind exists to avoid.
    expect(rowValue("CodeView").textContent).toContain("a.pdb");
  });

  it("does not mark a whole directory incomplete", () => {
    // The other half, and the one that keeps the admission from being noise on
    // every real binary: the four x86 corpus binaries declare one entry and the
    // two ARM64 ones three.
    renderHeaders(
      parsePE(
        buildMinimalPE64({
          directories: {
            debug: [
              { type: 2, codeView: { guid: CV_GUID, age: 1, pdbPath: "a.pdb" } },
              { type: 13 },
            ],
          },
        }),
      ),
    );
    expect(screen.getByText("Debug Info")).toBeTruthy();
    expect(screen.queryByText(/not every declared entry was read/)).toBeNull();
  });

  it("renders the block for a declared directory that yielded no entries at all", () => {
    // A debug directory whose RVA resolves into no section reads zero entries,
    // and under the old `entries.length > 0` test the entire block vanished — the
    // pane said nothing whatever about a directory the file declares, which is
    // the same silence as the grey "Unsigned" pill above.
    const pe = parsePE(
      buildMinimalPE64({ dataDirectories: new Map([[6, { virtualAddress: 0x900000, size: 28 }]]) }),
    );
    renderHeaders(pe);
    expect(screen.getByText("Debug Info")).toBeTruthy();
    expect(screen.getByText(/not every declared entry was read/)).toBeTruthy();
  });

  it("renders a CodeView entry whose payload is not RSDS as an empty one", () => {
    // The type says CodeView but the record's signature is not "RSDS" (an NB10
    // record, or garbage). Nothing is recovered, and the row must not claim a
    // GUID or a path it does not have.
    renderHeaders(
      parsePE(
        buildMinimalPE64({
          directories: { debug: [{ type: 2, rawData: new Uint8Array(32) }] },
        }),
      ),
    );
    expect(rowValue("CodeView").textContent).toBe("—");
  });
});

describe("HeaderView rich header", () => {
  it("is absent entirely when the image has no Rich block", () => {
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(screen.queryByText(/Rich Header/)).toBeNull();
  });

  it("decodes the XOR-obfuscated entries and prints each column in its own base", () => {
    // Real values, off `t64-arm.exe`: tool 0x0103 build 27412 used twice, tool
    // 0x0105 build 27412 used 147 times. The last row is the one the fixture
    // adds — a use count with the top bit set, which came back as `-1` before
    // `parseRichHeader` stopped letting an int32 XOR through.
    const entries = [
      { toolId: 0x0103, buildId: 27412, useCount: 2 },
      { toolId: 0x0105, buildId: 27412, useCount: 147 },
      { toolId: 0x00ff, buildId: 30133, useCount: 0xffffffff },
    ];
    renderHeaders(parsePE(buildMinimalPE64({ richHeader: { entries } })));

    const heading = screen.getByText(/Rich Header/);
    expect(heading.textContent).toBe("Rich Header (3 entries)");
    const rows = Array.from(
      (heading.nextElementSibling as HTMLElement).querySelectorAll("tbody tr"),
    );
    // Tool ID in hex (it is looked up in tables published as hex); build ID and
    // use count in decimal (a build ID is a linker version number and a count is
    // a count). Mixing those up is the whole of what this row can get wrong.
    expect(rows.map((r) => Array.from(r.children).map((c) => c.textContent))).toEqual([
      ["0x103", "27412", "2"],
      ["0x105", "27412", "147"],
      ["0xFF", "30133", "4294967295"],
    ]);
  });

  it("does not disturb the rest of the panel by moving e_lfanew", () => {
    // A Rich block pushes the PE signature past 0x80, which moves every
    // subsequent file offset. Nothing in the panel should notice.
    const pe = parsePE(
      buildMinimalPE64({ richHeader: { entries: [{ toolId: 1, buildId: 2, useCount: 3 }] } }),
    );
    expect(pe.dosHeader.e_lfanew).toBeGreaterThan(0x80);
    renderHeaders(pe);
    expect(rowValue("Image Base").textContent).toBe("0x0000000140000000");
    expect(rowValue("Magic").textContent).toBe("0x020B (PE32+)");
    expect(rowValue("Size of Headers").textContent).toBe(
      `0x${pe.optionalHeader.sizeOfHeaders.toString(16).toUpperCase().padStart(8, "0")}`,
    );
  });
});

describe("HeaderView digital signature", () => {
  const SIGNED: PEFixtureOptions = {
    certificate: {
      subjectCN: "Peekabin Test Publisher",
      issuerCN: "Peekabin Test Root CA",
      notBefore: "230115090000Z",
      notAfter: "260115085959Z",
    },
  };

  it("prints every field the DER walk recovered, against the bytes the fixture wrote", () => {
    const buf = buildMinimalPE64(SIGNED);
    const pe = parsePE(buf);
    renderHeaders(pe);

    expect(screen.getByText("Signed")).toBeTruthy();
    expect(screen.queryByText("No digital signature found in this binary.")).toBeNull();
    expect(rowValue("Subject").textContent).toBe("Peekabin Test Publisher");
    expect(rowValue("Issuer").textContent).toBe("Peekabin Test Root CA");
    // The two DER `UTCTime` bodies, reformatted. `23` is a two-digit year below
    // 50, so it resolves to 2023 — the pivot is in `parseUTCTime` and is the one
    // piece of arithmetic in that walk.
    expect(rowValue("Valid From").textContent).toBe("2023-01-15 09:00:00 UTC");
    expect(rowValue("Valid Until").textContent).toBe("2026-01-15 08:59:59 UTC");
    expect(rowValue("Revision").textContent).toBe("0x0200");
    expect(rowValue("Certificate Type").textContent).toBe("PKCS#7 SignedData");

    // Derived from the file, not restated: `dwLength` is the first dword of the
    // WIN_CERTIFICATE, at the file offset the security directory names.
    const secDir = pe.dataDirectories[4];
    const dwLength = new DataView(buf).getUint32(secDir.virtualAddress, true);
    expect(rowValue("Signature Size").textContent).toBe(`${dwLength.toLocaleString()} bytes`);
    expect(dwLength).toBeGreaterThan(8);
  });

  it("points the security directory at a FILE OFFSET, not an RVA", () => {
    // The one data directory whose first field is not an RVA. If it were read as
    // one, the WIN_CERTIFICATE would be looked for inside a section — and the
    // certificate is past the last section, so nothing would be found at all.
    const buf = buildMinimalPE64(SIGNED);
    const pe = parsePE(buf);
    const offset = pe.dataDirectories[4].virtualAddress;
    const lastSection = pe.sections[pe.sections.length - 1];
    expect(offset).toBeGreaterThanOrEqual(lastSection.pointerToRawData + lastSection.sizeOfRawData);
    // No section covers it as an RVA either, so a reader that took it for one
    // would resolve nothing rather than resolve something wrong.
    expect(
      pe.sections.some(
        (s) => offset >= s.virtualAddress && offset < s.virtualAddress + s.virtualSize,
      ),
    ).toBe(false);
    // And the row that shows it: the Certificate Table's column holds that same
    // file offset, which is what the format says and what dumpbin prints under
    // an "RVA" heading. The row says so beside the number — this is the POPULATED
    // half of the marker's population; the empty-directory half is in the data
    // directories block above (peek-a-bin-xnne).
    renderHeaders(pe);
    const dirTable = screen.getByText("Data Directories").nextElementSibling as HTMLElement;
    const certRow = Array.from(dirTable.querySelectorAll("tbody tr"))[4] as HTMLElement;
    expect(certRow.textContent).toContain("Certificate Table");
    expect(certRow.textContent).toContain(
      `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`,
    );
    expect(certRow.textContent).toContain("(file offset)");
    // The marker is a sibling of the hex, not inside it: the value stays
    // copyable as the bare number a reader pastes into a hex editor.
    expect(within(certRow).getAllByRole("button")[0].textContent).toBe(
      `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`,
    );
  });

  it("still says Signed for a certificate type it cannot parse", () => {
    // A non-PKCS#7 attribute certificate. `parseSecurityDirectory` returns early
    // without a subject or an issuer — so the badge must still read "Signed" and
    // the rows that have no value must be absent rather than blank.
    renderHeaders(
      parsePE(
        buildMinimalPE64({
          certificate: { certificateType: 0x0001, raw: new Uint8Array([1, 2, 3, 4]) },
        }),
      ),
    );
    expect(screen.getByText("Signed")).toBeTruthy();
    expect(screen.queryByText("Subject", { selector: "td" })).toBeNull();
    expect(screen.queryByText("Issuer", { selector: "td" })).toBeNull();
    expect(rowValue("Certificate Type").textContent).toBe("0x1");
    expect(rowValue("Signature Size").textContent).toBe("12 bytes");
  });

  /**
   * "UNREADABLE" IS A THIRD STATE AND THE PANEL USED TO HAVE TWO.
   *
   * `parseSecurityDirectory` answers `null` for a declared security directory
   * whose `WIN_CERTIFICATE` header does not fit in the file — a truncated
   * download, a carved sample, a crafted one — and `parsePE` swallows any throw
   * into the same `undefined`. Every one of those rendered the grey **Unsigned**
   * pill and "No digital signature found in this binary.": a positive claim about
   * the FILE resting on the tool's own failure to read it. The distinction this
   * codebase insists on everywhere else — `computeImphash` refusing with `null`,
   * `TRUNCATION_MARKER`, `ResourceTree.truncated` — was erased exactly
   * here. (peek-a-bin-wo8g)
   *
   * The fixture is the reachable route, through the real parser: directory 4
   * declared at a file offset the fixture does not contain.
   */
  it("does not call a certificate it could not read unsigned", () => {
    const pe = parsePE(
      buildMinimalPE64({
        dataDirectories: new Map([[4, { virtualAddress: 0x100000, size: 0x200 }]]),
      }),
    );
    expect(pe.certificate).toBeUndefined();
    renderHeaders(pe);

    expect(screen.getByText("Unreadable")).toBeTruthy();
    expect(screen.queryByText("Unsigned")).toBeNull();
    expect(screen.queryByText("No digital signature found in this binary.")).toBeNull();
    // The sentence names the directory it is talking about, derived from the
    // file's own fields rather than restated, and says in words that this is not
    // an unsigned binary — the claim a reader would otherwise carry away.
    const said = screen.getByText(/could not be read/);
    expect(said.textContent).toContain("0x100000");
    expect(said.textContent).toContain("512 bytes");
    expect(said.textContent).toContain("not an unsigned binary");
  });

  it("still says Unsigned for a file that declares no certificate", () => {
    // THE CONTROL THAT CATCHES A FIX WHICH SIMPLY STOPS CLAIMING ANYTHING. An
    // unsigned binary is the overwhelming majority of what this tool opens, and
    // "Unsigned" is true of it; withdrawing the pill, or painting every file
    // "Unreadable", trades one falsehood for a louder one.
    const pe = parsePE(buildMinimalPE64());
    renderHeaders(pe);
    expect(screen.getByText("Unsigned")).toBeTruthy();
    expect(screen.getByText("No digital signature found in this binary.")).toBeTruthy();
    expect(screen.queryByText("Unreadable")).toBeNull();
    expect(screen.queryByText(/could not be read/)).toBeNull();
  });

  it("folds the populated block away, keeping the badge", async () => {
    const { user } = renderHeaders(parsePE(buildMinimalPE64(SIGNED)));
    await user.click(screen.getByRole("button", { name: /Digital Signature/ }));
    expect(screen.queryByText("Peekabin Test Publisher")).toBeNull();
    expect(screen.getByText("Signed")).toBeTruthy();
  });
});

/**
 * THE TWO ASYNC ARMS OF THE CHECKSUM VALIDATION ROW.
 *
 * `useFileMetrics` posts to `metrics.worker.ts` only above
 * `MAX_SYNC_FILE_METRIC_BYTES`; below it the value is computed in the render
 * pass and neither `loading` nor `error` is ever observable. Every other fixture
 * in this file is ~1.5 KB.
 *
 * THE THRESHOLD IS NOT MOCKED. `REQUEST_TIMEOUT_MS` is mocked down in
 * `src/__tests__/App.dom.test.tsx` because provoking that one needs ~200 MiB of
 * *code*; this one needs 1 MiB of *bytes*, which a fixture can simply contain.
 * So the routing decision — the `>` in `useFileMetrics` — is executed for real,
 * and {@link belowThreshold} below is the control that proves it is the size and
 * not something else doing the routing.
 */
describe("HeaderView checksum validation, off the main thread", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** A PE whose one section body is `bytes` long, so the file is at least that. */
  function sizedPE(bytes: number): PEFile {
    return parsePE(
      buildMinimalPE64({
        sections: [
          {
            name: ".data",
            virtualAddress: 0x1000,
            virtualSize: bytes,
            data: new Uint8Array(bytes),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
          },
        ],
      }),
    );
  }

  const aboveThreshold = () => sizedPE(MAX_SYNC_FILE_METRIC_BYTES + 0x1000);
  const belowThreshold = () => sizedPE(0x1000);

  function deferredMetrics() {
    let settle!: (r: FileMetricsResult) => void;
    let fail!: (e: unknown) => void;
    const spy = vi.spyOn(metricsWorker, "fileMetrics").mockReturnValue(
      new Promise<FileMetricsResult>((res, rej) => {
        settle = res;
        fail = rej;
      }),
    );
    return { spy, settle, fail };
  }

  it("shows a loading state, then the worker's answer", async () => {
    const pe = aboveThreshold();
    expect(pe.buffer.byteLength).toBeGreaterThan(MAX_SYNC_FILE_METRIC_BYTES);
    const { spy, settle } = deferredMetrics();

    renderHeaders(pe);
    // The request has not replied, so the row must not be showing a value —
    // and specifically must not be showing the "Unavailable" arm, which is what
    // a `null` value with no loading flag would render.
    expect(rowValue("Checksum Validation").textContent).toBe("Computing…");
    expect(spy).toHaveBeenCalledTimes(1);
    // The client is handed exactly what `checksumFile` needs and nothing that
    // would drag the PEFile across a postMessage.
    expect(spy.mock.calls[0][1]).toBe(pe.dosHeader.e_lfanew);
    expect(spy.mock.calls[0][2]).toBe(pe.optionalHeader.checksum);

    await act(async () => {
      settle({
        checksum: { expected: 0x1234, actual: 0x9abc, valid: false },
        sectionEntropies: [],
      });
    });

    const cell = rowValue("Checksum Validation").textContent ?? "";
    expect(cell).toContain("Invalid");
    expect(cell).toContain("0x00001234");
    expect(cell).toContain("0x00009ABC");
    expect(cell).not.toContain("Computing");
  });

  it("resolves to Valid, so the loading state is not the only thing reachable", async () => {
    const { settle } = deferredMetrics();
    renderHeaders(aboveThreshold());
    expect(rowValue("Checksum Validation").textContent).toBe("Computing…");
    await act(async () => {
      settle({
        checksum: { expected: 0x4d5a, actual: 0x4d5a, valid: true },
        sectionEntropies: [],
      });
    });
    expect(rowValue("Checksum Validation").textContent).toBe("Valid");
  });

  it("names the failure rather than showing a spinner that never stops", async () => {
    const { fail } = deferredMetrics();
    renderHeaders(aboveThreshold());
    await act(async () => {
      fail(new Error("Worker reply could not be deserialized"));
    });
    const cell = rowValue("Checksum Validation");
    expect(cell.textContent).toBe("Unavailable (Worker reply could not be deserialized)");
    // The full message is on the title too, since the sentence is truncatable.
    const titled = within(cell).getByTitle("Worker reply could not be deserialized");
    expect(titled).toBeTruthy();
  });

  it("reaches the same failure arm through the real client, with no worker to build", async () => {
    // NO SPY AT ALL. jsdom implements no `Worker`, so the real
    // `MetricsWorkerClient.send` throws inside its own try and rejects the
    // request — which is the shape a browser produces when the worker module
    // fails to load. This is the arm reached without any test double in the way.
    const pe = aboveThreshold();
    renderHeaders(pe);
    expect(rowValue("Checksum Validation").textContent).toBe("Computing…");
    await waitFor(() =>
      expect(rowValue("Checksum Validation").textContent).toMatch(/^Unavailable \(/),
    );
    expect(rowValue("Checksum Validation").textContent).toContain("Worker is not defined");
  });

  it("stays synchronous below the threshold, and posts nothing", () => {
    // THE CONTROL for everything above: the same fixture shape under the
    // threshold takes the inline path, so no loading state is ever rendered and
    // the client is never called. Without this, every assertion above would be
    // equally true of a build in which the sync path had simply been deleted.
    const spy = vi.spyOn(metricsWorker, "fileMetrics");
    const pe = belowThreshold();
    expect(pe.buffer.byteLength).toBeLessThan(MAX_SYNC_FILE_METRIC_BYTES);
    renderHeaders(pe);
    expect(rowValue("Checksum Validation").textContent).toBe("Not set (0x00000000)");
    expect(spy).not.toHaveBeenCalled();
  });
});

/**
 * THE DECLARED COUNT AND THE TABLE UNDER IT (peek-a-bin-dd94).
 *
 * `parseDataDirectories` clamps to `Math.min(count, 16, fits)` because
 * `numberOfRvaAndSizes` is attacker-controlled; the panel printed the RAW count
 * and then rendered the clamped table beneath it. Neither number is false alone
 * — the same shape as the Certificate Table row's mislabelled offset — and this
 * is the adversarial-input direction of it: the parser noticed a crafted-PE tell
 * deliberately and the one surface a human reads swallowed it.
 *
 * Every number below is read off the fixture rather than written down, and the
 * two halves of the mismatch are separate `it`s on purpose: in one `it` the
 * first failure hides the second, and "the parenthetical is wrong" and "the
 * table is a different length than it claims" are different regressions.
 */
describe("HeaderView on a PE declaring more data directories than it has", () => {
  /** The bead's measured case: a PE32+ optional header claiming 40. */
  const pe40 = () => parsePE(buildMinimalPE64({ numberOfRvaAndSizes: 40 }));

  it("prints the declared count AND admits the clamp beside it", () => {
    const pe = pe40();
    expect(pe.optionalHeader.numberOfRvaAndSizes).toBe(40);
    expect(pe.dataDirectories.length).toBe(16);
    renderHeaders(pe);
    // No space in `textContent`: the gap is an `ml-2` margin, as with the entry
    // point row above.
    expect(rowValue("Number of RVA and Sizes").textContent).toBe("40(clamped to 16)");
  });

  it("renders exactly the rows the parser read, which is what the count contradicts", () => {
    const pe = pe40();
    renderHeaders(pe);
    const table = screen.getByText("Data Directories").nextElementSibling;
    if (!(table instanceof HTMLElement)) throw new Error("no data directory table");
    // Sixteen, under a declared 40. This is the half of the pair that was never
    // wrong and never the point.
    expect(table.querySelectorAll("tbody tr").length).toBe(pe.dataDirectories.length);
  });

  it("says WHY in the title, naming the format's maximum rather than the parser", () => {
    renderHeaders(pe40());
    const note = rowValue("Number of RVA and Sizes").querySelector("span[title]");
    expect(note?.getAttribute("title")).toContain("PE format defines sixteen");
  });

  it("says the header is truncated when THAT is what bound the count", () => {
    // The other arm of `dataDirectoryClamp`, and the reason it has two: a
    // plausible 16 that the file has no room for is a different finding, and
    // reporting the spec cap there would name a constraint that did not bind.
    const full = buildMinimalPE32();
    const opt = new DataView(full).getUint32(0x3c, true) + 4 + 20;
    const buf = full.slice(0, opt + 96 + 3 * 8);
    new DataView(buf).setUint32(opt + 92, 16, true);
    const pe = parsePE(buf);
    expect(pe.dataDirectories.length).toBe(3);
    renderHeaders(pe);

    expect(rowValue("Number of RVA and Sizes").textContent).toBe("16(clamped to 3)");
    const note = rowValue("Number of RVA and Sizes").querySelector("span[title]");
    expect(note?.getAttribute("title")).toContain("do not fit in the file");
  });

  it("shows NOTHING beside a plausible count — the control for all of the above", () => {
    // Without this, every assertion above is equally true of a panel that prints
    // "(clamped to N)" on every binary anyone opens. An ordinary fixture
    // declares 16 and holds 16.
    const pe = parsePE(buildMinimalPE64());
    expect(pe.optionalHeader.numberOfRvaAndSizes).toBe(pe.dataDirectories.length);
    renderHeaders(pe);
    expect(rowValue("Number of RVA and Sizes").textContent).toBe("16");
  });
});

/**
 * TWO LABELS THAT CLAIMED MORE THAN THE VALUE SUPPORTED.
 *
 * Both are the class the `ImageBase` defect above belongs to: a derived spelling
 * that is right for the values anyone has looked at and states something false
 * for the rest, where nothing static can see it because both spellings are the
 * same type.
 */
describe("HeaderView derives its labels from the values, not from beside them", () => {
  it("takes the Magic label from the magic", () => {
    // `is64` IS `magic === 0x020B`, so the old `pe.is64 ? "PE32+" : "PE32"`
    // printed `(PE32)` for every other value — including 0x0107, a ROM image,
    // which is neither. UNREACHABLE THROUGH `parsePE`, which throws on any third
    // magic, so the state is built by hand here: this pins the row's rule, and
    // is a guard against the parser widening rather than a repair of anything on
    // screen today.
    const pe = parsePE(buildMinimalPE32());
    pe.optionalHeader.magic = 0x0107;
    renderHeaders(pe);
    expect(rowValue("Magic").textContent).toBe("0x0107 (ROM)");
  });

  it("admits an unmapped magic the way the Machine and Subsystem rows do", () => {
    const pe = parsePE(buildMinimalPE32());
    pe.optionalHeader.magic = 0x0999;
    renderHeaders(pe);
    expect(rowValue("Magic").textContent).toBe("0x0999 (Unknown)");
  });

  it("still spells the two magics that reach it today", () => {
    // The control: the change must not move the label on any real file.
    renderHeaders(parsePE(buildMinimalPE32()));
    expect(rowValue("Magic").textContent).toBe("0x010B (PE32)");
  });

  it("names the deprecated COFF bits instead of dropping them", () => {
    // 0x8092 = BYTES_REVERSED_HI(0x8000) | BYTES_REVERSED_LO(0x0080) |
    // AGGRESSIVE_WS_TRIM(0x0010) | EXECUTABLE_IMAGE(0x0002). All three of the
    // deprecated bits were absent from the table, so a file setting them
    // rendered the same single chip as 0x0002 alone.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { coffCharacteristics: 0x8092 })));
    expect(chips("Characteristics")).toEqual([
      "EXECUTABLE_IMAGE",
      "AGGRESSIVE_WS_TRIM",
      "BYTES_REVERSED_LO",
      "BYTES_REVERSED_HI",
    ]);
  });

  it("admits a bit the format does not name", () => {
    // 0x0042 = EXECUTABLE_IMAGE(0x0002) | 0x0040, which is RESERVED and has no
    // name to add to the table — so this admission cannot be closed by
    // completing it. Before this the row rendered exactly as 0x0002 would.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { coffCharacteristics: 0x0042 })));
    expect(chips("Characteristics")).toEqual(["EXECUTABLE_IMAGE"]);
  });

  it("spells the unnamed bits, not merely that there were some", () => {
    // Split from the chip assertion above: a reader compares this against
    // `dumpbin`, so which bit is unaccounted for is the content of the finding.
    renderHeaders(parsePE(patchHeader(buildMinimalPE32(), { coffCharacteristics: 0x0042 })));
    expect(rowValue("Characteristics").textContent).toContain("(unknown bits: 0x0040)");
  });

  it("admits an unnamed DLL characteristic too — the second call site", () => {
    // 0x0104 = NX_COMPAT(0x0100) | 0x0004, reserved. Both flag rows share
    // `decodeFlags`, and a change that reached only one of them would leave the
    // other silently dropping bits.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { dllCharacteristics: 0x0104 })));
    expect(chips("DLL Characteristics")).toEqual(["NX_COMPAT"]);
    expect(rowValue("DLL Characteristics").textContent).toContain("(unknown bits: 0x0004)");
  });

  it("admits nothing on a word whose every set bit is named", () => {
    // The control for the admission, in the direction that matters: a normal
    // binary must not grow an "(unknown bits)" note. The fixture's own
    // characteristics are EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE.
    renderHeaders(parsePE(buildMinimalPE64()));
    expect(rowValue("Characteristics").textContent).not.toContain("unknown bits");
    expect(rowValue("DLL Characteristics").textContent).not.toContain("unknown bits");
  });

  it("still says `none` for a zero word, rather than admitting nothing twice", () => {
    // `FlagChips` returns early on an empty flag list; that early return had to
    // learn about the leftover mask, and getting it wrong the other way would
    // print `none` beside an unnamed set bit.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { coffCharacteristics: 0 })));
    expect(rowValue("Characteristics").textContent).toContain("none");
    expect(rowValue("Characteristics").textContent).not.toContain("unknown bits");
  });

  it("does NOT say `none` when the only set bits are unnamed", () => {
    // The pair to the case above, and the one an early return gets wrong: 0x0040
    // alone names no chip, so a `flags.length === 0` test on its own reports a
    // file that set a reserved bit as having set nothing.
    renderHeaders(parsePE(patchHeader(buildMinimalPE64(), { coffCharacteristics: 0x0040 })));
    expect(rowValue("Characteristics").textContent).not.toContain("none");
    expect(rowValue("Characteristics").textContent).toContain("(unknown bits: 0x0040)");
  });
});
