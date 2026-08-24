// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Anomaly } from "../../analysis/anomalies";
import type { AppState } from "../../hooks/usePEFile";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW } from "../../pe/constants";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
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
 * WHAT THE FIXTURE CANNOT REACH, stated rather than skipped:
 *
 *  - **The signature block's populated arm.** `pe.certificate.signed` needs a
 *    real Authenticode PKCS#7 blob; `buildMinimalPE*` has no `security`
 *    directory at all. Only the "Unsigned" arm is rendered here.
 *  - **Debug info and the Rich header.** Both come from `pe/metadata.ts` walks
 *    the fixture emits no data for, so `debugInfo.length > 0` and `richHeader`
 *    are both false and those two sub-blocks are never mounted.
 *  - **`fileMetrics.loading` / `fileMetrics.error`.** Every fixture here is
 *    ~1.5 KB, far under `MAX_SYNC_FILE_METRIC_BYTES` (1 MiB), so the metric
 *    resolves synchronously in the render pass and the two async arms of the
 *    Checksum Validation row are unreachable without a >1 MiB fixture and a
 *    worker. `asyncMetricState.test.ts` covers the state machine; the *render*
 *    of those two arms is not covered.
 *
 * {@link patchHeader} is how the fields the fixture builder does not expose are
 * set. That was a deliberate choice over extending `src/pe/__tests__/fixtures.ts`
 * — the builder is shared with a dozen suites and the four fields wanted here
 * are one `DataView` write each at offsets the PE spec fixes for both PE32 and
 * PE32+.
 */

/**
 * Set the four optional/COFF header fields `buildMinimalPE*` leaves at zero.
 *
 * The offsets are derived from `e_lfanew` rather than written down: the COFF
 * header starts four bytes past it and the optional header twenty past that.
 * `CheckSum` (64), `Subsystem` (68) and `DllCharacteristics` (70) sit at the
 * SAME optional-header offsets in PE32 and PE32+ — the two layouts diverge at
 * `ImageBase` and re-converge at `SizeOfImage` — which is what makes one helper
 * correct for both, and is asserted by using it on both below.
 */
function patchHeader(
  buf: ArrayBuffer,
  fields: {
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
