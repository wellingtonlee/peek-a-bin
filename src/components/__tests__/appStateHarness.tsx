import type { Dispatch, ReactNode } from "react";
import {
  type AppAction,
  AppDispatchContext,
  type AppState,
  AppStateContext,
  initialState,
} from "../../hooks/usePEFile";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";

/**
 * Shared scaffolding for the dialog component tests.
 *
 * NOT itself a test file — the name sits outside vitest's `*.{test,spec}`
 * include glob on purpose, so this is imported rather than collected.
 *
 * Every dialog covered by those suites reads {@link ../../hooks/usePEFile}'s two
 * contexts and nothing else — none of them touches `workers/disasmClient`, which
 * is what makes them mountable at all (it builds a `Worker` at module scope and
 * jsdom has none). So a provider pair plus a state object is the whole harness.
 *
 * The dispatch is the caller's, precisely so it can be a `vi.fn()`: what a
 * dialog *dispatches* is the observable half of most of these components, and
 * running it through the real reducer would hide the action behind a state diff.
 */
export function AppHarness({
  state,
  dispatch,
  children,
}: {
  state: AppState;
  dispatch: Dispatch<AppAction>;
  children: ReactNode;
}) {
  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>{children}</AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}

export const IMAGE_BASE = 0x140000000;
/** RVA of the one named export in {@link harnessPE}. */
export const EXPORT_RVA = 0x1500;

/**
 * A real parsed PE, not a hand-written object literal.
 *
 * `buildMinimalPE64` + `parsePE` is the pattern the rest of the suite uses, and
 * it matters specifically for `GoToAddressModal`'s file-offset mode, which walks
 * `pe.sections` for the one whose `[pointerToRawData, +sizeOfRawData)` window
 * contains the offset. Those two fields come out of the fixture builder's own
 * layout pass, so a literal would either duplicate that arithmetic or quietly
 * disagree with it.
 *
 * At this commit the layout is `.text` at file 0x200 (RVA 0x1000, 4 bytes) and
 * `.rdata` at file 0x400 (RVA 0x2000, 0xCC bytes); tests that depend on a
 * particular offset derive it from `pe.sections` rather than repeating those.
 */
export function harnessPE(strings: Iterable<[number, string]> = []): PEFile {
  const pe = parsePE(
    buildMinimalPE64({
      imageBase: IMAGE_BASE,
      directories: {
        imports: [
          {
            libraryName: "KERNEL32.dll",
            functions: [{ name: "CreateFileW" }, { name: "ReadFile" }],
          },
        ],
        exports: {
          dllName: "harness.dll",
          addresses: [EXPORT_RVA],
          names: [{ name: "ParseHeader", addressIndex: 0 }],
        },
      },
    }),
  );
  // `parsePE` leaves `strings` empty — it is filled by the `extractStrings` RPC,
  // which needs a worker. The palette only ever reads the map, so populating it
  // here is the whole of what a string result needs.
  for (const [va, str] of strings) pe.strings.set(va, str);
  return pe;
}

/** `initialState` with a parsed PE, plus whatever else the caller needs. */
export function stateWithPE(pe: PEFile, over: Partial<AppState> = {}): AppState {
  return { ...initialState, peFile: pe, ...over };
}
