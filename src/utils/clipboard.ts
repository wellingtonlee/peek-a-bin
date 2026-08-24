/**
 * The one declaration of "put this text on the clipboard".
 *
 * WHY THIS EXISTS AT ALL: `navigator.clipboard` is a **secure-context** API.
 * Over plain `http:` on anything but `localhost`/`127.0.0.1` the whole
 * `clipboard` object is absent from `navigator`, so `navigator.clipboard
 * .writeText(...)` is not a call that fails — it is a `TypeError` thrown at
 * property access, on click, with nothing caught. This repo ships an nginx
 * deployment and treats a LAN HTTP deployment as a supported configuration
 * (see the CSP entry in CLAUDE.md), and at `09a160e` there were 18 unguarded
 * call sites across 9 files: every Copy affordance in the app threw there.
 *
 * It is a single declaration for the reason `pe/sections.ts`,
 * `disasm/ripRelative.ts` and `disasm/stackIdiom.ts` are: a predicate written
 * at N sites drifts at N sites. A guard hand-written at 18 call sites is 18
 * chances to write the next one without it.
 *
 * NOT VERIFIED IN A BROWSER OVER `http:`. The secure-context rule is read from
 * the specification (W3C Clipboard API: the `clipboard` attribute is
 * `[SecureContext]`), not observed — nothing here has served this app over
 * plain http to a browser, and the tests simulate the absence by stubbing
 * `navigator`, which is a stand-in exactly as `test/domSetup.ts`'s
 * `offsetParent` shim is. What is verified is that this module and its callers
 * behave correctly *when the API is absent*, not that a browser makes it
 * absent when we think it does.
 *
 * A `document.execCommand("copy")` FALLBACK WAS COSTED AND REFUSED. It is the
 * one thing that would make a copy actually work on the HTTP deployment rather
 * than merely fail politely, so the refusal is a judgement and not an
 * oversight:
 *
 *  - It is not a call. It needs a detached-but-rendered element, the text put
 *    into it, a `Selection` saved, replaced and restored, the element removed,
 *    and a `finally` for every early exit — call it 30 lines of DOM
 *    choreography, all of it side-effecting on the live document and on the
 *    user's own selection.
 *  - It is deprecated, its return value lies (Safari has returned `true` for a
 *    copy that did not happen), and it only works inside a user gesture — so
 *    it cannot be reached from the one path here that is not a click, the
 *    Ctrl+C handlers in `useDisassemblyKeyboard.ts` and `HexView.tsx`, without
 *    a second grammar for when it may be tried.
 *  - It would be UNTESTABLE here in the direction that matters: jsdom
 *    implements neither `execCommand` nor a real `Selection`, so a test could
 *    only assert against a stub written to have the behaviour being claimed,
 *    which is the shape of test this repo already calls vacuous.
 *
 * The bead (`peek-a-bin-p0tz`) is a bug: every Copy button throws. Making the
 * throw stop is the fix. Making copy WORK without a secure context is a
 * feature, and it wants its own bead, its own measurement and a human with the
 * app open over http.
 */

/**
 * Copy `text`, reporting whether it worked.
 *
 * **Never throws, for any input or any environment.** That is the contract the
 * call sites rely on: a Copy handler calls this and reads the boolean, and no
 * handler needs its own `try`.
 *
 * Three ways it can answer `false`, and callers deliberately cannot tell them
 * apart — the user-facing fact is the same in all three, and inventing a
 * three-way distinction would put wording on screen that is a guess:
 *
 *  1. **No `navigator` at all** — a non-DOM environment.
 *  2. **No clipboard, or no `writeText` on it** — the non-secure-context case.
 *     Tested for `writeText` specifically and not just for `clipboard`, since
 *     the object can exist with a partial surface (older WebKit shipped
 *     `readText`/`writeText` asymmetrically, and a page can install a stub).
 *  3. **The write rejected** — the user denied the `clipboard-write`
 *     permission, or (Firefox) the document was not focused.
 *
 * ONE ORDERING IS LOAD-BEARING: `writeText` is called *before* this function
 * first suspends, so it still runs inside the user gesture that triggered it.
 * Do not put an `await` above it — browsers reject a clipboard write made from
 * a later task, and the failure would be intermittent and blamed on the user.
 */
export async function copyText(text: string): Promise<boolean> {
  const clipboard = typeof navigator === "undefined" ? undefined : navigator.clipboard;
  if (typeof clipboard?.writeText !== "function") return false;
  try {
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * What a site with a transient "Copied!" affordance flashes.
 *
 * The four sites that already had one (`HeaderView`'s `CopyableHex` and its
 * imphash row, `shared.tsx`'s operand double-click, and the disassembly
 * panel's address double-click) flashed green on a promise that was never
 * checked — so on the HTTP deployment they would have flashed *success* for a
 * copy that threw. `ok` is what stops that: green for `true`, red for `false`.
 *
 * It lives here rather than in a component because the disassembly panel
 * threads it from `DisassemblyView` through both `DisassemblyRows` and
 * `CFGView`, and a second structural copy of it in either would be the drift
 * this module exists to prevent.
 */
export interface CopyFlash {
  address: number;
  ok: boolean;
}

/**
 * The one wording for a failed copy, shown as the `title` of a site that
 * flashed red.
 *
 * Deliberately does NOT name a cause. `copyText` cannot tell an absent
 * clipboard from a denied permission from an unfocused document without
 * inspecting a rejection's message, which is browser-specific prose — so a
 * sentence naming one of them would be a guess presented as a diagnosis. The
 * two remedies it does name are the ones that are true in every case.
 *
 * It is a constant rather than a literal because it appears at four sites and
 * a fifth would otherwise be written by hand — the same reason
 * `components/analysisNotice.ts` owns `VIEW_TAB_LABELS`.
 */
export const COPY_FAILED_TITLE =
  "Copy failed — the clipboard is unavailable. It needs a secure context (https, or localhost) and permission to write.";
