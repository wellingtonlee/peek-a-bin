/**
 * The disasm worker's request watchdog: how long a reply may take, and what a
 * caller is handed when it does not arrive.
 *
 * A leaf that imports nothing, deliberately. `disasmClient.ts` constructs its
 * `Worker` singleton at module scope, so anything that needs the budget or the
 * error type — `components/analysisNotice.ts` states the budget in prose, and
 * `App.tsx` has to tell a timeout apart from a failed analysis — would
 * otherwise spawn a worker by importing it, and no test could reach either.
 * Same reason `stackIdiom.ts` and `sectionMemo.ts` are their own modules.
 */

/**
 * Watchdog for every worker request.
 *
 * One timeout for all methods rather than per-method budgets: the worker
 * services messages serially on a single thread, so a cheap call (`configure`,
 * `resetStructRegistry`) can sit queued behind a whole-image
 * `hybridDisassemble` for minutes. A short per-method timeout would reject
 * those queued requests even though nothing is wrong.
 *
 * 5 minutes is far above any legitimate run — measured at `755ea94` on a
 * 669 KiB-`.text` image, `detectFunctions` is the sole budget setter at
 * ~1335 ms per MiB of code and reaches 300 s at roughly 225 MiB of code — but
 * bounded, so a wedged worker (infinite loop, unresolved WASM load) surfaces as
 * a real error instead of leaving this and every later request pending forever.
 *
 * That it is *one* budget is what makes {@link WorkerTimeoutError} worth
 * having: the number is a property of the watchdog rather than of the method
 * that tripped it, so a surface can state it without knowing which RPC was in
 * flight. A future per-method budget would have to carry its own value to the
 * user, and `timeoutMs` on the error is already the place for it.
 */
export const REQUEST_TIMEOUT_MS = 5 * 60_000;

/**
 * The watchdog fired: this request never got a reply.
 *
 * Its own type rather than a bare `Error`, because the distinction it draws is
 * one the user has to be told. A rejected worker request lands in `App`'s
 * analysis chain, which reported every one of them as
 * `analysisPhase: "failed"` — the same terminal state a truncated or corrupt
 * file produces. The two call for opposite responses: a parse failure means the
 * file is bad and there is nothing to do, a timeout means the file is fine and
 * the tool gave up. Sniffing the message text for "timed out" would work and is
 * exactly the hand-written predicate this repo keeps deleting.
 *
 * Only the *client-side* watchdog can be an instance. An error thrown inside
 * the worker — `CapstoneUnavailableError`, `Arm64DecodeRateError` — is
 * flattened to `err?.message ?? String(err)` before it crosses `postMessage`
 * and arrives as a plain string, so class identity never survives that hop.
 * This one is minted on the main thread and caught on the main thread.
 */
export class WorkerTimeoutError extends Error {
  constructor(
    /** The RPC that was in flight. Internal vocabulary — for the log, not prose. */
    readonly method: string,
    /** The budget that elapsed, so a reader need not import the constant. */
    readonly timeoutMs: number,
  ) {
    super(`Worker request '${method}' timed out after ${timeoutMs / 1000}s`);
    this.name = "WorkerTimeoutError";
  }
}
