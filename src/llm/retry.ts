/**
 * Retry, backoff, and rate limiting for the LLM layer.
 *
 * ## The streaming retry boundary
 *
 * Every call in this app streams tokens straight into the UI, so a retry is only
 * safe *before the first token has been shown to the user*. Retrying after that
 * would replay the response from scratch and the user would see duplicated text.
 *
 * The boundary is therefore explicit and one-way:
 *
 *   - failures raised while connecting (network error, non-2xx response), and
 *   - failures raised while reading the stream but **before** the first token
 *
 * are retryable. The moment a token is handed to `onToken`, the caller wraps any
 * later failure in {@link LLMCommittedError}, which {@link shouldRetry} always
 * refuses. Partial output stays on screen and the error is surfaced as-is.
 *
 * ## Aborts
 *
 * An aborted request is never retried, and the backoff sleep is interruptible —
 * {@link sleep} rejects with {@link LLMAbortError} the moment the signal fires
 * rather than running the timer down. Callers treat an abort as terminal and
 * report nothing, matching the existing "user cancelled" behaviour.
 */

/** Thrown when a request is aborted, including during a backoff sleep. */
export class LLMAbortError extends Error {
  constructor(message = "Aborted") {
    super(message);
    this.name = "LLMAbortError";
  }
}

/** A non-2xx HTTP response. `retryAfterMs` is parsed from the `Retry-After` header. */
export class LLMHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly retryAfterMs: number | null = null,
  ) {
    super(message);
    this.name = "LLMHttpError";
  }
}

/** A transport-level failure — DNS, TLS, connection reset, CORS. */
export class LLMNetworkError extends Error {
  constructor(message = "Network error") {
    super(message);
    this.name = "LLMNetworkError";
  }
}

/**
 * Wraps a failure that happened after output was already shown to the user.
 * Retrying would duplicate that output, so this is never retried regardless of
 * what the underlying cause was.
 */
export class LLMCommittedError extends Error {
  constructor(readonly reason: unknown) {
    super(reason instanceof Error ? reason.message : String(reason));
    this.name = "LLMCommittedError";
  }
}

/** Status codes worth retrying: request timeout, rate limit, and any 5xx. */
export function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || (status >= 500 && status < 600);
}

export function shouldRetry(err: unknown): boolean {
  if (err instanceof LLMCommittedError) return false;
  if (err instanceof LLMAbortError) return false;
  if (err instanceof LLMHttpError) return isRetryableStatus(err.status);
  if (err instanceof LLMNetworkError) return true;
  return false;
}

/**
 * Parse a `Retry-After` header. Supports both RFC 9110 forms: delta-seconds
 * (`Retry-After: 30`) and an HTTP-date (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`).
 * Returns null when the header is absent or unparseable, so the caller falls back
 * to exponential backoff. Never returns a negative delay.
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | null {
  if (value == null) return null;
  const raw = value.trim();
  if (!raw) return null;

  // delta-seconds — a bare non-negative integer.
  if (/^\d+$/.test(raw)) {
    return Number(raw) * 1000;
  }

  // Any other bare number (negative, signed, fractional) is not a valid header.
  // Bail out before Date.parse, which happily reads "-5" as a year and would
  // turn a malformed value into "retry immediately" against a struggling server.
  if (/^[+-]?\d*\.?\d+$/.test(raw)) return null;

  const at = Date.parse(raw);
  if (Number.isNaN(at)) return null;
  return Math.max(0, at - now);
}

export interface RetryPolicy {
  /** Total attempts including the first. 1 disables retrying. */
  maxAttempts: number;
  /** First backoff delay; doubles each attempt. */
  baseDelayMs: number;
  /** Ceiling for a single backoff sleep, including an honoured `Retry-After`. */
  maxDelayMs: number;
  /** Give up once this much wall-clock time has elapsed across all attempts. */
  maxElapsedMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 500,
  maxDelayMs: 20_000,
  maxElapsedMs: 60_000,
};

/**
 * Exponential backoff with equal jitter: half the window is fixed so delays still
 * grow monotonically, half is random so concurrent clients do not resynchronise.
 * `random` is injectable to keep tests deterministic.
 */
export function backoffDelay(
  attempt: number,
  policy: RetryPolicy = DEFAULT_RETRY_POLICY,
  random: () => number = Math.random,
): number {
  const exponent = Math.max(0, attempt - 1);
  const window = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** exponent);
  return Math.round(window / 2 + random() * (window / 2));
}

/** Sleep that resolves after `ms`, or rejects with {@link LLMAbortError} on abort. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new LLMAbortError());
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      reject(new LLMAbortError());
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Caps how many LLM requests are in flight at once and enforces a minimum gap
 * between request starts.
 *
 * The vulnerability scanner fires up to 20 requests and batch rename loops over
 * batches; without spacing, a burst reliably trips a 429 that then has to be
 * retried. A slot is held for the whole streamed response, not just the fetch.
 */
export class RequestLimiter {
  private active = 0;
  private lastStart = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(
    private readonly maxConcurrent: number,
    private readonly minIntervalMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Resolves with a release function once a slot and the spacing gap are available. */
  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new LLMAbortError();

    while (this.active >= this.maxConcurrent) {
      await this.waitForSlot(signal);
      if (signal?.aborted) throw new LLMAbortError();
    }

    this.active++;
    let released = false;

    try {
      const wait = this.minIntervalMs - (this.now() - this.lastStart);
      if (wait > 0) await sleep(wait, signal);
    } catch (err) {
      this.active--;
      this.drain();
      throw err;
    }

    this.lastStart = this.now();

    return () => {
      if (released) return;
      released = true;
      this.active--;
      this.drain();
    };
  }

  private waitForSlot(signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const waiter = () => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      };
      const onAbort = () => {
        const i = this.waiters.indexOf(waiter);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new LLMAbortError());
      };
      this.waiters.push(waiter);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  private drain(): void {
    const next = this.waiters.shift();
    if (next) next();
  }
}

/**
 * Shared across every LLM call in the app. Two concurrent requests lets an
 * interactive chat proceed alongside a running scan without letting a bulk loop
 * saturate the provider.
 */
export const llmLimiter = new RequestLimiter(2, 250);

export interface RetryHooks {
  /** Called before each backoff sleep. Useful for surfacing "retrying…" in the UI. */
  onRetry?: (info: { attempt: number; delayMs: number; error: unknown }) => void;
}

export interface RunWithRetryOptions extends RetryHooks {
  signal?: AbortSignal;
  policy?: RetryPolicy;
  limiter?: RequestLimiter | null;
  random?: () => number;
  now?: () => number;
  sleepFn?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/**
 * Run `op` under the retry policy, honouring `Retry-After`, aborts, and both the
 * attempt cap and the total elapsed-time cap.
 *
 * `op` receives the 1-based attempt number. It must throw one of the error classes
 * above; anything else is treated as non-retryable and propagates untouched.
 */
export async function runWithRetry<T>(
  op: (attempt: number) => Promise<T>,
  options: RunWithRetryOptions = {},
): Promise<T> {
  const policy = options.policy ?? DEFAULT_RETRY_POLICY;
  const limiter = options.limiter === undefined ? llmLimiter : options.limiter;
  const random = options.random ?? Math.random;
  const now = options.now ?? (() => Date.now());
  const sleepFn = options.sleepFn ?? sleep;
  const signal = options.signal;
  const startedAt = now();

  let attempt = 0;
  for (;;) {
    attempt++;
    if (signal?.aborted) throw new LLMAbortError();

    const release = limiter ? await limiter.acquire(signal) : () => {};
    try {
      return await op(attempt);
    } catch (err) {
      if (signal?.aborted || err instanceof LLMAbortError) throw err;
      if (attempt >= policy.maxAttempts || !shouldRetry(err)) throw err;

      const retryAfter = err instanceof LLMHttpError ? err.retryAfterMs : null;
      const delay =
        retryAfter != null
          ? Math.min(retryAfter, policy.maxDelayMs)
          : backoffDelay(attempt, policy, random);

      // Do not start a sleep that would push us past the elapsed cap — fail now
      // with the real error instead of burning the budget and failing anyway.
      if (now() - startedAt + delay >= policy.maxElapsedMs) throw err;

      options.onRetry?.({ attempt, delayMs: delay, error: err });
      // Released before sleeping so a backing-off request does not hold a slot.
      release();
      await sleepFn(delay, signal);
    } finally {
      release();
    }
  }
}
