import { describe, expect, it, vi } from "vitest";
import {
  backoffDelay,
  DEFAULT_RETRY_POLICY,
  isRetryableStatus,
  LLMAbortError,
  LLMCommittedError,
  LLMHttpError,
  LLMNetworkError,
  parseRetryAfter,
  RequestLimiter,
  type RetryPolicy,
  runWithRetry,
  shouldRetry,
  sleep,
} from "../retry";

/** Records the delays it is asked to wait for, without actually waiting. */
function fakeSleeper() {
  const delays: number[] = [];
  const fn = async (ms: number, signal?: AbortSignal) => {
    if (signal?.aborted) throw new LLMAbortError();
    delays.push(ms);
  };
  return { delays, fn };
}

const FAST: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 100,
  maxDelayMs: 5_000,
  maxElapsedMs: 60_000,
};

describe("parseRetryAfter", () => {
  it("reads the delta-seconds form", () => {
    expect(parseRetryAfter("30")).toBe(30_000);
    expect(parseRetryAfter("0")).toBe(0);
    expect(parseRetryAfter("  7  ")).toBe(7_000);
  });

  it("reads the HTTP-date form relative to now", () => {
    const now = Date.parse("Wed, 21 Oct 2026 07:28:00 GMT");
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:28:30 GMT", now)).toBe(30_000);
  });

  it("clamps a date already in the past to zero rather than going negative", () => {
    const now = Date.parse("Wed, 21 Oct 2026 07:28:00 GMT");
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:27:00 GMT", now)).toBe(0);
  });

  it("returns null when absent or unparseable, so backoff takes over", () => {
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter(undefined)).toBeNull();
    expect(parseRetryAfter("")).toBeNull();
    expect(parseRetryAfter("   ")).toBeNull();
    expect(parseRetryAfter("soon")).toBeNull();
    expect(parseRetryAfter("-5")).toBeNull();
  });
});

describe("shouldRetry", () => {
  it("retries 408, 429 and 5xx", () => {
    for (const status of [408, 429, 500, 502, 503, 529, 599]) {
      expect(isRetryableStatus(status), String(status)).toBe(true);
      expect(shouldRetry(new LLMHttpError(status, "x")), String(status)).toBe(true);
    }
  });

  it("does not retry authentication or other permanent 4xx", () => {
    for (const status of [400, 401, 403, 404, 413, 422]) {
      expect(isRetryableStatus(status), String(status)).toBe(false);
      expect(shouldRetry(new LLMHttpError(status, "x")), String(status)).toBe(false);
    }
  });

  it("retries transport failures but never aborts or committed streams", () => {
    expect(shouldRetry(new LLMNetworkError())).toBe(true);
    expect(shouldRetry(new LLMAbortError())).toBe(false);
    expect(shouldRetry(new LLMCommittedError(new LLMNetworkError()))).toBe(false);
    expect(shouldRetry(new Error("unclassified"))).toBe(false);
  });
});

describe("backoffDelay", () => {
  it("doubles each attempt", () => {
    const half = () => 0.5;
    expect(backoffDelay(1, FAST, half)).toBe(75); // window 100 → 50 + 25
    expect(backoffDelay(2, FAST, half)).toBe(150); // window 200
    expect(backoffDelay(3, FAST, half)).toBe(300); // window 400
  });

  it("keeps jitter inside [window/2, window]", () => {
    for (const r of [0, 0.25, 0.999]) {
      const d = backoffDelay(3, FAST, () => r);
      expect(d).toBeGreaterThanOrEqual(200);
      expect(d).toBeLessThanOrEqual(400);
    }
  });

  it("clamps the window at maxDelayMs", () => {
    const d = backoffDelay(20, FAST, () => 1);
    expect(d).toBeLessThanOrEqual(FAST.maxDelayMs);
  });
});

describe("sleep", () => {
  it("resolves after the delay", async () => {
    await expect(sleep(1)).resolves.toBeUndefined();
  });

  it("rejects immediately when the signal is already aborted", async () => {
    const c = new AbortController();
    c.abort();
    await expect(sleep(10_000, c.signal)).rejects.toBeInstanceOf(LLMAbortError);
  });

  it("rejects as soon as the signal fires mid-sleep, without running the timer down", async () => {
    const c = new AbortController();
    const started = Date.now();
    const pending = sleep(30_000, c.signal);
    c.abort();
    await expect(pending).rejects.toBeInstanceOf(LLMAbortError);
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe("runWithRetry", () => {
  it("returns the first successful result without sleeping", async () => {
    const sleeper = fakeSleeper();
    const op = vi.fn().mockResolvedValue("ok");
    const result = await runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST });
    expect(result).toBe("ok");
    expect(op).toHaveBeenCalledTimes(1);
    expect(sleeper.delays).toEqual([]);
  });

  it("honours Retry-After on a 429 instead of using exponential backoff", async () => {
    const sleeper = fakeSleeper();
    const op = vi
      .fn()
      .mockRejectedValueOnce(new LLMHttpError(429, "Rate limited", 3_000))
      .mockResolvedValue("ok");

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST }),
    ).resolves.toBe("ok");
    expect(sleeper.delays).toEqual([3_000]);
  });

  it("clamps an outrageous Retry-After to maxDelayMs", async () => {
    const sleeper = fakeSleeper();
    const op = vi
      .fn()
      .mockRejectedValueOnce(new LLMHttpError(429, "Rate limited", 3_600_000))
      .mockResolvedValue("ok");

    await runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST });
    expect(sleeper.delays).toEqual([FAST.maxDelayMs]);
  });

  it("retries a 5xx with exponential backoff", async () => {
    const sleeper = fakeSleeper();
    const op = vi
      .fn()
      .mockRejectedValueOnce(new LLMHttpError(500, "API error (500)"))
      .mockRejectedValueOnce(new LLMHttpError(503, "API error (503)"))
      .mockResolvedValue("ok");

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST, random: () => 0.5 }),
    ).resolves.toBe("ok");
    expect(op).toHaveBeenCalledTimes(3);
    expect(sleeper.delays).toEqual([75, 150]);
  });

  it("retries a transient network failure", async () => {
    const sleeper = fakeSleeper();
    const op = vi
      .fn()
      .mockRejectedValueOnce(new LLMNetworkError("Failed to fetch"))
      .mockResolvedValue("ok");

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST }),
    ).resolves.toBe("ok");
    expect(op).toHaveBeenCalledTimes(2);
  });

  it("does not retry a 401 — a bad key will not fix itself", async () => {
    const sleeper = fakeSleeper();
    const err = new LLMHttpError(401, "Invalid API key");
    const op = vi.fn().mockRejectedValue(err);

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST }),
    ).rejects.toBe(err);
    expect(op).toHaveBeenCalledTimes(1);
    expect(sleeper.delays).toEqual([]);
  });

  it("does not retry a 403", async () => {
    const op = vi.fn().mockRejectedValue(new LLMHttpError(403, "Access denied"));
    await expect(runWithRetry(op, { limiter: null, policy: FAST })).rejects.toBeInstanceOf(
      LLMHttpError,
    );
    expect(op).toHaveBeenCalledTimes(1);
  });

  it("never retries a failure that already emitted output", async () => {
    const sleeper = fakeSleeper();
    const op = vi.fn().mockRejectedValue(new LLMCommittedError(new LLMNetworkError("reset")));

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST }),
    ).rejects.toBeInstanceOf(LLMCommittedError);
    expect(op).toHaveBeenCalledTimes(1);
  });

  it("enforces the attempt cap and surfaces the last real error", async () => {
    const sleeper = fakeSleeper();
    const op = vi.fn().mockRejectedValue(new LLMHttpError(503, "API error (503)"));

    await expect(
      runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: { ...FAST, maxAttempts: 3 } }),
    ).rejects.toMatchObject({ status: 503 });
    expect(op).toHaveBeenCalledTimes(3);
    expect(sleeper.delays).toHaveLength(2);
  });

  it("maxAttempts of 1 disables retrying entirely", async () => {
    const op = vi.fn().mockRejectedValue(new LLMNetworkError());
    await expect(
      runWithRetry(op, { limiter: null, policy: { ...FAST, maxAttempts: 1 } }),
    ).rejects.toBeInstanceOf(LLMNetworkError);
    expect(op).toHaveBeenCalledTimes(1);
  });

  it("gives up once the elapsed-time cap would be exceeded, rather than sleeping anyway", async () => {
    const sleeper = fakeSleeper();
    let clock = 0;
    const op = vi.fn().mockImplementation(async () => {
      clock += 4_000; // each attempt burns 4s of the 10s budget
      throw new LLMHttpError(500, "API error (500)");
    });

    await expect(
      runWithRetry(op, {
        limiter: null,
        sleepFn: sleeper.fn,
        now: () => clock,
        policy: { ...FAST, maxAttempts: 10, maxElapsedMs: 10_000 },
        random: () => 0.5,
      }),
    ).rejects.toMatchObject({ status: 500 });

    // Attempt 1 → 4s elapsed, sleeps 75ms. Attempt 2 → 8s, +150ms is under 10s.
    // Attempt 3 → 12s, already past the cap, so it stops instead of retrying.
    expect(op).toHaveBeenCalledTimes(3);
    expect(sleeper.delays).toEqual([75, 150]);
  });

  it("stops immediately when the signal aborts during backoff", async () => {
    const controller = new AbortController();
    const op = vi.fn().mockRejectedValue(new LLMHttpError(429, "Rate limited", 30_000));

    // Abort while the backoff sleep is being set up; the real sleep must observe it.
    const sleepFn = (ms: number, signal?: AbortSignal) => {
      controller.abort();
      return sleep(ms, signal);
    };

    const started = Date.now();
    await expect(
      runWithRetry(op, { limiter: null, sleepFn, signal: controller.signal, policy: FAST }),
    ).rejects.toBeInstanceOf(LLMAbortError);

    expect(op).toHaveBeenCalledTimes(1);
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("refuses to start when the signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const op = vi.fn();
    await expect(
      runWithRetry(op, { limiter: null, signal: controller.signal, policy: FAST }),
    ).rejects.toBeInstanceOf(LLMAbortError);
    expect(op).not.toHaveBeenCalled();
  });

  it("reports each retry so the UI can show progress", async () => {
    const sleeper = fakeSleeper();
    const onRetry = vi.fn();
    const op = vi
      .fn()
      .mockRejectedValueOnce(new LLMHttpError(429, "Rate limited", 1_000))
      .mockResolvedValue("ok");

    await runWithRetry(op, { limiter: null, sleepFn: sleeper.fn, policy: FAST, onRetry });
    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry.mock.calls[0][0]).toMatchObject({ attempt: 1, delayMs: 1_000 });
  });

  it("defaults are sane", () => {
    expect(DEFAULT_RETRY_POLICY.maxAttempts).toBeGreaterThan(1);
    expect(DEFAULT_RETRY_POLICY.maxDelayMs).toBeLessThanOrEqual(DEFAULT_RETRY_POLICY.maxElapsedMs);
  });
});

describe("RequestLimiter", () => {
  it("caps concurrency, releasing a slot only when the caller finishes", async () => {
    const limiter = new RequestLimiter(2, 0);
    const a = await limiter.acquire();
    const b = await limiter.acquire();

    let thirdStarted = false;
    const third = limiter.acquire().then((release) => {
      thirdStarted = true;
      return release;
    });

    await Promise.resolve();
    expect(thirdStarted).toBe(false);

    a();
    const releaseThird = await third;
    expect(thirdStarted).toBe(true);

    b();
    releaseThird();
  });

  it("spaces request starts by the minimum interval", async () => {
    // Frozen clock, so the limiter must actually wait out the interval.
    const clock = 0;
    const limiter = new RequestLimiter(4, 250, () => clock);

    const first = await limiter.acquire();
    first();

    const waited: number[] = [];
    const started = Date.now();
    const second = await limiter.acquire();
    waited.push(Date.now() - started);
    second();

    // The clock never advances, so the second acquire must have waited ~250ms.
    expect(waited[0]).toBeGreaterThanOrEqual(200);
  });

  it("does not consume a slot when aborted while queued", async () => {
    const limiter = new RequestLimiter(1, 0);
    const held = await limiter.acquire();

    const controller = new AbortController();
    const queued = limiter.acquire(controller.signal);
    controller.abort();
    await expect(queued).rejects.toBeInstanceOf(LLMAbortError);

    held();
    // The slot is free for a fresh caller — the aborted waiter did not take it.
    const next = await limiter.acquire();
    expect(typeof next).toBe("function");
    next();
  });

  it("rejects an acquire whose signal is already aborted", async () => {
    const limiter = new RequestLimiter(1, 0);
    const controller = new AbortController();
    controller.abort();
    await expect(limiter.acquire(controller.signal)).rejects.toBeInstanceOf(LLMAbortError);
  });

  it("is safe to release twice", async () => {
    const limiter = new RequestLimiter(1, 0);
    const release = await limiter.acquire();
    release();
    release();
    const next = await limiter.acquire();
    next();
  });
});
