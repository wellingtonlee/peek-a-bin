/**
 * The `Blob`-source rule, which two clients and two worker dispatches share.
 *
 * Everything here is a property no integration test can see. What goes over the
 * wire is invisible from a result — a correct answer computed from a copy and a
 * correct answer computed from a handle are the same answer — and the wiring
 * check is invisible from a result *by design*, since it exists to make a
 * mis-paired handle fall back to the behaviour that was always there. So the
 * claims are asserted directly, each with a control that could fail.
 *
 * The population is empty in one direction on purpose: `sourceFor`'s mismatch
 * arm and `bytesOf`'s fall-through arm have no occurrence in the app (a
 * correctly wired `File` always matches, and a structured clone always rebuilds
 * a real `Blob`), so they are bounds pinned here rather than measured — the
 * status `pop esp` and the `rip`/`rsp` refusals have elsewhere in this tree.
 */

import { describe, expect, it, vi } from "vitest";
import { BlobSourceRegistry, bytesOf } from "../blobSource";

/** Bytes varied enough that a wrong window is visible rather than plausible. */
function noisy(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed;
  for (let i = 0; i < length; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out[i] = (x >>> 16) & 0xff;
  }
  return out;
}

const bufferOf = (bytes: Uint8Array) => bytes.slice().buffer as ArrayBuffer;

describe("BlobSourceRegistry", () => {
  it("answers with the buffer when nothing is registered", () => {
    // The common case, not a fallback: two of the three load paths have no
    // `File` at all, so this must stay the behaviour.
    const registry = new BlobSourceRegistry("test");
    const buffer = bufferOf(noisy(64));
    expect(registry.sourceFor(buffer)).toBe(buffer);
  });

  it("answers with the registered blob, by identity", () => {
    const registry = new BlobSourceRegistry("test");
    const buffer = bufferOf(noisy(64));
    const blob = new Blob([buffer]);
    registry.register(buffer, blob);
    // Identity, not equality: the whole point is that this object is what
    // crosses `postMessage`, cloned by reference.
    expect(registry.sourceFor(buffer)).toBe(blob);
  });

  it("keys per buffer, so another file still gets its own answer", () => {
    const registry = new BlobSourceRegistry("test");
    const registered = bufferOf(noisy(64));
    const other = bufferOf(noisy(64, 9));
    registry.register(registered, new Blob([registered]));
    expect(registry.sourceFor(other)).toBe(other);
  });

  it("falls back to the buffer when the registered blob is the wrong size", () => {
    // The defect this catches is a mis-paired handle — a stale closure, a
    // mis-ordered argument, the previous load's `File` — which would answer one
    // file's question from another file's bytes.
    const registry = new BlobSourceRegistry("test");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const buffer = bufferOf(noisy(64));
    registry.register(buffer, new Blob([noisy(32)]));

    expect(registry.sourceFor(buffer)).toBe(buffer);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("names the client in the mismatch warning", () => {
    // Two clients share this rule; a warning that did not say which one had a
    // mis-paired handle would send the reader to the wrong load path.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const buffer = bufferOf(noisy(64));
    const registry = new BlobSourceRegistry("disasm worker");
    registry.register(buffer, new Blob([noisy(8)]));
    registry.sourceFor(buffer);

    expect(warn.mock.calls[0][0]).toContain("disasm worker");
    warn.mockRestore();
  });

  it("keeps two registries independent", () => {
    // Per-client on purpose: whether a client has been told is a fact about that
    // client's wiring, and a shared instance would make the second
    // `registerSourceBlob` call in `App.tsx` decoration rather than load-bearing.
    const a = new BlobSourceRegistry("a");
    const b = new BlobSourceRegistry("b");
    const buffer = bufferOf(noisy(64));
    const blob = new Blob([buffer]);
    a.register(buffer, blob);

    expect(a.sourceFor(buffer)).toBe(blob);
    expect(b.sourceFor(buffer)).toBe(buffer);
  });

  it("lets a later registration replace an earlier one", () => {
    // A second file's load registers against a second buffer, so this never
    // fires in the app — but a registry that ignored a re-registration would
    // pin the first handle for a buffer's whole life.
    const registry = new BlobSourceRegistry("test");
    const buffer = bufferOf(noisy(64));
    const first = new Blob([buffer]);
    const second = new Blob([buffer]);
    registry.register(buffer, first);
    registry.register(buffer, second);
    expect(registry.sourceFor(buffer)).toBe(second);
  });
});

describe("bytesOf", () => {
  it("returns an ArrayBuffer by identity, copying nothing", () => {
    const buffer = bufferOf(noisy(64));
    return expect(bytesOf(buffer)).resolves.toBe(buffer);
  });

  it("reads a Blob's bytes", async () => {
    const bytes = noisy(300);
    const read = new Uint8Array(await bytesOf(new Blob([bytes])));
    expect(Array.from(read)).toEqual(Array.from(bytes));
  });

  it("reads a File, which is the type the browser posts", async () => {
    // `File extends Blob`; the check is for Blob-ness, so this is the assertion
    // that the subclass is not excluded by a narrower one.
    const bytes = noisy(300, 3);
    const file = new File([bytes], "fixture.exe", { type: "application/octet-stream" });
    expect(Array.from(new Uint8Array(await bytesOf(file)))).toEqual(Array.from(bytes));
  });

  it("concatenates a multi-part Blob of odd length in order", async () => {
    // A Blob is the concatenation of its parts and this is the only place that
    // concatenation happens; an odd length also rules out a whole-word read.
    const bytes = noisy(4097, 7);
    const parts = new Blob([bytes.subarray(0, 1000), bytes.subarray(1000)]);
    const read = new Uint8Array(await bytesOf(parts));
    expect(read.byteLength).toBe(4097);
    expect(Array.from(read)).toEqual(Array.from(bytes));
  });

  it("propagates a failed read instead of answering from nothing", async () => {
    // A `File` whose backing file changed on disk must fail the read per the
    // File API rather than return the new bytes. A rejection surfaces as a
    // failed request, which every caller handles; what must never happen is a
    // plausible answer computed from an empty or partial read.
    const unreadable = {
      size: 64,
      arrayBuffer: () => Promise.reject(new Error("NotReadableError")),
    };
    Object.setPrototypeOf(unreadable, Blob.prototype);
    await expect(bytesOf(unreadable as unknown as Blob)).rejects.toThrow("NotReadableError");
  });

  it("passes an unrecognised value through the ArrayBuffer arm", async () => {
    // The direction of the test matters. An unrecognised value taking the
    // buffer arm is the pre-existing behaviour — the caller's own `DataView`
    // then throws, loudly; taking the Blob arm would call `.arrayBuffer()` on
    // something with no such method, from inside a worker.
    const looksLikeABlob = { size: 4, arrayBuffer: () => Promise.resolve(new ArrayBuffer(4)) };
    await expect(bytesOf(looksLikeABlob as unknown as Blob)).resolves.toBe(looksLikeABlob);
  });
});
