import { describe, it, expect } from "vitest";
import { parseAnnotationMessage } from "../useMcpSync";

/**
 * The MCP bridge's browser-side message gate.
 *
 * Frames arrive over a WebSocket from a separate process, so this is untrusted
 * input on the path into app state. Everything here is the client half only —
 * it does NOT exercise the bridge end to end, and in particular says nothing
 * about the 127.0.0.1 bind change (see the report).
 */

const FILE = "sample.exe";

function frame(body: Record<string, unknown>): string {
  return JSON.stringify({ type: "annotations", fileName: FILE, ...body });
}

describe("parseAnnotationMessage — accepts well-formed frames", () => {
  it("returns the validated payload", () => {
    const result = parseAnnotationMessage(
      frame({
        bookmarks: [{ address: 0x401000, label: "entry" }],
        renames: { "4198400": "main" },
        comments: { "4198400": "start here" },
      }),
      FILE,
    );
    expect(result).toEqual({
      bookmarks: [{ address: 0x401000, label: "entry" }],
      renames: { 4198400: "main" },
      comments: { 4198400: "start here" },
    });
  });

  it("coerces string address keys to numbers", () => {
    const result = parseAnnotationMessage(frame({ renames: { "4096": "fn" } }), FILE);
    expect(result?.renames).toEqual({ 4096: "fn" });
    expect(Object.keys(result?.renames ?? {})).toEqual(["4096"]);
  });

  it("fills in the sections the frame omits", () => {
    const result = parseAnnotationMessage(frame({ renames: { "1": "a" } }), FILE);
    expect(result).toEqual({ bookmarks: [], renames: { 1: "a" }, comments: {} });
  });

  it("accepts a frame with no annotations at all", () => {
    expect(parseAnnotationMessage(frame({}), FILE)).toEqual({
      bookmarks: [], renames: {}, comments: {},
    });
  });

  it("accepts a Buffer-like payload, as ws delivers for binary frames", () => {
    const raw = { toString: () => frame({ renames: { "1": "a" } }) };
    expect(parseAnnotationMessage(raw, FILE)?.renames).toEqual({ 1: "a" });
  });
});

describe("parseAnnotationMessage — envelope filtering", () => {
  it("ignores a frame for a different binary", () => {
    const other = JSON.stringify({
      type: "annotations", fileName: "other.exe", renames: { "1": "a" },
    });
    expect(parseAnnotationMessage(other, FILE)).toBeNull();
  });

  it("ignores a frame with no fileName", () => {
    const noName = JSON.stringify({ type: "annotations", renames: { "1": "a" } });
    expect(parseAnnotationMessage(noName, FILE)).toBeNull();
  });

  it("ignores frames of other message types", () => {
    for (const type of ["hello", "ping", "ANNOTATIONS", "", null, 0]) {
      const msg = JSON.stringify({ type, fileName: FILE, renames: { "1": "a" } });
      expect(parseAnnotationMessage(msg, FILE), String(type)).toBeNull();
    }
  });

  it("matches the filename exactly, not by prefix or case", () => {
    for (const name of ["sample", "sample.exe.bak", "SAMPLE.EXE", " sample.exe"]) {
      const msg = JSON.stringify({ type: "annotations", fileName: name, renames: { "1": "a" } });
      expect(parseAnnotationMessage(msg, FILE), name).toBeNull();
    }
  });
});

describe("parseAnnotationMessage — malformed input is ignored, never thrown", () => {
  it("ignores non-JSON payloads", () => {
    for (const raw of ["", "not json", "{", "undefined", "<html>", "\0"]) {
      expect(() => parseAnnotationMessage(raw, FILE)).not.toThrow();
      expect(parseAnnotationMessage(raw, FILE), JSON.stringify(raw)).toBeNull();
    }
  });

  it("ignores JSON that is not an object", () => {
    for (const raw of ["null", "42", '"a string"', "true", "[1,2,3]"]) {
      expect(parseAnnotationMessage(raw, FILE), raw).toBeNull();
    }
  });

  it("ignores a frame whose annotations fail validation", () => {
    const cases: Record<string, unknown>[] = [
      { bookmarks: "not an array" },
      { bookmarks: [{ address: "not a number", label: "x" }] },
      { bookmarks: [{ address: 1 }] },
      { bookmarks: [null] },
      { renames: "not an object" },
      { renames: { "1": 42 } },
      { comments: [1, 2] },
    ];
    for (const body of cases) {
      expect(parseAnnotationMessage(frame(body), FILE), JSON.stringify(body)).toBeNull();
    }
  });

  it("rejects a non-finite bookmark address", () => {
    // NaN/Infinity cannot survive JSON, so they arrive as strings or null.
    for (const address of ["NaN", "Infinity", null]) {
      const msg = frame({ bookmarks: [{ address, label: "x" }] });
      expect(parseAnnotationMessage(msg, FILE), String(address)).toBeNull();
    }
  });

  it("does not throw on deeply nested input", () => {
    let nested: unknown = "leaf";
    for (let i = 0; i < 500; i++) nested = { nested };
    const msg = JSON.stringify({ type: "annotations", fileName: FILE, renames: nested });
    expect(() => parseAnnotationMessage(msg, FILE)).not.toThrow();
  });

  it("ignores undefined and null payloads", () => {
    expect(parseAnnotationMessage(undefined, FILE)).toBeNull();
    expect(parseAnnotationMessage(null, FILE)).toBeNull();
  });
});

describe("parseAnnotationMessage — prototype pollution", () => {
  // A remote peer controls these keys, and they are used to build an object that
  // is spread into app state. A __proto__ key must not escape onto Object.prototype.
  it("does not pollute Object.prototype via a __proto__ rename key", () => {
    const msg = frame({ renames: { __proto__: "polluted" } });
    parseAnnotationMessage(msg, FILE);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
  });

  it("does not pollute via a nested __proto__ payload", () => {
    const msg = `{"type":"annotations","fileName":"${FILE}","renames":{"__proto__":{"pwned":true}}}`;
    parseAnnotationMessage(msg, FILE);
    expect(({} as Record<string, unknown>).pwned).toBeUndefined();
  });

  it("does not let constructor or prototype keys through as addresses", () => {
    for (const key of ["constructor", "prototype", "toString"]) {
      const result = parseAnnotationMessage(frame({ renames: { [key]: "x" } }), FILE);
      // Either rejected outright, or coerced to a numeric key — never retained
      // as the original identifier.
      if (result) expect(Object.keys(result.renames), key).not.toContain(key);
    }
  });
});
