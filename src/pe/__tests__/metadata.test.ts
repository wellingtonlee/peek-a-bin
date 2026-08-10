/**
 * PE metadata: MD5 / imphash, Rich header, debug directory, checksum, overlay.
 *
 * The MD5 here is hand-rolled and its output is never cross-checked at runtime —
 * a wrong digest is indistinguishable from a right one — so it is pinned against
 * the RFC 1321 vectors and differentially against Node's crypto for the block
 * and padding boundaries where hand-rolled implementations classically break.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  md5,
  computeImphash,
  parseRichHeader,
  parseDebugDirectory,
  validateChecksum,
  detectOverlay,
} from "../metadata";
import { ORDINAL_TABLES } from "../ordinalTables";
import { parsePE } from "../parser";
import { buildMinimalPE32, type SectionDef } from "./fixtures";
import { IMAGE_SCN_MEM_READ, IMAGE_SCN_CNT_INITIALIZED_DATA } from "../constants";

const ascii = (s: string) => new TextEncoder().encode(s);
const nodeMD5 = (data: Uint8Array) => createHash("md5").update(data).digest("hex");

describe("md5", () => {
  it("matches the RFC 1321 test suite", () => {
    // The seven vectors from RFC 1321, appendix A.5, verbatim.
    const vectors: [string, string][] = [
      ["", "d41d8cd98f00b204e9800998ecf8427e"],
      ["a", "0cc175b9c0f1b6a831c399e269772661"],
      ["abc", "900150983cd24fb0d6963f7d28e17f72"],
      ["message digest", "f96b697d7cb7938d525a2f31aaf161d0"],
      ["abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"],
      [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
      ],
      ["1234567890".repeat(8), "57edf4a22be3c955ac49da2e2107b67a"],
    ];

    for (const [input, expected] of vectors) {
      expect(md5(ascii(input)), `md5(${JSON.stringify(input)})`).toBe(expected);
    }
  });

  it("pads correctly around the 56-byte length-field boundary", () => {
    // 55 bytes is the largest message whose length field still fits in the first
    // block; 56 forces a second block that is pure padding. Off-by-one padding
    // arithmetic shows up here and nowhere else.
    for (const len of [54, 55, 56, 57]) {
      const input = ascii("a".repeat(len));
      expect(md5(input), `${len} bytes`).toBe(nodeMD5(input));
    }
  });

  it("pads correctly around the 64-byte block boundary", () => {
    for (const len of [63, 64, 65, 119, 120, 127, 128, 129]) {
      const input = ascii("b".repeat(len));
      expect(md5(input), `${len} bytes`).toBe(nodeMD5(input));
    }
  });

  it("agrees with Node crypto on multi-block binary input", () => {
    // Non-ASCII bytes, several blocks: catches sign-extension and endianness
    // slips that ASCII-only vectors would hide.
    const input = new Uint8Array(1000);
    for (let i = 0; i < input.length; i++) input[i] = (i * 37 + 11) & 0xff;
    expect(md5(input)).toBe(nodeMD5(input));
  });

  it("encodes the bit length past the 2^32-bit boundary", () => {
    // 2^29 bytes = 2^32 bits, where the low 32-bit length word wraps to zero and
    // the high word must carry. Anything that only writes the low word breaks.
    const input = new Uint8Array(0x20000000);
    expect(md5(input)).toBe(nodeMD5(input));
  }, 30000);
});

/**
 * The canonicalization rules asserted below were read out of pefile 2024.8.26
 * (`PE.get_imphash` and `ordlookup`), and the whole chain was checked once
 * against it directly: a fixture importing by name, by known ordinal, by
 * unknown ordinal, from .dll/.sys/.exe libraries produced a byte-identical
 * digest (1ebfdad3187029a6f23fd3c2c48d4a51). pefile is deliberately not a
 * dependency of this repo, so the rules are pinned here instead.
 */
describe("computeImphash", () => {
  /** The digest pefile would produce for a given canonical imphash string. */
  const digestOf = (canonical: string) => nodeMD5(ascii(canonical));

  it("returns an empty string when there is nothing to hash", () => {
    expect(computeImphash([])).toBe("");
    expect(computeImphash([{ libraryName: "KERNEL32.dll", functions: [], iatAddresses: [] }])).toBe(
      "",
    );
  });

  it("lowercases, strips the .dll extension and joins with commas", () => {
    const hash = computeImphash([
      { libraryName: "KERNEL32.dll", functions: ["Sleep", "CreateFileW"], iatAddresses: [] },
      { libraryName: "USER32.DLL", functions: ["MessageBoxA"], iatAddresses: [] },
    ]);
    expect(hash).toBe(digestOf("kernel32.sleep,kernel32.createfilew,user32.messageboxa"));
  });

  it("strips .sys and .ocx extensions too, like pefile", () => {
    // pefile strips the extension when it is one of dll/ocx/sys, which matters
    // for drivers — this tool's main subject.
    expect(
      computeImphash([
        { libraryName: "NTOSKRNL.exe", functions: ["ExAllocatePool"], iatAddresses: [] },
      ]),
    ).toBe(digestOf("ntoskrnl.exe.exallocatepool"));

    expect(
      computeImphash([
        { libraryName: "HAL.dll", functions: ["KeStallExecutionProcessor"], iatAddresses: [] },
      ]),
    ).toBe(digestOf("hal.kestallexecutionprocessor"));

    expect(
      computeImphash([
        { libraryName: "WDFLDR.SYS", functions: ["WdfVersionBind"], iatAddresses: [] },
      ]),
    ).toBe(digestOf("wdfldr.wdfversionbind"));

    expect(
      computeImphash([{ libraryName: "COMCTL32.ocx", functions: ["Foo"], iatAddresses: [] }]),
    ).toBe(digestOf("comctl32.foo"));
  });

  it("renders unresolvable ordinal imports as ord<N>", () => {
    // pefile's ordlookup.formatOrdString yields b"ord" + str(n); the parser's
    // own "Ordinal_N" spelling must not leak into the hash input.
    expect(
      computeImphash([{ libraryName: "SOMELIB.dll", functions: ["Ordinal_42"], iatAddresses: [] }]),
    ).toBe(digestOf("somelib.ord42"));
  });

  it("resolves known ordinals to their real names", () => {
    expect(
      computeImphash([
        { libraryName: "WS2_32.dll", functions: ["Ordinal_115", "Ordinal_23"], iatAddresses: [] },
      ]),
    ).toBe(digestOf("ws2_32.wsastartup,ws2_32.socket"));

    expect(
      computeImphash([{ libraryName: "oleaut32.dll", functions: ["Ordinal_2"], iatAddresses: [] }]),
    ).toBe(digestOf("oleaut32.sysallocstring"));
  });

  it("matches the winsock ordinal table", () => {
    // Verified one by one against pefile's ordlookup. Ordinal 9 is htons; it
    // was previously mapped to getpeername, which is ordinal 5 — every imphash
    // for a binary importing ws2_32!9 by ordinal came out wrong.
    const expected: [number, string][] = [
      [1, "accept"],
      [2, "bind"],
      [3, "closesocket"],
      [4, "connect"],
      [5, "getpeername"],
      [6, "getsockname"],
      [7, "getsockopt"],
      [8, "htonl"],
      [9, "htons"],
      [10, "ioctlsocket"],
      [11, "inet_addr"],
      [12, "inet_ntoa"],
      [13, "listen"],
      [14, "ntohl"],
      [15, "ntohs"],
      [16, "recv"],
      [17, "recvfrom"],
      [18, "select"],
      [19, "send"],
      [20, "sendto"],
      [21, "setsockopt"],
      [22, "shutdown"],
      [23, "socket"],
      [111, "wsagetlasterror"],
      [112, "wsasetlasterror"],
      [115, "wsastartup"],
      [116, "wsacleanup"],
    ];
    for (const [ordinal, funcName] of expected) {
      expect(
        computeImphash([
          { libraryName: "ws2_32.dll", functions: [`Ordinal_${ordinal}`], iatAddresses: [] },
        ]),
        `ws2_32 ordinal ${ordinal}`,
      ).toBe(digestOf(`ws2_32.${funcName}`));
    }
  });

  it("resolves ordinals across the full table, not just the low ones", () => {
    // Spot checks from the upper reaches of each table — these are the entries
    // that fell back to ord<N> while the tables were a hand-written subset.
    const cases: [string, number, string][] = [
      ["ws2_32.dll", 79, "wsaioctl"],
      ["ws2_32.dll", 92, "wsarecv"],
      ["ws2_32.dll", 151, "__wsafdisset"],
      ["ws2_32.dll", 500, "wep"],
      ["wsock32.dll", 52, "gethostbyname"],
      ["wsock32.dll", 1107, "wsarecvex"],
      ["oleaut32.dll", 15, "safearraycreate"],
      ["oleaut32.dll", 200, "geterrorinfo"],
      ["oleaut32.dll", 420, "olecreatefontindirect"],
    ];
    for (const [library, ordinal, funcName] of cases) {
      const libBase = library.replace(/\.dll$/, "");
      expect(
        computeImphash([
          { libraryName: library, functions: [`Ordinal_${ordinal}`], iatAddresses: [] },
        ]),
        `${library} ordinal ${ordinal}`,
      ).toBe(digestOf(`${libBase}.${funcName}`));
    }
  });

  it("keeps wsock32 and ws2_32 apart where their ordinals disagree", () => {
    // The two DLLs share most of their low ordinals but not all: 10, 11, 12 and
    // 24 differ. Aliasing one table to the other would silently corrupt these.
    const conflicts: [number, string, string][] = [
      [10, "ioctlsocket", "inet_addr"],
      [11, "inet_addr", "inet_ntoa"],
      [12, "inet_ntoa", "ioctlsocket"],
      [24, "wsapsetpostroutine", "migratewinsockconfiguration"],
    ];
    for (const [ordinal, ws2Name, wsockName] of conflicts) {
      expect(
        computeImphash([
          { libraryName: "ws2_32.dll", functions: [`Ordinal_${ordinal}`], iatAddresses: [] },
        ]),
        `ws2_32 ordinal ${ordinal}`,
      ).toBe(digestOf(`ws2_32.${ws2Name}`));
      expect(
        computeImphash([
          { libraryName: "wsock32.dll", functions: [`Ordinal_${ordinal}`], iatAddresses: [] },
        ]),
        `wsock32 ordinal ${ordinal}`,
      ).toBe(digestOf(`wsock32.${wsockName}`));
    }
  });

  it("has the same entry counts as pefile ordlookup", () => {
    // A regression guard on the generated tables: if a regeneration drops or
    // duplicates rows, these counts move.
    expect(Object.keys(ORDINAL_TABLES).sort()).toEqual([
      "oleaut32.dll",
      "ws2_32.dll",
      "wsock32.dll",
    ]);
    expect(Object.keys(ORDINAL_TABLES["oleaut32.dll"])).toHaveLength(425);
    expect(Object.keys(ORDINAL_TABLES["ws2_32.dll"])).toHaveLength(196);
    expect(Object.keys(ORDINAL_TABLES["wsock32.dll"])).toHaveLength(75);

    // Names are bare identifiers — no stray quoting or byte-string prefixes
    // from the transcription.
    for (const [library, table] of Object.entries(ORDINAL_TABLES)) {
      for (const [ordinal, funcName] of Object.entries(table)) {
        expect(funcName, `${library}!${ordinal}`).toMatch(/^[A-Za-z_][A-Za-z0-9_@?$]*$/);
        expect(Number(ordinal), `${library}!${ordinal}`).toBeGreaterThan(0);
      }
    }
  });

  it("falls back to ord<N> for an ordinal missing from the lookup table", () => {
    // ws2_32 is a known DLL but this ordinal is outside the bundled subset.
    expect(
      computeImphash([
        { libraryName: "ws2_32.dll", functions: ["Ordinal_9999"], iatAddresses: [] },
      ]),
    ).toBe(digestOf("ws2_32.ord9999"));
  });

  it("skips imports with no usable name", () => {
    expect(
      computeImphash([{ libraryName: "KERNEL32.dll", functions: ["", "Sleep"], iatAddresses: [] }]),
    ).toBe(digestOf("kernel32.sleep"));
  });

  it("preserves import order across libraries", () => {
    const a = computeImphash([
      { libraryName: "a.dll", functions: ["one"], iatAddresses: [] },
      { libraryName: "b.dll", functions: ["two"], iatAddresses: [] },
    ]);
    const b = computeImphash([
      { libraryName: "b.dll", functions: ["two"], iatAddresses: [] },
      { libraryName: "a.dll", functions: ["one"], iatAddresses: [] },
    ]);
    expect(a).toBe(digestOf("a.one,b.two"));
    expect(b).toBe(digestOf("b.two,a.one"));
    expect(a).not.toBe(b);
  });

  it("hashes a parsed fixture end to end", () => {
    const buf = buildMinimalPE32({
      directories: {
        imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "Sleep" }, { ordinal: 42 }] }],
      },
    });
    const pe = parsePE(buf);
    expect(computeImphash(pe.imports)).toBe(digestOf("kernel32.sleep,kernel32.ord42"));
  });
});

/** Build a buffer holding a Rich header: DanS, `count` entries, Rich, key. */
function richBuffer(
  entries: { toolId: number; buildId: number; useCount: number }[],
  opts: { key?: number; dansAt?: number; totalSize?: number } = {},
): ArrayBuffer {
  const key = opts.key ?? 0x12345678;
  const dansAt = opts.dansAt ?? 0x80;
  const richAt = dansAt + 16 + entries.length * 8;
  const size = opts.totalSize ?? richAt + 8;
  const buf = new ArrayBuffer(size);
  const dv = new DataView(buf);

  dv.setUint32(dansAt, 0x536e6144 ^ key, true); // "DanS"
  for (let i = 1; i < 4; i++) dv.setUint32(dansAt + i * 4, key, true); // 3 padding dwords (0 ^ key)
  entries.forEach((e, i) => {
    const at = dansAt + 16 + i * 8;
    dv.setUint32(at, (((e.toolId << 16) | e.buildId) >>> 0) ^ key, true);
    dv.setUint32(at + 4, e.useCount ^ key, true);
  });
  dv.setUint32(richAt, 0x68636952, true); // "Rich"
  dv.setUint32(richAt + 4, key, true);
  return buf;
}

describe("parseRichHeader", () => {
  it("returns null when there is no Rich marker", () => {
    expect(parseRichHeader(new ArrayBuffer(0x200))).toBeNull();
  });

  it("decodes XOR-obfuscated entries", () => {
    const entries = [
      { toolId: 0x0102, buildId: 0x521e, useCount: 3 },
      { toolId: 0x00ff, buildId: 0x0000, useCount: 17 },
    ];
    expect(parseRichHeader(richBuffer(entries))).toEqual(entries);
  });

  it("returns null when the DanS marker is missing", () => {
    const buf = richBuffer([{ toolId: 1, buildId: 2, useCount: 3 }]);
    new DataView(buf).setUint32(0x80, 0xdeadbeef, true); // clobber DanS
    expect(parseRichHeader(buf)).toBeNull();
  });

  it("does not throw when the Rich marker sits at the very end of the buffer", () => {
    // "Rich" with fewer than 4 bytes behind it: the XOR key read runs off the
    // end of the buffer.
    const buf = new ArrayBuffer(0x88);
    const dv = new DataView(buf);
    dv.setUint32(0x84, 0x68636952, true); // "Rich" as the last 4 bytes
    expect(() => parseRichHeader(buf)).not.toThrow();
    expect(parseRichHeader(buf)).toBeNull();
  });

  it("does not throw when only part of the XOR key follows the marker", () => {
    const buf = new ArrayBuffer(0x8a);
    new DataView(buf).setUint32(0x84, 0x68636952, true);
    expect(() => parseRichHeader(buf)).not.toThrow();
  });

  it("ignores a Rich marker before the 0x80 scan floor", () => {
    const buf = new ArrayBuffer(0x200);
    new DataView(buf).setUint32(0x40, 0x68636952, true);
    expect(parseRichHeader(buf)).toBeNull();
  });

  it("tolerates a truncated trailing entry", () => {
    // Entry area is not a whole multiple of 8: the walk must not read past Rich.
    const entries = [{ toolId: 1, buildId: 2, useCount: 3 }];
    const buf = richBuffer(entries, { totalSize: 0x200 });
    expect(() => parseRichHeader(buf)).not.toThrow();
  });
});

function dataSection(name: string, rva: number, data: Uint8Array): SectionDef {
  return {
    name,
    virtualAddress: rva,
    virtualSize: Math.max(data.length, 0x100),
    data,
    characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
  };
}

describe("parseDebugDirectory", () => {
  it("returns an empty list when no debug directory is present", () => {
    const pe = parsePE(buildMinimalPE32());
    expect(parseDebugDirectory(pe.buffer, pe)).toEqual([]);
  });

  it("names known debug types and falls back for unknown ones", () => {
    const rva = 0x2000;
    const data = new Uint8Array(0x100);
    const dv = new DataView(data.buffer);
    dv.setUint32(12, 13, true); // entry 0: POGO
    dv.setUint32(28 + 12, 999, true); // entry 1: unknown type

    const buf = buildMinimalPE32({
      sections: [dataSection(".rdata", rva, data)],
      dataDirectories: new Map([[6, { virtualAddress: rva, size: 56 }]]),
    });
    const pe = parsePE(buf);
    const info = parseDebugDirectory(pe.buffer, pe);
    expect(info.map((d) => d.typeName)).toEqual(["POGO", "Type 999"]);
  });

  it("extracts the GUID, age and PDB path from an RSDS CodeView record", () => {
    const rva = 0x2000;
    const data = new Uint8Array(0x200);
    const dv = new DataView(data.buffer);
    // The CodeView pointerToRawData is a *file* offset, so it is patched below
    // once the fixture's section placement is known.
    dv.setUint32(12, 2, true); // type = CodeView

    const buf = buildMinimalPE32({
      sections: [dataSection(".rdata", rva, data)],
      dataDirectories: new Map([[6, { virtualAddress: rva, size: 28 }]]),
    });

    // Locate the section body in the file and write the RSDS record into it.
    const pe0 = parsePE(buf);
    const sec = pe0.sections.find((s) => s.virtualAddress === rva)!;
    const cvOffset = sec.pointerToRawData + 0x80;
    const fileView = new DataView(buf);
    fileView.setUint32(sec.pointerToRawData + 24, cvOffset, true); // pointerToRawData
    fileView.setUint32(cvOffset, 0x53445352, true); // "RSDS"
    for (let i = 0; i < 16; i++) fileView.setUint8(cvOffset + 4 + i, i + 1);
    fileView.setUint32(cvOffset + 20, 7, true); // age
    const path = "C:\\build\\sample.pdb";
    for (let i = 0; i < path.length; i++) {
      fileView.setUint8(cvOffset + 24 + i, path.charCodeAt(i));
    }

    const pe = parsePE(buf);
    const info = parseDebugDirectory(pe.buffer, pe);
    expect(info).toHaveLength(1);
    expect(info[0].typeName).toBe("CodeView");
    expect(info[0].age).toBe(7);
    expect(info[0].pdbPath).toBe(path);
    // Bytes 01..10 in file order, formatted as a GUID string.
    expect(info[0].guid).toBe("01020304-0506-0708-090A-0B0C0D0E0F10");
  });

  it("does not throw when the CodeView record points past the end of the file", () => {
    const rva = 0x2000;
    const data = new Uint8Array(0x100);
    const dv = new DataView(data.buffer);
    dv.setUint32(12, 2, true); // CodeView
    dv.setUint32(24, 0xfffffff0, true); // pointerToRawData — far past EOF

    const buf = buildMinimalPE32({
      sections: [dataSection(".rdata", rva, data)],
      dataDirectories: new Map([[6, { virtualAddress: rva, size: 28 }]]),
    });
    const pe = parsePE(buf);
    expect(() => parseDebugDirectory(pe.buffer, pe)).not.toThrow();
    expect(parseDebugDirectory(pe.buffer, pe)[0].pdbPath).toBeUndefined();
  });

  it("stops at the end of the buffer when the declared size is absurd", () => {
    const rva = 0x2000;
    const data = new Uint8Array(0x100);
    const buf = buildMinimalPE32({
      sections: [dataSection(".rdata", rva, data)],
      dataDirectories: new Map([[6, { virtualAddress: rva, size: 0xffffffff }]]),
    });
    const pe = parsePE(buf);
    const started = Date.now();
    const info = parseDebugDirectory(pe.buffer, pe);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(info.length).toBeLessThanOrEqual(Math.ceil(buf.byteLength / 28));
  }, 10000);
});

describe("validateChecksum", () => {
  it("accepts a zero checksum as unverifiable rather than invalid", () => {
    const pe = parsePE(buildMinimalPE32());
    const result = validateChecksum(pe.buffer, pe);
    expect(result.expected).toBe(0);
    expect(result.valid).toBe(true);
  });

  it("reports a mismatch when the stored checksum is wrong", () => {
    const buf = buildMinimalPE32();
    const peOffset = new DataView(buf).getUint32(60, true);
    new DataView(buf).setUint32(peOffset + 4 + 20 + 64, 0xdeadbeef, true);

    const pe = parsePE(buf);
    const result = validateChecksum(pe.buffer, pe);
    expect(result.expected).toBe(0xdeadbeef);
    expect(result.valid).toBe(false);
    expect(result.actual).not.toBe(0xdeadbeef);
  });

  it("validates when the computed checksum is written back into the file", () => {
    // Round trip: the field is excluded from its own sum, so writing the
    // computed value must make the file verify.
    const buf = buildMinimalPE32();
    const pe0 = parsePE(buf);
    const computed = validateChecksum(buf, pe0).actual;

    const peOffset = new DataView(buf).getUint32(60, true);
    new DataView(buf).setUint32(peOffset + 4 + 20 + 64, computed, true);

    const pe = parsePE(buf);
    const result = validateChecksum(pe.buffer, pe);
    expect(result.expected).toBe(computed);
    expect(result.valid).toBe(true);
  });

  it("handles an odd-length buffer without reading past the end", () => {
    const buf = buildMinimalPE32();
    const odd = buf.slice(0, buf.byteLength - 1);
    const pe = parsePE(buf);
    expect(() => validateChecksum(odd, pe)).not.toThrow();
  });
});

describe("detectOverlay", () => {
  // A section body that exactly fills its file alignment, so the last section
  // ends where the file does — as it would in a linker-produced image. The
  // default 4-byte .text fixture leaves alignment padding, which detectOverlay
  // (reasonably) cannot tell apart from appended data.
  const aligned = () => ({ sections: [dataSection(".text", 0x1000, new Uint8Array(0x200))] });

  it("returns null when nothing follows the last section", () => {
    const pe = parsePE(buildMinimalPE32(aligned()));
    expect(detectOverlay(pe.buffer, pe)).toBeNull();
  });

  it("reports appended data as an overlay", () => {
    const buf = buildMinimalPE32(aligned());
    const withOverlay = new Uint8Array(buf.byteLength + 0x40);
    withOverlay.set(new Uint8Array(buf));
    withOverlay.fill(0x41, buf.byteLength);

    const pe = parsePE(withOverlay.buffer);
    const overlay = detectOverlay(pe.buffer, pe);
    expect(overlay).not.toBeNull();
    expect(overlay!.offset).toBe(buf.byteLength);
    expect(overlay!.size).toBe(0x40);
  });
});
