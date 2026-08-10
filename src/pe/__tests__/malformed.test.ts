/**
 * Hostile / malformed PE regression tests.
 *
 * The parser is fed attacker-supplied binaries by design, so every case here is
 * a crash or hang that a crafted file could previously trigger. Each test carries
 * an explicit timeout: a regression must surface as a failure, not as a hung suite.
 */

import { describe, it, expect } from "vitest";
import { parsePE } from "../parser";
import { parseSecurityDirectory } from "../authenticode";
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from "./fixtures";
import { IMAGE_SCN_MEM_READ, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE } from "../constants";

const TIMEOUT = 5000;

/** Locate the COFF header of a built fixture (e_lfanew lives at offset 60). */
function coffOffsetOf(buf: ArrayBuffer): number {
  return new DataView(buf).getUint32(60, true) + 4;
}

function dataSection(name: string, rva: number, data: Uint8Array): SectionDef {
  return {
    name,
    virtualAddress: rva,
    virtualSize: Math.max(data.length, 0x100),
    data,
    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
  };
}

describe("malformed PE handling", () => {
  describe("truncated input", () => {
    it("rejects a file shorter than the DOS header with a clear error", () => {
      const tiny = new ArrayBuffer(16);
      new DataView(tiny).setUint16(0, 0x5a4d, true); // valid MZ, nothing else
      // Must be a useful parse error, not a bare RangeError from getUint32(60).
      expect(() => parsePE(tiny)).toThrow(/too small/i);
    });

    it("rejects a PE whose COFF header runs past EOF", () => {
      const buf = new ArrayBuffer(80);
      const v = new DataView(buf);
      v.setUint16(0, 0x5a4d, true);
      v.setUint32(60, 70, true); // e_lfanew points near the very end
      v.setUint32(70, 0x00004550, true); // "PE\0\0" fits, COFF header does not
      expect(() => parsePE(buf)).toThrow(/truncated/i);
    });
  });

  describe("unbounded header counts", () => {
    it("clamps a bogus numberOfSections instead of throwing", { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE32();
      // 65535 sections claimed, but the buffer holds room for a handful.
      new DataView(buf).setUint16(coffOffsetOf(buf) + 2, 0xffff, true);

      const pe = parsePE(buf);
      expect(pe.sections.length).toBeLessThan(0xffff);
      // Each header is 40 bytes, so the count must fit the buffer.
      expect(pe.sections.length).toBeLessThanOrEqual(Math.ceil(buf.byteLength / 40));
    });

    it("clamps numberOfRvaAndSizes to the 16-entry spec maximum", { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE32();
      const optionalHeaderOffset = coffOffsetOf(buf) + 20;
      new DataView(buf).setUint32(optionalHeaderOffset + 92, 0xffffffff, true);

      const pe = parsePE(buf);
      expect(pe.dataDirectories.length).toBeLessThanOrEqual(16);
    });

    it("clamps numberOfRvaAndSizes on PE32+ too", { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE64();
      const optionalHeaderOffset = coffOffsetOf(buf) + 20;
      new DataView(buf).setUint32(optionalHeaderOffset + 108, 0xffffffff, true);

      const pe = parsePE(buf);
      expect(pe.dataDirectories.length).toBeLessThanOrEqual(16);
    });
  });

  describe("import table", () => {
    it("survives a thunk RVA that resolves outside every section", { timeout: TIMEOUT }, () => {
      // One import descriptor whose OriginalFirstThunk/FirstThunk point far
      // outside any section, so rvaToFileOffset returns -1. Reading a thunk at a
      // negative offset used to throw an uncaught RangeError and fail the load.
      const rva = 0x1000;
      const data = new Uint8Array(0x100);
      const dv = new DataView(data.buffer);
      dv.setUint32(0, 0x99999999, true); // OriginalFirstThunk — unmapped
      dv.setUint32(4, 0, true); // TimeDateStamp
      dv.setUint32(8, 0, true); // ForwarderChain
      dv.setUint32(12, rva + 0x40, true); // Name — valid, inside this section
      dv.setUint32(16, 0x99999999, true); // FirstThunk — unmapped
      // descriptor[1] is left zeroed, terminating the walk
      for (const [i, ch] of [..."BOGUS.DLL"].entries()) {
        data[0x40 + i] = ch.charCodeAt(0);
      }

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[1, { virtualAddress: rva, size: 40 }]]),
      });

      expect(() => parsePE(buf)).not.toThrow();
    });

    it("stops at the declared directory size when no null descriptor follows", {
      timeout: TIMEOUT,
    }, () => {
      // Two real libraries, but the directory claims to hold only one
      // descriptor. The walk must trust the declared extent rather than reading
      // whatever bytes follow as further descriptors.
      const buf = buildMinimalPE32({
        directories: {
          imports: [
            { libraryName: "FIRST.dll", functions: [{ name: "a" }] },
            { libraryName: "SECOND.dll", functions: [{ name: "b" }] },
          ],
        },
        dataDirectories: new Map([[1, { virtualAddress: 0x2000, size: 20 }]]),
      });

      const pe = parsePE(buf);
      expect(pe.imports.map((l) => l.libraryName)).toEqual(["FIRST.dll"]);
    });

    it("does not read past the buffer when the directory size is 0xFFFFFFFF", {
      timeout: TIMEOUT,
    }, () => {
      const buf = buildMinimalPE32({
        directories: { imports: [{ libraryName: "ONE.dll", functions: [{ name: "a" }] }] },
        dataDirectories: new Map([[1, { virtualAddress: 0x2000, size: 0xffffffff }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(pe.imports.map((l) => l.libraryName)).toEqual(["ONE.dll"]);
    });
  });

  describe("export table", () => {
    it("does not spin on a 0xFFFFFFFF numberOfNames", { timeout: TIMEOUT }, () => {
      // The name-pointer walk is bounded only by numberOfNames, read straight off
      // the file. Previously this looped ~4.3 billion times on `continue`,
      // freezing the main thread.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(24, 0xffffffff, true); // numberOfNames
      dv.setUint32(28, rva + 0x80, true); // addressTableRVA   — mapped
      dv.setUint32(32, rva + 0xa0, true); // namePointerRVA    — mapped
      dv.setUint32(36, rva + 0xc0, true); // ordinalTableRVA   — mapped

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 40 }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      // Whatever it recovers, it cannot exceed what the buffer could hold.
      expect(pe.exports.length).toBeLessThan(buf.byteLength);
    });

    it("does not spin on a 0xFFFFFFFF numberOfFunctions", { timeout: TIMEOUT }, () => {
      // The address-table walk covers ordinal-only exports, so it is driven by
      // numberOfFunctions — equally attacker-controlled and equally clamped.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(16, 1, true); // ordinal base
      dv.setUint32(20, 0xffffffff, true); // numberOfFunctions
      dv.setUint32(24, 0, true); // numberOfNames — ordinal-only
      dv.setUint32(28, rva + 0x80, true); // addressTableRVA — mapped
      // Two non-zero address slots so the walk has something to emit.
      dv.setUint32(0x80, 0x1500, true);
      dv.setUint32(0x84, 0x1600, true);

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 40 }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(pe.exports.length).toBeLessThan(buf.byteLength);
      expect(pe.exports.slice(0, 2).map((e) => [e.ordinal, e.address])).toEqual([
        [1, 0x1500],
        [2, 0x1600],
      ]);
    });

    it("survives a truncated export directory header", { timeout: TIMEOUT }, () => {
      // The directory RVA maps, but fewer than the 40 header bytes remain in the
      // file — reading Base/NumberOfFunctions there must not throw.
      // The section fills its file alignment exactly, so a directory 0x10 bytes
      // from its end really does run off the end of the buffer.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva + 0x1f0, size: 40 }]]),
      });
      const dirFileOffset = buf.byteLength - 0x10;
      expect(dirFileOffset + 40).toBeGreaterThan(buf.byteLength);

      let pe!: ReturnType<typeof parsePE>;
      expect(() => {
        pe = parsePE(buf);
      }).not.toThrow();
      expect(pe.exports).toEqual([]);
    });

    it("ignores a forwarder RVA that resolves outside every section", { timeout: TIMEOUT }, () => {
      // A directory size of 0xFFFFFFFF makes every address look like a forwarder;
      // the string RVA itself is unmapped, so no target can be read.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(16, 1, true); // ordinal base
      dv.setUint32(20, 1, true); // numberOfFunctions
      dv.setUint32(28, rva + 0x80, true); // addressTableRVA — mapped
      dv.setUint32(0x80, 0x99999999, true); // address — unmapped, "inside" the range

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 0xffffffff }]]),
      });

      const pe = parsePE(buf);
      expect(pe.exports).toHaveLength(1);
      expect(pe.exports[0].forwarder).toBeUndefined();
      expect(pe.exports[0].address).toBe(0x99999999);
    });

    it("bounds an unterminated forwarder string", { timeout: TIMEOUT }, () => {
      // The forwarder string runs to the end of the section with no NUL. It must
      // be clipped to the buffer, not read past it.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(16, 1, true); // ordinal base
      dv.setUint32(20, 1, true); // numberOfFunctions
      dv.setUint32(28, rva + 0x80, true); // addressTableRVA
      dv.setUint32(0x80, rva + 0xc0, true); // address -> inside the directory range
      data.fill(0x41, 0xc0, data.length); // 'A' with no terminator

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 0x200 }]]),
      });

      const pe = parsePE(buf);
      expect(pe.exports).toHaveLength(1);
      expect(pe.exports[0].forwarder).toMatch(/^A+$/);
      expect(pe.exports[0].forwarder!.length).toBeLessThanOrEqual(buf.byteLength);
    });

    it("survives an unmapped name-pointer table but keeps ordinal exports", {
      timeout: TIMEOUT,
    }, () => {
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(16, 1, true); // ordinal base
      dv.setUint32(20, 2, true); // numberOfFunctions
      dv.setUint32(24, 2, true); // numberOfNames
      dv.setUint32(28, rva + 0x80, true); // addressTableRVA — mapped
      dv.setUint32(32, 0x99999999, true); // namePointerRVA — unmapped
      dv.setUint32(36, 0x99999999, true); // ordinalTableRVA — unmapped
      dv.setUint32(0x80, 0x1500, true);
      dv.setUint32(0x84, 0x1600, true);

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 40 }]]),
      });

      const pe = parsePE(buf);
      expect(pe.exports.map((e) => [e.name, e.ordinal])).toEqual([
        ["Ordinal#1", 1],
        ["Ordinal#2", 2],
      ]);
    });
  });

  describe("base relocations", () => {
    it("bounds the entry walk when SizeOfBlock is 0xFFFFFFFF", { timeout: TIMEOUT }, () => {
      // entryCount is derived from SizeOfBlock, so a hostile value asks for ~2
      // billion iterations. The walk must stop at the end of the buffer instead.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      dv.setUint32(0, 0x1000, true); // VirtualAddress
      dv.setUint32(4, 0xffffffff, true); // SizeOfBlock

      const buf = buildMinimalPE32({
        sections: [dataSection(".reloc", rva, data)],
        dataDirectories: new Map([[5, { virtualAddress: rva, size: 0x200 }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(pe.relocations?.[0].entries.length).toBeLessThan(buf.byteLength);
    });

    it("bounds the block walk when the directory size is 0xFFFFFFFF", { timeout: TIMEOUT }, () => {
      // endPos is baseOffset + the declared directory size, so an oversized
      // directory leaves the buffer length as the only backstop.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const dv = new DataView(data.buffer);
      for (let i = 0; i < 0x200; i += 8) {
        dv.setUint32(i, 0x1000 + i, true); // VirtualAddress — always non-zero
        dv.setUint32(i + 4, 8, true); // SizeOfBlock — smallest legal block
      }

      const buf = buildMinimalPE32({
        sections: [dataSection(".reloc", rva, data)],
        dataDirectories: new Map([[5, { virtualAddress: rva, size: 0xffffffff }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(pe.relocations!.length).toBeLessThanOrEqual(buf.byteLength / 8);
    });
  });

  describe("TLS callbacks", () => {
    it("caps the callback walk on an array of non-zero pointers", { timeout: TIMEOUT }, () => {
      // The array is null-terminated, so a section full of non-zero pointers has
      // no terminator; only the hard iteration cap ends the walk.
      const rva = 0x1000;
      const data = new Uint8Array(0x400);
      const dv = new DataView(data.buffer);
      for (let i = 0; i < 0x100; i += 4) dv.setUint32(i, 0x00401000, true);
      dv.setUint32(0x100 + 12, 0x00400000 + rva, true); // AddressOfCallBacks -> offset 0

      const buf = buildMinimalPE32({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[9, { virtualAddress: rva + 0x100, size: 24 }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(pe.tlsDirectory!.callbacks.length).toBeLessThanOrEqual(256);
    });
  });

  describe("authenticode DER", () => {
    it("rejects a 4-byte DER length with the high bit set", { timeout: TIMEOUT }, () => {
      // `contentLen = (contentLen << 8) | byte` is signed-32 in JS, so 0xFF...
      // produced a NEGATIVE length. readDERChildren then walked backwards and
      // never terminated. This must return promptly instead.
      // The poisoned element must sit INSIDE a well-formed parent: readDERChildren
      // has to be entered with a positive length so that `pos += totalLen` can
      // then drive pos backwards and loop ~2 billion times.
      const buffer = new ArrayBuffer(0x200);
      const v = new DataView(buffer);
      const certOffset = 0x100;

      v.setUint32(certOffset, 0x40, true); // dwLength — 64 bytes total
      v.setUint16(certOffset + 4, 0x0200, true); // wRevision
      v.setUint16(certOffset + 6, 0x0002, true); // PKCS_SIGNED_DATA

      const cert = certOffset + 8; // bCertificate starts here
      v.setUint8(cert + 0, 0x30); // outer SEQUENCE
      v.setUint8(cert + 1, 0x30); // short-form length: 48 bytes of children
      // First child: a 4-byte long-form length of 0x80000000. Under the old
      // signed `<<` arithmetic that is -2147483648, making totalLen deeply
      // negative so `pos += totalLen` jumps ~2 billion bytes backwards.
      // (0xFFFFFFFF is NOT a repro — it yields -1, leaving totalLen positive.)
      v.setUint8(cert + 2, 0x06); // OID
      v.setUint8(cert + 3, 0x84); // long form, 4 length bytes
      v.setUint8(cert + 4, 0x80);
      v.setUint8(cert + 5, 0x00);
      v.setUint8(cert + 6, 0x00);
      v.setUint8(cert + 7, 0x00);

      const dirs = Array.from({ length: 16 }, () => ({ virtualAddress: 0, size: 0 }));
      dirs[4] = { virtualAddress: certOffset, size: 0x40 };

      const started = Date.now();
      const result = parseSecurityDirectory(buffer, dirs);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      // Signature is present but unparseable — it must report that, not hang.
      expect(result?.signed).toBe(true);
    });
  });
});
