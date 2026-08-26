/**
 * Hostile / malformed PE regression tests.
 *
 * The parser is fed attacker-supplied binaries by design, so every case here is
 * a crash or hang that a crafted file could previously trigger. Each test carries
 * an explicit timeout: a regression must surface as a failure, not as a hung suite.
 */

import { describe, expect, it } from "vitest";
import { parseSecurityDirectory } from "../authenticode";
import {
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
} from "../constants";
import {
  computeImphash,
  MAX_PDB_PATH_BYTES,
  PDB_PATH_TRUNCATION_MARKER,
  parseDebugDirectory,
} from "../metadata";
import {
  isNameTruncated,
  MAX_IMPORT_DESCRIPTORS,
  MAX_IMPORT_FUNCTIONS,
  NAME_TRUNCATION_MARKER,
  parsePE,
} from "../parser";
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from "./fixtures";

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
      // ...AND SAYS SO. The declared size is the one bound here that can be too
      // SMALL — `peek-a-bin-nygv` made the same observation about `SizeOfData`
      // — so honouring it silently is how a hostile file gets a well-formed
      // imphash for a library set the image does not have. The walk trusts the
      // declaration and records that it never reached a terminator.
      expect(pe.importsTruncated).toBe(true);
      expect(computeImphash(pe)).toBeNull();
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

    it("bounds an unterminated forwarder string, and says it cut it short", {
      timeout: TIMEOUT,
    }, () => {
      // The forwarder string runs to the end of the section with no NUL. It must
      // be clipped to the buffer, not read past it.
      //
      // THIS ROW USED TO ASSERT THE SILENT TRUNCATION AS THE RULE (`/^A+$/`,
      // i.e. a clipped forwarder that reads exactly like a complete one) and it
      // went red the moment `readCString` began marking. That is the shape the
      // house keeps finding — a test pinning a defect — and it is the reason
      // this half of `peek-a-bin-tmo9` is worth doing: `parseForwarder` splits
      // a forwarder on its dot to name a DLL and a symbol, so a clipped one
      // resolves to a target the file never named. The marker cannot be
      // mistaken for either half.
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
      expect(pe.exports[0].forwarder).toMatch(/^A+… <truncated>$/);
      expect(isNameTruncated(pe.exports[0].forwarder!)).toBe(true);
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

  /**
   * The load-config directory (peek-a-bin-7p5t). `CHPEMetadataPointer` sits at
   * 0xC8 of a structure whose real length is whatever the linker felt like
   * emitting, so the interesting failures are all "the field's offset exists,
   * the bytes at it belong to something else". Every one of these must yield
   * `chpeMetadataPointer: undefined` rather than a number: a wrong pointer here
   * would be read as evidence that an ordinary image is hybrid.
   */
  describe("load config directory", () => {
    it("ignores the field when the structure's own Size stops short of it", {
      timeout: TIMEOUT,
    }, () => {
      // 0x70 is an ordinary length for an older linker's structure — this is not
      // a hostile file, just an old one. The bytes at 0xC8 are the next
      // structure's, and the fixture puts a recognisable value there.
      //
      // Not hypothetical: both PE32 binaries on this machine (t32.exe, w32.exe)
      // declare a 0x48-byte load config against a 0x40-byte directory entry,
      // where the 32-bit field at 0x7C needs 0x80. Reading at the offset without
      // this check would report .rdata's next bytes as a CHPE pointer.
      const buf = buildMinimalPE64({
        directories: { loadConfig: { declaredSize: 0x70, chpeMetadataPointer: 0xdeadbeef } },
      });

      const lc = parsePE(buf).loadConfig;
      expect(lc?.declaredSize).toBe(0x70);
      expect(lc?.chpeMetadataPointer).toBeUndefined();
    });

    it("ignores the field when the data directory's Size stops short of it", {
      timeout: TIMEOUT,
    }, () => {
      // The other direction: the structure claims to be long, the directory
      // entry says otherwise. The smaller claim has to win either way round.
      const buf = buildMinimalPE64({
        directories: {
          loadConfig: { declaredSize: 0x140, directorySize: 0x70, chpeMetadataPointer: 0xdeadbeef },
        },
      });

      expect(parsePE(buf).loadConfig?.chpeMetadataPointer).toBeUndefined();
    });

    it("does not read a truncated structure past the end of its section", {
      timeout: TIMEOUT,
    }, () => {
      // Both sizes claim the full structure and the RVA resolves, but only 0x20
      // bytes of the section remain. A *second* section follows in the file, so
      // the bytes at 0xC8 exist and are readable — they just belong to something
      // else. A file-length check passes here and a section check does not,
      // which is the whole reason the bound is expressed against the section
      // table rather than against `view.byteLength`.
      const rva = 0x1000;
      const first = new Uint8Array(0x200);
      new DataView(first.buffer).setUint32(0x1e0, 0x140, true); // Size field
      const second = new Uint8Array(0x200).fill(0xaa); // recognisable, and not zero
      const buf = buildMinimalPE64({
        sections: [dataSection(".rdata", rva, first), dataSection(".data", rva + 0x1000, second)],
        dataDirectories: new Map([[10, { virtualAddress: rva + 0x1e0, size: 0x140 }]]),
      });

      let pe!: ReturnType<typeof parsePE>;
      expect(() => {
        pe = parsePE(buf);
      }).not.toThrow();
      // The premise, asserted rather than assumed: the field's bytes are inside
      // the file but outside the section the directory lives in.
      const section = pe.sections[0];
      const fieldOffset = section.pointerToRawData + 0x1e0 + 0xc8;
      expect(fieldOffset + 8).toBeLessThanOrEqual(buf.byteLength);
      expect(fieldOffset).toBeGreaterThan(section.pointerToRawData + section.sizeOfRawData);

      expect(pe.loadConfig?.declaredSize).toBe(0x140);
      expect(pe.loadConfig?.chpeMetadataPointer).toBeUndefined();
    });

    it("survives a directory RVA that resolves outside every section", {
      timeout: TIMEOUT,
    }, () => {
      const buf = buildMinimalPE64({
        dataDirectories: new Map([[10, { virtualAddress: 0x99999999, size: 0x140 }]]),
      });

      let pe!: ReturnType<typeof parsePE>;
      expect(() => {
        pe = parsePE(buf);
      }).not.toThrow();
      expect(pe.loadConfig).toBeUndefined();
    });

    it("survives a 0xFFFFFFFF directory size", { timeout: TIMEOUT }, () => {
      // An inflated directory size must not license a read past the section;
      // the structure here really is only 0x70 bytes long.
      const buf = buildMinimalPE64({
        directories: {
          loadConfig: { bytes: 0x70, declaredSize: 0xffffffff, directorySize: 0xffffffff },
        },
      });

      const started = Date.now();
      const lc = parsePE(buf).loadConfig;
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      expect(lc?.chpeMetadataPointer).toBeUndefined();
    });

    it("survives a directory whose Size field itself is off the end of the file", {
      timeout: TIMEOUT,
    }, () => {
      // Not even the 4 bytes at offset 0 are readable. The early bound has to
      // come before the Size read, not after it.
      const rva = 0x1000;
      const data = new Uint8Array(0x200);
      const buf = buildMinimalPE64({
        sections: [dataSection(".rdata", rva, data)],
        dataDirectories: new Map([[10, { virtualAddress: rva + 0x1fe, size: 0x140 }]]),
      });

      let pe!: ReturnType<typeof parsePE>;
      expect(() => {
        pe = parsePE(buf);
      }).not.toThrow();
      expect(pe.loadConfig).toBeUndefined();
    });

    it("leaves loadConfig undefined when the image has fewer than 11 data directories", {
      timeout: TIMEOUT,
    }, () => {
      // numberOfRvaAndSizes is 10, so index 10 does not exist at all. Indexing
      // past the end of the array must not throw.
      const buf = buildMinimalPE64({ numberOfRvaAndSizes: 10 });

      let pe!: ReturnType<typeof parsePE>;
      expect(() => {
        pe = parsePE(buf);
      }).not.toThrow();
      expect(pe.dataDirectories.length).toBe(10);
      expect(pe.loadConfig).toBeUndefined();
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

  /**
   * The CodeView PDB path scan (`peek-a-bin-nygv`).
   *
   * `parseDebugDirectory` used to scan for the path's terminating NUL from
   * `pointerToRawData + 24` forward through the **whole buffer**, then decode
   * everything it passed — during a render, on the main thread, on files this
   * tool opens at a couple of hundred MiB. The instrument here is the decoded
   * length and the returned value, never a timing: three agents share this
   * machine and a wall-clock assertion would be flaky where a length is exact.
   *
   * The well-formed row is the safety case for the whole change: it must stay
   * byte-identical to the pre-fix output.
   */
  describe("debug directory PDB path scan", () => {
    const WELL_FORMED_PATH = "C:\\build\\obj\\sample.pdb";

    /** Build a PE32 carrying one RSDS CodeView record with a known path. */
    function withCodeView(pdbPath = WELL_FORMED_PATH): ArrayBuffer {
      return buildMinimalPE32({
        directories: {
          debug: [{ type: 2, codeView: { guid: new Uint8Array(16).fill(0xab), age: 9, pdbPath } }],
        },
      });
    }

    /** File offset of debug entry `i`'s 28-byte `IMAGE_DEBUG_DIRECTORY`. */
    function debugEntryOffset(buf: ArrayBuffer, i = 0): number {
      const pe = parsePE(buf);
      const rva = pe.dataDirectories[6].virtualAddress;
      const sec = pe.sections.find(
        (s) => rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize,
      );
      if (!sec) throw new Error("fixture debug directory is not inside a section");
      return sec.pointerToRawData + (rva - sec.virtualAddress) + i * 28;
    }

    /** File offset of the RSDS payload entry `i` names (`PointerToRawData`). */
    function payloadOffset(buf: ArrayBuffer, i = 0): number {
      return new DataView(buf).getUint32(debugEntryOffset(buf, i) + 24, true);
    }

    function setSizeOfData(buf: ArrayBuffer, size: number, i = 0): void {
      new DataView(buf).setUint32(debugEntryOffset(buf, i) + 16, size, true);
    }

    /**
     * Grow the file by `extra` bytes and fill everything from `from` to the new
     * end with a non-zero byte, so the buffer holds **no NUL** after that point.
     *
     * The tail is what makes the measurement sharp: the old scan's decoded
     * length was `fileLength - pathStart`, so a small fixture would have hidden
     * the defect behind a small number. Section headers and the debug table
     * both sit *below* the payload in this layout, so nothing the parser reads
     * is disturbed — asserted by the callers, which all parse successfully.
     */
    function noNulAfter(buf: ArrayBuffer, from: number, extra: number): ArrayBuffer {
      const grown = new ArrayBuffer(buf.byteLength + extra);
      new Uint8Array(grown).set(new Uint8Array(buf));
      new Uint8Array(grown, from).fill(0x41); // 'A'
      return grown;
    }

    it("reads a well-formed path exactly, and does not mark it", { timeout: TIMEOUT }, () => {
      // THE SAFETY CASE. Every bound below is only admissible because this row
      // is unchanged by them.
      const buf = withCodeView();
      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info).toHaveLength(1);
      expect(info[0].pdbPath).toBe(WELL_FORMED_PATH);
      expect(info[0].pdbPathTruncated).toBeUndefined();
      expect(info[0].age).toBe(9);
    });

    it("bounds the scan when the record has no NUL after it at all", {
      timeout: TIMEOUT,
    }, () => {
      // The original defect. `SizeOfData` is cleared too, so the ONLY thing
      // standing between this scan and the end of the file is the cap.
      const base = withCodeView();
      const start = payloadOffset(base) + 24;
      setSizeOfData(base, 0);
      const buf = noNulAfter(base, start, 1 << 20);

      // The instrument, MEASURED against the pre-fix code rather than reasoned:
      // a megabyte of NUL-free bytes follows the record, and the old scan
      // decoded 1,049,036 characters of it against this one's 4,109. The
      // fixture is a megabyte only so the suite stays fast; the shape is
      // `fileLength - pathStart`, so on the ~253 MiB image this tool is
      // expected to open the old number is ~265,000,000 — inside a render.
      expect(buf.byteLength - start).toBeGreaterThan(64 * MAX_PDB_PATH_BYTES);

      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPathTruncated).toBe(true);
      expect(info[0].pdbPath).toContain(PDB_PATH_TRUNCATION_MARKER);
      expect(info[0].pdbPath).toHaveLength(MAX_PDB_PATH_BYTES + PDB_PATH_TRUNCATION_MARKER.length);
    });

    it("does not truncate a valid path when SizeOfData is zero", { timeout: TIMEOUT }, () => {
      // A declaration too small to hold even the fixed part plus a terminator
      // is not a credible statement about this record, so it is IGNORED rather
      // than honoured — honouring it would turn a robustness fix into a
      // correctness defect on a file whose path is perfectly well-formed.
      // HONEST NOTE ABOUT THIS ROW AS AN INSTRUMENT. Zeroing `SizeOfData` is
      // the control that exposed the defect (`peek-a-bin-nygv`), and it was
      // inert because nothing read the field. It is **still inert in that
      // direction** — this row is green before the fix and green after it, by
      // two different routes. It is not useless: it is the guard against the
      // opposite error, and goes red the moment the credibility test is
      // dropped and the field is honoured unconditionally. The row that proves
      // the field is read at all is the understating one below.
      const buf = withCodeView();
      setSizeOfData(buf, 0);
      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPath).toBe(WELL_FORMED_PATH);
      expect(info[0].pdbPathTruncated).toBeUndefined();
    });

    it("cuts the path short — visibly — when SizeOfData understates it", {
      timeout: TIMEOUT,
    }, () => {
      // The smaller bound wins, so an understated size DOES shorten the answer.
      // That is only admissible because the answer says so: the value carries
      // the marker and cannot be mistaken for a path.
      const buf = withCodeView();
      setSizeOfData(buf, 24 + 7); // room for "C:\\buil" and no terminator
      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPathTruncated).toBe(true);
      expect(info[0].pdbPath).toBe(`C:\\buil${PDB_PATH_TRUNCATION_MARKER}`);
      // A narrower answer must not wear a complete one's shape.
      expect(info[0].pdbPath).not.toBe(WELL_FORMED_PATH);
      expect(WELL_FORMED_PATH.startsWith(info[0].pdbPath ?? "")).toBe(false);
    });

    it("still reads the whole path when SizeOfData overstates it wildly", {
      timeout: TIMEOUT,
    }, () => {
      const buf = withCodeView();
      setSizeOfData(buf, 0xffffffff);
      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPath).toBe(WELL_FORMED_PATH);
      expect(info[0].pdbPathTruncated).toBeUndefined();
    });

    it("falls back to the cap when SizeOfData overstates and there is no NUL", {
      timeout: TIMEOUT,
    }, () => {
      // An absurd size is what a hostile file writes to defeat a size-only
      // bound; the cap is the backstop that makes the size field safe to trust.
      const base = withCodeView();
      const start = payloadOffset(base) + 24;
      setSizeOfData(base, 0xffffffff);
      const buf = noNulAfter(base, start, 1 << 20);

      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPathTruncated).toBe(true);
      expect(info[0].pdbPath).toHaveLength(MAX_PDB_PATH_BYTES + PDB_PATH_TRUNCATION_MARKER.length);
    });

    it("is bounded by the end of the file when that comes first", {
      timeout: TIMEOUT,
    }, () => {
      // Neither the declared size nor the cap may be read past the buffer.
      const base = withCodeView();
      const start = payloadOffset(base) + 24;
      setSizeOfData(base, 0xffffffff);
      const buf = noNulAfter(base, start, 16); // far short of the cap

      const info = parseDebugDirectory(buf, parsePE(buf));
      expect(info[0].pdbPathTruncated).toBe(true);
      expect(info[0].pdbPath?.length).toBeLessThan(
        MAX_PDB_PATH_BYTES + PDB_PATH_TRUNCATION_MARKER.length,
      );
      expect(info[0].pdbPath).toContain(PDB_PATH_TRUNCATION_MARKER);
    });
  });

  /**
   * IMPORT TABLE — two attacker-controlled walks, one of which used to be
   * bounded only by the end of the file (`peek-a-bin-tmo9`).
   *
   * These are instrumented on the RETURNED COUNT, never on a timing: several
   * agents share this machine and a wall-clock assertion would be flaky where a
   * count is exact. Every "before" figure below was taken at 5baec33 by running
   * the same fixture against the pre-fix parser.
   */
  describe("import table", () => {
    const RVA = 0x1000;

    /** A `.rdata`-shaped section whose virtual and raw extents are exact. */
    function rdata(data: Uint8Array, rva = RVA): SectionDef {
      return {
        name: ".rdata",
        virtualAddress: rva,
        virtualSize: data.length,
        data,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      };
    }

    /** Write a NUL-terminated ASCII name into `data` at `offset`. */
    function putName(data: Uint8Array, offset: number, name: string): void {
      data.set(new TextEncoder().encode(`${name}\0`), offset);
    }

    /** One import descriptor at section offset `at`. RVAs, not offsets. */
    function putDescriptor(
      dv: DataView,
      at: number,
      d: { originalFirstThunk: number; name: number; firstThunk: number },
    ): void {
      dv.setUint32(at, d.originalFirstThunk, true);
      dv.setUint32(at + 12, d.name, true);
      dv.setUint32(at + 16, d.firstThunk, true);
    }

    it("reads a well-formed import table exactly, and marks nothing", { timeout: TIMEOUT }, () => {
      // THE SAFETY CASE. Every bound below is only admissible because this row
      // is unchanged by it — a cap that truncates a real file has traded a hang
      // for a wrong answer, which is the worse of the two here.
      const buf = buildMinimalPE32({
        directories: {
          imports: [
            {
              libraryName: "KERNEL32.dll",
              functions: [{ name: "Sleep" }, { name: "ExitProcess" }, { ordinal: 42 }],
            },
            { libraryName: "USER32.dll", functions: [{ name: "MessageBoxA" }] },
          ],
        },
      });
      const pe = parsePE(buf);
      expect(pe.imports.map((i) => i.libraryName)).toEqual(["KERNEL32.dll", "USER32.dll"]);
      expect(pe.imports[0].functions).toEqual(["Sleep", "ExitProcess", "Ordinal_42"]);
      expect(pe.imports[1].functions).toEqual(["MessageBoxA"]);
      expect(pe.imports.some((i) => i.truncated)).toBe(false);
      expect(pe.importsTruncated).toBeUndefined();
      // A whole table still hashes. The refusal below must not be reachable by
      // an ordinary file, or it would withhold the imphash from everyone.
      expect(computeImphash(pe)).toMatch(/^[0-9a-f]{32}$/);
    });

    it("caps a thunk array that is never terminated", { timeout: TIMEOUT }, () => {
      // THE ORIGINAL DEFECT. The walk stops at a zero thunk and is otherwise
      // bounded only by `view.byteLength`, so an array of non-zero slots runs
      // to EOF pushing one entry per pointer-width slot — inside `parsePE`, on
      // the main thread, before anything renders.
      //
      // MEASURED at 5baec33 on this exact fixture: 262,080 functions in one
      // library, against MAX_IMPORT_FUNCTIONS after. The shape is
      // `sectionBytes / thunkSize`, so at the ~253 MiB image this tool is
      // expected to open the old number is tens of millions.
      const SIZE = 1 << 20;
      const data = new Uint8Array(SIZE);
      const dv = new DataView(data.buffer);
      putDescriptor(dv, 0, {
        originalFirstThunk: RVA + 0x100,
        name: RVA + 0x40,
        firstThunk: RVA + 0x100,
      });
      putName(data, 0x40, "HOSTILE.dll");
      // Every slot ordinal-flagged and non-zero, all the way to the section end.
      for (let o = 0x100; o + 4 <= SIZE; o += 4) dv.setUint32(o, 0x80000000 | 0x1234, true);

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      });
      const pe = parsePE(buf);

      // Liveness: the fixture really does hold far more slots than the cap, so
      // a green row is not one taken over an empty population.
      expect((SIZE - 0x100) / 4).toBeGreaterThan(MAX_IMPORT_FUNCTIONS);
      expect(pe.imports).toHaveLength(1);
      expect(pe.imports[0].functions).toHaveLength(MAX_IMPORT_FUNCTIONS);
      // ...and it says so, in both halves.
      expect(pe.imports[0].truncated).toBe(true);
      expect(pe.importsTruncated).toBe(true);
    });

    it("caps a descriptor array that is never terminated", { timeout: TIMEOUT }, () => {
      // The descriptor walk was already bounded by the directory's declared
      // size — but that field is a uint32 the file supplies, so declaring
      // 0xFFFFFFFF put it back on the buffer. MEASURED at 5baec33: 52,416
      // libraries out of a 1 MiB file, each with its own name decode.
      const SIZE = 1 << 20;
      const data = new Uint8Array(SIZE);
      const dv = new DataView(data.buffer);
      putName(data, 0x20, "HOSTILE.dll");
      for (let o = 0x100; o + 20 <= SIZE; o += 20) {
        putDescriptor(dv, o, { originalFirstThunk: 0, name: RVA + 0x20, firstThunk: 0 });
      }

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA + 0x100, size: 0xffffffff }]]),
      });
      const pe = parsePE(buf);

      expect((SIZE - 0x100) / 20).toBeGreaterThan(MAX_IMPORT_DESCRIPTORS);
      expect(pe.imports).toHaveLength(MAX_IMPORT_DESCRIPTORS);
      expect(pe.importsTruncated).toBe(true);
    });

    it("bounds the PRODUCT of the two walks, which is the case that killed the process", {
      timeout: TIMEOUT,
    }, () => {
      // THE ROW THAT JUSTIFIES A GLOBAL BUDGET RATHER THAN A PER-LIBRARY CAP.
      // Capping each walk separately still multiplies out: every descriptor may
      // name the same unterminated thunk array. MEASURED at 5baec33 on this
      // fixture, the old parser did not merely hang — node died with
      // `FATAL ERROR: Ineffective mark-compacts near heap limit`, i.e. ~4 GB of
      // import entries out of a ONE MEGABYTE file. In a browser that is the tab.
      const SIZE = 1 << 20;
      const THUNKS_AT = 0x80000;
      const data = new Uint8Array(SIZE);
      const dv = new DataView(data.buffer);
      putName(data, 0x20, "HOSTILE.dll");
      for (let o = THUNKS_AT; o + 4 <= SIZE; o += 4) dv.setUint32(o, 0x80000000 | 0x99, true);
      for (let o = 0x100; o + 20 <= THUNKS_AT; o += 20) {
        putDescriptor(dv, o, {
          originalFirstThunk: RVA + THUNKS_AT,
          name: RVA + 0x20,
          firstThunk: RVA + THUNKS_AT,
        });
      }

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA + 0x100, size: 0xffffffff }]]),
      });
      const pe = parsePE(buf);

      const total = pe.imports.reduce((sum, i) => sum + i.functions.length, 0);
      expect(pe.imports.length).toBeLessThanOrEqual(MAX_IMPORT_DESCRIPTORS);
      expect(total).toBeLessThanOrEqual(MAX_IMPORT_FUNCTIONS);
      // The budget is global, so it is spent by the first libraries and the
      // rest are empty — narrower than the file, and saying so.
      expect(total).toBe(MAX_IMPORT_FUNCTIONS);
      expect(pe.importsTruncated).toBe(true);
    });

    it("stops a thunk walk at the end of its own section, not at the end of the file", {
      timeout: TIMEOUT,
    }, () => {
      // THE SECTION BOUND, ASKED WHERE THE COUNT CAP CANNOT ANSWER. An import
      // array the file places inside a section does not continue past it, so
      // the section end is evidence the FILE provides. It is the bound that
      // improves the answer rather than only the cost: without it a missing
      // terminator at the end of `.rdata` reads the next section's bytes as
      // thunks, and the sections are contiguous in the file.
      const RDATA_SIZE = 0x400;
      const rd = new Uint8Array(RDATA_SIZE);
      const rdv = new DataView(rd.buffer);
      putDescriptor(rdv, 0, {
        originalFirstThunk: RVA + 0x100,
        name: RVA + 0x40,
        firstThunk: RVA + 0x100,
      });
      putName(rd, 0x40, "HOSTILE.dll");
      for (let o = 0x100; o + 4 <= RDATA_SIZE; o += 4) rdv.setUint32(o, 0x80000000 | 7, true);

      // A second section, immediately after, full of non-zero bytes: what the
      // unbounded walk would have decoded next.
      const NEXT_SIZE = 0x4000;
      const next = new Uint8Array(NEXT_SIZE).fill(0xcd);

      const buf = buildMinimalPE32({
        sections: [
          rdata(rd),
          {
            name: ".data",
            virtualAddress: 0x2000,
            virtualSize: NEXT_SIZE,
            data: next,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
          },
        ],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      });
      const pe = parsePE(buf);

      const slotsInSection = (RDATA_SIZE - 0x100) / 4;
      expect(pe.imports[0].functions).toHaveLength(slotsInSection);
      // Well under the count cap, so this row is the section bound's and
      // nothing else's; and far short of what the file could have supplied.
      expect(slotsInSection).toBeLessThan(MAX_IMPORT_FUNCTIONS);
      expect((NEXT_SIZE + RDATA_SIZE) / 4).toBeGreaterThan(slotsInSection * 4);
      expect(pe.imports[0].truncated).toBe(true);
      expect(pe.importsTruncated).toBe(true);
    });

    it("refuses to compute an imphash over a table that is not whole", { timeout: TIMEOUT }, () => {
      // THE CASE THAT DECIDES THE WHOLE DESIGN. A digest over a short import
      // list is well-formed and wrong: it is a hex string indistinguishable
      // from a correct one, nothing inside this tool ever validates it, and its
      // only use is comparison with another tool's answer — so it fails by
      // MATCHING NOTHING while looking entirely correct. Same trap as
      // `Ordinal_<n>`. `null` is the refusal; `""` still means "imports
      // nothing", and the two are different facts.
      const SIZE = 1 << 16;
      const data = new Uint8Array(SIZE);
      const dv = new DataView(data.buffer);
      putDescriptor(dv, 0, {
        originalFirstThunk: RVA + 0x100,
        name: RVA + 0x40,
        firstThunk: RVA + 0x100,
      });
      putName(data, 0x40, "KERNEL32.dll");
      for (let o = 0x100; o + 4 <= SIZE; o += 4) dv.setUint32(o, 0x80000000 | 5, true);

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      });
      const pe = parsePE(buf);

      expect(pe.importsTruncated).toBe(true);
      expect(computeImphash(pe)).toBeNull();
      // Not merely falsy: an image that imports nothing is a different answer,
      // and the Headers tab prints a different sentence for each.
      expect(computeImphash({ imports: [] })).toBe("");
    });

    it("marks a library name that runs past readCString's cap, and withholds the hash", {
      timeout: TIMEOUT,
    }, () => {
      // The `readCString` half. MEASURED at 5baec33: exactly 1024 characters,
      // tail "AAAAAAAA", with NOTHING marking it — a name that reads as the
      // file's own. The marker alone would not do here, because unlike a PDB
      // path this string reaches `computeImphash`: marking it changes a digest
      // instead of labelling a value. So a marked name also makes the ENTRY not
      // whole, which makes the TABLE not whole, which makes the hash refuse.
      const SIZE = 0x1000;
      const data = new Uint8Array(SIZE).fill(0x41); // 'A', no NUL anywhere
      const dv = new DataView(data.buffer);
      putDescriptor(dv, 0, {
        originalFirstThunk: RVA + 0x100,
        name: RVA + 0x800,
        firstThunk: RVA + 0x100,
      });
      dv.setUint32(0x100, 0x80000000 | 1, true);
      dv.setUint32(0x104, 0, true); // terminated thunk array: only the NAME is bad

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      });
      const pe = parsePE(buf);

      expect(pe.imports).toHaveLength(1);
      expect(pe.imports[0].libraryName).toHaveLength(1024 + NAME_TRUNCATION_MARKER.length);
      expect(pe.imports[0].libraryName.endsWith(NAME_TRUNCATION_MARKER)).toBe(true);
      expect(isNameTruncated(pe.imports[0].libraryName)).toBe(true);
      // The function list itself is complete — one ordinal — so this row is the
      // NAME's and nothing else's.
      expect(pe.imports[0].functions).toEqual(["Ordinal_1"]);
      expect(pe.imports[0].truncated).toBe(true);
      expect(computeImphash(pe)).toBeNull();
    });

    it("does not mark a name that ends exactly at the cap", { timeout: TIMEOUT }, () => {
      // PRECISION. Truncation is "the read stopped at the bound AND there is no
      // NUL sitting at it", not "the read reached the bound" — otherwise a name
      // of exactly 1024 bytes plus its terminator would be reported as cut
      // short and the imphash withheld from a file with nothing wrong with it.
      const SIZE = 0x1000;
      const data = new Uint8Array(SIZE);
      const dv = new DataView(data.buffer);
      putDescriptor(dv, 0, {
        originalFirstThunk: RVA + 0x100,
        name: RVA + 0x400,
        firstThunk: RVA + 0x100,
      });
      data.fill(0x42, 0x400, 0x400 + 1024); // 1024 'B's...
      data[0x400 + 1024] = 0; // ...and its terminator, exactly at the cap
      dv.setUint32(0x100, 0x80000000 | 1, true);
      dv.setUint32(0x104, 0, true);

      const buf = buildMinimalPE32({
        sections: [rdata(data)],
        dataDirectories: new Map([[1, { virtualAddress: RVA, size: 40 }]]),
      });
      const pe = parsePE(buf);

      expect(pe.imports[0].libraryName).toHaveLength(1024);
      expect(isNameTruncated(pe.imports[0].libraryName)).toBe(false);
      expect(pe.imports[0].truncated).toBeUndefined();
      expect(pe.importsTruncated).toBeUndefined();
      expect(computeImphash(pe)).toMatch(/^[0-9a-f]{32}$/);
    });
  });
});
