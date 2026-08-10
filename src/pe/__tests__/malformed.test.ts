/**
 * Hostile / malformed PE regression tests.
 *
 * The parser is fed attacker-supplied binaries by design, so every case here is
 * a crash or hang that a crafted file could previously trigger. Each test carries
 * an explicit timeout: a regression must surface as a failure, not as a hung suite.
 */

import { describe, it, expect } from 'vitest';
import { parsePE } from '../parser';
import { parseSecurityDirectory } from '../authenticode';
import { buildMinimalPE32, buildMinimalPE64, type SectionDef } from './fixtures';
import {
  IMAGE_SCN_MEM_READ,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_MEM_EXECUTE,
} from '../constants';

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

describe('malformed PE handling', () => {
  describe('truncated input', () => {
    it('rejects a file shorter than the DOS header with a clear error', () => {
      const tiny = new ArrayBuffer(16);
      new DataView(tiny).setUint16(0, 0x5a4d, true); // valid MZ, nothing else
      // Must be a useful parse error, not a bare RangeError from getUint32(60).
      expect(() => parsePE(tiny)).toThrow(/too small/i);
    });

    it('rejects a PE whose COFF header runs past EOF', () => {
      const buf = new ArrayBuffer(80);
      const v = new DataView(buf);
      v.setUint16(0, 0x5a4d, true);
      v.setUint32(60, 70, true); // e_lfanew points near the very end
      v.setUint32(70, 0x00004550, true); // "PE\0\0" fits, COFF header does not
      expect(() => parsePE(buf)).toThrow(/truncated/i);
    });
  });

  describe('unbounded header counts', () => {
    it('clamps a bogus numberOfSections instead of throwing', { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE32();
      // 65535 sections claimed, but the buffer holds room for a handful.
      new DataView(buf).setUint16(coffOffsetOf(buf) + 2, 0xffff, true);

      const pe = parsePE(buf);
      expect(pe.sections.length).toBeLessThan(0xffff);
      // Each header is 40 bytes, so the count must fit the buffer.
      expect(pe.sections.length).toBeLessThanOrEqual(Math.ceil(buf.byteLength / 40));
    });

    it('clamps numberOfRvaAndSizes to the 16-entry spec maximum', { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE32();
      const optionalHeaderOffset = coffOffsetOf(buf) + 20;
      new DataView(buf).setUint32(optionalHeaderOffset + 92, 0xffffffff, true);

      const pe = parsePE(buf);
      expect(pe.dataDirectories.length).toBeLessThanOrEqual(16);
    });

    it('clamps numberOfRvaAndSizes on PE32+ too', { timeout: TIMEOUT }, () => {
      const buf = buildMinimalPE64();
      const optionalHeaderOffset = coffOffsetOf(buf) + 20;
      new DataView(buf).setUint32(optionalHeaderOffset + 108, 0xffffffff, true);

      const pe = parsePE(buf);
      expect(pe.dataDirectories.length).toBeLessThanOrEqual(16);
    });
  });

  describe('import table', () => {
    it('survives a thunk RVA that resolves outside every section', { timeout: TIMEOUT }, () => {
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
      for (const [i, ch] of [...'BOGUS.DLL'].entries()) {
        data[0x40 + i] = ch.charCodeAt(0);
      }

      const buf = buildMinimalPE32({
        sections: [dataSection('.rdata', rva, data)],
        dataDirectories: new Map([[1, { virtualAddress: rva, size: 40 }]]),
      });

      expect(() => parsePE(buf)).not.toThrow();
    });
  });

  describe('export table', () => {
    it('does not spin on a 0xFFFFFFFF numberOfNames', { timeout: TIMEOUT }, () => {
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
        sections: [dataSection('.rdata', rva, data)],
        dataDirectories: new Map([[0, { virtualAddress: rva, size: 40 }]]),
      });

      const started = Date.now();
      const pe = parsePE(buf);
      expect(Date.now() - started).toBeLessThan(TIMEOUT);
      // Whatever it recovers, it cannot exceed what the buffer could hold.
      expect(pe.exports.length).toBeLessThan(buf.byteLength);
    });
  });

  describe('authenticode DER', () => {
    it('rejects a 4-byte DER length with the high bit set', { timeout: TIMEOUT }, () => {
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
