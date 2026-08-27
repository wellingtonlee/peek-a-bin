/**
 * "The reader could not read it" versus "the file does not have it", for the two
 * data directories `parsePE` reads behind a `catch`.
 *
 * BOTH DIRECTIONS ARE ASSERTED FOR EVERY ROW, and the second is the one that
 * matters here. A predicate that answers `true` for a declared-but-unreadable
 * directory is easy; one that stays `false` for a genuinely unsigned file, for a
 * file with no resources, and — the subtle one — for a resource tree that was
 * merely CUT SHORT is what makes the admission a signal instead of noise on
 * every binary. A fix that simply stopped making any claim at all would pass the
 * first half of each pair and fail the second. (peek-a-bin-wo8g)
 */

import { describe, expect, it } from "vitest";
import { certificateUnreadable, directoryDeclared, resourcesUnreadable } from "../dataDirectories";
import { parsePE } from "../parser";
import { buildMinimalPE32, buildMinimalPE64 } from "./fixtures";

describe("directoryDeclared", () => {
  it("is the three tests parsePE gates its optional readers on", () => {
    expect(directoryDeclared({ virtualAddress: 0x2000, size: 0x40 })).toBe(true);
    expect(directoryDeclared({ virtualAddress: 0, size: 0x40 })).toBe(false);
    expect(directoryDeclared({ virtualAddress: 0x2000, size: 0 })).toBe(false);
    // A table clamped short of this index — `dataDirectoryClamp`'s case — is not
    // a declaration either.
    expect(directoryDeclared(undefined)).toBe(false);
  });
});

describe("certificateUnreadable", () => {
  it("is true for a declared certificate the file does not contain", () => {
    // THE REACHABLE ROUTE, through the real parser: `parseSecurityDirectory`
    // answers null when the `WIN_CERTIFICATE` header does not fit in the file,
    // which is what a truncated or carved sample looks like. Directory 4's
    // address is a FILE OFFSET, not an RVA.
    const buf = buildMinimalPE64({
      dataDirectories: new Map([[4, { virtualAddress: 0x100000, size: 0x200 }]]),
    });
    const pe = parsePE(buf);
    expect(pe.certificate).toBeUndefined();
    expect(certificateUnreadable(pe)).toBe(true);
  });

  it("is false for a certificate that parsed", () => {
    const buf = buildMinimalPE64({ certificate: { subjectCN: "Acme" } });
    const pe = parsePE(buf);
    expect(pe.certificate?.signed).toBe(true);
    expect(certificateUnreadable(pe)).toBe(false);
  });

  it("is false for a file that declares no certificate at all", () => {
    // THE CONTROL THAT CATCHES A PREDICATE FIRING ON EVERY UNSIGNED BINARY,
    // which would put "Unreadable" on essentially every file the tool opens.
    const pe = parsePE(buildMinimalPE32());
    expect(pe.certificate).toBeUndefined();
    expect(certificateUnreadable(pe)).toBe(false);
  });

  it("is false for a malformed certificate the reader still described", () => {
    // `parseSecurityDirectory` reports `signed: true` with null fields for a
    // `dwLength` that overruns the file, so this is NOT the unreadable case even
    // though the certificate is malformed — the panel has something true to
    // print. Keeping the two apart is why the predicate reads `certificate`
    // rather than any notion of "the certificate looked odd".
    const buf = buildMinimalPE64({
      certificate: { subjectCN: "Acme", raw: new Uint8Array([0x01, 0x02, 0x03]) },
    });
    const pe = parsePE(buf);
    expect(pe.certificate?.signed).toBe(true);
    expect(certificateUnreadable(pe)).toBe(false);
  });
});

describe("resourcesUnreadable", () => {
  it("is false for a resource directory that parsed", () => {
    const buf = buildMinimalPE32({
      directories: {
        resources: [
          { id: 16, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1, 2, 3]) }] }] },
        ],
      },
    });
    const pe = parsePE(buf);
    expect(pe.resources?.entries).toHaveLength(1);
    expect(resourcesUnreadable(pe)).toBe(false);
  });

  it("is false for a file with no resource directory", () => {
    const pe = parsePE(buildMinimalPE32());
    expect(pe.resources).toBeUndefined();
    expect(resourcesUnreadable(pe)).toBe(false);
  });

  it("is false for a declared directory whose RVA resolves nowhere", () => {
    // THE ROW THAT KEEPS THE TWO ADMISSIONS APART. This file's resource
    // directory is unreachable, and `parseResourceDirectory` answers a tree
    // flagged `truncated` for it (peek-a-bin-dhcx) rather than throwing — so the
    // pane has a cut-short answer to describe and must NOT claim it knows
    // nothing. Were this `true`, the more specific of the two sentences would be
    // unreachable.
    const buf = buildMinimalPE32({
      dataDirectories: new Map([[2, { virtualAddress: 0x900000, size: 0x40 }]]),
    });
    const pe = parsePE(buf);
    expect(pe.resources).toEqual({ root: [], entries: [], truncated: true });
    expect(resourcesUnreadable(pe)).toBe(false);
  });

  it("is true for a declared directory that produced no tree", () => {
    // NO FIXTURE REACHES THIS THROUGH `parsePE` AND THAT IS THE POINT OF SAYING
    // SO HERE: `parseResourceDirectory` bounds every read on the buffer and
    // recurses to a fixed depth, so nothing on this machine can make it throw,
    // and the state is therefore built directly. The predicate is a guard on
    // `parsePE`'s `catch` — see `resourcesUnreadable`'s docstring — and this row
    // is what proves the guard is wired to the right pair of fields.
    const pe = parsePE(
      buildMinimalPE32({
        directories: {
          resources: [
            { id: 16, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1]) }] }] },
          ],
        },
      }),
    );
    expect(directoryDeclared(pe.dataDirectories[2])).toBe(true);
    expect(resourcesUnreadable({ ...pe, resources: undefined })).toBe(true);
  });
});
