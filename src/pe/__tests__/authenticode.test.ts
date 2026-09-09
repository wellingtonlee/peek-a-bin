/**
 * Authenticode / PKCS#7 DER walking.
 *
 * The DER reader is hand-rolled and runs over bytes an attacker fully controls
 * (the security directory is not covered by the Authenticode hash of the file
 * it is attached to). The bar every case here enforces is the same: no input
 * may throw, hang, or recurse without bound — a malformed signature must come
 * back as "signed, details unknown".
 */

import { describe, expect, it } from "vitest";
import { certificateValidityState, parseSecurityDirectory } from "../authenticode";
import type { DataDirectory } from "../types";

const TIMEOUT = 5000;

// ── DER construction helpers ────────────────────────────────────────────────

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Encode one DER element with the minimal (definite) length form. */
function der(tag: number, content: Uint8Array): Uint8Array {
  let header: number[];
  if (content.length < 0x80) {
    header = [tag, content.length];
  } else if (content.length < 0x100) {
    header = [tag, 0x81, content.length];
  } else {
    header = [tag, 0x82, (content.length >> 8) & 0xff, content.length & 0xff];
  }
  return concat([new Uint8Array(header), content]);
}

const seq = (...children: Uint8Array[]) => der(0x30, concat(children));
const set = (...children: Uint8Array[]) => der(0x31, concat(children));
const ctx0 = (...children: Uint8Array[]) => der(0xa0, concat(children));
const oid = (bytes: number[]) => der(0x06, new Uint8Array(bytes));
const int = (...bytes: number[]) => der(0x02, new Uint8Array(bytes));
const printable = (s: string) => der(0x13, new TextEncoder().encode(s));
const utcTime = (s: string) => der(0x17, new TextEncoder().encode(s));
const generalizedTime = (s: string) => der(0x18, new TextEncoder().encode(s));

const OID_CN = [0x55, 0x04, 0x03];
const OID_SIGNED_DATA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/** The attribute OIDs used below, by the short name the parser prints. */
const DN_OIDS: Record<string, number[]> = {
  CN: OID_CN,
  C: [0x55, 0x04, 0x06],
  L: [0x55, 0x04, 0x07],
  O: [0x55, 0x04, 0x0a],
  OU: [0x55, 0x04, 0x0b],
  /** `pseudonym`, which this parser has no short name for. */
  "2.5.4.65": [0x55, 0x04, 0x41],
};

/**
 * X.501 `Name`: the CN first, then `extra` in order, each as its own RDN.
 *
 * A real signer's DN carries O, L, ST and C beside the CN, and the parser used
 * to drop every one of them (`peek-a-bin-4q8w`), so there was nothing to fail
 * against until this could emit them.
 */
const name = (cn: string, extra: { type: string; value: string }[] = []) =>
  seq(
    set(seq(oid(OID_CN), printable(cn))),
    ...extra.map((a) => set(seq(oid(DN_OIDS[a.type]), printable(a.value)))),
  );

interface CertShape {
  issuer?: string;
  subject?: string;
  /** Attributes emitted after the subject's CN, in order. */
  subjectAttrs?: { type: string; value: string }[];
  notBefore?: Uint8Array;
  notAfter?: Uint8Array;
  /** Omit the optional [0] version field, shifting every later field index. */
  omitVersion?: boolean;
  /** Certificates in the `[0] certificates` SET. Default 1. */
  certificateCount?: number;
}

/** A structurally valid PKCS#7 SignedData wrapping one X.509 certificate. */
function buildPKCS7(shape: CertShape = {}): Uint8Array {
  const {
    issuer = "Test Issuer CA",
    subject = "Test Subject Corp",
    subjectAttrs = [],
    notBefore = utcTime("240101000000Z"),
    notAfter = utcTime("261231235959Z"),
    omitVersion = false,
    certificateCount = 1,
  } = shape;

  const oneCertificate = (subjectCN: string) => {
    const tbs = seq(
      ...(omitVersion ? [] : [ctx0(int(0x02))]), // [0] version v3
      int(0x01, 0x02, 0x03), // serialNumber
      seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])), // signatureAlgorithm
      name(issuer),
      seq(notBefore, notAfter), // validity
      name(subjectCN, subjectAttrs),
      seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])), // subjectPublicKeyInfo
    );
    return seq(tbs, seq(oid([0x2a])), der(0x03, new Uint8Array([0x00, 0xaa])));
  };
  // The extras carry a distinguishing CN, so a reader that took the wrong
  // element of the SET would be visible rather than merely wrong.
  const certificates = concat([
    oneCertificate(subject),
    ...Array.from({ length: Math.max(0, certificateCount - 1) }, (_, i) =>
      oneCertificate(`Intermediate CA ${i + 1}`),
    ),
  ]);

  const signedData = seq(
    int(0x01), // version
    set(), // digestAlgorithms
    seq(oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])), // encapContentInfo
    der(0xa0, certificates), // [0] certificates
    set(), // signerInfos
  );

  return seq(oid(OID_SIGNED_DATA), ctx0(signedData));
}

/** Wrap DER bytes in a WIN_CERTIFICATE and parse them as a security directory. */
function parseCert(
  cert: Uint8Array,
  opts: {
    revision?: number;
    certType?: number;
    dwLength?: number;
    offset?: number;
    /** Directory size, if it should differ from the WIN_CERTIFICATE dwLength. */
    dirSize?: number;
  } = {},
) {
  const offset = opts.offset ?? 0x40;
  const dwLength = opts.dwLength ?? 8 + cert.length;
  const buffer = new ArrayBuffer(offset + 8 + cert.length + 16);
  const view = new DataView(buffer);
  view.setUint32(offset, dwLength, true);
  view.setUint16(offset + 4, opts.revision ?? 0x0200, true);
  view.setUint16(offset + 6, opts.certType ?? 0x0002, true);
  new Uint8Array(buffer).set(cert, offset + 8);

  const dirs: DataDirectory[] = Array.from({ length: 16 }, () => ({
    virtualAddress: 0,
    size: 0,
  }));
  dirs[4] = { virtualAddress: offset, size: opts.dirSize ?? dwLength };
  return parseSecurityDirectory(buffer, dirs);
}

// ── Happy path ──────────────────────────────────────────────────────────────

describe("parseSecurityDirectory", () => {
  it("extracts subject, issuer and validity from a well-formed signature", () => {
    const info = parseCert(buildPKCS7());
    // `subject` and `issuer` are the WHOLE DN now — for a CN-only name that is
    // `CN=<the CN>`, and `subjectCN`/`issuerCN` carry the CN on its own. The
    // `toEqual` is exhaustive so a field added without a decision fails here.
    expect(info).toEqual({
      signed: true,
      revision: 0x0200,
      certificateType: 0x0002,
      subject: "CN=Test Subject Corp",
      subjectCN: "Test Subject Corp",
      issuer: "CN=Test Issuer CA",
      issuerCN: "Test Issuer CA",
      notBefore: "2024-01-01 00:00:00 UTC",
      notAfter: "2026-12-31 23:59:59 UTC",
      notAfterMs: Date.UTC(2026, 11, 31, 23, 59, 59),
      signatureSize: expect.any(Number),
      certificateCount: 1,
    });
  });

  it("renders every attribute of a Distinguished Name, in encoding order", () => {
    // THE DEFECT: `extractCN` walked the RDNSequence for the CN and dropped O,
    // OU, L, ST and C — so two publishers with the same CN and a different O
    // were one string on the page, and the half of the DN that distinguishes
    // least was the half that survived. Encoding order, not RFC 2253's reversed
    // order: this string is for comparing against the file and against what
    // another tool printed from the same bytes (peek-a-bin-4q8w).
    const info = parseCert(
      buildPKCS7({
        subjectAttrs: [
          { type: "O", value: "Acme Holdings" },
          { type: "L", value: "Springfield" },
          { type: "C", value: "US" },
        ],
      }),
    );
    expect(info?.subject).toBe("CN=Test Subject Corp, O=Acme Holdings, L=Springfield, C=US");
    // The CN is still available on its own, so nothing that wanted the short
    // form has to parse the DN back apart.
    expect(info?.subjectCN).toBe("Test Subject Corp");
    // The issuer is untouched by the subject's attributes — the two DNs are read
    // from different TBSCertificate slots and a shared walk would prove nothing.
    expect(info?.issuer).toBe("CN=Test Issuer CA");
  });

  it("names an attribute type it knows and spells the OID of one it does not", () => {
    // An attribute this parser has no short name for is rendered in dotted
    // decimal rather than SKIPPED, which is the difference between a partial DN
    // and a silently narrowed one. 2.5.4.65 is `pseudonym`.
    const info = parseCert(
      buildPKCS7({
        subjectAttrs: [
          { type: "OU", value: "Release Engineering" },
          { type: "2.5.4.65", value: "acme-build" },
        ],
      }),
    );
    expect(info?.subject).toBe("CN=Test Subject Corp, OU=Release Engineering, 2.5.4.65=acme-build");
  });

  it("decodes the wide and legacy string forms a DN value may use", () => {
    // BMPString (UTF-16BE) and T61String are decoded BY HAND rather than by
    // naming an encoding to `TextDecoder`: `utf-16be` and `t61` are label
    // lookups a runtime without full ICU may not have, and a decoder that
    // throws on a signature field is worse than a few lines of shifting. Both
    // are real in the wild — Microsoft's own timestamp certificates carry
    // BMPStrings.
    const bmp = (text: string) => {
      const out = new Uint8Array(text.length * 2);
      for (let i = 0; i < text.length; i++) {
        out[i * 2] = text.charCodeAt(i) >> 8;
        out[i * 2 + 1] = text.charCodeAt(i) & 0xff;
      }
      return der(0x1e, out);
    };
    const t61 = (bytes: number[]) => der(0x14, new Uint8Array(bytes));

    const subjectName = seq(
      set(seq(oid(OID_CN), bmp("Ünïcode Ltd"))),
      // 0xE9 is `é` in Latin-1, which is what T.61 amounts to for the characters
      // a real DN uses.
      set(seq(oid(DN_OIDS.O), t61([0x41, 0x63, 0x6d, 0xe9]))),
    );
    const tbs = seq(
      ctx0(int(0x02)),
      int(0x01),
      seq(oid([0x2a])),
      name("Test Issuer CA"),
      seq(utcTime("240101000000Z"), utcTime("261231235959Z")),
      subjectName,
      seq(oid([0x2a])),
    );
    const info = parseCert(
      seq(
        oid(OID_SIGNED_DATA),
        ctx0(seq(int(0x01), set(), seq(oid([0x2a])), ctx0(seq(tbs, seq(oid([0x2a])))), set())),
      ),
    );

    expect(info?.subjectCN).toBe("Ünïcode Ltd");
    expect(info?.subject).toBe("CN=Ünïcode Ltd, O=Acmé");
  });

  it("skips an attribute whose OID does not terminate, keeping the rest of the DN", () => {
    // A trailing byte with the continuation bit set is an unterminated arc, and
    // a PARTIAL OID names a different attribute type — so the attribute is
    // dropped rather than guessed at. The rest of the DN must survive, which is
    // the difference between a partial answer and a lost one.
    const subjectName = seq(
      set(seq(oid(OID_CN), printable("Test Subject Corp"))),
      set(seq(der(0x06, new Uint8Array([0x55, 0x04, 0x80])), printable("dropped"))),
      set(seq(oid(DN_OIDS.C), printable("US"))),
    );
    const tbs = seq(
      ctx0(int(0x02)),
      int(0x01),
      seq(oid([0x2a])),
      name("Test Issuer CA"),
      seq(utcTime("240101000000Z"), utcTime("261231235959Z")),
      subjectName,
      seq(oid([0x2a])),
    );
    const info = parseCert(
      seq(
        oid(OID_SIGNED_DATA),
        ctx0(seq(int(0x01), set(), seq(oid([0x2a])), ctx0(seq(tbs, seq(oid([0x2a])))), set())),
      ),
    );

    expect(info?.subject).toBe("CN=Test Subject Corp, C=US");
    expect(info?.subject).not.toContain("dropped");
  });

  it("counts the certificates in the SET, and describes the first", () => {
    // A real Authenticode signature carries the leaf plus intermediates. Every
    // field on `CertificateInfo` describes `certs[0]`, and with no count the
    // object implied there was only one.
    const info = parseCert(buildPKCS7({ certificateCount: 3 }));
    expect(info?.certificateCount).toBe(3);
    // The FIRST is still the one reported — the fixture gives the others a
    // distinguishing CN, so taking the wrong element would show up here.
    expect(info?.subjectCN).toBe("Test Subject Corp");
    expect(info?.subjectCN).not.toContain("Intermediate");
  });

  it("reports a single-certificate signature as one, not as absent", () => {
    // The control for the row above: `undefined` means the walk never reached
    // the SET, `0` an empty SET and `1` an ordinary single certificate, and the
    // panel shows the row only above 1. Collapsing them would make the count
    // unreadable.
    expect(parseCert(buildPKCS7())?.certificateCount).toBe(1);
  });

  it("reads GeneralizedTime validity fields", () => {
    const info = parseCert(
      buildPKCS7({
        notBefore: generalizedTime("20240101000000Z"),
        notAfter: generalizedTime("20991231235959Z"),
      }),
    );
    expect(info?.notBefore).toBe("2024-01-01 00:00:00 UTC");
    expect(info?.notAfter).toBe("2099-12-31 23:59:59 UTC");
    // The epoch comes off the OTHER DER time tag by the same route, so both
    // spellings of a validity date are comparable. Hand-computed literal beside
    // the arithmetic, so a wrong month-index would fail rather than agree with
    // itself.
    expect(info?.notAfterMs).toBe(4102444799000);
    expect(info?.notAfterMs).toBe(Date.UTC(2099, 11, 31, 23, 59, 59));
  });

  it("applies the UTCTime 50-year pivot", () => {
    const info = parseCert(
      buildPKCS7({ notBefore: utcTime("490101000000Z"), notAfter: utcTime("500101000000Z") }),
    );
    expect(info?.notBefore).toBe("2049-01-01 00:00:00 UTC");
    expect(info?.notAfter).toBe("1950-01-01 00:00:00 UTC");
    // AND THE EPOCH TAKES THE SAME PIVOT, from the same `fullYear`. Hand-computed:
    // 1950-01-01T00:00:00Z is 20 years before the epoch, i.e. negative. If the
    // two halves ever read different years, this is the row that says so —
    // `notAfter` would print 1950 while the panel compared 2050 against now and
    // called a 76-year-expired certificate current.
    expect(info?.notAfterMs).toBe(-631152000000);
    expect(info?.notAfterMs).toBe(Date.UTC(1950, 0, 1, 0, 0, 0));
  });

  it("shifts field indices when the optional version field is absent", () => {
    const info = parseCert(buildPKCS7({ omitVersion: true }));
    // Without [0] version the parser must not read issuer/subject one slot over.
    expect(info?.subjectCN).toBe("Test Subject Corp");
    expect(info?.issuerCN).toBe("Test Issuer CA");
  });

  it("returns null when there is no security directory", () => {
    const dirs: DataDirectory[] = Array.from({ length: 16 }, () => ({
      virtualAddress: 0,
      size: 0,
    }));
    expect(parseSecurityDirectory(new ArrayBuffer(0x100), dirs)).toBeNull();
    expect(parseSecurityDirectory(new ArrayBuffer(0x100), [])).toBeNull();
    expect(parseSecurityDirectory(new ArrayBuffer(0x100), dirs.slice(0, 4))).toBeNull();
  });
});

// ── WIN_CERTIFICATE header abuse ────────────────────────────────────────────

describe("WIN_CERTIFICATE header", () => {
  it("reports an unparseable signature rather than null when dwLength is nonsense", () => {
    // The directory still declares a signature; only the WIN_CERTIFICATE's own
    // length field is nonsense, so the result must be a "signed, unknown" record.
    for (const dwLength of [0, 1, 7, 0xffffffff, 0x7fffffff]) {
      const info = parseCert(buildPKCS7(), { dwLength, dirSize: 0x200 });
      expect(info?.signed, `dwLength=${dwLength}`).toBe(true);
      expect(info?.subject).toBeNull();
    }
  });

  it("does not parse non-PKCS7 certificate types", () => {
    for (const certType of [0x0001, 0x0003, 0x0004, 0xffff]) {
      const info = parseCert(buildPKCS7(), { certType });
      expect(info?.certificateType).toBe(certType);
      expect(info?.subject).toBeNull();
    }
  });

  it("returns null when the directory offset lies past the end of the file", () => {
    const dirs: DataDirectory[] = Array.from({ length: 16 }, () => ({
      virtualAddress: 0,
      size: 0,
    }));
    dirs[4] = { virtualAddress: 0xfffffff0, size: 0x100 };
    expect(parseSecurityDirectory(new ArrayBuffer(0x100), dirs)).toBeNull();

    dirs[4] = { virtualAddress: 0xfc, size: 0x100 }; // header itself runs off the end
    expect(parseSecurityDirectory(new ArrayBuffer(0x100), dirs)).toBeNull();
  });

  it("handles an empty bCertificate", () => {
    const info = parseCert(new Uint8Array(0), { dwLength: 8 });
    expect(info?.signed).toBe(true);
    expect(info?.subject).toBeNull();
  });
});

// ── Adversarial DER ─────────────────────────────────────────────────────────

describe("adversarial DER", () => {
  const expectDegrades = (cert: Uint8Array, label: string) => {
    const started = Date.now();
    let info: ReturnType<typeof parseCert>;
    expect(() => {
      info = parseCert(cert);
    }, label).not.toThrow();
    expect(Date.now() - started, `${label} took too long`).toBeLessThan(TIMEOUT);
    expect(info!.signed, label).toBe(true);
  };

  it("survives truncation at every prefix length", { timeout: 20000 }, () => {
    // Every cut point exercises a different half-read header, length or content.
    const full = buildPKCS7();
    for (let len = 0; len < full.length; len++) {
      expectDegrades(full.subarray(0, len), `truncated to ${len}`);
    }
  });

  it("rejects the indefinite length form instead of guessing at an end", () => {
    // BER indefinite length (0x80) has no length to bound the walk with.
    expectDegrades(new Uint8Array([0x30, 0x80, 0x06, 0x01, 0x2a, 0x00, 0x00]), "indefinite");
    expectDegrades(
      new Uint8Array([0x30, 0x06, 0x30, 0x80, 0x06, 0x01, 0x2a, 0x00]),
      "nested indefinite",
    );
  });

  it("rejects long-form lengths that exceed the buffer", () => {
    const cases: [string, number[]][] = [
      ["1-byte 0xFF", [0x30, 0x81, 0xff]],
      ["2-byte 0xFFFF", [0x30, 0x82, 0xff, 0xff]],
      ["3-byte 0xFFFFFF", [0x30, 0x83, 0xff, 0xff, 0xff]],
      ["4-byte 0xFFFFFFFF", [0x30, 0x84, 0xff, 0xff, 0xff, 0xff]],
      // 0x80000000 is the classic signed-shift repro: it used to come out
      // negative, driving the child walk backwards forever.
      ["4-byte 0x80000000", [0x30, 0x84, 0x80, 0x00, 0x00, 0x00]],
      ["5-byte length", [0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]],
      ["0x7F-byte length", [0x30, 0xff, 0x01]],
      ["length bytes truncated", [0x30, 0x84, 0x00]],
    ];
    for (const [label, bytes] of cases) {
      expectDegrades(new Uint8Array(bytes), label);
      // Same poison one level down, inside a well-formed parent: this is the
      // shape that reaches readDERChildren's `pos += totalLen`.
      expectDegrades(
        concat([new Uint8Array([0x30, bytes.length]), new Uint8Array(bytes)]),
        `nested ${label}`,
      );
    }
  });

  it("does not recurse without bound on deeply nested constructed types", {
    timeout: TIMEOUT,
  }, () => {
    // 50k nested SEQUENCEs. A recursive-descent walker blows the stack here;
    // this one must simply fail to find what it is looking for.
    const depth = 50000;
    const bytes = new Uint8Array(depth * 4 + 8);
    let at = 0;
    for (let i = 0; i < depth; i++) {
      // Each level: SEQUENCE with a 2-byte length covering everything after it.
      const remaining = (depth - i - 1) * 4 + 4;
      bytes[at] = 0x30;
      bytes[at + 1] = 0x82;
      bytes[at + 2] = (remaining >> 8) & 0xff;
      bytes[at + 3] = remaining & 0xff;
      at += 4;
    }
    expectDegrades(bytes.subarray(0, at + 4), "deep nesting");
  });

  it("handles zero-length and empty constructed elements", () => {
    expectDegrades(new Uint8Array([0x30, 0x00]), "empty SEQUENCE");
    expectDegrades(new Uint8Array([0x30, 0x02, 0x30, 0x00]), "SEQUENCE of empty SEQUENCE");
    expectDegrades(new Uint8Array([0x31, 0x00]), "empty SET");
    expectDegrades(new Uint8Array([0x06, 0x00]), "empty OID");
    expectDegrades(new Uint8Array([0xa0, 0x00]), "empty [0]");
    // A run of empty elements: each must still advance the child walk by 2.
    expectDegrades(
      concat([new Uint8Array([0x30, 0x40]), new Uint8Array(0x40)]),
      "zero-tag padding",
    );
  });

  it("handles a lone tag byte and a lone length byte", () => {
    expectDegrades(new Uint8Array([0x30]), "tag only");
    expectDegrades(new Uint8Array([0x30, 0x02, 0x30]), "child tag only");
    expectDegrades(new Uint8Array([0x00]), "zero byte");
    expectDegrades(new Uint8Array([0xff, 0xff]), "reserved tag");
  });

  it("does not mistake a CN attribute with a missing value for a name", () => {
    // parts.length < 2 — an RDN holding only the OID.
    const cert = seq(
      oid(OID_SIGNED_DATA),
      ctx0(
        seq(
          int(0x01),
          set(),
          seq(),
          ctx0(
            seq(
              seq(
                ctx0(int(0x02)),
                int(0x01),
                seq(),
                seq(set(seq(oid(OID_CN)))),
                seq(),
                seq(set(seq(oid(OID_CN)))),
                seq(),
              ),
            ),
          ),
        ),
      ),
    );
    const info = parseCert(cert);
    expect(info?.subject).toBeNull();
    expect(info?.issuer).toBeNull();
  });

  it("rejects non-numeric time fields instead of emitting NaN", () => {
    const info = parseCert(
      buildPKCS7({
        notBefore: utcTime("ABCDEFGHIJKLZ"),
        notAfter: generalizedTime("not-a-timestamp!"),
      }),
    );
    expect(info?.notBefore).toBeNull();
    expect(info?.notAfter).toBeNull();
  });

  it("rejects time strings that are too short", () => {
    const info = parseCert(
      buildPKCS7({ notBefore: utcTime("2401"), notAfter: generalizedTime("20240101") }),
    );
    expect(info?.notBefore).toBeNull();
    expect(info?.notAfter).toBeNull();
  });

  it("tolerates invalid UTF-8 in a CN", () => {
    const badCN = der(0x0c, new Uint8Array([0xff, 0xfe, 0x41, 0x80]));
    const cert = seq(
      oid(OID_SIGNED_DATA),
      ctx0(
        seq(
          int(0x01),
          set(),
          seq(),
          ctx0(
            seq(
              seq(
                ctx0(int(0x02)),
                int(0x01),
                seq(),
                seq(set(seq(oid(OID_CN), badCN))),
                seq(utcTime("240101000000Z"), utcTime("261231235959Z")),
                seq(set(seq(oid(OID_CN), badCN))),
                seq(),
              ),
            ),
          ),
        ),
      ),
    );
    const info = parseCert(cert);
    // Replacement characters are fine; a throw is not.
    expect(typeof info?.subject).toBe("string");
  });
});

// ── Fuzzing ─────────────────────────────────────────────────────────────────

/** xorshift32 — deterministic, so a failure is always reproducible. */
function makeRandom(seed: number) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
}

describe("DER fuzzing", () => {
  it("never throws or hangs on random bytes", { timeout: 20000 }, () => {
    const rand = makeRandom(0xc0ffee);
    const started = Date.now();
    for (let iter = 0; iter < 2000; iter++) {
      const len = rand() % 512;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = rand() & 0xff;
      expect(() => parseCert(bytes), `iteration ${iter}`).not.toThrow();
    }
    expect(Date.now() - started).toBeLessThan(20000);
  });

  it("never throws on random bytes biased toward DER tags and long lengths", {
    timeout: 20000,
  }, () => {
    // Uniform random bytes rarely produce a parseable header. Biasing toward
    // real tags and long-form length bytes is what actually reaches the deeper
    // walks, where the length arithmetic lives.
    const interesting = [
      0x30, 0x31, 0xa0, 0x06, 0x13, 0x0c, 0x17, 0x18, 0x02, 0x03, 0x80, 0x81, 0x82, 0x83, 0x84,
      0x85, 0xff, 0x00, 0x7f,
    ];
    const rand = makeRandom(0x5eed);
    for (let iter = 0; iter < 2000; iter++) {
      const len = 2 + (rand() % 128);
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = rand() % 4 === 0 ? rand() & 0xff : interesting[rand() % interesting.length];
      }
      expect(() => parseCert(bytes), `iteration ${iter}`).not.toThrow();
    }
  });

  it("never throws when single bytes of a valid signature are corrupted", {
    timeout: 20000,
  }, () => {
    const full = buildPKCS7();
    const poisons = [0x00, 0x01, 0x30, 0x80, 0x81, 0x84, 0x85, 0xa0, 0xff];
    for (let i = 0; i < full.length; i++) {
      for (const poison of poisons) {
        const mutated = full.slice();
        mutated[i] = poison;
        expect(() => parseCert(mutated), `byte ${i} = 0x${poison.toString(16)}`).not.toThrow();
      }
    }
  });
});

/**
 * `notAfterMs` AND `certificateValidityState`.
 *
 * The panel printed "Valid Until" and compared it against nothing, so an expired
 * certificate rendered exactly like a live one. The comparison needs an instant,
 * and the ONE place allowed to turn DER bytes into one is the parser — a view
 * that scanned the formatted string back apart would be a second declaration of
 * the DER time format, `UTCTime`'s two-digit pivot included, and the two copies
 * would drift into a *confident* wrong expiry claim with nothing cross-checking
 * them. (`peek-a-bin-v3uh.9`)
 *
 * `nowMs` is a parameter for a measured reason: `vi.useFakeTimers()` deadlocks
 * `waitFor` and `userEvent` in this repo, and a suite pinning "expired" against
 * the real clock flips arm on a date. Every arm below is reached with an
 * explicit instant and the tests are stable forever.
 */
describe("certificate expiry", () => {
  /** 2026-12-31 23:59:59 UTC, the node fixture's default `notAfter`. */
  const NOT_AFTER = Date.UTC(2026, 11, 31, 23, 59, 59);

  it("reports the notAfter epoch beside the text, from one reading of the bytes", () => {
    const info = parseCert(buildPKCS7({ notAfter: utcTime("261231235959Z") }));
    expect(info?.notAfter).toBe("2026-12-31 23:59:59 UTC");
    // Hand-computed: 1798761599000. The literal is beside the arithmetic so a
    // month-index or second-vs-millisecond slip fails rather than agreeing with
    // its own restatement.
    expect(info?.notAfterMs).toBe(1798761599000);
    expect(info?.notAfterMs).toBe(NOT_AFTER);
  });

  it("calls a certificate expired only after the last second it is valid", () => {
    const cert = { notAfterMs: NOT_AFTER };
    // `notAfter` names the LAST second of validity, so the certificate is
    // current throughout it and expired one millisecond later. The boundary is
    // asserted from both sides: a `>=` here would call a live certificate dead
    // for its final second, and no other row could see the difference.
    expect(certificateValidityState(cert, NOT_AFTER - 1)).toBe("current");
    expect(certificateValidityState(cert, NOT_AFTER)).toBe("current");
    expect(certificateValidityState(cert, NOT_AFTER + 1)).toBe("expired");
  });

  it("reports a long-past certificate expired and a far-future one current", () => {
    const past = parseCert(buildPKCS7({ notAfter: utcTime("000101000000Z") }));
    const future = parseCert(buildPKCS7({ notAfter: utcTime("491231235959Z") }));
    expect(past?.notAfterMs).toBe(Date.UTC(2000, 0, 1, 0, 0, 0));
    expect(future?.notAfterMs).toBe(Date.UTC(2049, 11, 31, 23, 59, 59));
    // Against the REAL clock, which is safe for exactly these two dates: the
    // year 2000 is behind every machine that can run this and 2049 is the last
    // year `UTCTime`'s pivot puts in the future.
    const now = Date.now();
    expect(certificateValidityState(past as { notAfterMs: number | null }, now)).toBe("expired");
    expect(certificateValidityState(future as { notAfterMs: number | null }, now)).toBe("current");
  });

  /**
   * THE THIRD ARM, AND THE REASON THERE ARE THREE.
   *
   * Folding an unreadable date in with `"current"` makes the tool assert a
   * validity it has no evidence for — the exact class this bead closes one level
   * up, where a green pill asserted a signature nothing verified. `"unknown"`
   * renders NEITHER claim.
   */
  it("answers unknown, never current, for a date it could not read", () => {
    expect(certificateValidityState({ notAfterMs: null }, Date.now())).toBe("unknown");
    // And the parser produces that state for real bytes: a validity field the
    // walk rejected outright leaves both halves null.
    const info = parseCert(buildPKCS7({ notAfter: utcTime("nonsense!") }));
    expect(info?.notAfter).toBeNull();
    expect(info?.notAfterMs).toBeNull();
    expect(certificateValidityState(info as { notAfterMs: number | null }, Date.now())).toBe(
      "unknown",
    );
  });

  it("refuses an epoch for digits that do not name a real instant, and still prints them", () => {
    // `isDigits` promises ASCII digits and nothing more, so a thirteenth month
    // reaches the formatter. `Date.UTC` would ROLL IT OVER to 2025-01-01 — an
    // epoch silently disagreeing with the text printed beside it, which is worse
    // than no epoch, because it is a confident answer about the wrong instant.
    const info = parseCert(buildPKCS7({ notAfter: utcTime("241301000000Z") }));
    expect(info?.notAfter).toBe("2024-13-01 00:00:00 UTC");
    expect(info?.notAfterMs).toBeNull();
    // The rolled-over instant is in the past, so a parser without the round-trip
    // check would have called this expired — a claim about a date that denotes
    // nothing.
    expect(Date.UTC(2024, 12, 1, 0, 0, 0)).toBeLessThan(Date.now());
    expect(certificateValidityState(info as { notAfterMs: number | null }, Date.now())).toBe(
      "unknown",
    );
  });

  it("refuses a day the month does not have, and a leap second", () => {
    const feb30 = parseCert(buildPKCS7({ notAfter: utcTime("240230000000Z") }));
    expect(feb30?.notAfter).toBe("2024-02-30 00:00:00 UTC");
    expect(feb30?.notAfterMs).toBeNull();
    // 2016-12-31T23:59:60Z was a real leap second and is not an instant the Date
    // model holds, so nothing here can compare it.
    const leap = parseCert(buildPKCS7({ notAfter: generalizedTime("20161231235960Z") }));
    expect(leap?.notAfter).toBe("2016-12-31 23:59:60 UTC");
    expect(leap?.notAfterMs).toBeNull();
  });

  it("accepts a leap day the month does have", () => {
    // The control for the two rows above: the round-trip check must reject an
    // impossible date without rejecting an unusual valid one.
    const info = parseCert(buildPKCS7({ notAfter: utcTime("240229120000Z") }));
    expect(info?.notAfter).toBe("2024-02-29 12:00:00 UTC");
    expect(info?.notAfterMs).toBe(Date.UTC(2024, 1, 29, 12, 0, 0));
  });

  it("gives every unparsable-certificate arm a null epoch rather than omitting it", () => {
    // The four early returns in `parseSecurityDirectory` and `parsePKCS7`'s
    // `base` all answer "signed, details unknown", and `notAfterMs` must be
    // present-and-null there like `notAfter` is — an absent field would make
    // `certificateValidityState` read `undefined` and, being neither null nor a
    // number, compare as `NaN`: "current".
    const badType = parseCert(new Uint8Array([1, 2, 3, 4]), { certType: 0x0001 });
    expect(badType?.notAfterMs).toBeNull();
    expect(certificateValidityState(badType as { notAfterMs: number | null }, 0)).toBe("unknown");
    const shortHeader = parseCert(new Uint8Array([1, 2, 3, 4]), { dwLength: 4 });
    expect(shortHeader?.notAfterMs).toBeNull();
    const notDER = parseCert(new Uint8Array([0xff, 0xff, 0xff]));
    expect(notDER?.notAfterMs).toBeNull();
  });
});
