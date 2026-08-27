/**
 * Authenticode / Digital Signature Parsing
 * Parses WIN_CERTIFICATE structure and performs minimal DER walking
 * to extract signer information from PKCS#7 SignedData.
 */

import type { DataDirectory } from "./types";

export interface CertificateInfo {
  signed: boolean;
  revision: number;
  certificateType: number;
  /**
   * The signer's **whole Distinguished Name**, rendered `CN=…, O=…, C=…`, or
   * `null` when it could not be read.
   *
   * IT USED TO BE THE CN ALONE, which is a narrower answer wearing a complete
   * one's shape: the row is labelled "Subject", and in X.509 a Subject *is* the
   * DN. Two publishers with the same CN and different O were one string on the
   * screen — and an analyst comparing a signature against a known-good one was
   * comparing the half of the DN that distinguishes least. `subjectCN` is beside
   * it for the common case where the CN is what a reader wants
   * (`peek-a-bin-4q8w`).
   */
  subject: string | null;
  /** The CN attribute alone, or `null` when the DN carries none. */
  subjectCN: string | null;
  /** The issuer's whole DN, on `subject`'s rule. */
  issuer: string | null;
  /** The issuer's CN attribute alone. */
  issuerCN: string | null;
  notBefore: string | null;
  notAfter: string | null;
  signatureSize: number;
  /**
   * How many certificates the PKCS#7 `certificates` SET held.
   *
   * **NOT A VALIDATED CHAIN, and the name says count for that reason.** The SET
   * is unordered and may carry intermediates, cross-certificates or certificates
   * unrelated to this signer; nothing here validates or orders them. What it
   * answers is the question the fields above used to beg: a real Authenticode
   * signature carries the leaf *plus* intermediates, and every field on this
   * object describes `certs[0]` alone with no indication that there were others.
   *
   * `undefined` when the walk did not reach the SET at all — which is a third
   * thing from `0` (an empty SET) and from `1`.
   */
  certificateCount?: number;
}

// DER tag constants
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_OID = 0x06;
const TAG_UTF8_STRING = 0x0c;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_IA5_STRING = 0x16;
const TAG_T61_STRING = 0x14;
const TAG_BMP_STRING = 0x1e;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_CONTEXT_0 = 0xa0;

interface DERElement {
  tag: number;
  headerLen: number;
  contentLen: number;
  contentOffset: number;
  totalLen: number;
}

function readDERElement(data: Uint8Array, offset: number): DERElement | null {
  if (offset >= data.length) return null;
  const tag = data[offset];
  let pos = offset + 1;
  if (pos >= data.length) return null;

  let contentLen = 0;
  let headerLen: number;
  const lenByte = data[pos];
  pos++;

  if (lenByte < 0x80) {
    contentLen = lenByte;
    headerLen = 2;
  } else if (lenByte === 0x80) {
    // Indefinite length — not supported, skip
    return null;
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes > 4 || pos + numBytes > data.length) return null;
    for (let i = 0; i < numBytes; i++) {
      // `*` rather than `<<`: JS bitwise shifts are signed-32, so a 4-byte length
      // with a leading byte >= 0x80 would produce a NEGATIVE contentLen. That makes
      // totalLen negative, and readDERChildren then walks backwards through the
      // buffer and never terminates — a hang no try/catch can recover from.
      contentLen = contentLen * 256 + data[pos + i];
    }
    headerLen = 2 + numBytes;
    pos += numBytes;
  }

  const contentOffset = offset + headerLen;
  // Reject lengths that run past the buffer as well as impossible negatives.
  if (contentLen < 0 || contentOffset + contentLen > data.length) return null;

  return {
    tag,
    headerLen,
    contentLen,
    contentOffset,
    totalLen: headerLen + contentLen,
  };
}

/**
 * The most children one DER container's child list will hold.
 *
 * **THE ARRAY WAS SIZED FROM THE FILE.** A DER header is at least two bytes, so
 * a container whose content is nothing but two-byte elements yields
 * `contentLen / 2` children — and `contentLen` is bounded only by
 * `WIN_CERTIFICATE.dwLength`, which is bounded only by the buffer. Measured at
 * `d8d8a6d`: a 1,048,576-byte file whose security directory covers the whole of
 * it, holding one long-form `SEQUENCE` full of two-byte NULLs, allocated
 * **41.6 MB of heap in one call** — a 40x amplification, in `parsePE`, on the
 * main thread. On a 253 MiB image that is ~10 GB, and `parseSecurityDirectory`'s
 * `try/catch` cannot catch an OOM.
 *
 * DER's own structure saves the *nesting* from multiplying — children partition
 * their parent's content range, so `extractCN`'s three levels sum to the top
 * container's length rather than cubing it — but nothing bounded any single
 * level.
 *
 * 4096 is far above every level X.509 and PKCS#7 actually use: a `SignedData`
 * has ~6 children, its certificates `SET` holds a chain of a handful, an RDN
 * `SEQUENCE` a few attributes. **Not measured against a real signature — no
 * binary on this machine is signed** (all six corpus images report no
 * certificate at all, so `corpus:parserdiff` has nothing to say here), so this
 * cap rests on the format and on documentation, and the evidence for it is
 * weaker than for the others in this census.
 *
 * A cut-short list is not marked. Every caller reads a *fixed field* out of the
 * list by index (`children[1]`, `tbsChildren[idx + 2]`) and falls back to `base`
 * — i.e. `subject: null`, `issuer: null` — when the list is too short, which is
 * the honest narrowing already: `null` means "not read", not "absent".
 */
const MAX_DER_CHILDREN = 4096;

function readDERChildren(data: Uint8Array, start: number, length: number): DERElement[] {
  const children: DERElement[] = [];
  let pos = start;
  const end = start + length;
  while (pos < end && children.length < MAX_DER_CHILDREN) {
    const el = readDERElement(data, pos);
    // <= 0 rather than === 0: a non-advancing element would loop forever.
    if (!el || el.totalLen <= 0) break;
    children.push(el);
    pos += el.totalLen;
  }
  return children;
}

/**
 * A DER string element's text.
 *
 * `tag` is optional and only ever WIDENS what is decoded: without it the bytes
 * are read as UTF-8, which is right for `UTF8String` and for the ASCII subsets
 * (`PrintableString`, `IA5String`) and is what every pre-existing caller wants.
 *
 * The two wide/legacy forms are decoded BY HAND rather than by naming an
 * encoding to `TextDecoder`: `utf-16be` and `t61`/`latin1` are label lookups that
 * a runtime built without full ICU may not have, and a decoder that throws at
 * startup on a signature field is a worse outcome than a few lines of shifting.
 * `UniversalString` (UTF-32BE) is deliberately NOT decoded — it is vanishingly
 * rare in a DN, and `readDNAttributes` skips an attribute it cannot read rather
 * than rendering a hole.
 */
function readDERString(data: Uint8Array, el: DERElement, tag?: number): string {
  const bytes = data.subarray(el.contentOffset, el.contentOffset + el.contentLen);
  if (tag === TAG_BMP_STRING) {
    // UTF-16BE, two bytes per code unit. An odd trailing byte is dropped: half a
    // code unit is not a character.
    let out = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
  }
  if (tag === TAG_T61_STRING) {
    // Treated as Latin-1, which is what T.61 amounts to for the characters a
    // real DN uses and what other PE tools print.
    let out = "";
    for (const byte of bytes) out += String.fromCharCode(byte);
    return out;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * The attribute types a DN is conventionally spelled with, by OID.
 *
 * Anything not here is rendered in dotted-decimal form rather than dropped —
 * skipping it is what made a DN read as its CN, and an unknown attribute is
 * still evidence about the signer. `2.5.4.x` is `X520`; the email address is the
 * one in common use from outside that arc.
 */
const DN_ATTRIBUTE_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "SERIALNUMBER",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "STREET",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "T",
  "2.5.4.42": "GN",
  "2.5.4.97": "OI",
  "1.2.840.113549.1.9.1": "E",
  "0.9.2342.19200300.100.1.25": "DC",
};

/** The CN's OID, needed on its own for {@link CertificateInfo.subjectCN}. */
const OID_CN_TEXT = "2.5.4.3";

/**
 * Decode a DER OBJECT IDENTIFIER to dotted decimal.
 *
 * The first byte packs two arcs (`40 * a + b`, with `a` capped at 2 and `b`
 * unbounded for `a === 2`); the rest are base-128 with the continuation bit set
 * on every byte but the last. Returns null for a truncated or over-long
 * encoding rather than a partial OID, because a partial OID would name a
 * different attribute type.
 */
function decodeOID(data: Uint8Array, el: DERElement): string | null {
  if (el.contentLen === 0) return null;
  const first = data[el.contentOffset];
  const arc1 = Math.min(2, Math.floor(first / 40));
  const parts: number[] = [arc1, arc1 === 2 ? first - 80 : first % 40];
  let value = 0;
  let started = false;
  for (let i = 1; i < el.contentLen; i++) {
    const byte = data[el.contentOffset + i];
    // 2^32 is far above any real arc and keeps this out of float territory.
    if (value > 0xffffff) return null;
    value = value * 128 + (byte & 0x7f);
    started = true;
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
      started = false;
    }
  }
  // A trailing byte with the continuation bit set is an unterminated arc.
  if (started) return null;
  return parts.join(".");
}

/** The DER string types a DN value may legitimately use. */
function isStringTag(tag: number): boolean {
  return (
    tag === TAG_UTF8_STRING ||
    tag === TAG_PRINTABLE_STRING ||
    tag === TAG_IA5_STRING ||
    tag === TAG_T61_STRING ||
    tag === TAG_BMP_STRING
  );
}

/** One attribute of a DN, in the order the encoding lists it. */
interface DNAttribute {
  /** `CN`, `O`, … or the dotted OID when this parser has no name for it. */
  type: string;
  value: string;
}

/**
 * Every attribute of a `Name`, in encoding order.
 *
 * `Name ::= SEQUENCE OF RelativeDistinguishedName`, and an RDN is a `SET OF
 * AttributeTypeAndValue` — a set with more than one member is legal (and rare),
 * so every member is collected rather than the first.
 *
 * An attribute whose OID or value this parser cannot read is SKIPPED rather than
 * rendered as a hole, and that is the one thing this function still narrows
 * silently: a DN is a set of claims and a partial one is not false, whereas an
 * invented `?=?` would be.
 */
function readDNAttributes(data: Uint8Array, nameElement: DERElement): DNAttribute[] {
  const out: DNAttribute[] = [];
  const rdns = readDERChildren(data, nameElement.contentOffset, nameElement.contentLen);
  for (const rdnSet of rdns) {
    if (rdnSet.tag !== TAG_SET) continue;
    for (const attr of readDERChildren(data, rdnSet.contentOffset, rdnSet.contentLen)) {
      if (attr.tag !== TAG_SEQUENCE) continue;
      const parts = readDERChildren(data, attr.contentOffset, attr.contentLen);
      if (parts.length < 2) continue;
      if (parts[0].tag !== TAG_OID || !isStringTag(parts[1].tag)) continue;
      const oid = decodeOID(data, parts[0]);
      if (oid === null) continue;
      out.push({
        type: DN_ATTRIBUTE_NAMES[oid] ?? oid,
        value: readDERString(data, parts[1], parts[1].tag),
      });
    }
  }
  return out;
}

/**
 * A DN rendered `CN=Acme Ltd, O=Acme, C=US`, or null when nothing was readable.
 *
 * Encoding order, not RFC 2253's reversed order: the point of this string is to
 * be compared with what the file contains and with what another tool printed
 * from the same bytes, and reversing it would make the two disagree for no gain.
 * A value containing a comma is left as it is — escaping it would make the string
 * something a reader could not paste back into a search.
 */
function renderDN(attrs: DNAttribute[]): string | null {
  if (attrs.length === 0) return null;
  return attrs.map((a) => `${a.type}=${a.value}`).join(", ");
}

/** The CN attribute of a DN, or null. The FIRST, if a DN carries several. */
function cnOf(attrs: DNAttribute[]): string | null {
  const cn = attrs.find((a) => a.type === DN_ATTRIBUTE_NAMES[OID_CN_TEXT]);
  return cn ? cn.value : null;
}

/** DER times are ASCII digits; anything else would render as "NaN-ab-cd". */
function isDigits(str: string): boolean {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

function parseUTCTime(data: Uint8Array, el: DERElement): string | null {
  const str = readDERString(data, el);
  if (str.length < 12 || !isDigits(str.substring(0, 12))) return null;
  const year = parseInt(str.substring(0, 2), 10);
  const fullYear = year >= 50 ? 1900 + year : 2000 + year;
  const month = str.substring(2, 4);
  const day = str.substring(4, 6);
  const hour = str.substring(6, 8);
  const min = str.substring(8, 10);
  const sec = str.substring(10, 12);
  return `${fullYear}-${month}-${day} ${hour}:${min}:${sec} UTC`;
}

function parseGeneralizedTime(data: Uint8Array, el: DERElement): string | null {
  const str = readDERString(data, el);
  if (str.length < 14 || !isDigits(str.substring(0, 14))) return null;
  const year = str.substring(0, 4);
  const month = str.substring(4, 6);
  const day = str.substring(6, 8);
  const hour = str.substring(8, 10);
  const min = str.substring(10, 12);
  const sec = str.substring(12, 14);
  return `${year}-${month}-${day} ${hour}:${min}:${sec} UTC`;
}

export function parseSecurityDirectory(
  buffer: ArrayBuffer,
  dataDirectories: DataDirectory[],
): CertificateInfo | null {
  // Security directory is at index 4
  if (dataDirectories.length <= 4) return null;
  const secDir = dataDirectories[4];
  if (!secDir || secDir.virtualAddress === 0 || secDir.size === 0) return null;

  // Security directory VA is a raw file offset (not RVA)
  const fileOffset = secDir.virtualAddress;
  if (fileOffset + 8 > buffer.byteLength) return null;

  const view = new DataView(buffer);

  // WIN_CERTIFICATE structure
  const dwLength = view.getUint32(fileOffset, true);
  const wRevision = view.getUint16(fileOffset + 4, true);
  const wCertificateType = view.getUint16(fileOffset + 6, true);

  if (dwLength < 8 || fileOffset + dwLength > buffer.byteLength) {
    return {
      signed: true,
      revision: wRevision,
      certificateType: wCertificateType,
      subject: null,
      subjectCN: null,
      issuer: null,
      issuerCN: null,
      notBefore: null,
      notAfter: null,
      signatureSize: dwLength,
    };
  }

  // Only parse PKCS_SIGNED_DATA (type 0x0002)
  if (wCertificateType !== 0x0002) {
    return {
      signed: true,
      revision: wRevision,
      certificateType: wCertificateType,
      subject: null,
      subjectCN: null,
      issuer: null,
      issuerCN: null,
      notBefore: null,
      notAfter: null,
      signatureSize: dwLength,
    };
  }

  // bCertificate starts at offset + 8
  const certData = new Uint8Array(buffer, fileOffset + 8, dwLength - 8);

  try {
    return parsePKCS7(certData, wRevision, wCertificateType, dwLength);
  } catch {
    return {
      signed: true,
      revision: wRevision,
      certificateType: wCertificateType,
      subject: null,
      subjectCN: null,
      issuer: null,
      issuerCN: null,
      notBefore: null,
      notAfter: null,
      signatureSize: dwLength,
    };
  }
}

function parsePKCS7(
  data: Uint8Array,
  revision: number,
  certType: number,
  signatureSize: number,
): CertificateInfo {
  const base: CertificateInfo = {
    signed: true,
    revision,
    certificateType: certType,
    subject: null,
    subjectCN: null,
    issuer: null,
    issuerCN: null,
    notBefore: null,
    notAfter: null,
    signatureSize,
  };

  // PKCS#7 ContentInfo: SEQUENCE { OID, [0] content }
  const contentInfo = readDERElement(data, 0);
  if (!contentInfo || contentInfo.tag !== TAG_SEQUENCE) return base;

  const contentInfoChildren = readDERChildren(
    data,
    contentInfo.contentOffset,
    contentInfo.contentLen,
  );
  if (contentInfoChildren.length < 2) return base;

  // content is [0] EXPLICIT
  const contentWrapper = contentInfoChildren[1];
  if (contentWrapper.tag !== TAG_CONTEXT_0) return base;

  // SignedData: SEQUENCE { version, digestAlgorithms, contentInfo, [0] certificates, ... }
  const signedData = readDERElement(data, contentWrapper.contentOffset);
  if (!signedData || signedData.tag !== TAG_SEQUENCE) return base;

  const sdChildren = readDERChildren(data, signedData.contentOffset, signedData.contentLen);

  // Find certificates [0] IMPLICIT SET OF Certificate
  let certsElement: DERElement | null = null;
  for (const child of sdChildren) {
    if (child.tag === TAG_CONTEXT_0) {
      certsElement = child;
      break;
    }
  }
  if (!certsElement) return base;

  // First certificate in the set
  const certs = readDERChildren(data, certsElement.contentOffset, certsElement.contentLen);
  // HOW MANY THERE WERE, recorded before the early return below: every field
  // this function goes on to fill describes `certs[0]`, and a real Authenticode
  // signature carries the leaf plus intermediates. Set even for an empty SET,
  // because 0 and "the walk never reached the SET" are different facts.
  base.certificateCount = certs.length;
  if (certs.length === 0) return base;

  const cert = certs[0];
  if (cert.tag !== TAG_SEQUENCE) return base;

  // TBSCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }
  const tbsCert = readDERElement(data, cert.contentOffset);
  if (!tbsCert || tbsCert.tag !== TAG_SEQUENCE) return base;

  const tbsChildren = readDERChildren(data, tbsCert.contentOffset, tbsCert.contentLen);

  // Determine field indices (version field is optional — tagged [0])
  let idx = 0;
  if (tbsChildren.length > 0 && tbsChildren[0].tag === TAG_CONTEXT_0) {
    idx = 1; // skip version
  }

  // serialNumber (idx), signatureAlgorithm (idx+1), issuer (idx+2), validity (idx+3), subject (idx+4)
  if (tbsChildren.length < idx + 5) return base;

  const issuerEl = tbsChildren[idx + 2];
  const validityEl = tbsChildren[idx + 3];
  const subjectEl = tbsChildren[idx + 4];

  const issuerAttrs = readDNAttributes(data, issuerEl);
  const subjectAttrs = readDNAttributes(data, subjectEl);
  base.issuer = renderDN(issuerAttrs);
  base.issuerCN = cnOf(issuerAttrs);
  base.subject = renderDN(subjectAttrs);
  base.subjectCN = cnOf(subjectAttrs);

  // Validity: SEQUENCE { notBefore, notAfter }
  if (validityEl.tag === TAG_SEQUENCE) {
    const validityChildren = readDERChildren(data, validityEl.contentOffset, validityEl.contentLen);
    if (validityChildren.length >= 2) {
      const nb = validityChildren[0];
      const na = validityChildren[1];
      if (nb.tag === TAG_UTC_TIME) base.notBefore = parseUTCTime(data, nb);
      else if (nb.tag === TAG_GENERALIZED_TIME) base.notBefore = parseGeneralizedTime(data, nb);
      if (na.tag === TAG_UTC_TIME) base.notAfter = parseUTCTime(data, na);
      else if (na.tag === TAG_GENERALIZED_TIME) base.notAfter = parseGeneralizedTime(data, na);
    }
  }

  return base;
}
