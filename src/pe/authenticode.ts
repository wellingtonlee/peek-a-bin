/**
 * Authenticode / Digital Signature Parsing
 * Parses WIN_CERTIFICATE structure and performs minimal DER walking
 * to extract signer information from PKCS#7 SignedData.
 */

import type { DataDirectory } from './types';

export interface CertificateInfo {
  signed: boolean;
  revision: number;
  certificateType: number;
  subject: string | null;
  issuer: string | null;
  notBefore: string | null;
  notAfter: string | null;
  signatureSize: number;
}

// DER tag constants
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTF8_STRING = 0x0C;
const TAG_PRINTABLE_STRING = 0x13;
const TAG_IA5_STRING = 0x16;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_CONTEXT_0 = 0xA0;

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
    const numBytes = lenByte & 0x7F;
    if (numBytes > 4 || pos + numBytes > data.length) return null;
    for (let i = 0; i < numBytes; i++) {
      contentLen = (contentLen << 8) | data[pos + i];
    }
    headerLen = 2 + numBytes;
    pos += numBytes;
  }

  return {
    tag,
    headerLen,
    contentLen,
    contentOffset: offset + headerLen,
    totalLen: headerLen + contentLen,
  };
}

function readDERChildren(data: Uint8Array, start: number, length: number): DERElement[] {
  const children: DERElement[] = [];
  let pos = start;
  const end = start + length;
  while (pos < end) {
    const el = readDERElement(data, pos);
    if (!el || el.totalLen === 0) break;
    children.push(el);
    pos += el.totalLen;
  }
  return children;
}

function readDERString(data: Uint8Array, el: DERElement): string {
  const bytes = data.subarray(el.contentOffset, el.contentOffset + el.contentLen);
  return new TextDecoder().decode(bytes);
}

// OID for CommonName (2.5.4.3)
const OID_CN = new Uint8Array([0x55, 0x04, 0x03]);

function oidEquals(data: Uint8Array, el: DERElement, target: Uint8Array): boolean {
  if (el.contentLen !== target.length) return false;
  for (let i = 0; i < target.length; i++) {
    if (data[el.contentOffset + i] !== target[i]) return false;
  }
  return true;
}

function extractCN(data: Uint8Array, nameElement: DERElement): string | null {
  // Name is a SEQUENCE of SETs of SEQUENCES (RDNs)
  const rdns = readDERChildren(data, nameElement.contentOffset, nameElement.contentLen);
  for (const rdnSet of rdns) {
    if (rdnSet.tag !== TAG_SET) continue;
    const attrs = readDERChildren(data, rdnSet.contentOffset, rdnSet.contentLen);
    for (const attr of attrs) {
      if (attr.tag !== TAG_SEQUENCE) continue;
      const parts = readDERChildren(data, attr.contentOffset, attr.contentLen);
      if (parts.length < 2) continue;
      if (parts[0].tag === TAG_OID && oidEquals(data, parts[0], OID_CN)) {
        const valTag = parts[1].tag;
        if (valTag === TAG_UTF8_STRING || valTag === TAG_PRINTABLE_STRING || valTag === TAG_IA5_STRING) {
          return readDERString(data, parts[1]);
        }
      }
    }
  }
  return null;
}

function parseUTCTime(data: Uint8Array, el: DERElement): string | null {
  const str = readDERString(data, el);
  if (str.length < 12) return null;
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
  if (str.length < 14) return null;
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
    return { signed: true, revision: wRevision, certificateType: wCertificateType,
             subject: null, issuer: null, notBefore: null, notAfter: null, signatureSize: dwLength };
  }

  // Only parse PKCS_SIGNED_DATA (type 0x0002)
  if (wCertificateType !== 0x0002) {
    return { signed: true, revision: wRevision, certificateType: wCertificateType,
             subject: null, issuer: null, notBefore: null, notAfter: null, signatureSize: dwLength };
  }

  // bCertificate starts at offset + 8
  const certData = new Uint8Array(buffer, fileOffset + 8, dwLength - 8);

  try {
    return parsePKCS7(certData, wRevision, wCertificateType, dwLength);
  } catch {
    return { signed: true, revision: wRevision, certificateType: wCertificateType,
             subject: null, issuer: null, notBefore: null, notAfter: null, signatureSize: dwLength };
  }
}

function parsePKCS7(
  data: Uint8Array,
  revision: number,
  certType: number,
  signatureSize: number,
): CertificateInfo {
  const base: CertificateInfo = {
    signed: true, revision, certificateType: certType,
    subject: null, issuer: null, notBefore: null, notAfter: null, signatureSize,
  };

  // PKCS#7 ContentInfo: SEQUENCE { OID, [0] content }
  const contentInfo = readDERElement(data, 0);
  if (!contentInfo || contentInfo.tag !== TAG_SEQUENCE) return base;

  const contentInfoChildren = readDERChildren(data, contentInfo.contentOffset, contentInfo.contentLen);
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

  base.issuer = extractCN(data, issuerEl);
  base.subject = extractCN(data, subjectEl);

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
