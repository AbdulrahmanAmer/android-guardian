// Pure-JS APK inspection: signing certificate SHA-1 (v2/v3 signing block, v1 fallback).
// No Java, no apksigner. Enough to match certificates against the stalkerware list.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const SIG_BLOCK_MAGIC = 'APK Sig Block 42';
const V2_ID = 0x7109871a;
const V3_ID = 0xf05368c0;
const V31_ID = 0x1b93ad61;

function findEocd(buf) {
  const min = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  return -1;
}

function readLenPrefixed(buf, offset) {
  const len = buf.readUInt32LE(offset);
  return { data: buf.subarray(offset + 4, offset + 4 + len), next: offset + 4 + len };
}

function certFromSigningBlock(buf, cdOffset) {
  if (cdOffset < 32) return null;
  const magic = buf.toString('latin1', cdOffset - 16, cdOffset);
  if (magic !== SIG_BLOCK_MAGIC) return null;
  const size = Number(buf.readBigUInt64LE(cdOffset - 24));
  const start = cdOffset - size - 8;
  if (start < 0) return null;
  let pos = start + 8; // skip leading size
  const end = cdOffset - 24;
  const found = {};
  while (pos + 12 <= end) {
    const len = Number(buf.readBigUInt64LE(pos));
    const id = buf.readUInt32LE(pos + 8);
    const value = buf.subarray(pos + 12, pos + 8 + len);
    if (id === V2_ID || id === V3_ID || id === V31_ID) found[id] = value;
    pos += 8 + len;
  }
  const block = found[V3_ID] || found[V31_ID] || found[V2_ID];
  if (!block) return null;
  // signers (len) -> signer (len) -> signed data (len) -> digests (len) , certificates (len) -> cert (len)
  const signers = readLenPrefixed(block, 0).data;
  const signer = readLenPrefixed(signers, 0).data;
  const signed = readLenPrefixed(signer, 0).data;
  const afterDigests = readLenPrefixed(signed, 0).next;
  const certs = readLenPrefixed(signed, afterDigests).data;
  const cert = readLenPrefixed(certs, 0).data;
  return cert.length ? Buffer.from(cert) : null;
}

// --- minimal DER walker for the v1 (JAR) signature ---
function derTlv(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr = 2 + n;
  }
  return { tag, len, start: pos + hdr, end: pos + hdr + len, raw: buf.subarray(pos, pos + hdr + len) };
}

function certFromPkcs7(der) {
  // ContentInfo SEQ { OID, [0] { SignedData SEQ { INTEGER, SET, SEQ, [0] certs ... } } }
  try {
    const ci = derTlv(der, 0);
    let p = ci.start;
    const oid = derTlv(der, p); p = oid.end;
    const ctx = derTlv(der, p);
    const sd = derTlv(der, ctx.start);
    p = sd.start;
    const ver = derTlv(der, p); p = ver.end;
    const algs = derTlv(der, p); p = algs.end;
    const content = derTlv(der, p); p = content.end;
    const certs = derTlv(der, p);
    if (certs.tag !== 0xa0) return null;
    const first = derTlv(der, certs.start);
    return Buffer.from(first.raw);
  } catch {
    return null;
  }
}

function certFromV1(buf, cdOffset, cdCount) {
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(pos) !== CD_SIG) break;
    const method = buf.readUInt16LE(pos + 10);
    const compSize = buf.readUInt32LE(pos + 20);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const lfhOffset = buf.readUInt32LE(pos + 42);
    const name = buf.toString('utf8', pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;
    if (!/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(name)) continue;
    if (buf.readUInt32LE(lfhOffset) !== LFH_SIG) continue;
    const lNameLen = buf.readUInt16LE(lfhOffset + 26);
    const lExtraLen = buf.readUInt16LE(lfhOffset + 28);
    const dataStart = lfhOffset + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(dataStart, dataStart + compSize);
    const der = method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
    const cert = certFromPkcs7(der);
    if (cert) return cert;
  }
  return null;
}

/** Returns { sha1, sha256 } of the first signing certificate, or null if unreadable. */
export function apkCertificate(file) {
  const buf = readFileSync(file);
  const eocd = findEocd(buf);
  if (eocd < 0) return null;
  const cdCount = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  let cert = null;
  try { cert = certFromSigningBlock(buf, cdOffset); } catch { cert = null; }
  if (!cert) cert = certFromV1(buf, cdOffset, cdCount);
  if (!cert) return null;
  return {
    sha1: createHash('sha1').update(cert).digest('hex').toUpperCase(),
    sha256: createHash('sha256').update(cert).digest('hex').toUpperCase(),
  };
}

export function fileSha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}
