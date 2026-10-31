// Pure-JS APK inspection: signing certificates (v3.1 / v3 / v2 signing block, v1 JAR fallback).
// No Java, no apksigner. Enough to match certificates against the stalkerware list.
//
// Every read is bounds-checked: a malformed or hostile APK produces an ApkFormatError, never a
// RangeError from reading past the buffer and never a huge allocation.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const SIG_BLOCK_MAGIC = 'APK Sig Block 42';
export const BLOCK_IDS = {
  V2: 0x7109871a,
  V3: 0xf05368c0,
  V31: 0x1b93ad61,
  PADDING: 0x42726577, // "verity padding" pair added by apksigner to align the block to 4096 bytes
};
const SCHEME_BY_ID = { [BLOCK_IDS.V3]: 'v3', [BLOCK_IDS.V2]: 'v2', [BLOCK_IDS.V31]: 'v3.1' };
// Order in which schemes contribute certificates. v3 and v2 carry the app's original signer
// (with v3.1 rotation the new key lives only in v3.1), so they come first; v1 last.
const SCHEME_ORDER = [BLOCK_IDS.V3, BLOCK_IDS.V2, BLOCK_IDS.V31];
const MAX_V1_SIGNATURE_BYTES = 4 * 1024 * 1024; // a .RSA file is a few KB; refuse zip bombs

export class ApkFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ApkFormatError';
  }
}

function fail(msg) {
  throw new ApkFormatError(msg);
}

// --- bounds-checked readers over a Buffer -----------------------------------------------------
function need(buf, off, len, what) {
  if (!Number.isSafeInteger(off) || !Number.isSafeInteger(len) || off < 0 || len < 0 || off + len > buf.length) {
    fail(`${what}: needs ${len} bytes at offset ${off}, buffer has ${buf.length}`);
  }
}
function u16(buf, off, what = 'uint16') { need(buf, off, 2, what); return buf.readUInt16LE(off); }
function u32(buf, off, what = 'uint32') { need(buf, off, 4, what); return buf.readUInt32LE(off); }
function u64(buf, off, what = 'uint64') {
  need(buf, off, 8, what);
  const v = buf.readBigUInt64LE(off);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${what}: length ${v} is impossible`);
  return Number(v);
}
function slice(buf, off, len, what) { need(buf, off, len, what); return buf.subarray(off, off + len); }

/** uint32 length-prefixed field at `off` inside `buf`. */
function lp(buf, off, what) {
  const len = u32(buf, off, `${what} length`);
  return { data: slice(buf, off + 4, len, what), next: off + 4 + len };
}
/** A whole buffer that is a sequence of uint32 length-prefixed items. */
function lpSequence(buf, what) {
  const items = [];
  let pos = 0;
  while (pos < buf.length) {
    const it = lp(buf, pos, `${what}[${items.length}]`);
    items.push(it.data);
    pos = it.next;
  }
  return items;
}

// --- ZIP structure ---------------------------------------------------------------------------
function findEocd(buf) {
  if (buf.length < 22) fail('file is too small to be a zip/APK');
  const min = Math.max(0, buf.length - 22 - 65535);
  let loose = -1;
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      const commentLen = buf.readUInt16LE(i + 20);
      if (i + 22 + commentLen === buf.length) return i; // the real EOCD ends exactly at EOF
      if (loose < 0) loose = i; // tolerate trailing bytes after the record
    }
  }
  if (loose >= 0) return loose;
  fail('no end-of-central-directory record (not a zip/APK, or truncated)');
}

function readEocd(buf) {
  const eocd = findEocd(buf);
  const cdCount = u16(buf, eocd + 10, 'EOCD entry count');
  const cdSize = u32(buf, eocd + 12, 'EOCD central directory size');
  const cdOffset = u32(buf, eocd + 16, 'EOCD central directory offset');
  if (cdOffset === 0xffffffff || cdCount === 0xffff) fail('zip64 APKs are not supported');
  if (cdOffset + cdSize > eocd) fail(`central directory (${cdOffset}+${cdSize}) overlaps the EOCD at ${eocd}`);
  return { eocd, cdCount, cdOffset, cdSize };
}

// --- APK Signing Block (v2 / v3 / v3.1) ------------------------------------------------------
/** Returns Map(id -> value Buffer) of the signing-block pairs, or null if the APK has no signing block. */
export function readSigningBlock(buf, cdOffset) {
  if (cdOffset < 32) return null;
  need(buf, cdOffset - 24, 24, 'signing block footer');
  if (buf.toString('latin1', cdOffset - 16, cdOffset) !== SIG_BLOCK_MAGIC) return null;
  const sizeInFooter = u64(buf, cdOffset - 24, 'signing block size (footer)');
  const start = cdOffset - sizeInFooter - 8;
  if (sizeInFooter < 24 || start < 0) fail(`signing block size ${sizeInFooter} does not fit before offset ${cdOffset}`);
  const sizeInHeader = u64(buf, start, 'signing block size (header)');
  if (sizeInHeader !== sizeInFooter) fail(`signing block sizes disagree (${sizeInHeader} vs ${sizeInFooter})`);
  const pairs = new Map();
  let pos = start + 8;
  const end = cdOffset - 24;
  while (pos < end) {
    const len = u64(buf, pos, 'signing block pair length');
    if (len < 4 || pos + 8 + len > end) fail(`signing block pair at ${pos} has bad length ${len}`);
    const id = u32(buf, pos + 8, 'signing block pair id');
    if (id !== BLOCK_IDS.PADDING && !pairs.has(id)) pairs.set(id, buf.subarray(pos + 12, pos + 8 + len));
    pos += 8 + len;
  }
  if (pos !== end) fail('signing block pairs overrun the block');
  return pairs;
}

/**
 * Certificates of every signer in a v2 / v3 / v3.1 scheme block.
 * Layout (all uint32 length-prefixed): signers -> signer -> signed data -> [digests, certificates -> cert, ...].
 * The certificates sequence is the second field of signed data in all three schemes.
 * Returns [[signer1 cert chain...], [signer2 cert chain...]] as DER Buffers.
 */
export function certsFromSchemeBlock(block, what = 'scheme block') {
  const signers = lpSequence(lp(block, 0, `${what} signers`).data, `${what} signer`);
  if (signers.length === 0) fail(`${what} has no signers`);
  return signers.map((signer, i) => {
    const signed = lp(signer, 0, `${what} signer ${i} signed data`).data;
    const digests = lp(signed, 0, `${what} signer ${i} digests`);
    const certs = lpSequence(lp(signed, digests.next, `${what} signer ${i} certificates`).data, `${what} signer ${i} certificate`);
    if (certs.length === 0) fail(`${what} signer ${i} has no certificate`);
    return certs.map((c) => Buffer.from(c));
  });
}

// --- minimal DER walker (v1 JAR signature = PKCS#7 SignedData) -------------------------------
export function derTlv(buf, pos) {
  need(buf, pos, 2, 'DER header');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) fail('DER multi-byte tags are not supported');
  let len = buf[pos + 1];
  let hdr = 2;
  if (len === 0x80) fail('DER indefinite length (BER) is not supported');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) fail(`DER length uses ${n} bytes`);
    need(buf, pos + 2, n, 'DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
    hdr = 2 + n;
  }
  need(buf, pos + hdr, len, `DER value (tag 0x${tag.toString(16)})`);
  return { tag, len, start: pos + hdr, end: pos + hdr + len, raw: buf.subarray(pos, pos + hdr + len) };
}

/** All certificates inside a PKCS#7 ContentInfo{SignedData}. Throws ApkFormatError on bad structure. */
export function certsFromPkcs7(der) {
  // ContentInfo SEQ { OID signedData, [0] EXPLICIT SignedData SEQ { version INTEGER, digestAlgs SET, contentInfo SEQ, [0] IMPLICIT certs, ... } }
  const ci = derTlv(der, 0);
  if (ci.tag !== 0x30) fail('PKCS#7: ContentInfo is not a SEQUENCE');
  const oid = derTlv(der, ci.start);
  if (oid.tag !== 0x06) fail('PKCS#7: missing content type OID');
  const ctx = derTlv(der, oid.end);
  if (ctx.tag !== 0xa0) fail('PKCS#7: missing [0] content');
  const sd = derTlv(der, ctx.start);
  if (sd.tag !== 0x30) fail('PKCS#7: SignedData is not a SEQUENCE');
  let p = sd.start;
  const ver = derTlv(der, p); p = ver.end;
  const algs = derTlv(der, p); p = algs.end;
  const content = derTlv(der, p); p = content.end;
  if (ver.tag !== 0x02 || algs.tag !== 0x31 || content.tag !== 0x30) fail('PKCS#7: unexpected SignedData layout');
  if (p >= sd.end) return [];
  const certs = derTlv(der, p);
  if (certs.tag !== 0xa0) return []; // no certificates field
  const out = [];
  let q = certs.start;
  while (q < certs.end) {
    const c = derTlv(der, q);
    if (c.end > certs.end) fail('PKCS#7: certificate overruns the certificates set');
    if (c.tag === 0x30) out.push(Buffer.from(c.raw));
    q = c.end;
  }
  return out;
}

/** v1 signature files (META-INF/*.RSA|DSA|EC) -> list of { name, certs: [DER...] }. */
function v1Signatures(buf, cdOffset, cdCount, cdEnd) {
  const found = [];
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (pos + 46 > cdEnd) fail(`central directory entry ${i} runs past the directory`);
    if (u32(buf, pos, 'CD signature') !== CD_SIG) fail(`central directory entry ${i} has a bad signature`);
    const method = u16(buf, pos + 10, 'CD method');
    const compSize = u32(buf, pos + 20, 'CD compressed size');
    const nameLen = u16(buf, pos + 28, 'CD name length');
    const extraLen = u16(buf, pos + 30, 'CD extra length');
    const commentLen = u16(buf, pos + 32, 'CD comment length');
    const lfhOffset = u32(buf, pos + 42, 'CD local header offset');
    const name = slice(buf, pos + 46, nameLen, 'CD file name').toString('utf8');
    pos += 46 + nameLen + extraLen + commentLen;
    if (!/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(name)) continue;
    if (u32(buf, lfhOffset, 'local header signature') !== LFH_SIG) fail(`${name}: local header missing`);
    const lNameLen = u16(buf, lfhOffset + 26, 'local name length');
    const lExtraLen = u16(buf, lfhOffset + 28, 'local extra length');
    const raw = slice(buf, lfhOffset + 30 + lNameLen + lExtraLen, compSize, `${name} data`);
    let der;
    if (method === 0) der = Buffer.from(raw);
    else if (method === 8) {
      try { der = inflateRawSync(raw, { maxOutputLength: MAX_V1_SIGNATURE_BYTES }); } catch (e) { fail(`${name}: cannot inflate (${e.code || e.message})`); }
    } else fail(`${name}: unsupported compression method ${method}`);
    found.push({ name, certs: certsFromPkcs7(der) });
  }
  return found;
}

function digest(der) {
  return {
    sha1: createHash('sha1').update(der).digest('hex').toUpperCase(),
    sha256: createHash('sha256').update(der).digest('hex').toUpperCase(),
  };
}

/**
 * Every signing certificate an APK carries, in priority order (first is primary).
 * Input: file path or Buffer. Returns { schemes: ['v3', 'v2', ...], certs: [{ sha1, sha256, scheme, signer, der }], warnings: [] }.
 * Only the first certificate of each signer's chain is the signer itself; the rest of a chain is
 * returned too (marked chainIndex > 0) because IOC lists sometimes record intermediate certs.
 * Throws ApkFormatError when nothing could be read because the file is malformed.
 */
export function apkCertificates(input) {
  const buf = Buffer.isBuffer(input) ? input : readFileSync(input);
  const { cdOffset, cdCount, cdSize } = readEocd(buf);
  const warnings = [];
  const out = [];
  const seen = new Set();
  const schemes = [];
  const add = (der, scheme, signer, chainIndex) => {
    const d = digest(der);
    if (seen.has(d.sha1)) return;
    seen.add(d.sha1);
    out.push({ ...d, scheme, signer, chainIndex, der });
  };

  const errors = [];
  try {
    const pairs = readSigningBlock(buf, cdOffset);
    if (pairs) {
      for (const id of SCHEME_ORDER) {
        if (!pairs.has(id)) continue;
        const scheme = SCHEME_BY_ID[id];
        try {
          const signers = certsFromSchemeBlock(pairs.get(id), `${scheme} block`);
          schemes.push(scheme);
          signers.forEach((chain, s) => chain.forEach((der, c) => add(der, scheme, s, c)));
        } catch (e) {
          if (!(e instanceof ApkFormatError)) throw e;
          errors.push(e);
          warnings.push(`${scheme}: ${e.message}`);
        }
      }
    }
  } catch (e) {
    if (!(e instanceof ApkFormatError)) throw e;
    errors.push(e);
    warnings.push(`signing block: ${e.message}`);
  }

  try {
    for (const sig of v1Signatures(buf, cdOffset, cdCount, cdOffset + cdSize)) {
      if (sig.certs.length && !schemes.includes('v1')) schemes.push('v1');
      sig.certs.forEach((der, c) => add(der, 'v1', 0, c));
    }
  } catch (e) {
    if (!(e instanceof ApkFormatError)) throw e;
    errors.push(e);
    warnings.push(`v1: ${e.message}`);
  }

  if (out.length === 0 && errors.length) throw errors[0];
  return { schemes, certs: out, warnings };
}

/**
 * Backwards-compatible: { sha1, sha256 } of the primary certificate plus `all` (every certificate)
 * and `scheme`; null when the APK is well-formed but unsigned. Throws ApkFormatError when malformed.
 */
export function apkCertificate(input) {
  const { certs, schemes, warnings } = apkCertificates(input);
  if (!certs.length) return null;
  const [primary] = certs;
  return {
    sha1: primary.sha1,
    sha256: primary.sha256,
    scheme: primary.scheme,
    schemes,
    all: certs.map(({ sha1, sha256, scheme, signer, chainIndex }) => ({ sha1, sha256, scheme, signer, chainIndex })),
    warnings,
  };
}

export function fileSha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}
