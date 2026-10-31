// APK signing-certificate reader against synthetic APKs built in memory.
// Real X.509 certificates are generated here (EC P-256, self-signed with node:crypto) and checked
// by node's own X509Certificate parser, so the expected SHA-1 does not come from lib/apk.mjs.
// Run: node test/apk.test.mjs
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, X509Certificate, randomBytes } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import * as zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { apkCertificate, apkCertificates, ApkFormatError, BLOCK_IDS } from '../lib/apk.mjs';

// ---------- DER encoding ----------
function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | b.length, ...b]);
}
const tlv = (tag, ...parts) => { const v = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(v.length), v]); };
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const int = (n) => tlv(0x02, Buffer.from([n]));
function oid(str) {
  const a = str.split('.').map(Number);
  const out = [40 * a[0] + a[1]];
  for (const v of a.slice(2)) {
    const b = [v & 0x7f];
    let x = v >>> 7;
    while (x) { b.unshift((x & 0x7f) | 0x80); x >>>= 7; }
    out.push(...b);
  }
  return tlv(0x06, Buffer.from(out));
}
const utf8 = (s) => tlv(0x0c, Buffer.from(s));
const utcTime = (s) => tlv(0x17, Buffer.from(s));
const bitString = (b) => tlv(0x03, Buffer.from([0]), b);
const ctx0 = (...p) => tlv(0xa0, ...p);

/** A genuine self-signed X.509 v3 certificate (EC P-256, ecdsa-with-SHA256). */
function makeCert(cn) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const name = seq(set(seq(oid('2.5.4.3'), utf8(cn))));
  const alg = seq(oid('1.2.840.10045.4.3.2'));
  const tbs = seq(
    ctx0(int(2)),
    tlv(0x02, Buffer.concat([Buffer.from([0x01]), randomBytes(8)])),
    alg,
    name,
    seq(utcTime('260101000000Z'), utcTime('360101000000Z')),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  const der = seq(tbs, alg, bitString(sign('sha256', tbs, privateKey)));
  const x = new X509Certificate(der);
  assert.ok(x.verify(publicKey), 'generated certificate must verify against its own key');
  return { der, publicKey, x };
}

/** PKCS#7 ContentInfo{SignedData} carrying the given certificates (signerInfos left empty). */
function pkcs7(...certs) {
  return seq(
    oid('1.2.840.113549.1.7.2'),
    ctx0(seq(int(1), set(seq(oid('2.16.840.1.101.3.4.2.1'), tlv(0x05))), seq(oid('1.2.840.113549.1.7.1')), tlv(0xa0, ...certs), set())),
  );
}

// ---------- ZIP / APK construction ----------
const crc32 = typeof zlib.crc32 === 'function' ? zlib.crc32 : (b) => {
  let c = ~0;
  for (const x of b) { c ^= x; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return ~c >>> 0;
};

/** Builds a zip. entries: [{ name, data, deflate }]. signingBlock (Buffer) goes between the entries and the central directory. */
function buildZip(entries, signingBlock = Buffer.alloc(0)) {
  const locals = [];
  const central = [];
  let off = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name);
    const body = e.deflate ? deflateRawSync(e.data) : e.data;
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(e.deflate ? 8 : 0, 8);
    lfh.writeUInt32LE(crc32(e.data) >>> 0, 14); lfh.writeUInt32LE(body.length, 18); lfh.writeUInt32LE(e.data.length, 22);
    lfh.writeUInt16LE(name.length, 26);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(e.deflate ? 8 : 0, 10);
    cd.writeUInt32LE(crc32(e.data) >>> 0, 16); cd.writeUInt32LE(body.length, 20); cd.writeUInt32LE(e.data.length, 24);
    cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(off, 42);
    locals.push(lfh, name, body);
    central.push(cd, name);
    off += 30 + name.length + body.length;
  }
  const cdOffset = off + signingBlock.length;
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([...locals, signingBlock, cdBuf, eocd]);
}

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const lp = (...parts) => { const v = Buffer.concat(parts); return Buffer.concat([u32(v.length), v]); };

/** v2 / v3 scheme value: signers -> signer -> signed data { digests, certificates, ... }. Each arg is one signer's cert chain. */
function schemeBlock(v3, ...chains) {
  const signers = chains.map((chain) => {
    const digests = lp(lp(u32(0x0103), lp(Buffer.alloc(32, 7))));
    const certs = lp(...chain.map((c) => lp(c)));
    const signed = v3 ? Buffer.concat([digests, certs, u32(24), u32(0x7fffffff), lp()]) : Buffer.concat([digests, certs, lp()]);
    const tail = v3 ? Buffer.concat([u32(24), u32(0x7fffffff)]) : Buffer.alloc(0);
    return lp(lp(signed), tail, lp(lp(u32(0x0103), lp(Buffer.alloc(64, 9)))), lp(Buffer.alloc(91, 5)));
  });
  return lp(...signers);
}

/** APK Signing Block from [id, value] pairs. */
function signingBlock(pairs) {
  const body = Buffer.concat(pairs.map(([id, v]) => Buffer.concat([u64(v.length + 4), u32(id), v])));
  const size = body.length + 8 + 16;
  return Buffer.concat([u64(size), body, u64(size), Buffer.from('APK Sig Block 42', 'latin1')]);
}

const sha1 = (b) => createHash('sha1').update(b).digest('hex').toUpperCase();
const x509sha1 = (x) => x.fingerprint.replace(/:/g, '').toUpperCase();

// ---------- tests ----------
let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${e.stack.split('\n').slice(0, 3).join('\n       ')}`); }
}

const A = makeCert('Signer A');
const B = makeCert('Signer B');
const C = makeCert('Signer C (rotated v3.1 key)');
const manifest = { name: 'AndroidManifest.xml', data: Buffer.from('<manifest/>') };
const dex = { name: 'classes.dex', data: Buffer.alloc(5000, 1), deflate: true };

test('generated certificates are real X.509 (node parser agrees on SHA-1)', () => {
  assert.equal(x509sha1(A.x), sha1(A.der));
  assert.notEqual(sha1(A.der), sha1(B.der));
});

test('v1-only APK, stored META-INF/CERT.RSA', () => {
  const apk = buildZip([manifest, dex, { name: 'META-INF/CERT.RSA', data: pkcs7(A.der) }]);
  const c = apkCertificate(apk);
  assert.equal(c.sha1, x509sha1(A.x));
  assert.equal(c.sha256, createHash('sha256').update(A.der).digest('hex').toUpperCase());
  assert.equal(c.scheme, 'v1');
});

test('v1-only APK, deflated META-INF/*.RSA with two certificates', () => {
  const apk = buildZip([manifest, { name: 'META-INF/ANDROIDD.RSA', data: pkcs7(A.der, B.der), deflate: true }]);
  const r = apkCertificates(apk);
  assert.deepEqual(r.certs.map((c) => c.sha1), [sha1(A.der), sha1(B.der)]);
  assert.deepEqual(Buffer.compare(r.certs[0].der, A.der), 0, 'walker returns exactly the certificate bytes');
});

test('v2 signing block around a known certificate', () => {
  const apk = buildZip([manifest, dex], signingBlock([[BLOCK_IDS.V2, schemeBlock(false, [A.der])]]));
  const c = apkCertificate(apk);
  assert.equal(c.sha1, x509sha1(A.x));
  assert.equal(c.scheme, 'v2');
});

test('v2 multi-signer: all certificates returned, first signer is primary', () => {
  const apk = buildZip([manifest], signingBlock([[BLOCK_IDS.V2, schemeBlock(false, [A.der], [B.der])]]));
  const c = apkCertificate(apk);
  assert.equal(c.sha1, sha1(A.der));
  assert.deepEqual(c.all.map((x) => [x.sha1, x.signer]), [[sha1(A.der), 0], [sha1(B.der), 1]]);
});

test('v3 + v3.1 + verity padding (0x42726577) + v1: padding skipped, every cert found, v3 primary', () => {
  const block = signingBlock([
    [BLOCK_IDS.V2, schemeBlock(false, [A.der])],
    [BLOCK_IDS.PADDING, Buffer.alloc(3000)],
    [BLOCK_IDS.V31, schemeBlock(true, [C.der])],
    [BLOCK_IDS.V3, schemeBlock(true, [A.der])],
  ]);
  const apk = buildZip([manifest, { name: 'META-INF/CERT.RSA', data: pkcs7(B.der), deflate: true }], block);
  const r = apkCertificates(apk);
  assert.deepEqual(r.schemes, ['v3', 'v2', 'v3.1', 'v1']);
  assert.deepEqual(r.certs.map((c) => c.sha1), [sha1(A.der), sha1(C.der), sha1(B.der)], 'A deduplicated across v3/v2');
  assert.equal(r.certs[0].scheme, 'v3');
  assert.deepEqual(r.warnings, []);
});

test('unsigned but well-formed APK returns null', () => {
  assert.equal(apkCertificate(buildZip([manifest, dex])), null);
});

test('malformed length fields throw ApkFormatError, never RangeError', () => {
  // signer length claims 2 GB
  const bad = schemeBlock(false, [A.der]);
  bad.writeUInt32LE(0x7fffffff, 4);
  const apk1 = buildZip([manifest], signingBlock([[BLOCK_IDS.V2, bad]]));
  assert.throws(() => apkCertificate(apk1), ApkFormatError);
  // pair length overruns the block
  const blk = signingBlock([[BLOCK_IDS.V2, schemeBlock(false, [A.der])]]);
  blk.writeBigUInt64LE(10n ** 12n, 8);
  assert.throws(() => apkCertificate(buildZip([manifest], blk)), ApkFormatError);
  // header and footer sizes disagree
  const blk2 = signingBlock([[BLOCK_IDS.V2, schemeBlock(false, [A.der])]]);
  blk2.writeBigUInt64LE(5n, 0);
  assert.throws(() => apkCertificate(buildZip([manifest], blk2)), ApkFormatError);
  // central directory offset past EOF
  const apk3 = buildZip([manifest]);
  apk3.writeUInt32LE(0x0fffffff, apk3.length - 6);
  assert.throws(() => apkCertificate(apk3), ApkFormatError);
  // DER length past the end inside a v1 signature
  const p7 = pkcs7(A.der);
  p7[1] = 0x84; // long-form length with 4 bytes -> reads garbage length
  assert.throws(() => apkCertificate(buildZip([manifest, { name: 'META-INF/CERT.RSA', data: p7 }])), ApkFormatError);
  // not a zip at all / truncated
  assert.throws(() => apkCertificate(Buffer.alloc(10)), ApkFormatError);
  assert.throws(() => apkCertificate(randomBytes(4096)), ApkFormatError);
});

test('broken signing block still falls back to a valid v1 signature (with a warning)', () => {
  const bad = schemeBlock(false, [A.der]);
  bad.writeUInt32LE(0x7fffffff, 4);
  const apk = buildZip([manifest, { name: 'META-INF/CERT.RSA', data: pkcs7(B.der) }], signingBlock([[BLOCK_IDS.V2, bad]]));
  const r = apkCertificates(apk);
  assert.deepEqual(r.certs.map((c) => c.sha1), [sha1(B.der)]);
  assert.ok(r.warnings.some((w) => /^v2:/.test(w)), JSON.stringify(r.warnings));
});

test('fuzz: 3000 random byte mutations never escape as anything but ApkFormatError', () => {
  const base = buildZip(
    [manifest, { name: 'META-INF/CERT.RSA', data: pkcs7(B.der), deflate: true }],
    signingBlock([[BLOCK_IDS.V3, schemeBlock(true, [A.der], [C.der])], [BLOCK_IDS.PADDING, Buffer.alloc(64)]]),
  );
  let seed = 12345;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  for (let i = 0; i < 3000; i++) {
    const m = Buffer.from(base);
    for (let k = 0; k < 1 + rnd(4); k++) m[rnd(m.length)] = rnd(256);
    const cut = rnd(10) === 0 ? m.subarray(0, rnd(m.length)) : m;
    try { apkCertificate(cut); } catch (e) { assert.ok(e instanceof ApkFormatError, `mutation ${i}: ${e.name}: ${e.message}`); }
  }
});

// Independent cross-check: OpenSSL reads the same PKCS#7 we built (optional, skipped without openssl).
const ossl = spawnSync('openssl', ['version'], { encoding: 'utf8', timeout: 10_000 });
test(ossl.status === 0 ? 'openssl parses the synthetic PKCS#7 and agrees on the certificate' : 'openssl cross-check (SKIPPED: openssl not on PATH)', () => {
  if (ossl.status !== 0) return;
  const r = spawnSync('openssl', ['pkcs7', '-inform', 'DER', '-print_certs', '-outform', 'PEM'], { input: pkcs7(A.der), timeout: 10_000 });
  assert.equal(r.status, 0, String(r.stderr));
  const pem = String(r.stdout).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)[0];
  assert.equal(x509sha1(new X509Certificate(pem)), sha1(A.der));
});

console.log(`\n${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''}`);
process.exit(failures.length ? 1 : 0);
