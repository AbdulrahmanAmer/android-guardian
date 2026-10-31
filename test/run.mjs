// Tests: parsers, rules against the infected and clean fixtures, IOC loading, VirusTotal client,
// APK certificate reader. Then runs every test/*.test.mjs file, each in its own process.
// Run: node test/run.mjs
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { Adb } from '../lib/adb.mjs';
import { collect, _internal } from '../lib/collect.mjs';
import { analyze } from '../lib/rules.mjs';
import { loadIocs, BUILTIN, parseStix } from '../lib/iocs.mjs';
import { lookupHashes, _clearVtCache } from '../lib/vt.mjs';
import { apkCertificate } from '../lib/apk.mjs';
import { htmlReport, consoleReport } from '../lib/report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, 'fixtures', 'infected');
if (!existsSync(join(fixtureDir, 'commands.json'))) execFileSync(process.execPath, [join(here, 'make-fixture.mjs')], { stdio: 'inherit', timeout: 60_000 });
// lib/ui-bundle.mjs is generated from ui/index.html and not committed; the server tests import it.
if (!existsSync(join(here, '..', 'lib', 'ui-bundle.mjs'))) execFileSync(process.execPath, [join(here, '..', 'build.mjs'), '--ui-only'], { stdio: 'inherit', timeout: 60_000 });

let passed = 0;
const failures = [];
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${e.message.split('\n')[0]}`); }
}

const adb = new Adb({ mode: 'replay', fixtureDir });
const snapshot = collect(adb);

await test('parses all packages from dumpsys', () => {
  assert.equal(snapshot.packages.length, 7);
  const sw = snapshot.packages.find((p) => p.pkg === 'com.systemservice');
  assert.ok(sw, 'stalkerware package present');
  assert.equal(sw.system, false);
  assert.equal(sw.installer, null);
  assert.equal(sw.sideloaded, true);
  assert.equal(sw.uid, 10301);
  assert.ok(sw.granted.includes('android.permission.READ_SMS'), 'runtime permission parsed as granted');
  assert.ok(sw.granted.includes('android.permission.SYSTEM_ALERT_WINDOW'), 'install permission parsed as granted');
  assert.equal(sw.hasLauncherIcon, false);
  assert.equal(sw.sha256, 'b'.repeat(64));
});

await test('system and store apps are classified', () => {
  const settings = snapshot.packages.find((p) => p.pkg === 'com.android.settings');
  assert.equal(settings.system, true);
  const wa = snapshot.packages.find((p) => p.pkg === 'com.whatsapp');
  assert.equal(wa.sideloaded, false);
  assert.equal(wa.hasLauncherIcon, true);
});

await test('special access lists parsed', () => {
  assert.deepEqual(snapshot.accessibility.map((a) => a.pkg), ['com.systemservice', 'com.google.android.marvin.talkback']);
  assert.deepEqual(snapshot.notificationListeners.map((a) => a.pkg), ['com.wifi.update.service']);
  assert.deepEqual(snapshot.deviceAdmins.map((a) => a.pkg), ['com.systemservice']);
  assert.ok(snapshot.idleWhitelist.includes('com.systemservice'));
  assert.ok(snapshot.usageAccess.includes('com.systemservice'));
  assert.ok(snapshot.running.includes('com.wifi.update.service'));
  assert.equal(snapshot.netstats['10301'].tx, 734003200);
});

await test('device_policy parser handles owner', () => {
  const r = _internal.parseDeviceAdmins('Device Owner:\n  admin=ComponentInfo{com.evil.mdm/.Owner}\n  name=\nEnabled Device Admins (User 0, provisioningState: 0):\n  com.evil.mdm/.Owner:\n    uid=10400\n');
  assert.equal(r.deviceOwner, 'com.evil.mdm/.Owner');
  assert.deepEqual(r.admins.map((a) => a.pkg), ['com.evil.mdm']);
});

// Offline IOC load: built-ins only unless a cached list exists in test/fixtures.
const iocs = await loadIocs({ cacheDir: join(here, 'fixtures', 'ioc-cache'), offline: !process.env.ONLINE });
// Make sure the fixture's known stalkerware name is an IOC even when offline.
iocs.packages.set('com.systemservice', 'TheTruthSpy');
iocs.count = iocs.packages.size + iocs.sha256.size + iocs.certSha1.size + iocs.domains.size;
const result = analyze(snapshot, iocs);
const by = (pkg) => result.apps.find((a) => a.pkg === pkg);

await test('known stalkerware is CRITICAL via IOC', () => {
  assert.equal(by('com.systemservice').level, 'CRITICAL');
  assert.ok(by('com.systemservice').reasons.some((r) => r.tag === 'ioc'));
});

await test('unknown RAT is CRITICAL via behaviour alone', () => {
  const rat = by('com.wifi.update.service');
  assert.equal(rat.level, 'CRITICAL', `score ${rat.score}: ${rat.reasons.map((r) => r.text).join('; ')}`);
  assert.ok(!rat.reasons.some((r) => r.tag === 'ioc'), 'must not rely on IOC');
  assert.ok(rat.reasons.some((r) => r.tag === 'hidden'));
  assert.ok(rat.reasons.some((r) => r.tag === 'notif'));
  assert.ok(rat.reasons.some((r) => r.tag === 'mimic'));
  assert.ok(rat.reasons.some((r) => r.tag === 'combo'));
});

await test('normal apps are not flagged', () => {
  assert.equal(by('com.whatsapp').level, 'OK', `whatsapp score ${by('com.whatsapp').score}`);
  assert.equal(by('com.android.settings').level, 'OK');
  assert.equal(by('com.google.android.marvin.talkback').level, 'OK');
  assert.ok(['OK', 'WATCH'].includes(by('org.supertuxkart.stk').level), `game is ${by('org.supertuxkart.stk').level}`);
});

await test('device findings include verifier off and developer options', () => {
  const texts = result.deviceFindings.map((f) => f.text).join(' | ');
  assert.match(texts, /Play Protect install check\) is turned OFF/);
  assert.match(texts, /Developer options are ON/);
  assert.ok(result.deviceFindings.find((f) => /Play Protect/.test(f.text)).fix.startsWith('settings put global package_verifier_enable 1'));
});

await test('summary counts', () => {
  assert.equal(result.summary.total, 7);
  assert.equal(result.summary.critical, 2);
  assert.equal(result.flagged[0].level, 'CRITICAL');
});

await test('hash IOC match flags an app with an unknown name', () => {
  const i2 = { ...iocs, packages: new Map(), sha256: new Map([['d'.repeat(64), 'EvilHash']]) };
  const r2 = analyze(snapshot, i2);
  assert.equal(r2.apps.find((a) => a.pkg === 'org.supertuxkart.stk').level, 'CRITICAL');
});

await test('certificate IOC match flags an app', () => {
  const certs = new Map([['com.whatsapp', 'ABCDEF']]);
  const i3 = { ...iocs, packages: new Map(), certSha1: new Map([['ABCDEF', 'EvilCert']]) };
  assert.equal(analyze(snapshot, i3, { certs }).apps.find((a) => a.pkg === 'com.whatsapp').level, 'CRITICAL');
});

await test('reports render', () => {
  const html = htmlReport(result);
  assert.match(html, /com\.systemservice/);
  assert.match(html, /CRITICAL/);
  assert.match(consoleReport(result), /\[CRITICAL\] com\.systemservice/);
  mkdirSync(join(here, 'out'), { recursive: true });
  writeFileSync(join(here, 'out', 'report.html'), html);
});

await test('built-in RAT list is used', () => {
  assert.ok(BUILTIN.packages['ahmyth.mine.king.ahmyth']);
  assert.match(iocs.packages.get('ahmyth.mine.king.ahmyth'), /^AhMyth RAT/);
});

// --- Calibration evidence: every app in the infected fixture ---
console.log('\n  infected fixture scores:');
for (const a of result.apps) console.log(`    ${String(a.score).padStart(3)} ${a.level.padEnd(10)} ${a.pkg}`);
console.log('');

// --- Clean phone: a typical phone full of store apps that legitimately hold scary rights ---
const cleanSnap = collect(new Adb({ mode: 'replay', fixtureDir: join(here, 'fixtures', 'clean') }));
const clean = analyze(cleanSnap, iocs);
// Every WATCH on the clean phone must be listed here with the reason it is acceptable.
const CLEAN_WATCH_OK = {
  'com.anydesk.anydeskandroid': 'remote-control notice, fine if the owner installed it',
  'com.anydesk.adcontrol.ad1': 'AnyDesk control plugin (accessibility): remote-control notice',
  'com.teamviewer.quicksupport.market': 'remote-control notice',
  'com.google.android.apps.kids.familylinkhelper': 'parental control on this phone: "make sure you consented"',
  'com.sec.android.app.kidshome': 'Samsung Kids: "make sure you consented"',
  'org.fdroid.fdroid': 'app store downloaded from the web: truly sideloaded + can install apps (15+8), nothing else',
};
await test('clean phone: 60+ third-party apps parsed', () => {
  assert.ok(cleanSnap.packages.filter((p) => !p.system).length >= 60, `only ${cleanSnap.packages.length}`);
});
await test('clean phone: zero CRITICAL and zero SUSPICIOUS apps', () => {
  const bad = clean.apps.filter((a) => a.level === 'CRITICAL' || a.level === 'SUSPICIOUS');
  assert.deepEqual(bad.map((a) => `${a.pkg} ${a.score}`), []);
});
await test('clean phone: every WATCH is a justified one (remote / monitoring notice, or the sideloaded store)', () => {
  const watch = clean.apps.filter((a) => a.level === 'WATCH').map((a) => a.pkg).sort();
  assert.deepEqual(watch, Object.keys(CLEAN_WATCH_OK).sort());
  for (const a of clean.apps.filter((x) => x.level === 'WATCH' && x.pkg !== 'org.fdroid.fdroid')) {
    assert.ok(a.reasons.some((r) => r.tag === 'remote' || r.tag === 'monitor'), `${a.pkg} is WATCH without a notice`);
  }
});
await test('clean phone: no device finding above WATCH', () => {
  assert.deepEqual(clean.deviceFindings.filter((f) => f.level !== 'WATCH').map((f) => f.text), []);
});
console.log('\n  clean fixture scores (third-party apps):');
for (const a of clean.apps.filter((x) => !x.system)) console.log(`    ${String(a.score).padStart(3)} ${a.level.padEnd(10)} ${a.pkg}${CLEAN_WATCH_OK[a.pkg] ? `  <- ${CLEAN_WATCH_OK[a.pkg]}` : ''}`);
console.log('');

// --- Echap STIX parser ---
await test('STIX parser reads every kind, OR patterns and certificate organisations, and logs what it skips', () => {
  const bundle = { objects: [
    { type: 'malware', id: 'malware--1', name: 'FakeSpy' },
    { type: 'indicator', id: 'indicator--1', pattern: "[app:id = 'com.fake.spy' OR app:id = 'com.fake.spy2']" },
    { type: 'indicator', id: 'indicator--2', pattern: "[file:hashes.sha256 = 'ABCDEF']" },
    { type: 'indicator', id: 'indicator--3', pattern: "[app:cert.sha1 = 'AA:BB:CC']" },
    { type: 'indicator', id: 'indicator--4', pattern: "[domain-name:value = 'Evil.Example']" },
    { type: 'indicator', id: 'indicator--5', pattern: "[app:cert.organization = 'Spy Corp Ltd']" },
    { type: 'indicator', id: 'indicator--6', pattern: "[mutex:name = 'x']" },
    { type: 'indicator', id: 'indicator--7', pattern: 'garbage' },
    ...[1, 2, 3, 4, 5].map((n) => ({ type: 'relationship', relationship_type: 'indicates', source_ref: `indicator--${n}`, target_ref: 'malware--1' })),
  ] };
  const m = { packages: new Map(), sha256: new Map(), certSha1: new Map(), domains: new Map(), certOrgs: new Map(), ips: new Map(), urls: new Map() };
  const logs = [];
  const st = parseStix(bundle, m, (x) => logs.push(x));
  assert.equal(m.packages.get('com.fake.spy2'), 'FakeSpy');
  assert.ok(m.sha256.has('abcdef') && m.certSha1.has('AABBCC') && m.domains.has('evil.example'));
  assert.equal(m.certOrgs.get('spy corp ltd'), 'FakeSpy');
  assert.equal(st.skippedKinds['mutex:name'], 1);
  assert.equal(st.unparsable, 1);
  assert.ok(logs.some((l) => /mutex:name/.test(l)) && logs.some((l) => /not understood\): 1/.test(l)), logs.join(' | '));
  // and the rules act on a certificate-organisation match
  const r = analyze(snapshot, { ...iocs, certOrgs: m.certOrgs }, { certs: new Map([['org.supertuxkart.stk', { sha1: 'X', org: 'Spy Corp Ltd' }]]) });
  assert.equal(r.apps.find((a) => a.pkg === 'org.supertuxkart.stk').score, 100);
});
await test('loadIocs reads a cached STIX file offline and logs counts per kind', async () => {
  const dir = join(here, 'out', 'stix-test');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'stalkerware.stix2'), JSON.stringify({ objects: [{ type: 'indicator', id: 'i', name: 'X', pattern: "[app:id = 'com.cached.spy']" }] }));
  const logs = [];
  const loaded = await loadIocs({ cacheDir: dir, offline: true, log: (x) => logs.push(x) });
  assert.equal(loaded.packages.get('com.cached.spy'), 'X');
  assert.ok(logs.some((l) => /1 packages/.test(l)), logs.join(' | '));
});

// --- VirusTotal client (fake network and fake clock: no real waiting) ---
function fakeVt(script) {
  let t = 0;
  const calls = [];
  const res = (status, body = {}, headers = {}) => ({ status, ok: status >= 200 && status < 300, json: async () => body, text: async () => JSON.stringify(body), headers: { get: (k) => headers[k.toLowerCase()] ?? null } });
  return {
    calls,
    elapsed: () => t,
    opts: {
      now: () => t,
      sleep: async (ms) => { t += ms; },
      fetchImpl: async (url) => { calls.push(url.split('/').pop()); t += 100; const step = script.shift(); return step ? res(...step) : res(404); },
    },
  };
}
const FOUND = [200, { data: { attributes: { last_analysis_stats: { malicious: 5, undetected: 60 } } } }];
await test('VirusTotal: per-minute 429 waits for Retry-After and retries the same file', async () => {
  _clearVtCache();
  const f = fakeVt([[429, { error: { code: 'QuotaExceededError' } }, { 'retry-after': '20' }], FOUND]);
  const out = await lookupHashes(['a'.repeat(64)], 'key', f.opts);
  assert.deepEqual(f.calls, ['a'.repeat(64), 'a'.repeat(64)]);
  assert.equal(out.get('a'.repeat(64)).malicious, 5);
  assert.ok(f.elapsed() >= 20_000 && f.elapsed() < 30_000, `waited ${f.elapsed()} ms (Retry-After said 20 s)`);
});
await test('VirusTotal: daily-quota 429 stops at once', async () => {
  _clearVtCache();
  const f = fakeVt([[429, { error: { code: 'QuotaExceededError', message: 'Daily quota exceeded' } }]]);
  const out = await lookupHashes(['1'.repeat(64), '2'.repeat(64)], 'key', f.opts);
  assert.equal(f.calls.length, 1);
  assert.equal(out.stats.stopped, 'quota');
  assert.equal(out.stats.skipped, 2);
});
await test('VirusTotal: two 429s in a row are treated as quota exhausted', async () => {
  _clearVtCache();
  const f = fakeVt([[429, {}], [429, {}]]);
  const out = await lookupHashes(['3'.repeat(64)], 'key', f.opts);
  assert.equal(f.calls.length, 2);
  assert.equal(out.stats.stopped, 'quota');
});
await test('VirusTotal: results are cached for the process', async () => {
  _clearVtCache();
  await lookupHashes(['c'.repeat(64)], 'key', fakeVt([FOUND]).opts);
  const f2 = fakeVt([]);
  const out = await lookupHashes(['C'.repeat(64)], 'key', f2.opts);
  assert.equal(f2.calls.length, 0);
  assert.equal(out.get('c'.repeat(64)).malicious, 5);
});
await test('VirusTotal: never waits longer than maxMinutes (default 4)', async () => {
  _clearVtCache();
  const hashes = Array.from({ length: 30 }, (_, n) => n.toString(16).padStart(64, '0'));
  const f = fakeVt([]);
  const logs = [];
  const out = await lookupHashes(hashes, 'key', { ...f.opts, max: 30, log: (x) => logs.push(x) });
  assert.ok(f.elapsed() <= 4 * 60_000, `waited ${f.elapsed()} ms`);
  assert.ok(out.stats.checked >= 15 && out.stats.checked < 30, `checked ${out.stats.checked}`);
  assert.equal(out.stats.stopped, 'time');
  assert.ok(logs.some((l) => /stopped after 4 minutes/.test(l)), logs.join(' | '));
});

// APK certificate reader against a real APK if one is available locally (any APK pulled by a scan, or TEST_APK env).
const apk = process.env.TEST_APK || [join(here, 'fixtures', 'sample.apk')].find(existsSync);
await test(apk ? `reads signing certificate from ${apk}` : 'APK certificate reader (SKIPPED: no sample APK; set TEST_APK=path)', () => {
  if (!apk) return;
  const c = apkCertificate(apk);
  assert.ok(c && /^[0-9A-F]{40}$/.test(c.sha1), `got ${JSON.stringify(c)}`);
});

// --- Every other test file (test/*.test.mjs), each in its own process; a file counts as one test ---
const files = readdirSync(here).filter((f) => f.endsWith('.test.mjs')).sort();
for (const f of files) {
  console.log(`\n--- ${f} ---`);
  const r = spawnSync(process.execPath, [join(here, f)], { encoding: 'utf8', timeout: 300_000 });
  process.stdout.write(r.stdout || '');
  if (r.stderr) process.stdout.write(r.stderr);
  if (r.status === 0) passed++;
  else failures.push(`${f} (exit ${r.status ?? r.signal})`);
}

console.log(`\n${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''} (test files run: ${files.join(', ') || 'none'})`);
process.exit(failures.length ? 1 : 0);
