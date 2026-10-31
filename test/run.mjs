// Tests: parsers, rules against the infected fixture, IOC loading, APK certificate reader.
// Run: node test/run.mjs
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { Adb } from '../lib/adb.mjs';
import { collect, _internal } from '../lib/collect.mjs';
import { analyze } from '../lib/rules.mjs';
import { loadIocs, BUILTIN } from '../lib/iocs.mjs';
import { apkCertificate } from '../lib/apk.mjs';
import { htmlReport, consoleReport } from '../lib/report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, 'fixtures', 'infected');
if (!existsSync(join(fixtureDir, 'commands.json'))) execFileSync(process.execPath, [join(here, 'make-fixture.mjs')], { stdio: 'inherit', timeout: 60_000 });

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
  assert.equal(iocs.packages.get('ahmyth.mine.king.ahmyth'), 'AhMyth RAT');
});

// APK certificate reader against a real APK if one is available locally (any APK pulled by a scan, or TEST_APK env).
const apk = process.env.TEST_APK || [join(here, 'fixtures', 'sample.apk')].find(existsSync);
await test(apk ? `reads signing certificate from ${apk}` : 'APK certificate reader (SKIPPED: no sample APK; set TEST_APK=path)', () => {
  if (!apk) return;
  const c = apkCertificate(apk);
  assert.ok(c && /^[0-9A-F]{40}$/.test(c.sha1), `got ${JSON.stringify(c)}`);
});

console.log(`\n${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''}`);
process.exit(failures.length ? 1 : 0);
