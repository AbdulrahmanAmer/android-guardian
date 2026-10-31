// Per-rule tests for lib/rules.mjs on small synthetic snapshots (one app, one trigger at a time).
// Run alone: node test/rules.test.mjs   (test/run.mjs runs it too)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze, looksRandom, labelImitatesSystem } from '../lib/rules.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const P = 'android.permission.';
const NOW = 1793400000; // 2026-10-30, same clock as the fixtures
const daysAgo = (d) => new Date((NOW - d * 86400) * 1000).toISOString().replace('T', ' ').slice(0, 19);
const STORES = new Set(['com.android.vending', 'com.sec.android.app.samsungapps', 'org.fdroid.fdroid']);
const SAFE_FIX = /^settings put (global|secure) [\w.]+ \S+$/; // same rule as remediate.applyDeviceFix

let uid = 10500;
function app(pkg, o = {}) {
  const installer = 'installer' in o ? o.installer : null;
  const system = !!o.system;
  return {
    pkg, uid: uid++, installer, system, updatedSystem: false, debuggable: !!o.debuggable, hidden: false,
    sideloaded: !system && !(installer && STORES.has(installer)),
    hasLauncherIcon: o.icon ?? true, requested: [...(o.requested || []), ...(o.granted || [])], granted: o.granted || [],
    firstInstall: o.first || '2024-01-01 10:00:00', versionName: '1.0', apkPath: null, sha256: o.sha256 || null,
    ...(o.extra || {}),
  };
}
function snap(packages, o = {}) {
  return {
    device: { now: String(NOW), defaultIme: '', defaultSms: '', ...(o.device || {}) },
    packages,
    accessibility: (o.acc || []).map((pkg) => ({ pkg, component: `${pkg}/.A` })),
    notificationListeners: (o.notif || []).map((pkg) => ({ pkg, component: `${pkg}/.N` })),
    deviceAdmins: (o.admin || []).map((pkg) => ({ pkg, component: `${pkg}/.D` })),
    deviceOwner: null, profileOwner: null,
    idleWhitelist: o.idle || [], usageAccess: o.usage || [], running: o.running || [],
    netstats: o.netstats || {}, ...(o.extra || {}),
  };
}
const IOCS = { packages: new Map(), sha256: new Map(), certSha1: new Map(), domains: new Map(), certOrgs: new Map(), count: 0 };
function run(packages, o = {}, extra = {}) {
  return analyze(snap(packages, o), o.iocs || IOCS, extra);
}
const one = (r, pkg) => r.apps.find((a) => a.pkg === pkg);
const tags = (a) => a.reasons.filter((x) => x.pts > 0 || x.tag === 'known').map((x) => x.tag);
const why = (a) => `score ${a.score}: ${a.reasons.map((x) => `+${x.pts} ${x.tag}`).join(', ')}`;

let passed = 0;
const failures = [];
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${e.message.split('\n')[0]}`); }
}

const SPY = [P + 'RECORD_AUDIO', P + 'READ_SMS'];

// ---------- calibration ----------
await test('calibration: hidden sideloaded app with accessibility + SMS + mic is CRITICAL', () => {
  const a = one(run([app('com.notes.helper', { icon: false, granted: SPY })], { acc: ['com.notes.helper'] }), 'com.notes.helper');
  assert.equal(a.level, 'CRITICAL', why(a));
});
await test('calibration: same rights, Play-installed with an icon, stays under 40', () => {
  const a = one(run([app('com.notes.helper', { installer: 'com.android.vending', granted: SPY })], { acc: ['com.notes.helper'] }), 'com.notes.helper');
  assert.ok(a.score < 40, why(a));
});
await test('calibration: known IOC scores 100 even for a system app or a monitoring app', () => {
  const iocs = { ...IOCS, packages: new Map([['com.sys.x', 'Evil'], ['com.qustodio.qustodioapp', 'Test']]) };
  const r = run([app('com.sys.x', { system: true }), app('com.qustodio.qustodioapp', { installer: 'com.android.vending' })], { iocs });
  assert.equal(one(r, 'com.sys.x').score, 100);
  assert.equal(one(r, 'com.qustodio.qustodioapp').score, 100);
});

// ---------- allowlist / category model ----------
await test('known app gets no credit when sideloaded (impostor with a real app\'s name)', () => {
  const r = run([app('com.x8bit.bitwarden', { granted: [P + 'SYSTEM_ALERT_WINDOW'] })], { acc: ['com.x8bit.bitwarden'] });
  const a = one(r, 'com.x8bit.bitwarden');
  assert.ok(!tags(a).includes('known'), why(a));
  assert.ok(a.reasons.some((x) => x.tag === 'access' && x.pts === 35), why(a));
});
await test('known app from Play gets credit only for rights its category expects', () => {
  // A password manager with accessibility is normal; one reading SMS is not.
  const r = run([app('com.x8bit.bitwarden', { installer: 'com.android.vending', granted: [P + 'READ_SMS'] })], { acc: ['com.x8bit.bitwarden'] });
  const a = one(r, 'com.x8bit.bitwarden');
  assert.ok(tags(a).includes('known') && !tags(a).includes('access'), why(a));
  assert.ok(a.reasons.some((x) => x.tag === 'perm' && /SMS/.test(x.text) && x.pts === 4), why(a));
});
await test('parental-control app is an informational WATCH asking for consent', () => {
  const a = one(run([app('com.qustodio.qustodioapp', { installer: 'com.android.vending', granted: SPY })], { admin: ['com.qustodio.qustodioapp'] }), 'com.qustodio.qustodioapp');
  assert.equal(a.level, 'WATCH', why(a));
  assert.match(a.reasons.find((x) => x.tag === 'monitor').text, /make sure you consented/);
});
await test('remote-control app is an informational WATCH that says it is fine if you installed it', () => {
  const a = one(run([app('com.anydesk.anydeskandroid', { installer: 'com.android.vending', granted: [P + 'SYSTEM_ALERT_WINDOW'] })]), 'com.anydesk.anydeskandroid');
  assert.equal(a.level, 'WATCH', why(a));
  assert.match(a.reasons.find((x) => x.tag === 'remote').text, /fine if you installed it yourself/);
});
await test('Bark is recognised by its label (package name unverified)', () => {
  const a = one(run([app('com.whatever.kids', { installer: 'com.android.vending' })], {}, { labels: new Map([['com.whatever.kids', 'Bark']]) }), 'com.whatever.kids');
  assert.ok(tags(a).includes('monitor'), why(a));
});

// ---------- new true-positive rules ----------
await test('rule labelmimic: label is a system-app name the package does not match', () => {
  const pkgs = [app('com.xq.tracker'), app('com.calc.pro')];
  const labels = new Map([['com.xq.tracker', 'Google Services'], ['com.calc.pro', 'Calculator']]);
  const r = run(pkgs, {}, { labels });
  assert.ok(tags(one(r, 'com.xq.tracker')).includes('labelmimic'), why(one(r, 'com.xq.tracker')));
  assert.ok(!tags(one(r, 'com.calc.pro')).includes('labelmimic'));
  assert.equal(labelImitatesSystem('Settings', 'com.android.settings'), false);
  assert.equal(labelImitatesSystem('System Update', 'com.abc.flashlight'), true);
});
await test('rule adminhidden: device admin with no icon', () => {
  const r = run([app('com.a.hid', { icon: false }), app('com.a.vis')], { admin: ['com.a.hid', 'com.a.vis'] });
  assert.ok(tags(one(r, 'com.a.hid')).includes('adminhidden'), why(one(r, 'com.a.hid')));
  assert.ok(!tags(one(r, 'com.a.vis')).includes('adminhidden'));
});
await test('rule dropper: accessibility + overlay + install apps (banking-trojan pattern)', () => {
  const full = [P + 'SYSTEM_ALERT_WINDOW', P + 'REQUEST_INSTALL_PACKAGES'];
  const r = run([
    app('com.b.on', { granted: full }), app('com.b.declared', { granted: full, requested: [P + 'BIND_ACCESSIBILITY_SERVICE'] }),
    app('com.b.noinstall', { granted: [P + 'SYSTEM_ALERT_WINDOW'] }),
  ], { acc: ['com.b.on', 'com.b.noinstall'] });
  assert.ok(tags(one(r, 'com.b.on')).includes('dropper'), why(one(r, 'com.b.on')));
  assert.ok(tags(one(r, 'com.b.declared')).includes('dropper'), 'declared-but-not-enabled accessibility still counts');
  assert.ok(!tags(one(r, 'com.b.noinstall')).includes('dropper'));
});
await test('rule logs: READ_LOGS granted scores 20, only requested scores 5', () => {
  const r = run([app('com.c.granted', { granted: [P + 'READ_LOGS'] }), app('com.c.asked', { requested: [P + 'READ_LOGS'] })]);
  assert.equal(one(r, 'com.c.granted').reasons.find((x) => x.tag === 'logs').pts, 20);
  assert.equal(one(r, 'com.c.asked').reasons.find((x) => x.tag === 'logs').pts, 5);
});
await test('rule capture: asks for CAPTURE_VIDEO_OUTPUT (system-only)', () => {
  const r = run([app('com.d.cap', { requested: [P + 'CAPTURE_VIDEO_OUTPUT'] }), app('com.d.plain')]);
  assert.ok(tags(one(r, 'com.d.cap')).includes('capture'));
  assert.ok(!tags(one(r, 'com.d.plain')).includes('capture'));
});
await test('rule projection: screen-capture service; active capture scores more', () => {
  const r = run([app('com.e.svc', { granted: [P + 'FOREGROUND_SERVICE_MEDIA_PROJECTION'] }), app('com.e.live')], { extra: { mediaProjection: ['com.e.live'] } });
  assert.equal(one(r, 'com.e.svc').reasons.find((x) => x.tag === 'projection').pts, 8);
  assert.equal(one(r, 'com.e.live').reasons.find((x) => x.tag === 'projection').pts, 25);
});
await test('rule persist: boot + foreground service + no icon', () => {
  const perms = [P + 'RECEIVE_BOOT_COMPLETED', P + 'FOREGROUND_SERVICE'];
  const r = run([app('com.f.hid', { icon: false, granted: perms }), app('com.f.vis', { granted: perms })]);
  assert.ok(tags(one(r, 'com.f.hid')).includes('persist'), why(one(r, 'com.f.hid')));
  assert.ok(!tags(one(r, 'com.f.vis')).includes('persist'));
});
await test('rule random: random-looking package name only counts when sideloaded', () => {
  const r = run([app('com.abcxyz.qwerty'), app('com.zxkhoxrgdfm.fnyjxklj', { installer: 'com.android.vending' })]);
  assert.ok(tags(one(r, 'com.abcxyz.qwerty')).includes('random'), why(one(r, 'com.abcxyz.qwerty')));
  assert.ok(!tags(one(r, 'com.zxkhoxrgdfm.fnyjxklj')).includes('random'));
  assert.ok(looksRandom('com.zxkhoxrgdfm.fnyjxklj'));
});
await test('rule random: no real package name in either fixture looks random', () => {
  const names = new Set();
  for (const f of ['clean', 'infected']) {
    const dump = JSON.parse(readFileSync(join(here, 'fixtures', f, 'commands.json'), 'utf8'))['shell dumpsys package packages'];
    for (const m of dump.matchAll(/Package \[([^\]]+)\]/g)) names.add(m[1]);
  }
  for (const n of ['com.mxtech.videoplayer.ad', 'com.zhiliaoapp.musically', 'org.thoughtcrime.securesms', 'net.dinglisch.android.taskerm', 'com.tencent.mm', 'com.dts.freefireth', 'com.strava', 'com.sxmobile.app',
    'de.blinkt.openvpn', 'com.bbva.bbvacontigo', 'org.schabi.newpipe', 'com.vkontakte.android', 'com.ttxapps.drivesync', 'com.hbo.hbonow',
    'com.cnn.mobile.android.phone', 'com.nytimes.android', 'ch.threema.app', 'com.wsandroid.suite', 'com.kms.free', 'com.sec.android.app.sbrowser',
    'com.lenovo.anyshare.gps', 'com.mcdonalds.app', 'com.dkbcodefactory.banking', 'com.qwant.liberty', 'com.skype.raider', 'com.lyft.android']) names.add(n);
  const hits = [...names].filter(looksRandom);
  assert.deepEqual(hits, []);
});
await test('rule adb/recent: installed over adb or by unknown installer in the last 14 days', () => {
  const r = run([
    app('com.g.adb', { installer: 'com.android.shell', first: daysAgo(3) }),
    app('com.g.null', { first: daysAgo(3) }),
    app('com.g.old', { first: daysAgo(20) }),
    app('com.g.spoof', { installer: 'com.android.vending', first: daysAgo(3), extra: { installInitiator: 'com.android.shell' } }),
  ]);
  const adb = one(r, 'com.g.adb');
  assert.ok(tags(adb).includes('adb') && adb.reasons.find((x) => x.tag === 'recent').pts === 10, why(adb));
  assert.equal(one(r, 'com.g.null').reasons.find((x) => x.tag === 'recent').pts, 10);
  assert.equal(one(r, 'com.g.old').reasons.find((x) => x.tag === 'recent').pts, 5);
  const spoof = one(r, 'com.g.spoof');
  assert.ok(spoof.sideloaded && tags(spoof).includes('adb'), `installer says Play but adb initiated it: ${why(spoof)}`);
});
await test('rule upload: sends far more than it receives, with no icon', () => {
  const pk = [app('com.h.up', { icon: false }), app('com.h.even', { icon: false }), app('com.h.icon')];
  const netstats = { [pk[0].uid]: { rx: 1e6, tx: 100e6 }, [pk[1].uid]: { rx: 50e6, tx: 100e6 }, [pk[2].uid]: { rx: 1e6, tx: 100e6 } };
  const r = run(pk, { netstats });
  assert.ok(tags(one(r, 'com.h.up')).includes('upload'), why(one(r, 'com.h.up')));
  assert.ok(!tags(one(r, 'com.h.even')).includes('upload'));
  assert.ok(!tags(one(r, 'com.h.icon')).includes('upload'));
});
await test('install age is measured against the phone clock (device.now), not the PC clock', () => {
  // Phone clock says mid-2020; the app was installed 2 days before that. By the PC clock it would be years old.
  const phoneNow = 1590000000;
  const first = new Date((phoneNow - 2 * 86400) * 1000).toISOString().replace('T', ' ').slice(0, 19);
  const r = run([app('com.i.x', { first })], { device: { now: String(phoneNow) } });
  assert.ok(tags(one(r, 'com.i.x')).includes('recent'), why(one(r, 'com.i.x')));
});

// ---------- device findings ----------
const findings = (o) => run([app('com.android.settings', { system: true }), app('com.k.kbd'), app('com.google.android.inputmethod.latin', { installer: 'com.android.vending' })], o).deviceFindings;
await test('device: several user profiles are reported', () => {
  const f = findings({ extra: { users: [{ id: 0, name: 'Owner' }, { id: 10, name: 'Kim' }] } });
  assert.ok(f.some((x) => x.level === 'WATCH' && /2 user profiles/.test(x.text)), JSON.stringify(f));
  assert.ok(!findings({ extra: { users: [{ id: 0, name: 'Owner' }] } }).some((x) => /user profiles/.test(x.text)));
});
await test('device: sideloaded app allowed to install apps is SUSPICIOUS, store app is WATCH', () => {
  const f = findings({ extra: { unknownSources: ['com.k.kbd', 'com.android.settings'] } });
  assert.ok(f.some((x) => x.level === 'SUSPICIOUS' && /com\.k\.kbd/.test(x.text)), JSON.stringify(f));
  assert.ok(f.some((x) => x.level === 'WATCH' && /com\.android\.settings/.test(x.text)));
});
await test('device: Play Protect scanning off is SUSPICIOUS with a safe fix', () => {
  const f = findings({ device: { now: String(NOW), packageVerifierUserConsent: '-1' } }).find((x) => /Play Protect scanning/.test(x.text));
  assert.ok(f && f.level === 'SUSPICIOUS' && SAFE_FIX.test(f.fix), JSON.stringify(f));
});
await test('device: sideloaded default keyboard is SUSPICIOUS; Gboard from Play is not reported', () => {
  const bad = findings({ device: { now: String(NOW), defaultIme: 'com.k.kbd/.Ime' } });
  assert.ok(bad.some((x) => x.level === 'SUSPICIOUS' && /keyboard/.test(x.text)), JSON.stringify(bad));
  const good = findings({ device: { now: String(NOW), defaultIme: 'com.google.android.inputmethod.latin/.LatinIME' } });
  assert.ok(!good.some((x) => /keyboard/i.test(x.text)), JSON.stringify(good));
  const r = run([app('com.k.kbd')], { device: { now: String(NOW), defaultIme: 'com.k.kbd/.Ime' } });
  assert.ok(tags(one(r, 'com.k.kbd')).includes('ime'));
});
await test('device: every offered fix passes the remediate allowlist', () => {
  const f = findings({
    device: { now: String(NOW), devSettings: true, adbEnabled: true, unknownSourcesLegacy: true, packageVerifier: '0', packageVerifierUserConsent: '-1', verifyAdbInstalls: '0', privateDnsMode: 'hostname', privateDnsHost: 'bad.example' },
    iocs: { ...IOCS, domains: new Map([['bad.example', 'X']]) },
  });
  assert.ok(f.length >= 6, JSON.stringify(f));
  for (const x of f) if (x.fix) assert.match(x.fix, SAFE_FIX);
});

console.log(`\nrules.test: ${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''}`);
process.exit(failures.length ? 1 : 0);
