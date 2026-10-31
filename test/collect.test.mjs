// Tests for data collection: adb wrapper, every dumpsys/cmd parser in collect.mjs, the readiness
// probes in device.mjs, and full collect() runs against the replay fixtures from make-fixture.mjs.
// Run: node test/collect.test.mjs   (exit 1 on any failure)
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { Adb, parseDevices, normalizeEol } from '../lib/adb.mjs';
import { collect, _internal as C } from '../lib/collect.mjs';
import { readiness, probeWrite, probeUninstall } from '../lib/device.mjs';

const here = dirname(fileURLToPath(import.meta.url));
execFileSync(process.execPath, [join(here, 'make-fixture.mjs')], { stdio: 'ignore', timeout: 60_000 });

let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${String(e.message).split('\n').slice(0, 3).join('\n       ')}`); }
}

const tmpDirs = [];
/** A real Adb in replay mode over an in-memory command table. */
function replayAdb(commands) {
  const dir = mkdtempSync(join(tmpdir(), 'ag-collect-'));
  tmpDirs.push(dir);
  writeFileSync(join(dir, 'commands.json'), JSON.stringify(commands));
  return new Adb({ mode: 'replay', fixtureDir: dir });
}
const fixture = (name) => new Adb({ mode: 'replay', fixtureDir: join(here, 'fixtures', name) });
const byPkg = (snap, pkg) => snap.packages.find((p) => p.pkg === pkg);

// ---------------------------------------------------------------------------------------------
// Synthetic dumpsys blocks, written the way the phones print them.
// ---------------------------------------------------------------------------------------------
const A8 = `Packages:
  Package [com.old.style] (1a2b3c):
    userId=10123
    pkg=Package{9f8e7d com.old.style}
    codePath=/data/app/com.old.style-1
    versionCode=42 minSdk=19 targetSdk=26
    versionName=4.2
    splits=[base]
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA DEBUGGABLE ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]
    firstInstallTime=2018-06-01 10:00:00
    lastUpdateTime=2018-06-02 10:00:00
    installerPackageName=com.android.vending
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA DEBUGGABLE ]
    requested permissions:
      android.permission.READ_SMS
      android.permission.WRITE_EXTERNAL_STORAGE: restricted=true, maxSdkVersion=28
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=123 installed=true hidden=false suspended=false stopped=true notLaunched=false enabled=0 instant=false
      gids=[3003]
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ USER_SET ]
        android.permission.CAMERA: granted=false, flags=[ USER_SET ]
  Package [com.priv.sys] (4d5e6f):
    userId=1000
    sharedUser=SharedUserSetting{abc android.uid.system/1000}
    codePath=/system/priv-app/PrivSys
    flags=[ SYSTEM HAS_CODE PERSISTENT ]
    privateFlags=[ PRIVILEGED DEFAULT_TO_DEVICE_PROTECTED_STORAGE ]
    User 0: ceDataInode=0 installed=true hidden=true suspended=false stopped=false notLaunched=false enabled=3 instant=false
`;

const A14_MULTI = `Packages:
  Package [com.new.style] (7a8b9c):
    appId=10300
    pkg=Package{1 com.new.style}
    codePath=/data/app/~~x==/com.new.style-y==
    versionCode=7 minSdk=26 targetSdk=34
    splits=[base, config.arm64_v8a, config.en]
    flags=[ HAS_CODE ALLOW_BACKUP ]
    installSource=InstallSource{installerPackageName=null, initiatingPackageName=com.android.chrome, originatingPackageName=null}
    pkgFlags=[ HAS_CODE ALLOW_BACKUP ]
    User 0: ceDataInode=0 installed=false hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
      installReason=0
      firstInstallTime=1970-01-01 00:00:00
    User 10: ceDataInode=55 installed=true hidden=false suspended=true distractionFlags=0 stopped=false notLaunched=false enabled=1 instant=false virtual=false
      installReason=0
      firstInstallTime=2026-10-01 12:00:00
      runtime permissions:
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED ]
      disabledComponents:
        com.new.style.Hidden
  Package [com.play.only] (0d0e0f):
    appId=10301
    codePath=/data/app/~~p==/com.play.only-q==
    flags=[ HAS_CODE ]
    installInitiator=com.android.vending
    User 0: ceDataInode=9 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
  Package [com.gone.everywhere] (111111):
    appId=10302
    codePath=/system/app/Gone
    flags=[ SYSTEM HAS_CODE ]
    User 0: ceDataInode=0 installed=false hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false virtual=false
`;

// ---------------------------------------------------------------------------------------------
// adb.mjs
// ---------------------------------------------------------------------------------------------
test('adb: CRLF and CRCRLF from old ptys are normalised', () => {
  assert.equal(normalizeEol('a\r\nb\r\r\nc\r'), 'a\nb\nc');
  assert.equal(normalizeEol('plain\n'), 'plain\n');
  assert.equal(replayAdb({ 'shell x': 'one\r\ntwo\r\n' }).shell('x'), 'one\ntwo\n');
});

test('adb: devices parser skips daemon noise and reads every state', () => {
  const d = parseDevices(`* daemon not running; starting now at tcp:5037
* daemon started successfully
adb server version (40) doesn't match this client (41); killing...
List of devices attached
R58M12ABCDE            device usb:1-1 product:a52 model:SM_A525F device:a52q transport_id:3
emulator-5554          offline transport_id:1
ABC123                 unauthorized usb:1-2 transport_id:4
0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:1-1 transport_id:5
ZY22                   recovery product:x model:Moto_G device:x transport_id:6
ZY23                   sideload transport_id:7

`);
  assert.deepEqual(d.map((x) => [x.serial, x.state]), [
    ['R58M12ABCDE', 'device'], ['emulator-5554', 'offline'], ['ABC123', 'unauthorized'],
    ['0123456789ABCDEF', 'no-permissions'], ['ZY22', 'recovery'], ['ZY23', 'sideload'],
  ]);
  assert.equal(d[0].model, 'SM_A525F');
  assert.equal(d[0].transportId, '3');
  assert.equal(d[4].model, 'Moto_G');
});

test('adb: replay honours recorded {stdout, stderr, status} records', () => {
  const adb = replayAdb({ 'shell settings put global x 1': { stdout: '', stderr: 'java.lang.SecurityException: Permission denial', status: 255 }, 'shell ok': 'fine\n' });
  const r = adb.shellResult('settings put global x 1');
  assert.equal(r.ok, false);
  assert.match(r.text, /SecurityException/);
  assert.equal(adb.shell('ok'), 'fine\n');
  assert.throws(() => adb.raw(['shell', 'settings put global x 1']), /failed \(255\)/);
});

// ---------------------------------------------------------------------------------------------
// dumpsys package packages
// ---------------------------------------------------------------------------------------------
test('packages: Android 8 format (userId=, flags=/pkgFlags=, package-level firstInstallTime)', () => {
  const m = C.parsePackagesDump(A8);
  const p = m.get('com.old.style');
  assert.equal(p.uid, 10123);
  assert.equal(p.debuggable, true);
  assert.equal(p.system, false);
  assert.equal(p.installer, 'com.android.vending');
  assert.equal(p.sideloaded, false);
  assert.equal(p.firstInstall, '2018-06-01 10:00:00');
  assert.equal(p.versionCode, 42);
  assert.equal(p.targetSdk, 26);
  assert.deepEqual(p.requested, ['android.permission.READ_SMS', 'android.permission.WRITE_EXTERNAL_STORAGE']);
  assert.deepEqual(p.granted.sort(), ['android.permission.INTERNET', 'android.permission.READ_SMS']);
  assert.ok(!p.granted.includes('android.permission.CAMERA'), 'granted=false must not count');
  assert.equal(p.stopped, true);
  assert.deepEqual(p.splits, ['base']);
});

test('packages: privileged, sharedUser, hidden and disabled-by-user state', () => {
  const p = C.parsePackagesDump(A8).get('com.priv.sys');
  assert.equal(p.system, true);
  assert.equal(p.privileged, true);
  assert.equal(p.sharedUser, 'android.uid.system');
  assert.equal(p.uid, 1000);
  assert.equal(p.hidden, true);
  assert.equal(p.enabled, false);
  assert.deepEqual(p.requested, [], 'no requested permissions section');
});

test('packages: Android 14 appId=, InstallSource{...}, splits, work-profile-only app', () => {
  const { packages, notInstalled } = C.parsePackagesDumpFull(A14_MULTI);
  const p = packages.get('com.new.style');
  assert.equal(p.uid, 10300);
  assert.equal(p.installer, null);
  assert.equal(p.installInitiator, 'com.android.chrome');
  assert.equal(p.sideloaded, true);
  assert.deepEqual(p.splits, ['base', 'config.arm64_v8a', 'config.en']);
  assert.deepEqual(p.installedUsers, [10]);
  assert.equal(p.installed, false);
  assert.equal(p.secondaryUserOnly, true);
  assert.equal(p.suspended, true, 'state comes from the user it is installed for');
  assert.equal(p.firstInstall, '2026-10-01 12:00:00', 'first install from the installed user, not the 1970 placeholder');
  assert.deepEqual(p.granted, ['android.permission.ACCESS_FINE_LOCATION']);
  assert.deepEqual(p.users.find((u) => u.id === 10).disabledComponents, ['com.new.style.Hidden']);
  assert.equal(packages.get('com.play.only').installInitiator, 'com.android.vending');
  assert.equal(packages.get('com.play.only').sideloaded, false, 'store as initiator without installer line');
  assert.deepEqual(notInstalled, ['com.gone.everywhere']);
  assert.ok(!packages.has('com.gone.everywhere'));
});

test('packages: Hidden system packages do not overwrite the live record', () => {
  const dump = `Packages:
  Package [com.google.android.gms] (1):
    appId=10100
    codePath=/data/app/~~g==/com.google.android.gms-h==
    flags=[ SYSTEM HAS_CODE UPDATED_SYSTEM_APP ]
    User 0: installed=true hidden=false enabled=0

Hidden system packages:
  Package [com.google.android.gms] (2):
    appId=10100
    codePath=/system/priv-app/PrebuiltGmsCore
    flags=[ SYSTEM HAS_CODE ]
    User 0: installed=true hidden=false enabled=0
`;
  const p = C.parsePackagesDump(dump).get('com.google.android.gms');
  assert.equal(p.path, '/data/app/~~g==/com.google.android.gms-h==');
  assert.equal(p.updatedSystem, true);
  assert.equal(p.factoryPath, '/system/priv-app/PrebuiltGmsCore');
});

test('packages: a malformed package cannot swallow the next one', () => {
  const dump = `Packages:
  Package [com.bad.one] (1):
    appId=10001
    flags=[ HAS_CODE
    requested permissions:
      android.permission.INTERNET
    ??? junk: [[[ {{{
GARBAGE AT COLUMN ZERO
  Package [com.good.two] (2):
    appId=10002
    codePath=/data/app/good
    flags=[ HAS_CODE ]
    User 0: installed=true enabled=0
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ ]
`;
  const m = C.parsePackagesDump(dump);
  assert.deepEqual([...m.keys()], ['com.bad.one', 'com.good.two']);
  assert.equal(m.get('com.good.two').uid, 10002);
  assert.deepEqual(m.get('com.good.two').granted, ['android.permission.CAMERA']);
  assert.deepEqual(m.get('com.bad.one').granted, []);
  // No column-0 line in between: the next header alone must close the open user/runtime list.
  const back2back = `Packages:
  Package [com.first] (1):
    appId=10001
    User 0: installed=true enabled=0
      runtime permissions:
        android.permission.READ_SMS: granted=true, flags=[ ]
  Package [com.second] (2):
    appId=10002
    User 0: installed=true enabled=0
`;
  const m2 = C.parsePackagesDump(back2back);
  assert.deepEqual([...m2.keys()], ['com.first', 'com.second']);
  assert.deepEqual(m2.get('com.second').granted, []);
  assert.equal(m2.get('com.second').uid, 10002);
});

test('packages: CRLF dump, Android 5 grantedPermissions:, no User line', () => {
  const dump = 'Packages:\r\n  Package [com.lollipop] (1):\r\n    userId=10050\r\n    codePath=/data/app/com.lollipop-1.apk\r\n    flags=[ HAS_CODE ]\r\n    grantedPermissions:\r\n      android.permission.READ_CONTACTS\r\n      android.permission.INTERNET\r\n';
  const p = C.parsePackagesDump(dump).get('com.lollipop');
  assert.equal(p.uid, 10050);
  assert.equal(p.path, '/data/app/com.lollipop-1.apk');
  assert.deepEqual(p.granted.sort(), ['android.permission.INTERNET', 'android.permission.READ_CONTACTS']);
  assert.equal(p.installed, true, 'no User line: assume installed for user 0');
});

// The bound is loose on purpose (a loaded CI box); a quadratic parser takes minutes on this input.
test('packages: parsing is linear (400 packages, ~30 MB, under 20 s)', () => {
  const filler = Array.from({ length: 2400 }, (_, i) => `        com.example.Component${i}`).join('\n');
  const parts = ['Packages:'];
  for (let i = 0; i < 400; i++) {
    parts.push(`  Package [com.bulk.app${i}] (${i.toString(16)}):
    appId=${10000 + i}
    codePath=/data/app/~~${i}==/com.bulk.app${i}-x==
    flags=[ HAS_CODE ]
    requested permissions:
      android.permission.INTERNET
    User 0: installed=true hidden=false enabled=0
      runtime permissions:
        android.permission.CAMERA: granted=${i % 2 === 0}, flags=[ USER_SET ]
      disabledComponents:
${filler}`);
  }
  const dump = parts.join('\n');
  assert.ok(dump.length > 25e6, `dump is ${dump.length} bytes`);
  const t0 = performance.now();
  const m = C.parsePackagesDump(dump);
  const ms = performance.now() - t0;
  assert.equal(m.size, 400);
  assert.deepEqual(m.get('com.bulk.app398').granted, ['android.permission.CAMERA']);
  assert.deepEqual(m.get('com.bulk.app399').granted, []);
  assert.ok(ms < 20000, `took ${Math.round(ms)} ms`);
  console.log(`       (parsed ${(dump.length / 1e6).toFixed(1)} MB in ${Math.round(ms)} ms)`);
});

// ---------------------------------------------------------------------------------------------
// Launcher icons
// ---------------------------------------------------------------------------------------------
test('launcher: query-activities output; error text is "unknown", not "no icons"', () => {
  const out = '2 activities found:\n  Activity #0:\n    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\n    com.foo/.Main\n  Activity #1:\n    com.bar/com.bar.ui.Start\n';
  assert.deepEqual(C.parseLauncherActivities(out), [{ pkg: 'com.foo', cls: 'com.foo.Main' }, { pkg: 'com.bar', cls: 'com.bar.ui.Start' }]);
  assert.equal(C.parseLauncherActivities("Error: unknown command 'query-activities'\n"), null);
  assert.equal(C.parseLauncherActivities('/system/bin/sh: cmd: not found\n'), null);
  assert.equal(C.parseLauncherActivities(''), null);
  assert.deepEqual(C.parseLauncherActivities('No activities found\n'), []);
});

test('launcher: resolver-table fallback needs MAIN + LAUNCHER/LEANBACK in the same filter, activities only', () => {
  const out = `Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        1a com.a/.Main filter 2b
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
        3c com.tv/.Tv filter 4d
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LEANBACK_LAUNCHER"
        5e com.home/.Home filter 6f
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.HOME"
      android.intent.action.VIEW:
        7a com.view/.V filter 8b
          Action: "android.intent.action.VIEW"
          Category: "android.intent.category.LAUNCHER"

Service Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        9c com.svc/.S filter 0d
          Action: "android.intent.action.MAIN"
          Category: "android.intent.category.LAUNCHER"
`;
  assert.deepEqual(C.parseResolverLaunchers(out).map((c) => c.pkg), ['com.a', 'com.tv']);
});

// ---------------------------------------------------------------------------------------------
// Small parsers
// ---------------------------------------------------------------------------------------------
test('users: pm list users, work profile flag', () => {
  const u = C.parseUsers('Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work profile:1030} running\n\tUserInfo{150:Secure Folder:10001030}\n');
  assert.deepEqual(u.map((x) => [x.id, x.managedProfile, x.running]), [[0, false, true], [10, true, true], [150, true, false]]);
  assert.equal(u[1].name, 'Work profile');
});

test('roles: holders joined by ";", errors ignored', () => {
  const r = C.parseRoles('SMS=com.a.sms\nDIALER=com.a.dialer;com.b.dialer\nASSISTANT=\nHOME=java.lang.SecurityException: nope\n');
  assert.deepEqual(r, { sms: ['com.a.sms'], dialer: ['com.a.dialer', 'com.b.dialer'], assistant: [] });
  assert.equal(C.parseRoles('/system/bin/sh: cmd: not found\n'), null);
  assert.equal(C.parseRoles('SMS=Unknown command: role\n'), null);
});

test('CA certificates listing: listed / denied / none', () => {
  assert.deepEqual(C.parseCaCertListing('9a5ba575.0\nc8750f0d.0\n'), { status: 'listed', files: ['9a5ba575.0', 'c8750f0d.0'] });
  assert.equal(C.parseCaCertListing('ls: /data/misc/user/0/cacerts-added: Permission denied').status, 'denied');
  assert.equal(C.parseCaCertListing('ls: /data/misc/user/0/cacerts-added: No such file or directory').status, 'none');
  assert.equal(C.parseCaCertListing('').status, 'none');
});

test('notification listeners from dumpsys: old and new header wording, stops at block end', () => {
  const r = C.parseNotificationListenersDump(`  Notification listeners:
    Allowed user profiles: {0}
    All notification listeners (1) enabled for current profiles:
      com.spy/com.spy.L
    Live notification listeners (1):
      com.spy/com.spy.L (user 0): ManagedServiceInfo[component=ComponentInfo{com.spy/com.spy.L},userid=0]
  Notification assistant services:
    Live services (1):
      com.android.ext.services/.notification.Assistant (user 0): ManagedServiceInfo[]
`);
  assert.equal(r.ok, true);
  assert.deepEqual(r.enabled.map((x) => x.pkg), ['com.spy']);
  assert.deepEqual(r.live.map((x) => [x.pkg, x.user]), [['com.spy', 0]]);
  assert.equal(C.parseNotificationListenersDump('Permission Denial: can\'t dump NotificationManager').ok, false);
});

test('processes: ps -o NAME and old toolbox ps', () => {
  assert.deepEqual([...C.parseProcessNames('NAME\ninit\ncom.a.b\ncom.c.d:remote\n')], ['com.a.b', 'com.c.d']);
  assert.deepEqual([...C.parseProcessNames("bad pid '-o'\nUSER PID PPID VSIZE RSS WCHAN PC NAME\nroot 1 0 1 1 SyS 0 S /init\nu0_a1 9 1 1 1 SyS 0 S com.x.y:svc\n")], ['com.x.y']);
});

test('settings component lists drop non-app entries', () => {
  assert.deepEqual(C.parseComponentList('com.android.server.accessibility.MagnificationController:com.a/.S').map((c) => c.pkg), ['com.a']);
});

test('settings error text is not a value; sha256sum paths are shell-quoted', () => {
  const seen = [];
  const fake = {
    shell(cmd) {
      seen.push(cmd);
      if (cmd === 'getprop ro.build.version.sdk') return '33\n';
      if (cmd === 'settings get global private_dns_specifier') return 'Exception occurred while executing \'get\':\njava.lang.SecurityException: denied\n';
      if (cmd === 'dumpsys package packages') return "Packages:\n  Package [com.q] (1):\n    appId=10001\n    codePath=/data/app/it's here\n    flags=[ HAS_CODE ]\n";
      if (cmd.startsWith('cmd package query-activities') && cmd.endsWith('.LAUNCHER')) return '1 activities found:\n  com.q/.M\n';
      return '';
    },
  };
  const s = collect(fake);
  assert.equal(s.device.privateDnsHost, '');
  assert.ok(seen.includes("sha256sum '/data/app/it'\\''s here/base.apk' 2>/dev/null"), seen.filter((c) => c.startsWith('sha256sum')).join(' | '));
  assert.equal(byPkg(s, 'com.q').hasLauncherIcon, true);
});

test('hashing: one sha256sum call per 40 app files', () => {
  const blocks = Array.from({ length: 81 }, (_, i) => `  Package [com.h${i}] (1):\n    appId=${10000 + i}\n    codePath=/data/app/h${i}\n    flags=[ HAS_CODE ]\n`).join('');
  const calls = [];
  const fake = {
    shell(cmd) {
      if (cmd.startsWith('sha256sum')) { calls.push(cmd); return `${'e'.repeat(64)}  /data/app/h80/base.apk\n`; }
      return cmd === 'dumpsys package packages' ? `Packages:\n${blocks}` : '';
    },
  };
  const s = collect(fake);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].split("' '").length, 40);
  assert.equal(byPkg(s, 'com.h80').sha256, 'e'.repeat(64));
  assert.equal(byPkg(s, 'com.h0').sha256, null);
});

test('launcher: no usable answer at all gives hasLauncherIcon null (unknown), never false', () => {
  const fake = { shell: (cmd) => (cmd === 'dumpsys package packages' ? 'Packages:\n  Package [com.q] (1):\n    appId=10001\n    codePath=/data/app/q\n    flags=[ HAS_CODE ]\n' : '') };
  const s = collect(fake);
  assert.equal(s.launcher.source, 'unavailable');
  assert.equal(byPkg(s, 'com.q').hasLauncherIcon, null);
});

// ---------------------------------------------------------------------------------------------
// Full collect() runs against the fixtures
// ---------------------------------------------------------------------------------------------
const infected = collect(fixture('infected'));
test('fixture infected (One UI 13): packages, debloated app, updated system app, new signals', () => {
  assert.equal(infected.packages.length, 7);
  assert.deepEqual(infected.notInstalledPackages, ['com.samsung.android.bixby.agent']);
  const v = byPkg(infected, 'com.android.vending');
  assert.equal(v.path, '/data/app/~~vnd==/com.android.vending-pq==', 'hidden system copy must not win');
  assert.equal(v.factoryPath, '/product/priv-app/Phonesky');
  assert.deepEqual(byPkg(infected, 'com.whatsapp').splits, ['base', 'config.arm64_v8a', 'config.xxhdpi']);
  assert.equal(infected.launcher.source, 'cmd');
  assert.equal(byPkg(infected, 'com.wifi.update.service').hasLauncherIcon, false);
  assert.deepEqual(infected.roles, { sms: ['com.samsung.android.messaging'], dialer: ['com.samsung.android.dialer'], assistant: [], home: ['com.sec.android.app.launcher'], source: 'role' });
  assert.deepEqual(infected.userCaCerts, { status: 'denied', count: null, files: [] });
  assert.equal(infected.device.stayOnWhilePluggedIn, 0);
  assert.deepEqual(infected.accessibilityShortcutTargets, [{ component: 'com.systemservice/com.systemservice.AccService', pkg: 'com.systemservice', via: 'shortcut' }]);
  assert.deepEqual(infected.notificationListenersLive.live.map((x) => x.pkg), ['com.android.systemui', 'com.wifi.update.service']);
  assert.deepEqual(infected.users.map((u) => u.id), [0]);
});

const legacy = collect(fixture('legacy-xiaomi'));
test('fixture legacy-xiaomi (MIUI, Android 7.1, CRLF): resolver fallback, disabled launcher, dual apps', () => {
  assert.equal(legacy.device.sdk, 25);
  assert.equal(legacy.device.model, 'Redmi 4X');
  assert.equal(legacy.launcher.source, 'dumpsys');
  assert.equal(byPkg(legacy, 'com.whatsapp').hasLauncherIcon, true);
  assert.equal(byPkg(legacy, 'com.android.sys.helper').hasLauncherIcon, false, 'launcher activity disabled by the app = hidden');
  assert.equal(byPkg(legacy, 'com.miui.home').hasLauncherIcon, false, 'HOME is not LAUNCHER');
  assert.equal(byPkg(legacy, 'com.facebook.appmanager').hasLauncherIcon, false, 'receiver table ignored');
  const wa = byPkg(legacy, 'com.whatsapp');
  assert.equal(wa.uid, 10120);
  assert.deepEqual(wa.installedUsers, [0, 999]);
  assert.equal(wa.sideloaded, false, 'Xiaomi GetApps is a store');
  assert.ok(wa.granted.includes('android.permission.RECORD_AUDIO'), 'grant held only in the dual-app user still counts');
  const spy = byPkg(legacy, 'com.android.sys.helper');
  assert.equal(spy.debuggable, true);
  assert.equal(spy.sha256, '2'.repeat(64));
  assert.deepEqual(byPkg(legacy, 'com.example.flashlight').requested, []);
  assert.equal(byPkg(legacy, 'com.facebook.appmanager').enabled, false);
  assert.deepEqual(legacy.roles, { source: 'settings', sms: ['com.android.mms'], dialer: ['com.android.contacts'], assistant: ['com.google.android.googlequicksearchbox'], home: [] });
  assert.equal(legacy.userCaCerts.count, 2);
  assert.equal(legacy.device.stayOnWhilePluggedIn, 3);
  assert.deepEqual(legacy.running.sort(), ['com.android.sys.helper', 'com.whatsapp']);
  assert.deepEqual(legacy.users.map((u) => u.id), [0, 999]);
});

const work = collect(fixture('work-pixel'));
test('fixture work-pixel (Android 14): work profile, InstallSource, leanback, stub, malformed block', () => {
  assert.equal(work.packages.length, 8);
  const mdm = byPkg(work, 'com.mdm.agent.tracker');
  assert.equal(mdm.secondaryUserOnly, true);
  assert.deepEqual(mdm.installedUsers, [10]);
  assert.equal(mdm.hasLauncherIcon, false, 'checked against the work-profile launcher query');
  assert.deepEqual(mdm.granted.sort(), ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET', 'android.permission.READ_CONTACTS']);
  assert.equal(mdm.firstInstall, '2026-10-29 03:00:00');
  assert.deepEqual(work.accessibility, [{ component: 'com.mdm.agent.tracker/.TrackService', pkg: 'com.mdm.agent.tracker', user: 10 }]);
  assert.deepEqual(work.notificationListeners.map((x) => [x.pkg, x.user]), [['com.mdm.agent.tracker', 10]]);
  assert.deepEqual(work.notificationListenersLive.live.map((x) => [x.pkg, x.user]), [['com.android.systemui', 0], ['com.mdm.agent.tracker', 10]]);
  assert.equal(work.users.find((u) => u.id === 10).managedProfile, true);
  assert.equal(byPkg(work, 'com.tv.remote.helper').hasLauncherIcon, true, 'LEANBACK_LAUNCHER counts as an icon');
  assert.equal(byPkg(work, 'com.spotify.music').sideloaded, false);
  assert.equal(byPkg(work, 'com.spotify.music').installInitiator, 'com.android.vending');
  assert.equal(byPkg(work, 'com.free.vpn.proxy').installer, 'com.google.android.packageinstaller');
  assert.equal(byPkg(work, 'com.free.vpn.proxy').installInitiator, 'com.android.chrome');
  assert.equal(byPkg(work, 'com.google.android.GoogleCamera').stub, true);
  assert.equal(byPkg(work, 'com.google.android.gms').factoryPath, '/system/priv-app/PrebuiltGmsCore');
  assert.equal(byPkg(work, 'com.oem.weird').installer, 'com.android.vending');
  assert.equal(byPkg(work, 'com.oem.weird').uid, 10240);
  assert.deepEqual(work.roles.home, ['com.google.android.apps.nexuslauncher']);
  assert.equal(work.userCaCerts.status, 'none');
  assert.equal(work.device.stayOnWhilePluggedIn, null);
});

// ---------------------------------------------------------------------------------------------
// device.mjs
// ---------------------------------------------------------------------------------------------
const OK_PHONE = {
  'shell getprop ro.product.model': 'Pixel 8\n',
  'shell getprop ro.product.manufacturer': 'Google\n',
  'shell getprop ro.build.version.release': '14\n',
  'shell getprop ro.build.version.sdk': '34\n',
  'shell settings put global android_guardian_probe 1': '',
  'shell settings get global android_guardian_probe': 'null\n', // after delete
  'shell settings delete global android_guardian_probe': 'Deleted 1 rows\n',
  'shell pm list users': 'Users:\n\tUserInfo{0:Owner:c13} running\n',
  'shell pm uninstall --user 0 com.android.guardian.probe.does.not.exist': 'Failure [not installed for 0]\n',
};
/** Replay Adb whose answer to `settings get` flips after the delete, like a real phone. */
function statefulPhone(cmds) {
  const adb = replayAdb(cmds);
  let stored = null;
  const raw = adb.raw.bind(adb);
  adb.raw = (args, o) => {
    const c = args.join(' ');
    if (c === 'shell settings put global android_guardian_probe 1' && !(cmds[c] && typeof cmds[c] === 'object')) stored = '1';
    if (c === 'shell settings delete global android_guardian_probe') stored = null;
    if (c === 'shell settings get global android_guardian_probe') return { stdout: `${stored ?? 'null'}\n`, stderr: '', status: 0 };
    return raw(args, o);
  };
  return adb;
}
const devicesAdb = (text) => replayAdb({ 'devices -l': text });

test('readiness: one state per adb state, noise ignored', () => {
  const cases = [
    ['List of devices attached\n\n', 'no-device'],
    ['* daemon not running; starting now at tcp:5037\n* daemon started successfully\nList of devices attached\nA1 unauthorized usb:1 transport_id:1\n', 'unauthorized'],
    ['List of devices attached\nA1 offline transport_id:1\n', 'offline'],
    ['List of devices attached\nA1 no permissions (user in plugdev group); see [http://developer.android.com/tools/device.html] usb:1-1 transport_id:1\n', 'no-permissions'],
    ['List of devices attached\nA1 recovery transport_id:1\n', 'recovery'],
    ['List of devices attached\nA1 sideload transport_id:1\n', 'sideload'],
  ];
  for (const [text, want] of cases) {
    const r = readiness('adb', { makeAdb: () => devicesAdb(text) });
    assert.equal(r.state, want, text);
    assert.ok(r.todo.length > 0 && r.title, `${want} has title and steps`);
  }
});

test('readiness: adb itself failing is a state, not an exception', () => {
  const r = readiness('adb', { makeAdb: () => ({ devices() { throw new Error('spawnSync adb ETIMEDOUT'); } }) });
  assert.equal(r.state, 'adb-error');
  assert.match(r.error, /ETIMEDOUT/);
});

test('readiness: several phones -> first "device" is used, others reported', () => {
  const list = replayAdb({ 'devices -l': fixtureCommands('work-pixel')['devices -l'] });
  const phone = statefulPhone(OK_PHONE);
  const r = readiness('adb', { makeAdb: (o) => (o.serial ? phone : list) });
  assert.equal(r.state, 'ready');
  assert.equal(r.device.serial, '37081FDJH000AB');
  assert.deepEqual(r.otherDevices.map((d) => [d.serial, d.state]), [['emulator-5554', 'unauthorized'], ['0123456789ABCDEF', 'no-permissions']]);
  assert.match(r.todo[0], /More than one phone/);
  assert.deepEqual(r.capabilities, { canWrite: true, canUninstall: true, probeCleanedUp: true, listUsers: true });
});

test('probeWrite: MIUI SecurityException -> canWrite false, no throw, nothing to clean', () => {
  const miui = replayAdb({ ...OK_PHONE, 'shell settings put global android_guardian_probe 1': { stdout: '', stderr: "Exception occurred while executing 'put':\njava.lang.SecurityException: Permission denial: writing to settings requires:android.permission.WRITE_SECURE_SETTINGS", status: 255 } });
  const w = probeWrite(miui);
  assert.equal(w.canWrite, false);
  assert.equal(w.cleanedUp, true);
  assert.match(w.detail, /SecurityException/);
});

test('probeWrite: success writes, reads back, deletes and verifies the delete', () => {
  const w = probeWrite(statefulPhone(OK_PHONE));
  assert.deepEqual({ canWrite: w.canWrite, cleanedUp: w.cleanedUp }, { canWrite: true, cleanedUp: true });
  const stuck = replayAdb({ ...OK_PHONE, 'shell settings get global android_guardian_probe': '1\n' }); // delete unsupported
  assert.equal(probeWrite(stuck).cleanedUp, false);
});

test('probeWrite / probeUninstall: a hung adb call never throws', () => {
  const hung = { shell() { throw new Error('ETIMEDOUT'); }, shellResult() { throw new Error('ETIMEDOUT'); } };
  assert.equal(probeWrite(hung).canWrite, false);
  assert.equal(probeUninstall(hung).canUninstall, false);
});

test('probeUninstall: normal failure strings vs SecurityException', () => {
  assert.equal(probeUninstall(replayAdb(OK_PHONE)).canUninstall, true);
  const old = replayAdb({ ...OK_PHONE, 'shell pm uninstall --user 0 com.android.guardian.probe.does.not.exist': 'Failure [DELETE_FAILED_INTERNAL_ERROR]\n' });
  assert.equal(probeUninstall(old).canUninstall, true);
  const locked = replayAdb({ ...OK_PHONE, 'shell pm uninstall --user 0 com.android.guardian.probe.does.not.exist': { stdout: '', stderr: 'java.lang.SecurityException: Permission Denial: runUninstall from pid=1234, uid=2000', status: 255 } });
  assert.equal(probeUninstall(locked).canUninstall, false);
  const mdm = replayAdb({ ...OK_PHONE, 'shell pm uninstall --user 0 com.android.guardian.probe.does.not.exist': 'Failure [DELETE_FAILED_USER_RESTRICTED]\n' });
  assert.equal(probeUninstall(mdm).canUninstall, false, 'MDM uninstall restriction is a refusal, not a normal failure');
  const noUsers = replayAdb({ ...OK_PHONE, 'shell pm list users': 'Error: java.lang.SecurityException: You need MANAGE_USERS permission\n' });
  const nu = probeUninstall(noUsers);
  assert.equal(nu.usersOk, false);
  assert.equal(nu.canUninstall, false);
});

function fixtureCommands(name) {
  return fixture(name).recording;
}

for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''}`);
process.exit(failures.length ? 1 : 0);
