// Remediation logic against a stateful fake phone.
//
// FakePhone subclasses the real Adb class and only replaces raw(), so the real shell()/shellResult()
// success detection from lib/adb.mjs is what remediate.mjs sees. The phone answers with the strings
// Android prints (written from AOSP source knowledge, NOT captured from a device; the same goes for
// test/fixtures/remediate/*.txt). What this proves: ordering, per-user handling, failure classification,
// manual next steps, no loops, and that "done" is decided by reading the phone's state back.
// What it cannot prove: that a real phone answers exactly like this. That needs a device.
// Run: node test/remediate.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Adb } from '../lib/adb.mjs';
import {
  removeApp, blockApp, undoBlock, setDnsProtection, clearDnsProtection, applyDeviceFix,
  parseDevicePolicy, listUsers, assertPackageName, classifyUninstall, BLOCK_APPOPS,
} from '../lib/remediate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(join(here, 'fixtures', 'remediate', n), 'utf8');
const P = 'android.permission.';
const BUCKETS = { active: 10, working_set: 20, frequent: 30, rare: 40, restricted: 45 };

class FakePhone extends Adb {
  constructor(o = {}) {
    super({ mode: 'live', bin: 'fake-adb' });
    this.sdk = o.sdk ?? 34;
    this.users = o.users ?? [{ id: 0, name: 'Owner' }];
    this.noAccessUsers = new Set(o.noAccessUsers ?? []);
    this.pkgs = new Map();
    for (const [name, p] of Object.entries(o.packages ?? {})) {
      this.pkgs.set(name, {
        system: false, uid: 10301, users: new Set([0]), enabled: {}, suspended: {}, ops: {}, bucket: 10,
        runtime: new Set(), install: new Set([P + 'INTERNET', P + 'RECEIVE_BOOT_COMPLETED']), ...p,
        runtime: new Set(p.runtime ?? []),
      });
    }
    this.admins = o.admins ?? []; // { user, component, testOnly }
    this.owners = o.owners ?? []; // { kind, user, component }
    this.settings = { 'global private_dns_mode': 'opportunistic', ...(o.settings ?? {}) };
    this.uninstallError = o.uninstallError ?? {}; // { [user]: 'Failure [...]' }
    this.lieAboutUninstall = !!o.lieAboutUninstall;
    this.unknownOps = new Set(o.unknownOps ?? []);
    this.ignoreDnsWrites = !!o.ignoreDnsWrites;
    this.idle = new Set(o.idle ?? []);
    this.netBlocked = new Set();
    this.log = [];
  }

  raw(args) {
    assert.equal(args[0], 'shell', `only shell commands expected, got ${args.join(' ')}`);
    const cmd = args[1];
    this.log.push(cmd);
    const out = this.answer(cmd);
    return { stdout: out, stderr: '', status: 0 };
  }

  pkgLine(name) {
    return name.replace(/\./g, '\\.');
  }

  answer(cmd) {
    let m;
    const ex = (msg) => `Exception occurred while executing '${cmd.split(' ')[1]}':\njava.lang.SecurityException: ${msg}`;
    if (cmd === 'getprop ro.build.version.sdk') return `${this.sdk}\n`;
    if (cmd === 'getprop ro.build.version.release') return this.sdk >= 28 ? '14\n' : '8.1.0\n';
    if (cmd === 'pm list users') return 'Users:\n' + this.users.map((u) => `\tUserInfo{${u.id}:${u.name}:c13} running`).join('\n') + '\n';
    if (cmd === 'dumpsys device_policy') return this.devicePolicy();
    if ((m = cmd.match(/^dpm remove-active-admin --user (\d+) '([^']+)'$/))) {
      const i = this.admins.findIndex((a) => a.component === m[2] && a.user === Number(m[1]));
      if (i < 0) return `Error: java.lang.IllegalArgumentException: Unknown admin: ${m[2]}\n`;
      if (!this.admins[i].testOnly) return `Error: java.lang.SecurityException: Attempt to remove non-test admin ComponentInfo{${m[2]}} ${m[1]}\n`;
      this.admins.splice(i, 1);
      return 'Success: true\n';
    }
    if ((m = cmd.match(/^settings get (global|secure) (\S+)$/))) return `${this.settings[`${m[1]} ${m[2]}`] ?? 'null'}\n`;
    if ((m = cmd.match(/^settings put (global|secure) (\S+) '?([^']*)'?$/))) {
      if (!(this.ignoreDnsWrites && /private_dns/.test(m[2]))) this.settings[`${m[1]} ${m[2]}`] = m[3];
      return '';
    }
    if ((m = cmd.match(/^am force-stop (?:--user all )?(\S+)$/))) return '';
    if ((m = cmd.match(/^pm list packages -s (\S+)$/))) return this.pkgs.get(m[1])?.system ? `package:${m[1]}\n` : '';
    if ((m = cmd.match(/^pm list packages -d --user (\d+) (\S+)$/))) {
      const p = this.pkgs.get(m[2]);
      return p && p.users.has(Number(m[1])) && [2, 3, 4].includes(p.enabled[m[1]]) ? `package:${m[2]}\n` : '';
    }
    if ((m = cmd.match(/^pm list packages --user (\d+) (\S+) 2>&1$/))) {
      if (this.noAccessUsers.has(Number(m[1]))) return ex(`Shell does not have permission to access user ${m[1]}`);
      const p = this.pkgs.get(m[2]);
      return p && p.users.has(Number(m[1])) ? `package:${m[2]}\n` : '';
    }
    if ((m = cmd.match(/^pm uninstall (.*)$/))) {
      assert.ok(!/(^|\s)-k(\s|$)/.test(m[1]), 'pm uninstall -k keeps data and is not acceptable');
      const um = m[1].match(/^--user (\d+) (\S+)$/);
      assert.ok(um, `unexpected uninstall form: ${cmd}`);
      const [user, name] = [Number(um[1]), um[2]];
      if (this.noAccessUsers.has(user)) return ex(`Shell does not have permission to access user ${user}`);
      const p = this.pkgs.get(name);
      if (!p || !p.users.has(user)) return `Failure [not installed for ${user}]\n`;
      if (this.admins.some((a) => a.user === user && a.component.startsWith(name + '/'))) return 'Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]\n';
      if (this.uninstallError[user]) return this.uninstallError[user] + '\n';
      if (!this.lieAboutUninstall) p.users.delete(user);
      return 'Success\n';
    }
    if ((m = cmd.match(/^pm disable-user --user 0 (\S+)$/))) {
      if (this.owners.some((o) => o.component.startsWith(m[1] + '/'))) return `Error: java.lang.SecurityException: Cannot disable a protected package: ${m[1]}\n`;
      this.pkgs.get(m[1]).enabled[0] = 3;
      return `Package ${m[1]} new state: disabled-user\n`;
    }
    if ((m = cmd.match(/^pm clear --user 0 (\S+)$/))) return 'Success\n';
    if ((m = cmd.match(/^pm (un)?suspend --user 0 (\S+)$/))) {
      const p = this.pkgs.get(m[2]);
      const want = !m[1];
      // Android silently refuses to suspend active admins / owners: it prints the unchanged state.
      const refuse = want && this.admins.some((a) => a.component.startsWith(m[2] + '/'));
      if (!refuse) p.suspended[0] = want;
      return `Package ${m[2]} new suspended state: ${!!p.suspended[0]}\n`;
    }
    if ((m = cmd.match(/^pm path (\S+)$/))) {
      const p = this.pkgs.get(m[1]);
      return p && (p.users.size || p.system) ? `package:/data/app/~~x==/${m[1]}-y==/base.apk\n` : '';
    }
    if ((m = cmd.match(/^pm revoke (\S+) (\S+)$/))) {
      const p = this.pkgs.get(m[1]);
      if (p.install.has(m[2])) return ex(`Permission ${m[2]} requested by ${m[1]} is not a changeable permission type`);
      if (!p.runtime.has(m[2]) && !(p.requested ?? []).includes(m[2])) return ex(`Package ${m[1]} has not requested permission ${m[2]}`);
      p.runtime.delete(m[2]);
      return '';
    }
    if ((m = cmd.match(/^appops set (\S+) (\S+) (\S+)$/))) {
      if (this.unknownOps.has(m[2])) return `Error: Unknown operation string: ${m[2]}\n`;
      this.pkgs.get(m[1]).ops[m[2]] = m[3];
      return '';
    }
    if ((m = cmd.match(/^appops get (\S+)$/))) {
      return Object.entries(this.pkgs.get(m[1]).ops).map(([k, v]) => `${k}: ${v}; time=+1h2m ago`).join('\n') + '\n';
    }
    if (cmd === 'dumpsys deviceidle whitelist') return [...this.idle].map((p) => `user,${p},10301`).join('\n') + '\n';
    if ((m = cmd.match(/^dumpsys deviceidle whitelist -(\S+)$/))) { this.idle.delete(m[1]); return `Removed: ${m[1]}\n`; }
    if ((m = cmd.match(/^cmd netpolicy (.*)$/))) {
      assert.ok(!/set restrict-background/.test(m[1]), 'phone-wide Data Saver must never be switched on');
      const nm = m[1].match(/^add restrict-background-blacklist (\d+)$/);
      assert.ok(nm, `unexpected netpolicy command: ${cmd}`);
      this.netBlocked.add(Number(nm[1]));
      return '';
    }
    if ((m = cmd.match(/^am get-standby-bucket (\S+)$/))) return `${this.pkgs.get(m[1]).bucket}\n`;
    if ((m = cmd.match(/^am set-standby-bucket (\S+) (\S+)$/))) {
      this.pkgs.get(m[1]).bucket = BUCKETS[m[2]] ?? Number(m[2]);
      return '';
    }
    if ((m = cmd.match(/^dumpsys package (\S+)$/))) return this.dumpPackage(m[1]);
    throw new Error(`FakePhone: unhandled command: ${cmd}`);
  }

  devicePolicy() {
    const lines = ['Current Device Policy Manager state:'];
    for (const o of this.owners) {
      lines.push(o.kind === 'device' ? '  Device Owner: ' : `  Profile Owner (User ${o.user}): `, `    admin=ComponentInfo{${o.component}}`, '    name=', `    package=${o.component.split('/')[0]}`);
      if (o.kind === 'device') lines.push('    User ID: 0');
      lines.push('');
    }
    for (const u of [...new Set(this.admins.map((a) => a.user))]) {
      lines.push(`  Enabled Device Admins (User ${u}, provisioningState: 0):`);
      for (const a of this.admins.filter((x) => x.user === u)) lines.push(`    ${a.component}:`, '      uid=10301', `      testOnlyAdmin=${!!a.testOnly}`);
    }
    return lines.join('\n') + '\n';
  }

  dumpPackage(name) {
    const p = this.pkgs.get(name);
    if (!p) return `Unable to find package: ${name}\n`;
    const out = ['Packages:', `  Package [${name}] (4f2a1c):`, `    userId=${p.uid}`, `    codePath=/data/app/${name}-1`, '    install permissions:'];
    for (const perm of p.install) out.push(`      ${perm}: granted=true`);
    for (const u of this.users) {
      if (!p.users.has(u.id)) continue;
      out.push(`    User ${u.id}: ceDataInode=4242 installed=true hidden=false suspended=${!!p.suspended[u.id]} distractionFlags=0 stopped=false notLaunched=false enabled=${p.enabled[u.id] ?? 0} instant=false virtual=false`);
      out.push('      runtime permissions:');
      for (const perm of p.runtime) out.push(`        ${perm}: granted=true, flags=[ USER_SET ]`);
    }
    return out.join('\n') + '\n';
  }

  idx(re) {
    return this.log.findIndex((c) => re.test(c));
  }
}

let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${e.stack.split('\n').slice(0, 4).join('\n       ')}`); }
}
const SPY = 'com.systemservice';
const spyPhone = (o = {}) => new FakePhone({
  packages: { [SPY]: { runtime: [P + 'READ_SMS', P + 'RECORD_AUDIO', P + 'ACCESS_FINE_LOCATION', 'com.systemservice.permission.C2D'], ...(o.pkg ?? {}) }, ...(o.packages ?? {}) },
  settings: {
    'secure enabled_accessibility_services': `${SPY}/.Svc:com.google.android.marvin.talkback/.TalkBackService`,
    'secure enabled_notification_listeners': `${SPY}/.Notif`,
    ...(o.settings ?? {}),
  },
  ...o,
});
const manualText = (r) => r.manualSteps.join('\n');

// ---------- parsing ----------
test('device_policy parser: device owner, admins, 4-space nesting, leaves the admin list', () => {
  const r = parseDevicePolicy(fx('dumpsys-device-policy-device-owner.txt'));
  assert.deepEqual(r.owners, [{ kind: 'device', user: 0, component: 'com.evil.mdm/com.evil.mdm.AdminReceiver' }]);
  assert.deepEqual(r.admins.map((a) => [a.user, a.component, a.testOnly]), [
    [0, 'com.evil.mdm/.AdminReceiver', false],
    [0, 'com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver', false],
  ]);
});

test('device_policy parser: work-profile owner and per-user admins', () => {
  const r = parseDevicePolicy(fx('dumpsys-device-policy-work-profile.txt'));
  assert.deepEqual(r.owners, [{ kind: 'profile', user: 10, component: 'com.spy.work/com.spy.work.Owner' }]);
  assert.deepEqual(r.admins.map((a) => [a.user, a.component]), [[0, 'com.systemservice/.AdminReceiver'], [10, 'com.spy.work/.Owner']]);
});

test('pm list users parser', () => {
  const fake = { shell: () => fx('pm-list-users.txt') };
  assert.deepEqual(listUsers(fake), [{ id: 0, name: 'Owner' }, { id: 10, name: 'Work profile' }]);
});

test('uninstall failure strings are classified', () => {
  assert.equal(classifyUninstall('Success'), 'SUCCESS');
  assert.equal(classifyUninstall('Failure [not installed for 0]'), 'NOT_INSTALLED');
  for (const c of ['DELETE_FAILED_DEVICE_POLICY_MANAGER', 'DELETE_FAILED_OWNER_BLOCKED', 'DELETE_FAILED_USER_RESTRICTED', 'DELETE_FAILED_INTERNAL_ERROR']) assert.equal(classifyUninstall(`Failure [${c}]`), c);
  assert.equal(classifyUninstall("Exception occurred while executing 'uninstall':\njava.lang.SecurityException: Shell does not have permission to access user 10"), 'NO_ACCESS_TO_USER');
});

test('package names that could inject shell are refused before any adb call', () => {
  for (const bad of ['com.foo; reboot', 'com.foo$(id)', "com.foo'", 'com', '-k com.foo', 'com.foo\nreboot', '']) {
    assert.throws(() => assertPackageName(bad));
    const phone = spyPhone();
    assert.throws(() => removeApp(phone, bad));
    assert.throws(() => blockApp(phone, bad));
    assert.equal(phone.log.length, 0, `no command may run for ${JSON.stringify(bad)}`);
  }
});

// ---------- removal ----------
test('removal order: admin -> accessibility -> notification listener -> force-stop -> uninstall, every user, no -k', () => {
  const phone = spyPhone({
    users: [{ id: 0, name: 'Owner' }, { id: 10, name: 'Work profile' }],
    admins: [{ user: 0, component: `${SPY}/.Admin`, testOnly: true }],
    pkg: { users: new Set([0, 10]) },
  });
  const r = removeApp(phone, SPY);
  const order = [/^dpm remove-active-admin/, /enabled_accessibility_services '/, /enabled_notification_listeners '/, /^am force-stop/, /^pm uninstall --user 0/].map((re) => phone.idx(re));
  assert.ok(order.every((i) => i >= 0), `all steps ran: ${order}`);
  assert.deepEqual([...order].sort((a, b) => a - b), order, `order was ${order}`);
  assert.ok(phone.idx(/^pm uninstall --user 10 /) > 0, 'work profile copy uninstalled too');
  assert.equal(phone.settings['secure enabled_accessibility_services'], 'com.google.android.marvin.talkback/.TalkBackService', 'other accessibility services untouched');
  assert.equal(r.ok, true);
  assert.equal(r.removed, true);
  assert.equal(r.disabled, false);
  assert.deepEqual(r.manualSteps, []);
  for (const k of ['ok', 'removed', 'disabled', 'steps', 'manualSteps']) assert.ok(k in r, `result has ${k}`);
});

test('non-test device admin: dpm tried once, Settings path given, uninstall refused, app disabled instead', () => {
  const phone = spyPhone({ admins: [{ user: 0, component: `${SPY}/.Admin`, testOnly: false }] });
  const r = removeApp(phone, SPY);
  assert.equal(phone.log.filter((c) => c.startsWith('dpm ')).length, 1, 'never loops on dpm');
  assert.equal(phone.log.filter((c) => c.startsWith('pm uninstall')).length, 1, 'never loops on uninstall');
  assert.match(manualText(r), /Device admin apps/);
  assert.match(manualText(r), /Deactivate/);
  assert.equal(r.manualSteps.length, 1, `one clear instruction, got ${JSON.stringify(r.manualSteps)}`);
  assert.equal(r.removed, false);
  assert.equal(r.disabled, true, 'falls back to disable');
  assert.equal(r.ok, true, 'disabled counts as neutralised');
  assert.ok(phone.idx(/^pm clear --user 0/) > 0, 'data wiped');
});

test('device owner: factory reset is stated as the only way; nothing loops; honest failure', () => {
  const comp = `${SPY}/${SPY}.Owner`;
  const phone = spyPhone({ owners: [{ kind: 'device', user: 0, component: comp }], admins: [{ user: 0, component: `${SPY}/.Owner`, testOnly: false }] });
  const r = removeApp(phone, SPY);
  assert.equal(phone.log.filter((c) => c.startsWith('dpm ')).length, 1);
  assert.match(manualText(r), /device owner/);
  assert.match(manualText(r), /factory reset is the only way/i);
  assert.match(manualText(r), /Erase all data/);
  assert.equal(r.manualSteps.length, 1, 'no duplicate DPM advice after the owner advice');
  assert.equal(r.removed, false);
  assert.equal(r.disabled, false, 'protected package cannot be disabled');
  assert.equal(r.suspended, false, 'Android refused the suspension and the read-back shows it');
  assert.equal(r.ok, false);
  assert.match(r.steps.at(-1).text, /Removal FAILED/);
});

test('work-profile owner: remove the work profile, factory reset only if that is refused', () => {
  const phone = spyPhone({
    users: [{ id: 0, name: 'Owner' }, { id: 10, name: 'Work profile' }],
    owners: [{ kind: 'profile', user: 10, component: `${SPY}/${SPY}.Owner` }],
    admins: [{ user: 10, component: `${SPY}/.Owner`, testOnly: false }],
    pkg: { users: new Set([10]) },
  });
  const r = removeApp(phone, SPY);
  assert.match(manualText(r), /Remove work profile/);
  assert.match(manualText(r), /factory reset is the only way/);
  assert.equal(r.ok, false, 'still installed and enabled in the work profile');
});

for (const [code, re] of [
  ['DELETE_FAILED_OWNER_BLOCKED', /blocked uninstalling/],
  ['DELETE_FAILED_USER_RESTRICTED', /no uninstall apps/],
  ['DELETE_FAILED_INTERNAL_ERROR', /Restart the phone/],
]) {
  test(`${code}: plain next step, disabled as fallback`, () => {
    const phone = spyPhone({ uninstallError: { 0: `Failure [${code}]` } });
    const r = removeApp(phone, SPY);
    assert.match(manualText(r), re);
    assert.equal(r.disabled, true);
    assert.equal(r.removed, false);
    assert.ok(r.steps.some((s) => !s.ok && s.text.includes(code)), 'the raw Android answer is shown');
  });
}

test('"not installed for 0": only the work-profile copy is removed', () => {
  const phone = spyPhone({ users: [{ id: 0, name: 'Owner' }, { id: 10, name: 'Work profile' }], pkg: { users: new Set([10]) } });
  const r = removeApp(phone, SPY);
  assert.equal(phone.idx(/^pm uninstall --user 0 /), -1, 'no pointless uninstall for user 0');
  assert.ok(phone.idx(/^pm uninstall --user 10 /) >= 0);
  assert.equal(r.removed, true);
  assert.equal(r.ok, true);
});

test('work profile the shell may not touch: user 0 cleaned, Work-tab instructions, not claimed fully removed', () => {
  const phone = spyPhone({ users: [{ id: 0, name: 'Owner' }, { id: 10, name: 'Work profile' }], noAccessUsers: [10] });
  const r = removeApp(phone, SPY);
  assert.equal(r.removed, false);
  assert.equal(r.ok, true);
  assert.match(manualText(r), /Work tab/);
});

test('system app: removed for the user, factory copy explained', () => {
  const phone = spyPhone({ pkg: { system: true } });
  const r = removeApp(phone, SPY);
  assert.equal(r.removed, true);
  assert.equal(r.system, true);
  assert.match(r.steps.at(-1).text, /factory copy/);
});

test('verification reads the phone back: a "Success" that did not happen is reported as FAILED', () => {
  const phone = spyPhone({ lieAboutUninstall: true });
  const r = removeApp(phone, SPY);
  assert.equal(r.ok, false);
  assert.equal(r.removed, false);
  assert.match(r.steps.at(-1).text, /Removal FAILED/);
  assert.ok(r.manualSteps.length >= 1, 'gives the person something to do');
});

// ---------- disarm ----------
test('blockApp (Android 14): revokes granted + dangerous, app-ops ignore, per-uid data block, restricted bucket, suspended, verified', () => {
  const phone = spyPhone({ unknownOps: ['BIND_ACCESSIBILITY_SERVICE'], idle: [SPY] });
  const granted = [P + 'READ_SMS', P + 'RECORD_AUDIO', P + 'ACCESS_FINE_LOCATION', P + 'INTERNET', 'com.systemservice.permission.C2D'];
  const r = blockApp(phone, SPY, { uid: 10301, granted });
  const p = phone.pkgs.get(SPY);
  assert.deepEqual([...p.runtime], [], 'every runtime grant revoked, custom ones included');
  for (const op of BLOCK_APPOPS.filter((o) => o !== 'BIND_ACCESSIBILITY_SERVICE')) assert.equal(p.ops[op], 'ignore', op);
  assert.ok(r.steps.some((s) => /Not available on this Android version: BIND_ACCESSIBILITY_SERVICE/.test(s.text)), 'missing op reported, not fatal');
  assert.ok(!r.steps.some((s) => !s.ok && /INTERNET/.test(s.action)), 'install-time permission is not reported as a failure');
  assert.ok(phone.netBlocked.has(10301));
  assert.equal(p.bucket, 45, 'restricted bucket');
  assert.equal(p.suspended[0], true);
  assert.ok(!phone.idle.has(SPY), 'battery exemption removed');
  assert.equal(r.ok, true, JSON.stringify(r.steps.at(-1)));
  assert.equal(r.suspended, true);
  assert.equal(r.previousBucket, '10');
  assert.match(r.steps.at(-1).text, /suspended/);
});

test('blockApp (Android 10): rare bucket instead of restricted', () => {
  const phone = spyPhone({ sdk: 29 });
  const r = blockApp(phone, SPY, { uid: 10301 });
  assert.equal(phone.pkgs.get(SPY).bucket, 40);
  assert.equal(r.ok, true);
});

test('blockApp (Android 8.1): no suspend or bucket attempted, warned honestly', () => {
  const phone = spyPhone({ sdk: 27 });
  const r = blockApp(phone, SPY, { uid: 10301 });
  assert.equal(phone.idx(/^pm suspend/), -1);
  assert.equal(phone.idx(/set-standby-bucket/), -1);
  assert.match(r.warnings.join(' '), /Android 9 or newer/);
  assert.equal(r.ok, true, 'permissions revoked is the best possible on 8.1');
});

test('blockApp: suspension refused (active admin) -> not ok, manual steps', () => {
  const phone = spyPhone({ admins: [{ user: 0, component: `${SPY}/.Admin`, testOnly: false }] });
  const r = blockApp(phone, SPY, { uid: 10301 });
  assert.equal(r.suspended, false);
  assert.equal(r.ok, false);
  assert.match(manualText(r), /Device admin apps/);
  assert.match(manualText(r), /Don't allow/);
});

test('undoBlock: un-suspends and restores the bucket; permissions stay revoked', () => {
  const phone = spyPhone();
  const b = blockApp(phone, SPY, { uid: 10301 });
  const u = undoBlock(phone, SPY, { previousBucket: b.previousBucket });
  const p = phone.pkgs.get(SPY);
  assert.equal(u.ok, true);
  assert.equal(p.suspended[0], false);
  assert.equal(p.bucket, 10);
  assert.ok(!p.runtime.has(P + 'READ_SMS'), 'still revoked');
});

// ---------- protect ----------
test('Private DNS: refused politely below Android 9, nothing written', () => {
  const phone = spyPhone({ sdk: 27 });
  const r = setDnsProtection(phone, 'quad9');
  assert.equal(r.ok, false);
  assert.equal(r.unsupported, true);
  assert.equal(phone.idx(/^settings put/), -1);
  assert.match(r.steps[0].text, /Android 9 or newer/);
});

test('Private DNS: set, both values read back, corporate Wi-Fi warning; clear -> opportunistic', () => {
  const phone = spyPhone();
  const r = setDnsProtection(phone, 'quad9');
  assert.equal(r.ok, true);
  assert.equal(phone.settings['global private_dns_mode'], 'hostname');
  assert.equal(phone.settings['global private_dns_specifier'], 'dns.quad9.net');
  assert.ok(phone.idx(/^settings get global private_dns_mode$/) > phone.idx(/^settings put global private_dns_mode/), 'mode read back after write');
  assert.match(r.warnings.join(' '), /Wi-Fi/);
  const c = clearDnsProtection(phone);
  assert.equal(c.ok, true);
  assert.equal(phone.settings['global private_dns_mode'], 'opportunistic');
});

test('Private DNS: a phone that ignores the write is reported, with manual steps', () => {
  const phone = spyPhone({ ignoreDnsWrites: true });
  const r = setDnsProtection(phone, 'adguard');
  assert.equal(r.ok, false);
  assert.match(manualText(r), /Private DNS provider hostname/);
});

// ---------- device fixes ----------
test('device fixes: allowlisted settings pass; anything else is refused before reaching the phone', () => {
  const phone = spyPhone();
  for (const ok of ['settings put global package_verifier_enable 1', 'settings put global development_settings_enabled 0', 'settings put secure install_non_market_apps 0', 'settings put global verifier_verify_adb_installs 1', 'settings put global private_dns_mode opportunistic']) {
    assert.equal(applyDeviceFix(phone, ok).ok, true, ok);
  }
  const n = phone.log.length;
  for (const bad of [
    'settings put global adb_enabled 0',
    'settings put global package_verifier_enable 0',
    'settings put secure enabled_accessibility_services evil/.S',
    'settings put global private_dns_mode hostname',
    'settings put global development_settings_enabled 0; reboot',
    'settings put global development_settings_enabled 0\nreboot',
    'pm uninstall com.android.settings',
  ]) assert.throws(() => applyDeviceFix(phone, bad), undefined, bad);
  assert.equal(phone.log.length, n, 'refused fixes never reach the phone');
});

console.log(`\n${passed} passed, ${failures.length} failed${failures.length ? ': ' + failures.join(', ') : ''}`);
process.exit(failures.length ? 1 : 0);
