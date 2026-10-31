// Turns a collected snapshot + indicator lists into findings with scores.
//
// ============================== SCORING TABLE ==============================
// Bands: >=70 CRITICAL (remove) | 40-69 SUSPICIOUS (review) | 20-39 WATCH (note) | <20 OK. Max 100.
//
// Certain (any install source, system apps included):
//   Package / APK hash / signing cert on the known list (Echap or built-in RAT list)   100
//   Signing-certificate organisation on the known list                                 100
//   VirusTotal: >=3 engines malicious 100 | 1-2 engines 30
//
// Install source decides how much behaviour counts ("tier"):
//   sideloaded (no store, browser/file manager, adb)  -> SIDE column
//   from an app store                                  -> STORE column (about a third)
//   from a major store AND on the KNOWN_APPS list      -> rights its category expects score 0,
//                                                          anything else uses the STORE column
//   system app                                         -> behaviour not scored
//
//   signal                                                       SIDE  STORE  tag
//   accessibility service ON                                       35    12   access
//   device administrator                                           25     9   admin
//   notification access                                            20     7   notif
//   usage access                                                    8     3   usage
//   battery-optimisation exempt                                    10     4   battery
//   microphone / camera / SMS / call log                      8/5/10/10 3/2/4/4 perm
//   location / contacts / files                                  6/4/2  2/2/1  perm
//   4+ surveillance kinds at once                                  15     0   combo
//   draw over apps / install apps                                 8/8   3/3   perm
//   READ_LOGS granted (only possible via adb/root) | requested   20|5   7|2   logs
//   asks for system-only capture rights (CAPTURE_VIDEO_OUTPUT..)   15     5   capture
//   screen-capture (media projection) service | capturing now   8|25  3|10   projection
//   asks to disable lock screen                                     5     2   perm
//   no launcher icon (25 if it also has 2+ surveillance kinds
//     or accessibility, else 10)                                25|10    3   hidden
//   hidden flag set by the system                                  15    15   hidden
//   device admin AND no icon (classic stalkerware)                 20     7   adminhidden
//   accessibility + overlay + install apps (dropper / banking
//     trojan pattern: Anatsa, Hook, Cerberus families)             25     8   dropper
//   starts at boot + foreground service + no icon                  15     5   persist
//   uploads >= 20 MB and >= 4x what it downloads, no icon          20     7   upload
//   not from an app store                                          15     -   sideload
//   installed over USB/adb (com.android.shell)                     10     -   adb
//   installed <14 days ago by adb/unknown installer 10 | other
//     sideload <30 days 5                                        10|5     -   recent
//   package or label imitates a system component                   15     0   mimic
//   label is a system-app name that the package name does not
//     match (e.g. "Google Services" in com.xq.tracker)             25     8   labelmimic
//   random-looking package name (entropy heuristic)                15     0   random
//   debug build                                                     5     2   debug
//   running with no icon                                            5     0   running
//   is the default keyboard / default SMS app                    20/10    0   ime / sms
//   remote-control or monitoring app on the KNOWN_APPS list    25 (informational, any tier)  remote / monitor
//
// Calibration targets (enforced by test/run.mjs and test/rules.test.mjs):
//   hidden + sideloaded + accessibility + SMS + mic                  >= 70 (93)
//   same rights, Play-installed, with an icon                        <  40 (18)
//   every app in test/fixtures/clean (a typical phone)               <  20, except remote-control /
//                                                                      monitoring apps (informational WATCH)
// ===========================================================================

import { knownApp, MONITOR_LABELS, CREDIT_STORES } from './iocs.mjs';

const P = 'android.permission.';
const SURVEILLANCE = {
  mic: [P + 'RECORD_AUDIO', P + 'CAPTURE_AUDIO_OUTPUT'],
  camera: [P + 'CAMERA'],
  sms: [P + 'READ_SMS', P + 'RECEIVE_SMS', P + 'RECEIVE_MMS', P + 'SEND_SMS'],
  calls: [P + 'READ_CALL_LOG', P + 'PROCESS_OUTGOING_CALLS', P + 'READ_PHONE_STATE', P + 'ANSWER_PHONE_CALLS'],
  location: [P + 'ACCESS_FINE_LOCATION', P + 'ACCESS_BACKGROUND_LOCATION'],
  contacts: [P + 'READ_CONTACTS', P + 'READ_CALENDAR'],
  storage: [P + 'READ_EXTERNAL_STORAGE', P + 'MANAGE_EXTERNAL_STORAGE', P + 'READ_MEDIA_IMAGES'],
};
const SURVEILLANCE_ALL = new Set(Object.values(SURVEILLANCE).flat());
const CONTROL = {
  overlay: P + 'SYSTEM_ALERT_WINDOW',
  install: P + 'REQUEST_INSTALL_PACKAGES',
  boot: P + 'RECEIVE_BOOT_COMPLETED',
  accessibility: P + 'BIND_ACCESSIBILITY_SERVICE',
  foreground: P + 'FOREGROUND_SERVICE',
  projection: P + 'FOREGROUND_SERVICE_MEDIA_PROJECTION',
  readLogs: P + 'READ_LOGS',
  disableKeyguard: P + 'DISABLE_KEYGUARD',
};
const SYSTEM_ONLY_CAPTURE = [P + 'CAPTURE_VIDEO_OUTPUT', P + 'CAPTURE_SECURE_VIDEO_OUTPUT', P + 'CAPTURE_AUDIO_OUTPUT'];

// SIDE / STORE points per signal (see table above).
const W = {
  access: [35, 12], admin: [25, 9], notif: [20, 7], usage: [8, 3], battery: [10, 4],
  mic: [8, 3], camera: [5, 2], sms: [10, 4], calls: [10, 4], location: [6, 2], contacts: [4, 2], storage: [2, 1],
  overlay: [8, 3], install: [8, 3], readLogs: [20, 7], readLogsAsk: [5, 2], capture: [15, 5], projection: [8, 3],
  projecting: [25, 10], keyguard: [5, 2], hiddenStrong: [25, 3], hiddenWeak: [10, 3], hiddenFlag: [15, 15],
  adminHidden: [20, 7], dropper: [25, 8], persist: [15, 5], upload: [20, 7], combo: [15, 0], mimic: [15, 0],
  labelMimic: [25, 8], random: [15, 0], debug: [5, 2], running: [5, 0], ime: [20, 0], smsDefault: [10, 0],
};
const ADB_INSTALLERS = new Set(['com.android.shell', 'adb']);
const MIMIC = /(^|\.)(system|service|services|sync|update|updater|settings|wifi|android|google|security|device|phone|cloud|backup|monitor)(\.|$)/i;
// Labels that only the OS or the phone maker should be using.
const SYSTEM_LABEL = /^(android( system| services?| system webview| update| security)?|system( update| service| services| ui| settings| manager)?|google( play)?( services?)?|play services|google services framework|settings|wi-?fi( service| update)?|software update|security update|update service|device (care|health|services?|manager)|sync service|battery service|services?|phone services?|sim toolkit|carrier services)$/i;
const TLD = new Set(['com', 'org', 'net', 'io', 'app', 'me', 'co', 'de', 'uk', 'jp', 'ru', 'cn', 'in', 'br', 'fr', 'info', 'xyz', 'dev', 'android']);

function words(s) {
  return (s || '').toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3);
}
// Common acronyms with no vowels that appear in real package names (openvpn, smsbackup, pdfreader).
const ACRONYMS = /vpn|sms|mms|pdf|gps|xml|html?|sdk|nfc|dns|ftp|ssh|mp[34]|tv|hd|qr|wsj|nyt|bbc|cnn|hbo|bbva|kms|dkb|ttx|vlc|mx/g;
function letters(seg) {
  return seg.toLowerCase().replace(/[^a-z]/g, '').replace(ACRONYMS, '');
}
// Random-looking segment: few vowels or long consonant runs (y counts as a consonant).
function randomishSegment(seg) {
  const s = letters(seg);
  if (s.length < 5) return false;
  const vowels = (s.match(/[aeiou]/g) || []).length / s.length;
  const run = Math.max(0, ...(s.match(/[^aeiou]+/g) || []).map((r) => r.length));
  return vowels < 0.2 || run >= 5 || (vowels < 0.3 && run >= 4);
}
function strongRandomSegment(seg) {
  const s = letters(seg);
  if (s.length < 8) return false;
  const vowels = (s.match(/[aeiou]/g) || []).length / s.length;
  const run = Math.max(0, ...(s.match(/[^aeiou]+/g) || []).map((r) => r.length));
  return vowels < 0.2 && run >= 4;
}
/** True for names like com.abcxyz.qwerty or com.zxkhoxrgdfm.fnyjxklj. Exported for tests. */
export function looksRandom(pkg) {
  const segs = pkg.split('.').filter((s, i) => !(i === 0 && TLD.has(s)));
  const flagged = segs.filter(randomishSegment);
  return flagged.length >= 2 || segs.some(strongRandomSegment);
}
/** Label claims to be a system component and the package name shares no word with it. Exported for tests. */
export function labelImitatesSystem(label, pkg) {
  if (!label || !SYSTEM_LABEL.test(label.trim())) return false;
  const pk = new Set(words(pkg));
  return !words(label).some((w) => pk.has(w));
}

function refNow(snapshot) {
  const s = Number(snapshot?.device?.now);
  return Number.isFinite(s) && s > 1e9 ? s * 1000 : Date.now();
}
function daysSince(dateStr, now) {
  const t = Date.parse(dateStr);
  return Number.isFinite(t) ? (now - t) / 86_400_000 : null;
}
function initiator(p) {
  return p.installInitiator ?? p.initiatingInstaller ?? p.installInitiatingPackageName ?? null;
}
function mb(bytes) {
  return `${Math.round(bytes / 1048576)} MB`;
}

export function analyze(snapshot, iocs, { certs = new Map(), labels = new Map(), vt = new Map(), certOrgs = new Map() } = {}) {
  const accPkgs = new Set((snapshot.accessibility || []).map((a) => a.pkg));
  const nlPkgs = new Set((snapshot.notificationListeners || []).map((a) => a.pkg));
  const adminPkgs = new Set((snapshot.deviceAdmins || []).map((a) => a.pkg));
  const idle = new Set(snapshot.idleWhitelist || []);
  const usage = new Set(snapshot.usageAccess || []);
  const running = new Set(snapshot.running || []);
  const projecting = new Set((snapshot.mediaProjection || []).map((x) => (typeof x === 'string' ? x : x.pkg)));
  const dev = snapshot.device || {};
  const imePkg = (dev.defaultIme || '').split('/')[0];
  const smsPkg = snapshot.roles?.sms?.[0] || dev.defaultSms || '';
  // Accessibility services that the volume-key shortcut / on-screen button can switch on later.
  const accShortcut = new Set((snapshot.accessibilityShortcutTargets || []).map((a) => a.pkg));
  const now = refNow(snapshot);

  const apps = [];
  for (const p of snapshot.packages) {
    const reasons = [];
    let score = 0;
    const add = (pts, text, tag) => { score += pts; reasons.push({ pts, text, tag }); };
    const label = labels.get(p.pkg) || p.label || null;
    const granted = new Set(p.granted || []);
    const requested = new Set(p.requested || []);
    const has = (perm) => granted.has(perm) || requested.has(perm);

    // --- Install source ---
    const init = initiator(p);
    const viaAdb = ADB_INSTALLERS.has(p.installer) || ADB_INSTALLERS.has(init);
    // An installer field claiming a store while the install was initiated over adb (`adb install -i`) is not a store install.
    const sideloaded = !p.system && (p.sideloaded || viaAdb);
    const tier = p.system ? 'system' : sideloaded ? 'side' : 'store';
    const kn = knownApp(p.pkg);
    const credited = kn && (p.system || (tier === 'store' && CREDIT_STORES.has(p.installer || init)));
    const known = credited ? kn : null;
    const expected = [];
    // Behaviour signal: skipped if the app's known category needs it, else SIDE or STORE points.
    const sig = (key, w, text, tag, expectKeys = [key]) => {
      if (known && expectKeys.every((k) => known.expects.has(k))) { expected.push(key); return; }
      const pts = tier === 'side' ? w[0] : w[1];
      if (pts > 0) add(pts, text, tag);
    };

    // --- Known-bad indicators (certain) ---
    const knownPkg = iocs.packages.get(p.pkg);
    if (knownPkg) add(100, `Package name is on the known stalkerware/RAT list (${knownPkg})`, 'ioc');
    if (p.sha256 && iocs.sha256.has(p.sha256)) add(100, `App file hash matches known stalkerware (${iocs.sha256.get(p.sha256)})`, 'ioc');
    const certVal = certs.get(p.pkg);
    const cert = typeof certVal === 'object' && certVal ? certVal.sha1 : certVal;
    if (cert && iocs.certSha1.has(cert)) add(100, `Signed with a certificate used by known stalkerware (${iocs.certSha1.get(cert)})`, 'ioc');
    const org = (certOrgs.get(p.pkg) || (typeof certVal === 'object' && certVal ? certVal.org : '') || '').trim().toLowerCase();
    if (org && iocs.certOrgs?.has(org)) add(100, `Signed by an organisation that makes known stalkerware (${iocs.certOrgs.get(org)})`, 'ioc');

    const vtHit = p.sha256 && vt.get(p.sha256);
    if (vtHit?.known && vtHit.malicious >= 3) add(100, `Flagged as malicious by ${vtHit.malicious} of ${vtHit.total} antivirus engines on VirusTotal`, 'vt');
    else if (vtHit?.known && vtHit.malicious + vtHit.suspicious >= 1) add(30, `Flagged by ${vtHit.malicious + vtHit.suspicious} antivirus engine(s) on VirusTotal`, 'vt');

    // --- Informational: legitimate apps that give someone else access (any install source) ---
    const activeSystem = p.system && (adminPkgs.has(p.pkg) || accPkgs.has(p.pkg));
    if (p.system && !activeSystem) {
      // preinstalled and not switched on: part of the firmware, not something someone added
    } else if (kn?.notice === 'remote') {
      add(25, `Remote-control app (${kn.name}). This is fine if you installed it yourself; if you did not, someone could use it to see and control your screen. Remove it if you do not recognise it`, 'remote');
    } else if (kn?.notice === 'monitor') {
      add(25, `Monitoring app (${kn.name}): it lets another person see this phone's activity or location. Fine if you set it up or agreed to it (for example for your child); make sure you consented. If you did not, treat it as spyware`, 'monitor');
    } else if (kn?.notice === 'parent') {
      add(0, `${kn.name}: lets you supervise another person's phone; it does not watch this one`, 'parent');
    } else if (!kn && label && MONITOR_LABELS.some(([re]) => re.test(label))) {
      const name = MONITOR_LABELS.find(([re]) => re.test(label))[1];
      add(25, `Looks like a monitoring app (${name}): it lets another person see this phone's activity. Make sure you consented to it`, 'monitor');
    }

    // --- Behaviour heuristics (not for plain system apps) ---
    let cats = [];
    if (!p.system) {
      if (known) add(0, `Recognised as ${known.name || 'an app'} (${known.what}), installed from ${p.installer || init}: the rights it needs for that are not counted`, 'known');

      const hasIcon = p.hasLauncherIcon !== false;
      const accOn = accPkgs.has(p.pkg);
      const accDeclared = accOn || accShortcut.has(p.pkg) || requested.has(CONTROL.accessibility) || (p.accessibilityServices?.length > 0);
      if (accOn) sig('access', W.access, 'Accessibility service is ON: can read everything on screen and tap for you', 'access');
      if (adminPkgs.has(p.pkg)) sig('admin', W.admin, 'Device administrator: can lock/wipe the phone and resist uninstall', 'admin');
      if (nlPkgs.has(p.pkg)) sig('notif', W.notif, 'Notification access: reads all incoming notifications and messages', 'notif');
      if (usage.has(p.pkg)) sig('usage', W.usage, 'Usage access: sees which apps you open and when', 'usage');
      if (idle.has(p.pkg)) sig('battery', W.battery, 'Excluded from battery optimisation: stays alive in background', 'battery');

      cats = Object.entries(SURVEILLANCE).filter(([, perms]) => perms.some((x) => granted.has(x))).map(([k]) => k);
      const catText = { mic: 'Can record with the microphone', camera: 'Can use the camera', sms: 'Can read and send text messages (SMS)', calls: 'Can read the call log and phone state', location: 'Can track your location', contacts: 'Can read contacts and calendar', storage: 'Can read files and photos' };
      for (const c of cats) sig(c, W[c], catText[c], 'perm');
      const catShort = { mic: 'microphone', camera: 'camera', sms: 'SMS', calls: 'calls', location: 'location', contacts: 'contacts', storage: 'files' };
      if (cats.length >= 4) sig('combo', W.combo, `Holds ${cats.length} kinds of surveillance access at once (${cats.map((c) => catShort[c]).join(', ')})`, 'combo', cats);

      const overlay = granted.has(CONTROL.overlay);
      const install = has(CONTROL.install);
      if (overlay) sig('overlay', W.overlay, 'Can draw over other apps (fake login screens, hidden taps)', 'perm');
      if (install) sig('install', W.install, 'Can install other apps', 'perm');
      if (granted.has(CONTROL.readLogs)) sig('readLogs', W.readLogs, 'Has been granted access to system logs (only possible over USB or with root): can read what other apps log', 'logs');
      else if (requested.has(CONTROL.readLogs)) sig('readLogs', W.readLogsAsk, 'Asks to read system logs', 'logs');
      const capture = SYSTEM_ONLY_CAPTURE.filter((x) => requested.has(x) || granted.has(x));
      if (capture.length) sig('capture', W.capture, `Asks for screen/audio capture rights that only system apps can have (${capture.map((x) => x.replace(P, '')).join(', ')}): typical of spyware that records the screen or calls`, 'capture', ['projection']);
      if (projecting.has(p.pkg)) sig('projection', W.projecting, 'Is capturing or sharing your screen right now', 'projection');
      else if (has(CONTROL.projection)) sig('projection', W.projection, 'Has a screen-capture service (can record or stream your screen once you allow it)', 'projection');
      if (requested.has(CONTROL.disableKeyguard)) sig('keyguard', W.keyguard, 'Asks to disable the lock screen', 'perm', ['admin']);

      if (!hasIcon) {
        const strong = cats.length >= 2 || accOn;
        sig('hidden', strong ? W.hiddenStrong : W.hiddenWeak, 'No app icon in the launcher: hidden from you', 'hidden');
        if (adminPkgs.has(p.pkg)) sig('adminHidden', W.adminHidden, 'Device administrator with no icon: the classic stalkerware set-up (hard to find, hard to remove)', 'adminhidden', ['admin', 'hidden']);
        if (has(CONTROL.boot) && has(CONTROL.foreground)) sig('persist', W.persist, 'Starts itself when the phone boots and keeps a background service running, with no icon', 'persist', ['hidden']);
        if (running.has(p.pkg)) sig('running', W.running, 'Running right now despite having no icon', 'running', ['hidden']);
        const net = snapshot.netstats?.[String(p.uid)];
        if (net && net.tx >= 20 * 1048576 && net.tx >= 4 * Math.max(net.rx, 1)) {
          sig('upload', W.upload, `Sent ${mb(net.tx)} but received only ${mb(net.rx)}, with no icon: looks like it is uploading data from this phone`, 'upload', ['hidden']);
        }
      }
      if (accDeclared && overlay && install) {
        sig('dropper', W.dropper, 'Accessibility + draw over apps + install apps: the pattern of banking trojans and droppers (Anatsa, Hook, Cerberus families)', 'dropper', ['access', 'overlay', 'install']);
      }
      if (p.hidden) add(W.hiddenFlag[tier === 'side' ? 0 : 1], 'Marked hidden by the system for this user', 'hidden');

      if (tier === 'side') {
        const src = viaAdb ? 'installed over USB with adb' : p.installer ? `installed by ${p.installer}` : 'installer unknown: browser download or file manager';
        add(15, `Not installed from an app store (${src})`, 'sideload');
        if (viaAdb) add(10, 'Installed from a computer over USB (adb), which needs the phone in hand and unlocked', 'adb');
        const age = daysSince(p.firstInstall, now);
        if (age !== null && age >= -1 && age < 14 && (viaAdb || !p.installer)) add(10, `Installed ${Math.max(0, Math.round(age))} days ago from an unknown source`, 'recent');
        else if (age !== null && age >= -1 && age < 30) add(5, `Installed recently (${Math.max(0, Math.round(age))} days ago)`, 'recent');
        if (looksRandom(p.pkg)) add(W.random[0], `Package name looks randomly generated (${p.pkg}), typical of malware builders`, 'random');
      }
      const labelMimic = labelImitatesSystem(label, p.pkg);
      if (labelMimic) sig('labelMimic', W.labelMimic, `Calls itself "${label}" but its package name (${p.pkg}) does not match: pretends to be part of the phone's system`, 'labelmimic', ['__never']);
      else if (MIMIC.test(p.pkg) || (label && MIMIC.test(label))) sig('mimic', W.mimic, `Name imitates a system component ("${label || p.pkg}")`, 'mimic', ['__never']);
      if (p.debuggable) sig('debug', W.debug, 'Built in debug mode (typical of home-made RAT payloads)', 'debug', ['__never']);
      if (p.pkg === imePkg) sig('ime', W.ime, 'Is your keyboard: sees everything you type, including passwords', 'ime');
      if (p.pkg === smsPkg) sig('sms', W.smsDefault, 'Is your default SMS app: receives every text message, including login codes', 'sms');
    }

    const certain = reasons.some((r) => r.tag === 'ioc' || (r.tag === 'vt' && r.pts >= 100));
    const final = certain ? 100 : Math.min(100, score);
    apps.push({
      pkg: p.pkg,
      label: label || known?.name || null,
      score: final,
      level: final >= 70 ? 'CRITICAL' : final >= 40 ? 'SUSPICIOUS' : final >= 20 ? 'WATCH' : 'OK',
      reasons: reasons.sort((a, b) => b.pts - a.pts),
      category: known?.category || null,
      system: p.system,
      sideloaded,
      installer: p.installer,
      firstInstall: p.firstInstall,
      versionName: p.versionName,
      uid: p.uid,
      apkPath: p.apkPath,
      sha256: p.sha256,
      cert: cert || null,
      virusTotal: vtHit || null,
      hasLauncherIcon: p.hasLauncherIcon,
      accessibility: (snapshot.accessibility || []).filter((a) => a.pkg === p.pkg).map((a) => a.component),
      notificationListeners: (snapshot.notificationListeners || []).filter((a) => a.pkg === p.pkg).map((a) => a.component),
      deviceAdmins: (snapshot.deviceAdmins || []).filter((a) => a.pkg === p.pkg).map((a) => a.component),
      dangerousGranted: (p.granted || []).filter((g) => SURVEILLANCE_ALL.has(g) || g === CONTROL.overlay),
      networkBytes: (() => { const n = snapshot.netstats?.[String(p.uid)]; return n ? n.rx + n.tx : 0; })(),
      running: running.has(p.pkg),
    });
  }
  apps.sort((a, b) => b.score - a.score || a.pkg.localeCompare(b.pkg));

  const deviceFindings = deviceChecks(snapshot, iocs, apps, now);
  const flagged = apps.filter((a) => a.level !== 'OK');
  return {
    device: dev,
    deviceFindings,
    apps,
    flagged,
    summary: {
      total: apps.length,
      thirdParty: apps.filter((a) => !a.system).length,
      critical: apps.filter((a) => a.level === 'CRITICAL').length,
      suspicious: apps.filter((a) => a.level === 'SUSPICIOUS').length,
      watch: apps.filter((a) => a.level === 'WATCH').length,
      iocCount: iocs.count,
      iocUpdated: iocs.source?.updated || null,
    },
  };
}

function usersOf(snapshot) {
  const u = snapshot.users ?? snapshot.device?.users ?? null;
  if (!Array.isArray(u)) return null;
  return u.map((x) => (typeof x === 'object' && x ? { id: Number(x.id ?? x.userId), name: x.name || '' } : { id: Number(x), name: '' }));
}

function deviceChecks(snapshot, iocs, apps, now) {
  const dev = snapshot.device || {};
  const out = [];
  const df = (level, text, fix = null) => out.push({ level, text, fix });
  const byPkg = new Map(apps.map((a) => [a.pkg, a]));
  const appName = (pkg) => { const a = byPkg.get(pkg); return a?.label ? `${a.label} (${pkg})` : pkg; };

  if (snapshot.deviceOwner) df('CRITICAL', `This phone is MANAGED by ${snapshot.deviceOwner}. The owner app controls everything and cannot be removed without a factory reset. Expected only on work phones.`);
  if (snapshot.profileOwner) df('SUSPICIOUS', `A work profile is managed by ${snapshot.profileOwner}. Expected only if your employer or school set it up.`);
  if (dev.rootBinary) df('SUSPICIOUS', 'A root binary (su) is present. Rooted phones let malware hide completely from this scan.');
  if (dev.verifiedBoot && dev.verifiedBoot !== 'green') df('SUSPICIOUS', `Verified boot is "${dev.verifiedBoot}": the system software may have been modified.`);
  if (dev.bootloaderLocked === '0') df('SUSPICIOUS', 'Bootloader is unlocked: anyone with the phone for a few minutes could have flashed modified software.');
  if (/test-keys/.test(dev.buildTags || '')) df('SUSPICIOUS', 'System is signed with test keys (custom or unofficial firmware).');
  if (dev.debuggable) df('WATCH', 'System build is debuggable.');
  const patchAge = daysSince(dev.securityPatch, now);
  if (patchAge !== null && patchAge > 180) df('WATCH', `Security patch level is ${dev.securityPatch} (${Math.round(patchAge / 30)} months old). Install system updates.`);
  if (dev.devSettings) df('WATCH', `Developer options are ON${dev.adbEnabled ? ' and USB debugging is allowed' : ''} (needed for this scan; turn off afterwards so nobody can use a cable to install apps).`, 'settings put global development_settings_enabled 0');
  if (dev.unknownSourcesLegacy) df('WATCH', 'Installing from unknown sources is allowed globally.', 'settings put secure install_non_market_apps 0');
  if (dev.packageVerifier === '0') df('SUSPICIOUS', 'App verification (Play Protect install check) is turned OFF.', 'settings put global package_verifier_enable 1');
  if (String(dev.packageVerifierUserConsent ?? '') === '-1' || dev.playProtect === false) {
    df('SUSPICIOUS', 'Google Play Protect scanning is turned OFF. Spyware often switches it off so it is not caught.', 'settings put global package_verifier_user_consent 1');
  }
  if (dev.verifyAdbInstalls === '0') df('WATCH', 'Verification of apps installed over USB is OFF.', 'settings put global verifier_verify_adb_installs 1');
  if (dev.privateDnsMode === 'hostname' && dev.privateDnsHost && iocs.domains?.has(dev.privateDnsHost.toLowerCase())) df('CRITICAL', `Private DNS points at a known stalkerware domain (${dev.privateDnsHost}).`, 'settings put global private_dns_mode opportunistic');

  // Several users / profiles: other profiles are not scanned.
  const users = usersOf(snapshot);
  if (users && users.length > 1) {
    const others = users.filter((u) => u.id !== 0);
    const names = others.map((u) => (u.name ? `"${u.name}"` : `user ${u.id}`)).join(', ');
    df('WATCH', `This phone has ${users.length} user profiles (${names} besides the main one). Apps in other profiles (Secure Folder, Dual Messenger, work or guest profiles) are not checked by this scan. Remove any profile you do not recognise in Settings > Users / Multiple users.`);
  }

  // Apps allowed to install other apps ("Install unknown apps").
  const srcRaw = snapshot.unknownSources ?? snapshot.installUnknownApps ?? null;
  if (Array.isArray(srcRaw) && srcRaw.length) {
    const srcs = srcRaw.map((x) => (typeof x === 'string' ? x : x.pkg)).filter(Boolean);
    const bad = srcs.filter((s) => byPkg.get(s)?.sideloaded);
    if (bad.length) df('SUSPICIOUS', `These apps that did not come from a store are allowed to install other apps: ${bad.map(appName).join(', ')}. That is how spyware installs more spyware. Turn it off in Settings > Apps > Special access > Install unknown apps.`);
    const rest = srcs.filter((s) => !bad.includes(s));
    if (rest.length) df('WATCH', `These apps are allowed to install other apps outside the Play Store: ${rest.map(appName).join(', ')}. Fine if you use them for that; otherwise turn it off in Settings > Apps > Special access > Install unknown apps.`);
  }

  // Keyboard and SMS app: they see every keystroke / every text message.
  const imePkg = (dev.defaultIme || '').split('/')[0];
  const ime = byPkg.get(imePkg);
  if (ime && !ime.system) {
    if (ime.sideloaded) df('SUSPICIOUS', `Your keyboard (${appName(imePkg)}) was not installed from an app store. A keyboard sees everything you type, including passwords. Switch back to the phone's own keyboard in Settings > System > Keyboard, then remove this one if you do not know it.`);
    else if (!ime.category) df('WATCH', `Your keyboard is a third-party app (${appName(imePkg)}). Keyboards see everything you type; fine if you chose it yourself.`);
  }
  const sms = byPkg.get(dev.defaultSms);
  if (sms && !sms.system) {
    if (sms.sideloaded) df('SUSPICIOUS', `Your default SMS app (${appName(sms.pkg)}) was not installed from an app store. It receives every text, including login codes.`);
    else if (!sms.category) df('WATCH', `Your default SMS app is a third-party app (${appName(sms.pkg)}). Fine if you chose it yourself.`);
  }
  return out;
}
