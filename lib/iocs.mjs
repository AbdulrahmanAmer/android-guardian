// Indicators of compromise: known-bad package names, APK hashes, signing
// certificates and domains. Public source: Echap's stalkerware-indicators
// (used by Amnesty's MVT). Plus a small built-in list of well-known RAT families,
// and the allowlist of legitimate apps that hold scary rights by design (KNOWN_APPS).
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const STIX_URL = 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2';
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;

// Default package names of open-source / leaked Android RAT builders, as produced when the
// builder is run without renaming. Attackers often rename, so behaviour heuristics still matter.
// Only names whose builder default is well documented are listed. Families whose builders
// randomise the package name per build (Cerberus leak, Hydra, BRATA, Xenomorph, Craxs, EagleSpy,
// SpyMax) are deliberately NOT listed: a guessed name would be noise, not detection.
export const BUILTIN = {
  packages: {
    'ahmyth.mine.king.ahmyth': 'AhMyth RAT (open-source builder default)',
    'com.etechd.l3mon': 'L3MON RAT (AhMyth fork, builder default)',
    'net.droidjack.server': 'DroidJack RAT (builder default)',
    'my.app.client': 'AndroRAT (original builder default)',
    'com.example.reverseshell2': 'AndroRAT (karma9874 builder default)',
    'com.metasploit.stage': 'Metasploit Android payload (msfvenom default)',
    'com.connect': 'Dendroid RAT (builder default)',
    'com.android.tester': 'SpyNote RAT',
    'com.spynote.software.spynote': 'SpyNote RAT',
    'com.hawkshaw': 'HawkShaw RAT',
    'com.rat.pro': 'Generic RAT',
    'com.system.service.update': 'Masquerading spyware',
  },
};

// ---------------------------------------------------------------------------------------------
// Legitimate apps that need powerful rights for what they do. rules.mjs gives these credit for
// the rights in their category's `expects` list ONLY when the app came from a major store
// (CREDIT_STORES) or is a system app; a sideloaded copy with the same package name gets no credit.
// Rights not in `expects` are still scored (at the store rate). Keys used in `expects`:
//   access (accessibility service ON), admin (device administrator), notif (notification access),
//   usage (usage access), battery (battery-optimisation exempt), overlay, install, readLogs,
//   projection (screen capture service), hidden (no launcher icon is normal), ime (default keyboard),
//   sms, calls, mic, camera, location, contacts, storage.
// `notice`: 'remote' / 'monitor' apps are always reported as an informational WATCH;
//           'parent' apps get a 0-point note (they watch another phone, not this one).
// To add an app: put its exact package name under the right category. Keep it to apps from
// well-known publishers; when unsure, leave it out (an unknown Play app still scores low).
// ---------------------------------------------------------------------------------------------
const ALL = ['access', 'admin', 'notif', 'usage', 'battery', 'overlay', 'install', 'readLogs', 'projection', 'hidden', 'ime',
  'sms', 'calls', 'mic', 'camera', 'location', 'contacts', 'storage'];
export const CATEGORIES = {
  keyboard: { what: 'keyboard', expects: ['ime', 'mic', 'contacts', 'storage', 'hidden'] },
  screenReader: { what: 'screen reader / accessibility tool', expects: ['access', 'overlay', 'hidden', 'calls', 'battery', 'mic', 'notif'] },
  passwordManager: { what: 'password manager (fills passwords using accessibility)', expects: ['access', 'overlay', 'camera', 'storage', 'battery', 'notif'] },
  automation: { what: 'automation app (needs broad access by design)', expects: ALL.filter((k) => k !== 'install') },
  optimizer: { what: 'battery / app optimiser', expects: ['access', 'usage', 'battery', 'overlay', 'admin', 'hidden'] },
  launcher: { what: 'home-screen launcher', expects: ['notif', 'usage', 'admin', 'access', 'contacts', 'location', 'calls', 'storage', 'overlay', 'mic'] },
  antivirus: { what: 'security app (uses accessibility to block bad links and apps)', expects: ['access', 'admin', 'usage', 'overlay', 'battery', 'notif', 'location', 'camera', 'sms', 'calls', 'contacts', 'storage', 'projection'] },
  messaging: { what: 'messaging app', expects: ['mic', 'camera', 'contacts', 'location', 'storage', 'sms', 'calls', 'battery', 'overlay', 'notif'] },
  sms: { what: 'SMS app', expects: ['sms', 'contacts', 'mic', 'camera', 'location', 'storage', 'calls', 'battery', 'notif'] },
  callerId: { what: 'caller-ID / spam-call blocker', expects: ['calls', 'contacts', 'sms', 'overlay', 'battery', 'notif', 'location', 'storage'] },
  wearable: { what: 'smartwatch / fitness-band companion (mirrors notifications and messages to the watch)', expects: ['notif', 'sms', 'calls', 'contacts', 'location', 'battery', 'mic', 'storage', 'camera'] },
  findDevice: { what: 'find-my-phone app', expects: ['location', 'admin', 'battery'] },
  remote: { what: 'remote-control app', notice: 'remote', expects: ['access', 'overlay', 'projection', 'install', 'storage', 'battery', 'notif', 'hidden'] },
  monitor: { what: 'monitoring / parental-control app', notice: 'monitor', expects: ALL },
  parent: { what: 'parent-side parental-control app (watches another phone, not this one)', notice: 'parent', expects: ['location', 'notif', 'contacts', 'camera'] },
  vendor: { what: 'app from the phone or OS maker', expects: ALL },
};
export const KNOWN_APPS = {
  keyboard: {
    'com.google.android.inputmethod.latin': 'Gboard', 'com.touchtype.swiftkey': 'Microsoft SwiftKey',
    'com.samsung.android.honeyboard': 'Samsung Keyboard', 'com.grammarly.android.keyboard': 'Grammarly Keyboard',
  },
  screenReader: {
    'com.google.android.marvin.talkback': 'Android Accessibility Suite (TalkBack)', 'com.samsung.android.accessibility.talkback': 'Samsung TalkBack',
    'com.google.android.apps.accessibility.voiceaccess': 'Voice Access',
  },
  passwordManager: {
    'com.x8bit.bitwarden': 'Bitwarden', 'com.onepassword.android': '1Password', 'com.agilebits.onepassword': '1Password 7',
    'com.lastpass.lpandroid': 'LastPass', 'com.dashlane': 'Dashlane', 'keepass2android.keepass2android': 'Keepass2Android',
    'com.kunzisoft.keepass.free': 'KeePassDX', 'com.callpod.android_apps.keeper': 'Keeper', 'proton.android.pass': 'Proton Pass',
  },
  automation: { 'net.dinglisch.android.taskerm': 'Tasker', 'com.arlosoft.macrodroid': 'MacroDroid', 'com.llamalab.automate': 'Automate' },
  optimizer: { 'com.oasisfeng.greenify': 'Greenify' },
  launcher: {
    'com.microsoft.launcher': 'Microsoft Launcher', 'com.teslacoilsw.launcher': 'Nova Launcher', 'com.teslacoilsw.launcher.prime': 'Nova Launcher Prime',
    'ginlemon.flowerfree': 'Smart Launcher', 'com.actionlauncher.playstore': 'Action Launcher', 'bitpit.launcher': 'Niagara Launcher',
  },
  antivirus: {
    'com.bitdefender.security': 'Bitdefender Mobile Security', 'org.malwarebytes.antimalware': 'Malwarebytes',
    'com.avast.android.mobilesecurity': 'Avast Mobile Security', 'com.wsandroid.suite': 'McAfee Security', 'com.kms.free': 'Kaspersky',
    'com.symantec.mobilesecurity': 'Norton 360', 'com.eset.ems2.gp': 'ESET Mobile Security', 'com.lookout': 'Lookout',
  },
  messaging: {
    'com.whatsapp': 'WhatsApp', 'com.whatsapp.w4b': 'WhatsApp Business', 'org.telegram.messenger': 'Telegram',
    'org.thoughtcrime.securesms': 'Signal', 'com.facebook.orca': 'Messenger', 'com.viber.voip': 'Viber', 'jp.naver.line.android': 'LINE',
    'com.discord': 'Discord', 'com.tencent.mm': 'WeChat', 'com.skype.raider': 'Skype',
  },
  sms: {
    'com.google.android.apps.messaging': 'Google Messages', 'com.samsung.android.messaging': 'Samsung Messages',
    'com.textra': 'Textra', 'com.p1.chompsms': 'Chomp SMS', 'xyz.klinker.messenger': 'Pulse SMS',
  },
  callerId: { 'com.truecaller': 'Truecaller', 'com.google.android.dialer': 'Google Phone' },
  wearable: {
    'com.samsung.android.app.watchmanager': 'Galaxy Wearable', 'com.google.android.wearable.app': 'Wear OS',
    'com.fitbit.FitbitMobile': 'Fitbit', 'com.garmin.android.apps.connectmobile': 'Garmin Connect', 'com.huawei.health': 'Huawei Health',
  },
  findDevice: { 'com.google.android.apps.adm': 'Google Find My Device', 'com.samsung.android.fmm': 'Samsung Find My Mobile' },
  remote: {
    'com.teamviewer.quicksupport.market': 'TeamViewer QuickSupport', 'com.teamviewer.quicksupport.addon.universal': 'TeamViewer QuickSupport add-on',
    'com.teamviewer.host.market': 'TeamViewer Host (unattended access)', 'com.anydesk.anydeskandroid': 'AnyDesk',
    'com.anydesk.adcontrol.ad1': 'AnyDesk control plugin', 'com.rsupport.rs.activity.rsupport.aas2': 'RemoteView',
    'com.splashtop.streamer.csrs': 'Splashtop Streamer', 'com.airdroid.remote': 'AirDroid Remote', 'com.sand.airdroid': 'AirDroid',
    'com.sand.airdroidkidp': 'AirDroid Parental Control', 'com.google.android.apps.chromeremotedesktop': 'Chrome Remote Desktop',
    'com.microsoft.rdc.androidx': 'Microsoft Remote Desktop', 'com.nexters.remoteview': 'RemoteView', 'com.realvnc.viewer.android': 'VNC Viewer',
  },
  monitor: {
    'com.google.android.apps.kids.familylinkhelper': 'Google Family Link (child device)', 'com.qustodio.qustodioapp': 'Qustodio',
    'com.symantec.familysafety': 'Norton Family', 'com.kaspersky.safekids': 'Kaspersky Safe Kids', 'com.sec.android.app.kidshome': 'Samsung Kids',
    'com.microsoft.familysafety': 'Microsoft Family Safety', 'com.life360.android.safetymapd': 'Life360 (location sharing)',
  },
  parent: { 'com.google.android.apps.kids.familylink': 'Google Family Link (parent app)' },
};
// Bark's Android package name could not be verified offline, so it is matched by its label only
// (labels are read from pulled APKs). A label match adds the monitoring notice but grants NO credit.
export const MONITOR_LABELS = [[/^bark( for kids| jr)?$/i, 'Bark']];
// Store-installed apps in these namespaces are published by the OS/phone maker (Play and Galaxy
// Store do not let third parties publish under them).
export const VENDOR_PREFIXES = ['com.google.android.', 'com.samsung.android.', 'com.sec.android.', 'com.microsoft.'];
// Stores whose install counts toward allowlist credit. F-Droid / Aurora installs are still treated
// as "from a store" by collect.mjs, but get no allowlist credit (anyone can publish a repo).
export const CREDIT_STORES = new Set([
  'com.android.vending', 'com.sec.android.app.samsungapps', 'com.huawei.appmarket', 'com.xiaomi.mipicks',
  'com.oppo.market', 'com.heytap.market', 'com.vivo.appstore', 'com.amazon.venezia',
]);

/** pkg -> { name, category, what, notice, expects:Set } or null. Category membership only; install source is judged in rules.mjs. */
export function knownApp(pkg) {
  for (const [category, apps] of Object.entries(KNOWN_APPS)) {
    if (apps[pkg]) {
      const c = CATEGORIES[category];
      return { name: apps[pkg], category, what: c.what, notice: c.notice || null, expects: new Set(c.expects) };
    }
  }
  if (VENDOR_PREFIXES.some((p) => pkg.startsWith(p))) {
    const c = CATEGORIES.vendor;
    return { name: null, category: 'vendor', what: c.what, notice: null, expects: new Set(c.expects) };
  }
  return null;
}

// STIX pattern object paths -> which map the value goes into. Anything else is counted as skipped
// (and logged), never silently dropped.
const KIND_MAP = {
  'app:id': 'packages',
  'file:hashes.sha256': 'sha256',
  "file:hashes.'sha-256'": 'sha256',
  'app:cert.sha1': 'certSha1',
  'domain-name:value': 'domains',
  'ipv4-addr:value': 'ips',
  'ipv6-addr:value': 'ips',
  'url:value': 'urls',
};
function kindTarget(kind) {
  if (KIND_MAP[kind]) return KIND_MAP[kind];
  // certificate_organizations-style indicators: app:cert.organization, app:cert.subject.organization, x509-certificate:subject...
  if (/cert/i.test(kind) && /organi[sz]ation|subject|issuer/i.test(kind)) return 'certOrgs';
  if (/cert/i.test(kind) && /sha-?1/i.test(kind)) return 'certSha1';
  if (/sha-?256/i.test(kind)) return 'sha256';
  return null;
}

/** Parses an Echap-style STIX2 bundle (object) into indicator maps. Exported for tests. */
export function parseStix(data, iocs, log = () => {}) {
  const objects = data?.objects || [];
  const malwareName = new Map();
  for (const o of objects) if (o.type === 'malware') malwareName.set(o.id, o.name);
  const indicatorToMalware = new Map();
  for (const o of objects) {
    if (o.type === 'relationship' && o.relationship_type === 'indicates') indicatorToMalware.set(o.source_ref, o.target_ref);
  }
  const counts = {};
  const skippedKinds = {};
  let unparsable = 0;
  const bump = (obj, k) => { obj[k] = (obj[k] || 0) + 1; };
  for (const o of objects) {
    if (o.type !== 'indicator') continue;
    if (!o.pattern) { unparsable++; continue; }
    const name = malwareName.get(indicatorToMalware.get(o.id)) || o.name || 'known stalkerware';
    // A pattern may hold several comparisons joined by OR/AND: take every `path = 'value'`.
    const comparisons = [...o.pattern.matchAll(/([\w.:'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'/g)];
    if (!comparisons.length) { unparsable++; continue; }
    for (const [, kind, raw] of comparisons) {
      const value = raw.replace(/\\'/g, "'");
      const target = kindTarget(kind);
      if (!target) { bump(skippedKinds, kind); continue; }
      bump(counts, target);
      if (target === 'packages') iocs.packages.set(value, name);
      else if (target === 'sha256') iocs.sha256.set(value.toLowerCase(), name);
      else if (target === 'certSha1') iocs.certSha1.set(value.toUpperCase().replace(/:/g, ''), name);
      else if (target === 'domains') iocs.domains.set(value.toLowerCase(), name);
      else if (target === 'certOrgs') iocs.certOrgs.set(value.trim().toLowerCase(), name);
      else iocs[target].set(value.toLowerCase(), name);
    }
  }
  const parts = Object.entries(counts).map(([k, v]) => `${v} ${k}`);
  log(`Indicators read: ${parts.join(', ') || 'none'}`);
  const skipped = Object.entries(skippedKinds);
  if (skipped.length) log(`Indicators not used (unknown kind): ${skipped.map(([k, v]) => `${v} ${k}`).join(', ')}`);
  if (unparsable) log(`Indicators not used (pattern not understood): ${unparsable}`);
  return { counts, skippedKinds, unparsable };
}

export function loadIocs({ cacheDir, refresh = false, log = () => {}, offline = false } = {}) {
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, 'stalkerware.stix2');
  let stale = true;
  if (existsSync(file)) stale = Date.now() - statSync(file).mtimeMs > MAX_AGE_MS;
  return (async () => {
    if ((refresh || stale || !existsSync(file)) && !offline) {
      try {
        log('Downloading latest stalkerware indicators (Echap list)');
        const res = await fetch(STIX_URL, { signal: AbortSignal.timeout(60_000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        writeFileSync(file, await res.text());
      } catch (e) {
        log(`Could not refresh indicators: ${e.message}${existsSync(file) ? ' (using cached copy)' : ''}`);
      }
    }
    const iocs = {
      packages: new Map(), sha256: new Map(), certSha1: new Map(), domains: new Map(),
      certOrgs: new Map(), ips: new Map(), urls: new Map(), source: null, count: 0, stats: null,
    };
    for (const [pkg, name] of Object.entries(BUILTIN.packages)) iocs.packages.set(pkg, name);
    if (existsSync(file)) {
      try {
        iocs.stats = parseStix(JSON.parse(readFileSync(file, 'utf8')), iocs, log);
        iocs.source = { file, updated: statSync(file).mtime.toISOString() };
      } catch (e) {
        log(`Indicator file is damaged and was not used: ${e.message}`);
      }
    }
    iocs.count = iocs.packages.size + iocs.sha256.size + iocs.certSha1.size + iocs.domains.size + iocs.certOrgs.size;
    return iocs;
  })();
}
