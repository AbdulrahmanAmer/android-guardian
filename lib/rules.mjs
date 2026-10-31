// Turns a collected snapshot + indicator lists into findings with scores.
// Score bands: >=70 CRITICAL (remove), 40-69 SUSPICIOUS (review), 20-39 WATCH (note).

const P = 'android.permission.';
const SURVEILLANCE = {
  mic: [P + 'RECORD_AUDIO', P + 'CAPTURE_AUDIO_OUTPUT'],
  camera: [P + 'CAMERA'],
  sms: [P + 'READ_SMS', P + 'RECEIVE_SMS', P + 'RECEIVE_MMS', P + 'SEND_SMS'],
  calls: [P + 'READ_CALL_LOG', P + 'PROCESS_OUTGOING_CALLS', P + 'READ_PHONE_STATE', 'android.permission.ANSWER_PHONE_CALLS'],
  location: [P + 'ACCESS_FINE_LOCATION', P + 'ACCESS_BACKGROUND_LOCATION'],
  contacts: [P + 'READ_CONTACTS', P + 'READ_CALENDAR'],
  storage: [P + 'READ_EXTERNAL_STORAGE', P + 'MANAGE_EXTERNAL_STORAGE', P + 'READ_MEDIA_IMAGES'],
};
const CONTROL = {
  overlay: P + 'SYSTEM_ALERT_WINDOW',
  install: P + 'REQUEST_INSTALL_PACKAGES',
  usage: P + 'PACKAGE_USAGE_STATS',
  boot: P + 'RECEIVE_BOOT_COMPLETED',
  accessibility: P + 'BIND_ACCESSIBILITY_SERVICE',
  admin: P + 'BIND_DEVICE_ADMIN',
  notifications: P + 'BIND_NOTIFICATION_LISTENER_SERVICE',
  wake: P + 'WAKE_LOCK',
  foreground: P + 'FOREGROUND_SERVICE',
  killBg: P + 'KILL_BACKGROUND_PROCESSES',
  readLogs: P + 'READ_LOGS',
  disableKeyguard: P + 'DISABLE_KEYGUARD',
};

// Package prefixes that are expected to hold powerful rights (keyboard makers, screen readers, launchers, password managers).
const TRUSTED_PREFIXES = [
  'com.google.', 'com.android.', 'com.samsung.', 'com.sec.', 'com.microsoft.', 'com.oneplus.', 'com.xiaomi.', 'com.miui.',
  'com.huawei.', 'com.oppo.', 'com.coloros.', 'com.vivo.', 'com.motorola.', 'com.sonymobile.', 'com.lge.', 'com.nothing.',
  'com.touchtype.', 'com.bitwarden.', 'com.lastpass.', 'com.agilebits.', 'com.onepassword.', 'com.x8bit.bitwarden', 'keepass2android.',
  'com.teslacoilsw.launcher', 'com.actionlauncher.', 'ch.protonmail.', 'com.whatsapp', 'org.telegram.messenger', 'com.facebook.',
  'com.instagram.', 'com.spotify.', 'com.nianticlabs.', 'com.duolingo', 'com.anydesk.', 'com.teamviewer.',
];
// Remote-control apps that are legitimate but give full control: not malware, but worth telling the owner about.
const REMOTE_CONTROL_APPS = {
  'com.teamviewer.quicksupport.market': 'TeamViewer QuickSupport',
  'com.teamviewer.host.market': 'TeamViewer Host (unattended access)',
  'com.anydesk.anydeskandroid': 'AnyDesk',
  'com.rsupport.rs.activity.rsupport.aas2': 'RemoteView',
  'com.splashtop.streamer.csrs': 'Splashtop Streamer',
  'com.airdroid.remote': 'AirDroid Remote',
  'com.sand.airdroid': 'AirDroid',
  'com.google.android.apps.chromeremotedesktop': 'Chrome Remote Desktop',
  'com.microsoft.rdc.androidx': 'Microsoft Remote Desktop',
  'com.nexters.remoteview': 'RemoteView',
  'com.realvnc.viewer.android': 'VNC Viewer',
};
const MIMIC = /(^|\.)(system|service|services|sync|update|updater|settings|wifi|android|google|security|device|phone|cloud|backup|monitor)(\.|$)/i;

function trusted(pkg) {
  return TRUSTED_PREFIXES.some((p) => pkg.startsWith(p));
}
function daysSince(dateStr) {
  const t = Date.parse(dateStr);
  return Number.isFinite(t) ? (Date.now() - t) / 86_400_000 : null;
}

export function analyze(snapshot, iocs, { certs = new Map(), labels = new Map(), vt = new Map() } = {}) {
  const accPkgs = new Set(snapshot.accessibility.map((a) => a.pkg));
  const nlPkgs = new Set(snapshot.notificationListeners.map((a) => a.pkg));
  const adminPkgs = new Set(snapshot.deviceAdmins.map((a) => a.pkg));
  const idle = new Set(snapshot.idleWhitelist);
  const usage = new Set(snapshot.usageAccess);
  const running = new Set(snapshot.running);

  const apps = [];
  for (const p of snapshot.packages) {
    const reasons = [];
    let score = 0;
    const add = (pts, text, tag) => { score += pts; reasons.push({ pts, text, tag }); };
    const label = labels.get(p.pkg);

    // --- Known-bad indicators (certain) ---
    const knownPkg = iocs.packages.get(p.pkg);
    if (knownPkg) add(100, `Package name is on the known stalkerware/RAT list (${knownPkg})`, 'ioc');
    if (p.sha256 && iocs.sha256.has(p.sha256)) add(100, `App file hash matches known stalkerware (${iocs.sha256.get(p.sha256)})`, 'ioc');
    const cert = certs.get(p.pkg);
    if (cert && iocs.certSha1.has(cert)) add(100, `Signed with a certificate used by known stalkerware (${iocs.certSha1.get(cert)})`, 'ioc');

    const vtHit = p.sha256 && vt.get(p.sha256);
    if (vtHit?.known && vtHit.malicious >= 3) add(100, `Flagged as malicious by ${vtHit.malicious} of ${vtHit.total} antivirus engines on VirusTotal`, 'vt');
    else if (vtHit?.known && vtHit.malicious + vtHit.suspicious >= 1) add(30, `Flagged by ${vtHit.malicious + vtHit.suspicious} antivirus engine(s) on VirusTotal`, 'vt');

    const remote = REMOTE_CONTROL_APPS[p.pkg];
    if (remote) add(30, `Remote-control app installed (${remote}). Fine if you installed it; a stranger could use it to see and control your screen`, 'remote');

    const isTrusted = p.system || trusted(p.pkg);
    const granted = new Set(p.granted);
    const requested = new Set(p.requested);

    // --- Behaviour heuristics (only for apps that are not plain system apps) ---
    if (!p.system) {
      if (accPkgs.has(p.pkg)) add(isTrusted ? 10 : 35, 'Accessibility service is ON: can read everything on screen and tap for you', 'access');
      if (adminPkgs.has(p.pkg)) add(isTrusted ? 8 : 25, 'Device administrator: can lock/wipe the phone and resist uninstall', 'admin');
      if (nlPkgs.has(p.pkg)) add(isTrusted ? 5 : 20, 'Notification access: reads all incoming notifications and messages', 'notif');
      if (usage.has(p.pkg)) add(isTrusted ? 2 : 8, 'Usage access: sees which apps you open and when', 'usage');
      if (idle.has(p.pkg)) add(isTrusted ? 2 : 10, 'Excluded from battery optimisation: stays alive in background', 'battery');

      const cats = Object.entries(SURVEILLANCE).filter(([, perms]) => perms.some((x) => granted.has(x))).map(([k]) => k);
      const catPts = { mic: 8, camera: 5, sms: 10, calls: 10, location: 6, contacts: 4, storage: 2 };
      const catText = { mic: 'Can record with the microphone', camera: 'Can use the camera', sms: 'Can read and send text messages (SMS)', calls: 'Can read the call log and phone state', location: 'Can track your location', contacts: 'Can read contacts and calendar', storage: 'Can read files and photos' };
      for (const c of cats) add(isTrusted ? Math.ceil(catPts[c] / 3) : catPts[c], catText[c], 'perm');
      const catShort = { mic: 'microphone', camera: 'camera', sms: 'SMS', calls: 'calls', location: 'location', contacts: 'contacts', storage: 'files' };
      if (cats.length >= 4 && !isTrusted) add(15, `Holds ${cats.length} kinds of surveillance access at once (${cats.map((c) => catShort[c]).join(', ')})`, 'combo');

      if (granted.has(CONTROL.overlay)) add(isTrusted ? 2 : 8, 'Can draw over other apps (fake login screens, hidden taps)', 'perm');
      if (granted.has(CONTROL.install) || requested.has(CONTROL.install)) add(isTrusted ? 1 : 8, 'Can install other apps', 'perm');
      if (requested.has(CONTROL.readLogs)) add(5, 'Asks to read system logs', 'perm');
      if (requested.has(CONTROL.disableKeyguard)) add(5, 'Asks to disable the lock screen', 'perm');

      if (!p.hasLauncherIcon && !isTrusted) {
        add(cats.length >= 2 || accPkgs.has(p.pkg) ? 25 : 10, 'No app icon in the launcher: hidden from you', 'hidden');
      }
      if (p.hidden) add(15, 'Marked hidden by the system for this user', 'hidden');
      if (p.sideloaded && !isTrusted) add(15, `Not installed from an app store${p.installer ? ` (installed by ${p.installer})` : ' (installer unknown: USB, browser download or file manager)'}`, 'sideload');
      if (!isTrusted && (MIMIC.test(p.pkg) || (label && MIMIC.test(label)))) add(15, `Name imitates a system component ("${label || p.pkg}")`, 'mimic');
      const age = daysSince(p.firstInstall);
      if (age !== null && age < 30 && p.sideloaded && !isTrusted) add(5, `Installed recently (${Math.round(age)} days ago)`, 'recent');
      if (p.debuggable && !isTrusted) add(5, 'Built in debug mode (typical of home-made RAT payloads)', 'debug');
      if (running.has(p.pkg) && !p.hasLauncherIcon && !isTrusted) add(5, 'Running right now despite having no icon', 'running');
    } else if (p.updatedSystem && p.sha256 && iocs.sha256.has(p.sha256)) {
      // already covered by ioc above
    }

    const net = snapshot.netstats[String(p.uid)];
    const bytes = net ? net.rx + net.tx : 0;

    apps.push({
      pkg: p.pkg,
      label: label || null,
      score: Math.min(100, score),
      level: score >= 70 ? 'CRITICAL' : score >= 40 ? 'SUSPICIOUS' : score >= 20 ? 'WATCH' : 'OK',
      reasons: reasons.sort((a, b) => b.pts - a.pts),
      system: p.system,
      sideloaded: p.sideloaded,
      installer: p.installer,
      firstInstall: p.firstInstall,
      versionName: p.versionName,
      uid: p.uid,
      apkPath: p.apkPath,
      sha256: p.sha256,
      cert: cert || null,
      virusTotal: vtHit || null,
      hasLauncherIcon: p.hasLauncherIcon,
      accessibility: snapshot.accessibility.filter((a) => a.pkg === p.pkg).map((a) => a.component),
      notificationListeners: snapshot.notificationListeners.filter((a) => a.pkg === p.pkg).map((a) => a.component),
      deviceAdmins: snapshot.deviceAdmins.filter((a) => a.pkg === p.pkg).map((a) => a.component),
      dangerousGranted: p.granted.filter((g) => Object.values(SURVEILLANCE).flat().includes(g) || g === CONTROL.overlay),
      networkBytes: bytes,
      running: running.has(p.pkg),
    });
  }
  apps.sort((a, b) => b.score - a.score || a.pkg.localeCompare(b.pkg));

  // --- Device-level findings ---
  const dev = snapshot.device;
  const deviceFindings = [];
  const df = (level, text, fix) => deviceFindings.push({ level, text, fix });
  if (snapshot.deviceOwner) df('CRITICAL', `This phone is MANAGED by ${snapshot.deviceOwner}. The owner app controls everything and cannot be removed without a factory reset. Expected only on work phones.`, null);
  if (snapshot.profileOwner) df('SUSPICIOUS', `A work profile is managed by ${snapshot.profileOwner}.`, null);
  if (dev.rootBinary) df('SUSPICIOUS', 'A root binary (su) is present. Rooted phones let malware hide completely from this scan.', null);
  if (dev.verifiedBoot && dev.verifiedBoot !== 'green') df('SUSPICIOUS', `Verified boot is "${dev.verifiedBoot}": the system software may have been modified.`, null);
  if (dev.bootloaderLocked === '0') df('SUSPICIOUS', 'Bootloader is unlocked: anyone with the phone for a few minutes could have flashed modified software.', null);
  if (/test-keys/.test(dev.buildTags)) df('SUSPICIOUS', 'System is signed with test keys (custom or unofficial firmware).', null);
  if (dev.debuggable) df('WATCH', 'System build is debuggable.', null);
  const patchAge = daysSince(dev.securityPatch);
  if (patchAge !== null && patchAge > 180) df('WATCH', `Security patch level is ${dev.securityPatch} (${Math.round(patchAge / 30)} months old). Install system updates.`, null);
  if (dev.devSettings) df('WATCH', 'Developer options are ON (needed for this scan; turn off afterwards).', 'settings put global development_settings_enabled 0');
  if (dev.unknownSourcesLegacy) df('WATCH', 'Installing from unknown sources is allowed globally.', 'settings put secure install_non_market_apps 0');
  if (dev.packageVerifier === '0') df('SUSPICIOUS', 'App verification (Play Protect install check) is turned OFF.', 'settings put global package_verifier_enable 1');
  if (dev.verifyAdbInstalls === '0') df('WATCH', 'Verification of apps installed over USB is OFF.', 'settings put global verifier_verify_adb_installs 1');
  if (dev.privateDnsMode === 'hostname' && dev.privateDnsHost && iocs.domains.has(dev.privateDnsHost.toLowerCase())) df('CRITICAL', `Private DNS points at a known stalkerware domain (${dev.privateDnsHost}).`, 'settings put global private_dns_mode opportunistic');
  const imePkg = (dev.defaultIme || '').split('/')[0];
  const imeApp = apps.find((a) => a.pkg === imePkg);
  if (imeApp && !imeApp.system && !trusted(imePkg)) df('SUSPICIOUS', `Keyboard is a third-party app (${imeApp.label || imePkg}): keyboards see everything you type.`, null);
  const smsApp = apps.find((a) => a.pkg === dev.defaultSms);
  if (smsApp && !smsApp.system && !trusted(smsApp.pkg)) df('SUSPICIOUS', `Default SMS app is a third-party app (${smsApp.label || smsApp.pkg}).`, null);

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
