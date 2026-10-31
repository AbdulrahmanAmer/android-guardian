// Pulls everything we need from the phone with as few adb round trips as possible.
// Nothing here judges; it only collects. Judging lives in rules.mjs.

const KNOWN_STORES = new Set([
  'com.android.vending', // Google Play
  'com.sec.android.app.samsungapps', // Galaxy Store
  'com.huawei.appmarket',
  'com.xiaomi.mipicks',
  'com.oppo.market',
  'com.heytap.market',
  'com.vivo.appstore',
  'com.amazon.venezia',
  'com.aurora.store',
  'org.fdroid.fdroid',
]);

function getprop(adb, name) {
  return adb.shell(`getprop ${name}`).trim();
}
function setting(adb, ns, name) {
  const v = adb.shell(`settings get ${ns} ${name}`).trim();
  return v === 'null' ? '' : v;
}

function parsePackagesDump(dump) {
  // Splits `dumpsys package packages` into one record per package.
  const pkgs = new Map();
  const blocks = dump.split(/\r?\n(?=  Package \[)/);
  for (const block of blocks) {
    const head = block.match(/^\s*Package \[([^\]]+)\]/);
    if (!head) continue;
    const name = head[1];
    const get = (re) => (block.match(re) || [, ''])[1].trim();
    const flagsLine = get(/\n\s+(?:pkgFlags|flags)=\[([^\]]*)\]/);
    const privFlags = get(/\n\s+privateFlags=\[([^\]]*)\]/);
    const requested = [];
    const reqSection = block.match(/requested permissions:\r?\n([\s\S]*?)(?=\n\s{4}\S|\n\s{2}\S|$)/);
    if (reqSection) {
      for (const line of reqSection[1].split(/\r?\n/)) {
        const m = line.match(/^\s+([\w.]+)(?::|\s|$)/);
        if (m) requested.push(m[1]);
      }
    }
    const granted = new Set();
    for (const m of block.matchAll(/^\s+([\w.]+): granted=true/gm)) granted.add(m[1]);
    const userLine = block.match(/User 0:[^\n]*/);
    pkgs.set(name, {
      pkg: name,
      path: get(/\n\s+codePath=(\S+)/),
      versionName: get(/\n\s+versionName=([^\r\n]*)/),
      uid: Number(get(/\n\s+(?:userId|appId)=(\d+)/)) || null,
      installer: (() => { const v = get(/\n\s+installerPackageName=([^\r\n]*)/); return v && v !== 'null' ? v : null; })(),
      firstInstall: get(/\n\s+firstInstallTime=([^\r\n]*)/),
      lastUpdate: get(/\n\s+lastUpdateTime=([^\r\n]*)/),
      system: /\bSYSTEM\b/.test(flagsLine),
      updatedSystem: /\bUPDATED_SYSTEM_APP\b/.test(flagsLine),
      debuggable: /\bDEBUGGABLE\b/.test(flagsLine),
      privileged: /\bPRIVILEGED\b/.test(privFlags),
      hidden: /hidden=true/.test(userLine ? userLine[0] : ''),
      enabled: !/enabled=(2|3|4)/.test(userLine ? userLine[0] : ''),
      stopped: /stopped=true/.test(userLine ? userLine[0] : ''),
      requested,
      granted: [...granted],
      sideloaded: false, // filled below
    });
  }
  for (const p of pkgs.values()) {
    p.sideloaded = !p.system && !(p.installer && KNOWN_STORES.has(p.installer));
  }
  return pkgs;
}

function parseLauncherActivities(out) {
  // `cmd package query-activities --brief ...` lists "pkg/cls" lines, one per launcher entry.
  const set = new Set();
  for (const m of out.matchAll(/^\s*([\w.]+)\/[\w.$]+/gm)) set.add(m[1]);
  return set;
}

function parseComponentList(value) {
  // "pkg/cls:pkg2/cls2" style settings values.
  return value
    .split(':')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => ({ component: s, pkg: s.split('/')[0] }));
}

function parseDeviceAdmins(dump) {
  // dumpsys device_policy: "Enabled Device Admins (User 0, provisioningState: 0):" then entries
  // "  com.foo/.AdminReceiver:" ...  Also device/profile owners.
  const admins = [];
  for (const m of dump.matchAll(/^\s{2,}([\w.]+\/[\w.$]+):\s*$/gm)) {
    admins.push({ component: m[1], pkg: m[1].split('/')[0] });
  }
  const owner = (dump.match(/Device Owner:[\s\S]*?admin=ComponentInfo\{([^}]+)\}/) || [])[1] || null;
  const profileOwner = (dump.match(/Profile Owner[^\n]*:[\s\S]*?admin=ComponentInfo\{([^}]+)\}/) || [])[1] || null;
  return { admins, deviceOwner: owner, profileOwner };
}

function parseIdleWhitelist(out) {
  // Lines like "user,com.foo,10123" or "system,com.bar,1000"
  const set = new Set();
  for (const m of out.matchAll(/^(?:user|system|system-excidle),([\w.]+),/gm)) set.add(m[1]);
  return set;
}

function parseNetstats(out) {
  // Best effort. `dumpsys netstats detail` groups buckets under a header line:
  //   ident=[{type=WIFI ...}] uid=10123 set=DEFAULT tag=0x0
  //     NetworkStatsHistory: bucketDuration=7200
  //       st=1693000000 rb=12345 rp=67 tb=890 tp=12 op=0
  const byUid = new Map();
  let uid = null;
  for (const line of out.split(/\r?\n/)) {
    const h = line.match(/\buid=(\d+)\b/);
    if (h) { uid = Number(h[1]); continue; }
    const b = uid !== null && line.match(/\brb=(\d+)\b.*\btb=(\d+)\b/);
    if (b) {
      const cur = byUid.get(uid) || { rx: 0, tx: 0 };
      cur.rx += Number(b[1]);
      cur.tx += Number(b[2]);
      byUid.set(uid, cur);
    }
  }
  return byUid;
}

function parseSha256List(out) {
  const map = new Map();
  for (const m of out.matchAll(/^([0-9a-f]{64})\s+\*?(\S+)/gm)) map.set(m[2], m[1]);
  return map;
}

export function collect(adb, { log = () => {} } = {}) {
  log('Reading device info');
  const device = {
    model: getprop(adb, 'ro.product.model'),
    manufacturer: getprop(adb, 'ro.product.manufacturer'),
    android: getprop(adb, 'ro.build.version.release'),
    sdk: Number(getprop(adb, 'ro.build.version.sdk')) || 0,
    securityPatch: getprop(adb, 'ro.build.version.security_patch'),
    buildTags: getprop(adb, 'ro.build.tags'),
    verifiedBoot: getprop(adb, 'ro.boot.verifiedbootstate'),
    bootloaderLocked: getprop(adb, 'ro.boot.flash.locked'),
    debuggable: getprop(adb, 'ro.debuggable') === '1',
    rootBinary: /\/su\b/.test(adb.shell('which su 2>/dev/null; ls /sbin/su /system/xbin/su /system/bin/su 2>/dev/null')),
    adbEnabled: setting(adb, 'global', 'adb_enabled') === '1',
    devSettings: setting(adb, 'global', 'development_settings_enabled') === '1',
    unknownSourcesLegacy: setting(adb, 'secure', 'install_non_market_apps') === '1',
    packageVerifier: setting(adb, 'global', 'package_verifier_enable'),
    verifyAdbInstalls: setting(adb, 'global', 'verifier_verify_adb_installs'),
    privateDnsMode: setting(adb, 'global', 'private_dns_mode'),
    privateDnsHost: setting(adb, 'global', 'private_dns_specifier'),
    defaultIme: setting(adb, 'secure', 'default_input_method'),
    defaultSms: setting(adb, 'secure', 'sms_default_application'),
    now: adb.shell('date +%s').trim(),
  };

  log('Reading special-access settings');
  const accessibility = parseComponentList(setting(adb, 'secure', 'enabled_accessibility_services'));
  const notificationListeners = parseComponentList(setting(adb, 'secure', 'enabled_notification_listeners'));
  const { admins, deviceOwner, profileOwner } = parseDeviceAdmins(adb.shell('dumpsys device_policy'));
  const idleWhitelist = parseIdleWhitelist(adb.shell('dumpsys deviceidle whitelist'));
  const launcherPkgs = parseLauncherActivities(
    adb.shell('cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER'),
  );
  const usageAccess = new Set();
  for (const m of adb.shell('appops query-op GET_USAGE_STATS allow 2>/dev/null').matchAll(/^([\w.]+)$/gm)) usageAccess.add(m[1]);

  log('Reading all installed packages (one big dump)');
  const packages = parsePackagesDump(adb.shell('dumpsys package packages', { maxBuffer: 512 * 1024 * 1024 }));

  // Apps that have a launcher icon
  for (const p of packages.values()) p.hasLauncherIcon = launcherPkgs.has(p.pkg);

  log(`Hashing ${[...packages.values()].filter((p) => !p.system || p.updatedSystem).length} app files on the phone`);
  const toHash = [...packages.values()].filter((p) => (!p.system || p.updatedSystem) && p.path);
  const apkPaths = new Map();
  for (const p of toHash) {
    // codePath is a directory for user apps; the file is base.apk inside it.
    apkPaths.set(p.pkg, p.path.endsWith('.apk') ? p.path : `${p.path}/base.apk`);
  }
  const hashes = new Map();
  const list = [...apkPaths.values()];
  for (let i = 0; i < list.length; i += 40) {
    const chunk = list.slice(i, i + 40);
    const out = adb.shell(`sha256sum ${chunk.map((x) => `'${x}'`).join(' ')} 2>/dev/null`);
    for (const [path, h] of parseSha256List(out)) hashes.set(path, h);
  }
  for (const p of packages.values()) {
    p.apkPath = apkPaths.get(p.pkg) || null;
    p.sha256 = p.apkPath ? hashes.get(p.apkPath) || null : null;
  }

  log('Reading network usage per app');
  const netstats = parseNetstats(adb.shell('dumpsys netstats detail'));

  log('Reading running processes');
  const running = new Set();
  for (const m of adb.shell('ps -A -o NAME 2>/dev/null || ps -A').matchAll(/^([a-z][\w.]+)(?::\S+)?$/gm)) running.add(m[1]);

  return {
    collectedAt: new Date().toISOString(),
    device,
    accessibility,
    notificationListeners,
    deviceAdmins: admins,
    deviceOwner,
    profileOwner,
    idleWhitelist: [...idleWhitelist],
    usageAccess: [...usageAccess],
    running: [...running],
    netstats: Object.fromEntries([...netstats].map(([k, v]) => [k, v])),
    packages: [...packages.values()],
  };
}

export const _internal = { parsePackagesDump, parseDeviceAdmins, parseLauncherActivities, parseIdleWhitelist, parseNetstats };
