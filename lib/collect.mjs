// Pulls everything we need from the phone with as few adb round trips as possible.
// Nothing here judges; it only collects. Judging lives in rules.mjs.
//
// Every parser is line-based and linear: `dumpsys package packages` is 20-40 MB on a phone with
// 400 apps, and one malformed package must never swallow the next one. Formats exercised by the
// fixtures in test/make-fixture.mjs: Android 8 (MIUI), 13 (One UI), 14 (Pixel, work profile).
// Anything the phone does not print is reported as unknown (null), never invented.

const KNOWN_STORES = new Set([
  'com.android.vending', // Google Play
  'com.sec.android.app.samsungapps', // Galaxy Store
  'com.huawei.appmarket',
  'com.xiaomi.mipicks',
  'com.xiaomi.market',
  'com.oppo.market',
  'com.heytap.market',
  'com.vivo.appstore',
  'com.amazon.venezia',
  'com.aurora.store',
  'org.fdroid.fdroid',
]);

const PKG_NAME = /^[A-Za-z]\w*(?:\.\w+)+$/;
const COMPONENT = /^[A-Za-z][\w.]*\/[\w.$]+$/;

function getprop(adb, name) {
  return adb.shell(`getprop ${name}`).trim();
}
/** Reads a setting. "null" (unset) and error text (SecurityException, sh: not found) both read as ''. */
function setting(adb, ns, name, user = null) {
  const v = adb.shell(`settings${user === null ? '' : ` --user ${user}`} get ${ns} ${name}`).trim();
  return v === 'null' || /^(Error|Exception|java\.|\/system\/bin\/sh:|usage:)|Exception[: ]/i.test(v) ? '' : v;
}
const indentOf = (line) => {
  let i = 0;
  while (i < line.length && (line.charCodeAt(i) === 32 || line.charCodeAt(i) === 9)) i++;
  return i;
};
/** POSIX single-quote a path for the phone's shell. */
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

// ---------------------------------------------------------------------------------------------
// dumpsys package packages
// ---------------------------------------------------------------------------------------------

/**
 * Splits `dumpsys package packages` into one record per installed package.
 *
 * Handles: `flags=` and `pkgFlags=`; `userId=` (<= Android 9) and `appId=` (10+);
 * `installerPackageName=` as its own line and inside an `InstallSource{...}`; `installInitiator=` /
 * `initiatingPackageName=`; per-user sections (`User 0:`, `User 10:` work profile, `User 999:` MIUI
 * dual apps, `User 150:` Samsung Secure Folder), each with its own installed/enabled/hidden state,
 * runtime permissions and disabled components; `requested permissions:` absent; `install permissions:`
 * and Android 5 `grantedPermissions:`; `splits=[...]`; and the `Hidden system packages:` section, which
 * repeats package names with their factory-image path and must not overwrite the live record.
 *
 * Packages present in the dump but installed for no user (e.g. a system app removed with
 * `pm uninstall --user 0`) are returned separately in notInstalled, not as packages.
 */
function parsePackagesDumpFull(dump) {
  const pkgs = new Map();
  const hiddenSystem = new Map(); // pkg -> factory codePath (updated system apps)
  let section = null; // column-0 header in force ("Packages:", "Hidden system packages:", ...)
  let cur = null; // package under construction
  let user = null; // "User N:" block under construction (inside cur)
  let sub = null; // { kind, list, indent, target } list section under construction

  const finish = () => {
    if (cur) {
      if (cur.hiddenSection) {
        if (cur.attrs.codePath && !hiddenSystem.has(cur.name)) hiddenSystem.set(cur.name, cur.attrs.codePath);
      } else if (!pkgs.has(cur.name)) {
        pkgs.set(cur.name, cur);
      }
    }
    cur = null; user = null; sub = null;
  };

  const lines = dump.split('\n');
  for (let li = 0; li < lines.length; li++) {
    let line = lines[li];
    if (line.endsWith('\r')) line = line.replace(/\r+$/, '');
    if (!line.trim()) continue;
    const ind = indentOf(line);

    if (ind === 0) {
      finish();
      // Only header-shaped lines change section; any other stray column-0 line just ends the package.
      if (/^[A-Z][A-Za-z ]*:\s*$/.test(line)) section = line.trim();
      continue;
    }

    // Fast path, checked first: most lines of a big dump are items of an open list section
    // ("requested permissions:", "runtime permissions:", "disabledComponents:", ...).
    const t = line.trim();
    if (sub && cur && ind > sub.indent) {
      if (sub.kind === 'requested') {
        const m = /^([^\s:,]+)/.exec(t);
        if (m) sub.target.requested.push(m[1]);
      } else if (sub.kind === 'perm') {
        const m = /^([^\s:,]+)(?::\s*granted=(true|false))?/.exec(t);
        if (m) sub.target[sub.list].push({ name: m[1], granted: m[2] === undefined ? sub.defaultGranted : m[2] === 'true' });
      } else if (sub.kind === 'components') {
        const m = /^([\w.$]+)$/.exec(t);
        if (m) sub.target[sub.list].push(m[1]);
      }
      continue;
    }

    const head = /^\s*Package \[([^\]\s]+)\](?: \(([^)]*)\))?:?\s*$/.exec(line);
    if (head) {
      finish();
      const inPackages = section === null || /^Packages:/i.test(section);
      const inHidden = section !== null && /^Hidden system packages/i.test(section);
      if (!inPackages && !inHidden) continue;
      cur = {
        name: head[1], indent: ind, hiddenSection: inHidden,
        attrs: Object.create(null), installSource: Object.create(null),
        requested: [], install: [], legacyGranted: [], sharedRuntime: [], users: [],
      };
      continue;
    }
    if (!cur) continue;
    if (ind <= cur.indent) { finish(); continue; } // stray line at package level: the package is over
    sub = null;

    if (user && ind <= user.indent) user = null;

    const userHead = /^\s*User (\d+):(.*)$/.exec(line);
    if (userHead) {
      user = { id: Number(userHead[1]), indent: ind, attrs: Object.create(null), runtime: [], disabledComponents: [] };
      for (const m of userHead[2].matchAll(/(\w+)=(\S+)/g)) user.attrs[m[1]] = m[2];
      cur.users.push(user);
      continue;
    }

    const listHead = /^\s*([A-Za-z][A-Za-z0-9 _-]*?)(?:\s*\(\d+\))?:\s*$/.exec(line);
    if (listHead) {
      const name = listHead[1].toLowerCase();
      if (name === 'requested permissions') sub = { kind: 'requested', indent: ind, target: cur };
      else if (name === 'install permissions') sub = { kind: 'perm', list: 'install', defaultGranted: true, indent: ind, target: cur };
      else if (name === 'grantedpermissions') sub = { kind: 'perm', list: 'legacyGranted', defaultGranted: true, indent: ind, target: cur };
      else if (name === 'runtime permissions') {
        sub = user
          ? { kind: 'perm', list: 'runtime', defaultGranted: false, indent: ind, target: user }
          : { kind: 'perm', list: 'sharedRuntime', defaultGranted: false, indent: ind, target: cur };
      } else if (user && name === 'disabledcomponents') sub = { kind: 'components', list: 'disabledComponents', indent: ind, target: user };
      else sub = { kind: 'skip', indent: ind }; // declared permissions, overlay paths, usesLibraries, enabledComponents...
      continue;
    }

    // key=value attribute line, owned by the open user block or by the package.
    const kv = /^([A-Za-z]\w*)=(.*)$/.exec(t);
    const owner = user || cur;
    if (kv && !(kv[1] in owner.attrs)) owner.attrs[kv[1]] = kv[2].trim();
    if (!user) {
      if (t.startsWith('versionCode=')) {
        for (const m of t.matchAll(/\b(minSdk|targetSdk)=(\d+)/g)) cur.attrs[m[1]] ??= m[2];
      }
      // InstallSource{installerPackageName=..., initiatingPackageName=..., ...}
      const isrc = /InstallSource\{([^}]*)/.exec(t);
      if (isrc) for (const m of isrc[1].matchAll(/(\w+)=([^\s,}]+)/g)) cur.installSource[m[1]] ??= m[2];
    }
  }
  finish();

  const packages = new Map();
  const notInstalled = [];
  for (const raw of pkgs.values()) {
    const rec = toRecord(raw, hiddenSystem.get(raw.name) || null);
    if (rec.installedUsers.length === 0) notInstalled.push(rec.pkg);
    else packages.set(rec.pkg, rec);
  }
  return { packages: finalizeSideloaded(packages), notInstalled };
}

const nullish = (v) => (v === undefined || v === '' || v === 'null' ? null : v);
const tokenSet = (v) => ` ${(v || '').replace(/[[\],]/g, ' ').trim().split(/\s+/).join(' ')} `;

function toRecord(raw, factoryPath) {
  const a = raw.attrs;
  const flags = tokenSet(a.flags || a.pkgFlags);
  const pflags = tokenSet(a.privateFlags || a.privatePkgFlags);
  const has = (s, f) => s.includes(` ${f} `);

  // Per-user state. No "User N:" line at all (very old or truncated dumps): assume installed for user 0.
  const rawUsers = raw.users.length ? raw.users : [{ id: 0, attrs: {}, runtime: [], disabledComponents: [] }];
  const users = rawUsers.map((u) => {
    const enabledState = Number(u.attrs.enabled ?? 0) || 0; // 0 default, 1 on, 2 off, 3 off by user, 4 until used
    return {
      id: u.id,
      installed: u.attrs.installed === undefined ? true : u.attrs.installed === 'true',
      enabled: !(enabledState === 2 || enabledState === 3 || enabledState === 4),
      enabledState,
      hidden: u.attrs.hidden === 'true',
      stopped: u.attrs.stopped === 'true',
      suspended: u.attrs.suspended === 'true',
      firstInstall: nullish(u.attrs.firstInstallTime),
      granted: u.runtime.filter((p) => p.granted).map((p) => p.name),
      disabledComponents: u.disabledComponents,
    };
  });
  const installedUsers = users.filter((u) => u.installed).map((u) => u.id);
  const primary = users.find((u) => u.id === 0 && u.installed) || users.find((u) => u.installed) || users[0];

  // Granted = install-time grants + runtime grants in every user the app is installed for.
  // (Union on purpose: an app spying from the work profile is still spying.)
  const granted = new Set();
  for (const p of raw.install) if (p.granted) granted.add(p.name);
  for (const p of raw.legacyGranted) if (p.granted) granted.add(p.name);
  for (const p of raw.sharedRuntime) if (p.granted) granted.add(p.name);
  for (const u of users) if (u.installed) for (const g of u.granted) granted.add(g);

  const is = raw.installSource;
  const installer = nullish(a.installerPackageName) || nullish(is.installerPackageName);
  const initiator = nullish(a.installInitiator) || nullish(a.initiatingPackageName) || nullish(is.installInitiator) || nullish(is.initiatingPackageName);
  const firstInstall = nullish(a.firstInstallTime) || primary.firstInstall
    || users.map((u) => u.firstInstall).filter(Boolean).sort()[0] || '';
  const shared = /SharedUserSetting\{\S+ ([^/\s}]+)\//.exec(a.sharedUser || '');
  const codePath = a.codePath || '';

  return {
    pkg: raw.name,
    path: codePath,
    versionName: a.versionName || '',
    versionCode: a.versionCode ? Number(a.versionCode.split(/\s/)[0]) || null : null,
    targetSdk: a.targetSdk ? Number(a.targetSdk) : null,
    minSdk: a.minSdk ? Number(a.minSdk) : null,
    uid: Number(a.appId || a.userId) || null,
    sharedUser: shared ? shared[1] : null,
    installer,
    installInitiator: initiator,
    originatingPackage: nullish(a.originatingPackageName) || nullish(is.originatingPackageName),
    firstInstall,
    lastUpdate: a.lastUpdateTime || '',
    system: has(flags, 'SYSTEM'),
    updatedSystem: has(flags, 'UPDATED_SYSTEM_APP'),
    factoryPath, // factory-image copy of an updated system app (from "Hidden system packages:")
    stub: /-Stub(\/|$)/.test(codePath), // system stub that downloads the real app on first use
    debuggable: has(flags, 'DEBUGGABLE'),
    testOnly: has(flags, 'TEST_ONLY'),
    privileged: has(pflags, 'PRIVILEGED'),
    splits: a.splits ? tokenSet(a.splits).trim().split(' ').filter(Boolean) : [],
    // State for the primary user (user 0, or the first user the app is installed for).
    installed: installedUsers.includes(0),
    hidden: primary.hidden,
    enabled: primary.enabled,
    stopped: primary.stopped,
    suspended: primary.suspended,
    users,
    installedUsers,
    secondaryUserOnly: installedUsers.length > 0 && !installedUsers.includes(0),
    requested: [...new Set(raw.requested)],
    granted: [...granted],
    sideloaded: false, // filled by finalizeSideloaded
  };
}

function finalizeSideloaded(pkgs) {
  for (const p of pkgs.values()) {
    const viaStore = p.installer ? KNOWN_STORES.has(p.installer) : !!(p.installInitiator && KNOWN_STORES.has(p.installInitiator));
    p.sideloaded = !p.system && !viaStore;
  }
  return pkgs;
}

/** Map<pkg, record> of installed packages (kept for existing callers). */
function parsePackagesDump(dump) {
  return parsePackagesDumpFull(dump).packages;
}

// ---------------------------------------------------------------------------------------------
// Launcher icons
// ---------------------------------------------------------------------------------------------

/** Expands "pkg/.Cls" to { pkg, cls: "pkg.Cls" }. */
function component(s) {
  const [pkg, cls = ''] = s.split('/');
  return { pkg, cls: cls.startsWith('.') ? pkg + cls : cls };
}

/**
 * `cmd package query-activities --brief ...`: "pkg/cls" lines. Returns null when the output is not
 * a query-activities answer at all (command missing, usage text, exception), so the caller falls
 * back instead of concluding "no app has an icon".
 */
function parseLauncherActivities(out) {
  const comps = [];
  for (const m of out.matchAll(/^\s*([A-Za-z][\w.]*\/[\w.$]+)\s*$/gm)) comps.push(component(m[1]));
  if (!comps.length && !/No activities found|^\s*0 activities found/im.test(out)) return null;
  return comps;
}

/**
 * Fallback for phones without `cmd package` (Android 6 and older, locked-down OEM builds): the
 * activity resolver table from `dumpsys package r activity`. A filter counts when it has the MAIN
 * action and the LAUNCHER or LEANBACK_LAUNCHER category. Unlike query-activities, this table still
 * lists components the app has disabled (the classic "hide my icon" trick), so the caller subtracts
 * each user's disabledComponents.
 */
function parseResolverLaunchers(out) {
  const comps = new Map();
  let inActivities = false;
  let curComp = null;
  let compIndent = 0;
  let hasMain = false;
  let hasLauncher = false;
  const flush = () => {
    if (curComp && hasMain && hasLauncher) comps.set(curComp, component(curComp));
    curComp = null; hasMain = false; hasLauncher = false;
  };
  for (let line of out.split('\n')) {
    if (line.endsWith('\r')) line = line.replace(/\r+$/, '');
    if (!line.trim()) continue;
    const ind = indentOf(line);
    if (ind === 0) {
      flush();
      inActivities = /^Activity Resolver Table:/i.test(line);
      continue;
    }
    if (!inActivities) continue;
    const c = /^\s+[0-9a-f]+ ([A-Za-z][\w.]*\/[\w.$]+)(?: filter [0-9a-f]+)?\s*$/.exec(line);
    if (c) { flush(); curComp = c[1]; compIndent = ind; continue; }
    if (!curComp) continue;
    if (ind <= compIndent) { flush(); continue; }
    const act = /Action: "([^"]+)"/.exec(line);
    if (act && act[1] === 'android.intent.action.MAIN') hasMain = true;
    const cat = /Category: "([^"]+)"/.exec(line);
    if (cat && (cat[1] === 'android.intent.category.LAUNCHER' || cat[1] === 'android.intent.category.LEANBACK_LAUNCHER')) hasLauncher = true;
  }
  flush();
  return [...comps.values()];
}

const LAUNCHER_Q = (cat, user = 0) => `cmd package query-activities --brief${user ? ` --user ${user}` : ''} -a android.intent.action.MAIN -c android.intent.category.${cat}`;

/** Returns { source: 'cmd'|'dumpsys'|'unavailable', byUser: Map<userId, Set<pkg>> }. */
function collectLaunchers(adb, packages, secondaryUsers) {
  const byUser = new Map();
  const viaCmd = (user) => {
    const phone = parseLauncherActivities(adb.shell(LAUNCHER_Q('LAUNCHER', user)));
    if (!phone || phone.length === 0) return null; // a working phone always has launcher apps
    const tv = parseLauncherActivities(adb.shell(LAUNCHER_Q('LEANBACK_LAUNCHER', user))) || [];
    return new Set([...phone, ...tv].map((c) => c.pkg));
  };
  const primary = viaCmd(0);
  if (primary) {
    byUser.set(0, primary);
    for (const u of secondaryUsers) {
      const s = viaCmd(u);
      if (s) byUser.set(u, s);
    }
    return { source: 'cmd', byUser };
  }
  // Fallback: resolver table (not per user), minus components the app disabled for that user.
  const comps = parseResolverLaunchers(adb.shell('dumpsys package r activity', { maxBuffer: 256 * 1024 * 1024 }));
  if (comps.length === 0) return { source: 'unavailable', byUser };
  for (const uid of [0, ...secondaryUsers]) {
    const set = new Set();
    for (const c of comps) {
      const u = packages.get(c.pkg)?.users.find((x) => x.id === uid);
      if (u && u.disabledComponents.includes(c.cls)) continue;
      set.add(c.pkg);
    }
    byUser.set(uid, set);
  }
  return { source: 'dumpsys', byUser };
}

// ---------------------------------------------------------------------------------------------
// Smaller parsers
// ---------------------------------------------------------------------------------------------

function parseComponentList(value) {
  // "pkg/cls:pkg2/cls2" style settings values. Entries without "/" (e.g. the magnification shortcut
  // "com.android.server.accessibility.MagnificationController") are features, not apps.
  return value
    .split(':')
    .map((s) => s.trim())
    .filter((s) => COMPONENT.test(s))
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

/** `pm list users`: "UserInfo{0:Owner:c13} running", "UserInfo{10:Work profile:1030} running". */
function parseUsers(out) {
  const users = [];
  for (const m of out.matchAll(/UserInfo\{(\d+):(.*?):([0-9a-fA-F]+)\}(\s+running)?/g)) {
    const flags = parseInt(m[3], 16);
    users.push({ id: Number(m[1]), name: m[2], flags, running: !!m[4], managedProfile: (flags & 0x20) !== 0 });
  }
  return users;
}

const ROLES = { SMS: 'sms', DIALER: 'dialer', ASSISTANT: 'assistant', HOME: 'home' };
// One round trip for all four roles. `cmd role get-role-holders` prints the holders joined by ";".
const ROLE_CMD = `for r in ${Object.keys(ROLES).join(' ')}; do echo "$r=$(cmd role get-role-holders android.app.role.$r 2>&1)"; done`;

function parseRoles(out) {
  const roles = {};
  let ok = false;
  for (const line of out.split('\n')) {
    const m = /^(SMS|DIALER|ASSISTANT|HOME)=(.*)$/.exec(line.trim());
    if (!m || /Exception|Error|Unknown|not found|usage/i.test(m[2])) continue;
    ok = true;
    roles[ROLES[m[1]]] = m[2].split(/[;,\s]+/).filter((s) => PKG_NAME.test(s));
  }
  return ok ? roles : null;
}

/** `ls /data/misc/user/0/cacerts-added 2>&1`: files named "<8 hex>.<n>". */
function parseCaCertListing(out) {
  const t = out.trim();
  if (/Permission denied/i.test(t)) return { status: 'denied', files: [] };
  if (!t || /No such file/i.test(t)) return { status: 'none', files: [] };
  const files = t.split(/\s+/).filter((f) => /^[0-9a-f]{8}\.\d+$/.test(f));
  return files.length ? { status: 'listed', files } : { status: 'unknown', files: [] };
}

/**
 * The "Notification listeners:" block of `dumpsys notification`. Sub-headers differ by version
 * ("Enabled listeners:", "All notification listeners (5) enabled for current profiles:",
 * "Live listeners (3):", "Live notification listeners (3):"), so they are classified by keyword.
 */
function parseNotificationListenersDump(out) {
  const res = { ok: false, enabled: [], live: [] };
  const lines = out.split('\n');
  const start = lines.findIndex((l) => /^\s*Notification listeners:\s*$/.test(l));
  if (start < 0) return res;
  res.ok = true;
  const base = indentOf(lines[start]);
  let bucket = null;
  const seen = new Set();
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i].replace(/\r+$/, '');
    if (!line.trim()) continue;
    if (indentOf(line) <= base) break;
    const header = /^\s*([A-Za-z][^:{]*?):\s*$/.exec(line);
    if (header) { bucket = /live/i.test(header[1]) ? 'live' : /enabled|approved/i.test(header[1]) ? 'enabled' : null; continue; }
    if (!bucket) continue;
    const m = /^\s*(?:ComponentInfo\{([^}]+)\}|([A-Za-z][\w.]*\/[\w.$]+))/.exec(line);
    const comp = m && (m[1] || m[2]);
    if (!comp || !comp.includes('/')) continue;
    const userM = /\(user (\d+)\)/.exec(line);
    const key = `${bucket} ${comp} ${userM ? userM[1] : ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    res[bucket].push({ component: comp, pkg: comp.split('/')[0], ...(userM ? { user: Number(userM[1]) } : {}) });
  }
  return res;
}

/** `ps -A -o NAME` (one name per line) or old toolbox `ps` (name in the last column). */
function parseProcessNames(out) {
  const set = new Set();
  for (const line of out.split('\n')) {
    const last = line.trim().split(/\s+/).pop();
    if (!last) continue;
    const name = last.split(':')[0];
    if (/^[a-z]/.test(name) && PKG_NAME.test(name)) set.add(name);
  }
  return set;
}

// ---------------------------------------------------------------------------------------------

export function collect(adb, { log = () => {} } = {}) {
  log('Reading device info');
  const sdk = Number(getprop(adb, 'ro.build.version.sdk')) || 0;
  const stayOn = setting(adb, 'global', 'stay_on_while_plugged_in');
  const device = {
    model: getprop(adb, 'ro.product.model'),
    manufacturer: getprop(adb, 'ro.product.manufacturer'),
    android: getprop(adb, 'ro.build.version.release'),
    sdk,
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
    // Bitmask: 1 AC, 2 USB, 4 wireless, 8 dock. Non-zero keeps the screen awake while charging.
    stayOnWhilePluggedIn: /^\d+$/.test(stayOn) ? Number(stayOn) : null,
    now: adb.shell('date +%s').trim(),
  };

  log('Reading users and work profiles');
  const users = parseUsers(adb.shell('pm list users'));
  const listedSecondary = users.map((u) => u.id).filter((id) => id !== 0);

  log('Reading special-access settings');
  const accessibility = parseComponentList(setting(adb, 'secure', 'enabled_accessibility_services')).map((c) => ({ ...c, user: 0 }));
  const notificationListeners = parseComponentList(setting(adb, 'secure', 'enabled_notification_listeners')).map((c) => ({ ...c, user: 0 }));
  for (const u of listedSecondary.slice(0, 6)) {
    accessibility.push(...parseComponentList(setting(adb, 'secure', 'enabled_accessibility_services', u)).map((c) => ({ ...c, user: u })));
    notificationListeners.push(...parseComponentList(setting(adb, 'secure', 'enabled_notification_listeners', u)).map((c) => ({ ...c, user: u })));
  }
  // The accessibility shortcut (volume keys) and the on-screen accessibility button can switch a
  // service on later even when it is off right now.
  const accessibilityShortcutTargets = [
    ...parseComponentList(setting(adb, 'secure', 'accessibility_shortcut_target_service')).map((c) => ({ ...c, via: 'shortcut' })),
    ...parseComponentList(setting(adb, 'secure', 'accessibility_button_targets')).map((c) => ({ ...c, via: 'button' })),
  ];
  const { admins, deviceOwner, profileOwner } = parseDeviceAdmins(adb.shell('dumpsys device_policy'));
  const idleWhitelist = parseIdleWhitelist(adb.shell('dumpsys deviceidle whitelist'));
  const usageAccess = new Set();
  for (const m of adb.shell('appops query-op GET_USAGE_STATS allow 2>/dev/null').matchAll(/^\s*([A-Za-z]\w*(?:\.\w+)+)\s*$/gm)) usageAccess.add(m[1]);

  // Default SMS / phone / assistant / home apps. Android 10+ has roles; older phones keep settings.
  let roles = sdk >= 29 ? parseRoles(adb.shell(ROLE_CMD)) : null;
  if (roles) roles.source = 'role';
  else {
    const pkgOf = (v) => [String(v || '').split('/')[0]].filter((s) => PKG_NAME.test(s));
    roles = {
      source: 'settings',
      sms: pkgOf(device.defaultSms),
      dialer: pkgOf(setting(adb, 'secure', 'dialer_default_application')),
      assistant: pkgOf(setting(adb, 'secure', 'assistant')),
    };
  }
  for (const k of Object.values(ROLES)) roles[k] ??= [];

  // User-installed CA certificates (a man-in-the-middle sign). Usually unreadable without root.
  const ca = parseCaCertListing(adb.shell('ls /data/misc/user/0/cacerts-added 2>&1'));
  const userCaCerts = { status: ca.status, count: ca.status === 'listed' ? ca.files.length : ca.status === 'none' ? 0 : null, files: ca.files };

  const notificationListenersLive = parseNotificationListenersDump(adb.shell('dumpsys notification', { maxBuffer: 256 * 1024 * 1024 }));

  log('Reading all installed packages (one big dump)');
  const { packages, notInstalled } = parsePackagesDumpFull(adb.shell('dumpsys package packages', { maxBuffer: 512 * 1024 * 1024 }));

  // Launcher icon (phone or TV launcher), checked in the user each app is installed for.
  const secondaryUsers = new Set(listedSecondary);
  for (const p of packages.values()) for (const u of p.installedUsers) if (u !== 0) secondaryUsers.add(u);
  const launcher = collectLaunchers(adb, packages, [...secondaryUsers].slice(0, 6));
  for (const p of packages.values()) {
    // null = could not be determined (never "hidden" by default).
    const uid = p.installedUsers.includes(0) && launcher.byUser.has(0) ? 0 : p.installedUsers.find((u) => launcher.byUser.has(u));
    p.hasLauncherIcon = uid === undefined ? null : launcher.byUser.get(uid).has(p.pkg);
  }

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
    const out = adb.shell(`sha256sum ${chunk.map(shq).join(' ')} 2>/dev/null`);
    for (const [path, h] of parseSha256List(out)) hashes.set(path, h);
  }
  for (const p of packages.values()) {
    p.apkPath = apkPaths.get(p.pkg) || null;
    p.sha256 = p.apkPath ? hashes.get(p.apkPath) || null : null;
  }

  log('Reading network usage per app');
  const netstats = parseNetstats(adb.shell('dumpsys netstats detail'));

  log('Reading running processes');
  const running = parseProcessNames(adb.shell('ps -A -o NAME 2>/dev/null || ps -A'));

  return {
    collectedAt: new Date().toISOString(),
    device,
    users,
    accessibility,
    accessibilityShortcutTargets,
    notificationListeners,
    notificationListenersLive,
    deviceAdmins: admins,
    deviceOwner,
    profileOwner,
    roles,
    userCaCerts,
    idleWhitelist: [...idleWhitelist],
    usageAccess: [...usageAccess],
    running: [...running],
    netstats: Object.fromEntries([...netstats].map(([k, v]) => [k, v])),
    launcher: { source: launcher.source },
    notInstalledPackages: notInstalled,
    packages: [...packages.values()],
  };
}

export const _internal = {
  parsePackagesDump, parsePackagesDumpFull, parseDeviceAdmins, parseLauncherActivities, parseResolverLaunchers,
  parseIdleWhitelist, parseNetstats, parseSha256List, parseUsers, parseRoles, parseCaCertListing,
  parseNotificationListenersDump, parseProcessNames, parseComponentList, ROLE_CMD, LAUNCHER_Q, shq,
};
