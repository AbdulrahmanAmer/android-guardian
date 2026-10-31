// Removal, disarming and protection over ADB, without root.
//
// Every public function returns at least { ok, steps: [{ action, ok, text }], manualSteps: [string] }.
// `steps` is what the tool did and what the phone answered; `manualSteps` is what the person must
// do on the phone themselves when Android refused (plain language, which Settings screen, what to tap).
// Nothing here retries in a loop: every refusal is reported once with its next step.

const P = 'android.permission.';
const DANGEROUS = [
  'RECORD_AUDIO', 'CAMERA', 'READ_SMS', 'RECEIVE_SMS', 'RECEIVE_MMS', 'SEND_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
  'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'READ_CALENDAR',
  'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO',
  'READ_MEDIA_AUDIO', 'ANSWER_PHONE_CALLS', 'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'POST_NOTIFICATIONS', 'NEARBY_WIFI_DEVICES', 'BLUETOOTH_CONNECT',
].map((p) => P + p);

/** App-ops set to `ignore` when disarming. Ops that do not exist on a given Android version are skipped and reported. */
export const BLOCK_APPOPS = [
  'RECORD_AUDIO', 'CAMERA', 'COARSE_LOCATION', 'FINE_LOCATION', 'READ_SMS', 'READ_CALL_LOG', 'SYSTEM_ALERT_WINDOW', 'GET_USAGE_STATS',
  'RUN_IN_BACKGROUND', 'RUN_ANY_IN_BACKGROUND', 'WAKE_LOCK', 'BIND_ACCESSIBILITY_SERVICE',
];

export const DNS_PROVIDERS = {
  quad9: { host: 'dns.quad9.net', label: 'Quad9 (blocks malware + stalkerware domains, non-profit)' },
  adguard: { host: 'dns.adguard-dns.com', label: 'AdGuard DNS (blocks malware, trackers and ads)' },
  cloudflare: { host: 'security.cloudflare-dns.com', label: 'Cloudflare for Families (blocks malware)' },
};

/** The only settings a device fix may change, and the only values it may set them to. */
export const DEVICE_FIX_ALLOWLIST = {
  'global development_settings_enabled': ['0'],
  'secure install_non_market_apps': ['0'],
  'global package_verifier_enable': ['1'],
  'global verifier_verify_adb_installs': ['1'],
  'global private_dns_mode': ['opportunistic'],
};

// Where things are on the phone. Menus differ by maker; these name Pixel/stock and Samsung and give a search term.
const WHERE = {
  deviceAdmin: 'Settings › Security & privacy › More security & privacy › Device admin apps (Samsung: Settings › Security and privacy › Other security settings › Device admin apps; any phone: search Settings for "device admin")',
  appInfo: (pkg) => `Settings › Apps › See all apps › ${pkg} (Samsung: Settings › Apps › ${pkg}; the app may show a different name; tap ⋮ › Show system apps if you cannot find it)`,
  factoryReset: 'Settings › System › Reset options › Erase all data (Samsung: Settings › General management › Reset › Factory data reset)',
  workProfile: 'Settings › Passwords & accounts › Work tab › Remove work profile (Samsung: Settings › Accounts and backup › Manage accounts › Work › Remove work profile; any phone: search Settings for "work profile")',
  privateDns: 'Settings › Network & internet › Private DNS (Samsung: Settings › Connections › More connection settings › Private DNS)',
};

const BEFORE_RESET = 'Before a factory reset: save this report (it is evidence), back up photos and contacts, and if you may be in danger talk to a support organisation first (stopstalkerware.org lists them). Do not restore a full phone backup afterwards; reinstall your apps from the store instead.';

const PKG_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
const COMPONENT_RE = /^[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z0-9_.$]+$/;

/** Package names reach a shell on the phone: anything that is not a plain Java package name is refused. */
export function assertPackageName(pkg) {
  if (typeof pkg !== 'string' || pkg.length > 255 || !PKG_RE.test(pkg)) throw new Error(`Refusing invalid package name: ${JSON.stringify(pkg)}`);
  return pkg;
}

function step(steps, action, res) {
  steps.push({ action, ok: res.ok, text: res.text });
  return res.ok;
}
function info(steps, action, text, ok = true) {
  steps.push({ action, ok, text });
}
function manual(list, text) {
  if (!list.includes(text)) list.push(text);
}

export function readSdk(adb) {
  return Number(adb.shell('getprop ro.build.version.sdk').trim()) || 0;
}

/** `pm list users` -> [{ id, name }]. Always includes user 0. */
export function listUsers(adb) {
  const users = [];
  for (const m of adb.shell('pm list users').matchAll(/UserInfo\{(\d+):([^:}]*)/g)) users.push({ id: Number(m[1]), name: m[2] });
  if (!users.some((u) => u.id === 0)) users.unshift({ id: 0, name: 'Owner' });
  return users;
}

const fullComponent = (c) => {
  const [pkg, cls] = c.split('/');
  return `${pkg}/${cls.startsWith('.') ? pkg + cls : cls}`;
};
const pkgOf = (c) => c.split('/')[0];

/** dumpsys device_policy -> { owners: [{ kind: 'device'|'profile', user, component }], admins: [{ user, component, testOnly }] } */
export function parseDevicePolicy(dump) {
  const owners = [];
  const admins = [];
  let section = null;
  for (const line of String(dump).split(/\r?\n/)) {
    let m;
    if ((m = line.match(/^(\s*)Device Owner\b(?! Type)/))) { section = { kind: 'device', user: 0, indent: m[1].length }; continue; }
    if ((m = line.match(/^(\s*)Profile Owner \(User (\d+)\)/))) { section = { kind: 'profile', user: Number(m[2]), indent: m[1].length }; continue; }
    if ((m = line.match(/^(\s*)Enabled Device Admins \(User (\d+)/))) { section = { kind: 'admins', user: Number(m[2]), indent: m[1].length }; continue; }
    if (section && line.trim() && line.match(/^\s*/)[0].length <= section.indent) section = null; // left that block
    if (section && (section.kind === 'device' || section.kind === 'profile')) {
      if (!section.owner && (m = line.match(/admin=ComponentInfo\{([^}]+)\}/))) {
        section.owner = { kind: section.kind, user: section.user, component: m[1] };
        owners.push(section.owner);
      } else if (section.owner && section.kind === 'device' && (m = line.match(/^\s*User ID:\s*(\d+)/))) section.owner.user = Number(m[1]);
      continue;
    }
    if (section?.kind === 'admins') {
      // Indentation differs between Android versions (2 or 4 spaces); match on shape, not depth.
      if ((m = line.match(/^\s+([\w.]+\/[\w.$]+):\s*$/))) admins.push({ user: section.user, component: m[1], testOnly: null });
      else if ((m = line.match(/^\s+testOnlyAdmin=(true|false)/)) && admins.length) admins.at(-1).testOnly = m[1] === 'true';
    }
  }
  return { owners, admins };
}

function componentListWithout(adb, settingName, pkg) {
  const cur = adb.shell(`settings get secure ${settingName}`).trim();
  if (!cur || cur === 'null') return null;
  const all = cur.split(':').filter(Boolean);
  const kept = all.filter((c) => c.split('/')[0] !== pkg);
  if (kept.length === all.length) return null; // nothing to change
  return kept.join(':');
}

/**
 * Take away device-admin, accessibility and notification-listener rights, in that order.
 * Device admin: one attempt per admin component, never repeated. Owner apps get the factory-reset answer.
 */
export function stripSpecialAccess(adb, pkg, steps, manualSteps = [], policy = parseDevicePolicy(adb.shell('dumpsys device_policy'))) {
  assertPackageName(pkg);
  const result = { adminRemoved: true, owner: null };
  for (const adm of policy.admins.filter((a) => pkgOf(a.component) === pkg)) {
    if (!COMPONENT_RE.test(adm.component)) { info(steps, 'Remove device-administrator right', `Skipped: unexpected component name ${adm.component}`, false); result.adminRemoved = false; continue; }
    const owner = policy.owners.find((o) => fullComponent(o.component) === fullComponent(adm.component) || pkgOf(o.component) === pkg);
    const res = adb.shellResult(`dpm remove-active-admin --user ${adm.user} '${adm.component}'`);
    if (step(steps, `Remove device-administrator right (${adm.component}, user ${adm.user})`, res)) continue;
    result.adminRemoved = false;
    if (owner || /owner/i.test(res.text)) {
      const o = owner || { kind: /profile/i.test(res.text) ? 'profile' : 'device', user: adm.user };
      result.owner = o;
      if (o.kind === 'profile' && o.user !== 0) {
        manual(manualSteps, `${pkg} manages the work profile (user ${o.user}) on this phone and Android does not let it be removed over USB. Remove the whole work profile: ${WHERE.workProfile}. This deletes every app and file inside the work profile. If the phone does not let you remove it, a factory reset is the only way: ${WHERE.factoryReset}. ${BEFORE_RESET}`);
      } else {
        manual(manualSteps, `${pkg} is the ${o.kind === 'device' ? 'device owner' : 'profile owner'} of this phone: it manages the whole phone. Android never lets an owner app be removed over USB or from Settings. A factory reset is the only way to remove it: ${WHERE.factoryReset}. If this is a work phone from your employer, ask their IT team instead. ${BEFORE_RESET}`);
      }
    } else if (/protected/i.test(res.text)) {
      manual(manualSteps, `Android reports the administrator right of ${pkg} as protected, so it cannot be removed over USB. Try on the phone: ${WHERE.deviceAdmin}, turn ${pkg} off and tap Deactivate. If the switch is greyed out, a factory reset is the only way: ${WHERE.factoryReset}. ${BEFORE_RESET}`);
    } else {
      // Typical: "Attempt to remove non-test admin" (shell may only remove test-only admins).
      manual(manualSteps, `Turn off the device-administrator right of ${pkg} on the phone: ${WHERE.deviceAdmin}. Tap ${pkg}, tap Deactivate (or turn its switch off), then press Remove again here.`);
    }
  }

  const acc = componentListWithout(adb, 'enabled_accessibility_services', pkg);
  if (acc !== null) {
    step(steps, 'Turn off accessibility access', adb.shellResult(`settings put secure enabled_accessibility_services '${acc}'`));
    if (!acc) adb.shellResult('settings put secure accessibility_enabled 0');
  }
  const nl = componentListWithout(adb, 'enabled_notification_listeners', pkg);
  if (nl !== null) step(steps, 'Turn off notification access', adb.shellResult(`settings put secure enabled_notification_listeners '${nl}'`));
  return result;
}

/** true / false, or null when the shell is not allowed to look into that user (managed work profile). */
export function isInstalledFor(adb, pkg, user = 0) {
  const out = adb.shell(`pm list packages --user ${user} ${pkg} 2>&1`);
  if (/SecurityException|does not have permission|Error/i.test(out)) return null;
  return new RegExp(`^package:${pkg.replace(/\./g, '\\.')}\\s*$`, 'm').test(out);
}
export function isInstalled(adb, pkg) {
  return isInstalledFor(adb, pkg, 0) === true;
}

function userLine(adb, pkg, user = 0) {
  return adb.shell(`dumpsys package ${pkg}`).match(new RegExp(`User ${user}:[^\\n]*`))?.[0] || '';
}

/** Classify a `pm uninstall` answer. */
export function classifyUninstall(text) {
  const t = String(text || '');
  if (/^\s*Success\s*$/m.test(t)) return 'SUCCESS';
  if (/not installed for \d+/i.test(t)) return 'NOT_INSTALLED';
  for (const code of ['DELETE_FAILED_DEVICE_POLICY_MANAGER', 'DELETE_FAILED_OWNER_BLOCKED', 'DELETE_FAILED_USER_RESTRICTED', 'DELETE_FAILED_INTERNAL_ERROR']) {
    if (t.includes(code)) return code;
  }
  if (/does not have permission to access user|SecurityException/i.test(t)) return 'NO_ACCESS_TO_USER';
  return 'UNKNOWN';
}

function uninstallAdvice(code, pkg, user, ctx) {
  const ownerName = ctx.deviceOwner ? ` (${pkgOf(ctx.deviceOwner.component)})` : '';
  switch (code) {
    case 'DELETE_FAILED_DEVICE_POLICY_MANAGER':
      if (ctx.owner || ctx.adminAdviceGiven) return null; // the admin step already said what to do
      return `Android refused because ${pkg} is still a device administrator. On the phone: ${WHERE.deviceAdmin}. Tap ${pkg}, tap Deactivate, then press Remove again here.`;
    case 'DELETE_FAILED_OWNER_BLOCKED':
      return `The phone's manager app${ownerName} has blocked uninstalling ${pkg}. If this is a work phone, ask your employer's IT team. If nobody you know manages this phone, the manager app itself is part of the problem and a factory reset is the only way to remove it: ${WHERE.factoryReset}. ${BEFORE_RESET}`;
    case 'DELETE_FAILED_USER_RESTRICTED':
      return `Uninstalling apps is switched off on this phone by its manager app${ownerName} (restriction "no uninstall apps"). If this is a work phone, ask your employer's IT team. Otherwise only a factory reset lifts the restriction: ${WHERE.factoryReset}. ${BEFORE_RESET} Until then the app has been disabled and stripped of its rights where Android allowed it.`;
    case 'DELETE_FAILED_INTERNAL_ERROR':
      return `Android gave an internal error while removing ${pkg} (common for apps that are part of the phone's own software). Restart the phone, connect again and press Remove once more. If it still fails: ${WHERE.appInfo(pkg)}, tap Uninstall, or Disable if Uninstall is greyed out.`;
    case 'NO_ACCESS_TO_USER':
      return user !== 0
        ? `USB access to the work profile (user ${user}) is blocked by its manager. On the phone open Settings › Apps, switch to the Work tab, choose ${pkg} and tap Uninstall. If you do not recognise the work profile, remove it entirely: ${WHERE.workProfile}.`
        : `Android refused USB access while removing ${pkg}. ${WHERE.appInfo(pkg)}, tap Uninstall.`;
    default:
      return `Android refused to remove ${pkg}. Try on the phone: ${WHERE.appInfo(pkg)}, tap Uninstall (or Disable if Uninstall is greyed out).`;
  }
}

/** Remove an app completely, for every user on the phone (or disable it where it cannot be uninstalled). */
export function removeApp(adb, pkg) {
  assertPackageName(pkg);
  const steps = [];
  const manualSteps = [];
  const sdk = readSdk(adb);
  const policy = parseDevicePolicy(adb.shell('dumpsys device_policy'));
  const deviceOwner = policy.owners.find((o) => o.kind === 'device') || null;

  // 1-3. admin -> accessibility -> notification listener
  const access = stripSpecialAccess(adb, pkg, steps, manualSteps, policy);
  // 4. force-stop in every user
  step(steps, 'Force-stop the app', adb.shellResult(`am force-stop --user all ${pkg}`));

  // 5. uninstall (data included: never `-k`) for every user that has it
  const system = new RegExp(`^package:${pkg.replace(/\./g, '\\.')}\\s*$`, 'm').test(adb.shell(`pm list packages -s ${pkg}`));
  const users = listUsers(adb);
  const perUser = {};
  for (const u of users) {
    const before = isInstalledFor(adb, pkg, u.id);
    if (before === false) { perUser[u.id] = 'NOT_INSTALLED'; continue; }
    const res = adb.shellResult(`pm uninstall --user ${u.id} ${pkg}`);
    const code = before === null && classifyUninstall(res.text) === 'UNKNOWN' ? 'NO_ACCESS_TO_USER' : classifyUninstall(res.text);
    perUser[u.id] = code;
    const label = `Uninstall for user ${u.id}${u.name ? ` (${u.name})` : ''}`;
    if (code === 'SUCCESS') info(steps, label, res.text || 'Success');
    else if (code === 'NOT_INSTALLED') info(steps, label, 'Not installed for this user.');
    else {
      info(steps, label, `${code}: ${res.text}`, false);
      const advice = uninstallAdvice(code, pkg, u.id, { owner: access.owner, adminAdviceGiven: !access.adminRemoved, deviceOwner });
      if (advice) manual(manualSteps, advice);
    }
  }

  // Fallback for user 0 when Android refused: disable, wipe data, cut background, suspend.
  const failed0 = !['SUCCESS', 'NOT_INSTALLED'].includes(perUser[0]);
  if (failed0) {
    const dis = adb.shellResult(`pm disable-user --user 0 ${pkg}`);
    step(steps, 'Disable for this user', dis);
    step(steps, 'Clear its data', adb.shellResult(`pm clear --user 0 ${pkg}`));
    blockBackground(adb, pkg, steps, sdk);
    if (!dis.ok && sdk >= 28) step(steps, 'Suspend the app (it cannot open or run)', adb.shellResult(`pm suspend --user 0 ${pkg}`));
  }

  // Verify: read the phone's own state back.
  const after = {};
  for (const u of users) after[u.id] = isInstalledFor(adb, pkg, u.id);
  const pathOut = adb.shell(`pm path ${pkg}`).trim();
  const line0 = after[0] ? userLine(adb, pkg, 0) : '';
  const disabledListed = after[0]
    ? new RegExp(`^package:${pkg.replace(/\./g, '\\.')}\\s*$`, 'm').test(adb.shell(`pm list packages -d --user 0 ${pkg}`))
    : false;
  const disabled0 = !!after[0] && (/enabled=(2|3|4)\b/.test(line0) || disabledListed);
  const suspended0 = !!after[0] && /suspended=true/.test(line0);
  const stillIn = users.filter((u) => after[u.id] === true).map((u) => u.id);
  const unknown = users.filter((u) => after[u.id] === null).map((u) => u.id);
  const removed = stillIn.length === 0 && unknown.length === 0;
  const otherEnabled = stillIn.filter((id) => id !== 0);
  const ok = (after[0] !== true || disabled0 || suspended0) && otherEnabled.length === 0;

  let text;
  if (removed) text = system && pathOut
    ? 'Removed for every user. It is a system app: a factory copy stays in the phone\'s read-only system area, cannot run, and only returns after a factory reset.'
    : 'App is gone from the phone.';
  else if (after[0] !== true && otherEnabled.length === 0) text = `Removed for your user. Could not check user ${unknown.join(', ')} (managed work profile).`;
  else if (disabled0) text = `App could not be uninstalled but is now disabled for your user (it cannot run).${otherEnabled.length ? ` It is still installed for user ${otherEnabled.join(', ')}.` : ''}`;
  else if (suspended0) text = 'App could not be uninstalled or disabled but is suspended (it cannot open or run).';
  else text = `App is still installed and enabled for user ${stillIn.join(', ')}. Removal FAILED.`;
  steps.push({ action: 'Verify', ok, text });
  if (unknown.length) manual(manualSteps, uninstallAdvice('NO_ACCESS_TO_USER', pkg, unknown[0], {}));
  if (!ok && manualSteps.length === 0) manual(manualSteps, uninstallAdvice('UNKNOWN', pkg, 0, {}));

  return { ok, removed, disabled: disabled0, suspended: suspended0, system, perUser, steps, manualSteps };
}

function uidOf(adb, pkg) {
  const m = adb.shell(`dumpsys package ${pkg}`).match(/\n\s+(?:userId|appId)=(\d+)/);
  return m ? Number(m[1]) : null;
}

function blockBackground(adb, pkg, steps, sdk, uid, { ops = true } = {}) {
  if (ops) {
    step(steps, 'Forbid running in background', adb.shellResult(`appops set ${pkg} RUN_IN_BACKGROUND ignore`));
    if (sdk >= 28) step(steps, 'Forbid any background activity', adb.shellResult(`appops set ${pkg} RUN_ANY_IN_BACKGROUND ignore`));
    step(steps, 'Forbid drawing over other apps', adb.shellResult(`appops set ${pkg} SYSTEM_ALERT_WINDOW ignore`));
  }
  if (new RegExp(`,${pkg.replace(/\./g, '\\.')},`).test(adb.shell('dumpsys deviceidle whitelist'))) {
    step(steps, 'Remove battery-optimisation exemption', adb.shellResult(`dumpsys deviceidle whitelist -${pkg}`));
  }
  if (uid) {
    // Per-app only. Never `cmd netpolicy set restrict-background true`: that is Data Saver for the whole phone.
    let r = adb.shellResult(`cmd netpolicy add restrict-background-blacklist ${uid}`);
    if (!r.ok && /unknown|invalid/i.test(r.text)) r = adb.shellResult(`cmd netpolicy add restrict-background-denylist ${uid}`);
    step(steps, 'Block background mobile data', r);
  }
}

const NOT_REVOCABLE = /not a changeable permission type|has not requested permission|Unknown permission|is not a runtime permission|non-runtime permission/i;

function grantedPermissions(adb, pkg) {
  return [...adb.shell(`dumpsys package ${pkg}`).matchAll(/^\s+([\w.]+): granted=true/gm)].map((m) => m[1]);
}

/** `appops get <pkg>` -> Map(op -> mode) */
export function parseAppops(out) {
  const map = new Map();
  for (const m of String(out).matchAll(/^\s*([A-Z_]+):\s*([a-z]+)/gm)) map.set(m[1], m[2]);
  return map;
}

/** Keep the app installed but take away everything that makes it dangerous. */
export function blockApp(adb, pkg, { uid, granted = [] } = {}) {
  assertPackageName(pkg);
  const steps = [];
  const manualSteps = [];
  const warnings = [];
  const sdk = readSdk(adb);
  stripSpecialAccess(adb, pkg, steps, manualSteps);
  step(steps, 'Force-stop the app', adb.shellResult(`am force-stop ${pkg}`));

  // Runtime permissions: everything the snapshot saw granted, plus the dangerous list.
  const held = granted.length ? granted : grantedPermissions(adb, pkg);
  const toRevoke = [...new Set([...held, ...DANGEROUS])].filter((p) => /^[\w.]+$/.test(p));
  const revoked = [];
  let notRevocable = 0;
  for (const perm of toRevoke) {
    const res = adb.shellResult(`pm revoke ${pkg} ${perm}`);
    if (res.ok) { if (held.includes(perm)) { revoked.push(perm); info(steps, `Revoke ${perm.replace(P, '')}`, res.text); } continue; }
    if (NOT_REVOCABLE.test(res.text)) { notRevocable++; continue; }
    step(steps, `Revoke ${perm.replace(P, '')}`, res);
  }
  if (notRevocable) info(steps, 'Install-time permissions', `${notRevocable} permission(s) are not runtime permissions or were never requested; Android does not allow revoking those (normal).`);

  // App-ops: ignore where the op exists on this Android version.
  const unsupportedOps = [];
  const setOps = [];
  for (const op of BLOCK_APPOPS) {
    const res = adb.shellResult(`appops set ${pkg} ${op} ignore`);
    if (res.ok) setOps.push(op);
    else if (/Unknown operation|No operation|Invalid op/i.test(res.text)) unsupportedOps.push(op);
    else step(steps, `Set app-op ${op} to ignore`, res);
  }
  info(steps, 'Block sensitive app-ops', `Set to "ignore": ${setOps.join(', ') || 'none'}${unsupportedOps.length ? `. Not available on this Android version: ${unsupportedOps.join(', ')}` : ''}.`, setOps.length > 0);

  // Background: per-app data restriction, standby bucket, battery exemption.
  const appUid = uid || uidOf(adb, pkg);
  blockBackground(adb, pkg, steps, sdk, appUid, { ops: false });
  let previousBucket = null;
  if (sdk >= 28) {
    previousBucket = adb.shell(`am get-standby-bucket ${pkg}`).trim() || null;
    const bucket = sdk >= 30 ? 'restricted' : 'rare';
    step(steps, `Put the app in the "${bucket}" standby bucket`, adb.shellResult(`am set-standby-bucket ${pkg} ${bucket}`));
    // Strongest no-root option: a suspended app cannot open, run or receive broadcasts; the phone shows a dialog instead.
    step(steps, 'Suspend the app (it cannot open or run)', adb.shellResult(`pm suspend --user 0 ${pkg}`));
  } else {
    warnings.push(`Android ${sdk ? `SDK ${sdk}` : 'version unknown'}: suspending apps and the restricted standby bucket need Android 9 or newer, so the app can still start; only its permissions and background rights were removed.`);
  }
  adb.shellResult(`am force-stop ${pkg}`);
  if (appUid) warnings.push('The background-data block only applies to mobile data; on Wi-Fi the suspension and app-op blocks are what stop it.');

  // Verify from the phone's own state.
  const dump = adb.shell(`dumpsys package ${pkg}`);
  const stillGranted = [...dump.matchAll(/^\s+([\w.]+): granted=true/gm)].map((m) => m[1]).filter((p) => DANGEROUS.includes(p) || revoked.includes(p));
  const modes = parseAppops(adb.shell(`appops get ${pkg}`));
  const notIgnored = setOps.filter((op) => modes.has(op) && !['ignore', 'deny', 'errored'].includes(modes.get(op)));
  const suspended = sdk >= 28 ? /suspended=true/.test(dump.match(/User 0:[^\n]*/)?.[0] || '') : false;
  const bucketNow = sdk >= 28 ? adb.shell(`am get-standby-bucket ${pkg}`).trim() : '';
  const ok = stillGranted.length === 0 && (sdk < 28 || suspended);
  const parts = [];
  parts.push(stillGranted.length ? `still holds ${stillGranted.map((p) => p.replace(P, '')).join(', ')}` : 'no dangerous permission granted');
  if (notIgnored.length) parts.push(`app-ops not confirmed as ignore: ${notIgnored.join(', ')}`);
  if (sdk >= 28) parts.push(suspended ? 'suspended' : 'NOT suspended');
  if (bucketNow) parts.push(`standby bucket ${bucketNow}`);
  steps.push({ action: 'Verify', ok, text: parts.join('; ') + '.' });
  if (!ok) manual(manualSteps, `Some rights could not be taken away over USB. On the phone: ${WHERE.appInfo(pkg)}. Tap Permissions and set each one to "Don't allow", then tap Force stop. If Android lets you, tap Uninstall instead.`);
  if (sdk >= 28 && suspended) warnings.push('If you opened this by mistake: "Undo" un-suspends the app. Its permissions stay revoked; grant them again in the phone\'s Settings if you trust it.');
  return { ok, suspended, previousBucket, steps, manualSteps, warnings };
}

/** Undo the parts of blockApp that stop the app working (suspension, standby bucket). Permissions stay revoked by design. */
export function undoBlock(adb, pkg, { previousBucket } = {}) {
  assertPackageName(pkg);
  const steps = [];
  const manualSteps = [];
  const sdk = readSdk(adb);
  if (sdk < 28) {
    info(steps, 'Nothing to undo', 'Android 8 and older: this tool did not suspend the app.');
    return { ok: true, steps, manualSteps };
  }
  step(steps, 'Un-suspend the app', adb.shellResult(`pm unsuspend --user 0 ${pkg}`));
  const bucket = /^(active|working_set|frequent|rare|restricted|\d{1,2})$/.test(String(previousBucket || '')) && !['45', '50', 'restricted'].includes(String(previousBucket)) ? previousBucket : 'active';
  step(steps, `Standby bucket back to ${bucket}`, adb.shellResult(`am set-standby-bucket ${pkg} ${bucket}`));
  step(steps, 'Allow background activity again', adb.shellResult(`appops set ${pkg} RUN_ANY_IN_BACKGROUND allow`));
  const suspended = /suspended=true/.test(userLine(adb, pkg, 0));
  steps.push({ action: 'Verify', ok: !suspended, text: suspended ? 'App is still suspended.' : 'App can open again. Its permissions stay revoked; grant them in Settings if you trust it.' });
  if (suspended) manual(manualSteps, `Open the app on the phone and, on the "app paused" dialog, tap the option to unpause, or restart the phone and press Undo again.`);
  return { ok: !suspended, steps, manualSteps };
}

const DNS_CORPORATE_WARNING = 'Some workplace, school, hotel and café Wi-Fi networks block Private DNS. If the phone shows "Private DNS server cannot be accessed" or has no internet on such a network, set it back to Automatic: ' + WHERE.privateDns + '.';

/** Private DNS to a filtering resolver: blocks stalkerware/malware command servers phone-wide. Android 9+ only. */
export function setDnsProtection(adb, provider = 'quad9') {
  const p = DNS_PROVIDERS[provider];
  if (!p) throw new Error(`Unknown DNS provider ${provider}`);
  const steps = [];
  const manualSteps = [];
  const sdk = readSdk(adb);
  if (sdk < 28) {
    const release = adb.shell('getprop ro.build.version.release').trim();
    info(steps, 'Private DNS', `This phone runs Android ${release || '(unknown version)'}${sdk ? ` (SDK ${sdk})` : ''}. Private DNS needs Android 9 or newer, so nothing was changed.`, false);
    return { ok: false, unsupported: true, steps, manualSteps, warnings: [] };
  }
  step(steps, `Set Private DNS to ${p.host}`, adb.shellResult(`settings put global private_dns_specifier ${p.host}`));
  step(steps, 'Enable Private DNS (hostname mode)', adb.shellResult('settings put global private_dns_mode hostname'));
  const mode = adb.shell('settings get global private_dns_mode').trim();
  const host = adb.shell('settings get global private_dns_specifier').trim();
  const ok = mode === 'hostname' && host === p.host;
  steps.push({ action: 'Verify', ok, text: ok ? `Phone now uses ${p.host} for all DNS lookups.` : `Private DNS reads back as mode "${mode}", server "${host}".` });
  if (!ok) manual(manualSteps, `Set it by hand: ${WHERE.privateDns} › Private DNS provider hostname › type ${p.host} › Save.`);
  return { ok, steps, manualSteps, warnings: [DNS_CORPORATE_WARNING] };
}

/** Back to the Android default ("Automatic" = opportunistic). */
export function clearDnsProtection(adb) {
  const steps = [];
  const manualSteps = [];
  const sdk = readSdk(adb);
  if (sdk < 28) {
    info(steps, 'Private DNS', 'This phone is older than Android 9 and has no Private DNS setting; nothing to undo.');
    return { ok: true, unsupported: true, steps, manualSteps, warnings: [] };
  }
  step(steps, 'Private DNS back to automatic', adb.shellResult('settings put global private_dns_mode opportunistic'));
  const mode = adb.shell('settings get global private_dns_mode').trim();
  const ok = mode === 'opportunistic';
  steps.push({ action: 'Verify', ok, text: ok ? 'Private DNS is on Automatic (the Android default).' : `Private DNS reads back as "${mode}".` });
  if (!ok) manual(manualSteps, `Set it by hand: ${WHERE.privateDns} › Automatic › Save.`);
  return { ok, steps, manualSteps, warnings: [] };
}

/**
 * Device-level hardening commands offered by rules.mjs findings. The command text can come back from the
 * browser, so only `settings put` on the allowlisted names with the allowlisted values is accepted.
 */
export function applyDeviceFix(adb, cmd) {
  const m = /^settings put (global|secure) ([\w.]+) (\S+)$/.exec(String(cmd));
  if (!m) throw new Error('Refusing unknown fix command');
  const allowed = DEVICE_FIX_ALLOWLIST[`${m[1]} ${m[2]}`];
  if (!allowed || !allowed.includes(m[3])) throw new Error(`Refusing fix for setting ${m[1]} ${m[2]} = ${m[3]}: not on the allowlist`);
  const steps = [];
  step(steps, cmd, adb.shellResult(cmd));
  const now = adb.shell(`settings get ${m[1]} ${m[2]}`).trim();
  steps.push({ action: 'Verify', ok: now === m[3], text: `${m[2]} reads back as "${now}"` });
  return { ok: steps.every((s) => s.ok), steps, manualSteps: [] };
}
