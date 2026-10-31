// Removal and blocking over ADB, without root.
// Every function returns { ok, steps: [{ action, ok, text }] } so the UI can show exactly what happened.

const DANGEROUS = [
  'RECORD_AUDIO', 'CAMERA', 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
  'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'READ_CALENDAR',
  'READ_PHONE_STATE', 'READ_EXTERNAL_STORAGE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO', 'ANSWER_PHONE_CALLS',
].map((p) => 'android.permission.' + p);

export const DNS_PROVIDERS = {
  quad9: { host: 'dns.quad9.net', label: 'Quad9 (blocks malware + stalkerware domains, non-profit)' },
  adguard: { host: 'dns.adguard-dns.com', label: 'AdGuard DNS (blocks malware, trackers and ads)' },
  cloudflare: { host: 'security.cloudflare-dns.com', label: 'Cloudflare for Families (blocks malware)' },
};

function step(steps, action, res) {
  steps.push({ action, ok: res.ok, text: res.text });
  return res.ok;
}

function componentListWithout(adb, settingName, pkg) {
  const cur = adb.shell(`settings get secure ${settingName}`).trim();
  if (!cur || cur === 'null') return null;
  const kept = cur.split(':').filter((c) => c && c.split('/')[0] !== pkg);
  if (kept.length === cur.split(':').filter(Boolean).length) return null; // nothing to change
  return kept.join(':');
}

export function stripSpecialAccess(adb, pkg, steps) {
  // Accessibility
  const acc = componentListWithout(adb, 'enabled_accessibility_services', pkg);
  if (acc !== null) {
    step(steps, 'Turn off accessibility access', adb.shellResult(`settings put secure enabled_accessibility_services '${acc}'`));
    if (!acc) adb.shellResult('settings put secure accessibility_enabled 0');
  }
  // Notification listeners
  const nl = componentListWithout(adb, 'enabled_notification_listeners', pkg);
  if (nl !== null) step(steps, 'Turn off notification access', adb.shellResult(`settings put secure enabled_notification_listeners '${nl}'`));
  // Device admin
  const dump = adb.shell('dumpsys device_policy');
  for (const m of dump.matchAll(/^\s{2,}([\w.]+\/[\w.$]+):\s*$/gm)) {
    if (m[1].split('/')[0] === pkg) step(steps, `Remove device-administrator right (${m[1]})`, adb.shellResult(`dpm remove-active-admin ${m[1]}`));
  }
}

export function isInstalled(adb, pkg) {
  return new RegExp(`^package:${pkg.replace(/\./g, '\\.')}\\s*$`, 'm').test(adb.shell(`pm list packages --user 0 ${pkg}`));
}

/** Remove an app completely (or disable it if it cannot be uninstalled). */
export function removeApp(adb, pkg) {
  const steps = [];
  stripSpecialAccess(adb, pkg, steps);
  step(steps, 'Force-stop the app', adb.shellResult(`am force-stop ${pkg}`));
  let res = adb.shellResult(`pm uninstall --user 0 ${pkg}`);
  let removed = step(steps, 'Uninstall', res);
  if (!removed && /DEVICE_POLICY_MANAGER/i.test(res.text)) {
    steps.push({ action: 'Note', ok: false, text: 'The app is protected by a device-administrator policy. On the phone: Settings > Security > Device admin apps > turn it off for this app, then try again.' });
  }
  if (!removed) {
    // System or protected app: disable and wipe its data instead.
    step(steps, 'Disable for this user', adb.shellResult(`pm disable-user --user 0 ${pkg}`));
    step(steps, 'Clear its data', adb.shellResult(`pm clear ${pkg}`));
    blockBackground(adb, pkg, steps);
  }
  const stillThere = isInstalled(adb, pkg);
  const enabled = stillThere && !/enabled=(2|3)/.test(adb.shell(`dumpsys package ${pkg}`).match(/User 0:[^\n]*/)?.[0] || '');
  steps.push({
    action: 'Verify',
    ok: !stillThere || !enabled,
    text: !stillThere ? 'App is gone from the phone.' : !enabled ? 'App could not be uninstalled but is now disabled and cannot run.' : 'App is still installed and enabled. Removal FAILED.',
  });
  return { ok: !stillThere || !enabled, removed: !stillThere, steps };
}

function blockBackground(adb, pkg, steps, uid) {
  step(steps, 'Forbid running in background', adb.shellResult(`appops set ${pkg} RUN_IN_BACKGROUND ignore`));
  adb.shellResult(`appops set ${pkg} RUN_ANY_IN_BACKGROUND ignore`);
  step(steps, 'Forbid drawing over other apps', adb.shellResult(`appops set ${pkg} SYSTEM_ALERT_WINDOW ignore`));
  step(steps, 'Remove battery-optimisation exemption', adb.shellResult(`dumpsys deviceidle whitelist -${pkg}`));
  if (uid) step(steps, 'Block background internet', adb.shellResult(`cmd netpolicy add restrict-background-blacklist ${uid}`));
}

/** Keep the app installed but take away everything that makes it dangerous. */
export function blockApp(adb, pkg, { uid, granted = [] } = {}) {
  const steps = [];
  stripSpecialAccess(adb, pkg, steps);
  step(steps, 'Force-stop the app', adb.shellResult(`am force-stop ${pkg}`));
  const toRevoke = granted.filter((g) => DANGEROUS.includes(g));
  for (const perm of toRevoke) step(steps, `Revoke ${perm.replace('android.permission.', '')}`, adb.shellResult(`pm revoke ${pkg} ${perm}`));
  blockBackground(adb, pkg, steps, uid);
  const stillGranted = [...adb.shell(`dumpsys package ${pkg}`).matchAll(/^\s+([\w.]+): granted=true/gm)].map((m) => m[1]).filter((p) => DANGEROUS.includes(p));
  steps.push({ action: 'Verify', ok: stillGranted.length === 0, text: stillGranted.length ? `Still holds: ${stillGranted.join(', ')}` : 'All surveillance permissions revoked; app cannot run in the background.' });
  return { ok: stillGranted.length === 0, steps };
}

/** Private DNS to a filtering resolver: blocks stalkerware/malware command servers phone-wide. */
export function setDnsProtection(adb, provider = 'quad9') {
  const steps = [];
  const p = DNS_PROVIDERS[provider];
  if (!p) throw new Error(`Unknown DNS provider ${provider}`);
  step(steps, `Set Private DNS to ${p.host}`, adb.shellResult(`settings put global private_dns_specifier ${p.host}`));
  step(steps, 'Enable Private DNS (hostname mode)', adb.shellResult('settings put global private_dns_mode hostname'));
  const now = adb.shell('settings get global private_dns_specifier').trim();
  steps.push({ action: 'Verify', ok: now === p.host, text: now === p.host ? `Phone now uses ${p.host} for all DNS lookups.` : `Private DNS reads back as "${now}"` });
  return { ok: now === p.host, steps };
}

export function clearDnsProtection(adb) {
  const steps = [];
  step(steps, 'Private DNS back to automatic', adb.shellResult('settings put global private_dns_mode opportunistic'));
  return { ok: steps.every((s) => s.ok), steps };
}

/** Device-level hardening commands offered by rules.mjs findings. Only known-safe `settings put` commands are allowed. */
export function applyDeviceFix(adb, cmd) {
  if (!/^settings put (global|secure) [\w.]+ \S+$/.test(cmd)) throw new Error('Refusing unknown fix command');
  const steps = [];
  step(steps, cmd, adb.shellResult(cmd));
  return { ok: steps.every((s) => s.ok), steps };
}
