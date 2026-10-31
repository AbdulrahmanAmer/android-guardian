// Is the phone ready? Figures out exactly what the user still has to do, in plain words.
import { Adb } from './adb.mjs';

export const STEPS_ENABLE_DEBUGGING = [
  'On the phone open Settings > About phone.',
  'Tap "Build number" 7 times until it says you are a developer (on Samsung: Settings > About phone > Software information).',
  'Go back to Settings > System > Developer options (Samsung: Settings > Developer options) and turn on "USB debugging".',
  'Plug the phone into this computer with a USB cable. If the phone asks, choose "File transfer" and tap "Allow" for USB debugging.',
];

const PROBE_KEY = 'android_guardian_probe';
const PROBE_PKG = 'com.android.guardian.probe.does.not.exist';

/** Never let a probe take readiness down: a timeout or spawn error reads as "probe failed". */
function safe(fn, fallback) {
  try { return fn(); } catch { return fallback; }
}

/**
 * Can we change settings? Writes a private key, reads it back, deletes it, and checks it is gone.
 * Xiaomi/MIUI refuses `settings put` over USB (SecurityException) until "USB debugging (Security
 * settings)" is on; that must read as canWrite=false, never as an exception.
 */
export function probeWrite(dev) {
  const put = safe(() => dev.shellResult(`settings put global ${PROBE_KEY} 1`), { ok: false, text: 'probe failed' });
  const readBack = put.ok ? safe(() => dev.shell(`settings get global ${PROBE_KEY}`).trim(), '') : '';
  const canWrite = put.ok && readBack === '1';
  let cleanedUp = true;
  if (put.ok) {
    safe(() => dev.shellResult(`settings delete global ${PROBE_KEY}`), null);
    const after = safe(() => dev.shell(`settings get global ${PROBE_KEY}`).trim(), '?');
    cleanedUp = after === 'null' || after === '';
  }
  return { canWrite, cleanedUp, detail: put.ok ? '' : put.text };
}

/**
 * Can we uninstall? `pm list users` must answer, and uninstalling a package that does not exist must
 * fail the normal way ("Failure [not installed for 0]" on Android 8+, "Failure [DELETE_FAILED_INTERNAL_ERROR]"
 * before), not with a SecurityException / "Permission Denial" (some OEM builds and MDM-locked phones).
 */
export function probeUninstall(dev) {
  const users = safe(() => dev.shellResult('pm list users').text, '');
  const usersOk = /UserInfo\{\d+:/.test(users);
  const un = safe(() => dev.shellResult(`pm uninstall --user 0 ${PROBE_PKG}`).text, '');
  // DELETE_FAILED_USER_RESTRICTED is checked before the package lookup, so an MDM "no uninstalling"
  // restriction shows up even for a package that does not exist.
  const denied = /SecurityException|Permission Denial|not allowed|denied|USER_RESTRICTED|DEVICE_POLICY_MANAGER/i.test(un);
  const normal = /Failure|Unknown package|not installed/i.test(un) || /^Success$/m.test(un);
  return { canUninstall: usersOk && normal && !denied, usersOk, detail: un.split('\n')[0].slice(0, 200) };
}

const NOT_READY = {
  unauthorized: {
    title: 'Phone found, waiting for your permission',
    todo: ['Look at the phone screen: a box asks "Allow USB debugging?". Tick "Always allow from this computer" and tap Allow.', 'If no box appears, unplug and plug the cable again, or in Developer options tap "Revoke USB debugging authorizations" and reconnect.'],
  },
  authorizing: {
    title: 'Phone found, waiting for your permission',
    todo: ['Look at the phone screen and tap Allow on "Allow USB debugging?".'],
  },
  offline: {
    title: 'Phone connected but not responding',
    todo: ['Unlock the phone screen.', 'Unplug the cable and plug it in again.', 'Turn USB debugging off and on in Developer options.'],
  },
  'no-permissions': {
    title: 'This computer is not allowed to talk to the phone',
    todo: ['Unplug the phone and plug it in again.', 'On the phone, choose "File transfer" when it asks what the USB connection is for.', 'If it still does not work, restart this computer.'],
  },
  recovery: {
    title: 'The phone is in recovery mode',
    todo: ['Choose "Reboot system now" on the phone and wait for it to start normally.', 'Then unlock it and press "Check again".'],
  },
  sideload: {
    title: 'The phone is waiting for an update file (sideload mode)',
    todo: ['On the phone go back and choose "Reboot system now".', 'Then unlock it and press "Check again".'],
  },
  rescue: {
    title: 'The phone is in rescue mode',
    todo: ['Restart the phone normally, unlock it, and press "Check again".'],
  },
  bootloader: {
    title: 'The phone is in bootloader (fastboot) mode',
    todo: ['Choose "Start" on the phone (use the volume keys, confirm with the power key) and wait for it to start normally.'],
  },
};
const NOT_READY_ORDER = ['unauthorized', 'authorizing', 'no-permissions', 'offline', 'recovery', 'sideload', 'rescue', 'bootloader'];

/**
 * readiness(bin) -> { state, title, devices, todo, device?, capabilities?, otherDevices? }
 * state: no-adb | adb-error | no-device | unauthorized | authorizing | no-permissions | offline |
 *        recovery | sideload | rescue | bootloader | ready.
 * With several phones attached, the first one in state "device" is used and the others are listed
 * in otherDevices (and in todo), so the user knows which phone was picked.
 * `makeAdb` is for tests (replay fixtures); production code passes only `bin`.
 */
export function readiness(bin, { makeAdb = (opts) => new Adb(opts) } = {}) {
  if (!bin) {
    return { state: 'no-adb', title: 'Phone driver (adb) not found', devices: [], todo: ['Reinstall Android Guardian; the platform-tools folder is missing.'] };
  }
  let devices;
  try {
    devices = makeAdb({ bin, timeoutMs: 20_000 }).devices();
  } catch (e) {
    return {
      state: 'adb-error',
      title: 'The phone driver (adb) did not answer',
      devices: [],
      todo: ['Close other Android tools (Android Studio, phone managers, other copies of this program) and press "Check again".', 'If it keeps happening, restart this computer.'],
      error: String(e?.message || e).slice(0, 300),
    };
  }
  if (devices.length === 0) {
    return {
      state: 'no-device',
      title: 'No phone detected',
      devices,
      todo: ['Connect the phone with a USB cable (a charging-only cable will not work).', ...STEPS_ENABLE_DEBUGGING],
    };
  }
  const ready = devices.find((d) => d.state === 'device');
  if (!ready) {
    const st = NOT_READY_ORDER.find((s) => devices.some((d) => d.state === s));
    if (st) return { state: st, title: NOT_READY[st].title, devices, todo: NOT_READY[st].todo };
    return { state: 'offline', title: NOT_READY.offline.title, devices, todo: NOT_READY.offline.todo };
  }

  const otherDevices = devices.filter((d) => d !== ready);
  const dev = makeAdb({ bin, serial: ready.serial, timeoutMs: 20_000 });
  const prop = (name) => safe(() => dev.shell(`getprop ${name}`).trim(), '');
  const info = {
    serial: ready.serial,
    model: prop('ro.product.model') || (ready.model || '').replace(/_/g, ' '),
    manufacturer: prop('ro.product.manufacturer'),
    android: prop('ro.build.version.release'),
    sdk: Number(prop('ro.build.version.sdk')) || 0,
  };
  const write = probeWrite(dev);
  const uninstall = probeUninstall(dev);

  const todo = [];
  if (otherDevices.length) {
    const names = otherDevices.map((d) => `${(d.model || d.serial).replace(/_/g, ' ')} (${d.state})`);
    todo.push(`More than one phone is connected. Checking ${info.manufacturer} ${info.model} (${info.serial}); unplug the others if this is not the right one: ${names.join(', ')}.`);
  }
  if (!write.canWrite) {
    todo.push(
      /xiaomi|redmi|poco/i.test(info.manufacturer)
        ? 'Xiaomi phones need one more switch: Settings > Additional settings > Developer options > "USB debugging (Security settings)" > ON. You must be signed into a Mi account and the phone needs a SIM card for this switch.'
        : 'The phone refuses setting changes over USB. Removal will still work; some "block" and "protect" actions will not. Check Developer options for a second USB debugging switch.',
    );
  }
  if (!uninstall.canUninstall) {
    todo.push('The phone refuses to uninstall apps over USB (it may be managed by an organisation, or a security app blocks it). The scan still works; removal may fail.');
  }
  return {
    state: 'ready',
    title: `Connected: ${info.manufacturer} ${info.model} (Android ${info.android})`,
    devices,
    otherDevices,
    device: info,
    capabilities: { canWrite: write.canWrite, canUninstall: uninstall.canUninstall, probeCleanedUp: write.cleanedUp, listUsers: uninstall.usersOk },
    todo,
  };
}
