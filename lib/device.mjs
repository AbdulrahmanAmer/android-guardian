// Is the phone ready? Figures out exactly what the user still has to do, in plain words.
import { Adb } from './adb.mjs';

export const STEPS_ENABLE_DEBUGGING = [
  'On the phone open Settings > About phone.',
  'Tap "Build number" 7 times until it says you are a developer (on Samsung: Settings > About phone > Software information).',
  'Go back to Settings > System > Developer options (Samsung: Settings > Developer options) and turn on "USB debugging".',
  'Plug the phone into this computer with a USB cable. If the phone asks, choose "File transfer" and tap "Allow" for USB debugging.',
];

export function readiness(bin) {
  if (!bin) {
    return { state: 'no-adb', title: 'Phone driver (adb) not found', devices: [], todo: ['Reinstall Android Guardian; the platform-tools folder is missing.'] };
  }
  const adb = new Adb({ bin, timeoutMs: 20_000 });
  const devices = adb.devices().filter((d) => d.serial && !/^List/.test(d.serial));
  if (devices.length === 0) {
    return {
      state: 'no-device',
      title: 'No phone detected',
      devices,
      todo: ['Connect the phone with a USB cable (a charging-only cable will not work).', ...STEPS_ENABLE_DEBUGGING],
    };
  }
  const unauthorized = devices.find((d) => d.state === 'unauthorized');
  if (unauthorized && !devices.some((d) => d.state === 'device')) {
    return {
      state: 'unauthorized',
      title: 'Phone found, waiting for your permission',
      devices,
      todo: ['Look at the phone screen: a box asks "Allow USB debugging?". Tick "Always allow from this computer" and tap Allow.', 'If no box appears, unplug and plug the cable again, or in Developer options tap "Revoke USB debugging authorizations" and reconnect.'],
    };
  }
  const offline = devices.find((d) => d.state === 'offline');
  if (offline && !devices.some((d) => d.state === 'device')) {
    return { state: 'offline', title: 'Phone connected but not responding', devices, todo: ['Unlock the phone screen.', 'Unplug the cable and plug it in again.', 'Turn USB debugging off and on in Developer options.'] };
  }
  const ready = devices.find((d) => d.state === 'device');
  const dev = new Adb({ bin, serial: ready.serial, timeoutMs: 20_000 });
  const info = {
    serial: ready.serial,
    model: dev.shell('getprop ro.product.model').trim(),
    manufacturer: dev.shell('getprop ro.product.manufacturer').trim(),
    android: dev.shell('getprop ro.build.version.release').trim(),
  };
  // Can we change settings? (Xiaomi/MIUI blocks this until "USB debugging (Security settings)" is on.)
  const probe = dev.shellResult('settings put global android_guardian_probe 1');
  const canWrite = probe.ok && dev.shell('settings get global android_guardian_probe').trim() === '1';
  dev.shellResult('settings delete global android_guardian_probe');
  const canUninstall = /Success|Failure \[(DELETE_FAILED_INTERNAL_ERROR|not installed)/i.test(dev.shellResult('pm uninstall --user 0 com.android.guardian.does.not.exist').text) || true;
  const todo = [];
  if (!canWrite) {
    todo.push(
      /xiaomi|redmi|poco/i.test(info.manufacturer)
        ? 'Xiaomi phones need one more switch: Settings > Additional settings > Developer options > "USB debugging (Security settings)" > ON. You must be signed into a Mi account and the phone needs a SIM card for this switch.'
        : 'The phone refuses setting changes over USB. Removal will still work; some "block" and "protect" actions will not. Check Developer options for a second USB debugging switch.',
    );
  }
  return {
    state: 'ready',
    title: `Connected: ${info.manufacturer} ${info.model} (Android ${info.android})`,
    devices,
    device: info,
    capabilities: { canWrite, canUninstall },
    todo,
  };
}
