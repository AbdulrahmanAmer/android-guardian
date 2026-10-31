// Where things live, both when running from source (node guardian.mjs) and as the compiled AndroidGuardian.exe.
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import { findAdb } from './adb.mjs';

export const IS_COMPILED = /AndroidGuardian/i.test(basename(process.execPath));
export const APP_DIR = IS_COMPILED ? dirname(process.execPath) : join(dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_DIR = join(APP_DIR, 'data');
export const REPORT_DIR = join(APP_DIR, 'reports');
export const WORK_DIR = join(APP_DIR, 'data', 'work');

for (const d of [DATA_DIR, REPORT_DIR, WORK_DIR]) mkdirSync(d, { recursive: true });

const exe = (name) => (process.platform === 'win32' ? `${name}.exe` : name);

/** Bundled adb first, then the Android SDK on this machine, then PATH. */
export function adbBinary() {
  const bundled = join(APP_DIR, 'platform-tools', exe('adb'));
  if (existsSync(bundled)) return bundled;
  return findAdb();
}

/** aapt2 reads the human-readable app name out of an APK. Optional. */
export function aapt2Binary() {
  const bundled = join(APP_DIR, 'tools', exe('aapt2'));
  if (existsSync(bundled)) return bundled;
  const sdk = process.env.ANDROID_HOME || (process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Android', 'Sdk'));
  if (sdk && existsSync(join(sdk, 'build-tools'))) {
    for (const v of readdirSync(join(sdk, 'build-tools')).sort().reverse()) {
      const p = join(sdk, 'build-tools', v, exe('aapt2'));
      if (existsSync(p)) return p;
    }
  }
  return null;
}
