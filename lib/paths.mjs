// Where things live, both when running from source (node guardian.mjs) and as the compiled AndroidGuardian.exe.
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync, readdirSync, realpathSync } from 'node:fs';
import { findAdb } from './adb.mjs';

/** Kept in step with package.json by test/server.test.mjs (the compiled exe cannot read package.json). */
export const VERSION = '0.1.0';

// winget's portable install starts the exe through a symlink: resolve it so the bundled adb is found next to the real file.
const EXE = (() => { try { return realpathSync(process.execPath); } catch { return process.execPath; } })();
export const IS_COMPILED = /AndroidGuardian/i.test(basename(EXE));
export const APP_DIR = IS_COMPILED ? dirname(EXE) : join(dirname(fileURLToPath(import.meta.url)), '..');
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

/** "android-guardian-samsung-sm-a525f-2026-10-31.html": model and scan date, safe for any file system. */
export function reportFileName(device = {}, when = new Date()) {
  const slug = (s) => String(s ?? '').normalize('NFKD').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase().slice(0, 40);
  const maker = slug(device.manufacturer);
  let model = slug(device.model);
  if (maker && model.startsWith(maker)) model = model.slice(maker.length).replace(/^-+/, '');
  const name = [maker, model].filter(Boolean).join('-') || 'phone';
  let d = new Date(when);
  if (Number.isNaN(d.getTime())) d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `android-guardian-${name}-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}.html`;
}
