// Small persistent settings file next to the app (data/config.json).
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DATA_DIR } from './paths.mjs';

const FILE = join(DATA_DIR, 'config.json');
const DEFAULTS = { vtApiKey: '' };

export function loadConfig() {
  try { return { ...DEFAULTS, ...(existsSync(FILE) ? JSON.parse(readFileSync(FILE, 'utf8')) : {}) }; } catch { return { ...DEFAULTS }; }
}
export function saveConfig(patch) {
  const next = { ...loadConfig(), ...patch };
  writeFileSync(FILE, JSON.stringify(next, null, 1));
  return next;
}

/** A VirusTotal API key is 64 hex characters; accept any short alphanumeric string, or empty to clear. */
export const isValidVtKey = (k) => typeof k === 'string' && /^[A-Za-z0-9]{0,128}$/.test(k.trim());
