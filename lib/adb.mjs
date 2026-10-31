// Thin wrapper around the adb binary. Every phone command goes through here so a
// scan can be recorded to disk and replayed later without a phone (fixtures/tests).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const CANDIDATES = [
  process.env.ADB,
  process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Android', 'Sdk', 'platform-tools', 'adb.exe'),
  process.env.ANDROID_HOME && join(process.env.ANDROID_HOME, 'platform-tools', 'adb.exe'),
  process.env.ANDROID_HOME && join(process.env.ANDROID_HOME, 'platform-tools', 'adb'),
  'adb',
].filter(Boolean);

export function findAdb() {
  for (const c of CANDIDATES) {
    if (c === 'adb') {
      const r = spawnSync('adb', ['version'], { encoding: 'utf8', timeout: 10_000 });
      if (r.status === 0) return 'adb';
    } else if (existsSync(c)) return c;
  }
  return null;
}

/**
 * mode: 'live' (talk to a phone), 'record' (talk and save every command), 'replay' (answer from a recording).
 * A recording is <fixtureDir>/commands.json: { "<adb args joined by space>": "<stdout>" }.
 * In replay, a key ending in "*" matches any command that starts with the text before the "*".
 */
export class Adb {
  constructor({ bin, serial, mode = 'live', fixtureDir, timeoutMs = 120_000 } = {}) {
    this.bin = bin;
    this.serial = serial;
    this.mode = mode;
    this.fixtureDir = fixtureDir;
    this.timeoutMs = timeoutMs;
    this.recording = null;
    if (mode !== 'live') {
      if (!fixtureDir) throw new Error(`${mode} mode needs fixtureDir`);
      mkdirSync(fixtureDir, { recursive: true });
      const file = join(fixtureDir, 'commands.json');
      this.recording = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
    }
  }

  _replay(args) {
    const key = args.join(' ');
    if (key in this.recording) return this.recording[key];
    let best = null;
    for (const k of Object.keys(this.recording)) {
      if (k.endsWith('*') && key.startsWith(k.slice(0, -1)) && (!best || k.length > best.length)) best = k;
    }
    return best ? this.recording[best] : undefined;
  }

  raw(args, { allowFail = false, maxBuffer = 256 * 1024 * 1024 } = {}) {
    if (this.mode === 'replay') {
      const out = this._replay(args);
      if (out === undefined) {
        if (allowFail) return { stdout: '', stderr: 'fixture missing', status: 1 };
        throw new Error(`No fixture for: adb ${args.join(' ')}`);
      }
      return { stdout: out, stderr: '', status: 0 };
    }
    const full = this.serial ? ['-s', this.serial, ...args] : args;
    const r = spawnSync(this.bin, full, { encoding: 'utf8', timeout: this.timeoutMs, maxBuffer });
    if (r.error) throw r.error;
    const out = { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
    if (this.mode === 'record') {
      this.recording[args.join(' ')] = out.stdout;
      writeFileSync(join(this.fixtureDir, 'commands.json'), JSON.stringify(this.recording, null, 1));
    }
    if (out.status !== 0 && !allowFail) {
      throw new Error(`adb ${args.join(' ')} failed (${out.status}): ${out.stderr || out.stdout}`);
    }
    return out;
  }

  /** Run a shell command on the phone and return stdout ('' on failure). */
  shell(cmd, opts = {}) {
    return this.raw(['shell', cmd], { allowFail: true, ...opts }).stdout;
  }

  /** Run a shell command where the result matters; returns { text, ok }. */
  shellResult(cmd) {
    const r = this.raw(['shell', cmd], { allowFail: true });
    const text = (r.stdout + r.stderr).trim();
    return { text, ok: r.status === 0 && !/Failure|Error|error:|not allowed|SecurityException|Exception/i.test(text) };
  }

  pull(remote, local) {
    if (this.mode === 'replay') return false;
    const r = this.raw(['pull', remote, local], { allowFail: true });
    return r.status === 0 && existsSync(local);
  }

  devices() {
    const out = this.raw(['devices', '-l'], { allowFail: true }).stdout;
    return out
      .split(/\r?\n/)
      .slice(1)
      .map((l) => l.trim())
      .filter((l) => l && !/^\*/.test(l))
      .map((l) => {
        const [serial, state, ...rest] = l.split(/\s+/);
        const props = Object.fromEntries(rest.map((kv) => kv.split(':')));
        return { serial, state, model: props.model, device: props.device };
      });
  }
}
