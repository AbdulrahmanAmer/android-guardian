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
 * Phones without the adb shell protocol (Android 6 and older) send output through a pty, which
 * turns "\n" into "\r\n" (and on some Windows/adb combinations "\r\r\n"). Every parser downstream
 * expects plain "\n", so shell output is normalised once, here.
 */
export function normalizeEol(text) {
  return text.includes('\r') ? text.replace(/\r+\n/g, '\n').replace(/\r+$/, '') : text;
}

// States `adb devices` can print after the serial. "no permissions" carries a free-text tail.
const DEVICE_PROP = /^(usb|product|model|device|transport_id|features):/;

/**
 * Parses `adb devices -l`. Ignores the header, adb-server start-up noise ("* daemon not running;
 * starting now at tcp:5037", "* daemon started successfully", "adb server version (41) doesn't
 * match this client (39); killing...") and anything else that is not a serial + state line.
 */
export function parseDevices(out) {
  const list = [];
  for (const raw of normalizeEol(out || '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('*') || /^List of devices/i.test(line) || /^adb (server|: )/i.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 2) continue;
    const serial = tokens[0];
    let i = 1;
    const stateWords = [];
    while (i < tokens.length && !DEVICE_PROP.test(tokens[i])) stateWords.push(tokens[i++]);
    const stateText = stateWords.join(' ');
    let state = stateWords[0] || 'unknown';
    if (/^no permissions/i.test(stateText)) state = 'no-permissions';
    if (!/^(device|unauthorized|offline|recovery|sideload|bootloader|rescue|authorizing|connecting|host|no-permissions|unknown)$/.test(state)) continue;
    const props = {};
    for (const t of tokens.slice(i)) {
      const k = t.indexOf(':');
      props[t.slice(0, k)] = t.slice(k + 1);
    }
    list.push({ serial, state, stateText, model: props.model, device: props.device, product: props.product, transportId: props.transport_id });
  }
  return list;
}

/**
 * mode: 'live' (talk to a phone), 'record' (talk and save every command), 'replay' (answer from a recording).
 * A recording is <fixtureDir>/commands.json: { "<adb args joined by space>": <result> }, where <result> is the
 * stdout string (command succeeded with nothing on stderr) or { stdout, stderr, status }.
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
      const rec = this._replay(args);
      if (rec === undefined) {
        if (allowFail) return { stdout: '', stderr: 'fixture missing', status: 1 };
        throw new Error(`No fixture for: adb ${args.join(' ')}`);
      }
      const out = typeof rec === 'string' ? { stdout: rec, stderr: '', status: 0 } : { stdout: rec.stdout ?? '', stderr: rec.stderr ?? '', status: rec.status ?? 0 };
      if (out.status !== 0 && !allowFail) throw new Error(`adb ${args.join(' ')} failed (${out.status}): ${out.stderr || out.stdout}`);
      return out;
    }
    const full = this.serial ? ['-s', this.serial, ...args] : args;
    const r = spawnSync(this.bin, full, { encoding: 'utf8', timeout: this.timeoutMs, maxBuffer });
    if (r.error) throw r.error;
    const out = { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
    if (this.mode === 'record') {
      // Plain string when the command succeeded quietly (small, readable, same as older recordings);
      // the full triple when stderr or the exit status carry information a replay must reproduce.
      this.recording[args.join(' ')] = out.status === 0 && !out.stderr ? out.stdout : out;
      writeFileSync(join(this.fixtureDir, 'commands.json'), JSON.stringify(this.recording, null, 1));
    }
    if (out.status !== 0 && !allowFail) {
      throw new Error(`adb ${args.join(' ')} failed (${out.status}): ${out.stderr || out.stdout}`);
    }
    return out;
  }

  /** Run a shell command on the phone and return stdout ('' on failure), line endings normalised. */
  shell(cmd, opts = {}) {
    return normalizeEol(this.raw(['shell', cmd], { allowFail: true, ...opts }).stdout);
  }

  /** Run a shell command where the result matters; returns { text, ok }. */
  shellResult(cmd) {
    const r = this.raw(['shell', cmd], { allowFail: true });
    const text = normalizeEol(r.stdout + r.stderr).trim();
    return { text, ok: r.status === 0 && !/Failure|Error|error:|not allowed|SecurityException|Exception/i.test(text) };
  }

  pull(remote, local) {
    if (this.mode === 'replay') return false;
    const r = this.raw(['pull', remote, local], { allowFail: true });
    return r.status === 0 && existsSync(local);
  }

  devices() {
    return parseDevices(this.raw(['devices', '-l'], { allowFail: true }).stdout);
  }
}
