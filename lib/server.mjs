// Local web interface: a small HTTP server on 127.0.0.1 that the default browser opens.
//
// Safety: binds to 127.0.0.1 only; rejects any Host header that is not 127.0.0.1/localhost (DNS rebinding);
// every POST needs the header "X-Guardian: 1" and a same-origin Origin (cross-site requests cannot set it);
// every response carries no-store, nosniff and a CSP that allows nothing from outside this page.
//
// Phone-changing actions (remove, block, fix, DNS) run in a child process (`guardian __action`) so the
// server stays responsive while adb works, and so each phone command can be shown live in the page.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { existsSync, writeFileSync } from 'node:fs';
import { Adb } from './adb.mjs';
import { readiness, STEPS_ENABLE_DEBUGGING } from './device.mjs';
import { loadIocs } from './iocs.mjs';
import { runScan } from './scan.mjs';
import { htmlReport } from './report.mjs';
import * as remediate from './remediate.mjs';
import { adbBinary, APP_DIR, DATA_DIR, WORK_DIR, REPORT_DIR, IS_COMPILED, VERSION, reportFileName } from './paths.mjs';
import { UI_HTML } from './ui-bundle.mjs';
import { loadConfig, saveConfig, isValidVtKey } from './config.mjs';

const { DNS_PROVIDERS } = remediate;
const hasUndoBlock = () => typeof remediate.undoBlock === 'function';

// GUARDIAN_DEMO=<fixture dir> runs the interface against a recorded phone (screenshots, UI work without a device).
const DEMO = process.env.GUARDIAN_DEMO || null;
const IDLE_MS = Number(process.env.GUARDIAN_IDLE_MS) || 10 * 60_000;
// A recorded scan answers instantly; in demo mode its log is played back at this pace so the Scanning screen can be seen.
const DEMO_PACE_MS = DEMO ? Number(process.env.GUARDIAN_DEMO_PACE_MS ?? 600) : 0;
const PKG_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
const MAX_BODY = 64 * 1024;

const state = {
  scanning: false,
  log: [],
  progress: null, // { step, total, label }
  steps: [],
  scanError: null, // { message, at }
  result: null,
  snapshot: null,
  lastScanAt: null,
  iocs: null,
  serial: null,
  busy: null, // { kind, pkg, n, text, startedAt } while a phone action runs
  actions: {}, // pkg -> { outcome: removed|disabled|suspended|blocked|failed, kind, at, ok, steps, manualSteps, warnings, demo, previousBucket }
  actionLog: [], // every action since the scan, in order, as htmlReport wants it: { kind, pkg, ...outcome }
  other: {}, // 'dns' | 'fix:<i>' -> last outcome, so a refreshed page can show it again
};
const clients = new Set();
let port = 0;
let shuttingDown = false;

// ---------- events ----------
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}
function log(text) {
  state.log.push({ t: Date.now(), text });
  if (state.log.length > 500) state.log.splice(0, state.log.length - 500);
  broadcast('log', { text });
  if (state.scanning) progressFromLog(text);
}

// ---------- scan progress: which step of how many, in plain words ----------
const SCAN_STEPS = [
  { label: 'Loading the list of known spyware', match: /known indicators|stalkerware indicators|refresh indicators/i },
  { label: 'Reading the phone’s details', match: /device info/i },
  { label: 'Checking for work profiles and other users', match: /users and work profiles/i },
  { label: 'Checking which apps have special access', match: /special-access/i },
  { label: 'Reading the list of installed apps', match: /installed packages/i },
  { label: 'Taking a fingerprint of each app', match: /^Hashing/i },
  { label: 'Checking which apps use the internet', match: /network usage/i },
  { label: 'Checking what is running right now', match: /running processes/i },
  { label: 'Checking who made each app', match: /Checking signatures/i, liveOnly: true },
  { label: 'Asking VirusTotal about app files', match: /VirusTotal/i, needsVt: true },
];
function setProgress(i, label) {
  state.progress = { step: Math.min(i + 1, state.steps.length), total: state.steps.length, label: label || state.steps[i]?.label || '' };
  broadcast('progress', state.progress);
}
function progressFromLog(text) {
  if (/^Scan finished/i.test(text)) return setProgress(state.steps.length - 1, 'Finishing up');
  const i = state.steps.findIndex((s) => s.match.test(text));
  if (i >= 0 && i + 1 >= (state.progress?.step || 0)) setProgress(i);
}

// ---------- phone ----------
const DEMO_STATES = {
  'no-adb': { state: 'no-adb', title: 'Phone driver (adb) not found', devices: [], todo: ['Reinstall Android Guardian; the platform-tools folder is missing.'] },
  'no-device': { state: 'no-device', title: 'No phone detected', devices: [], todo: ['Connect the phone with a USB cable (a charging-only cable will not work).', ...STEPS_ENABLE_DEBUGGING] },
  unauthorized: { state: 'unauthorized', title: 'Phone found, waiting for your permission', devices: [], todo: ['Look at the phone screen: a box asks "Allow USB debugging?". Tick "Always allow from this computer" and tap Allow.', 'If no box appears, unplug and plug the cable again, or in Developer options tap "Revoke USB debugging authorizations" and reconnect.'] },
  offline: { state: 'offline', title: 'Phone connected but not responding', devices: [], todo: ['Unlock the phone screen.', 'Unplug the cable and plug it in again.', 'Turn USB debugging off and on in Developer options.'] },
};
let demoState = process.env.GUARDIAN_DEMO_STATE || 'ready';
function demoReadiness() {
  const device = { serial: 'demo', model: 'SM-A525F (recording)', manufacturer: 'samsung', android: '13' };
  if (DEMO_STATES[demoState]) return DEMO_STATES[demoState];
  if (demoState === 'multiple') return multiple([{ serial: 'a', state: 'device', model: 'SM_A525F' }, { serial: 'b', state: 'device', model: 'Pixel_7' }]);
  if (demoState === 'xiaomi') {
    return { state: 'ready', title: 'Connected (demo recording)', devices: [], device: { ...device, manufacturer: 'Xiaomi', model: 'Redmi Note 12 (recording)' }, capabilities: { canWrite: false }, todo: ['Xiaomi phones need one more switch: Settings > Additional settings > Developer options > "USB debugging (Security settings)" > ON. You must be signed into a Mi account and the phone needs a SIM card for this switch.'] };
  }
  return { state: 'ready', title: 'Connected (demo recording)', devices: [], device, capabilities: { canWrite: false }, todo: [] };
}
function multiple(devices) {
  const names = devices.filter((d) => d.state === 'device').map((d) => (d.model || d.serial).replace(/_/g, ' '));
  return {
    state: 'multiple',
    title: 'More than one phone is connected',
    devices,
    todo: [`Connected now: ${names.join(', ')}.`, 'Unplug every phone except the one you want to check.', 'Then press "Check again".'],
  };
}

let readyCache = { at: 0, value: null };
/** Asking the phone costs a few adb calls; reuse the answer briefly, and never probe while a scan or action is using the phone. */
function currentReadiness({ fresh = false } = {}) {
  const busy = state.scanning || state.busy;
  if (readyCache.value && !fresh && (busy || Date.now() - readyCache.at < 2500)) return readyCache.value;
  let r = DEMO ? demoReadiness() : readiness(adbBinary());
  if (!DEMO && (r.devices || []).filter((d) => d.state === 'device').length > 1) r = multiple(r.devices);
  readyCache = { at: Date.now(), value: r };
  return r;
}

function deviceSerial() {
  const r = currentReadiness({ fresh: true });
  if (r.state !== 'ready') throw new Error(r.title);
  state.serial = r.device.serial;
  return r.device.serial;
}

function adbForScan() {
  if (DEMO) {
    if (demoState !== 'ready' && demoState !== 'xiaomi') throw new Error(currentReadiness().title);
    return new Adb({ mode: 'replay', fixtureDir: DEMO });
  }
  return new Adb({ bin: adbBinary(), serial: deviceSerial(), timeoutMs: 180_000 });
}

async function ensureIocs(refresh = false) {
  if (!state.iocs || refresh) state.iocs = await loadIocs({ cacheDir: DATA_DIR, refresh, log, offline: !!DEMO && !refresh });
  return state.iocs;
}

async function startScan() {
  if (state.scanning || state.busy) return false;
  state.scanning = true;
  state.log = [];
  state.scanError = null;
  const vtApiKey = loadConfig().vtApiKey;
  state.steps = SCAN_STEPS.filter((s) => (!s.liveOnly || !DEMO) && (!s.needsVt || vtApiKey));
  broadcast('scan', { status: 'started' });
  setProgress(0);
  (async () => {
    try {
      const adb = adbForScan();
      const iocs = await ensureIocs();
      log(`Using ${iocs.count} known indicators${iocs.source?.updated ? ` (list updated ${String(iocs.source.updated).slice(0, 10)})` : ''}`);
      const held = [];
      const scanLog = DEMO_PACE_MS ? (t) => held.push(t) : log;
      const { result, snapshot, outDir } = await runScan({ adb, iocs, workDir: WORK_DIR, log: scanLog, pullApks: !DEMO, vtApiKey });
      for (const t of held) { await new Promise((r) => setTimeout(r, DEMO_PACE_MS)); log(t); }
      state.result = result;
      state.snapshot = snapshot;
      state.lastScanAt = new Date().toISOString();
      state.actions = {};
      state.actionLog = [];
      state.other = {};
      try { writeFileSync(join(outDir, 'report.html'), htmlReport(result, { actions: [] })); } catch (e) { log(`Could not save the report file: ${e.message}`); }
      broadcast('scan', { status: 'done' });
    } catch (e) {
      state.scanError = { message: e.message, at: new Date().toISOString() };
      if (!/^Scan failed/.test(state.log.at(-1)?.text || '')) log(`Scan failed: ${e.message}`);
      broadcast('scan', { status: 'failed', error: e.message });
    } finally {
      state.scanning = false;
      state.progress = null;
    }
  })();
  return true;
}

// ---------- phone actions ----------
/** The function each action runs; also used by the `guardian __action` child process. */
export function performAction(kind, payload, adb) {
  const opts = { uid: payload.uid, granted: payload.granted || [] };
  switch (kind) {
    case 'remove': return remediate.removeApp(adb, payload.pkg);
    case 'block': return remediate.blockApp(adb, payload.pkg, opts);
    case 'undo-block':
      if (!hasUndoBlock()) throw new Error('Undo is not available in this version.');
      return remediate.undoBlock(adb, payload.pkg, opts);
    case 'fix': return remediate.applyDeviceFix(adb, payload.cmd);
    case 'dns-on': return remediate.setDnsProtection(adb, payload.provider || 'quad9');
    case 'dns-off': return remediate.clearDnsProtection(adb);
    default: throw new Error(`Unknown action ${kind}`);
  }
}

/** A phone command in the words the page shows while it runs. */
export function describeCommand(cmd) {
  const c = String(cmd);
  const perm = c.match(/pm (revoke|grant) \S+ android\.permission\.(\w+)/);
  if (perm) return `${perm[1] === 'revoke' ? 'Taking away' : 'Giving back'} ${perm[2].toLowerCase().replace(/_/g, ' ')}`;
  const table = [
    [/enabled_accessibility_services|accessibility_enabled/, 'Turning off its accessibility access'],
    [/enabled_notification_listeners/, 'Turning off its notification access'],
    [/dpm remove-active-admin/, 'Removing its device-administrator right'],
    [/am force-stop/, 'Stopping the app'],
    [/pm uninstall/, 'Uninstalling it'],
    [/pm disable/, 'Turning it off'],
    [/pm enable/, 'Turning it back on'],
    [/pm clear/, 'Wiping its data'],
    [/pm unsuspend/, 'Letting the app open again'],
    [/pm suspend/, 'Pausing the app so it cannot open'],
    [/pm revoke/, 'Taking away a permission'],
    [/set-standby-bucket/, 'Changing how often it may wake up'],
    [/appops set \S+ \S+ allow/, 'Allowing it to run in the background again'],
    [/appops set \S+ (RUN_IN_BACKGROUND|RUN_ANY_IN_BACKGROUND)/, 'Stopping it from running in the background'],
    [/appops set \S+ SYSTEM_ALERT_WINDOW/, 'Stopping it from drawing over other apps'],
    [/appops set/, 'Limiting what it may do'],
    [/deviceidle whitelist/, 'Removing its battery exemption'],
    [/netpolicy/, 'Changing its background internet access'],
    [/private_dns/, 'Changing the phone’s Private DNS'],
    [/^settings put/, 'Changing a phone setting'],
  ];
  return table.find(([re]) => re.test(c))?.[1] || 'Working';
}

/** Run an action in a child process and report each phone command as it starts. */
function runActionChild(kind, payload, serial, onCmd) {
  return new Promise((resolve, reject) => {
    const script = join(APP_DIR, 'guardian.mjs');
    const self = IS_COMPILED || !existsSync(script) ? [] : [script];
    const arg = Buffer.from(JSON.stringify({ kind, payload, serial, demo: DEMO })).toString('base64url');
    let child;
    try { child = spawn(process.execPath, [...self, '__action', arg], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); } catch (e) { e.started = false; return reject(e); }
    let buf = '', err = '', out = null, started = false;
    const timer = setTimeout(() => child.kill(), 5 * 60_000);
    child.stdout.on('data', (d) => {
      buf += d;
      for (let i; (i = buf.indexOf('\n')) >= 0; ) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let m; try { m = JSON.parse(line); } catch { continue; }
        if (m.t === 'cmd') { started = true; onCmd(m.cmd); } else if (m.t === 'done') out = m.out; else if (m.t === 'error') err = m.message;
      }
    });
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => { clearTimeout(timer); e.started = started; reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (out) return resolve(out);
      const e = new Error(err.trim().split('\n').pop() || `The helper stopped (code ${code}).`);
      e.started = started;
      reject(e);
    });
  });
}

/** Make an action's answer uniform whatever version of remediate.mjs produced it, and honest in demo mode. */
function normalise(kind, out) {
  const n = {
    ok: !!out?.ok,
    removed: !!out?.removed,
    disabled: typeof out?.disabled === 'boolean' ? out.disabled : kind === 'remove' && !!out?.ok && !out?.removed,
    steps: Array.isArray(out?.steps) ? out.steps.map((s) => ({ action: String(s.action ?? ''), ok: !!s.ok, text: String(s.text ?? '') })) : [],
    manualSteps: Array.isArray(out?.manualSteps) ? out.manualSteps.map(String) : [],
    warnings: Array.isArray(out?.warnings) ? out.warnings.map(String) : [],
    suspended: !!out?.suspended,
  };
  if (out?.previousBucket !== undefined) n.previousBucket = out.previousBucket;
  if (DEMO) {
    n.ok = n.removed = n.disabled = n.suspended = false;
    n.warnings = [];
    n.demo = true;
    n.steps = n.steps.filter((s) => s.action !== 'Verify').map((s) => ({ ...s, ok: false, text: /fixture missing/.test(s.text) ? 'not possible in the demo recording' : s.text }));
    n.steps.push({ action: 'Verify', ok: false, text: 'Nothing was changed: this is a recording, not a real phone.' });
  }
  return n;
}

async function runAction(kind, payload, key) {
  const serial = DEMO ? 'demo' : deviceSerial();
  state.busy = { kind, pkg: payload.pkg || null, key, n: 0, text: 'Starting', startedAt: Date.now() };
  broadcast('action', { phase: 'start', ...state.busy });
  const onCmd = (cmd) => {
    state.busy.n++;
    state.busy.text = describeCommand(cmd);
    broadcast('action', { phase: 'step', ...state.busy });
  };
  let out;
  try {
    try {
      out = await runActionChild(kind, payload, serial, onCmd);
    } catch (e) {
      if (e.started) throw e; // the phone was already touched: never run it twice
      // The helper could not start at all (nothing reached the phone): run here instead, without live steps.
      console.error(`(running "${kind}" without live steps: ${e.message})`);
      const adb = DEMO ? new Adb({ mode: 'replay', fixtureDir: DEMO }) : new Adb({ bin: adbBinary(), serial, timeoutMs: 180_000 });
      out = performAction(kind, payload, adb);
    }
    out = normalise(kind, out);
  } finally {
    state.busy = null;
  }
  broadcast('action', { phase: 'done', kind, pkg: payload.pkg || null, key, ok: out.ok });
  return out;
}

function record(kind, pkg, out) {
  state.actionLog.push({ kind, pkg, ...out, at: new Date().toISOString() });
  if (kind === 'undo-block') {
    if (out.ok) delete state.actions[pkg];
    else state.actions[pkg] = { ...state.actions[pkg], undoFailed: true, steps: out.steps, manualSteps: out.manualSteps };
    return;
  }
  const outcome = kind === 'remove'
    ? (out.removed ? 'removed' : out.disabled ? 'disabled' : out.suspended && out.ok ? 'suspended' : 'failed')
    : out.ok ? 'blocked' : 'failed';
  state.actions[pkg] = {
    outcome, kind, at: new Date().toISOString(), ok: out.ok, steps: out.steps, manualSteps: out.manualSteps, warnings: out.warnings, demo: !!out.demo,
    ...(out.previousBucket !== undefined ? { previousBucket: out.previousBucket } : {}),
  };
}

/** The scan result as the page sees it: each app carries what was done to it, and the counts leave out what was dealt with. */
function resultView() {
  const r = state.result;
  const dealt = (a) => ['removed', 'disabled', 'suspended', 'blocked'].includes(state.actions[a.pkg]?.outcome);
  const annotate = (a) => (state.actions[a.pkg] ? { ...a, action: state.actions[a.pkg] } : a);
  const open = r.apps.filter((a) => !dealt(a));
  const removed = r.apps.filter((a) => state.actions[a.pkg]?.outcome === 'removed').length;
  return {
    ...r,
    apps: r.apps.map(annotate),
    flagged: r.flagged.map(annotate),
    summary: {
      ...r.summary,
      total: r.summary.total - removed,
      critical: open.filter((a) => a.level === 'CRITICAL').length,
      suspicious: open.filter((a) => a.level === 'SUSPICIOUS').length,
      watch: open.filter((a) => a.level === 'WATCH').length,
      dealtWith: r.flagged.filter(dealt).length,
      found: { critical: r.summary.critical, suspicious: r.summary.suspicious, watch: r.summary.watch },
    },
    lastScanAt: state.lastScanAt,
    other: state.other,
    demo: !!DEMO,
  };
}

// ---------- http ----------
const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
function send(res, code, type, body, extra = {}) {
  res.writeHead(code, { ...SECURITY_HEADERS, 'content-type': type, ...extra });
  res.end(body);
}
const json = (res, code, body) => send(res, code, 'application/json; charset=utf-8', JSON.stringify(body));
const text = (res, code, body) => send(res, code, 'text/plain; charset=utf-8', body);

class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > MAX_BODY) { reject(new HttpError(413, 'Request too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new HttpError(400, 'Request is not valid JSON')); }
    });
    req.on('error', reject);
  });
}

function hostAllowed(req) {
  const host = String(req.headers.host || '').toLowerCase();
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
}
function originAllowed(req) {
  const o = req.headers.origin;
  return !o || o === `http://127.0.0.1:${port}` || o === `http://localhost:${port}`;
}

function appFromResult(pkg) {
  if (typeof pkg !== 'string' || !PKG_RE.test(pkg)) throw new HttpError(400, 'That is not a valid app name.');
  if (!state.result) throw new HttpError(409, 'Scan the phone first.');
  const app = state.result.apps.find((a) => a.pkg === pkg);
  if (!app) throw new HttpError(400, 'That app was not in the last scan.');
  return app;
}

function openFolder(dir) {
  if (process.env.GUARDIAN_DRY_OPEN) return false;
  const [cmd, args] = process.platform === 'win32' ? ['explorer', [dir]] : process.platform === 'darwin' ? ['open', [dir]] : ['xdg-open', [dir]];
  try { spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: false }).unref(); return true; } catch { return false; }
}

async function handle(req, res) {
  if (!hostAllowed(req)) return text(res, 421, 'Android Guardian only answers on 127.0.0.1.');
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const p = url.pathname;
  if (req.method !== 'GET' && req.method !== 'POST') return text(res, 405, 'Method not allowed');
  if (req.method === 'POST' && (req.headers['x-guardian'] !== '1' || !originAllowed(req))) return text(res, 403, 'Forbidden');
  try {
    if (req.method === 'GET') {
      if (p === '/') return send(res, 200, 'text/html; charset=utf-8', UI_HTML);
      if (p === '/favicon.ico') { res.writeHead(204, SECURITY_HEADERS); return res.end(); }
      if (p === '/api/events') {
        res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'text/event-stream', connection: 'keep-alive' });
        res.write(': hello\n\n');
        clients.add(res);
        armIdle();
        const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
        req.on('close', () => { clearInterval(ping); clients.delete(res); armIdle(); });
        return;
      }
      if (p === '/api/status') {
        return json(res, 200, {
          version: VERSION,
          demo: !!DEMO,
          readiness: currentReadiness(),
          scanning: state.scanning,
          progress: state.progress,
          scanError: state.scanError,
          hasResult: !!state.result,
          lastScanAt: state.lastScanAt,
          log: state.log.slice(-200),
          busy: state.busy,
          dns: DNS_PROVIDERS,
          features: { undoBlock: hasUndoBlock() },
        });
      }
      if (p === '/api/result') {
        if (!state.result) return json(res, 404, { error: 'No scan yet' });
        return json(res, 200, resultView());
      }
      if (p === '/api/report.html') {
        if (!state.result) return json(res, 404, { error: 'No scan yet' });
        const name = reportFileName(state.result.device, state.lastScanAt || new Date());
        return send(res, 200, 'text/html; charset=utf-8', htmlReport(state.result, { actions: state.actionLog }), {
          'content-disposition': `attachment; filename="${name}"; filename*=UTF-8''${encodeURIComponent(name)}`,
        });
      }
      if (p === '/api/settings') {
        const c = loadConfig();
        return json(res, 200, { vtApiKeySet: !!c.vtApiKey, vtApiKeyHint: c.vtApiKey ? `…${c.vtApiKey.slice(-4)}` : '', reportsDir: REPORT_DIR });
      }
      return json(res, 404, { error: 'Not found' });
    }

    // POST
    const body = await readBody(req);
    if (p === '/api/scan') {
      if (state.busy) return json(res, 409, { error: 'Wait for the current change on the phone to finish.' });
      if (!(await startScan())) return json(res, 409, { error: 'A scan is already running.', scanning: true });
      return json(res, 202, { ok: true });
    }
    if (p === '/api/quit') {
      json(res, 200, { ok: true });
      setTimeout(() => shutdown('quit'), 50);
      return;
    }
    if (p === '/api/settings') {
      if (typeof body.vtApiKey === 'string') {
        if (!isValidVtKey(body.vtApiKey)) return json(res, 400, { error: 'That does not look like a VirusTotal key (letters and digits only).' });
        saveConfig({ vtApiKey: body.vtApiKey.trim() });
      }
      return json(res, 200, { ok: true });
    }
    if (p === '/api/open-reports') return json(res, 200, { path: REPORT_DIR, opened: openFolder(REPORT_DIR) });
    if (p === '/api/refresh-iocs') {
      const iocs = await ensureIocs(true);
      return json(res, 200, { count: iocs.count, updated: iocs.source?.updated || null });
    }
    if (p === '/api/demo-state' && DEMO) {
      demoState = String(body.state || 'ready');
      readyCache = { at: 0, value: null };
      return json(res, 200, { ok: true, state: demoState });
    }

    const kinds = { '/api/remove': 'remove', '/api/block': 'block', '/api/fix': 'fix', '/api/dns': 'dns' };
    if (p === '/api/undo-block' && hasUndoBlock()) kinds[p] = 'undo-block';
    if (!kinds[p]) return json(res, 404, { error: 'Not found' });
    if (state.scanning) return json(res, 409, { error: 'Wait for the scan to finish.' });
    if (state.busy) return json(res, 409, { error: 'Another change is still running on the phone.' });
    let kind = kinds[p];
    let payload, key;
    if (kind === 'remove' || kind === 'block' || kind === 'undo-block') {
      const app = appFromResult(body.pkg);
      const snap = state.snapshot?.packages?.find((a) => a.pkg === app.pkg);
      payload = { pkg: app.pkg, uid: app.uid ?? snap?.uid, granted: snap?.granted || [] };
      if (kind === 'undo-block') payload.previousBucket = state.actions[app.pkg]?.previousBucket;
    } else if (kind === 'fix') {
      const f = state.result?.deviceFindings?.[Number(body.index)];
      if (!f?.fix) return json(res, 400, { error: 'There is no fix for that setting.' });
      payload = { cmd: f.fix };
      key = `fix:${Number(body.index)}`;
    } else {
      kind = body.on ? 'dns-on' : 'dns-off';
      if (body.on && !DNS_PROVIDERS[body.provider]) return json(res, 400, { error: 'Unknown DNS provider.' });
      payload = { provider: body.provider };
      key = 'dns';
    }
    const out = await runAction(kind, payload, key);
    if (payload.pkg) record(kind, payload.pkg, out);
    else {
      state.other[key] = { ...out, kind, at: new Date().toISOString() };
      state.actionLog.push({ kind: kind.startsWith('dns') ? 'dns' : kind, ...out, at: state.other[key].at });
    }
    return json(res, 200, out);
  } catch (e) {
    const code = e instanceof HttpError ? e.code : 500;
    json(res, code, { error: e.message });
  }
}

// ---------- lifecycle ----------
let server = null;
let idleTimer = null;
function minutes(ms) {
  return ms >= 60_000 ? `${Math.round(ms / 60_000)} minute${Math.round(ms / 60_000) === 1 ? '' : 's'}` : `${Math.round(ms / 1000)} seconds`;
}
/** With no page open for IDLE_MS, close by itself so the console window does not linger forever. */
function armIdle() {
  clearTimeout(idleTimer);
  if (clients.size || shuttingDown) return;
  idleTimer = setTimeout(() => {
    if (clients.size) return;
    if (state.scanning || state.busy) return armIdle();
    console.log(`\nNo browser tab has had Android Guardian open for ${minutes(IDLE_MS)}, so it closed itself. Open it again any time.`);
    shutdown('idle');
  }, IDLE_MS);
}

function shutdown(why) {
  if (shuttingDown) return;
  shuttingDown = true;
  clearTimeout(idleTimer);
  broadcast('quit', { why });
  for (const res of clients) res.end();
  clients.clear();
  if (why !== 'idle') console.log('');
  console.log('Goodbye.');
  try { server?.closeAllConnections?.(); } catch { /* old runtime */ }
  server?.close();
  setTimeout(() => process.exit(0), 150);
}

function setConsoleTitle(title) {
  try { process.title = title; } catch { /* not supported */ }
  if (process.stdout.isTTY) process.stdout.write(`\x1b]0;${title}\x07`);
}

export function startUi({ port: wanted = 0, open = true } = {}) {
  setConsoleTitle('Android Guardian');
  server = createServer(handle);
  server.on('error', (e) => {
    console.error(e.code === 'EADDRINUSE' ? `Port ${wanted} is already in use. Is Android Guardian already open? Close it, or start with --port 0.` : `Could not start: ${e.message}`);
    process.exit(4);
  });
  server.listen(wanted, '127.0.0.1', () => {
    port = server.address().port;
    const url = `http://127.0.0.1:${port}/`;
    console.log(`Android Guardian ${VERSION} is running at ${url}`);
    if (DEMO) console.log(`Demo mode: showing the recorded phone in ${DEMO}. Nothing on a real phone can change.`);
    console.log('Keep this window open while you use it. To quit, press Quit on the page or close this window.');
    if (open) {
      const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
      try { spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); } catch { console.log(`Open ${url} in your browser.`); }
    }
    armIdle();
  });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK']) {
    try { process.on(sig, () => shutdown('signal')); } catch { /* signal not supported here */ }
  }
  return server;
}
