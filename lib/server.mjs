// Local web interface: a small HTTP server on 127.0.0.1 that the default browser opens.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { Adb } from './adb.mjs';
import { readiness } from './device.mjs';
import { loadIocs } from './iocs.mjs';
import { runScan } from './scan.mjs';
import { htmlReport } from './report.mjs';
import { removeApp, blockApp, setDnsProtection, clearDnsProtection, applyDeviceFix, DNS_PROVIDERS } from './remediate.mjs';
import { adbBinary, DATA_DIR, WORK_DIR, REPORT_DIR } from './paths.mjs';
import { UI_HTML } from './ui-bundle.mjs';
import { loadConfig, saveConfig } from './config.mjs';

const state = { scanning: false, log: [], result: null, snapshot: null, lastScanAt: null, iocs: null, serial: null };
const clients = new Set();

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}
function log(text) {
  state.log.push({ t: Date.now(), text });
  broadcast('log', { text });
}

function json(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); }
    });
  });
}

// GUARDIAN_DEMO=<fixture dir> runs the interface against a recorded phone (screenshots, UI work without a device).
const DEMO = process.env.GUARDIAN_DEMO || null;
function currentReadiness() {
  if (DEMO) return { state: 'ready', title: 'Connected (demo recording)', devices: [], device: { serial: 'demo', model: 'SM-A525F (recording)', manufacturer: 'samsung', android: '13' }, capabilities: { canWrite: false }, todo: [] };
  return readiness(adbBinary());
}

function adbForDevice() {
  if (DEMO) return new Adb({ mode: 'replay', fixtureDir: DEMO });
  const bin = adbBinary();
  const r = readiness(bin);
  if (r.state !== 'ready') throw new Error(`Phone not ready: ${r.title}`);
  state.serial = r.device.serial;
  return new Adb({ bin, serial: r.device.serial, timeoutMs: 180_000 });
}

async function ensureIocs(refresh = false) {
  if (!state.iocs || refresh) state.iocs = await loadIocs({ cacheDir: DATA_DIR, refresh, log });
  return state.iocs;
}

async function startScan() {
  if (state.scanning) return;
  state.scanning = true;
  state.log = [];
  broadcast('scan', { status: 'started' });
  try {
    const adb = adbForDevice();
    const iocs = await ensureIocs();
    log(`Using ${iocs.count} known indicators${iocs.source ? ` (list updated ${iocs.source.updated.slice(0, 10)})` : ''}`);
    const { result, snapshot, outDir } = await runScan({ adb, iocs, workDir: WORK_DIR, log, pullApks: !DEMO, vtApiKey: loadConfig().vtApiKey });
    state.result = result;
    state.snapshot = snapshot;
    state.lastScanAt = new Date().toISOString();
    writeFileSync(join(outDir, 'report.html'), htmlReport(result));
    broadcast('scan', { status: 'done' });
  } catch (e) {
    log(`Scan failed: ${e.message}`);
    broadcast('scan', { status: 'failed', error: e.message });
  } finally {
    state.scanning = false;
  }
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const p = url.pathname;
  try {
    if (p === '/' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(UI_HTML);
    }
    if (p === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      res.write(': hello\n\n');
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    if (p === '/api/status') {
      const r = currentReadiness();
      return json(res, 200, { readiness: r, scanning: state.scanning, hasResult: !!state.result, lastScanAt: state.lastScanAt, log: state.log.slice(-200), dns: DNS_PROVIDERS });
    }
    if (p === '/api/scan' && req.method === 'POST') {
      startScan();
      return json(res, 202, { ok: true });
    }
    if (p === '/api/result') {
      if (!state.result) return json(res, 404, { error: 'No scan yet' });
      return json(res, 200, state.result);
    }
    if (p === '/api/report.html') {
      if (!state.result) return json(res, 404, { error: 'No scan yet' });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-disposition': 'attachment; filename="android-guardian-report.html"' });
      return res.end(htmlReport(state.result));
    }
    if (p === '/api/settings' && req.method === 'GET') {
      const c = loadConfig();
      return json(res, 200, { vtApiKeySet: !!c.vtApiKey, vtApiKeyHint: c.vtApiKey ? `…${c.vtApiKey.slice(-4)}` : '' });
    }
    if (p === '/api/settings' && req.method === 'POST') {
      const body = await readBody(req);
      const patch = {};
      if (typeof body.vtApiKey === 'string') patch.vtApiKey = body.vtApiKey.trim();
      saveConfig(patch);
      return json(res, 200, { ok: true });
    }
    if (p === '/api/refresh-iocs' && req.method === 'POST') {
      const iocs = await ensureIocs(true);
      return json(res, 200, { count: iocs.count, updated: iocs.source?.updated || null });
    }
    if (req.method === 'POST' && ['/api/remove', '/api/block', '/api/fix', '/api/dns'].includes(p)) {
      if (state.scanning) return json(res, 409, { error: 'Wait for the scan to finish' });
      const body = await readBody(req);
      const adb = adbForDevice();
      let out;
      if (p === '/api/remove') out = removeApp(adb, body.pkg);
      else if (p === '/api/block') {
        const app = state.result?.apps.find((a) => a.pkg === body.pkg);
        const snap = state.snapshot?.packages.find((a) => a.pkg === body.pkg);
        out = blockApp(adb, body.pkg, { uid: app?.uid, granted: snap?.granted || [] });
      } else if (p === '/api/fix') out = applyDeviceFix(adb, body.cmd);
      else out = body.on ? setDnsProtection(adb, body.provider || 'quad9') : clearDnsProtection(adb);
      // Keep the in-memory result honest after a removal.
      if (p === '/api/remove' && out.removed && state.result) {
        state.result.apps = state.result.apps.filter((a) => a.pkg !== body.pkg);
        state.result.flagged = state.result.flagged.filter((a) => a.pkg !== body.pkg);
      }
      return json(res, 200, out);
    }
    json(res, 404, { error: 'Not found' });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
}

export function startUi({ port = 0, open = true } = {}) {
  const server = createServer(handle);
  server.listen(port, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${server.address().port}/`;
    console.log(`Android Guardian is running at ${url}`);
    console.log('Keep this window open while you use it. Close it to quit.');
    if (open) {
      const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
      try { spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore' }).unref(); } catch { /* user can open the url manually */ }
    }
  });
  return server;
}
