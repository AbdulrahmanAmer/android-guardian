// Interface server tests: security guards, scan lifecycle, removal in demo mode, report download, quit, idle exit, CLI.
// Starts the real server (`guardian ui --demo`) on a free port. Run: node test/server.test.mjs
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { request } from 'node:http';
import { readFileSync, existsSync, mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { VERSION, reportFileName, REPORT_DIR } from '../lib/paths.mjs';
import { describeCommand } from '../lib/server.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const guardian = join(root, 'guardian.mjs');
const fixture = join(root, 'test', 'fixtures', 'infected');

let passed = 0;
const failures = [];
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ok   ${name}`); } catch (e) { failures.push(name); console.log(`  FAIL ${name}\n       ${String(e.message).split('\n').slice(0, 3).join('\n       ')}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Start `guardian ui --demo` and resolve once it prints its address. */
function startServer(env = {}) {
  const child = spawn(process.execPath, [guardian, 'ui', '--demo', fixture, '--port', '0', '--no-open'], { cwd: root, env: { ...process.env, GUARDIAN_DRY_OPEN: '1', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`server did not start:\n${out}`)), 15_000);
    const check = setInterval(() => {
      const m = out.match(/http:\/\/127\.0\.0\.1:(\d+)\//);
      if (m) { clearInterval(check); clearTimeout(t); resolve({ child, port: Number(m[1]), output: () => out, exited }); }
    }, 50);
  });
}

/** Raw HTTP so the Host header can be set (fetch does not allow it). */
function http(port, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, body: data, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}
const post = (port, path, body = {}, headers = {}) => http(port, path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-guardian': '1', origin: `http://127.0.0.1:${port}`, ...headers }, body });

// ---------- pure ----------
await test('VERSION in lib/paths.mjs matches package.json', () => {
  assert.equal(VERSION, JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version);
});
await test('report file name carries model and date, and is file-system safe', () => {
  assert.equal(reportFileName({ manufacturer: 'samsung', model: 'SM-A525F' }, new Date(2026, 9, 31)), 'android-guardian-samsung-sm-a525f-2026-10-31.html');
  assert.equal(reportFileName({ manufacturer: 'Google', model: 'Google Pixel 7 "Pro"/..\\x' }, new Date(2026, 0, 2)), 'android-guardian-google-pixel-7-pro-x-2026-01-02.html');
  assert.equal(reportFileName({}, 'not a date').startsWith('android-guardian-phone-'), true);
});
await test('phone commands are described in plain words', () => {
  assert.equal(describeCommand('pm uninstall --user 0 com.x.y'), 'Uninstalling it');
  assert.equal(describeCommand('pm revoke com.x.y android.permission.RECORD_AUDIO'), 'Taking away record audio');
  assert.equal(describeCommand('dpm remove-active-admin com.x/.A'), 'Removing its device-administrator right');
});

// ---------- CLI ----------
await test('--version prints the version', () => {
  const r = spawnSync(process.execPath, [guardian, '--version'], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), VERSION);
});
await test('--help lists every command and the exit codes', () => {
  const r = spawnSync(process.execPath, [guardian, '--help'], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(r.status, 0);
  for (const c of ['ui', 'status', 'scan', 'remove', 'block', 'unblock', 'protect-dns', '--out', '--demo', 'Exit codes']) assert.ok(r.stdout.includes(c), `help mentions ${c}`);
  for (const code of ['0 ', '1 ', '2 ', '3 ', '4 ']) assert.ok(r.stdout.includes(`\n  ${code}`), `help documents exit code ${code.trim()}`);
});
await test('unknown command exits 4 with a plain message', () => {
  const r = spawnSync(process.execPath, [guardian, 'frobnicate'], { encoding: 'utf8', timeout: 20_000 });
  assert.equal(r.status, 4);
  assert.match(r.stderr, /Unknown command "frobnicate"/);
});
await test('scan --replay --out writes the named report and exits 3 for a critical find', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ag-out-'));
  try {
    const r = spawnSync(process.execPath, [guardian, 'scan', '--replay', fixture, '--out', dir], { encoding: 'utf8', cwd: root, timeout: 60_000 });
    assert.equal(r.status, 3, r.stderr);
    const files = readdirSync(dir);
    assert.ok(files.some((f) => /^android-guardian-samsung-sm-a525f-\d{4}-\d\d-\d\d\.html$/.test(f)), files.join(','));
    assert.ok(files.some((f) => f.endsWith('.json')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------- server ----------
const srv = await startServer({ GUARDIAN_DEMO_PACE_MS: '150' });
const { port } = srv;

await test('page is served with no-store, nosniff and a CSP that allows nothing remote', async () => {
  const r = await http(port, '/');
  assert.equal(r.status, 200);
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  const csp = r.headers['content-security-policy'];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self' 'unsafe-inline'/);
  assert.doesNotMatch(csp, /https?:/);
  assert.ok(r.body.includes('Android Guardian'));
  assert.ok(r.body.includes("'x-guardian': '1'"), 'page sends the CSRF header');
});
await test('foreign Host header is refused (DNS rebinding)', async () => {
  const r = await http(port, '/api/status', { headers: { host: `evil.example:${port}` } });
  assert.equal(r.status, 421);
  const r2 = await http(port, '/api/status', { headers: { host: `localhost:${port}` } });
  assert.equal(r2.status, 200);
});
await test('POST without X-Guardian, or from another origin, is refused', async () => {
  assert.equal((await http(port, '/api/scan', { method: 'POST', body: {} })).status, 403);
  assert.equal((await post(port, '/api/scan', {}, { origin: 'http://evil.example' })).status, 403);
  assert.equal((await post(port, '/api/quit', {}, { 'x-guardian': '0' })).status, 403);
});
await test('status carries version, demo readiness and no scan yet', async () => {
  const r = await http(port, '/api/status');
  assert.equal(r.json.version, VERSION);
  assert.equal(r.json.readiness.state, 'ready');
  assert.equal(r.json.hasResult, false);
  assert.equal(r.json.scanning, false);
});
await test('event stream opens', async () => {
  const first = await new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path: '/api/events', headers: { host: `127.0.0.1:${port}` } }, (res) => {
      res.once('data', (d) => { resolve({ type: res.headers['content-type'], text: String(d) }); req.destroy(); });
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(first.type, 'text/event-stream');
  assert.match(first.text, /hello/);
});
await test('two scan requests at once start only one scan', async () => {
  const [a, b] = await Promise.all([post(port, '/api/scan'), post(port, '/api/scan')]);
  assert.deepEqual([a.status, b.status].sort(), [202, 409], `statuses ${a.status} ${a.body} / ${b.status} ${b.body}`);
});
let status;
await test('scan finishes; status keeps the log and the last step', async () => {
  for (let i = 0; i < 100; i++) {
    status = (await http(port, '/api/status')).json;
    if (!status.scanning && (status.hasResult || status.scanError)) break;
    await sleep(100);
  }
  assert.equal(status.scanError, null);
  assert.equal(status.hasResult, true);
  assert.ok(status.log.some((l) => /Scan finished/.test(l.text)), 'log restored from status');
  assert.equal(status.progress, null, 'progress cleared after the scan');
});
await test('result is served with counts', async () => {
  const r = await http(port, '/api/result');
  assert.equal(r.status, 200);
  assert.ok(r.json.summary.critical >= 1);
  assert.ok(r.json.flagged.some((a) => a.pkg === 'com.systemservice'));
});
await test('report download is an attachment named with model and date', async () => {
  const r = await http(port, '/api/report.html');
  assert.equal(r.status, 200);
  assert.match(r.headers['content-disposition'], /^attachment; filename="android-guardian-samsung-sm-a525f-\d{4}-\d\d-\d\d\.html"; filename\*=UTF-8''android-guardian-samsung-sm-a525f-\d{4}-\d\d-\d\d\.html$/);
  assert.match(r.body, /<html/);
});
await test('remove refuses names that are not app names, or not from the scan', async () => {
  const bad = await post(port, '/api/remove', { pkg: 'com.x; reboot' });
  assert.equal(bad.status, 400);
  const notScanned = await post(port, '/api/remove', { pkg: 'com.not.scanned' });
  assert.equal(notScanned.status, 400);
});
await test('remove in demo mode reports honestly that nothing changed, with live steps', async () => {
  // listen to the event stream: each phone command must be announced while the action runs (helper process path)
  const events = [];
  const sse = request({ host: '127.0.0.1', port, path: '/api/events', headers: { host: `127.0.0.1:${port}` } }, (res) => {
    res.setEncoding('utf8');
    let buf = '';
    res.on('data', (d) => {
      buf += d;
      for (const block of buf.split('\n\n').slice(0, -1)) {
        const [ev, data] = block.split('\n');
        if (ev === 'event: action') events.push(JSON.parse(data.slice(6)));
      }
      buf = buf.slice(buf.lastIndexOf('\n\n') + 2);
    });
  });
  sse.on('error', () => {});
  sse.end();
  await sleep(200);
  const r = await post(port, '/api/remove', { pkg: 'com.systemservice' });
  await sleep(200);
  sse.destroy();
  const steps = events.filter((e) => e.phase === 'step');
  assert.ok(steps.length >= 3, `live step events: ${JSON.stringify(events)}`);
  assert.ok(steps.every((e) => e.text && e.text !== 'Working'), JSON.stringify(steps.map((e) => e.text)));
  assert.ok(events.some((e) => e.phase === 'done'));
  assert.equal(r.status, 200, r.body);
  assert.equal(r.json.ok, false);
  assert.equal(r.json.removed, false);
  assert.equal(r.json.demo, true);
  assert.ok(r.json.steps.length >= 2);
  assert.ok(r.json.steps.every((s) => s.ok === false));
  const res = (await http(port, '/api/result')).json;
  const app = res.apps.find((a) => a.pkg === 'com.systemservice');
  assert.equal(app.action.outcome, 'failed');
  assert.equal(res.summary.dealtWith, 0);
});
await test('fix accepts only an index into the scan findings', async () => {
  const r = await post(port, '/api/fix', { index: 999 });
  assert.equal(r.status, 400);
});
await test('settings refuse a malformed VirusTotal key', async () => {
  const r = await post(port, '/api/settings', { vtApiKey: 'abc def<script>' });
  assert.equal(r.status, 400);
});
await test('open reports folder returns the reports path', async () => {
  const r = await post(port, '/api/open-reports');
  assert.equal(r.status, 200);
  assert.equal(r.json.path, REPORT_DIR);
});
await test('undo-block is routed only when remediate exports undoBlock', async () => {
  const has = typeof (await import('../lib/remediate.mjs')).undoBlock === 'function';
  const r = await post(port, '/api/undo-block', { pkg: 'com.systemservice' });
  if (has) assert.notEqual(r.status, 404); else assert.equal(r.status, 404);
  assert.equal((await http(port, '/api/status')).json.features.undoBlock, has);
});
await test('Quit stops the server and says Goodbye', async () => {
  const r = await post(port, '/api/quit');
  assert.equal(r.status, 200);
  const code = await Promise.race([srv.exited, sleep(5000).then(() => 'timeout')]);
  assert.equal(code, 0);
  assert.match(srv.output(), /Goodbye/);
  assert.match(srv.output(), /Keep this window open/);
});

// ---------- idle exit ----------
await test('with no tab open the server closes itself; an open tab keeps it alive', async () => {
  const s = await startServer({ GUARDIAN_IDLE_MS: '1200' });
  // keep a tab "open" for longer than the idle time
  const req = request({ host: '127.0.0.1', port: s.port, path: '/api/events', headers: { host: `127.0.0.1:${s.port}` } }, () => {});
  req.on('error', () => {});
  req.end();
  await sleep(2200);
  assert.equal(s.child.exitCode, null, 'still running while a tab is connected');
  req.destroy();
  const code = await Promise.race([s.exited, sleep(6000).then(() => 'timeout')]);
  assert.equal(code, 0);
  assert.match(s.output(), /closed itself/);
  assert.match(s.output(), /Goodbye/);
});

if (!srv.child.exitCode && srv.child.exitCode !== 0) srv.child.kill();
console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
