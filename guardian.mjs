#!/usr/bin/env node
// Android Guardian: find and remove spyware, stalkerware and remote-control trojans on an Android phone over USB.
//
//   AndroidGuardian.exe              open the guided interface (default)
//   guardian scan [--replay DIR] [--record DIR] [--json] [--offline]
//   guardian status
//   guardian remove <package>
//   guardian block <package>
//   guardian protect-dns [quad9|adguard|cloudflare|off]
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Adb } from './lib/adb.mjs';
import { readiness } from './lib/device.mjs';
import { loadIocs } from './lib/iocs.mjs';
import { runScan } from './lib/scan.mjs';
import { consoleReport, htmlReport } from './lib/report.mjs';
import { removeApp, blockApp, setDnsProtection, clearDnsProtection } from './lib/remediate.mjs';
import { adbBinary, DATA_DIR, WORK_DIR } from './lib/paths.mjs';

const args = process.argv.slice(2);
const cmd = args.find((a) => !a.startsWith('--')) || 'ui';
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true) : null;
};
const log = (t) => console.error(`• ${t}`);

function liveAdb() {
  const bin = adbBinary();
  const r = readiness(bin);
  if (r.state !== 'ready') {
    console.error(`${r.title}\n` + r.todo.map((t) => `  - ${t}`).join('\n'));
    process.exit(2);
  }
  return new Adb({ bin, serial: r.device.serial, timeoutMs: 180_000 });
}

async function main() {
  if (cmd === 'ui') {
    if (flag('demo')) process.env.GUARDIAN_DEMO = typeof flag('demo') === 'string' ? flag('demo') : 'test/fixtures/infected';
    const { startUi } = await import('./lib/server.mjs');
    startUi({ port: Number(flag('port')) || 0, open: !flag('no-open') });
    return;
  }
  if (cmd === 'status') {
    const r = readiness(adbBinary());
    console.log(r.title);
    for (const t of r.todo) console.log(`  - ${t}`);
    if (r.capabilities) console.log(`  can change settings: ${r.capabilities.canWrite}`);
    return;
  }
  if (cmd === 'scan') {
    const replay = flag('replay');
    const record = flag('record');
    let adb;
    if (replay) adb = new Adb({ mode: 'replay', fixtureDir: replay });
    else {
      adb = liveAdb();
      if (record) adb = new Adb({ bin: adb.bin, serial: adb.serial, mode: 'record', fixtureDir: record, timeoutMs: 180_000 });
    }
    const iocs = await loadIocs({ cacheDir: DATA_DIR, log, offline: !!flag('offline') || !!replay });
    const { loadConfig } = await import('./lib/config.mjs');
    const { result, outDir } = await runScan({ adb, iocs, workDir: WORK_DIR, log, pullApks: !replay, vtApiKey: process.env.VT_API_KEY || loadConfig().vtApiKey });
    writeFileSync(join(outDir, 'report.html'), htmlReport(result));
    if (flag('json')) console.log(JSON.stringify(result, null, 1));
    else console.log(consoleReport(result));
    console.error(`\nReport saved in ${outDir}`);
    process.exit(result.summary.critical ? 3 : result.summary.suspicious ? 1 : 0);
  }
  const target = args[args.indexOf(cmd) + 1];
  if (cmd === 'remove' || cmd === 'block') {
    if (!target) throw new Error(`Usage: guardian ${cmd} <package>`);
    const adb = liveAdb();
    const out = cmd === 'remove' ? removeApp(adb, target) : blockApp(adb, target, { granted: [...adb.shell(`dumpsys package ${target}`).matchAll(/^\s+([\w.]+): granted=true/gm)].map((m) => m[1]) });
    for (const s of out.steps) console.log(`${s.ok ? 'OK  ' : 'FAIL'} ${s.action}${s.text ? `: ${s.text}` : ''}`);
    process.exit(out.ok ? 0 : 1);
  }
  if (cmd === 'protect-dns') {
    const adb = liveAdb();
    const out = target === 'off' ? clearDnsProtection(adb) : setDnsProtection(adb, target || 'quad9');
    for (const s of out.steps) console.log(`${s.ok ? 'OK  ' : 'FAIL'} ${s.action}${s.text ? `: ${s.text}` : ''}`);
    process.exit(out.ok ? 0 : 1);
  }
  throw new Error(`Unknown command ${cmd}`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
