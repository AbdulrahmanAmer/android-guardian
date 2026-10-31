#!/usr/bin/env node
// Android Guardian: find and remove spyware, stalkerware and remote-control trojans on an Android phone over USB.
// Run with --help for the commands. Exit codes are listed in HELP below.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Adb } from './lib/adb.mjs';
import { readiness } from './lib/device.mjs';
import { loadIocs } from './lib/iocs.mjs';
import { runScan } from './lib/scan.mjs';
import { consoleReport, htmlReport } from './lib/report.mjs';
import * as remediate from './lib/remediate.mjs';
import { adbBinary, APP_DIR, DATA_DIR, WORK_DIR, VERSION, reportFileName } from './lib/paths.mjs';

const EXIT = { OK: 0, FOUND_SUSPICIOUS: 1, STEP_FAILED: 1, NOT_READY: 2, FOUND_CRITICAL: 3, ERROR: 4 };

const HELP = `Android Guardian ${VERSION}
Finds and removes spyware, stalkerware and remote-control apps on an Android phone connected by USB.

Usage: AndroidGuardian.exe [command] [options]
       (from source: node guardian.mjs [command] [options])

Commands
  ui                      Open the guided interface in your browser. This is what happens
                          when you just double-click the program.
      --port <number>       Use this port on 127.0.0.1 (default: any free port)
      --no-open             Do not open the browser; just print the address
      --demo [folder]       Show a recorded phone instead of a real one (for trying it out)

  status                  Say whether a phone is connected and ready, and what to do if not.
                          (Always exits 0; read the text.)

  scan                    Check the connected phone and print what was found.
      --out <folder>        Also save the report (HTML) and the raw results (JSON) in this folder
      --json                Print the full result as JSON instead of text
      --offline             Do not download the latest list of known spyware
      --record <folder>     Save every phone answer, to replay later without the phone
      --replay <folder>     Scan a recording instead of a phone

  remove <app>            Remove an app from the phone (for example: remove com.example.spy).
                          Its special rights are taken away first so it cannot resist.
  block <app>             Keep the app, but take away its microphone, camera, messages,
                          location and background rights.
  unblock <app>           Give back what "block" took away (if this version supports it).
  protect-dns [name]      Make the phone use a DNS service that blocks known spyware servers.
                          name: quad9 (default), adguard, cloudflare, or off to turn it off.

  help, --help, -h        Show this text.
  --version, -v           Show the version number.

Exit codes
  0   Done. For scan: nothing suspicious was found.
  1   scan: some apps need a look (suspicious). remove/block/protect-dns: a step did not work.
  2   The phone is not ready (not connected, USB debugging off, or not allowed yet).
  3   scan: a threat was found (critical).
  4   Something went wrong (unknown command, missing argument, or an unexpected error).
`;

const args = process.argv.slice(2);
const VALUE_FLAGS = new Set(['--port', '--out', '--record', '--replay', '--demo']);
// Words that are not a flag and not the value of a flag (--port 1, --out dir) are the command and its argument.
const positional = args.filter((a, i) => !a.startsWith('-') && !(i > 0 && VALUE_FLAGS.has(args[i - 1])));
const cmd = positional[0] || 'ui';
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('-') ? args[i + 1] : true) : null;
};
const log = (t) => console.error(`• ${t}`);

class CliError extends Error { constructor(msg, code = EXIT.ERROR) { super(msg); this.code = code; } }

function liveAdb() {
  const bin = adbBinary();
  const r = readiness(bin);
  if (r.state !== 'ready') {
    console.error(`${r.title}\n` + r.todo.map((t) => `  - ${t}`).join('\n'));
    process.exit(EXIT.NOT_READY);
  }
  return new Adb({ bin, serial: r.device.serial, timeoutMs: 180_000 });
}

function printSteps(out) {
  for (const s of out.steps || []) console.log(`${s.ok ? 'OK  ' : 'FAIL'} ${s.action}${s.text ? `: ${s.text}` : ''}`);
  if (out.manualSteps?.length) {
    console.log('\nDo this on the phone:');
    out.manualSteps.forEach((t, i) => console.log(`  ${i + 1}. ${t}`));
  }
}

async function main() {
  if (args.includes('--help') || args.includes('-h') || cmd === 'help') { console.log(HELP); return; }
  if (args.includes('--version') || args.includes('-v')) { console.log(VERSION); return; }

  // Internal: the interface runs phone changes through this so it stays responsive and can show each step live.
  if (cmd === '__action') {
    const input = JSON.parse(Buffer.from(positional[1] || '', 'base64url').toString('utf8'));
    const { performAction } = await import('./lib/server.mjs');
    const adb = input.demo ? new Adb({ mode: 'replay', fixtureDir: input.demo }) : new Adb({ bin: adbBinary(), serial: input.serial, timeoutMs: 180_000 });
    const real = adb.shellResult.bind(adb);
    adb.shellResult = (c) => { process.stdout.write(JSON.stringify({ t: 'cmd', cmd: c }) + '\n'); return real(c); };
    try {
      const out = performAction(input.kind, input.payload || {}, adb);
      process.stdout.write(JSON.stringify({ t: 'done', out }) + '\n');
    } catch (e) {
      process.stdout.write(JSON.stringify({ t: 'error', message: e.message }) + '\n');
      process.exitCode = EXIT.ERROR;
    }
    return;
  }

  if (cmd === 'ui') {
    if (flag('demo')) process.env.GUARDIAN_DEMO = resolve(typeof flag('demo') === 'string' ? flag('demo') : join(APP_DIR, 'test', 'fixtures', 'infected'));
    const port = flag('port');
    if (port !== null && !/^\d{1,5}$/.test(String(port))) throw new CliError('--port needs a number, for example --port 47831');
    const { startUi } = await import('./lib/server.mjs');
    startUi({ port: Number(port) || 0, open: !flag('no-open') });
    return;
  }
  if (cmd === 'status') {
    const r = readiness(adbBinary());
    console.log(r.title);
    for (const t of r.todo) console.log(`  - ${t}`);
    if (r.capabilities) console.log(`  can change settings: ${r.capabilities.canWrite}`);
    process.exit(r.state === 'ready' ? 0 : 2); // 2 = phone not ready, same meaning as for scan; CI expects 2 with no phone
  }
  if (cmd === 'scan') {
    const replay = flag('replay');
    const record = flag('record');
    const outFlag = flag('out');
    if (outFlag === true) throw new CliError('--out needs a folder, for example --out C:\\Reports');
    let adb;
    if (typeof replay === 'string') adb = new Adb({ mode: 'replay', fixtureDir: replay });
    else {
      adb = liveAdb();
      if (typeof record === 'string') adb = new Adb({ bin: adb.bin, serial: adb.serial, mode: 'record', fixtureDir: record, timeoutMs: 180_000 });
    }
    const iocs = await loadIocs({ cacheDir: DATA_DIR, log, offline: !!flag('offline') || !!replay });
    const { loadConfig } = await import('./lib/config.mjs');
    const { result, snapshot, outDir } = await runScan({ adb, iocs, workDir: WORK_DIR, log, pullApks: !replay, vtApiKey: process.env.VT_API_KEY || loadConfig().vtApiKey });
    const html = htmlReport(result);
    writeFileSync(join(outDir, 'report.html'), html);
    if (typeof outFlag === 'string') {
      const dir = resolve(outFlag);
      mkdirSync(dir, { recursive: true });
      const name = reportFileName(result.device);
      writeFileSync(join(dir, name), html);
      writeFileSync(join(dir, name.replace(/\.html$/, '.json')), JSON.stringify({ result, snapshot }, null, 1));
      console.error(`Report saved as ${join(dir, name)}`);
    }
    if (flag('json')) console.log(JSON.stringify(result, null, 1));
    else console.log(consoleReport(result));
    console.error(`\nReport saved in ${outDir}`);
    process.exit(result.summary.critical ? EXIT.FOUND_CRITICAL : result.summary.suspicious ? EXIT.FOUND_SUSPICIOUS : EXIT.OK);
  }
  const target = positional[1];
  if (cmd === 'remove' || cmd === 'block' || cmd === 'unblock') {
    if (!target) throw new CliError(`Which app? Usage: ${cmd} <app>, for example: ${cmd} com.example.spy`);
    if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(target)) throw new CliError(`"${target}" is not an app name (they look like com.example.app).`);
    if (cmd === 'unblock' && typeof remediate.undoBlock !== 'function') throw new CliError('This version cannot undo a block yet.');
    const adb = liveAdb();
    const granted = () => [...adb.shell(`dumpsys package ${target}`).matchAll(/^\s+([\w.]+): granted=true/gm)].map((m) => m[1]);
    const out = cmd === 'remove' ? remediate.removeApp(adb, target) : cmd === 'block' ? remediate.blockApp(adb, target, { granted: granted() }) : remediate.undoBlock(adb, target, {});
    printSteps(out);
    process.exit(out.ok ? EXIT.OK : EXIT.STEP_FAILED);
  }
  if (cmd === 'protect-dns') {
    if (target && target !== 'off' && !remediate.DNS_PROVIDERS[target]) throw new CliError(`Unknown DNS service "${target}". Use quad9, adguard, cloudflare or off.`);
    const adb = liveAdb();
    const out = target === 'off' ? remediate.clearDnsProtection(adb) : remediate.setDnsProtection(adb, target || 'quad9');
    printSteps(out);
    process.exit(out.ok ? EXIT.OK : EXIT.STEP_FAILED);
  }
  throw new CliError(`Unknown command "${cmd}". Run with --help to see the commands.`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(e.code && Number.isInteger(e.code) ? e.code : EXIT.ERROR);
});
