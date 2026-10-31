// One full scan: collect -> first pass -> pull suspicious APKs for certificate/label -> final analysis.
import { join } from 'node:path';
import { mkdirSync, existsSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { collect } from './collect.mjs';
import { analyze } from './rules.mjs';
import { apkCertificate } from './apk.mjs';
import { aapt2Binary } from './paths.mjs';
import { lookupHashes } from './vt.mjs';

const MAX_PULL = 80;

function labelFromApk(aapt2, file) {
  if (!aapt2) return null;
  const r = spawnSync(aapt2, ['dump', 'badging', file], { encoding: 'utf8', timeout: 30_000, maxBuffer: 64 * 1024 * 1024 });
  const m = (r.stdout || '').match(/application-label(?:-en[-\w]*)?:'([^']*)'/) || (r.stdout || '').match(/application-label:'([^']*)'/);
  return m ? m[1] : null;
}

export async function runScan({ adb, iocs, workDir, log = () => {}, pullApks = true, vtApiKey = '' }) {
  const snapshot = collect(adb, { log });
  let result = analyze(snapshot, iocs);

  const certs = new Map();
  const labels = new Map();
  if (pullApks) {
    const candidates = result.apps
      .filter((a) => !a.system && a.apkPath && (a.score >= 10 || a.sideloaded || !a.hasLauncherIcon))
      .slice(0, MAX_PULL);
    const aapt2 = aapt2Binary();
    const apkDir = join(workDir, 'apks');
    mkdirSync(apkDir, { recursive: true });
    log(`Checking signatures of ${candidates.length} apps${aapt2 ? ' and reading their names' : ''}`);
    let i = 0;
    for (const a of candidates) {
      i++;
      const local = join(apkDir, `${a.pkg}.apk`);
      if (!existsSync(local) && !adb.pull(a.apkPath, local)) continue;
      try {
        const c = apkCertificate(local);
        if (c) certs.set(a.pkg, c.sha1);
      } catch { /* unreadable apk */ }
      const label = labelFromApk(aapt2, local);
      if (label) labels.set(a.pkg, label);
      if (i % 10 === 0) log(`  ${i}/${candidates.length}`);
    }
    result = analyze(snapshot, iocs, { certs, labels });
  }

  if (vtApiKey) {
    const hashes = result.apps.filter((a) => !a.system && a.sha256 && (a.score >= 10 || a.sideloaded)).map((a) => a.sha256);
    const vt = await lookupHashes(hashes, vtApiKey, { log });
    if (vt.size) result = analyze(snapshot, iocs, { certs, labels, vt });
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outDir = join(workDir, '..', '..', 'reports', stamp);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'snapshot.json'), JSON.stringify(snapshot, null, 1));
  writeFileSync(join(outDir, 'result.json'), JSON.stringify(result, null, 1));
  log(`Scan finished: ${result.summary.critical} critical, ${result.summary.suspicious} suspicious, ${result.summary.watch} to watch.`);
  return { snapshot, result, outDir };
}
