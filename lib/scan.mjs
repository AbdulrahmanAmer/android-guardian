// One full scan: collect -> first pass -> pull suspicious APKs for certificate/label -> final analysis.
// Pulling is capped (size and total time) so a phone full of large games cannot stall the scan; anything
// skipped is logged and returned in `warnings`. Pulled APKs are deleted after reading unless keepApks.
import { join } from 'node:path';
import { mkdirSync, writeFileSync, appendFileSync, rmSync, readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { collect } from './collect.mjs';
import { analyze } from './rules.mjs';
import { apkCertificate, fileSha256 } from './apk.mjs';
import { aapt2Binary } from './paths.mjs';
import { lookupHashes } from './vt.mjs';

const MAX_PULL = 80;
export const PULL_LIMITS = {
  maxApkBytes: 150 * 1024 * 1024, // skip anything bigger: spyware is small, big files are games and maps
  maxPullMs: 4 * 60 * 1000, // stop pulling after this, keep what was read
};

function labelFromApk(aapt2, file) {
  if (!aapt2) return null;
  const r = spawnSync(aapt2, ['dump', 'badging', file], { encoding: 'utf8', timeout: 30_000, maxBuffer: 64 * 1024 * 1024 });
  const m = (r.stdout || '').match(/application-label(?:-en[-\w]*)?:'([^']*)'/) || (r.stdout || '').match(/application-label:'([^']*)'/);
  return m ? m[1] : null;
}

/** Folder-name-safe device model: "Pixel 7 Pro" -> "Pixel-7-Pro". */
export function safeName(s, fallback = 'phone') {
  const v = String(s || '').normalize('NFKD').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 40);
  return v || fallback;
}

/** Sizes of files on the phone in one round trip per 40 paths. Missing entries mean "unknown". */
function remoteSizes(adb, paths) {
  const sizes = new Map();
  for (let i = 0; i < paths.length; i += 40) {
    const chunk = paths.slice(i, i + 40);
    const out = adb.shell(`stat -c '%s %n' ${chunk.map((x) => `'${x.replace(/'/g, '')}'`).join(' ')} 2>/dev/null`);
    for (const m of out.matchAll(/^(\d+) (\S.*)$/gm)) sizes.set(m[2].trim(), Number(m[1]));
  }
  return sizes;
}

const mb = (n) => `${Math.round(n / 1024 / 1024)} MB`;

export async function runScan({
  adb, iocs, workDir, log = () => {}, pullApks = true, vtApiKey = '',
  keepApks = process.argv.includes('--keep-apks'),
  reportDir = join(workDir, '..', '..', 'reports'),
  limits = PULL_LIMITS,
  now = () => Date.now(),
}) {
  const warnings = [];
  // Output folder first, so scan.log captures everything, including a failure half-way.
  const model = adb.shell('getprop ro.product.model').trim();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outDir = join(reportDir, `${stamp}_${safeName(model)}`);
  mkdirSync(outDir, { recursive: true });
  const logFile = join(outDir, 'scan.log');
  writeFileSync(logFile, '');
  const plog = (t) => {
    try { appendFileSync(logFile, `${new Date().toISOString()}  ${t}\n`); } catch { /* the log must never break a scan */ }
    log(t);
  };
  const warn = (t) => { warnings.push(t); plog(`WARNING: ${t}`); };

  try {
    const snapshot = collect(adb, { log: plog });
    let result = analyze(snapshot, iocs);

    const certs = new Map();
    const labels = new Map();
    if (pullApks) {
      const all = result.apps.filter((a) => !a.system && a.apkPath && (a.score >= 10 || a.sideloaded || !a.hasLauncherIcon));
      // Most suspicious first, so a time cut drops the least interesting apps.
      all.sort((a, b) => b.score - a.score);
      const candidates = all.slice(0, MAX_PULL);
      if (all.length > MAX_PULL) warn(`Only the ${MAX_PULL} most suspicious app files were checked; ${all.length - MAX_PULL} lower-scoring apps were not (${all.slice(MAX_PULL).map((a) => a.pkg).join(', ')}).`);
      const aapt2 = aapt2Binary();
      const apkDir = keepApks ? join(outDir, 'apks') : join(workDir, 'apks', stamp);
      mkdirSync(apkDir, { recursive: true });
      const sizes = remoteSizes(adb, candidates.map((a) => a.apkPath));
      plog(`Checking signatures of ${candidates.length} apps${aapt2 ? ' and reading their names' : ''}`);
      const started = now();
      const skippedBig = [];
      let skippedTime = [];
      let i = 0;
      for (const a of candidates) {
        i++;
        if (now() - started > limits.maxPullMs) {
          skippedTime = candidates.slice(i - 1);
          break;
        }
        const size = sizes.get(a.apkPath);
        if (size !== undefined && size > limits.maxApkBytes) {
          skippedBig.push(`${a.pkg} (${mb(size)})`);
          continue;
        }
        const local = join(apkDir, `${a.pkg}.apk`);
        if (!adb.pull(a.apkPath, local)) {
          if (adb.mode !== 'replay') warn(`Could not copy ${a.pkg} from the phone; its signature was not checked.`);
          continue;
        }
        try {
          const c = apkCertificate(local);
          if (c) {
            // Prefer a certificate that is on the indicator list (multi-signer / rotated keys), else the primary.
            const hit = c.all.find((x) => iocs.certSha1?.has?.(x.sha1));
            certs.set(a.pkg, (hit || c).sha1);
          }
        } catch (e) {
          warn(`Could not read the signature of ${a.pkg}: ${e.message}`);
        }
        const label = labelFromApk(aapt2, local);
        if (label) labels.set(a.pkg, label);
        // The phone could not hash it (old toybox, permissions): hash the copy instead.
        const pkgRec = snapshot.packages.find((p) => p.pkg === a.pkg);
        if (pkgRec && !pkgRec.sha256) {
          try { pkgRec.sha256 = fileSha256(local); } catch { /* keep null */ }
        }
        if (!keepApks) rmSync(local, { force: true });
        if (i % 10 === 0) plog(`  ${i}/${candidates.length}`);
      }
      if (skippedBig.length) warn(`Skipped ${skippedBig.length} app file(s) over ${mb(limits.maxApkBytes)}: ${skippedBig.join(', ')}. Their names and hashes were still checked.`);
      if (skippedTime.length) warn(`Stopped copying app files after ${Math.round(limits.maxPullMs / 60000)} minutes; ${skippedTime.length} were not checked: ${skippedTime.map((a) => a.pkg).join(', ')}. Their names and hashes were still checked.`);
      if (!keepApks) {
        try {
          rmSync(apkDir, { recursive: true, force: true });
          const parent = join(workDir, 'apks');
          if (existsSync(parent) && readdirSync(parent).length === 0) rmSync(parent, { recursive: true, force: true });
        } catch { /* best effort */ }
      } else plog(`App files kept in ${apkDir}`);
      result = analyze(snapshot, iocs, { certs, labels });
    }

    if (vtApiKey) {
      const hashes = result.apps.filter((a) => !a.system && a.sha256 && (a.score >= 10 || a.sideloaded)).map((a) => a.sha256);
      const vt = await lookupHashes(hashes, vtApiKey, { log: plog });
      if (vt.size) result = analyze(snapshot, iocs, { certs, labels, vt });
      if (new Set(hashes).size > vt.size) warn(`VirusTotal answered for ${vt.size} of ${new Set(hashes).size} app files (free-tier limit or network).`);
    }

    result.warnings = warnings;
    writeFileSync(join(outDir, 'snapshot.json'), JSON.stringify(snapshot, null, 1));
    writeFileSync(join(outDir, 'result.json'), JSON.stringify(result, null, 1));
    plog(`Scan finished: ${result.summary.critical} critical, ${result.summary.suspicious} suspicious, ${result.summary.watch} to watch.`);
    return { snapshot, result, outDir, warnings };
  } catch (e) {
    plog(`Scan failed: ${e.message}`);
    throw e;
  }
}

export const _internal = { remoteSizes };
