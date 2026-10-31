// Indicators of compromise: known-bad package names, APK hashes, signing
// certificates and domains. Public source: Echap's stalkerware-indicators
// (used by Amnesty's MVT). Plus a small built-in list of well-known RAT families.
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const STIX_URL = 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2';
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;

// Default package names of popular open-source / leaked Android RAT builders.
// Real attackers often rename these, so heuristics still matter.
export const BUILTIN = {
  packages: {
    'ahmyth.mine.king.ahmyth': 'AhMyth RAT',
    'com.etechd.l3mon': 'L3MON RAT',
    'net.droidjack.server': 'DroidJack RAT',
    'my.app.client': 'AndroRAT',
    'com.metasploit.stage': 'Metasploit payload',
    'com.example.reverseshell2': 'Reverse shell payload',
    'com.connect': 'Dendroid RAT',
    'com.android.tester': 'SpyNote RAT',
    'com.spynote.software.spynote': 'SpyNote RAT',
    'com.hawkshaw': 'HawkShaw RAT',
    'com.rat.pro': 'Generic RAT',
    'com.system.service.update': 'Masquerading spyware',
  },
};

export function loadIocs({ cacheDir, refresh = false, log = () => {}, offline = false } = {}) {
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, 'stalkerware.stix2');
  let stale = true;
  if (existsSync(file)) stale = Date.now() - statSync(file).mtimeMs > MAX_AGE_MS;
  return (async () => {
    if ((refresh || stale || !existsSync(file)) && !offline) {
      try {
        log('Downloading latest stalkerware indicators (Echap list)');
        const res = await fetch(STIX_URL, { signal: AbortSignal.timeout(60_000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        writeFileSync(file, await res.text());
      } catch (e) {
        log(`Could not refresh indicators: ${e.message}${existsSync(file) ? ' (using cached copy)' : ''}`);
      }
    }
    const iocs = { packages: new Map(), sha256: new Map(), certSha1: new Map(), domains: new Map(), source: null, count: 0 };
    for (const [pkg, name] of Object.entries(BUILTIN.packages)) iocs.packages.set(pkg, name);
    if (existsSync(file)) {
      const data = JSON.parse(readFileSync(file, 'utf8'));
      const objects = data.objects || [];
      // malware objects give human names; indicators reference them via relationships
      const malwareName = new Map();
      for (const o of objects) if (o.type === 'malware') malwareName.set(o.id, o.name);
      const indicatorToMalware = new Map();
      for (const o of objects) {
        if (o.type === 'relationship' && o.relationship_type === 'indicates') indicatorToMalware.set(o.source_ref, o.target_ref);
      }
      for (const o of objects) {
        if (o.type !== 'indicator' || !o.pattern) continue;
        const name = malwareName.get(indicatorToMalware.get(o.id)) || o.name || 'known stalkerware';
        const m = o.pattern.match(/^\[([\w.:-]+)\s*=\s*'([^']+)'\]$/);
        if (!m) continue;
        const [, kind, value] = m;
        if (kind === 'app:id') iocs.packages.set(value, name);
        else if (kind === 'file:hashes.sha256') iocs.sha256.set(value.toLowerCase(), name);
        else if (kind === 'app:cert.sha1') iocs.certSha1.set(value.toUpperCase().replace(/:/g, ''), name);
        else if (kind === 'domain-name:value') iocs.domains.set(value.toLowerCase(), name);
      }
      iocs.source = { file, updated: statSync(file).mtime.toISOString() };
    }
    iocs.count = iocs.packages.size + iocs.sha256.size + iocs.certSha1.size + iocs.domains.size;
    return iocs;
  })();
}
