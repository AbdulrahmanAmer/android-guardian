// Optional VirusTotal lookup of APK hashes (free API key, 4 requests/minute).
// Only hashes are sent, never files. Off unless the user saves a key.
const API = 'https://www.virustotal.com/api/v3/files/';
const FREE_TIER_GAP_MS = 15_500;

export async function lookupHashes(hashes, apiKey, { log = () => {}, max = 12, gapMs = FREE_TIER_GAP_MS } = {}) {
  const out = new Map();
  const list = [...new Set(hashes.filter(Boolean))].slice(0, max);
  if (!apiKey || list.length === 0) return out;
  log(`Asking VirusTotal about ${list.length} app file${list.length === 1 ? '' : 's'} (free key: ~${Math.ceil((list.length * gapMs) / 60000)} min)`);
  for (let i = 0; i < list.length; i++) {
    const sha = list[i];
    try {
      const res = await fetch(API + sha, { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(30_000) });
      if (res.status === 404) out.set(sha, { known: false });
      else if (res.status === 429) { log('VirusTotal rate limit reached; stopping lookups for this scan'); break; }
      else if (!res.ok) { log(`VirusTotal error ${res.status}`); break; }
      else {
        const j = await res.json();
        const s = j.data?.attributes?.last_analysis_stats || {};
        const total = Object.values(s).reduce((a, b) => a + b, 0);
        out.set(sha, { known: true, malicious: s.malicious || 0, suspicious: s.suspicious || 0, total, link: `https://www.virustotal.com/gui/file/${sha}` });
      }
    } catch (e) {
      log(`VirusTotal lookup failed: ${e.message}`);
      break;
    }
    if (i < list.length - 1) await new Promise((r) => setTimeout(r, gapMs));
  }
  return out;
}
