// Optional VirusTotal lookup of APK hashes (free API key: 4 requests/minute, 500/day).
// Only hashes are sent, never files. Off unless the user saves a key.
// - Results are cached in memory for the life of the process (a re-scan does not spend quota again).
// - A 429 is either the per-minute limit (wait, retry once) or the daily/monthly quota (stop).
// - The whole lookup never takes longer than `maxMinutes` (default 4): hashes not reached are skipped.
const API = 'https://www.virustotal.com/api/v3/files/';
const FREE_TIER_GAP_MS = 15_500;
const MINUTE_WINDOW_MS = 61_000;

const cache = new Map(); // sha256 -> result, only definitive answers (found / not found)
export function _clearVtCache() { cache.clear(); }

function retryAfterMs(res, now) {
  const h = res.headers?.get?.('retry-after');
  if (h) {
    const s = Number(h);
    if (Number.isFinite(s)) return Math.max(0, s * 1000);
    const t = Date.parse(h);
    if (Number.isFinite(t)) return Math.max(0, t - now);
  }
  // Generic rate-limit headers, in case VirusTotal (or a proxy) sends them.
  const remaining = res.headers?.get?.('x-ratelimit-remaining');
  const reset = res.headers?.get?.('x-ratelimit-reset');
  if (remaining === '0' && reset) {
    const r = Number(reset);
    if (Number.isFinite(r)) return r > 1e9 ? Math.max(0, r * 1000 - now) : r * 1000;
  }
  return null;
}

export async function lookupHashes(hashes, apiKey, {
  log = () => {}, max = 12, gapMs = FREE_TIER_GAP_MS, maxMinutes = 4,
  fetchImpl = globalThis.fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = () => Date.now(),
} = {}) {
  const out = new Map();
  const stats = { asked: 0, cached: 0, checked: 0, skipped: 0, stopped: null };
  out.stats = stats;
  const unique = [...new Set(hashes.filter(Boolean).map((h) => h.toLowerCase()))];
  stats.asked = unique.length;
  for (const sha of unique) if (cache.has(sha)) { out.set(sha, cache.get(sha)); stats.cached++; }
  const list = unique.filter((h) => !cache.has(h)).slice(0, max);
  stats.skipped = unique.length - stats.cached - list.length;
  if (!apiKey || list.length === 0) return out;

  const deadline = now() + maxMinutes * 60_000;
  const est = Math.min(maxMinutes, Math.ceil((list.length * gapMs) / 60000));
  log(`Asking VirusTotal about ${list.length} app file${list.length === 1 ? '' : 's'} (free key: up to ~${est} min)`);
  // Wait, unless that would cross the deadline. Returns false when out of time.
  const waitFor = async (ms) => {
    if (now() + ms > deadline) return false;
    if (ms > 0) await sleep(ms);
    return true;
  };

  let i = 0;
  let retried = false;
  while (i < list.length) {
    const sha = list[i];
    let res;
    try {
      const remaining = deadline - now();
      if (remaining <= 0) { stats.stopped = 'time'; break; }
      res = await fetchImpl(API + sha, { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(Math.min(30_000, remaining)) });
    } catch (e) {
      log(`VirusTotal lookup failed: ${e.message}`);
      stats.stopped = 'network';
      break;
    }
    if (res.status === 429) {
      let body = '';
      try { body = await res.text(); } catch { /* ignore */ }
      const quota = /daily|monthly|QuotaExceeded.*(day|month)/i.test(body);
      if (quota || retried) {
        log('VirusTotal daily quota for this key is used up; the remaining apps were not checked this time');
        stats.stopped = 'quota';
        break;
      }
      const wait = retryAfterMs(res, now()) ?? MINUTE_WINDOW_MS;
      log(`VirusTotal asked us to slow down; waiting ${Math.ceil(wait / 1000)} s`);
      if (!(await waitFor(wait))) { stats.stopped = 'time'; break; }
      retried = true;
      continue; // same hash again
    }
    retried = false;
    if (res.status === 401 || res.status === 403) {
      log('VirusTotal refused the API key (check it in Settings)');
      stats.stopped = 'auth';
      break;
    }
    if (res.status === 404) {
      const r = { known: false };
      cache.set(sha, r);
      out.set(sha, r);
    } else if (!res.ok) {
      log(`VirusTotal error ${res.status}`);
      stats.stopped = `http-${res.status}`;
      break;
    } else {
      const j = await res.json();
      const s = j.data?.attributes?.last_analysis_stats || {};
      const total = Object.values(s).reduce((a, b) => a + b, 0);
      const r = { known: true, malicious: s.malicious || 0, suspicious: s.suspicious || 0, total, link: `https://www.virustotal.com/gui/file/${sha}` };
      cache.set(sha, r);
      out.set(sha, r);
    }
    stats.checked++;
    i++;
    if (i < list.length) {
      // Honour a server hint if the key is about to hit its window, else the free-tier pace.
      const hinted = res.headers?.get?.('x-ratelimit-remaining') === '0' ? retryAfterMs(res, now()) : null;
      if (!(await waitFor(Math.max(gapMs, hinted ?? 0)))) { stats.stopped = 'time'; break; }
    }
  }
  const notChecked = list.length - stats.checked;
  stats.skipped += notChecked;
  if (stats.stopped === 'time' && notChecked) log(`VirusTotal: stopped after ${maxMinutes} minutes; ${notChecked} app file${notChecked === 1 ? ' was' : 's were'} not checked`);
  return out;
}
