// Console text and a self-contained HTML report.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function consoleReport(result) {
  const lines = [];
  const d = result.device;
  lines.push(`Phone: ${d.manufacturer} ${d.model}, Android ${d.android}, security patch ${d.securityPatch}`);
  lines.push(`Apps checked: ${result.summary.total} (${result.summary.thirdParty} user-installed). Indicators loaded: ${result.summary.iocCount}.`);
  lines.push('');
  if (result.flagged.length === 0) lines.push('No suspicious apps found.');
  for (const a of result.flagged) {
    lines.push(`[${a.level}] ${a.label ? `${a.label} (${a.pkg})` : a.pkg}  score ${a.score}`);
    for (const r of a.reasons) lines.push(`    +${r.pts}  ${r.text}`);
  }
  if (result.deviceFindings.length) {
    lines.push('');
    lines.push('Phone settings:');
    for (const f of result.deviceFindings) lines.push(`  [${f.level}] ${f.text}`);
  }
  return lines.join('\n');
}

export function htmlReport(result, { generatedAt = new Date() } = {}) {
  const d = result.device;
  const level = (l) => `<span class="lvl ${l.toLowerCase()}">${l}</span>`;
  const apps = result.flagged
    .map(
      (a) => `<section class="app ${a.level.toLowerCase()}">
  <h3>${level(a.level)} ${esc(a.label || a.pkg)} <small>${esc(a.pkg)}</small> <span class="score">${a.score}</span></h3>
  <ul>${a.reasons.map((r) => `<li><b>+${r.pts}</b> ${esc(r.text)}</li>`).join('')}</ul>
  <p class="meta">Installed ${esc(a.firstInstall || '?')}${a.installer ? ` by ${esc(a.installer)}` : ''} · version ${esc(a.versionName || '?')}${a.sha256 ? ` · SHA-256 ${esc(a.sha256)}` : ''}${a.cert ? ` · cert ${esc(a.cert)}` : ''}</p>
</section>`,
    )
    .join('\n');
  const dev = result.deviceFindings.map((f) => `<li>${level(f.level)} ${esc(f.text)}</li>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Android Guardian report</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--crit:#c62828;--sus:#e65100;--watch:#9e7b00;--ok:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--muted:#9aa0a6;--card:#1d2024}}
body{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;max-width:900px;margin-inline:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}h3{font-size:15px;margin:0 0 6px}
.muted{color:var(--muted)}.app{background:var(--card);border-radius:10px;padding:14px 16px;margin:10px 0;border-left:4px solid var(--muted)}
.app.critical{border-color:var(--crit)}.app.suspicious{border-color:var(--sus)}.app.watch{border-color:var(--watch)}
.lvl{font-size:11px;font-weight:700;padding:2px 6px;border-radius:4px;color:#fff;background:var(--muted);vertical-align:middle}
.lvl.critical{background:var(--crit)}.lvl.suspicious{background:var(--sus)}.lvl.watch{background:var(--watch)}.lvl.ok{background:var(--ok)}
.score{float:right;font-weight:700;color:var(--muted)}small{color:var(--muted);font-weight:400}.meta{font-size:12px;color:var(--muted);margin:6px 0 0;word-break:break-all}
ul{margin:4px 0;padding-left:18px}.summary{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}.summary div{background:var(--card);padding:10px 14px;border-radius:8px}
</style></head><body>
<h1>Android Guardian report</h1>
<p class="muted">${esc(generatedAt.toISOString().replace('T', ' ').slice(0, 16))} · ${esc(d.manufacturer)} ${esc(d.model)} · Android ${esc(d.android)} · patch ${esc(d.securityPatch)}</p>
<div class="summary"><div><b>${result.summary.total}</b> apps checked</div><div><b>${result.summary.critical}</b> critical</div><div><b>${result.summary.suspicious}</b> suspicious</div><div><b>${result.summary.watch}</b> to watch</div><div><b>${result.summary.iocCount}</b> known indicators</div></div>
<h2>Apps</h2>
${apps || '<p>No suspicious apps found.</p>'}
<h2>Phone settings</h2>
<ul>${dev || '<li>Nothing to report.</li>'}</ul>
<p class="muted">Score bands: 70+ critical (remove), 40–69 suspicious (review), 20–39 watch. Known-indicator data from the Echap stalkerware-indicators project.<br>Android Guardian is free and open source (MIT), by Abdulraham Amer · https://github.com/AbdulrahmanAmer/android-guardian</p>
</body></html>`;
}
