// Console text and a self-contained HTML report.
// The HTML follows the interface's design: one type family, severity colours used only for severity,
// a single reading column (no cards grid), light and dark mode, and clean printing to PDF.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || '')) ? String(u) : null);

export const FOOTER = 'Android Guardian · free and open source (MIT) · Abdulraham Amer';

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
    if (a.virusTotal?.link) lines.push(`    VirusTotal: ${a.virusTotal.link}`);
  }
  if (result.deviceFindings.length) {
    lines.push('');
    lines.push('Phone settings:');
    for (const f of result.deviceFindings) lines.push(`  [${f.level}] ${f.text}`);
  }
  if (result.warnings?.length) {
    lines.push('');
    lines.push('Scan notes:');
    for (const w of result.warnings) lines.push(`  - ${w}`);
  }
  return lines.join('\n');
}

const KIND_TITLE = {
  remove: (n) => `Remove ${n}`,
  block: (n) => `Take away the rights of ${n}`,
  undo: (n) => `Undo the block on ${n}`,
  dns: () => 'Protect the phone (Private DNS)',
  fix: () => 'Phone setting',
};

function actionKind(a) {
  const k = a.kind || a.type || a.action;
  if (k && KIND_TITLE[k]) return k;
  if ('removed' in a) return 'remove';
  if ('suspended' in a) return 'block';
  return a.pkg ? 'block' : 'fix';
}

function outcome(a, kind) {
  if (kind === 'remove') {
    if (a.removed) return 'Removed from the phone.';
    if (a.disabled) return 'Could not be uninstalled; disabled instead (it cannot run).';
    if (a.suspended) return 'Could not be uninstalled or disabled; suspended (it cannot open or run).';
    return 'NOT removed. See the steps below.';
  }
  if (kind === 'block') return a.ok ? 'Rights taken away and the app is stopped from running.' : 'Only partly done. See the steps below.';
  return a.ok ? 'Done and checked on the phone.' : 'NOT done. See the steps below.';
}

function deviceRows(d) {
  const yesNo = (v) => (v ? 'yes' : 'no');
  const rows = [
    ['Phone', `${d.manufacturer || ''} ${d.model || ''}`.trim() || 'unknown'],
    ['Android', `${d.android || '?'}${d.sdk ? ` (SDK ${d.sdk})` : ''}`],
    ['Security patch', d.securityPatch || 'unknown'],
    ['Verified boot', d.verifiedBoot || 'unknown'],
    ['Bootloader', d.bootloaderLocked === '1' ? 'locked' : d.bootloaderLocked === '0' ? 'UNLOCKED' : 'unknown'],
    ['Root binary found', yesNo(d.rootBinary)],
    ['Private DNS', d.privateDnsMode === 'hostname' ? `on (${d.privateDnsHost || '?'})` : d.privateDnsMode || 'automatic'],
  ];
  return rows.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');
}

/**
 * htmlReport(result, { generatedAt, actions, warnings })
 * actions: remediation results, e.g. { kind: 'remove', pkg, ...removeApp(...) } or { kind: 'dns', ...setDnsProtection(...) }.
 */
export function htmlReport(result, { generatedAt = new Date(), actions = [], warnings = result.warnings || [] } = {}) {
  const d = result.device || {};
  const s = result.summary || {};
  const nameOf = new Map((result.apps || []).map((a) => [a.pkg, a.label || a.pkg]));
  const sev = (l) => `<span class="sev ${esc(String(l).toLowerCase())}">${esc(l)}</span>`;
  const actionsFor = (pkg) => actions.filter((x) => x.pkg === pkg);

  const apps = (result.flagged || [])
    .map((a) => {
      const vt = a.virusTotal;
      const vtLink = safeUrl(vt?.link);
      const meta = [
        ['Installed', `${a.firstInstall || 'unknown'}${a.installer ? ` by ${a.installer}` : a.sideloaded ? ' (not from an app store)' : ''}`],
        ['Version', a.versionName || 'unknown'],
        a.sha256 && ['App file SHA-256', a.sha256],
        a.cert && ['Signing certificate SHA-1', a.cert],
        a.uid && ['Android user ID', String(a.uid)],
      ].filter(Boolean);
      const vtRow = vt
        ? `<tr><th scope="row">VirusTotal</th><td>${vt.known ? `${esc(vt.malicious)} of ${esc(vt.total)} engines say malicious` : 'not known to VirusTotal'}${vtLink ? ` · <a href="${esc(vtLink)}">${esc(vtLink)}</a>` : ''}</td></tr>`
        : '';
      const done = actionsFor(a.pkg)
        .map((x) => `<p class="done"><b>${esc(KIND_TITLE[actionKind(x)](a.label || a.pkg))}:</b> ${esc(outcome(x, actionKind(x)))}</p>`)
        .join('');
      return `<section class="app" aria-labelledby="app-${esc(a.pkg)}">
  <h3 id="app-${esc(a.pkg)}">${sev(a.level)} <span class="name">${esc(a.label || a.pkg)}</span> <span class="pkg">${esc(a.pkg)}</span> <span class="score">score ${esc(a.score)}</span></h3>
  <ul class="reasons">${a.reasons.map((r) => `<li><span class="pts">+${esc(r.pts)}</span> ${esc(r.text)}</li>`).join('')}</ul>
  <table class="facts">${meta.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}${vtRow}</table>
  ${done}
</section>`;
    })
    .join('\n');

  const doneSection = actions.length
    ? `<h2>What was done</h2>
${actions
  .map((x) => {
    const kind = actionKind(x);
    const title = KIND_TITLE[kind](nameOf.get(x.pkg) || x.pkg || '');
    const steps = (x.steps || []).map((st) => `<li><span class="${st.ok ? 'ok' : 'bad'}">${st.ok ? 'OK' : 'FAILED'}</span> ${esc(st.action)}${st.text ? ` <span class="muted">${esc(st.text)}</span>` : ''}</li>`).join('');
    return `<section class="action">
  <h3>${esc(title)}${x.pkg && nameOf.get(x.pkg) !== x.pkg ? ` <span class="pkg">${esc(x.pkg)}</span>` : ''}</h3>
  <p>${esc(outcome(x, kind))}</p>
  ${steps ? `<ol class="steps">${steps}</ol>` : ''}
  ${(x.warnings || []).map((w) => `<p class="muted">${esc(w)}</p>`).join('')}
</section>`;
  })
  .join('\n')}`
    : '';

  const manual = [];
  for (const x of actions) for (const m of x.manualSteps || []) manual.push({ who: x.pkg ? nameOf.get(x.pkg) || x.pkg : null, text: m });
  if (result.deviceFindings?.some((f) => /MANAGED by/.test(f.text)) && !manual.some((m) => /factory reset/i.test(m.text))) {
    manual.push({ who: null, text: 'This phone is managed by a device-owner app. If it is not a work phone from your employer, a factory reset is the only way to remove that app (Settings › System › Reset options › Erase all data). Save this report first; it is evidence.' });
  }
  const manualSection = manual.length
    ? `<h2>What you still need to do on the phone</h2>
<ol class="manual">${manual.map((m) => `<li>${m.who ? `<b>${esc(m.who)}:</b> ` : ''}${esc(m.text)}</li>`).join('')}</ol>`
    : '';

  const dev = (result.deviceFindings || []).map((f) => `<li>${sev(f.level)} ${esc(f.text)}</li>`).join('');
  const notes = warnings.length ? `<h2>Scan notes</h2><ul class="notes">${warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : '';
  const when = generatedAt instanceof Date ? generatedAt.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : String(generatedAt);
  const countLine = [
    `<b>${esc(s.critical ?? 0)}</b> ${sev('CRITICAL')}`,
    `<b>${esc(s.suspicious ?? 0)}</b> ${sev('SUSPICIOUS')}`,
    `<b>${esc(s.watch ?? 0)}</b> ${sev('WATCH')}`,
    `<b>${esc(s.total ?? 0)}</b> apps checked (${esc(s.thirdParty ?? 0)} installed by a person)`,
    `<b>${esc(s.iocCount ?? 0)}</b> known indicators${s.iocUpdated ? ` (list of ${esc(String(s.iocUpdated).slice(0, 10))})` : ''}`,
  ].join(' <span class="sep">·</span> ');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Android Guardian report</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<style>
:root{--paper:#ffffff;--paper-2:#f3f4f6;--ink:#111318;--ink-2:#5b6472;--rule:#dfe3e8;--action:#1a56db;
--sev-critical:#b3261e;--sev-suspicious:#b45309;--sev-watch:#8a6d00;--sev-ok:#1b7f3b;
--fs-caption:14px;--fs-body:16px;--fs-section:20px;--fs-title:28px;--measure:820px}
@media (prefers-color-scheme:dark){:root{--paper:#0e1013;--paper-2:#181b20;--ink:#eceef1;--ink-2:#9aa3af;--rule:#262b33;--action:#5b8def;
--sev-critical:#ef6a62;--sev-suspicious:#f0a04b;--sev-watch:#d9b94a;--sev-ok:#5fc07e}}
*{box-sizing:border-box}
html,body{margin:0;background:var(--paper);color:var(--ink);font:var(--fs-body)/1.5 system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:var(--measure);margin:0 auto;padding:32px 16px}
h1{font-size:var(--fs-title);font-weight:700;letter-spacing:-.015em;line-height:1.2;margin:0 0 4px}
h2{font-size:var(--fs-section);font-weight:600;margin:40px 0 12px;padding-top:16px;border-top:1px solid var(--rule)}
h3{font-size:var(--fs-body);font-weight:600;margin:0 0 6px;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}
p{margin:6px 0}a{color:var(--action);overflow-wrap:anywhere}
.muted,.caption{color:var(--ink-2);font-size:var(--fs-caption)}
.sev{font-size:var(--fs-caption);font-weight:600;letter-spacing:.04em;color:var(--ink-2)}
.sev.critical{color:var(--sev-critical)}.sev.suspicious{color:var(--sev-suspicious)}.sev.watch{color:var(--sev-watch)}.sev.ok{color:var(--sev-ok)}
.counts{margin:16px 0 0;font-size:var(--fs-caption);color:var(--ink-2)}.counts b{color:var(--ink);font-size:var(--fs-body)}.sep{margin:0 6px}
.pkg,.score{font-size:var(--fs-caption);color:var(--ink-2);font-weight:400;overflow-wrap:anywhere}.score{margin-left:auto}
.app,.action{padding:16px 0;border-bottom:1px solid var(--rule)}
ul,ol{margin:6px 0;padding-left:20px}
.reasons{list-style:none;padding-left:0}.reasons li{font-size:var(--fs-caption);padding:2px 0}
.pts{display:inline-block;min-width:3.2em;color:var(--ink-2);font-variant-numeric:tabular-nums}
table{border-collapse:collapse;width:100%;table-layout:fixed;font-size:var(--fs-caption);margin:8px 0}
th{font-weight:500;color:var(--ink-2);text-align:left;vertical-align:top;padding:3px 16px 3px 0;width:13em}
td{padding:3px 0;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
.facts td{font-family:inherit}
.done{font-size:var(--fs-caption);margin-top:8px}
.steps{font-size:var(--fs-caption)}.steps .ok{font-weight:600}.steps .bad{font-weight:600;color:var(--sev-critical)}
.manual li{margin:8px 0}
.notes li{font-size:var(--fs-caption);color:var(--ink-2)}
footer{max-width:var(--measure);margin:0 auto;padding:24px 16px 48px;font-size:var(--fs-caption);color:var(--ink-2);border-top:1px solid var(--rule)}
@media (max-width:560px){:root{--fs-title:24px}th{width:8.5em;padding-right:10px}.score{margin-left:0}}
@media print{
:root{--paper:#fff;--paper-2:#fff;--ink:#000;--ink-2:#444;--rule:#bbb;--action:#000;--sev-critical:#b3261e;--sev-suspicious:#b45309;--sev-watch:#8a6d00;--sev-ok:#1b7f3b}
html,body{background:#fff;color:#000;font-size:11pt}
main{max-width:none;padding:0}
h2{break-after:avoid}h3{break-after:avoid}
.app{break-inside:avoid}.app+.app{break-before:page}
.action,.manual li,tr{break-inside:avoid}
a{color:#000;text-decoration:none}
footer{max-width:none;padding:12px 0 0}
}
</style></head><body>
<main>
<h1>Android Guardian report</h1>
<p class="caption">${esc(when)} · ${esc(d.manufacturer)} ${esc(d.model)} · Android ${esc(d.android)}</p>
<p class="counts">${countLine}</p>

<h2>This phone</h2>
<table class="device">${deviceRows(d)}</table>

<h2>Flagged apps</h2>
${apps || '<p>No suspicious apps found.</p>'}
${manualSection}
${doneSection}
<h2>Phone settings</h2>
<ul class="findings">${dev || '<li>Nothing to report.</li>'}</ul>
${notes}
<p class="muted">Score bands: 70 and above critical (remove), 40 to 69 suspicious (review), 20 to 39 watch. Known-indicator data from the Echap stalkerware-indicators project (CC BY-SA 4.0).</p>
</main>
<footer>${esc(FOOTER)}</footer>
</body></html>`;
}
