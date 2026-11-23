import fs from 'node:fs';
import path from 'node:path';

export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function finalize(report, complete) {
  const runs = report.runs.filter(Boolean);
  const errors = report.errors.length + runs.reduce((n, r) => n + r.errors.length, 0);
  const blockers = runs.reduce((n, r) => n + (r.blockers ?? 0), 0);
  const visualFailed = runs.some(r => r.visual?.status === 'mismatch');
  const primary = runs.filter(r => !r.sweep);
  const visualMissing = !!report.baseline && (!primary.length || primary.some(r =>
    !['match', 'mismatch'].includes(r.visual?.status)
    || (r.captures ?? []).some(c => !['match', 'mismatch'].includes(c.visual?.status))));
  const incomplete = !complete || errors > 0 || visualMissing;
  report.summary = {
    status: incomplete ? 'incomplete' : blockers || visualFailed ? 'failed' : 'passed',
    complete: !incomplete, planned: report.planned, completed: runs.length, blockers, errors,
    visual: !report.baseline ? 'not_checked' : incomplete ? 'incomplete' : visualFailed ? 'failed' : 'passed',
    manualReview: 'required',
  };
  report.durationMs = Math.round(performance.now() - report._started);
  return incomplete ? 2 : blockers || visualFailed ? 1 : 0;
}
export function writeReport(report, folder, html = true) {
  const { _started, ...data } = report;
  const dest = path.join(folder, 'audit.json');
  fs.writeFileSync(dest + '.tmp', JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(dest + '.tmp', dest);
  if (!html) return;
  const e = escapeHTML;
  const image = (name, caption) => name ? `<figure><a href="${e(name)}"><img loading="lazy" src="${e(name)}" alt="${e(caption)}"></a><figcaption>${e(caption)}</figcaption></figure>` : '';
  const groups = new Map();
  for (const r of report.runs.filter(Boolean)) {
    for (const type of ['tap', 'fontOffLadder', 'contrast', 'clip', 'rhythm', 'lead', 'edge', 'axis', 'gap', 'a11y', 'runtime', 'errors', 'warn']) {
      for (const finding of r[type] ?? []) {
        const key = type + ':' + finding;
        if (!groups.has(key)) groups.set(key, { type, finding, runs: [] });
        groups.get(key).runs.push(`${r.theme}/${r.width}`);
      }
    }
    if (r.hscroll) groups.set(`hscroll:${r.theme}:${r.width}`, { type: 'hscroll', finding: 'Przewijanie poziome', runs: [`${r.theme}/${r.width}`] });
  }
  const findings = [...groups.values()].map(g => `<tr><td>${e(g.type)}</td><td>${e(g.finding)}</td><td>${e(g.runs.join(', '))}</td></tr>`).join('');
  // Stany po kliknięciu i okno otwarte od wejścia: co kliknięto, co się otworzyło, ile nowych uwag, zrzut.
  const stateRows = report.runs.filter(Boolean).flatMap(r => [
    ...(r.arrival ? [`<tr><td>${e(r.theme)}/${r.width}</td><td>okno po wejściu: ${e(r.arrival.window)}</td><td>${e(r.arrival.closed ? 'zamknięte: ' + r.arrival.closed : 'nie do zamknięcia')}</td><td>${r.arrival.blockers ?? 0}</td><td>${e((r.arrival.findings ?? []).slice(0, 3).join(' · '))}</td><td>${r.arrival.shot ? `<a href="${e(r.arrival.shot)}">zrzut</a>` : ''}</td></tr>`] : []),
    ...(Array.isArray(r.states) ? r.states : []).map(s => `<tr><td>${e(r.theme)}/${r.width}</td><td>${e(s.trigger ?? '')}</td><td>${e(s.kind)}${s.target ? ' → ' + e(s.target) : ''}${s.reason ? ' (' + e(s.reason) + ')' : ''}</td><td>${s.blockers ?? 0}</td><td>${e([...[...(s.findings ?? []), ...(s.runtime ?? [])].slice(0, 3), ...(s.notices ?? [])].join(' · '))}</td><td>${s.shot ? `<a href="${e(s.shot)}">zrzut</a>` : ''}</td></tr>`),
  ]).join('');
  const states = stateRows ? `<h2>Stany po kliknięciu</h2><table><thead><tr><th>Pomiar</th><th>Wyzwalacz</th><th>Skutek</th><th>Nowe uwagi</th><th>Przykłady</th><th>Dowód</th></tr></thead><tbody>${stateRows}</tbody></table>` : '';
  const cards = report.runs.filter(Boolean).map(r => `<section><h2>${e(r.theme)} · ${r.width}px · ${r.blockers ?? 0} blokerów · ${r.durationMs} ms</h2>
    <p>Dowody: ${e(r.status)} · porównanie: ${e(r.visual?.status ?? 'not_checked')}${r.visual?.differentPixels != null ? ` · ${r.visual.differentPixels} zmienionych pikseli` : ''}</p>${(r.attempts ?? []).map((a, i) => `<p>Odrzucone podejście ${i + 1}: ${e((a.errors ?? []).join(' · '))} · uwag: ${a.blockers ?? 0}${(a.runtime ?? []).length ? ' · błędy wykonania: ' + e(a.runtime.slice(0, 5).join(' · ')) : ''}${(a.warn ?? []).length ? ' · ' + e(a.warn.join(' · ')) : ''}</p>`).join('')}
    <div class="images">${image(r.expected, 'Zatwierdzony wzorzec')}${image(r.shot, 'Obecny ekran')}${image(r.diff, 'Różnice (różowe)')}</div>${(r.captures ?? []).map(c => `<h3>Panel ${e(c.scroll?.panel)} · przewinięcie ${e(c.scroll?.offset)}px · ${e(c.visual?.status)}</h3><div class="images">${image(c.expected, 'Wzorzec panelu')}${image(c.shot, 'Panel po przewinięciu')}${image(c.diff, 'Różnice panelu')}</div>`).join('')}</section>`).join('');
  fs.writeFileSync(path.join(folder, 'report.html'), `<!doctype html><html lang="pl"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Helix — raport</title>
    <style>body{font:15px system-ui;max-width:1500px;margin:auto;padding:24px;background:#f5f5f3;color:#202020}h1{font-size:28px}h2{font-size:18px}section{background:white;padding:20px;margin:20px 0;border:1px solid #ddd}.images{display:flex;gap:12px}figure{margin:0;flex:1;min-width:0}img{width:100%;max-height:650px;object-fit:contain;object-position:top;background:#ddd}figcaption{padding:8px}table{border-collapse:collapse;width:100%;background:white}td,th{padding:8px;border:1px solid #ddd;text-align:left;overflow-wrap:anywhere}td:last-child{max-width:250px}pre{white-space:pre-wrap}@media(max-width:700px){.images{display:block}body{padding:12px}}</style>
    <h1>Helix: ${e(report.summary.status)}</h1><p>${e(report.caseId)} · ${e(report.generated)} · ${(report.durationMs / 1000).toFixed(1)} s · ${report.summary.completed}/${report.summary.planned} pomiarów</p>
    <p>Automat: ${report.summary.blockers} blokerów, ${report.summary.errors} błędów wykonania. Zgodność ze wzorcem: <strong>${e(report.summary.visual)}</strong>. Przegląd kompozycji i zachowania: wymagany.</p>
    <p>Wzorzec: ${e(report.baseline?.approval?.reviewer ?? 'brak')} · ${e(report.baseline?.approval?.note ?? '')}. Maski: ${e(report.contract?.mask || 'brak')}.</p>
    <pre>${e(report.errors.join('\n'))}</pre><details><summary>Ustawienia i pochodzenie</summary><pre>${e(JSON.stringify({ contract: report.contract, config: report.config, source: report.source }, null, 2))}</pre></details>
    <h2>Problemy zebrane ze wszystkich szerokości</h2><table><thead><tr><th>Reguła</th><th>Problem</th><th>Wystąpienia</th></tr></thead><tbody>${findings}</tbody></table>${states}${cards}</html>`);
}
