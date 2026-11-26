'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const DEFAULT_MODELS = ["openai/gpt-4o-mini","anthropic/claude-3.5-haiku","google/gemini-2.0-flash-001","deepseek/deepseek-chat","x-ai/grok-3-mini"];
const QUESTIONS = {
  numbers: "List every statistic or number shown on this page and what each one refers to.",
  summary: "Summarize what this page is about in 4-5 sentences, including any key figures.",
  company: "What does this company do, and what concrete facts (sizes, counts, values, locations) does the page state?",
  missing: "Is any information on this page missing, contradictory, or shown as a placeholder (for example 0 values)? List it."
};
const PAGES = {bots: 'Bot view', scan: 'Site scan', schema: 'Structured data', access: 'AI access', llms: 'llms.txt', ai: 'AI test', settings: 'Settings'};
let LAST = null;
let SETTINGS = {key_source: 'none', key_hint: '', models: [], storage_ok: false, auth: false};

function store(k, v){ try{ localStorage.setItem(k, v); }catch(e){} }
function load(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }

async function api(path, opts){
  const res = await fetch(path, opts);
  if (res.status === 401){ location.href = '/login'; throw new Error('Login required'); }
  return res.json();
}
const post = (path, body) => api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});

/* ---------------------------------------------------------------- routing */
function currentPage(){
  const m = location.hash.match(/^#\/([a-z]+)/);
  return m && PAGES[m[1]] ? m[1] : 'bots';
}
function route(){
  const p = currentPage();
  Object.keys(PAGES).forEach(k => $('#page-' + k).classList.toggle('hidden', k !== p));
  $$('.nav nav a[data-page]').forEach(a => a.dataset.page === p ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'));
  $('#checkbar').classList.toggle('hidden', ['settings', 'scan', 'access', 'llms'].includes(p));
  document.title = `${PAGES[p]} – AI Bot View Checker`;
}
window.addEventListener('hashchange', () => { route(); window.scrollTo(0, 0); });

/* ---------------------------------------------------------------- settings */
function currentModels(){
  if (SETTINGS.models && SETTINGS.models.length) return SETTINGS.models;
  const local = (load('abvc_models') || '').split('\n').map(s => s.trim()).filter(Boolean);
  return local.length ? local : DEFAULT_MODELS;
}
function keyStatusHtml(s){
  if (s.key_source === 'saved') return `<span class="chip ok">Saved key in use</span> ${esc(s.key_hint)}`;
  if (s.key_source === 'env') return `<span class="chip ok">Server key in use</span> ${esc(s.key_hint)} (from OPENROUTER_API_KEY)`;
  return '<span class="chip warn">No key saved</span>';
}
function applySettings(s){
  SETTINGS = s;
  $('#keyStatus').innerHTML = keyStatusHtml(s);
  $('#aiKeyStatus').innerHTML = keyStatusHtml(s) + (s.key_source === 'none' ? ' <a class="links" href="#/settings">Add one in Settings</a>' : '');
  $('#clearKey').classList.toggle('hidden', s.key_source !== 'saved');
  $('#saveKey').disabled = !s.storage_ok;
  $('#keyNote').textContent = s.storage_ok
    ? 'A saved key works from any browser after you sign in.'
    : 'Saving is unavailable because the server has no writable storage. You can still paste a key on the AI test page for one test.';
  $('#models').value = currentModels().join('\n');
  renderModelPicks();
}
function renderModelPicks(){
  $('#modelPick').innerHTML = currentModels().map((m, i) =>
    `<label><input type="checkbox" class="model-cb" value="${esc(m)}" checked> ${esc(m)}</label>`).join('');
}

$('#saveKey').onclick = async () => {
  const k = $('#key').value.trim();
  if (!k){ $('#keyNote').textContent = 'Paste a key first, then save it.'; return; }
  $('#saveKey').disabled = true;
  try{
    const s = await post('/api/settings', {openrouter_key: k});
    if (s.error) throw new Error(s.error);
    $('#key').value = ''; applySettings(s); $('#keyNote').textContent = 'Key saved.';
  }catch(e){ $('#keyNote').textContent = 'Could not save the key: ' + e.message; $('#saveKey').disabled = false; }
};
$('#clearKey').onclick = async () => {
  if (!confirm('Remove the saved OpenRouter key from the server?')) return;
  try{
    const s = await post('/api/settings', {clear_key: true});
    if (s.error) throw new Error(s.error);
    applySettings(s); $('#keyNote').textContent = 'Saved key removed.';
  }catch(e){ $('#keyNote').textContent = 'Could not remove the key: ' + e.message; }
};
$('#saveModels').onclick = async () => {
  const models = $('#models').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!models.length){ $('#modelNote').textContent = 'Add at least one model ID.'; return; }
  store('abvc_models', models.join('\n'));
  if (!SETTINGS.storage_ok){
    applySettings({...SETTINGS, models: []});
    $('#modelNote').textContent = 'Saved in this browser only, because the server has no writable storage.';
    return;
  }
  try{
    const s = await post('/api/settings', {models});
    if (s.error) throw new Error(s.error);
    applySettings(s); $('#modelNote').textContent = 'Models saved.';
  }catch(e){ $('#modelNote').textContent = 'Could not save models: ' + e.message; }
};
$('#loadModels').onclick = async () => {
  $('#loadModels').disabled = true; $('#modelNote').textContent = 'Loading model list…';
  try{
    const d = await api('/api/models');
    if (d.error) throw new Error(d.error);
    $('#modelList').innerHTML = d.models.map(m => `<option value="${esc(m)}">`).join('');
    $('#modelNote').textContent = `${d.models.length} models loaded. Type in the search box to find one, then click Add.`;
  }catch(e){ $('#modelNote').textContent = 'Could not load models: ' + e.message; }
  finally{ $('#loadModels').disabled = false; }
};
$('#addModel').onclick = () => {
  const m = $('#modelSearch').value.trim(); if (!m) return;
  const list = $('#models').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!list.includes(m)) list.push(m);
  $('#models').value = list.join('\n'); $('#modelSearch').value = '';
  $('#modelNote').textContent = 'Added. Click Save models to keep the change.';
};

/* ---------------------------------------------------------------- check */
function updateBotSummary(){
  const n = $$('.bot-cb:checked').length;
  $('#botSummary').textContent = `Bots to test: ${n} selected, plus a normal browser for comparison`;
}
$('#selAll').onclick = () => { $$('.bot-cb').forEach(c => c.checked = true); updateBotSummary(); };
$('#selNone').onclick = () => { $$('.bot-cb').forEach(c => c.checked = false); updateBotSummary(); };
$('#url').addEventListener('keydown', e => { if (e.key === 'Enter') runCheck(); });
$('#checkBtn').onclick = runCheck;

async function runCheck(){
  const url = $('#url').value.trim();
  if (!url){ $('#checkStatus').textContent = 'Enter a URL to check.'; return; }
  store('abvc_url', url);
  const bots = $$('.bot-cb:checked').map(c => c.value);
  $('#checkBtn').disabled = true;
  $('#checkStatus').textContent = `Fetching as ${bots.length + 1} user agents…`;
  try{
    const data = await post('/api/check', {url, bots});
    if (data.error){ $('#checkStatus').textContent = data.error; return; }
    LAST = data;
    try{ sessionStorage.setItem('abvc_last', JSON.stringify(data)); }catch(e){}
    renderAll();
  }catch(e){
    $('#checkStatus').textContent = 'Check failed: ' + e.message;
  }finally{ $('#checkBtn').disabled = false; }
}

function renderAll(){
  if (!LAST) return;
  $$('[data-empty]').forEach(el => el.classList.add('hidden'));
  $$('[data-full]').forEach(el => el.classList.remove('hidden'));
  $('#checkStatus').textContent = `Showing ${LAST.url}, checked ${LAST.checked_at}.`;
  renderBots();
  setupSchema();
  setupAI();
}

/* ---------------------------------------------------------------- bot view */
function norm(v){ return String(v ?? '').replace(/[,\s]/g, ''); }
function counterInfo(r){
  if (!r.counters || !r.counters.length) return {html: '<span class="chip na">none</span>', bad: 0};
  let bad = 0;
  const html = r.counters.map(c => {
    const wrong = c.to !== null && c.to !== undefined && norm(c.shown) !== norm(c.to);
    if (wrong) bad++;
    return wrong ? `<span class="start" title="Shows ${esc(c.shown)}, final value is ${esc(c.to)}">${esc(c.shown || '∅')}</span>` : esc(c.shown);
  }).join(', ');
  return {html, bad};
}
function statusChip(r){
  if (r.error) return `<span class="chip bad">Error</span>`;
  if (r.challenge) return `<span class="chip bad">${r.status} challenge</span>`;
  if (r.status >= 200 && r.status < 300) return `<span class="chip ok">${r.status}</span>`;
  if (r.status >= 300 && r.status < 400) return `<span class="chip warn">${r.status}</span>`;
  return `<span class="chip bad">${r.status ?? '?'}</span>`;
}
function robotsChip(r){
  if (r.robots_allowed === null || r.robots_allowed === undefined) return '<span class="chip na">n/a</span>';
  return r.robots_allowed ? '<span class="chip ok">Allowed</span>' : '<span class="chip bad">Blocked</span>';
}
function schemaChip(r, base){
  const s = r.structured;
  if (!s) return '<span class="chip na">–</span>';
  if (!s.items.length) return '<a href="#/schema" class="chip bad" style="text-decoration:none">none</a>';
  let h = `<a href="#/schema" class="chip ${s.counts.error ? 'warn' : 'ok'}" style="text-decoration:none">${plural(s.items.length, 'item')}</a>`;
  if (base && base.structured && r.id !== 'browser' && s.types.join() !== base.structured.types.join())
    h += ' <span class="chip bad">differs from browser</span>';
  return h;
}

function renderBots(){
  const data = LAST;
  const rb = data.robots;
  $('#robotsLine').innerHTML = rb.status === 200
    ? `robots.txt found at <a href="${esc(rb.url)}" target="_blank" rel="noopener">${esc(rb.url)}</a>.`
    : `robots.txt returned ${esc(rb.status ?? rb.error)}; treated as ${rb.status === 401 || rb.status === 403 ? 'blocking all bots' : 'allowing all bots'}.`;
  const base = data.results.find(r => r.id === 'browser');
  const rows = data.results.map(r => {
    const ci = counterInfo(r);
    let diff = '';
    if (base && base.words && r.id !== 'browser'){
      const pct = Math.round((r.words - base.words) / base.words * 100);
      diff = pct === 0 ? '<span class="chip ok">same</span>' : `<span class="chip ${Math.abs(pct) > 10 ? 'bad' : 'warn'}">${pct > 0 ? '+' : ''}${pct}%</span>`;
    }
    return `<tr>
      <td><strong>${esc(r.label)}</strong></td>
      <td>${statusChip(r)}</td>
      <td>${robotsChip(r)}</td>
      <td class="num">${r.ms ?? '–'} ms</td>
      <td class="num">${(r.bytes/1024).toFixed(0)} KB</td>
      <td class="num">${r.words.toLocaleString()}</td>
      <td>${diff}</td>
      <td class="counters">${ci.html}${ci.bad ? ` <span class="chip bad">${ci.bad} not final</span>` : ''}</td>
      <td>${schemaChip(r, base)}</td>
    </tr>`;
  }).join('');
  $('#summary').innerHTML = `<thead><tr><th>Bot</th><th>HTTP</th><th>robots.txt</th><th>Time</th><th>Size</th><th>Words</th><th>vs browser</th><th>Animated counters</th><th>Schema</th></tr></thead><tbody>${rows}</tbody>`;

  $('#details').innerHTML = data.results.map(r => {
    const heads = r.headings.length
      ? `<ul class="heads">${r.headings.map(h => `<li><span>${h.level}</span>${esc(h.text)}</li>`).join('')}</ul>`
      : '<div class="note">No H1–H3 headings found.</div>';
    const counters = r.counters.length
      ? `<div class="tablewrap"><table><thead><tr><th>Shown in HTML</th><th>Final (data-to-value)</th><th>Start (data-from-value)</th></tr></thead><tbody>${
          r.counters.map(c => `<tr><td>${esc(c.shown)}</td><td>${esc(c.to)}</td><td>${esc(c.from)}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="note">No animated counters detected.</div>';
    return `<details class="bot">
      <summary>${esc(r.label)} ${statusChip(r)} <span class="note" style="margin:0;font-weight:400">${r.words.toLocaleString()} words</span></summary>
      <div class="dbody">
        ${r.error ? `<p class="chip bad">${esc(r.error)}</p>` : ''}
        <dl class="kv">
          <dt>User agent</dt><dd>${esc(r.ua)}</dd>
          <dt>Final URL</dt><dd>${esc(r.final_url)}</dd>
          <dt>Title</dt><dd>${esc(r.title) || '<span class="chip bad">missing</span>'}</dd>
          <dt>Meta description</dt><dd>${esc(r.meta.description) || '<span class="chip warn">missing</span>'}</dd>
          <dt>Meta robots</dt><dd>${esc(r.meta.robots) || '–'}</dd>
          <dt>X-Robots-Tag</dt><dd>${esc(r.x_robots_tag) || '–'}</dd>
          <dt>Canonical</dt><dd>${esc(r.canonical) || '–'}</dd>
          <dt>Links / images</dt><dd>${r.links} links, ${r.images} images (${r.images_no_alt} without alt)</dd>
          <dt>Server / cache</dt><dd>${esc(r.server) || '–'}${r.cf_cache ? ' / Cloudflare ' + esc(r.cf_cache) : ''}</dd>
          ${r.insecure_ssl ? '<dt>SSL</dt><dd><span class="chip warn">Certificate could not be verified</span></dd>' : ''}
        </dl>
        <div class="subhead">Headings</div>${heads}
        <div class="subhead">Animated counters</div>${counters}
        <div class="subhead">Text this bot can read <a class="links" style="font-weight:400" data-copy="${esc(r.id)}">Copy text</a></div>
        <pre class="text">${esc(r.text) || '(no readable text)'}</pre>
      </div></details>`;
  }).join('');
  $$('[data-copy]').forEach(a => a.onclick = (e) => {
    e.preventDefault();
    const r = LAST.results.find(x => x.id === a.dataset.copy);
    navigator.clipboard.writeText(r.text).then(() => { a.textContent = 'Copied'; setTimeout(() => a.textContent = 'Copy text', 1500); });
  });
}

/* ---------------------------------------------------------------- structured data */
const LEVEL = {error: ['bad', 'Error'], warning: ['warn', 'Warning'], suggestion: ['na', 'Suggestion']};
function setupSchema(){
  const ss = $('#schemaBot'); const prev = ss.value;
  ss.innerHTML = LAST.results.map(r => `<option value="${r.id}">${esc(r.label)}</option>`).join('');
  ss.value = LAST.results.some(r => r.id === prev) ? prev : (LAST.results.some(r => r.id === 'gptbot') ? 'gptbot' : 'browser');
  renderSchema();
}
function renderSchema(){
  if (!LAST) return;
  const r = LAST.results.find(x => x.id === $('#schemaBot').value) || LAST.results[0];
  const s = r && r.structured;
  if (!s){ $('#schemaBody').innerHTML = '<div class="note" style="margin:0">This bot received no page content, so there is nothing to check.</div>'; return; }
  const c = s.counts;
  let h = `<div class="chips">
    <span class="chip ${s.items.length ? 'ok' : 'bad'}">${plural(s.items.length, 'item')} in ${plural(s.blocks, 'JSON-LD block')}</span>
    <span class="chip ${c.error ? 'bad' : 'ok'}">${plural(c.error, 'error')}</span>
    <span class="chip ${c.warning ? 'warn' : 'ok'}">${plural(c.warning, 'warning')}</span>
    <span class="chip na">${plural(c.suggestion, 'suggestion')}</span></div>`;
  if (s.types.length) h += `<div class="note" style="margin:0 0 6px">Types: ${s.types.map(esc).join(', ')}</div>`;
  if (s.microdata_types.length) h += `<div class="note" style="margin:0 0 6px">Microdata also found (listed only, not checked): ${s.microdata_types.map(esc).join(', ')}</div>`;
  if (s.error) h += `<p class="chip bad">Check failed: ${esc(s.error)}</p>`;
  if (s.facts.length){
    h += `<div class="subhead">What AI tools can read from your structured data</div><dl class="kv">${
      s.facts.map(f => `<dt>${esc(f.label)}</dt><dd>${esc(f.value)} <span class="note" style="margin:0">${esc(f.source)}</span></dd>`).join('')}</dl>`;
  }
  if (s.issues.length){
    h += `<div class="subhead">Findings</div><ul class="issues">${s.issues.map(i =>
      `<li><span class="chip ${LEVEL[i.level][0]}">${LEVEL[i.level][1]}</span><span>${esc(i.msg)}<span class="where">${esc(i.where)}</span></span></li>`).join('')}</ul>`;
  } else {
    h += '<div class="note">No problems found.</div>';
  }
  if (s.items.length){
    h += `<div class="subhead">Items</div><div class="tablewrap"><table><thead><tr><th>Type</th><th>Key properties present</th><th>Missing required</th><th>Could add</th></tr></thead><tbody>${
      s.items.map(it => `<tr><td><strong>${esc(it.types.join(' / '))}</strong> <span class="note" style="margin:0">${esc(it.id)}</span></td>
        <td>${it.present.length ? esc(it.present.join(', ')) : (it.family ? '–' : `<span class="note" style="margin:0">${it.props} properties (type not checked in detail)</span>`)}</td>
        <td>${it.missing_required.length ? `<span class="chip bad">${esc(it.missing_required.join(', '))}</span>` : '–'}</td>
        <td>${it.missing_recommended.length ? esc(it.missing_recommended.join(', ')) : '–'}</td></tr>`).join('')}</tbody></table></div>`;
  }
  if (s.suggested){
    h += `<div class="subhead">Suggested starting point <a class="links" style="font-weight:400" id="copySuggested">Copy</a></div>
      <div class="note" style="margin:0 0 4px">An Organization item built from this page. Replace the REPLACE values, and for a local service company use a LocalBusiness type such as HVACBusiness with a full address. Add it site-wide, for example in your SEO plugin's schema settings.</div>
      <pre class="text" id="suggestedJson">${esc(s.suggested)}</pre>`;
  }
  if (s.jsonld.length){
    h += `<details class="bot"><summary>Raw JSON-LD</summary><div class="dbody"><pre class="text">${esc(JSON.stringify(s.jsonld, null, 2))}</pre></div></details>`;
  }
  $('#schemaBody').innerHTML = h;
  const cp = $('#copySuggested');
  if (cp) cp.onclick = () => navigator.clipboard.writeText(s.suggested).then(() => { cp.textContent = 'Copied'; setTimeout(() => cp.textContent = 'Copy', 1500); });
}
$('#schemaBot').onchange = renderSchema;

/* ---------------------------------------------------------------- AI test */
function setupAI(){
  const sel = $('#viewBot'); const prev = sel.value;
  sel.innerHTML = LAST.results.filter(r => r.text).map(r => `<option value="${r.id}">${esc(r.label)} (${r.words.toLocaleString()} words)</option>`).join('');
  sel.value = LAST.results.some(r => r.id === prev && r.text) ? prev : (LAST.results.find(r => r.id === 'gptbot' && r.text) ? 'gptbot' : sel.options[0]?.value);
}
document.querySelectorAll('[data-q]').forEach(a => a.onclick = () => $('#question').value = QUESTIONS[a.dataset.q]);

function aiMode(){ return ($$('input[name=aimode]').find(r => r.checked) || {}).value || 'text'; }
function applyMode(){
  const m = aiMode();
  $('#textOpts').classList.toggle('hidden', m !== 'text');
  $('#fetchOpts').classList.toggle('hidden', m !== 'fetch');
  store('abvc_aimode', m);
}
$$('input[name=aimode]').forEach(r => r.onchange = applyMode);
$('#engine').onchange = () => store('abvc_engine', $('#engine').value);

$('#askBtn').onclick = async () => {
  if (!LAST){ $('#askStatus').textContent = 'Check a page first.'; return; }
  const key = $('#onceKey').value.trim();
  if (!key && SETTINGS.key_source === 'none'){ $('#askStatus').innerHTML = 'Add an OpenRouter key first, in <a class="links" href="#/settings">Settings</a>.'; return; }
  const models = $$('.model-cb:checked').map(c => c.value);
  if (!models.length){ $('#askStatus').textContent = 'Pick at least one model.'; return; }
  const mode = aiMode();
  const engine = $('#engine').value;
  const question = $('#question').value.trim() || QUESTIONS.numbers;
  let payload;
  if (mode === 'fetch'){
    payload = {key, url: LAST.url, question, mode: 'fetch', engine};
  } else {
    const view = LAST.results.find(r => r.id === $('#viewBot').value);
    if (!view){ $('#askStatus').textContent = 'Pick a bot view that has readable text.'; return; }
    let text = view.text;
    if ($('#incSchema').checked && view.structured && view.structured.jsonld.length)
      text += '\n\nSTRUCTURED DATA (JSON-LD) IN THE PAGE:\n' + JSON.stringify(view.structured.jsonld).slice(0, 15000);
    payload = {key, bot: view.label, url: LAST.url, text, question, mode: 'text'};
  }
  $('#askBtn').disabled = true;
  let done = 0;
  $('#askStatus').textContent = mode === 'fetch'
    ? `Asking ${plural(models.length, 'model')} to fetch the page with the ${engine} engine…`
    : `Asking ${plural(models.length, 'model')} using the ${payload.bot} view…`;
  $('#answers').innerHTML = models.map((m, i) =>
    `<div class="answer" id="ans${i}"><h3>${esc(m)}</h3><div class="meta">Waiting for answer…</div><div class="body"></div></div>`).join('');
  await Promise.all(models.map(async (model, i) => {
    const card = $('#ans' + i);
    try{
      const r = await post('/api/ask', {...payload, model});
      if (r.error){ card.classList.add('err'); card.querySelector('.meta').textContent = 'Failed'; card.querySelector('.body').textContent = r.error; }
      else{
        const tok = r.usage && r.usage.total_tokens ? `, ${r.usage.total_tokens.toLocaleString()} tokens` : '';
        let fetchInfo = '';
        let fetchCount = 0;
        if (r.mode === 'fetch'){
          const stu = (r.usage && r.usage.server_tool_use) || {};
          fetchCount = Object.entries(stu).filter(([k]) => k.includes('fetch')).reduce((a, [, v]) => a + (Number(v) || 0), 0);
          fetchInfo = `, ${r.engine} engine, ${fetchCount ? `${fetchCount} page ${fetchCount === 1 ? 'fetch' : 'fetches'} recorded by OpenRouter` : 'no fetch recorded'}`;
        }
        card.querySelector('.meta').textContent = `${(r.ms/1000).toFixed(1)} s${tok}${r.truncated ? ', page text truncated' : ''}${fetchInfo}`;
        card.querySelector('.body').textContent = r.answer;
        if (r.mode === 'fetch' && !fetchCount)
          card.insertAdjacentHTML('beforeend', '<div class="warnline">OpenRouter recorded no page fetch for this answer, so the model may have answered without reading your page.</div>');
      }
    }catch(e){ card.classList.add('err'); card.querySelector('.meta').textContent = 'Failed'; card.querySelector('.body').textContent = e.message; }
    done++; $('#askStatus').textContent = `${done} of ${models.length} answered.`;
  }));
  $('#askBtn').disabled = false;
};

/* ---------------------------------------------------------------- site scan */
const ISSUE_LABELS = {fetch: 'Fetch failed', blocked: 'Bot challenge page', http: 'HTTP error', robots: 'Blocked by robots.txt',
  counters: 'Counters at starting value', noindex: 'Noindex', thin: 'Little readable text', title: 'No title',
  description: 'No meta description', schema: 'No structured data', schema_errors: 'Structured data errors', redirect: 'Redirects'};
const LEVEL_CHIP = {error: 'bad', warning: 'warn', info: 'na', ok: 'ok'};
let SCAN = null, scanTimer = null, scanLevel = 'all', scanCode = '';

$('#scanBtn').onclick = startScan;
$('#scanUrl').addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
$('#scanBot').onchange = () => store('abvc_scan_bot', $('#scanBot').value);
$('#stopBtn').onclick = async () => {
  if (!SCAN) return;
  try{ await post('/api/scan/stop', {id: SCAN.id}); }catch(e){}
  $('#scanStatus').textContent = 'Stopping after the pages in progress…';
};
$('#scanHistory').onchange = () => { const id = $('#scanHistory').value; if (id) pollScan(id); };
$('#scanFilter').oninput = renderScanTable;
$$('#scanLevels button').forEach(b => b.onclick = () => {
  scanLevel = b.dataset.level;
  $$('#scanLevels button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  renderScanTable();
});
$('#scanCsv').onclick = downloadCsv;

async function startScan(){
  const url = $('#scanUrl').value.trim();
  if (!url){ $('#scanStatus').textContent = 'Enter a site or sitemap URL.'; return; }
  store('abvc_scan_url', url);
  $('#scanBtn').disabled = true;
  $('#scanStatus').textContent = 'Starting…';
  try{
    const d = await post('/api/scan/start', {url, bot: $('#scanBot').value, limit: Number($('#scanLimit').value)});
    if (d.error){ $('#scanStatus').textContent = d.error; $('#scanBtn').disabled = false; return; }
    scanLevel = 'all'; scanCode = ''; $('#scanFilter').value = '';
    $$('#scanLevels button').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.level === 'all')));
    pollScan(d.id);
  }catch(e){ $('#scanStatus').textContent = 'Could not start the scan: ' + e.message; $('#scanBtn').disabled = false; }
}

async function pollScan(id){
  clearTimeout(scanTimer);
  try{
    const d = await api('/api/scan/status?id=' + encodeURIComponent(id));
    if (d.error){ $('#scanStatus').textContent = d.error; $('#scanBtn').disabled = false; return; }
    SCAN = d; store('abvc_scan', id);
    renderScan();
    if (d.status === 'running') scanTimer = setTimeout(() => pollScan(id), 1500);
    else loadScanHistory();
  }catch(e){
    $('#scanStatus').textContent = 'Lost contact with the scan, retrying… (' + e.message + ')';
    scanTimer = setTimeout(() => pollScan(id), 4000);
  }
}

function renderScan(){
  const d = SCAN;
  const running = d.status === 'running';
  $('#scanBtn').disabled = running;
  $('#stopBtn').classList.toggle('hidden', !running);
  $('#scanProgress').classList.toggle('hidden', !running);
  $('#scanBar').style.width = d.total ? `${Math.round(d.done / d.total * 100)}%` : '6%';
  const src = d.source === 'links' ? 'links on the start page (no sitemap found)' : 'the sitemap';
  const limited = d.found > d.total ? ` The sitemap lists ${d.found} pages; this scan covers the first ${d.total}.` : '';
  let msg;
  if (d.status === 'failed') msg = `Scan failed: ${d.error}`;
  else if (running && d.phase === 'discovering') msg = `Reading the sitemap for ${d.url}…`;
  else if (running) msg = `Checking as ${d.bot_label}: ${d.done} of ${d.total} pages from ${src}.${limited}`;
  else msg = `${d.status === 'stopped' ? 'Stopped' : 'Finished'}: ${d.done} of ${d.total} pages from ${src}, checked as ${d.bot_label} on ${d.started_at}.${limited}`;
  $('#scanStatus').textContent = msg;
  if (!$('#scanUrl').value) $('#scanUrl').value = d.url;
  $('#scanResults').classList.toggle('hidden', !d.results.length);
  if (!d.results.length) return;

  const by = {error: 0, warning: 0, ok: 0};
  d.results.forEach(r => { by[r.level] = (by[r.level] || 0) + 1; });
  $('#scanSummary').innerHTML = `<span class="chip ${by.error ? 'bad' : 'ok'}">${plural(by.error, 'page')} with errors</span>
    <span class="chip ${by.warning ? 'warn' : 'ok'}">${plural(by.warning, 'page')} with warnings</span>
    <span class="chip ok">${plural(by.ok, 'page')} OK</span>`;
  const codes = {};
  d.results.forEach(r => r.issues.forEach(i => { codes[i.code] = codes[i.code] || {n: 0, level: i.level}; codes[i.code].n++; }));
  const order = {error: 0, warning: 1, info: 2};
  const entries = Object.entries(codes).sort((a, b) => order[a[1].level] - order[b[1].level] || b[1].n - a[1].n);
  $('#scanIssueTotals').innerHTML = entries.length
    ? entries.map(([code, v]) => `<button class="chip ${LEVEL_CHIP[v.level]}${scanCode === code ? ' active' : ''}" data-code="${esc(code)}">${esc(ISSUE_LABELS[code] || code)}: ${v.n}</button>`).join('')
    : '<span class="note" style="margin:0">No issues found.</span>';
  $$('#scanIssueTotals [data-code]').forEach(b => b.onclick = () => { scanCode = scanCode === b.dataset.code ? '' : b.dataset.code; renderScan(); });
  renderScanTable();
}

function scanRows(){
  const q = $('#scanFilter').value.trim().toLowerCase();
  const rank = {error: 0, warning: 1, ok: 2};
  return (SCAN ? SCAN.results : []).filter(r =>
      (scanLevel === 'all' || r.level === scanLevel) &&
      (!scanCode || r.issues.some(i => i.code === scanCode)) &&
      (!q || r.url.toLowerCase().includes(q) || (r.title || '').toLowerCase().includes(q)))
    .sort((a, b) => rank[a.level] - rank[b.level] || a.url.localeCompare(b.url));
}
function pathOf(u){ try{ const x = new URL(u); return (x.pathname + x.search) || '/'; }catch(e){ return u; } }

function renderScanTable(){
  if (!SCAN) return;
  const rows = scanRows();
  $('#scanCount').textContent = `Showing ${rows.length} of ${plural(SCAN.results.length, 'page')}${scanCode ? `, only "${ISSUE_LABELS[scanCode] || scanCode}"` : ''}.`;
  if (!rows.length){ $('#scanTable').innerHTML = '<tbody><tr><td class="note">No pages match these filters.</td></tr></tbody>'; return; }
  $('#scanTable').innerHTML = `<thead><tr><th>Page</th><th>HTTP</th><th>Words</th><th>Counters</th><th>Schema</th><th>Issues</th><th></th></tr></thead><tbody>${
    rows.map(r => `<tr>
      <td class="pagecell"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(pathOf(r.url))}</a><span>${esc(r.title)}</span></td>
      <td>${r.status ? `<span class="chip ${r.status < 300 ? 'ok' : r.status < 400 ? 'warn' : 'bad'}">${r.status}</span>` : '<span class="chip bad">–</span>'}</td>
      <td class="num">${(r.words || 0).toLocaleString()}</td>
      <td>${!r.counters ? '–' : r.counters_bad ? `<span class="chip bad">${r.counters_bad} of ${r.counters} at start</span>` : `<span class="chip ok">${r.counters} OK</span>`}</td>
      <td>${r.schema_items ? `<span class="chip ${r.schema_errors ? 'warn' : 'ok'}">${plural(r.schema_items, 'item')}</span>` : (r.status && r.status < 400 ? '<span class="chip bad">none</span>' : '–')}</td>
      <td>${r.issues.length ? r.issues.map(i => `<span class="issue"><span class="dot ${LEVEL_CHIP[i.level]}"></span><span>${esc(i.msg)}</span></span>`).join('') : '<span class="chip ok">OK</span>'}</td>
      <td><a class="links" data-inspect="${esc(r.url)}">Inspect</a></td>
    </tr>`).join('')}</tbody>`;
  $$('[data-inspect]').forEach(a => a.onclick = () => { $('#url').value = a.dataset.inspect; location.hash = '#/bots'; runCheck(); });
}

function downloadCsv(){
  if (!SCAN) return;
  const cols = ['url', 'final_url', 'status', 'words', 'counters', 'counters_at_start', 'schema_items', 'schema_errors', 'level', 'issues'];
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [cols.join(',')].concat(scanRows().map(r => [r.url, r.final_url, r.status, r.words, r.counters, r.counters_bad,
    r.schema_items, r.schema_errors, r.level, r.issues.map(i => i.msg).join('; ')].map(q).join(',')));
  const blob = new Blob(['\ufeff' + lines.join('\r\n')], {type: 'text/csv;charset=utf-8'});
  let host = 'site'; try{ host = new URL(SCAN.url).hostname; }catch(e){}
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan-${host}-${(SCAN.started_at || '').slice(0, 10)}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function loadScanHistory(){
  try{
    const d = await api('/api/scan/list');
    const cur = SCAN ? SCAN.id : '';
    const items = d.scans || [];
    $('#scanHistory').innerHTML = (items.length ? '<option value="">Choose a scan…</option>' : '<option value="">None yet</option>') + items.map(s => {
      let host = s.url; try{ host = new URL(s.url).hostname; }catch(e){}
      return `<option value="${esc(s.id)}" ${s.id === cur ? 'selected' : ''}>${esc(host)}, ${esc((s.started_at || '').slice(0, 16))}, ${s.done} of ${s.total} pages${s.status === 'running' ? ' (running)' : ''}</option>`;
    }).join('');
  }catch(e){}
}

/* ---------------------------------------------------------------- AI access */
let ACCESS = null;
const VERDICT = {allowed: ['ok', 'Allowed'], blocked_robots: ['bad', 'Blocked by robots.txt'], blocked_server: ['bad', 'Blocked by server']};
$('#accessBtn').onclick = runAccess;
$('#accessUrl').addEventListener('keydown', e => { if (e.key === 'Enter') runAccess(); });
$('#copyRobots').onclick = () => navigator.clipboard.writeText($('#robotsOut').textContent).then(() => {
  $('#copyRobots').textContent = 'Copied'; setTimeout(() => $('#copyRobots').textContent = 'Copy', 1500); });

async function runAccess(){
  const url = $('#accessUrl').value.trim();
  if (!url){ $('#accessStatus').textContent = 'Enter a page or site URL.'; return; }
  store('abvc_access_url', url);
  $('#accessBtn').disabled = true;
  $('#accessStatus').textContent = 'Reading robots.txt and testing each crawler…';
  try{
    const d = await post('/api/access', {url});
    if (d.error){ $('#accessStatus').textContent = d.error; return; }
    ACCESS = d; renderAccess();
    $('#accessStatus').textContent = `Checked ${d.url} at ${d.checked_at}.`;
  }catch(e){ $('#accessStatus').textContent = 'Check failed: ' + e.message; }
  finally{ $('#accessBtn').disabled = false; }
}
function liveChip(l){
  if (l.error) return `<span class="chip bad" title="${esc(l.error)}">Failed</span>`;
  if (l.challenge) return `<span class="chip bad">${l.status} challenge</span>`;
  return `<span class="chip ${l.status < 300 ? 'ok' : l.status < 400 ? 'warn' : 'bad'}">${l.status}</span>`;
}
function renderAccess(){
  const d = ACCESS;
  $('#accessResults').classList.remove('hidden');
  const n = k => d.agents.filter(a => a.verdict === k).length;
  $('#accessSummary').innerHTML = `<span class="chip ${n('allowed') ? 'ok' : 'na'}">${n('allowed')} allowed</span>
    <span class="chip ${n('blocked_robots') ? 'bad' : 'ok'}">${n('blocked_robots')} blocked by robots.txt</span>
    <span class="chip ${n('blocked_server') ? 'bad' : 'ok'}">${n('blocked_server')} blocked by the server</span>`;
  const notes = [];
  notes.push(d.robots.status === 200
    ? `robots.txt found at <a href="${esc(d.robots.url)}" target="_blank" rel="noopener">${esc(d.robots.url)}</a>.`
    : `No robots.txt (${esc(d.robots.status ?? d.robots.error)}), so robots rules allow every crawler.`);
  if (d.browser_error || (d.browser_status || 0) >= 400)
    notes.push(`A normal browser request also failed (${esc(d.browser_error || 'HTTP ' + d.browser_status)}), so a block may not be specific to AI crawlers.`);
  if (d.page_robots) notes.push(`This page's robots instructions: ${esc(d.page_robots)}.`);
  $('#accessNotes').innerHTML = notes.join(' ');
  $('#accessTable').innerHTML = `<thead><tr><th>Crawler</th><th>Used for</th><th>robots.txt</th><th>Live test</th><th>Result</th><th>Your choice</th></tr></thead><tbody>${
    d.agents.map(a => `<tr>
      <td><strong>${esc(a.token)}</strong><span class="sub">${esc(a.company)}</span></td>
      <td>${esc(a.purpose)}</td>
      <td>${a.robots_allowed === false ? '<span class="chip bad">Disallowed</span>' : a.robots_allowed ? '<span class="chip ok">Allowed</span>' : '<span class="chip na">–</span>'}</td>
      <td>${a.live ? liveChip(a.live) : '<span class="note" style="margin:0">rule only</span>'}</td>
      <td><span class="chip ${VERDICT[a.verdict][0]}">${VERDICT[a.verdict][1]}</span></td>
      <td><select class="acc-choice" data-token="${esc(a.token)}" aria-label="Rule for ${esc(a.token)}">
        <option value="allow" ${a.robots_allowed === false ? '' : 'selected'}>Allow</option>
        <option value="block" ${a.robots_allowed === false ? 'selected' : ''}>Block</option></select></td>
    </tr>`).join('')}</tbody>`;
  $$('.acc-choice').forEach(s => s.onchange = renderRobots);
  $('#robotsCurrent').textContent = d.robots.status === 200 ? (d.robots.text || '(empty file)') : '(no robots.txt file)';
  renderRobots();
}

const GEN_MARK = '# AI crawlers: generated by AI Bot View Checker';
function buildRobots(){
  const text = ACCESS.robots.status === 200 ? (ACCESS.robots.text || '') : '';
  const choices = $$('.acc-choice').map(s => ({token: s.dataset.token, block: s.value === 'block'}));
  const ai = new Set(choices.map(c => c.token.toLowerCase()));
  const pre = [], groups = [], sitemaps = [];
  let cur = null, inAgents = false;
  for (const raw of text.replace(/\r/g, '').split('\n')){
    const t = raw.trim();
    if (t === GEN_MARK || t.startsWith('# All listed AI crawlers follow')) continue;
    const m = t.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    const key = m ? m[1].toLowerCase() : '';
    if (key === 'sitemap'){ sitemaps.push(t); continue; }
    if (key === 'user-agent'){
      if (!cur || !inAgents){ cur = {agents: [], rules: []}; groups.push(cur); }
      cur.agents.push(m[2].split('#')[0].trim()); inAgents = true; continue;
    }
    if (!cur){ if (t || pre.length) pre.push(raw); continue; }
    if (t) inAgents = false;
    cur.rules.push(raw);
  }
  const trim = arr => { const a = arr.slice(); while (a.length && !a[a.length - 1].trim()) a.pop(); return a; };
  const kept = groups.map(g => ({agents: g.agents.filter(a => !ai.has(a.toLowerCase())), rules: trim(g.rules)})).filter(g => g.agents.length);
  const star = kept.find(g => g.agents.includes('*'));
  const starBlocksAll = !!star && star.rules.some(r => /^\s*disallow\s*:\s*\/\s*$/i.test(r));
  const blocked = choices.filter(c => c.block).map(c => c.token);
  const allowed = choices.filter(c => !c.block).map(c => c.token);
  const out = [];
  const p = trim(pre); if (p.length) out.push(...p, '');
  if (!kept.length) out.push('User-agent: *', 'Disallow:', '');
  kept.forEach(g => out.push(...g.agents.map(a => `User-agent: ${a}`), ...g.rules, ''));
  out.push(GEN_MARK);
  if (blocked.length) out.push(...blocked.map(t => `User-agent: ${t}`), 'Disallow: /', '');
  if (allowed.length && starBlocksAll) out.push(...allowed.map(t => `User-agent: ${t}`), 'Allow: /', '');
  if (!blocked.length && !(allowed.length && starBlocksAll)) out.push('# All listed AI crawlers follow the rules for all crawlers above.', '');
  out.push(...sitemaps);
  return out.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}
function renderRobots(){ $('#robotsOut').textContent = buildRobots(); }

/* ---------------------------------------------------------------- llms.txt */
let LLMS = null;
$('#llmsBtn').onclick = runLlms;
$('#llmsGenBtn').onclick = runLlmsGen;
$('#llmsUrl').addEventListener('keydown', e => { if (e.key === 'Enter') runLlms(); });
$('#llmsCopy').onclick = () => navigator.clipboard.writeText($('#llmsText').value).then(() => {
  $('#llmsCopy').textContent = 'Copied'; setTimeout(() => $('#llmsCopy').textContent = 'Copy', 1500); });
$('#llmsDownload').onclick = () => {
  const blob = new Blob([$('#llmsText').value], {type: 'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'llms.txt';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

async function runLlms(){
  const url = $('#llmsUrl').value.trim();
  if (!url){ $('#llmsStatus').textContent = 'Enter a site URL.'; return; }
  store('abvc_llms_url', url);
  $('#llmsBtn').disabled = true;
  $('#llmsStatus').textContent = 'Looking for llms.txt and checking its links…';
  try{
    const d = await post('/api/llms', {url});
    if (d.error){ $('#llmsStatus').textContent = d.error; return; }
    LLMS = d; renderLlms();
    $('#llmsStatus').textContent = `Checked ${d.origin} at ${d.checked_at}.`;
  }catch(e){ $('#llmsStatus').textContent = 'Check failed: ' + e.message; }
  finally{ $('#llmsBtn').disabled = false; }
}
function renderLlms(){
  const d = LLMS;
  $('#llmsResults').classList.remove('hidden');
  $('#llmsFiles').innerHTML = d.files.map(f => `<div class="filerow"><strong>/${esc(f.name)}</strong>
    ${f.exists
      ? `<span class="chip ok">Found</span><span class="note">${(f.bytes / 1024).toFixed(1)} KB, ${esc(f.content_type || 'no content type')}</span><a class="links" href="${esc(f.url)}" target="_blank" rel="noopener">Open</a>`
      : `<span class="chip ${f.name === 'llms.txt' ? 'warn' : 'na'}">Not found</span><span class="note">${esc(f.note || f.error || 'HTTP ' + f.status)}</span>`}
    </div>`).join('');
  $('#llmsIssues').innerHTML = d.issues.length
    ? d.issues.map(i => `<li><span class="chip ${LEVEL[i.level][0]}">${LEVEL[i.level][1]}</span><span>${esc(i.msg)}</span></li>`).join('')
    : '<li><span class="chip ok">OK</span><span>No problems found.</span></li>';
  if (d.links.length){
    $('#llmsLinks').innerHTML = `<div class="subhead">Links (${d.links.length} in ${plural(d.sections.length, 'section')})</div><div class="tablewrap"><table><thead><tr><th>Section</th><th>Link</th><th>Description</th><th>Status</th></tr></thead><tbody>${
      d.links.map(l => `<tr><td>${esc(l.section) || '–'}</td>
        <td><a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a><span class="sub">${esc(l.url)}</span></td>
        <td>${esc(l.notes) || '–'}</td>
        <td>${l.status === undefined && !l.error ? '<span class="chip na">not checked</span>' : l.error || (l.status || 0) >= 400 ? `<span class="chip bad" title="${esc(l.error || '')}">${l.status || 'Failed'}</span>` : `<span class="chip ok">${l.status}</span>`}</td></tr>`).join('')}</tbody></table></div>`;
  } else $('#llmsLinks').innerHTML = '';
}
async function runLlmsGen(){
  const url = $('#llmsUrl').value.trim();
  if (!url){ $('#llmsStatus').textContent = 'Enter a site URL.'; return; }
  store('abvc_llms_url', url);
  $('#llmsGenBtn').disabled = true;
  $('#llmsStatus').textContent = 'Reading the sitemap and up to 40 pages. This can take a minute…';
  try{
    const d = await post('/api/llms/generate', {url});
    if (d.error){ $('#llmsStatus').textContent = d.error; return; }
    $('#llmsDraft').classList.remove('hidden');
    $('#llmsText').value = d.markdown;
    $('#llmsDraftNote').textContent = `Built from ${plural(d.pages, 'page')} found through ${d.source === 'links' ? 'links on the homepage' : 'the sitemap'}, using each page's title and meta description. Pages marked noindex and category or tag pages are left out; blog posts go under “Optional”. Review it before publishing.`;
    $('#llmsStatus').textContent = 'Draft ready below.';
    $('#llmsDraft').scrollIntoView({behavior: 'smooth', block: 'start'});
  }catch(e){ $('#llmsStatus').textContent = 'Could not draft the file: ' + e.message; }
  finally{ $('#llmsGenBtn').disabled = false; }
}

/* ---------------------------------------------------------------- start */
async function init(){
  route();
  $('#url').value = load('abvc_url') || '';
  const savedMode = load('abvc_aimode');
  if (savedMode) $$('input[name=aimode]').forEach(r => r.checked = r.value === savedMode);
  if (load('abvc_engine')) $('#engine').value = load('abvc_engine');
  applyMode();
  try{
    const saved = sessionStorage.getItem('abvc_last');
    if (saved){ LAST = JSON.parse(saved); renderAll(); }
  }catch(e){ LAST = null; }
  const [bots, s] = await Promise.all([api('/api/bots'), api('/api/settings')]);
  $('#bots').innerHTML = bots.filter(b => b.id !== 'browser').map(b =>
    `<label><input type="checkbox" class="bot-cb" value="${b.id}" ${b.default ? 'checked' : ''}>
     <span>${esc(b.label)}<small>${esc(b.note)}</small></span></label>`).join('');
  $$('.bot-cb').forEach(c => c.onchange = updateBotSummary);
  updateBotSummary();
  $('#scanBot').innerHTML = bots.map(b => `<option value="${b.id}">${esc(b.label)}</option>`).join('');
  $('#scanBot').value = load('abvc_scan_bot') || 'gptbot';
  $('#scanUrl').value = load('abvc_scan_url') || '';
  loadScanHistory();
  const sid = load('abvc_scan');
  if (sid) pollScan(sid);
  const lastUrl = load('abvc_url') || load('abvc_scan_url') || '';
  $('#accessUrl').value = load('abvc_access_url') || lastUrl;
  $('#llmsUrl').value = load('abvc_llms_url') || lastUrl;
  $('#signout').classList.toggle('hidden', !s.auth);
  applySettings(s);
}
init();
