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
const PAGES = {projects: 'Projects', bots: 'Bot view', scan: 'Site scan', schema: 'Structured data', access: 'AI access', logs: 'Crawler visits', llms: 'llms.txt', ai: 'AI test', cite: 'AI citations', settings: 'Settings'};
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
  $('#checkbar').classList.toggle('hidden', ['settings', 'scan', 'access', 'llms', 'cite', 'projects', 'logs'].includes(p));
  const head = $('#page-' + p + ' .pagehead');
  if (head && head.nextElementSibling !== $('#checkbar')) head.after($('#checkbar'));
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
  renderCiteModels();
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
          const stu = Object.assign({}, (r.usage && r.usage.server_tool_use) || {}, (r.usage && r.usage.server_tool_use_details) || {});
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

/* ---------------------------------------------------------------- AI citations */
let CITE = null, citeTimer = null;
const CITE_FIELDS = ['citeDomain', 'citeBrand', 'citeComp', 'citePrompts', 'citeEngine', 'citeLocation'];
function renderCiteModels(){
  const box = $('#citeModels'); if (!box) return;
  const prev = new Set($$('.cite-model:checked').map(c => c.value));
  const list = currentModels();
  box.innerHTML = list.map((m, i) => `<label><input type="checkbox" class="cite-model" value="${esc(m)}" ${(prev.size ? prev.has(m) : i < 3) ? 'checked' : ''}> ${esc(m)}</label>`).join('');
  $$('.cite-model').forEach(c => c.onchange = citeEstimate);
  citeEstimate();
}
function citeLines(){ return $('#citePrompts').value.split('\n').map(s => s.trim()).filter(Boolean); }
function citeEstimate(){
  const q = Math.min(citeLines().length, 10), m = Math.min($$('.cite-model:checked').length, 6);
  $('#citeEstimate').textContent = q && m
    ? `This runs ${plural(q, 'question')} × ${plural(m, 'model')} = ${plural(q * m, 'answer')}. Each answer costs the model's usage plus its searches (roughly $0.005 to $0.02 per search with Exa, Parallel or Perplexity; Firecrawl costs more; native search is priced by the model provider). Each model may search up to 3 times per answer.`
    : 'Add questions and pick models to see how many answers this will run.';
}
CITE_FIELDS.forEach(id => $('#' + id).addEventListener('input', () => {
  const form = {}; CITE_FIELDS.forEach(f => form[f] = $('#' + f).value); store('abvc_cite_form', JSON.stringify(form)); citeEstimate();
}));
$('#citeBtn').onclick = startCite;
$('#citeStop').onclick = async () => {
  if (!CITE) return;
  try{ await post('/api/cite/stop', {id: CITE.id}); }catch(e){}
  $('#citeStatus').textContent = 'Stopping after the answers in progress…';
};
$('#citeHistory').onchange = () => { const id = $('#citeHistory').value; if (id) pollCite(id); };
$('#citeCsv').onclick = citeCsv;

async function startCite(){
  if (SETTINGS.key_source === 'none'){ $('#citeStatus').innerHTML = 'Add an OpenRouter key first, in <a class="links" href="#/settings">Settings</a>.'; return; }
  const prompts = citeLines();
  const models = $$('.cite-model:checked').map(c => c.value);
  if (!$('#citeDomain').value.trim()){ $('#citeStatus').textContent = "Enter your site's domain."; return; }
  if (!prompts.length){ $('#citeStatus').textContent = 'Add at least one question.'; return; }
  if (prompts.length > 10){ $('#citeStatus').textContent = 'Use up to 10 questions per test.'; return; }
  if (!models.length || models.length > 6){ $('#citeStatus').textContent = 'Pick between 1 and 6 models.'; return; }
  const loc = $('#citeLocation').value.split(',').map(s => s.trim());
  const location = loc[0] ? {city: loc[0] || '', region: loc[1] || '', country: loc[2] || ''} : null;
  $('#citeBtn').disabled = true;
  $('#citeStatus').textContent = 'Starting…';
  try{
    const d = await post('/api/cite/start', {domain: $('#citeDomain').value, brands: $('#citeBrand').value, competitors: $('#citeComp').value,
      prompts, models, engine: $('#citeEngine').value, location, sentiment: $('#citeSentiment').checked});
    if (d.error){ $('#citeStatus').textContent = d.error; $('#citeBtn').disabled = false; return; }
    pollCite(d.id);
  }catch(e){ $('#citeStatus').textContent = 'Could not start the test: ' + e.message; $('#citeBtn').disabled = false; }
}

async function pollCite(id){
  clearTimeout(citeTimer);
  try{
    const d = await api('/api/cite/status?id=' + encodeURIComponent(id));
    if (d.error){ $('#citeStatus').textContent = d.error; $('#citeBtn').disabled = false; return; }
    CITE = d; store('abvc_cite', id);
    renderCite();
    if (d.status === 'running') citeTimer = setTimeout(() => pollCite(id), 2500);
    else loadCiteHistory();
  }catch(e){
    $('#citeStatus').textContent = 'Lost contact with the test, retrying… (' + e.message + ')';
    citeTimer = setTimeout(() => pollCite(id), 5000);
  }
}

function hostOf(u){ try{ return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); }catch(e){ return ''; } }
function domMatch(h, d){ return !!h && !!d && (h === d || h.endsWith('.' + d)); }
function compDomains(){ return (CITE.results.find(r => r.competitors) || {competitors: []}).competitors.map(c => c.label); }
function citeStatusOf(r){
  if (r.error) return 'error';
  if (r.brand.cited) return 'cited';
  if (r.brand.mentioned) return 'mentioned';
  return 'none';
}
function citeChip(r){
  if (!r) return '<span class="chip na">…</span>';
  const s = citeStatusOf(r);
  if (s === 'error') return `<span class="chip bad" title="${esc(r.error)}">Error</span>`;
  if (s === 'cited') return `<span class="chip ok">Cited #${r.brand.rank}${r.brand.mentioned ? ' + named' : ''}</span>`;
  if (s === 'mentioned') return '<span class="chip warn">Named, not cited</span>';
  return '<span class="chip na">Not found</span>';
}

function renderCite(){
  const d = CITE;
  const running = d.status === 'running';
  $('#citeBtn').disabled = running;
  $('#citeStop').classList.toggle('hidden', !running);
  $('#citeProgress').classList.toggle('hidden', !running);
  $('#citeBar').style.width = d.total ? `${Math.round(d.done / d.total * 100)}%` : '5%';
  const engineNote = `${d.engine} search${d.location ? ', searching from ' + Object.values(d.location).join(', ') : ''}`;
  $('#citeStatus').textContent = d.status === 'failed' ? `Test failed: ${d.error}`
    : running ? `Asking: ${d.done} of ${d.total} answers done for ${d.domain} (${engineNote})…`
    : `${d.status === 'stopped' ? 'Stopped' : 'Finished'}: ${d.done} of ${d.total} answers for ${d.domain}, ${engineNote}, started ${d.started_at}.`;
  $('#citeResults').classList.toggle('hidden', !d.results.length);
  if (!d.results.length) return;

  const ok = d.results.filter(r => !r.error);
  const errors = d.results.length - ok.length;
  const cited = ok.filter(r => r.brand.cited), named = ok.filter(r => r.brand.mentioned);
  const pct = (n, t) => t ? Math.round(n / t * 100) + '%' : '–';
  const ranks = cited.map(r => r.brand.rank);
  const avg = ranks.length ? (ranks.reduce((a, b) => a + b, 0) / ranks.length).toFixed(1) : null;
  const noSearch = ok.filter(r => !r.searches && !(r.citations || []).length).length;
  const score = ok.length ? Math.round(ok.reduce((a, r) => a + answerScore(r), 0) / ok.length) : null;
  const rated = ok.filter(r => r.sentiment), pos = rated.filter(r => r.sentiment === 'positive').length, neg = rated.filter(r => r.sentiment === 'negative').length;
  $('#citeSummary').innerHTML = `
    ${score !== null ? `<span class="chip ${score >= 50 ? 'ok' : score >= 20 ? 'warn' : 'bad'}">Visibility score ${score}/100</span>` : ''}
    ${rated.length ? `<span class="chip ${neg ? 'warn' : 'ok'}">Described positively in ${pos} of ${rated.length}${neg ? `, negatively in ${neg}` : ''}</span>` : ''}
    <span class="chip ${cited.length ? 'ok' : 'bad'}">Cited in ${cited.length} of ${ok.length} answers (${pct(cited.length, ok.length)})</span>
    <span class="chip ${named.length ? 'ok' : 'warn'}">Named in ${named.length} of ${ok.length} (${pct(named.length, ok.length)})</span>
    ${avg ? `<span class="chip na">Average position when cited: #${avg}</span>` : ''}
    ${errors ? `<span class="chip bad">${plural(errors, 'answer')} failed</span>` : ''}
    ${noSearch ? `<span class="chip warn" title="No search or sources were recorded for these answers">${noSearch} answered without searching</span>` : ''}`;

  const rows = [{label: `${d.domain} (you)`, get: r => r.brand}].concat(
    compDomains().map((label, i) => ({label, get: r => (r.competitors || [])[i] || {}})));
  $('#citeSov').innerHTML = `<thead><tr><th>Brand</th><th>Named in answers</th><th>Cited as a source</th><th>Best position</th></tr></thead><tbody>${
    rows.map(row => {
      const st = ok.map(row.get);
      const n = st.filter(s => s.mentioned).length, c = st.filter(s => s.cited).length;
      const best = st.filter(s => s.rank).map(s => s.rank).sort((a, b) => a - b)[0];
      return `<tr><td><strong>${esc(row.label)}</strong></td><td>${n} (${pct(n, ok.length)})</td><td>${c} (${pct(c, ok.length)})</td><td>${best ? '#' + best : '–'}</td></tr>`;
    }).join('')}</tbody>`;

  const idx = new Map(d.results.map((r, i) => [r.prompt + '\u0000' + r.model, i]));
  $('#citeMatrix').innerHTML = `<thead><tr><th>Question</th>${d.models.map(m => `<th>${esc(m)}</th>`).join('')}</tr></thead><tbody>${
    d.prompts.map(p => `<tr><td>${esc(p)}</td>${d.models.map(m => {
      const i = idx.get(p + '\u0000' + m);
      return `<td>${i === undefined ? citeChip(null) : `<button class="cell" data-ans="${i}">${citeChip(d.results[i])}</button>`}</td>`;
    }).join('')}</tr>`).join('')}</tbody>`;
  $$('#citeMatrix [data-ans]').forEach(b => b.onclick = () => {
    const el = $('#cans-' + b.dataset.ans); if (!el) return;
    el.open = true; el.scrollIntoView({behavior: 'smooth', block: 'start'});
  });

  const pIdx = new Map(d.prompts.map((x, k) => [x, k])), mIdx = new Map(d.models.map((x, k) => [x, k]));
  const order = d.results.map((r, k) => k).sort((x, y) => (pIdx.get(d.results[x].prompt) - pIdx.get(d.results[y].prompt)) || (mIdx.get(d.results[x].model) - mIdx.get(d.results[y].model)));
  $('#citeAnswers').innerHTML = order.map(i => {
    const r = d.results[i];
    const srcs = (r.citations || []).length ? r.citations : (r.text_links || []).map(u => ({url: u, title: ''}));
    return `<details class="bot" id="cans-${i}">
      <summary><span>${esc(r.model)}</span>${citeChip(r)}<span class="note" style="margin:0;font-weight:400">${esc(r.prompt)}</span></summary>
      <div class="dbody">
        ${r.error ? `<p class="chip bad" style="white-space:normal">${esc(r.error)}</p>` : `
        <div class="note" style="margin:0 0 8px">${r.searches ? plural(r.searches, 'search') + ' recorded by OpenRouter' : 'No search recorded by OpenRouter'}, ${(r.ms / 1000).toFixed(1)} s${r.tokens ? ', ' + r.tokens.toLocaleString() + ' tokens' : ''}</div>
        ${r.sentiment ? `<div class="note" style="margin:0 0 8px"><span class="chip ${SENT[r.sentiment][0]}">Described ${SENT[r.sentiment][1]}</span> ${esc(r.sentiment_reason || '')}</div>` : ''}
        <div class="answertext">${highlightAnswer(r.answer, d) || '(empty answer)'}</div>
        <div class="subhead">Sources (${srcs.length})</div>
        ${srcs.length ? `<ol class="sources">${srcs.map(c => {
          const h = hostOf(c.url);
          const mine = domMatch(h, d.domain);
          const comp = !mine && (r.competitors || []).some(x => x.domain && domMatch(h, x.domain));
          return `<li class="${mine ? 'mine' : comp ? 'comp' : ''}"><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.title || c.url)}</a> <span class="sub" style="display:inline">${esc(h)}</span></li>`;
        }).join('')}</ol>` : '<div class="note" style="margin:0">No sources were returned.</div>'}`}
      </div></details>`;
  }).join('');
  renderCiteInsights();
  renderTrend();
}

function citeCsv(){
  if (!CITE) return;
  const comps = compDomains();
  const cols = ['question', 'model', 'result', 'cited_position', 'named', 'searches', 'score', 'sentiment', ...comps.map(c => `competitor: ${c}`), 'sources'];
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [cols.map(q).join(',')].concat(CITE.results.map(r => [r.prompt, r.model,
    r.error ? 'error: ' + r.error : citeStatusOf(r), r.brand && r.brand.rank || '', r.brand && r.brand.mentioned ? 'yes' : 'no', r.searches || 0,
    r.error ? '' : answerScore(r), r.sentiment || '',
    ...comps.map((c, i) => { const x = (r.competitors || [])[i]; return !x ? '' : x.cited ? `cited #${x.rank}` : x.mentioned ? 'named' : 'no'; }),
    (r.hosts || []).join(' ')].map(q).join(',')));
  const blob = new Blob(['\ufeff' + lines.join('\r\n')], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ai-citations-${CITE.domain}-${(CITE.started_at || '').slice(0, 10)}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function loadCiteHistory(){
  try{
    const d = await api('/api/cite/list');
    const cur = CITE ? CITE.id : '';
    const items = d.runs || [];
    CITE_RUNS = items; renderTrend();
    $('#citeHistory').innerHTML = (items.length ? '<option value="">Choose a test…</option>' : '<option value="">None yet</option>') + items.map(s =>
      `<option value="${esc(s.id)}" ${s.id === cur ? 'selected' : ''}>${esc(s.domain)}, ${esc((s.started_at || '').slice(0, 16))}, ${s.done} of ${s.total}${s.status === 'running' ? ' (running)' : ''}</option>`).join('');
  }catch(e){}
}

/* ---------------------------------------------------------------- projects */
let PROJECTS = [], PROJ_STORAGE = true, EDITING = null;
const splitList = v => v.split(',').map(s => s.trim()).filter(Boolean);

async function loadProjects(){
  try{
    const d = await api('/api/projects');
    PROJECTS = d.projects || [];
    PROJ_STORAGE = d.storage_ok !== false;
  }catch(e){ PROJECTS = []; }
  const active = load('abvc_project') || '';
  $('#projectSel').innerHTML = '<option value="">No project</option>' + PROJECTS.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  $('#projectSel').value = PROJECTS.some(p => p.id === active) ? active : '';
  $('#projNew').disabled = !PROJ_STORAGE;
  if (!PROJ_STORAGE) $('#projStatus').textContent = 'Projects need writable storage on the server.';
  renderProjects();
  renderCtx();
}

function activeProject(){ return PROJECTS.find(p => p.id === $('#projectSel').value) || null; }
function renderCtx(){
  const el = $('#ctx'); if (!el) return;
  const p = activeProject();
  el.innerHTML = p
    ? `<span class="ctx-dot" aria-hidden="true"></span><span>Working on <strong>${esc(p.name)}</strong></span><span class="ctx-site">${esc(hostOf(p.site) || p.site)}</span><a class="links" href="#/projects">Change</a>`
    : `<span>No client selected.</span><a class="links" href="#/projects">Choose a project</a>`;
}

function applyProject(p, openLatest){
  store('abvc_project', p ? p.id : '');
  $('#projectSel').value = p ? p.id : '';
  renderProjects();
  renderCtx();
  if (!p) return;
  const site = p.site;
  [['#url', 'abvc_url'], ['#scanUrl', 'abvc_scan_url'], ['#accessUrl', 'abvc_access_url'], ['#llmsUrl', 'abvc_llms_url']]
    .forEach(([sel, k]) => { $(sel).value = site; store(k, site); });
  $('#citeDomain').value = hostOf(site);
  $('#citeBrand').value = (p.brands || []).join(', ');
  $('#citeComp').value = (p.competitors || []).join(', ');
  $('#citeLocation').value = p.location || '';
  $('#citePrompts').value = (p.questions || []).join('\n');
  const form = {}; CITE_FIELDS.forEach(f => form[f] = $('#' + f).value); store('abvc_cite_form', JSON.stringify(form));
  citeEstimate();
  if (openLatest && p.latest){
    if (p.latest.scan && p.latest.scan.id) pollScan(p.latest.scan.id);
    if (p.latest.cite && p.latest.cite.id) pollCite(p.latest.cite.id);
  }
}
$('#projectSel').onchange = () => applyProject(activeProject(), true);

function renderProjects(){
  const box = $('#projList');
  if (!PROJECTS.length){
    box.innerHTML = '<div class="empty">No projects yet. Create one for each client, and every page will fill in for them automatically.</div>';
    return;
  }
  const active = $('#projectSel').value;
  const pct = (n, t) => t ? Math.round(n / t * 100) + '%' : '–';
  box.innerHTML = `<div class="projcards">${PROJECTS.map(p => {
    const s = p.latest && p.latest.scan, c = p.latest && p.latest.cite;
    const scanHtml = s
      ? `<div class="chips"><span class="chip ${s.errors ? 'bad' : 'ok'}">${plural(s.errors, 'error page')}</span><span class="chip ${s.warnings ? 'warn' : 'ok'}">${plural(s.warnings, 'warning page')}</span><span class="chip na">${plural(s.pages, 'page')}</span></div><span class="note" style="margin:0">${esc((s.started_at || '').slice(0, 16))}, as ${esc(s.bot || '')}</span>`
      : '<span class="note" style="margin:0">Not scanned yet</span>';
    const citeHtml = c
      ? `<div class="chips">${c.score !== null && c.score !== undefined ? `<span class="chip ${c.score >= 50 ? 'ok' : c.score >= 20 ? 'warn' : 'bad'}">Score ${c.score}</span>` : ''}<span class="chip ${c.cited ? 'ok' : 'bad'}">Cited ${pct(c.cited, c.answers)}</span><span class="chip ${c.named ? 'ok' : 'warn'}">Named ${pct(c.named, c.answers)}</span><span class="chip na">${plural(c.answers, 'answer')}</span></div><span class="note" style="margin:0">${esc((c.started_at || '').slice(0, 16))}</span>`
      : '<span class="note" style="margin:0">No test yet</span>';
    return `<article class="projcard ${p.id === active ? 'active' : ''}">
      <header><h3>${esc(p.name)}</h3><span class="sub">${esc(p.site)}</span></header>
      <dl class="kv">
        <dt>Site scan</dt><dd>${scanHtml}</dd>
        <dt>AI citations</dt><dd>${citeHtml}</dd>
        <dt>Setup</dt><dd>${plural((p.competitors || []).length, 'competitor')}, ${plural((p.questions || []).length, 'question')}${p.location ? ', ' + esc(p.location) : ''}</dd>
      </dl>
      <div class="row actions">
        ${p.id === active ? '<span class="chip ok">In use</span>' : `<button class="ghost" data-use="${esc(p.id)}">Use this project</button>`}
        <a class="links" data-go="${esc(p.id)}" data-page="bots">Bot view</a>
        <a class="links" data-go="${esc(p.id)}" data-page="scan">Site scan</a>
        <a class="links" data-go="${esc(p.id)}" data-page="cite">AI citations</a>
        <a class="links" data-edit="${esc(p.id)}">Edit</a>
      </div>
    </article>`;
  }).join('')}</div>`;
  $$('[data-use]').forEach(b => b.onclick = () => applyProject(PROJECTS.find(p => p.id === b.dataset.use), true));
  $$('[data-go]').forEach(a => a.onclick = () => {
    const p = PROJECTS.find(x => x.id === a.dataset.go);
    if (p && p.id !== $('#projectSel').value) applyProject(p, true);
    location.hash = '#/' + a.dataset.page;
  });
  $$('[data-edit]').forEach(a => a.onclick = () => openProjectForm(PROJECTS.find(p => p.id === a.dataset.edit)));
}

function openProjectForm(p){
  EDITING = p || null;
  $('#projForm').classList.remove('hidden');
  $('#projFormTitle').textContent = p ? `Edit ${p.name}` : 'New project';
  $('#projDelete').classList.toggle('hidden', !p);
  $('#projFormNote').textContent = '';
  if (p){
    $('#pName').value = p.name; $('#pSite').value = p.site;
    $('#pBrands').value = (p.brands || []).join(', '); $('#pComp').value = (p.competitors || []).join(', ');
    $('#pLoc').value = p.location || ''; $('#pQuestions').value = (p.questions || []).join('\n');
  } else if ($('#projectSel').value){
    ['#pName', '#pSite', '#pBrands', '#pComp', '#pLoc', '#pQuestions'].forEach(s => $(s).value = '');
  } else {
    $('#pName').value = '';
    $('#pSite').value = $('#url').value.trim() || ($('#citeDomain').value.trim() ? 'https://' + $('#citeDomain').value.trim() : '');
    $('#pBrands').value = $('#citeBrand').value; $('#pComp').value = $('#citeComp').value;
    $('#pLoc').value = $('#citeLocation').value; $('#pQuestions').value = $('#citePrompts').value;
    if ($('#pSite').value || $('#pBrands').value) $('#projFormNote').textContent = 'Filled in from what you last used. Change anything before saving.';
  }
  $('#projForm').scrollIntoView({behavior: 'smooth', block: 'start'});
  $('#pName').focus();
}
$('#projNew').onclick = () => openProjectForm(null);
$('#projCancel').onclick = () => { $('#projForm').classList.add('hidden'); EDITING = null; };
$('#projSave').onclick = async () => {
  const questions = $('#pQuestions').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!$('#pName').value.trim()){ $('#projFormNote').textContent = 'Give the project a name.'; return; }
  if (!$('#pSite').value.trim()){ $('#projFormNote').textContent = 'Add the website address.'; return; }
  if (questions.length > 10){ $('#projFormNote').textContent = 'Use up to 10 questions.'; return; }
  $('#projSave').disabled = true;
  try{
    const d = await post('/api/projects/save', {id: EDITING ? EDITING.id : '', name: $('#pName').value, site: $('#pSite').value,
      brands: splitList($('#pBrands').value), competitors: splitList($('#pComp').value), location: $('#pLoc').value, questions});
    if (d.error){ $('#projFormNote').textContent = d.error; return; }
    const wasActive = EDITING && EDITING.id === $('#projectSel').value;
    $('#projForm').classList.add('hidden'); EDITING = null;
    await loadProjects();
    const saved = PROJECTS.find(p => p.id === d.id);
    if (saved && (wasActive || !$('#projectSel').value)) applyProject(saved, false);
    $('#projStatus').textContent = `Saved ${d.name}.`;
  }catch(e){ $('#projFormNote').textContent = 'Could not save: ' + e.message; }
  finally{ $('#projSave').disabled = false; }
};
$('#projDelete').onclick = async () => {
  if (!EDITING || !confirm(`Delete the project "${EDITING.name}"? Saved scans and tests are kept.`)) return;
  const id = EDITING.id;
  try{ await post('/api/projects/delete', {id}); }catch(e){}
  if ($('#projectSel').value === id) store('abvc_project', '');
  $('#projForm').classList.add('hidden'); EDITING = null;
  await loadProjects();
  $('#projStatus').textContent = 'Project deleted.';
};

/* ---------------------------------------------------------------- crawler visits */
let LOGS = null;
$('#logBtn').onclick = uploadLog;
$('#logFilter').oninput = renderLogPages;
$('#logCsv').onclick = logCsv;

function fmtBytes(n){ return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; }
function uploadLog(){
  const f = $('#logFile').files[0];
  if (!f){ $('#logStatus').textContent = 'Choose a log file first.'; return; }
  if (f.size > 150 * 1024 * 1024){ $('#logStatus').textContent = 'The file is larger than 150 MB. Compress it with gzip or export a shorter period.'; return; }
  $('#logBtn').disabled = true;
  $('#logProgress').classList.remove('hidden'); $('#logBar').style.width = '0%';
  $('#logStatus').textContent = `Uploading ${f.name} (${fmtBytes(f.size)})…`;
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/logs/analyze');
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');
  xhr.setRequestHeader('X-File-Name', encodeURIComponent(f.name));
  xhr.upload.onprogress = e => {
    if (!e.lengthComputable) return;
    const pct = Math.round(e.loaded / e.total * 100);
    $('#logBar').style.width = pct + '%';
    $('#logStatus').textContent = pct < 100 ? `Uploading ${f.name}: ${pct}%…` : 'Analyzing the log and checking crawler addresses…';
  };
  const done = () => { $('#logBtn').disabled = false; $('#logProgress').classList.add('hidden'); };
  xhr.onerror = () => { done(); $('#logStatus').textContent = 'Upload failed. Check your connection and try again.'; };
  xhr.onload = () => {
    done();
    if (xhr.status === 401){ location.href = '/login'; return; }
    let d; try{ d = JSON.parse(xhr.responseText); }catch(e){ $('#logStatus').textContent = `The server returned an unexpected response (HTTP ${xhr.status}).`; return; }
    if (d.error && !d.stats){ $('#logStatus').textContent = d.error; return; }
    LOGS = d; renderLogs();
    $('#logStatus').textContent = d.error || `Analyzed ${d.file.name} (${fmtBytes(d.file.bytes)}${d.file.gzip ? ', gzip' : ''}) at ${d.analyzed_at}.`;
  };
  xhr.send(f);
}

function verifyChip(b){
  if (!b.verifiable && !b.verified && !b.fake) return `<span class="chip na" title="${esc(b.list_error || 'This company does not publish an IP address list')}">Can't verify</span>`;
  if (b.fake && !b.verified) return '<span class="chip bad">All fake</span>';
  if (b.fake) return `<span class="chip warn">${b.verified.toLocaleString()} real, ${b.fake.toLocaleString()} fake</span>`;
  return '<span class="chip ok">Verified</span>';
}
function renderLogs(){
  const d = LOGS, s = d.stats;
  $('#logResults').classList.toggle('hidden', !s.parsed);
  if (!s.parsed) return;
  const range = s.first ? (s.first === s.last ? s.first : `${s.first} to ${s.last}`) : 'unknown dates';
  $('#logSummary').innerHTML = `
    <span class="chip na">${s.lines.toLocaleString()} lines, ${range}</span>
    <span class="chip ${s.ai_visits ? 'ok' : 'warn'}">${s.ai_visits.toLocaleString()} AI crawler requests</span>
    <span class="chip ${s.verified ? 'ok' : 'na'}">${s.verified.toLocaleString()} verified by IP</span>
    ${s.fake ? `<span class="chip bad">${s.fake.toLocaleString()} fake</span>` : ''}
    ${s.unknown ? `<span class="chip na">${s.unknown.toLocaleString()} can't be verified</span>` : ''}
    ${s.proxy ? `<span class="chip warn">${s.proxy.toLocaleString()} through Cloudflare</span>` : ''}`;
  const warns = [];
  if (s.truncated) warns.push(['warning', 'Only the first 3 million lines were analyzed.']);
  if (s.unparsed) warns.push([s.unparsed > s.parsed ? 'error' : 'suggestion', `${s.unparsed.toLocaleString()} lines could not be read${d.unparsed_sample.length ? '. Example: ' + d.unparsed_sample[0] : ''}`]);
  if (s.no_ua > s.parsed / 2) warns.push(['warning', 'Most lines have no user agent, so crawlers cannot be recognized. Use the “combined” log format, which includes it.']);
  if (s.proxy) warns.push(['warning', 'Some crawler requests show Cloudflare addresses instead of the real visitor address, so they cannot be verified. Turn on real visitor IPs on the server (for example Apache mod_remoteip or Nginx real_ip with Cloudflare\'s ranges), or analyze Cloudflare\'s own logs.']);
  const LIST_NAMES = {'openai-gptbot': 'GPTBot', 'openai-searchbot': 'OAI-SearchBot', 'openai-chatgpt-user': 'ChatGPT-User', 'openai-adsbot': 'OAI-AdsBot',
    perplexitybot: 'PerplexityBot', 'perplexity-user': 'Perplexity-User', googlebot: 'Googlebot', bingbot: 'Bingbot', applebot: 'Applebot', 'mistralai-user': 'MistralAI-User'};
  const failed = Object.keys(d.list_errors || {}).filter(k => k !== 'cloudflare').map(k => LIST_NAMES[k] || k);
  if (failed.length) warns.push(['suggestion', `The published IP lists for ${failed.join(', ')} could not be loaded right now, so those crawlers show as “can't verify”. Try again later.`]);
  if (!s.ai_visits) warns.push(['warning', 'No AI crawler requests were found in this log. Check the period covered, and the AI access page in case crawlers are blocked.']);
  $('#logWarnings').innerHTML = warns.map(([l, m]) => `<li><span class="chip ${LEVEL[l][0]}">${LEVEL[l][1]}</span><span>${esc(m)}</span></li>`).join('');

  $('#logBots').innerHTML = d.bots.length ? `<thead><tr><th>Crawler</th><th>Requests</th><th>Identity</th><th>Pages</th><th>robots.txt</th><th>Errors</th><th>Last seen</th></tr></thead><tbody>${
    d.bots.map(b => `<tr>
      <td><strong>${esc(b.label)}</strong><span class="sub">${esc(b.company)}</span></td>
      <td class="num">${b.hits.toLocaleString()}</td>
      <td>${verifyChip(b)}${b.proxy ? ` <span class="chip warn">${b.proxy} via Cloudflare</span>` : ''}</td>
      <td class="num">${b.pages.toLocaleString()}</td>
      <td class="num">${b.robots ? b.robots.toLocaleString() : '–'}</td>
      <td>${b.errors ? `<span class="chip bad">${b.errors.toLocaleString()}</span>` : '<span class="chip ok">0</span>'}</td>
      <td class="num">${esc(b.last || '–')}</td></tr>`).join('')}</tbody>` : '<tbody><tr><td class="note">No AI crawlers found.</td></tr></tbody>';
  $('#logNotSeen').textContent = d.not_seen.length ? `Not seen in this log: ${d.not_seen.map(x => x.label).join(', ')}.` : '';

  const days = d.days.filter(x => x.date !== 'unknown');
  const max = Math.max(1, ...days.map(x => x.real + x.fake));
  $('#logDays').innerHTML = days.length ? days.map(x => `<div class="day" title="${esc(x.date)}: ${x.real} real or unverifiable, ${x.fake} fake">
      <span class="real" style="height:${x.real / max * 100}%"></span><span class="fake" style="height:${x.fake / max * 100}%"></span></div>`).join('') : '<div class="note">No dates found in the log.</div>';
  const old = $('#logDays').nextElementSibling;
  if (old && old.classList.contains('daylabels')) old.remove();
  if (days.length) $('#logDays').insertAdjacentHTML('afterend', `<div class="daylabels"><span>${esc(days[0].date)}</span><span>${esc(days[days.length - 1].date)}</span></div>`);

  renderLogPages();
  $('#logErrorsPanel').classList.toggle('hidden', !d.errors.length);
  $('#logErrors').innerHTML = `<thead><tr><th>Page</th><th>Crawler</th><th>Status</th><th>Times</th></tr></thead><tbody>${
    d.errors.map(e => `<tr><td>${esc(e.path)}</td><td>${esc(e.bot)}</td><td><span class="chip bad">${e.status}</span></td><td class="num">${e.count.toLocaleString()}</td></tr>`).join('')}</tbody>`;
  $('#logFakesPanel').classList.toggle('hidden', !d.fakes.length);
  $('#logFakes').innerHTML = `<thead><tr><th>Address</th><th>Claimed to be</th><th>Requests</th></tr></thead><tbody>${
    d.fakes.map(f => `<tr><td>${esc(f.ip)}</td><td>${esc(f.bot)}</td><td class="num">${f.count.toLocaleString()}</td></tr>`).join('')}</tbody>`;
}
function logRows(){
  const q = $('#logFilter').value.trim().toLowerCase();
  return (LOGS ? LOGS.pages : []).filter(p => !q || p.path.toLowerCase().includes(q));
}
function renderLogPages(){
  if (!LOGS) return;
  const rows = logRows();
  $('#logPagesNote').textContent = `${LOGS.total_pages.toLocaleString()} different pages were read by AI crawlers (files like images and scripts are left out). Showing the top ${Math.min(rows.length, 150)}${$('#logFilter').value ? ' matching the filter' : ''}.`;
  $('#logPages').innerHTML = rows.length ? `<thead><tr><th>Page</th><th>Requests</th><th>Crawlers</th><th>Errors</th></tr></thead><tbody>${
    rows.map(p => `<tr><td style="word-break:break-all">${esc(p.path)}</td><td class="num">${p.hits.toLocaleString()}</td>
      <td>${p.bots.slice(0, 5).map(([b, n]) => `<span class="chip na">${esc(b)} ${n}</span>`).join(' ')}</td>
      <td>${p.errors ? `<span class="chip bad">${p.errors.toLocaleString()}</span>` : '–'}</td></tr>`).join('')}</tbody>` : '<tbody><tr><td class="note">No pages match.</td></tr></tbody>';
}
function logCsv(){
  if (!LOGS) return;
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [['page', 'requests', 'errors', 'crawlers'].map(q).join(',')].concat(logRows().map(p =>
    [p.path, p.hits, p.errors, p.bots.map(([b, n]) => `${b} ${n}`).join('; ')].map(q).join(',')));
  const blob = new Blob(['\ufeff' + lines.join('\r\n')], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `crawler-visits-${(LOGS.file.name || 'log').replace(/[^\w.-]+/g, '_')}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------------------------------------------------------------- citation insights */
let CITE_RUNS = [], OPPS = [];
const SENT = {positive: ['ok', 'positively'], neutral: ['na', 'neutrally'], negative: ['bad', 'negatively']};
function answerScore(r){
  const b = r.brand || {}; let s = 0;
  if (b.mentioned) s += 40 + (r.sentiment === 'positive' ? 20 : r.sentiment === 'negative' ? 0 : 10);
  if (b.cited){ const k = b.rank || 9; s += k === 1 ? 40 : k === 2 ? 30 : k === 3 ? 20 : 10; }
  return s;
}
function cleanDom(s){ s = String(s || '').trim(); return hostOf(/^https?:\/\//i.test(s) ? s : 'http://' + s); }
function parseComps(list){
  return (list || []).map(e => {
    const m = e.match(/^(.*?)\s*\(([^)]+)\)\s*$/);
    if (m) return {label: e, names: m[1].trim() ? [m[1].trim()] : [], domain: cleanDom(m[2])};
    if (e.includes('.') && !e.includes(' ')) return {label: e, names: [], domain: cleanDom(e)};
    return {label: e, names: [e], domain: ''};
  });
}
function reEsc(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function highlightAnswer(text, d){
  const html = esc(text || '');
  const terms = [];
  (d.brands || []).forEach(n => n && n.length > 1 && terms.push([n, 'me']));
  if (d.domain) terms.push([d.domain, 'me']);
  parseComps(d.competitors).forEach(c => { c.names.forEach(n => n.length > 1 && terms.push([n, 'them'])); if (c.domain) terms.push([c.domain, 'them']); });
  if (!terms.length) return html;
  terms.sort((a, b) => b[0].length - a[0].length);
  const cls = new Map(terms.map(([t, c]) => [esc(t).toLowerCase(), c]));
  const re = new RegExp('(?<![\\w])(' + terms.map(([t]) => reEsc(esc(t))).join('|') + ')(?![\\w])', 'gi');
  return html.replace(re, m => `<mark class="${cls.get(m.toLowerCase()) || 'me'}">${m}</mark>`);
}

function renderCiteInsights(){
  const d = CITE; if (!d) return;
  const ok = d.results.filter(r => !r.error);
  const comps = parseComps(d.competitors);
  const compOf = h => comps.find(c => c.domain && domMatch(h, c.domain));
  const hosts = new Map(), opps = new Map();
  ok.forEach(r => {
    const srcs = (r.citations || []).length ? r.citations : (r.text_links || []).map(u => ({url: u, title: ''}));
    const named = (r.competitors || []).filter(x => x.mentioned || x.cited).map(x => x.label);
    const seen = new Set();
    srcs.forEach(c => {
      const h = hostOf(c.url); if (!h) return;
      if (!seen.has(h)){
        seen.add(h);
        const e = hosts.get(h) || {host: h, n: 0, qs: new Set()};
        e.n++; e.qs.add(r.prompt); hosts.set(h, e);
      }
      if (!r.brand.cited && !domMatch(h, d.domain) && !compOf(h)){
        const u = c.url.split('#')[0];
        const o = opps.get(u) || {url: u, title: c.title || '', host: h, n: 0, qs: new Set(), comps: new Set()};
        o.n++; o.qs.add(r.prompt); named.forEach(x => o.comps.add(x));
        if (!o.title && c.title) o.title = c.title;
        opps.set(u, o);
      }
    });
  });
  const hrows = [...hosts.values()].sort((a, b) => b.n - a.n).slice(0, 30);
  $('#citeSources').innerHTML = hrows.length ? `<thead><tr><th>Website</th><th>Cited in</th><th>Whose site</th><th>Example question</th></tr></thead><tbody>${
    hrows.map(e => {
      const mine = domMatch(e.host, d.domain), comp = compOf(e.host);
      return `<tr><td><strong>${esc(e.host)}</strong></td><td class="num">${e.n} of ${ok.length} (${Math.round(e.n / ok.length * 100)}%)</td>
        <td>${mine ? '<span class="chip ok">You</span>' : comp ? `<span class="chip warn">${esc(comp.label)}</span>` : '<span class="chip na">Third party</span>'}</td>
        <td>${esc([...e.qs][0])}${e.qs.size > 1 ? ` <span class="note" style="margin:0">+${e.qs.size - 1} more</span>` : ''}</td></tr>`;
    }).join('')}</tbody>` : '<tbody><tr><td class="note">No sources were returned.</td></tr></tbody>';
  OPPS = [...opps.values()].sort((a, b) => b.n - a.n || b.comps.size - a.comps.size).slice(0, 25);
  $('#citeOpps').innerHTML = OPPS.length ? OPPS.map((o, i) => `<div class="opp">
      <div class="opphead"><div><a href="${esc(o.url)}" target="_blank" rel="noopener"><strong>${esc(o.title || o.url)}</strong></a><span class="sub">${esc(o.host)}</span></div>
      <button class="ghost" data-brief="${i}">Draft outreach</button></div>
      <div class="note" style="margin:4px 0 0">Cited in ${plural(o.n, 'answer')} where you were not cited: ${[...o.qs].map(q => '“' + esc(q) + '”').join(', ')}${o.comps.size ? `. Competitors named there: ${esc([...o.comps].join(', '))}` : ''}.</div>
      <div class="brief hidden" id="brief-${i}"></div></div>`).join('')
    : '<div class="note">No opportunities found: your site was cited wherever sources were given, or the other sources were competitors\' own sites.</div>';
  $$('[data-brief]').forEach(b => b.onclick = () => draftBrief(Number(b.dataset.brief), b));
}

async function draftBrief(i, btn){
  const o = OPPS[i], box = $('#brief-' + i);
  const model = ($$('.cite-model:checked')[0] || {}).value || currentModels()[0];
  if (SETTINGS.key_source === 'none'){ box.classList.remove('hidden'); box.innerHTML = '<div class="note">Add an OpenRouter key first, in <a class="links" href="#/settings">Settings</a>.</div>'; return; }
  btn.disabled = true; box.classList.remove('hidden');
  box.innerHTML = `<div class="note">Reading the page and drafting with ${esc(model)}…</div>`;
  try{
    const r = await post('/api/brief', {url: o.url, title: o.title, domain: CITE.domain, brands: CITE.brands, question: [...o.qs][0], competitors: [...o.comps], model});
    if (r.error) throw new Error(r.error);
    box.innerHTML = `<div class="answertext">${esc(r.brief)}</div><div class="links"><a data-copybrief="1">Copy</a></div>`;
    box.querySelector('[data-copybrief]').onclick = e => navigator.clipboard.writeText(r.brief).then(() => { e.target.textContent = 'Copied'; });
  }catch(e){ box.innerHTML = `<div class="note" style="color:var(--bad)">Could not draft: ${esc(e.message)}</div>`; }
  finally{ btn.disabled = false; }
}

function renderTrend(){
  const box = $('#citeTrend'); if (!box || !CITE) return;
  const runs = CITE_RUNS.filter(s => s.domain === CITE.domain && s.summary && s.summary.score !== null && s.summary.score !== undefined)
    .sort((a, b) => (a.started_at || '').localeCompare(b.started_at || '')).slice(-12);
  if (runs.length < 2){
    box.innerHTML = runs.length ? '<div class="note">Run this test again later to see how the score changes over time.</div>' : '';
    return;
  }
  const last = runs[runs.length - 1], prev = runs[runs.length - 2];
  const delta = last.summary.score - prev.summary.score;
  box.innerHTML = `<div class="subhead">Visibility over time <span class="chip ${delta > 0 ? 'ok' : delta < 0 ? 'bad' : 'na'}">${delta > 0 ? '+' : ''}${delta} since ${esc((prev.started_at || '').slice(0, 10))}</span></div>
    <div class="trendbars">${runs.map(s => `<button class="tbar ${s.id === CITE.id ? 'cur' : ''}" data-run="${esc(s.id)}" title="${esc(s.started_at)}: score ${s.summary.score}, cited in ${s.summary.cited} of ${s.summary.answers} answers"><em>${s.summary.score}</em><span style="height:${Math.max(3, s.summary.score)}%"></span></button>`).join('')}</div>
    <div class="daylabels"><span>${esc((runs[0].started_at || '').slice(0, 10))}</span><span>${esc((last.started_at || '').slice(0, 10))}</span></div>`;
  $$('#citeTrend [data-run]').forEach(b => b.onclick = () => pollCite(b.dataset.run));
}

/* ---------------------------------------------------------------- question ideas */
$('#qOpen').onclick = () => $('#qIdeas').classList.toggle('hidden');
$('#qGen').onclick = async () => {
  const proj = activeProject();
  const dom = $('#citeDomain').value.trim();
  const site = proj ? proj.site : (dom ? 'https://' + dom.replace(/^https?:\/\//, '') : '');
  if (!site){ $('#qStatus').textContent = "Enter your site's domain first."; return; }
  if (SETTINGS.key_source === 'none'){ $('#qStatus').innerHTML = 'Add an OpenRouter key first, in <a class="links" href="#/settings">Settings</a>.'; return; }
  const model = ($$('.cite-model:checked')[0] || {}).value || currentModels()[0];
  $('#qGen').disabled = true;
  $('#qStatus').textContent = `Reading the site and asking ${model} for ideas…`;
  try{
    const r = await post('/api/questions', {site, brands: $('#citeBrand').value, location: $('#citeLocation').value,
      personas: $('#qPersonas').value, count: Number($('#qCount').value), model});
    if (r.error) throw new Error(r.error);
    $('#qList').innerHTML = r.questions.map((q, i) => `<label class="idea"><input type="checkbox" class="q-cb" value="${esc(q.question)}" ${i < 5 ? 'checked' : ''}>
      <span>${esc(q.question)}<span class="chips" style="margin:3px 0 0">${q.persona ? `<span class="chip na">${esc(q.persona)}</span>` : ''}${q.intent ? `<span class="chip na">${esc(q.intent)}</span>` : ''}</span></span></label>`).join('');
    $('#qActions').classList.remove('hidden');
    $('#qSaveProj').classList.toggle('hidden', !proj);
    $('#qStatus').textContent = `${plural(r.questions.length, 'idea')} from ${r.model}. Tick the ones to use.`;
  }catch(e){ $('#qStatus').textContent = 'Could not generate ideas: ' + e.message; }
  finally{ $('#qGen').disabled = false; }
};
function pickedIdeas(){ return $$('.q-cb:checked').map(c => c.value); }
$('#qAdd').onclick = () => {
  const cur = citeLines();
  const add = pickedIdeas().filter(q => !cur.includes(q));
  const all = cur.concat(add);
  $('#citePrompts').value = all.join('\n');
  $('#citePrompts').dispatchEvent(new Event('input'));
  $('#qStatus').textContent = all.length > 10
    ? `Added ${plural(add.length, 'question')}. You now have ${all.length}; a test uses up to 10, so remove some before running.`
    : `Added ${plural(add.length, 'question')}.`;
};
$('#qSaveProj').onclick = async () => {
  const p = activeProject(); if (!p) return;
  const qs = (p.questions || []).concat(pickedIdeas().filter(q => !(p.questions || []).includes(q))).slice(0, 10);
  try{
    const r = await post('/api/projects/save', {id: p.id, name: p.name, site: p.site, brands: p.brands, competitors: p.competitors, location: p.location, questions: qs});
    if (r.error) throw new Error(r.error);
    await loadProjects();
    applyProject(PROJECTS.find(x => x.id === p.id), false);
    $('#qStatus').textContent = `Saved to ${p.name}: ${plural(qs.length, 'question')} (projects keep up to 10).`;
  }catch(e){ $('#qStatus').textContent = 'Could not save: ' + e.message; }
};

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
  try{
    const form = JSON.parse(load('abvc_cite_form') || '{}');
    CITE_FIELDS.forEach(f => { if (form[f] !== undefined) $('#' + f).value = form[f]; });
  }catch(e){}
  citeEstimate();
  loadCiteHistory();
  const cid = load('abvc_cite');
  if (cid) pollCite(cid);
  loadProjects();
  $('#signout').classList.toggle('hidden', !s.auth);
  applySettings(s);
}
init();
