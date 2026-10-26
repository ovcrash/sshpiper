// Vanilla-JS operator console for relay-admind.
//
// Talks to the REST API under /v1/*: manages registry entries (list, add,
// persona, probe, expose, retire) and browses the audit (recorded sessions,
// event timelines, asciicast playback, captured files). The bearer token is
// held in sessionStorage and sent on every /v1 call; the static assets load
// without it (see requireToken on the server).

import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import './style.css';

const $ = (id) => document.getElementById(id);
const view = $('view');
const toasts = $('toasts');

// ---------- small helpers ----------

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function showToast(message, kind = 'info', timeout = 4000) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = message;
  toasts.appendChild(el);
  if (timeout > 0) {
    setTimeout(() => {
      el.style.transition = 'opacity 0.25s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 280);
    }, timeout);
  }
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
  return (n / 1024 / 1024).toFixed(1) + ' MiB';
}

function statePill(state) {
  const s = String(state || '');
  const tone = s === 'exposed' ? 'green' : s === 'retired' ? 'red' : s === 'probed' ? 'amber' : 'gray';
  return `<span class="pill ${tone}">${escapeHtml(s || 'unknown')}</span>`;
}

// ---------- token + API ----------

const TOKEN_KEY = 'relay.console.token';
function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
}
function setToken(t) {
  try { if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
}

const loginDialog = $('login');
const loginForm = $('login-form');
const loginToken = $('login-token');
const loginError = $('login-error');

function requireLogin(msg) {
  if (msg) loginError.textContent = msg;
  if (!loginDialog.open) {
    try { loginDialog.showModal(); } catch (e) { loginDialog.setAttribute('open', ''); }
  }
  loginToken.focus();
}

// api issues a /v1 request with the bearer token and returns parsed JSON.
// On 401 it drops the token and reopens the login dialog, throwing so callers
// stop. Other non-2xx throw with the server's error message.
async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers, { Authorization: 'Bearer ' + getToken() });
  if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  if (r.status === 401) {
    setToken('');
    requireLogin('Invalid or missing token.');
    throw new Error('unauthorized');
  }
  const text = await r.text();
  let body = null;
  if (text) { try { body = JSON.parse(text); } catch (e) { body = text; } }
  if (!r.ok) {
    const msg = (body && body.error) ? body.error : ('HTTP ' + r.status);
    throw new Error(msg);
  }
  return body;
}

// apiRaw returns the Response for binary/text downloads (casts, files).
async function apiRaw(path) {
  const r = await fetch(path, { headers: { Authorization: 'Bearer ' + getToken() } });
  if (r.status === 401) {
    setToken('');
    requireLogin('Invalid or missing token.');
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r;
}

// ---------- router ----------

const routes = [
  { re: /^#\/entries\/?$/, fn: () => renderEntries() },
  { re: /^#\/entry\/(.+)$/, fn: (m) => renderEntry(decodeURIComponent(m[1])) },
  { re: /^#\/audit\/([^/]+)\/([^/]+)$/, fn: (m) => renderAuditSession(m[1], decodeURIComponent(m[2])) },
  { re: /^#\/audit\/?$/, fn: () => renderAudit() },
];

function setActiveNav() {
  const h = location.hash || '#/entries';
  const which = h.startsWith('#/audit') ? 'audit' : 'entries';
  for (const a of document.querySelectorAll('#nav a')) {
    a.classList.toggle('active', a.dataset.route === which);
  }
}

async function route() {
  if (!getToken()) { requireLogin(); return; }
  setActiveNav();
  const h = location.hash || '#/entries';
  for (const r of routes) {
    const m = r.re.exec(h);
    if (m) {
      try { await r.fn(m); } catch (e) {
        if (e.message !== 'unauthorized') view.innerHTML = errorCard(e.message);
      }
      return;
    }
  }
  location.hash = '#/entries';
}

function errorCard(msg) {
  return `<section class="card"><div class="card-body errors">${escapeHtml(msg)}</div></section>`;
}

// ---------- entries list ----------

async function renderEntries() {
  const entries = await api('/v1/entries');
  const counts = { total: entries.length, exposed: 0, retired: 0 };
  for (const e of entries) {
    if (e.state === 'exposed') counts.exposed++;
    if (e.state === 'retired') counts.retired++;
  }
  const rows = entries.map((e) => {
    const auth = [e.auth_password ? 'password' : '', e.auth_key ? 'key' : ''].filter(Boolean).join('+') || '—';
    return `<tr class="clickable" data-ip="${escapeHtml(e.external_ip)}">
      <td><code>${escapeHtml(e.external_ip)}</code></td>
      <td>${escapeHtml(e.username)}</td>
      <td><code>${escapeHtml(e.backend_host)}:${e.backend_port || 22}</code></td>
      <td>${escapeHtml(auth)}</td>
      <td>${statePill(e.state)}</td>
      <td class="mono">${escapeHtml(fmtTime(e.updated_at))}</td>
    </tr>`;
  }).join('');

  view.innerHTML = `
    <div class="page-head">
      <h1><svg class="ic"><use href="#i-server"/></svg> Entries</h1>
      <button class="btn btn-primary" id="add-entry"><svg class="ic"><use href="#i-plus"/></svg><span>Add entry</span></button>
    </div>
    <section class="stats">
      <div class="stat"><div class="stat-icon"><svg class="ic"><use href="#i-server"/></svg></div><div class="stat-body"><div class="stat-label">Entries</div><div class="stat-value">${counts.total}</div></div></div>
      <div class="stat"><div class="stat-icon"><svg class="ic"><use href="#i-shield"/></svg></div><div class="stat-body"><div class="stat-label">Exposed</div><div class="stat-value">${counts.exposed}</div></div></div>
      <div class="stat"><div class="stat-icon"><svg class="ic"><use href="#i-x"/></svg></div><div class="stat-body"><div class="stat-label">Retired</div><div class="stat-value">${counts.retired}</div></div></div>
    </section>
    <section class="card">
      <div class="table-wrap">
        <table><thead><tr><th>external ip</th><th>user</th><th>backend</th><th>auth</th><th>state</th><th>updated</th></tr></thead>
        <tbody>${rows || ''}</tbody></table>
        ${entries.length ? '' : '<div class="empty">No entries yet. Add one to get started.</div>'}
      </div>
    </section>`;

  for (const tr of view.querySelectorAll('tr.clickable')) {
    tr.addEventListener('click', () => { location.hash = '#/entry/' + encodeURIComponent(tr.dataset.ip); });
  }
  $('add-entry').addEventListener('click', openAddEntry);
}

// ---------- add entry dialog ----------

function openAddEntry() {
  const dlg = document.createElement('dialog');
  dlg.className = 'form-dialog';
  dlg.innerHTML = `
    <form method="dialog">
      <h2>Add entry</h2>
      <div class="form-grid">
        <div class="field"><label>External IP</label><input type="text" name="external_ip" placeholder="203.0.113.10" required></div>
        <div class="field"><label>Username</label><input type="text" name="username" placeholder="alice" required></div>
        <div class="field"><label>Backend host</label><input type="text" name="backend_host" placeholder="10.0.0.21" required></div>
        <div class="field"><label>Backend port</label><input type="number" name="backend_port" value="22" min="1" max="65535"></div>
        <div class="field span2"><label>Password (leave empty to use a key)</label><input type="password" name="password" autocomplete="new-password"></div>
        <div class="field span2"><label>Private key (PEM, optional)</label><textarea name="private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
        <div class="field span2"><label>Public key (optional)</label><textarea name="public_key" placeholder="ssh-ed25519 AAAA..."></textarea></div>
      </div>
      <div class="errors"></div>
      <div class="dialog-actions">
        <button class="btn btn-ghost" value="cancel" type="submit" formnovalidate>Cancel</button>
        <button class="btn btn-primary" value="ok" type="submit">Create</button>
      </div>
    </form>`;
  document.body.appendChild(dlg);
  const form = dlg.querySelector('form');
  const errBox = dlg.querySelector('.errors');
  form.addEventListener('submit', async (e) => {
    if (e.submitter && e.submitter.value === 'cancel') { dlg.close(); return; }
    e.preventDefault();
    const fd = new FormData(form);
    const body = {
      external_ip: fd.get('external_ip').trim(),
      username: fd.get('username').trim(),
      backend_host: fd.get('backend_host').trim(),
      backend_port: parseInt(fd.get('backend_port'), 10) || 22,
      password: fd.get('password') || '',
      private_key: fd.get('private_key') || '',
      public_key: fd.get('public_key') || '',
    };
    try {
      await api('/v1/entries', { method: 'POST', body: JSON.stringify(body) });
      showToast('Entry ' + body.external_ip + ' created', 'success');
      dlg.close();
      location.hash = '#/entry/' + encodeURIComponent(body.external_ip);
      if ((location.hash) === '#/entry/' + encodeURIComponent(body.external_ip)) route();
    } catch (err) {
      errBox.textContent = err.message;
    }
  });
  dlg.addEventListener('close', () => dlg.remove());
  try { dlg.showModal(); } catch (e) { dlg.setAttribute('open', ''); }
}

// ---------- entry detail ----------

async function renderEntry(ip) {
  const e = await api('/v1/entries/' + encodeURIComponent(ip));
  const p = e.persona || {};
  const events = e.events || [];
  const exposed = e.state === 'exposed';
  const retired = e.state === 'retired';

  view.innerHTML = `
    <div class="page-head">
      <h1><a href="#/entries" class="crumbs"><svg class="ic"><use href="#i-back"/></svg></a> <code>${escapeHtml(e.external_ip)}</code> ${statePill(e.state)}</h1>
      <a class="btn btn-ghost" href="#/audit?ip=${encodeURIComponent(e.external_ip)}"><svg class="ic"><use href="#i-pulse"/></svg><span>Audit sessions</span></a>
    </div>
    <div class="detail-grid">
      <section class="card"><div class="card-head"><h2><svg class="ic"><use href="#i-server"/></svg> Entry</h2></div>
        <div class="card-body"><dl class="kv">
          <dt>external ip</dt><dd><code>${escapeHtml(e.external_ip)}</code></dd>
          <dt>username</dt><dd>${escapeHtml(e.username)}</dd>
          <dt>backend</dt><dd><code>${escapeHtml(e.backend_host)}:${e.backend_port || 22}</code></dd>
          <dt>auth</dt><dd>${e.auth_password ? 'password ' : ''}${e.auth_key ? 'key' : ''}${(!e.auth_password && !e.auth_key) ? '—' : ''}</dd>
          <dt>state</dt><dd>${statePill(e.state)}</dd>
          <dt>created</dt><dd class="mono">${escapeHtml(fmtTime(e.created_at))}</dd>
          <dt>updated</dt><dd class="mono">${escapeHtml(fmtTime(e.updated_at))}</dd>
          ${e.retired_at ? `<dt>retired</dt><dd class="mono">${escapeHtml(fmtTime(e.retired_at))}</dd>` : ''}
        </dl></div>
      </section>
      <section class="card"><div class="card-head"><h2><svg class="ic"><use href="#i-key"/></svg> Persona</h2></div>
        <div class="card-body"><dl class="kv">
          <dt>host keys</dt><dd>${p.has_host_keys ? 'present' : '<span class="pill gray">none</span>'}</dd>
          <dt>ssh version</dt><dd class="mono">${escapeHtml(p.ssh_version || '—')}</dd>
          <dt>HASSH</dt><dd class="mono">${escapeHtml(p.hassh_server || '—')}</dd>
          <dt>auth methods</dt><dd class="mono">${escapeHtml(p.auth_methods || '—')}</dd>
          <dt>probed</dt><dd class="mono">${escapeHtml(fmtTime(p.probed_at) || '—')}</dd>
        </dl></div>
      </section>
    </div>
    <section class="card">
      <div class="card-head"><h2><svg class="ic"><use href="#i-shield"/></svg> Actions</h2></div>
      <div class="card-body actions-row">
        <button class="btn" data-act="generate" ${exposed || retired ? 'disabled title="not while exposed/retired"' : ''}>Generate host keys</button>
        <button class="btn" data-act="probe" ${retired ? 'disabled' : ''}>Probe backend</button>
        <button class="btn btn-primary" data-act="expose" ${exposed || retired ? 'disabled' : ''}>Expose</button>
        <button class="btn btn-danger" data-act="retire" ${retired ? 'disabled' : ''}>Retire</button>
      </div>
    </section>
    <section class="card">
      <div class="card-head"><h2><svg class="ic"><use href="#i-pulse"/></svg> Registry events</h2></div>
      <div class="card-body">
        ${events.length ? `<div class="timeline">${events.map((ev) => `
          <div class="tl"><span class="tl-time">${escapeHtml(fmtTime(ev.at))}</span><span class="tl-kind">${escapeHtml(ev.event)}</span>${ev.detail ? `<span class="tl-detail">${escapeHtml(ev.detail)}</span>` : ''}</div>`).join('')}</div>`
          : '<div class="empty">No events yet.</div>'}
      </div>
    </section>`;

  for (const btn of view.querySelectorAll('button[data-act]')) {
    btn.addEventListener('click', () => entryAction(e, btn.dataset.act));
  }
}

async function entryAction(e, act) {
  const ip = e.external_ip;
  try {
    if (act === 'generate') {
      await api('/v1/entries/' + encodeURIComponent(ip) + '/persona/generate', { method: 'POST', body: '{}' });
      showToast('Host keys generated', 'success');
    } else if (act === 'probe') {
      const res = await api('/v1/entries/' + encodeURIComponent(ip) + '/probe', { method: 'POST' });
      const problems = (res && res.Problems) || (res && res.problems) || [];
      showToast(problems.length ? ('Probe: ' + problems.length + ' problem(s)') : 'Probe OK', problems.length ? 'info' : 'success');
    } else if (act === 'expose') {
      await api('/v1/entries/' + encodeURIComponent(ip) + '/expose', { method: 'POST' });
      showToast('Entry exposed', 'success');
    } else if (act === 'retire') {
      if (!confirm('Retire ' + ip + '? The proxy will stop serving it.')) return;
      await api('/v1/entries/' + encodeURIComponent(ip) + '/retire', { method: 'POST', body: '{}' });
      showToast('Entry retired', 'success');
    }
    renderEntry(ip);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ---------- audit list ----------

function auditIPFilter() {
  const m = /[?&]ip=([^&]+)/.exec(location.hash);
  return m ? decodeURIComponent(m[1]) : '';
}

const AUDIT_PAGE = 100;

function auditRowHtml(s) {
  return `
    <tr class="clickable" data-day="${escapeHtml(s.day)}" data-id="${escapeHtml(s.id)}">
      <td class="mono">${escapeHtml(fmtTime(s.start))}</td>
      <td><code>${escapeHtml(s.src_ip || '')}</code></td>
      <td><code>${escapeHtml(s.dst_ip || '')}</code></td>
      <td>${s.login_success ? '<span class="pill green">ok</span>' : '<span class="pill gray">—</span>'} ${s.login_attempts || 0}</td>
      <td>${s.commands || 0}</td>
      <td>${s.channels || 0}</td>
      <td>${s.files || 0}</td>
    </tr>`;
}

async function renderAudit() {
  const ip = auditIPFilter();
  view.innerHTML = `
    <div class="page-head">
      <h1><svg class="ic"><use href="#i-pulse"/></svg> Audit sessions${ip ? ` · <code>${escapeHtml(ip)}</code>` : ''}</h1>
      ${ip ? '<a class="btn btn-ghost" href="#/audit">Clear filter</a>' : ''}
    </div>
    <section class="card">
      <div class="table-wrap">
        <table><thead><tr><th>started</th><th>source</th><th>external ip</th><th>logins</th><th>cmds</th><th>casts</th><th>files</th></tr></thead>
        <tbody id="audit-rows"></tbody></table>
        <div class="empty" id="audit-empty" style="display:none">No recorded sessions.</div>
      </div>
      <div class="card-body" style="display:flex;justify-content:center">
        <button class="btn" id="audit-more" style="display:none">Load more</button>
      </div>
    </section>`;

  const tbody = $('audit-rows');
  const emptyBox = $('audit-empty');
  const moreBtn = $('audit-more');
  let offset = 0;

  const loadPage = async () => {
    moreBtn.disabled = true;
    const q = `/v1/audit/sessions?limit=${AUDIT_PAGE}&offset=${offset}` + (ip ? '&ip=' + encodeURIComponent(ip) : '');
    const page = await api(q);
    for (const s of page) {
      tbody.insertAdjacentHTML('beforeend', auditRowHtml(s));
      const tr = tbody.lastElementChild;
      tr.addEventListener('click', () => { location.hash = '#/audit/' + tr.dataset.day + '/' + encodeURIComponent(tr.dataset.id); });
    }
    offset += page.length;
    emptyBox.style.display = offset === 0 ? '' : 'none';
    // a short page means we reached the end
    moreBtn.style.display = page.length === AUDIT_PAGE ? '' : 'none';
    moreBtn.disabled = false;
  };

  moreBtn.addEventListener('click', loadPage);
  await loadPage();
}

// ---------- audit session detail ----------

function eventRow(ev) {
  let cls = '';
  let detail = '';
  switch (ev.eventid) {
    case 'piper.login.success': cls = 'ok'; detail = (ev.username || '') + (ev.password ? ' / ' + ev.password : ''); break;
    case 'piper.login.failed': cls = 'fail'; detail = (ev.username || '') + (ev.password ? ' / ' + ev.password : ''); break;
    case 'piper.command.input': detail = ev.input || ''; break;
    case 'piper.client.version': detail = ev.version || ''; break;
    case 'piper.file.upload':
    case 'piper.file.download': detail = (ev.filename || '') + ' (' + fmtBytes(ev.size) + ')'; break;
    case 'piper.channel.request': detail = ev.request_type || ''; break;
    default: detail = ev.message || '';
  }
  const kind = ev.eventid.replace(/^piper\./, '');
  return `<div class="tl ${cls}"><span class="tl-time">${escapeHtml(fmtTime(ev.timestamp))}</span><span class="tl-kind">${escapeHtml(kind)}</span>${detail ? `<span class="tl-detail">${escapeHtml(detail)}</span>` : ''}</div>`;
}

async function renderAuditSession(day, id) {
  const d = await api('/v1/audit/sessions/' + day + '/' + encodeURIComponent(id));
  const base = '/v1/audit/sessions/' + day + '/' + encodeURIComponent(id);

  const casts = (d.casts || []).map((c) => `
    <button class="btn" data-cast="${escapeHtml(c.channel)}"><svg class="ic"><use href="#i-play"/></svg><span>${escapeHtml(c.channel)} · ${fmtBytes(c.size)}</span></button>`).join('');
  const files = (d.files || []).map((f) => `
    <tr><td><code>${escapeHtml(f.filename || '(no name)')}</code></td><td>${escapeHtml(f.transfer || '')}</td><td>${fmtBytes(f.size)}</td>
      <td class="mono">${escapeHtml(f.sha.slice(0, 16))}…</td>
      <td><a class="btn btn-ghost" href="#" data-file="${escapeHtml(f.sha)}"><svg class="ic"><use href="#i-download"/></svg><span>download</span></a></td></tr>`).join('');

  view.innerHTML = `
    <div class="page-head">
      <h1><a href="#/audit" class="crumbs"><svg class="ic"><use href="#i-back"/></svg></a> Session <code>${escapeHtml(id.slice(0, 8))}</code></h1>
    </div>
    <div class="detail-grid">
      <section class="card"><div class="card-head"><h2>Summary</h2></div><div class="card-body"><dl class="kv">
        <dt>external ip</dt><dd><code>${escapeHtml(d.dst_ip || '')}</code></dd>
        <dt>source</dt><dd><code>${escapeHtml(d.src_ip || '')}:${d.src_port || ''}</code></dd>
        <dt>client</dt><dd class="mono">${escapeHtml(d.client_version || '—')}</dd>
        <dt>HASSH</dt><dd class="mono">${escapeHtml(d.hassh || '—')}</dd>
        <dt>login</dt><dd>${d.login_success ? '<span class="pill green">success</span>' : '<span class="pill gray">none</span>'} · ${d.login_attempts || 0} attempt(s)</dd>
        <dt>start</dt><dd class="mono">${escapeHtml(fmtTime(d.start))}</dd>
        <dt>end</dt><dd class="mono">${escapeHtml(fmtTime(d.end))}</dd>
      </dl></div></section>
      <section class="card"><div class="card-head"><h2>Recordings & files</h2></div><div class="card-body">
        <div class="actions-row">${casts || '<span class="card-sub">No recordings.</span>'}</div>
        ${files ? `<div class="table-wrap" style="margin-top:1rem"><table><thead><tr><th>file</th><th>dir</th><th>size</th><th>sha256</th><th></th></tr></thead><tbody>${files}</tbody></table></div>` : '<p class="card-sub" style="margin-top:1rem">No captured files.</p>'}
      </div></section>
    </div>
    <section class="card"><div class="card-head"><h2><svg class="ic"><use href="#i-pulse"/></svg> Timeline</h2><span class="card-sub">${(d.events || []).length} events</span></div>
      <div class="card-body">${(d.events || []).length ? `<div class="timeline">${d.events.map(eventRow).join('')}</div>` : '<div class="empty">No events.</div>'}</div>
    </section>`;

  for (const btn of view.querySelectorAll('button[data-cast]')) {
    btn.addEventListener('click', () => playCast(base, btn.dataset.cast));
  }
  for (const a of view.querySelectorAll('a[data-file]')) {
    a.addEventListener('click', (e) => { e.preventDefault(); downloadFile(base, a.dataset.file); });
  }
}

async function downloadFile(base, sha) {
  try {
    const r = await apiRaw(base + '/files/' + sha);
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = sha;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  } catch (e) {
    showToast('Download failed: ' + e.message, 'error');
  }
}

// ---------- cast player (xterm) ----------

const viewer = $('viewer');
const viewerOutput = $('viewer-output');
const viewerTitle = $('viewer-title');
const viewerClose = $('viewer-close');
const viewerDownload = $('viewer-download');
let term = null;
let fitAddon = null;
let castAbort = false;
let currentCast = null;

function ensureTerminal() {
  if (term) return;
  term = new Terminal({
    convertEol: true, cursorBlink: false, disableStdin: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 13, scrollback: 5000,
    theme: { background: '#000000', foreground: '#eeeeee' },
  });
  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(viewerOutput);
  if (typeof ResizeObserver === 'function') {
    const ro = new ResizeObserver(() => { try { fitAddon.fit(); } catch (e) { /* ignore */ } });
    ro.observe(viewerOutput);
  }
}

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

async function playCast(base, channel) {
  let text;
  try {
    const r = await apiRaw(base + '/cast/' + channel);
    text = await r.text();
  } catch (e) {
    showToast('Cannot load recording: ' + e.message, 'error');
    return;
  }
  const lines = text.split('\n').filter((l) => l.length);
  const frames = [];
  for (let i = 1; i < lines.length; i++) {
    try { const f = JSON.parse(lines[i]); if (Array.isArray(f) && f.length >= 3) frames.push(f); } catch (e) { /* ignore */ }
  }

  viewerTitle.textContent = channel;
  currentCast = { base, channel };
  ensureTerminal();
  if (typeof viewer.showModal === 'function') viewer.showModal(); else viewer.setAttribute('open', '');
  term.reset();
  requestAnimationFrame(() => { try { fitAddon.fit(); } catch (e) { /* ignore */ } });

  castAbort = false;
  let prev = frames.length ? frames[0][0] : 0;
  for (const f of frames) {
    if (castAbort) return;
    const gap = Math.min(Math.max(0, f[0] - prev), 2) * 1000;
    if (gap > 0) await sleep(gap);
    if (castAbort) return;
    if (f[1] === 'o' || f[1] === 'i') term.write(f[2]);
    prev = f[0];
  }
}

function closeViewer() {
  castAbort = true;
  if (viewer.open) { try { viewer.close(); } catch (e) { viewer.removeAttribute('open'); } }
}
viewerClose.addEventListener('click', closeViewer);
viewer.addEventListener('close', () => { castAbort = true; });
viewer.addEventListener('cancel', () => { castAbort = true; });
viewerDownload.addEventListener('click', (e) => {
  e.preventDefault();
  if (currentCast) downloadCast(currentCast.base, currentCast.channel);
});

async function downloadCast(base, channel) {
  try {
    const r = await apiRaw(base + '/cast/' + channel);
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = channel;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  } catch (err) {
    showToast('Download failed: ' + err.message, 'error');
  }
}

// ---------- version ----------

async function loadMeta() {
  try {
    const r = await fetch('/v1/healthz');
    $('meta').textContent = r.ok ? 'connected' : 'unreachable';
  } catch (e) { $('meta').textContent = 'unreachable'; }
}

// ---------- wiring ----------

loginForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const t = loginToken.value.trim();
  if (!t) return;
  setToken(t);
  loginToken.value = '';
  loginError.textContent = '';
  try { loginDialog.close(); } catch (err) { loginDialog.removeAttribute('open'); }
  loadMeta();
  route();
});

$('refresh').addEventListener('click', () => route());
$('signout').addEventListener('click', () => {
  setToken('');
  showToast('Token forgotten', 'info', 1800);
  requireLogin();
});

window.addEventListener('hashchange', route);

// ---------- bootstrap ----------

(async () => {
  if (getToken()) {
    await loadMeta();
    route();
  } else {
    requireLogin();
  }
})();
