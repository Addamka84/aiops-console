'use strict';
/* aiops console UI: vanilla JS, no build step, no external resources. Everything is built with DOM nodes and text nodes (never parsed as markup). */

// ---------------------------------------------------------------- helpers
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (['value', 'checked', 'disabled', 'selected', 'readOnly'].includes(k)) e[k] = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}
const clone = (o) => JSON.parse(JSON.stringify(o));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const storage = {
  get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* ignore */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch (e) { /* ignore */ } },
};
const fmtTime = (iso) => { if (!iso) return '-'; const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString(); };
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const S = {
  token: storage.get('token') || '', role: null, actor: '', tab: storage.get('tab') || 'status',
  snoozes: [], snoozeHours: 24, known: null, base: null, draft: null, test: null, testHours: 24, testError: '', diff: null, comment: '',
  timer: null, proposalsPending: 0,
};
let toastTimer = null;

async function api(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: Object.assign({ Authorization: 'Bearer ' + S.token }, body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const txt = await r.text();
  let data = null;
  try { data = JSON.parse(txt); } catch (e) { /* not JSON */ }
  if (!r.ok) {
    const err = new Error(errText(r.status, data, txt));
    err.status = r.status;
    throw err;
  }
  return data;
}
function errText(status, data, txt) {
  const d = data && data.detail;
  if (d && d.errors) return d.errors.join('\n');
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.map((x) => (x.loc ? x.loc.join('.') + ': ' : '') + x.msg).join('\n');
  return 'HTTP ' + status + (txt ? ': ' + txt.slice(0, 200) : '');
}
function toast(msg, bad) {
  let box = document.getElementById('toast');
  if (!box) { box = h('div', { id: 'toast' }); document.body.append(box); }
  const t = h('div', { class: bad ? 'bad' : '' }, msg);
  box.append(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}
function sevBadge(s) { return h('span', { class: 'badge sev-' + (s || 'info') }, s || 'info'); }
function stateBadge(s) { return h('span', { class: 'badge b-' + s }, s); }
function diffEl(text) {
  const pre = h('pre', { class: 'diff' });
  if (!text) { pre.append('(no changes)'); return pre; }
  for (const line of text.split('\n')) {
    const cls = line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@') ? 'hunk' : line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : '';
    pre.append(h('span', { class: cls }, line + '\n'));
  }
  return pre;
}
const isAdmin = () => S.role === 'admin';

// ---------------------------------------------------------------- shell
// [id, label, group]: the side menu shows the groups; on a narrow screen it becomes one scrollable row.
const TABS = [['status', 'Status', 'Monitor'], ['incidents', 'Incidents', 'Monitor'], ['history', 'History', 'Monitor'],
  ['known', 'Noise & known issues', 'Configure'], ['topology', 'Topology', 'Configure'], ['detectors', 'Detectors', 'Configure'], ['rules', 'Alert rules', 'Configure'], ['ingest', 'Severity & ingest', 'Configure'], ['settings', 'Settings', 'Configure'],
  ['supervisor', 'Supervisor', 'AI'], ['proposals', 'Proposals', 'AI']];

// The version comes from the open health endpoint, so it is also shown on the sign-in page.
async function loadVersion() {
  if (S.version) return;
  try { const r = await fetch('/api/v1/health'); const j = await r.json(); S.version = (j && j.version) || ''; } catch (e) { /* the version is optional */ }
}
const verEl = () => (S.version ? h('span', { class: 'ver muted', title: 'aiops-console version' }, 'v' + S.version) : null);

function renderShell(content) {
  const app = document.getElementById('app');
  const items = [];
  let grp = null;
  for (const [id, label, g] of TABS) {
    if (g !== grp) { grp = g; items.push(h('div', { class: 'grp' }, g)); }
    items.push(h('button', { class: S.tab === id ? 'on' : '', onclick: () => go(id), 'aria-current': S.tab === id ? 'page' : null },
      h('span', {}, label), id === 'proposals' && S.proposalsPending ? h('span', { class: 'cnt', title: 'Pending proposals' }, S.proposalsPending) : null));
  }
  app.replaceChildren(
    h('header', {}, h('div', { class: 'bar' },
      h('span', { class: 'brand' }, 'aiops console ', verEl()),
      h('span', { class: 'grow' }),
      h('span', { class: 'badge ' + (isAdmin() ? 'b-up' : 'b-unknown'), title: S.actor }, S.role),
      h('button', { class: 'btn', onclick: signOut }, 'Sign out'))),
    h('div', { class: 'layout' }, h('nav', { class: 'side', 'aria-label': 'Sections' }, items), h('main', {}, content)));
  stackTables(app);
}
// Phone layout: tables with a header row become cards (CSS under 640 px); each cell gets its column name as data-l.
function stackTables(root) {
  for (const t of root.querySelectorAll('table')) {
    const hr = t.tHead && t.tHead.rows[0];
    if (!hr || t.classList.contains('stack')) continue;
    const labels = [...hr.cells].map((c) => c.textContent.trim());
    for (const b of t.tBodies) for (const r of b.rows) [...r.cells].forEach((c, i) => { if (labels[i]) c.setAttribute('data-l', labels[i]); });
    t.classList.add('stack');
  }
}
function go(tab) {
  S.tab = tab; storage.set('tab', tab);
  clearInterval(S.timer); S.timer = null;
  render();
}
function signOut() { storage.del('token'); S.token = ''; S.role = null; clearInterval(S.timer); render(); }

async function render() {
  if (S.tab !== 'status' && S.timer) { clearInterval(S.timer); S.timer = null; }
  await loadVersion();
  if (!S.token) return renderLogin();
  if (!S.role) {
    try {
      const w = await api('GET', '/api/v1/whoami');
      S.role = w.role; S.actor = w.actor;
    } catch (e) { return renderLogin(e.status === 401 ? 'Invalid token.' : e.message); }
  }
  refreshPendingCount();
  const page = { status: pageStatus, incidents: pageIncidents, known: pageKnown, topology: pageTopology, detectors: pageDetectors, rules: pageRules, ingest: pageIngest, supervisor: pageSupervisor, settings: pageSettings, proposals: pageProposals, history: pageHistory }[S.tab] || pageStatus;
  try { await page(); } catch (e) {
    if (e.status === 401) { storage.del('token'); S.token = ''; S.role = null; return renderLogin('Session expired.'); }
    renderShell(h('div', { class: 'err' }, e.message));
  }
}
async function refreshPendingCount() {
  try { S.proposalsPending = (await api('GET', '/api/v1/proposals?status=pending&limit=200')).length; } catch (e) { /* ignore */ }
}

function renderLogin(msg) {
  const inp = h('input', { type: 'password', class: 'mono grow', placeholder: 'API token (read or admin)', autocomplete: 'off' });
  const go_ = async () => {
    S.token = inp.value.trim(); S.role = null;
    storage.set('token', S.token);
    render();
  };
  inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') go_(); });
  document.getElementById('app').replaceChildren(h('div', { class: 'login panel' },
    h('h2', {}, 'aiops console ', verEl()),
    h('p', { class: 'muted' }, 'Enter your API token. It is kept for this browser tab only.'),
    msg ? h('div', { class: 'err' }, msg) : null,
    h('div', { class: 'row' }, inp, h('button', { class: 'btn primary', onclick: go_ }, 'Sign in'))));
  inp.focus();
}

// ---------------------------------------------------------------- status
function issueList(issues) {
  if (!issues || !issues.length) return h('p', { class: 'muted' }, 'No issues reported.');
  return issues.map((i) => h('div', { class: 'issue' },
    h('div', { class: 'row' }, sevBadge(i.severity), h('strong', {}, i.title || i.id), h('span', { class: 'muted small' }, [i.status, (i.hosts || []).join(', ')].filter(Boolean).join(' · '))),
    h('details', {}, h('summary', { class: 'muted small' }, 'Details'),
      h('dl', { class: 'kv small' },
        h('dt', {}, 'Evidence'), h('dd', {}, i.evidence || '-'),
        h('dt', {}, 'Likely cause'), h('dd', {}, i.likely_cause || '-'),
        h('dt', {}, 'Suggested action'), h('dd', {}, i.suggested_action || '-')))));
}
function resultCard(title, r) {
  if (!r) return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, title), h('p', { class: 'muted' }, 'Nothing yet.'));
  return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, title),
    h('p', { class: 'muted small' }, [r.model, r.endpoint, r.window || r.alert].filter(Boolean).join(' · ')),
    r.correlation ? h('p', { class: 'small' }, h('span', { class: 'badge sev-low' }, 'correlated'), ' ' + (r.correlated_alerts || 1) + ' alert(s) grouped via the topology',
      r.correlation.root ? ' · root hypothesis: ' + r.correlation.root + ' (confidence ' + r.correlation.confidence + ')' : '',
      r.correlation.suspected_dependency ? ' · suspected shared dependency: ' + r.correlation.suspected_dependency.ci : '',
      r.ungrounded_hosts ? ' · ' + r.ungrounded_hosts + ' invented name(s) removed from the model output' : '') : null,
    h('p', {}, r.summary || ''), issueList(r.issues));
}
// ---------------------------------------------------------------- incidents (list, timeline, state, notes, feedback)
S.inc = { hours: 168, state: 'unresolved', list: null, quality: null, sel: null, detail: null, error: '', note: '', owner: '',
  fb: { root_cause: 'correct', severity: 'right', grouping: 'right', comment: '' } };
const INC_STATE_CLS = { open: 'b-pending', acknowledged: 'b-ok', resolved: 'b-approved' };
const FB_OPTS = { root_cause: [['correct', 'Root cause correct'], ['wrong', 'Root cause wrong'], ['unsure', 'Not sure'], ['n/a', 'No root cause given']],
  severity: [['right', 'Severity right'], ['too_high', 'Severity too high'], ['too_low', 'Severity too low']],
  grouping: [['right', 'Grouping right'], ['should_split', 'Should be split'], ['should_merge', 'Should be merged'], ['n/a', 'Single alert']] };
const fbLabel = (k, v) => ((FB_OPTS[k].find((o) => o[0] === v) || [v, v])[1]);
async function loadIncList() {
  const x = S.inc;
  try {
    [x.list, x.quality] = await Promise.all([api('GET', '/api/v1/incidents?hours=' + x.hours + '&state=' + x.state),
      api('GET', '/api/v1/incidents/quality?days=30')]);
    x.error = '';
  } catch (e) { x.error = e.message; x.list = x.list || []; }
}
async function loadIncDetail() {
  const x = S.inc;
  if (!x.sel) { x.detail = null; return; }
  try {
    x.detail = await api('GET', '/api/v1/incidents/' + encodeURIComponent(x.sel));
    x.owner = x.detail.owner || '';
    if (x.detail.feedback) x.fb = Object.assign({ comment: '' }, x.detail.feedback);
  } catch (e) { x.detail = null; x.error = e.message; }
}
async function pageIncidents() { await loadIncList(); await loadIncDetail(); drawInc(); }
async function incSelect(id) {
  S.inc.sel = id; S.inc.note = ''; S.inc.fb = { root_cause: 'correct', severity: 'right', grouping: 'right', comment: '' };
  await loadIncDetail(); drawInc();
  const d = document.getElementById('inc-detail'); if (d) d.scrollIntoView({ block: 'start' });
}
async function incPost(path, body, msg) {
  try { await api('POST', '/api/v1/incidents/' + encodeURIComponent(S.inc.sel) + path, body); toast(msg); } catch (e) { toast(e.message, true); return; }
  await loadIncList(); await loadIncDetail(); drawInc();
}
function pctOf(r) { return r && r.rated ? r.good + '/' + r.rated + ' (' + Math.round(r.rate * 100) + '%)' : 'no ratings yet'; }
function incTimeline(d) {
  const ev = [{ ts: d.time, who: 'alerting', what: (d.alert_items.length ? d.alert_items.length + ' alert(s) grouped' : 'Alert') + (d.root_hypothesis ? ' · root hypothesis ' + d.root_hypothesis : '') },
    { ts: d.time, who: 'model', what: 'AI triage: ' + d.issue_count + ' issue(s), max ' + (d.max_severity || 'none') + (d.secs ? ' · ' + d.secs + ' s' : '') }];
  for (const e of d.events) {
    const b = e.body || {};
    const what = e.kind === 'state' ? 'State ' + b.from + ' → ' + b.to + (b.owner !== undefined ? ' · owner ' + (b.owner || '-') : '')
      : e.kind === 'note' ? 'Note: ' + b.text
        : 'Feedback: ' + ['root_cause', 'severity', 'grouping'].map((k) => fbLabel(k, b[k])).join(', ') + (b.comment ? ' · ' + b.comment : '');
    ev.push({ ts: e.ts, who: e.actor, what });
  }
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Who'), h('th', {}, 'What'))),
    h('tbody', {}, ev.map((e) => h('tr', {}, h('td', { class: 'nowrap small' }, fmtTime(e.ts)), h('td', { class: 'small nowrap' }, e.who), h('td', { class: 'small' }, e.what)))));
}
function incDetailEl(d) {
  const x = S.inc;
  const sel = (k) => h('select', { onchange: (e) => { x.fb[k] = e.target.value; } }, FB_OPTS[k].map(([v, l]) => h('option', { value: v, selected: x.fb[k] === v }, l)));
  const st = d.state;
  const actions = isAdmin() ? h('div', { style: 'margin-top:12px' },
    h('div', { class: 'row' },
      h('input', { placeholder: 'owner (optional)', value: x.owner, style: 'width:180px', oninput: (e) => { x.owner = e.target.value; } }),
      st !== 'acknowledged' && st !== 'resolved' ? h('button', { class: 'btn primary', onclick: () => incPost('/state', { state: 'acknowledged', owner: x.owner }, 'Acknowledged') }, 'Acknowledge') : null,
      st !== 'resolved' ? h('button', { class: 'btn', onclick: () => incPost('/state', { state: 'resolved', owner: x.owner }, 'Resolved') }, 'Resolve')
        : h('button', { class: 'btn', onclick: () => incPost('/state', { state: 'open', owner: x.owner }, 'Reopened') }, 'Reopen')),
    h('h3', {}, 'Was the triage right?'),
    h('p', { class: 'muted small' }, 'Your answer is the measurement: the quality figures at the top come from it. The latest answer counts; earlier ones stay in the timeline.'),
    h('div', { class: 'row' }, sel('root_cause'), sel('severity'), sel('grouping')),
    h('div', { class: 'row', style: 'margin-top:6px' },
      h('input', { class: 'grow', placeholder: 'Comment (optional): what was the real cause?', value: x.fb.comment || '', oninput: (e) => { x.fb.comment = e.target.value; } }),
      h('button', { class: 'btn primary', onclick: () => incPost('/feedback', x.fb, 'Feedback saved') }, d.feedback ? 'Update feedback' : 'Save feedback')),
    h('h3', {}, 'Note'),
    h('div', { class: 'row' },
      h('input', { class: 'grow', placeholder: 'What did you find or do?', value: x.note, oninput: (e) => { x.note = e.target.value; } }),
      h('button', { class: 'btn', onclick: () => { if (x.note.trim()) incPost('/notes', { text: x.note }, 'Note added'); } }, 'Add note')))
    : h('p', { class: 'muted small' }, 'Admin token required to change the state, add notes or give feedback.');
  return h('div', { class: 'panel', id: 'inc-detail' },
    h('div', { class: 'row' }, sevBadge(d.max_severity || 'info'), h('h3', { style: 'margin:0' }, d.title), h('span', { class: 'grow' }),
      h('span', { class: 'badge ' + (INC_STATE_CLS[st] || 'b-unknown') }, st), d.owner ? h('span', { class: 'muted small' }, 'owner: ' + d.owner) : null,
      h('button', { class: 'icon', title: 'Close', onclick: () => { x.sel = null; x.detail = null; drawInc(); } }, '×')),
    h('p', { class: 'muted small' }, [fmtTime(d.time), d.model, d.window].filter(Boolean).join(' · ')),
    d.correlated_alerts > 1 || d.root_hypothesis ? h('p', { class: 'small' }, h('span', { class: 'badge sev-low' }, 'correlated'),
      ' ' + d.correlated_alerts + ' alert(s) grouped via the topology' + (d.root_hypothesis ? ' · root hypothesis: ' + d.root_hypothesis + ' (confidence ' + d.root_confidence + ')' : '')) : null,
    h('p', {}, d.summary),
    d.alert_items.length ? h('details', {}, h('summary', { class: 'small' }, 'Grouped alerts (' + d.alert_items.length + ')'),
      h('ul', { class: 'small mono' }, d.alert_items.map((t) => h('li', {}, t)))) : h('p', { class: 'small mono muted' }, d.alert),
    issueList(d.issues),
    d.guard_notes.length ? h('div', { class: 'note small' }, 'Guards changed the model output: ' + d.guard_notes.join('; ')) : null,
    h('h3', {}, 'Timeline'), incTimeline(d),
    actions);
}
function drawInc() {
  const x = S.inc, q = x.quality;
  const rows = (x.list || []).map((i) => h('tr', { class: i.id === x.sel ? 'sel' : '', style: 'cursor:pointer', onclick: () => incSelect(i.id) },
    h('td', { class: 'nowrap small' }, fmtTime(i.time)), h('td', {}, sevBadge(i.max_severity || 'info')),
    h('td', {}, i.title, i.root_hypothesis ? h('div', { class: 'muted small' }, 'root hypothesis: ' + i.root_hypothesis) : null),
    h('td', { class: 'num' }, i.correlated_alerts), h('td', {}, h('span', { class: 'badge ' + (INC_STATE_CLS[i.state] || 'b-unknown') }, i.state), i.owner ? h('div', { class: 'muted small' }, i.owner) : null),
    h('td', { class: 'small' }, i.feedback ? fbLabel('root_cause', i.feedback.root_cause) : h('span', { class: 'muted' }, '-'))));
  renderShell([
    h('h2', {}, 'Incidents'),
    h('p', { class: 'muted' }, 'AI-triaged incidents with their state, notes and your feedback. The incident itself is stored in VictoriaLogs; the state, notes and feedback are kept by the console and audited.'),
    q ? h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Triage quality (last 30 days, from your feedback)'),
      h('div', { class: 'stats' },
        h('div', { class: 'stat' }, h('div', { class: 'big' }, q.with_feedback + ' / ' + q.incidents), h('div', { class: 'small muted' }, 'incidents with feedback')),
        h('div', { class: 'stat' }, h('div', { class: 'big' }, pctOf(q.root_cause)), h('div', { class: 'small muted' }, 'root cause correct')),
        h('div', { class: 'stat' }, h('div', { class: 'big' }, pctOf(q.severity)), h('div', { class: 'small muted' }, 'severity right (' + q.severity_too_high + ' too high, ' + q.severity_too_low + ' too low)')),
        h('div', { class: 'stat' }, h('div', { class: 'big' }, pctOf(q.grouping)), h('div', { class: 'small muted' }, 'grouping right')))) : null,
    x.error ? h('div', { class: 'err' }, x.error) : null,
    x.detail ? incDetailEl(x.detail) : null,
    h('div', { class: 'panel' },
      h('div', { class: 'row' },
        h('select', { onchange: async (e) => { x.state = e.target.value; await loadIncList(); drawInc(); } },
          [['unresolved', 'Not resolved'], ['all', 'All'], ['open', 'Open'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved']].map(([v, l]) => h('option', { value: v, selected: v === x.state }, l))),
        h('select', { onchange: async (e) => { x.hours = Number(e.target.value); await loadIncList(); drawInc(); } },
          [[24, 'Last 24 h'], [168, 'Last 7 days'], [720, 'Last 30 days']].map(([v, l]) => h('option', { value: v, selected: v === x.hours }, l))),
        h('span', { class: 'muted small' }, (x.list || []).length + ' incident(s)')),
      rows.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Time', 'Severity', 'Incident', 'Alerts', 'State', 'Feedback'].map((t) => h('th', {}, t)))), h('tbody', {}, rows))
        : h('p', { class: 'muted' }, 'No incidents in this view.')),
  ]);
}

// ---------------------------------------------------------------- statistics (review of the last check, log volume chart)
const SVGNS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v); }
  for (const c of kids.flat(Infinity)) { if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c))); }
  return e;
}
const fmtN = (n) => (n === undefined || n === null ? '-' : Number(n).toLocaleString());
const fmtShort = (n) => (n >= 1e6 ? +(n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? +(n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k' : String(n));
function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}
S.stats = { hours: 24, by: 'pipeline', runs: null, volume: null, error: '', at: 0 };
async function loadStats(force) {
  const st = S.stats;
  if (!force && Date.now() - st.at < 60000) return;
  st.at = Date.now();
  try {
    const [runs, volume] = await Promise.all([
      api('GET', '/api/v1/stats/runs?kind=all&limit=14'),
      api('GET', '/api/v1/stats/volume?hours=' + st.hours + '&by=' + st.by)]);
    st.runs = runs; st.volume = volume; st.error = '';
  } catch (e) { st.error = e.message; }
}
function volumeChart(v) {
  const W = 760, H = 230, L = 50, R = 8, T = 8, B = 26;
  const n = v.series.length ? v.series[0].points.length : 0;
  if (!n) return h('p', { class: 'muted' }, 'No data in this window.');
  const sums = Array.from({ length: n }, (_, i) => v.series.reduce((a, s) => a + s.points[i], 0));
  const ymax = niceMax(Math.max(...sums));
  const bw = (W - L - R) / n, y = (val) => T + (H - T - B) * (1 - val / ymax);
  const t0 = Date.parse(v.from);
  const svg = svgEl('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart', role: 'img', 'aria-label': 'Log messages per ' + (v.step_s / 3600 >= 1 ? v.step_s / 3600 + ' h' : v.step_s / 60 + ' min') });
  for (let g = 0; g <= 4; g++) {
    const val = (ymax * g) / 4;
    svg.append(svgEl('line', { x1: L, x2: W - R, y1: y(val), y2: y(val), class: 'grid-line' }), svgEl('text', { x: L - 6, y: y(val) + 4, class: 'axis', 'text-anchor': 'end' }, fmtShort(val)));
  }
  const every = Math.max(1, Math.ceil(n / 8));
  for (let i = 0; i < n; i++) {
    let acc = 0;
    v.series.forEach((s, k) => {
      const c = s.points[i];
      if (!c) return;
      const top = y(acc + c), hgt = y(acc) - top;
      acc += c;
      svg.append(svgEl('rect', { x: L + i * bw + 0.5, y: top, width: Math.max(bw - 1, 1), height: Math.max(hgt, 0.5), class: 'c' + (k % 8) },
        svgEl('title', {}, s.name + ': ' + fmtN(c) + ' · ' + new Date(t0 + i * v.step_s * 1000).toLocaleString())));
    });
    if (i % every === 0) {
      const d = new Date(t0 + i * v.step_s * 1000);
      svg.append(svgEl('text', { x: L + i * bw + bw / 2, y: H - 8, class: 'axis', 'text-anchor': 'middle' }, v.hours > 24 ? d.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' }) + ' ' + d.getHours() + 'h' : String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0')));
    }
  }
  const legend = h('div', { class: 'legend' }, v.series.map((s, k) => h('span', { class: 'lg' }, h('i', { class: 'sw c' + (k % 8) }), s.name, ' ', h('span', { class: 'muted' }, fmtN(s.total)))));
  return h('div', {}, svg, legend);
}
function reviewCard(r) {
  if (!r) return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Last check reviewed'), h('p', { class: 'muted' }, 'No check with statistics yet (they are recorded from v1.4.0 on).'));
  const st = r.stats || {};
  const cell = (label, val, sub) => h('div', { class: 'stat' }, h('div', { class: 'big' }, val), h('div', { class: 'small' }, label), sub ? h('div', { class: 'muted small' }, sub) : null);
  const removed = (st.noise_lines || 0) + (st.snoozed_lines || 0);
  const src = st.by_source ? Object.entries(st.by_source).sort((a, b) => b[1] - a[1]).map(([k, v]) => k + ' ' + fmtN(v)).join(' · ') : '';
  return h('div', { class: 'panel' },
    h('h3', { style: 'margin-top:0' }, 'Last check reviewed'),
    h('p', { class: 'muted small' }, [r.kind, fmtTime(r.time), (st.hours ? 'window ' + st.hours + ' h' : ''), r.model, r.secs + ' s'].filter(Boolean).join(' · ')),
    h('div', { class: 'stats' },
      cell('log lines in the window', fmtN(st.window_lines), src),
      cell('warning/error-like lines checked', fmtN(st.candidate_lines), fmtN(st.patterns) + ' distinct patterns'),
      cell('removed as noise / snoozed', fmtN(removed), 'snoozed ' + fmtN(st.snoozed_lines || 0)),
      cell('already-known issues', fmtN(st.known_lines)),
      cell('sent to the model', fmtN(st.kept_patterns) + ' patterns', fmtN(st.kept_lines) + ' lines'),
      cell('issues reported', fmtN(r.issue_count), r.dropped_known ? r.dropped_known + ' known dropped' : '')));
}
function runsTable(runs) {
  if (!runs || !runs.length) return null;
  const row = (r) => { const st = r.stats || {}; return h('tr', {},
    h('td', { class: 'small nowrap' }, fmtTime(r.time)), h('td', {}, r.kind),
    h('td', { class: 'num' }, fmtN(st.window_lines)), h('td', { class: 'num' }, fmtN(st.candidate_lines)),
    h('td', { class: 'num' }, fmtN((st.noise_lines || 0) + (st.snoozed_lines || 0))), h('td', { class: 'num' }, fmtN(st.kept_patterns)),
    h('td', { class: 'num' }, r.issue_count ? sevBadge(r.max_severity) : '0'), h('td', { class: 'num' }, r.secs + ' s')); };
  return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Recent checks'),
    h('table', {}, h('thead', {}, h('tr', {}, ['Time', 'Kind', 'Lines in window', 'Checked', 'Removed', 'To model', 'Issues', 'Took'].map((x, i) => h('th', { class: i > 1 ? 'num' : '' }, x)))),
      h('tbody', {}, runs.map(row))));
}
function volumePanel() {
  const st = S.stats;
  const sel = (key, opts) => h('select', { onchange: async (e) => { st[key] = key === 'hours' ? Number(e.target.value) : e.target.value; await loadStats(true); pageStatus().catch(() => {}); } },
    opts.map(([v, l]) => h('option', { value: v, selected: v === st[key] }, l)));
  return h('div', { class: 'panel' },
    h('div', { class: 'row' }, h('h3', { class: 'grow', style: 'margin:0' }, 'Log volume (messages in VictoriaLogs)'),
      sel('hours', [[6, '6 h'], [24, '24 h'], [72, '3 days'], [168, '7 days']]),
      sel('by', [['pipeline', 'by source type'], ['host', 'by host']])),
    st.error ? h('div', { class: 'err' }, 'Statistics unavailable: ' + st.error) : null,
    st.volume ? h('p', { class: 'muted small' }, fmtN(st.volume.total) + ' messages in the window. Hover a bar for details.') : null,
    st.volume ? volumeChart(st.volume) : null);
}
// New log patterns / rate spikes found by the detector (report mode). Everything is rendered as text.
S.novelty = { data: null, error: '' };
async function loadNovelty() {
  try { S.novelty.data = await api('GET', '/api/v1/novelty?status=open&limit=500'); S.novelty.error = ''; } catch (e) { S.novelty.error = e.message; }
}
// View state of the findings list: level filter (default: warning and above), grouping by host, open groups, rows shown when ungrouped.
S.novUi = { level: 'warn', group: true, open: {}, shown: 100 };
const WARN_UP = ['emerg', 'alert', 'crit', 'critical', 'err', 'error', 'warning'];
const lvlSev = (l) => (['emerg', 'alert', 'crit', 'err', 'error'].includes(l) ? 'high' : l === 'warning' ? 'medium' : 'info');
async function noveltyDo(fn) {
  try { await fn(); } catch (e) { toast(e.message, true); }
  await loadNovelty(); pageStatus().catch(() => {});
}
function noveltyPanel() {
  const title = h('h3', { class: 'grow', style: 'margin:0' }, 'New patterns & rate spikes');
  const n = S.novelty.data;
  if (!n) return h('div', { class: 'panel' }, h('div', { class: 'row' }, title), S.novelty.error ? h('div', { class: 'err' }, 'Unavailable: ' + S.novelty.error) : null);
  const st = n.status, f = n.findings;
  const learning = st.learning_until && new Date(st.learning_until) > new Date();
  const info = st.mode !== 'report' ? 'The detector is off (setting NOVELTY_MODE).'
    : st.backfill === 'running' ? 'Building the baseline from stored logs, findings start afterwards.'
      : [fmtN(st.patterns) + ' patterns in the baseline', st.last_scan ? 'last scan ' + fmtTime(st.last_scan) : 'first scan pending',
        learning ? 'learning until ' + fmtTime(st.learning_until) + ' (no findings yet)' : '',
        st.error ? 'last error: ' + st.error : '', st.truncated && st.truncated.length ? 'very many distinct messages in: ' + st.truncated.join(', ') : '',
        n.advisor && n.advisor.state === 'ready' ? 'noise advisor: ' + f.filter((x) => x.likely_noise).length + ' of ' + f.length + ' marked likely noise (advisory)'
          : n.advisor && (n.advisor.state === 'learning' || n.advisor.state === 'training') ? 'noise advisor is learning'
            : n.advisor && n.advisor.state === 'insufficient' ? 'noise advisor: not enough labelled patterns yet' : ''].filter(Boolean).join(' · ');
  const text = (x) => x.host + ' | ' + x.ident + ' | ' + x.tmpl;
  const row = (x) => h('tr', {},
    h('td', { class: 'small nowrap' }, fmtTime(x.ts)),
    h('td', {}, h('span', { class: 'badge sev-' + (x.kind === 'spike' ? 'medium' : 'low') }, x.kind)),
    h('td', {}, h('span', { class: 'badge sev-' + lvlSev(x.level) }, x.level)),
    h('td', { class: 'small' }, x.host, h('div', { class: 'muted' }, x.ident)),
    h('td', { class: 'mono small', style: 'word-break:break-word' }, x.tmpl,
      x.likely_noise ? h('div', {}, h('span', { class: 'badge sev-low', title: 'Advisory only (score ' + x.noise_score + '): similar to lines your noise rules already cover. Nothing is filtered; review it, then add a rule or dismiss.' }, 'likely noise')) : null),
    h('td', { class: 'num small nowrap' }, fmtN(x.hits) + 'x', x.kind === 'spike' ? h('div', { class: 'muted' }, 'usual ~' + x.baseline) : null),
    h('td', { class: 'nowrap' },
      h('button', { class: 'btn', title: 'Propose a noise rule for this line (review it on the Proposals page)', onclick: () => noveltyDo(async () => {
        const r = await api('POST', '/api/v1/proposals', { key: 'known', comment: 'noise from the novelty detector: ' + x.ident, patch: { add_noise: [ruleFromLine(text(x))] } });
        toast('Proposal #' + r.id + ' created.'); refreshPendingCount();
      }) }, '+ noise'), ' ',
      h('button', { class: 'btn', title: 'Draft a detector for this pattern (alert when it appears): files a proposal with a 7-day backtest; the detector stays disabled until you approve and enable it', onclick: () => noveltyDo(async () => {
        const r = await api('POST', '/api/v1/novelty/' + x.id + '/detector-draft');
        toast('Detector proposal #' + r.id + ' created (' + r.backtest.firings + ' firing(s) in ' + (r.backtest.hours / 24) + ' days).'); refreshPendingCount();
      }) }, '+ detector'), ' ',
      isAdmin() ? h('button', { class: 'btn', title: 'Mark as reviewed (hides it from this list and the digest)', onclick: () => noveltyDo(() => api('POST', '/api/v1/novelty/' + x.id + '/dismiss')) }, 'Dismiss') : null));
  const ui = S.novUi;
  const redraw = () => pageStatus().catch(() => {});
  const visible = ui.level === 'all' ? f : f.filter((x) => WARN_UP.includes(x.level));
  const hidden = f.length - visible.length;
  const likely = visible.filter((x) => x.likely_noise);
  const dismissIds = (ids, what) => confirm('Dismiss ' + ids.length + ' finding(s)' + (what ? ' ' + what : '') + '? They disappear from this list and the digest; nothing else changes.')
    && noveltyDo(() => api('POST', '/api/v1/novelty/dismiss', { ids: ids.slice(0, 500) }));
  const tbl = (rows) => h('table', {}, h('thead', {}, h('tr', {}, ['Found', 'Kind', 'Level', 'Source', 'Message pattern', 'Count', ''].map((x, i) => h('th', { class: i === 5 ? 'num' : '' }, x)))),
    h('tbody', {}, rows.map(row)));
  const byHost = new Map();
  for (const x of visible) { if (!byHost.has(x.host)) byHost.set(x.host, []); byHost.get(x.host).push(x); }
  const lvCount = (rows) => Object.entries(rows.reduce((a, x) => (a[x.level] = (a[x.level] || 0) + 1, a), {})).map(([l, c]) => l + ' ' + c).join(' · ');
  const groups = [...byHost.entries()].sort((a, b) => (b[1].filter((x) => WARN_UP.includes(x.level)).length - a[1].filter((x) => WARN_UP.includes(x.level)).length) || (b[1].length - a[1].length));
  const group = ([host, rows]) => {
    const det = h('details', { open: ui.open[host] === undefined ? groups.length <= 2 : ui.open[host], ontoggle: () => { ui.open[host] = det.open; } },
      h('summary', {}, h('strong', {}, host), ' ', h('span', { class: 'badge b-unknown' }, rows.length), ' ', h('span', { class: 'muted small' }, lvCount(rows)),
        rows.some((x) => x.likely_noise) ? h('span', { class: 'muted small' }, ' · likely noise ' + rows.filter((x) => x.likely_noise).length) : null,
        isAdmin() ? h('button', { class: 'btn', style: 'margin-left:8px', title: 'Dismiss every finding of this host in the current view',
          onclick: (ev) => { ev.preventDefault(); ev.stopPropagation(); dismissIds(rows.map((x) => x.id), 'of ' + host); } }, 'Dismiss ' + rows.length) : null),
      tbl(rows));
    return det;
  };
  const shown = visible.slice(0, ui.shown);
  const lvlSel = h('select', { 'aria-label': 'Level filter', onchange: () => { ui.level = lvlSel.value; redraw(); } },
    h('option', { value: 'warn', selected: ui.level === 'warn' }, 'Warning and above'), h('option', { value: 'all', selected: ui.level === 'all' }, 'Everything'));
  const grpBox = h('input', { type: 'checkbox', checked: ui.group, onchange: () => { ui.group = grpBox.checked; redraw(); } });
  return h('div', { class: 'panel' },
    h('div', { class: 'row' }, title,
      isAdmin() && f.length > 1 ? h('button', { class: 'btn', title: 'Dismiss every open finding, including the hidden ones', onclick: () => confirm('Dismiss all ' + f.length + ' open findings (including hidden ones)?') && noveltyDo(() => api('POST', '/api/v1/novelty/dismiss-all')) }, 'Dismiss all (' + f.length + ')') : null),
    h('p', { class: 'muted small' }, info),
    f.length ? h('div', { class: 'row', style: 'margin-bottom:8px' }, lvlSel, h('label', { class: 'small' }, grpBox, ' group by host'),
      isAdmin() && likely.length ? h('button', { class: 'btn', title: 'Advisory marks only: review a few first', onclick: () => dismissIds(likely.map((x) => x.id), 'marked likely noise') }, 'Dismiss likely noise (' + likely.length + ')') : null) : null,
    hidden ? h('p', { class: 'muted small' }, hidden + ' lower-level finding(s) (info, debug, notice) hidden. ',
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); ui.level = 'all'; redraw(); } }, 'Show everything')) : null,
    visible.length ? (ui.group ? h('div', {}, groups.map(group))
      : h('div', {}, tbl(shown), visible.length > shown.length ? h('div', { class: 'row', style: 'justify-content:center;margin-top:8px' },
        h('button', { class: 'btn', onclick: () => { ui.shown += 100; redraw(); } }, 'Show more (' + shown.length + ' of ' + visible.length + ')')) : null))
      : h('p', { class: 'muted' }, f.length ? 'Nothing at this level.' : (st.mode === 'report' ? 'Nothing new. Patterns never seen before, or far above their normal rate, will show up here.' : '')));
}
async function pageStatus() {
  const [s] = await Promise.all([api('GET', '/api/v1/status'), loadStats(false), loadNovelty()]);
  const hoursInp = h('input', { type: 'number', min: 1, max: 168, value: 24, style: 'width:80px' });
  const busy = { v: false };
  const act = (fn) => async (ev) => {
    if (busy.v) return; busy.v = true; ev.target.disabled = true;
    try { await fn(); } catch (e) { toast(e.message, true); }
    busy.v = false; ev.target.disabled = false;
  };
  renderShell([
    h('div', { class: 'grid' },
      h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'LLM endpoints'),
        (s.endpoints && s.endpoints.length ? s.endpoints : [{ url: '(not probed yet)', state: 'unknown' }]).map((e) => h('div', { class: 'row' },
          stateBadge(e.state), h('span', { class: 'mono small' }, e.url),
          e.checked ? h('span', { class: 'muted small', title: 'Last reachability check (the model is not called)' },
            'checked ' + fmtTime(e.checked) + (e.latency_ms !== null && e.latency_ms !== undefined ? ', ' + e.latency_ms + ' ms' : '')) : null,
          e.state === 'down' ? h('span', { class: 'err small' }, (e.why || 'unreachable') + ' · retry in ' + e.retry_in_s + ' s') : null))),
      h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Service'),
        h('dl', { class: 'kv' },
          h('dt', {}, 'Started'), h('dd', {}, fmtTime(s.started)),
          h('dt', {}, 'Queue'), h('dd', {}, s.pending + ' job(s) waiting'),
          h('dt', {}, 'Next digest'), h('dd', {}, fmtTime(s.next_digest_utc)),
          h('dt', {}, 'Notifications'), h('dd', {}, s.notify_configured ? 'configured' : 'not configured (HA_WEBHOOK_URL)'),
          h('dt', {}, 'Last notification'), h('dd', {}, s.last_notify ? (s.last_notify.ok ? 'ok' : 'FAILED') + ' · ' + s.last_notify.kind + ' · ' + fmtTime(s.last_notify.at) : '-'),
          h('dt', {}, 'Config revisions'), h('dd', {}, 'known #' + s.config.known_rev + ', topology #' + (s.config.topology_rev || 0) + ', detectors #' + (s.config.detectors_rev || 0) + ', rules #' + (s.config.rules_rev || 0) + ', settings #' + s.config.settings_rev))),
      h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Actions'),
        isAdmin() ? h('div', { class: 'row' },
          h('span', { class: 'muted small' }, 'Digest over the last'), hoursInp, h('span', { class: 'muted small' }, 'h'),
          h('button', { class: 'btn primary', onclick: act(async () => { await api('POST', '/api/v1/jobs/digest', { hours: Number(hoursInp.value) }); toast('Digest queued'); }) }, 'Run now'))
          : h('p', { class: 'muted small' }, 'Admin token required.'),
        isAdmin() ? h('div', { class: 'row', style: 'margin-top:8px' },
          h('button', { class: 'btn', disabled: !s.notify_configured, onclick: act(async () => { await api('POST', '/api/v1/jobs/notify-test'); toast('Test notification queued'); }) }, 'Send test notification')) : null)),
    noveltyPanel(),
    reviewCard(S.stats.runs ? S.stats.runs.find((r) => r.kind === 'digest' && r.stats && r.stats.window_lines !== undefined) || null : null),
    volumePanel(),
    runsTable(S.stats.runs),
    resultCard('Last digest', s.last_digest),
    resultCard('Last incident', s.last_incident),
    s.last_incident ? h('p', { class: 'small' }, h('button', { class: 'btn', onclick: () => go('incidents') }, 'Open the incident list'),
      ' · state, notes and feedback for every incident') : null,
  ]);
  if (!S.timer) {
    S.timer = setInterval(() => {
      const a = document.activeElement;
      if (document.hidden || S.tab !== 'status' || (a && ['INPUT', 'SELECT', 'TEXTAREA'].includes(a.tagName))) return;  // do not steal focus while typing
      pageStatus().catch(() => {});
    }, 10000);
  }
}

// ---------------------------------------------------------------- noise & known issues
const norm = (d) => Object.assign({}, d, { context: d.context || [], noise: d.noise || [], known_issues: d.known_issues || [], must_keep: d.must_keep || [] });
const TS_PREFIX = /^(?:\[?<N>-<N>-<N>[ T]<N>:<N>:<N>(?:[.,]<N>)?(?:\+<N>:<N>|Z)?\]?\s*)+/;

function ruleFromLine(text) {
  const parts = text.split(' | ');
  const ident = (parts[1] || '').trim();
  let msg = parts.slice(2).join(' | ').replace(TS_PREFIX, '').trim();
  if (msg.length > 60) msg = msg.slice(0, 60).replace(/\s+\S*$/, '');  // cut at a word boundary
  // The line still contains the timestamp between "ident |" and the message text, hence ".*".
  return '\\| ' + esc(ident) + ' \\| .*' + esc(msg);
}
async function loadKnown() {
  S.known = await api('GET', '/api/v1/config/known');
  S.base = norm(S.known.content); S.draft = clone(S.base);
  S.test = null; S.testError = ''; S.diff = null; S.comment = '';
  S.snoozes = await api('GET', '/api/v1/snoozes');
}
// Snoozes are changed through their own endpoints (immediately, without touching unsaved edits of the rest).
async function refreshSnoozes() {
  const k = await api('GET', '/api/v1/config/known');
  S.known = k;
  for (const doc of [S.base, S.draft]) { if (k.content.snoozes && k.content.snoozes.length) doc.snoozes = clone(k.content.snoozes); else delete doc.snoozes; }
  S.snoozes = await api('GET', '/api/v1/snoozes');
}
const fmtLeft = (s) => (s <= 0 ? 'expired' : s < 5400 ? Math.max(1, Math.round(s / 60)) + ' min left' : s < 172800 ? Math.round(s / 3600) + ' h left' : Math.round(s / 86400) + ' days left');
async function doSnooze(regex, note) {
  const hours = S.snoozeHours;
  try {
    if (isAdmin()) {
      await api('POST', '/api/v1/snoozes', { regex, hours, note });
      await refreshSnoozes();
      toast('Snoozed for ' + hours + ' h; active now.');
    } else {
      const r = await api('POST', '/api/v1/proposals', { key: 'known', comment: 'snooze for ' + hours + ' h' + (note ? ': ' + note : ''), patch: { add_snoozes: [{ regex, hours, note }] } });
      toast('Proposal #' + r.id + ' created.');
      refreshPendingCount();
    }
  } catch (e) { toast(e.message, true); }
  if (S.test) await runTest(); else draw();
}
async function dropSnooze(id) {
  try { await api('DELETE', '/api/v1/snoozes/' + encodeURIComponent(id)); await refreshSnoozes(); } catch (e) { toast(e.message, true); }
  draw();
}
// The document sent to the server: an empty must_keep list is left out (the key is optional).
function draftOut() {
  const c = clone(S.draft);
  c.must_keep = (c.must_keep || []).map((x) => x.trim()).filter(Boolean);
  if (!c.must_keep.length) delete c.must_keep;
  return c;
}
// Index of the first noise rule that matches a must_keep sample line (client-side hint only; the server decides on save).
function mkConflict(line) {
  const variants = [line, line.replace(/<N>/g, '123')];
  for (let i = 0; i < S.draft.noise.length; i++) {
    try { const rx = new RegExp(S.draft.noise[i]); if (variants.some((v) => rx.test(v))) return i; } catch (e) { /* inline flags etc.: left to the server */ }
  }
  return null;
}
async function runTest() {
  S.testError = '';
  try { S.test = await api('POST', '/api/v1/test/known', { hours: S.testHours, content: draftOut() }); } catch (e) { S.test = null; S.testError = e.message; }
  S.diff = null;
  draw();
}
// "Why isn't it shown?": one log line's path into the model input (level -> noise -> snooze -> known issue -> volume cap)
S.exp = { host: '', ident: '', message: '', source: 'syslog', level: '', hours: 24, res: null, error: '', busy: false };
async function runExplain() {
  const x = S.exp;
  x.error = ''; x.busy = true; draw();
  try {
    x.res = await api('POST', '/api/v1/explain', { host: x.host, ident: x.ident, message: x.message, source: x.source,
      level: x.source === 'docker' ? null : (x.level || null), hours: x.hours, content: draftOut() });
  } catch (e) { x.res = null; x.error = e.message; }
  x.busy = false; draw();
}
const EXP_OUTCOME = { suppressed: ['Removed by a noise rule', 'sev-medium'], snoozed: ['Snoozed', 'sev-medium'], known: ['Known issue', 'sev-medium'],
  filtered: ['Filtered by level', 'sev-medium'], capped: ['Cut by the volume cap', 'sev-medium'], not_found: ['Not in the window', 'b-unknown'],
  unknown: ['Depends on the level', 'b-unknown'], reaches_model: ['Reaches the model', 'b-up'] };
const EXP_STEP = { level: 'Level filter', noise: 'Noise rules', snooze: 'Snoozes', known: 'Known issues', volume: 'Volume cap (live window)' };
function explainPanel() {
  const x = S.exp, r = x.res;
  const inp = (k, ph, cls, extra) => h('input', Object.assign({ class: cls || '', placeholder: ph, value: x[k], oninput: (e) => { x[k] = e.target.value; },
    onkeydown: (e) => { if (e.key === 'Enter' && x.message.trim()) runExplain(); } }, extra || {}));
  const lvlHint = x.source === 'journald' ? 'PRIORITY 0-7' : 'level, e.g. err';
  const out = r ? EXP_OUTCOME[r.verdict.outcome] || [r.verdict.outcome, 'b-unknown'] : null;
  const mark = (res) => (res === 'stop' ? h('span', { class: 'badge b-down' }, 'stops here') : res === 'pass' ? h('span', { class: 'badge b-up' }, 'passes')
    : h('span', { class: 'badge b-unknown' }, 'unknown'));
  return h('div', { class: 'panel', id: 'explain-panel' },
    h('h3', { style: 'margin-top:0' }, 'Why isn’t it shown?'),
    h('p', { class: 'muted small' }, 'Paste a log line to see its path into the model input, in the order the service applies the rules. Uses your current (unsaved) edits; nothing is changed.'),
    h('div', { class: 'row' },
      h('select', { onchange: (e) => { x.source = e.target.value; draw(); } }, ['syslog', 'journald', 'docker'].map((s) => h('option', { value: s, selected: s === x.source }, s))),
      inp('host', 'host'), inp('ident', x.source === 'docker' ? 'container' : 'ident / app'),
      x.source === 'docker' ? null : inp('level', lvlHint, '', { style: 'width:130px' }),
      h('select', { title: 'Live window for the volume check', onchange: (e) => { x.hours = Number(e.target.value); } },
        [[0, 'rules only'], [6, '6 h'], [24, '24 h'], [72, '72 h']].map(([n, l]) => h('option', { value: n, selected: n === x.hours }, l)))),
    h('div', { class: 'row', style: 'margin-top:6px' }, inp('message', 'the message, e.g. Failed to refresh device state for LED-12', 'grow mono'),
      h('button', { class: 'btn primary', disabled: x.busy, onclick: () => { if (x.message.trim()) runExplain(); } }, x.busy ? 'Checking…' : 'Explain')),
    x.error ? h('div', { class: 'err' }, x.error) : null,
    r ? h('div', { style: 'margin-top:10px' },
      h('p', {}, h('span', { class: 'badge ' + out[1] }, out[0]), ' ', r.verdict.summary),
      h('div', { class: 'muted small mono', style: 'margin-bottom:6px' }, 'Matched as: ' + r.text),
      h('table', {}, h('tbody', {}, r.steps.map((s) => h('tr', {},
        h('td', { class: 'nowrap' }, EXP_STEP[s.step] || s.step), h('td', { class: 'nowrap' }, mark(s.result)), h('td', { class: 'small' }, s.detail))))),
      r.must_keep ? h('p', { class: 'small' }, 'Listed under Never suppress: no noise rule or snooze may match it.') : null) : null);
}
async function showDiff() {
  try { S.diff = (await api('POST', '/api/v1/config/known/diff', { content: draftOut() })).diff; } catch (e) { toast(e.message, true); }
  draw();
}
async function submit(kind) {
  const comment = S.comment.trim();
  if (!comment) { toast('Add a short comment (what and why).', true); return; }
  try {
    if (kind === 'save') {
      const r = await api('PUT', '/api/v1/config/known', { content: draftOut(), comment });
      toast(r.changed ? 'Saved as revision ' + r.rev + '; active now.' : 'No changes.');
      await loadKnown();
    } else {
      const r = await api('POST', '/api/v1/proposals', { key: 'known', content: draftOut(), comment });
      toast('Proposal #' + r.id + ' created.');
      S.comment = '';
      refreshPendingCount();
    }
  } catch (e) { S.testError = e.message; toast('Rejected: see the message above', true); }
  draw();
}
const pageKnown = async () => { if (!S.draft) await loadKnown(); draw(); };

function draw() {
  const d = S.draft, t = S.test;
  const dirty = !same(norm(d), S.base);
  const noiseStat = (i) => (t && t.noise[i] ? t.noise[i] : null);
  const issueStat = (id) => (t ? t.known.find((k) => k.id === id) : null);
  const touched = () => { S.test = null; S.diff = null; };

  const ctxRows = d.context.map((c, i) => h('div', { class: 'row top' },
    h('textarea', { class: 'grow', rows: 2, value: c, oninput: (e) => { d.context[i] = e.target.value; } }),
    h('button', { class: 'icon', title: 'Remove', onclick: () => { d.context.splice(i, 1); draw(); } }, '×')));

  const noiseRows = d.noise.map((rx, i) => {
    const st = noiseStat(i);
    return h('tr', { class: st && st.patterns === 0 ? 'unused' : '' },
      h('td', { class: 'num muted' }, i + 1),
      h('td', {}, h('input', { class: 'mono', style: 'width:100%', value: rx, oninput: (e) => { d.noise[i] = e.target.value; touched(); } }),
        st && st.samples.length ? h('details', {}, h('summary', { class: 'muted small' }, 'sample lines'), st.samples.map((x) => h('div', { class: 'mono small muted' }, x))) : null),
      h('td', { class: 'num small' }, st ? (st.patterns ? st.patterns + ' patterns / ' + st.lines + ' lines' : 'no match') : '-'),
      h('td', {}, h('button', { class: 'icon', title: 'Remove', onclick: () => { d.noise.splice(i, 1); touched(); draw(); } }, '×')));
  });
  const addNoise = (rx) => { d.noise.push(rx || ''); touched(); draw(); if (!rx) { const ins = document.querySelectorAll('#noise-table input'); ins[ins.length - 1].focus(); } else runTest(); };

  const issueCards = d.known_issues.map((k, i) => {
    const st = issueStat(k.id);
    const f = (key, label, mono, rows) => h('div', { style: 'margin-bottom:6px' }, h('div', { class: 'muted small' }, label),
      rows ? h('textarea', { rows, value: k[key] || '', oninput: (e) => { k[key] = e.target.value; touched(); } })
        : h('input', { class: mono ? 'mono' : '', style: 'width:100%', value: k[key] || '', oninput: (e) => { if (e.target.value) k[key] = e.target.value; else delete k[key]; touched(); } }));
    return h('div', { class: 'panel', style: 'background:var(--bg)' },
      h('div', { class: 'row' }, h('strong', { class: 'grow' }, k.id || '(new)'),
        st ? h('span', { class: 'small muted' }, st.patterns ? st.patterns + ' patterns / ' + st.lines + ' lines' : 'no match') : null,
        h('button', { class: 'icon', title: 'Remove', onclick: () => { d.known_issues.splice(i, 1); touched(); draw(); } }, '×')),
      f('id', 'ID (unique)', true), f('note', 'Note (shown to the model as "already acknowledged")', false, 2),
      f('match', 'Input regex: log line "host | ident | message" that marks this issue', true),
      f('match_output', 'Output regex (optional): drops model issues whose title/evidence matches; defaults to the input regex', true),
      f('match_alert', 'Alert regex (optional): a firing alert whose text matches is only logged, opens no incident and joins no correlation; name the host and the device', true));
  });

  const mkRows = d.must_keep.map((m, i) => {
    const hint = h('span', { class: 'err small' });
    const upd = () => {   // updated in place (no redraw: a redraw on blur would swallow the click on Save)
      const hit = mkConflict(d.must_keep[i]);
      hint.textContent = hit !== null ? 'noise rule #' + (hit + 1) + ' matches this line: it would be rejected' : '';
      hint.title = hit !== null ? d.noise[hit] : '';
      hint.style.display = hit !== null ? '' : 'none';
    };
    upd();
    return h('div', { style: 'margin-bottom:6px' },
      h('div', { class: 'row top' },
        h('input', { class: 'grow mono', value: m, oninput: (e) => { d.must_keep[i] = e.target.value; touched(); upd(); } }),
        h('button', { class: 'icon', title: 'Remove', onclick: () => { d.must_keep.splice(i, 1); touched(); draw(); } }, '×')),
      hint);
  });
  const keptRows = t ? t.kept_top.map((k) => h('tr', {}, h('td', { class: 'num' }, k.hits + '×'), h('td', { class: 'mono small' }, k.text),
    h('td', { class: 'nowrap' },
      h('button', { class: 'btn small', title: 'Add a permanent noise rule from this line', onclick: () => addNoise(ruleFromLine(k.text)) }, '+ noise'), ' ',
      h('button', { class: 'btn small', title: 'Mute this line for ' + S.snoozeHours + ' h (then it comes back by itself)', onclick: () => doSnooze(ruleFromLine(k.text), '') }, 'snooze ' + S.snoozeHours + ' h')))) : [];

  const snoozeRows = S.snoozes.map((s) => h('tr', { class: s.active ? '' : 'unused' },
    h('td', {}, h('div', { class: 'mono small' }, s.regex), s.note ? h('div', { class: 'muted small' }, s.note) : null),
    h('td', { class: 'num small nowrap' }, s.active ? fmtLeft(s.remaining_s) : 'expired', h('div', { class: 'muted' }, s.until)),
    h('td', {}, isAdmin() ? h('button', { class: 'icon', title: 'Remove', onclick: () => dropSnooze(s.id) }, '×') : null)));
  const snoozePanel = h('div', { class: 'panel' },
    h('h3', { style: 'margin-top:0' }, 'Snoozed (' + S.snoozes.filter((s) => s.active).length + ' active)'),
    h('div', { class: 'row' }, h('span', { class: 'muted small' }, 'Snooze length for the buttons in the dry run below'),
      h('select', { onchange: (e) => { S.snoozeHours = Number(e.target.value); draw(); } },
        [[1, '1 h'], [6, '6 h'], [24, '1 day'], [72, '3 days'], [168, '7 days'], [720, '30 days']].map(([n, l]) => h('option', { value: n, selected: n === S.snoozeHours }, l)))),
    snoozeRows.length ? h('table', {}, h('tbody', {}, snoozeRows)) : h('p', { class: 'muted small' }, 'Nothing is snoozed. A snooze mutes a line temporarily; it expires by itself and is not a permanent rule.'),
    isAdmin() ? null : h('p', { class: 'muted small' }, 'Read-only token: a snooze becomes a proposal.'));

  const testPanel = h('div', { class: 'panel' },
    h('h3', { style: 'margin-top:0' }, 'Dry run against the live logs'),
    h('div', { class: 'row' },
      h('span', { class: 'muted small' }, 'Window'),
      h('select', { onchange: (e) => { S.testHours = Number(e.target.value); } }, [6, 24, 72, 168].map((n) => h('option', { value: n, selected: n === S.testHours }, n + ' h'))),
      h('button', { class: 'btn primary', onclick: runTest }, 'Run test'),
      h('span', { class: 'muted small' }, 'Uses your current (unsaved) edits; nothing is changed.')),
    S.testError ? h('div', { class: 'err' }, S.testError) : null,
    t ? h('div', {},
      h('p', {}, h('strong', {}, t.rows + ' log patterns'), ': noise rules remove ' + t.noise_patterns + ' (' + t.noise_lines + ' lines), known issues ' + t.known_patterns + ', ',
        h('strong', {}, t.kept_patterns + ' reach the model'), ' (saved config: ' + t.baseline.kept_patterns + ').',
        t.unused_noise.length ? ' ' + t.unused_noise.length + ' of ' + t.noise.length + ' noise rules matched nothing in this window.' : ''),
      keptRows.length ? h('div', {}, h('h3', {}, 'Still reaching the model (most frequent)'),
        h('table', {}, h('tbody', {}, keptRows))) : null) : null);

  const bar = h('div', { class: 'savebar' },
    S.diff !== null ? diffEl(S.diff) : null,
    h('div', { class: 'row', style: S.diff !== null ? 'margin-top:8px' : '' },
      h('input', { class: 'grow', placeholder: 'Comment: what and why', value: S.comment, oninput: (e) => { S.comment = e.target.value; } }),
      h('button', { class: 'btn', disabled: !dirty, onclick: showDiff }, 'Preview diff'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => { S.draft = clone(S.base); S.test = null; S.diff = null; draw(); } }, 'Discard edits'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => submit('propose') }, 'Propose'),
      isAdmin() ? h('button', { class: 'btn primary', disabled: !dirty, onclick: () => submit('save') }, 'Save') : null),
    h('div', { class: 'muted small', style: 'margin-top:6px' },
      'Revision #' + S.known.id + (dirty ? ' · unsaved changes' : '') + (isAdmin() ? '' : ' · read-only token: use Propose, an admin approves.')));

  renderShell([
    h('h2', {}, 'Noise & known issues'),
    h('p', { class: 'muted' }, 'Rules run before the model sees the logs. Lines are matched as "host | ident | message" with numbers collapsed to <N>.'),
    explainPanel(),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Lab context (facts given to the model)'), ctxRows,
      h('button', { class: 'btn', onclick: () => { d.context.push(''); draw(); } }, '+ Add fact')),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Noise rules (' + d.noise.length + ')'),
      h('table', { id: 'noise-table' }, h('thead', {}, h('tr', {}, h('th', {}, '#'), h('th', {}, 'Regex'), h('th', {}, 'Last test'), h('th', {}))), h('tbody', {}, noiseRows)),
      h('div', { style: 'margin-top:8px' }, h('button', { class: 'btn', onclick: () => addNoise('') }, '+ Add noise rule'))),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Known issues (' + d.known_issues.length + ')'), issueCards,
      h('button', { class: 'btn', onclick: () => { d.known_issues.push({ id: '', note: '', match: '' }); touched(); draw(); } }, '+ Add known issue')),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Never suppress (' + d.must_keep.length + ')'),
      h('p', { class: 'muted small' }, 'Sample lines of events that must never be muted, as "host | ident | message" with numbers as <N>. A noise rule or snooze that matches one of them is rejected, whether it is typed here, proposed by the Supervisor or approved later.'),
      mkRows, h('button', { class: 'btn', onclick: () => { d.must_keep.push(''); touched(); draw(); } }, '+ Add sample line')),
    snoozePanel, testPanel, bar,
  ]);
}

// ---------------------------------------------------------------- topology (devices, IPs, roles, dependencies)
const TOPO_KINDS = ['host', 'container', 'network', 'service', 'device'];
const TOPO_DEPS = ['network', 'storage', 'dns', 'mqtt', 'power', 'runtime', 'data', 'auth', 'other'];
S.topo = null;
const assetName = (a) => a.name || a.id;
const topoNorm = (d) => ({ assets: (d && d.assets) || [] });
const topoSlug = (s) => String(s).toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^[-_.]+/, '').slice(0, 48);
async function loadTopo() {
  const r = await api('GET', '/api/v1/config/topology');
  const keep = S.topo || {};
  S.topo = { rev: r.id, base: topoNorm(r.content), draft: clone(topoNorm(r.content)), edit: null, filter: keep.filter || '', test: null, testText: keep.testText || '',
    testError: '', cov: keep.cov || null, covError: '', covHours: keep.covHours || 168, diff: null, comment: '', error: '' };
}
function topoFindByName(name) {
  const n = String(name).toLowerCase();
  return S.topo.draft.assets.find((a) => a.id === n || (a.name || '').toLowerCase() === n || (a.aliases || []).some((x) => x.toLowerCase() === n));
}
function topoEditStart(a, isNew) {
  S.topo.edit = { isNew, orig: a.id, a: Object.assign({ id: '', kind: 'host', aliases: [], depends_on: [] }, clone(a)) };
  drawTopo();
}
function topoEditApply() {
  const e = S.topo.edit, a = e.a, list = S.topo.draft.assets;
  for (const k of ['name', 'ip', 'role', 'note', 'runs_on']) { if (!a[k]) delete a[k]; }
  if (!a.aliases || !a.aliases.length) delete a.aliases;
  if (!a.depends_on || !a.depends_on.length) delete a.depends_on;
  if (!a.criticality || a.criticality === 'normal') delete a.criticality;
  if (!a.id) { toast('The id is required.', true); return; }
  if (e.isNew) list.push(a);
  else {
    const i = list.findIndex((x) => x.id === e.orig);
    list[i] = a;
    if (e.orig !== a.id) {  // renamed: keep the references valid
      for (const x of list) { if (x.runs_on === e.orig) x.runs_on = a.id; (x.depends_on || []).forEach((d) => { if (d.id === e.orig) d.id = a.id; }); }
    }
  }
  S.topo.edit = null; S.topo.test = null; S.topo.diff = null;
  drawTopo();
}
function topoRemove(id) {
  const list = S.topo.draft.assets;
  S.topo.draft.assets = list.filter((x) => x.id !== id);
  for (const x of S.topo.draft.assets) { if (x.runs_on === id) delete x.runs_on; if (x.depends_on) { x.depends_on = x.depends_on.filter((d) => d.id !== id); if (!x.depends_on.length) delete x.depends_on; } }
  S.topo.test = null; S.topo.diff = null;
  drawTopo();
}
async function topoCoverage() {
  S.topo.covError = '';
  try { S.topo.cov = await api('GET', '/api/v1/topology/coverage?hours=' + S.topo.covHours); } catch (e) { S.topo.cov = null; S.topo.covError = e.message; }
  drawTopo();
}
async function topoTry() {
  S.topo.testError = '';
  try { S.topo.test = await api('POST', '/api/v1/test/topology', { text: S.topo.testText, content: S.topo.draft }); } catch (e) { S.topo.test = null; S.topo.testError = e.message; }
  drawTopo();
}
async function topoDiff() {
  try { S.topo.diff = (await api('POST', '/api/v1/config/topology/diff', { content: S.topo.draft })).diff; } catch (e) { toast(e.message, true); }
  drawTopo();
}
async function topoSubmit(kind) {
  const t = S.topo, comment = t.comment.trim();
  if (!comment) { toast('Add a short comment (what and why).', true); return; }
  t.error = '';
  try {
    if (kind === 'save') { const r = await api('PUT', '/api/v1/config/topology', { content: t.draft, comment }); toast(r.changed ? 'Saved as revision ' + r.rev + '; active now.' : 'No changes.'); S.topo.comment = ''; await loadTopo(); }
    else { const r = await api('POST', '/api/v1/proposals', { key: 'topology', content: t.draft, comment }); toast('Proposal #' + r.id + ' created.'); t.comment = ''; refreshPendingCount(); }
  } catch (e) { S.topo.error = e.message; toast('Rejected: see the message above', true); }
  drawTopo();
}
const pageTopology = async () => { if (!S.topo) await loadTopo(); drawTopo(); };

function topoEditor() {
  const e = S.topo.edit, a = e.a, others = S.topo.draft.assets.filter((x) => x.id !== e.orig);
  const field = (label, key, opts = {}) => h('div', { style: 'margin-bottom:6px' }, h('div', { class: 'muted small' }, label),
    h('input', { class: opts.mono ? 'mono' : '', style: 'width:100%', value: a[key] || '', placeholder: opts.ph || '', oninput: (ev) => { a[key] = ev.target.value; } }));
  const sel = (label, key, options, blank, dflt = '') => h('div', { style: 'margin-bottom:6px' }, h('div', { class: 'muted small' }, label),
    h('select', { onchange: (ev) => { a[key] = ev.target.value; } },
      (blank ? [['', blank]] : []).concat(options.map((o) => (Array.isArray(o) ? o : [o, o]))).map(([v, l]) => h('option', { value: v, selected: v === (a[key] || dflt) }, l))));
  const deps = (a.depends_on || []).map((d, i) => h('div', { class: 'row' },
    h('select', { onchange: (ev) => { d.id = ev.target.value; } }, [['', '(choose)']].concat(others.map((x) => [x.id, (x.name || x.id) + ' (' + x.kind + ')'])).map(([v, l]) => h('option', { value: v, selected: v === d.id }, l))),
    h('select', { onchange: (ev) => { d.type = ev.target.value; } }, TOPO_DEPS.map((t) => h('option', { value: t, selected: t === (d.type || 'other') }, t))),
    h('button', { class: 'icon', title: 'Remove', onclick: () => { a.depends_on.splice(i, 1); drawTopo(); } }, '×')));
  return h('div', { class: 'panel', id: 'topo-editor' },
    h('h3', { style: 'margin-top:0' }, e.isNew ? 'New device' : 'Edit ' + e.orig),
    h('div', { class: 'grid' },
      h('div', {}, field('ID (unique; lowercase letters, digits, - _ .)', 'id', { mono: true }), field('Display name (optional)', 'name'),
        sel('Kind', 'kind', TOPO_KINDS), field('IP address', 'ip', { mono: true, ph: '192.0.2.x' })),
      h('div', {}, field('Role / function', 'role'),
        h('div', { style: 'margin-bottom:6px' }, h('div', { class: 'muted small' }, 'Names in the logs (comma separated: host, container name, syslog identifier)'),
          h('input', { class: 'mono', style: 'width:100%', value: (a.aliases || []).join(', '), oninput: (ev) => { a.aliases = ev.target.value.split(',').map((x) => x.trim()).filter(Boolean); } })),
        sel('Runs on (containers: the host)', 'runs_on', others.map((x) => [x.id, (x.name || x.id) + ' (' + x.kind + ')']), '(none)'),
        sel('Criticality', 'criticality', ['low', 'normal', 'high'], '', 'normal'), field('Note', 'note'))),
    h('div', { class: 'muted small' }, 'Depends on'), deps,
    h('div', { style: 'margin:6px 0' }, h('button', { class: 'btn', onclick: () => { a.depends_on = (a.depends_on || []).concat([{ id: '', type: 'network' }]); drawTopo(); } }, '+ dependency')),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: topoEditApply }, 'Apply to draft'),
      h('button', { class: 'btn', onclick: () => { S.topo.edit = null; drawTopo(); } }, 'Cancel')));
}
function drawTopo() {
  const t = S.topo, d = t.draft;
  const dirty = !same(d, t.base);
  const q = t.filter.trim().toLowerCase();
  const order = { host: 0, network: 1, service: 2, container: 3, device: 4 };
  const matches = (a) => !q || [a.id, a.name, a.ip, a.role, ...(a.aliases || [])].some((x) => String(x || '').toLowerCase().includes(q));
  const list = d.assets.filter(matches).sort((x, y) => (order[x.kind] - order[y.kind]) || assetName(x).localeCompare(assetName(y)));
  const nm = (id) => { const x = d.assets.find((y) => y.id === id); return x ? assetName(x) : id; };
  const rows = list.map((a) => h('tr', {},
    h('td', {}, h('strong', {}, assetName(a)), a.name && a.name !== a.id ? h('div', { class: 'muted small mono' }, a.id) : null),
    h('td', { class: 'small' }, a.kind, a.criticality === 'high' ? h('div', {}, h('span', { class: 'badge sev-high' }, 'high')) : null),
    h('td', { class: 'mono small' }, a.ip || ''),
    h('td', { class: 'small' }, a.role || '', (a.aliases && a.aliases.length) ? h('div', { class: 'muted mono' }, a.aliases.join(', ')) : null),
    h('td', { class: 'small' }, a.runs_on ? h('div', {}, 'on ' + nm(a.runs_on)) : null,
      (a.depends_on || []).map((x) => h('div', {}, nm(x.id), ' ', h('span', { class: 'muted' }, '(' + (x.type || 'other') + ')')))),
    h('td', { class: 'nowrap' }, h('button', { class: 'btn small', onclick: () => topoEditStart(a, false) }, 'Edit'), ' ',
      h('button', { class: 'icon', title: 'Remove', onclick: () => { if (confirm('Remove ' + assetName(a) + ' and the references to it?')) topoRemove(a.id); } }, '×'))));

  const cov = t.cov;
  const covPanel = h('div', { class: 'panel' },
    h('div', { class: 'row' }, h('h3', { class: 'grow', style: 'margin:0' }, 'Coverage against the logs'),
      h('select', { onchange: (e) => { t.covHours = Number(e.target.value); } }, [[24, '24 h'], [72, '3 days'], [168, '7 days'], [336, '14 days']].map(([n, l]) => h('option', { value: n, selected: n === t.covHours }, l))),
      h('button', { class: 'btn', onclick: topoCoverage }, cov ? 'Refresh' : 'Check')),
    h('p', { class: 'muted small' }, 'Compares the hosts and containers seen in VictoriaLogs with the saved topology (so it does not rot).'),
    t.covError ? h('div', { class: 'err' }, t.covError) : null,
    cov ? h('div', {},
      h('h4', {}, 'Seen in the logs, not in the topology (' + cov.unknown.length + ')'),
      cov.unknown.length ? h('table', {}, h('tbody', {}, cov.unknown.slice(0, 40).map((u) => h('tr', {},
        h('td', {}, h('strong', {}, u.name)), h('td', { class: 'small' }, u.kind + (u.host ? ' on ' + u.host : '')),
        h('td', { class: 'num small' }, fmtN(u.lines) + ' lines'),
        h('td', {}, h('button', { class: 'btn small', onclick: () => {
          const host = u.host ? topoFindByName(u.host) : null;
          topoEditStart({ id: topoSlug(u.name), name: u.name, kind: u.kind, runs_on: host ? host.id : '' }, true);
          document.getElementById('topo-editor') && document.getElementById('topo-editor').scrollIntoView();
        } }, '+ add')))))) : h('p', { class: 'muted small' }, 'Everything seen in the logs is in the topology.'),
      cov.unknown.length > 40 ? h('p', { class: 'muted small' }, '+' + (cov.unknown.length - 40) + ' more (the least frequent).') : null,
      h('h4', {}, 'In the topology, not seen in the logs (' + cov.silent.length + ')'),
      cov.silent.length ? h('p', { class: 'small' }, cov.silent.map((s) => s.name + ' (' + s.kind + ')').join(', '), h('span', { class: 'muted' }, ' - silent, renamed, or no longer there?'))
        : h('p', { class: 'muted small' }, 'All hosts and containers in the topology appear in the logs.')) : null);

  const tryPanel = h('div', { class: 'panel' },
    h('h3', { style: 'margin-top:0' }, 'What the model would get'),
    h('p', { class: 'muted small' }, 'Paste an alert or a log line: shows the devices found in it (by id, name, alias or IP) and the topology section sent to the model. Uses your unsaved edits.'),
    h('textarea', { rows: 2, style: 'width:100%', placeholder: 'e.g. nfs: server 192.0.2.172 not responding (homesrv)', value: t.testText, oninput: (e) => { t.testText = e.target.value; } }),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: topoTry }, 'Try it')),
    t.testError ? h('div', { class: 'err' }, t.testError) : null,
    t.test ? h('div', {}, h('p', { class: 'small' }, t.test.matched.length ? 'Found: ' + t.test.matched.join(', ') + ' (' + t.test.chars + ' characters)' : 'No device found in this text.'),
      t.test.section.length ? h('pre', { class: 'mono small', style: 'white-space:pre-wrap' }, t.test.section.join('\n')) : null) : null);

  const bar = h('div', { class: 'savebar' },
    t.diff !== null ? diffEl(t.diff) : null,
    t.error ? h('div', { class: 'err' }, t.error) : null,
    h('div', { class: 'row', style: t.diff !== null ? 'margin-top:8px' : '' },
      h('input', { class: 'grow', placeholder: 'Comment: what and why', value: t.comment, oninput: (e) => { t.comment = e.target.value; } }),
      h('button', { class: 'btn', disabled: !dirty, onclick: topoDiff }, 'Preview diff'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => { S.topo.draft = clone(S.topo.base); S.topo.edit = null; S.topo.diff = null; S.topo.test = null; drawTopo(); } }, 'Discard edits'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => topoSubmit('propose') }, 'Propose'),
      isAdmin() ? h('button', { class: 'btn primary', disabled: !dirty, onclick: () => topoSubmit('save') }, 'Save') : null),
    h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Revision #' + t.rev + (dirty ? ' · unsaved changes' : '') + (isAdmin() ? '' : ' · read-only token: use Propose, an admin approves.')));

  renderShell([
    h('h2', {}, 'Topology'),
    h('p', { class: 'muted' }, 'Devices, IPs, roles and dependencies. For each alert or digest the service picks the devices that appear in it, adds what they depend on and what depends on them, and gives the model that short section; the model may claim a cause only along these dependencies.'),
    t.edit ? topoEditor() : null,
    h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('h3', { class: 'grow', style: 'margin:0' }, 'Devices (' + d.assets.length + ')'),
        h('input', { placeholder: 'Filter…', value: t.filter, oninput: (e) => { t.filter = e.target.value; drawTopo(); const i = document.getElementById('topo-filter'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, id: 'topo-filter' }),
        h('button', { class: 'btn', onclick: () => topoEditStart({ id: '', kind: 'host' }, true) }, '+ Add device')),
      d.assets.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Device', 'Kind', 'IP', 'Role / log names', 'Depends on', ''].map((x) => h('th', {}, x)))), h('tbody', {}, rows))
        : h('p', { class: 'muted' }, 'No devices yet. Add them here, or import a prepared file with scripts/logstack/console.ps1 import -Key topology.')),
    covPanel, tryPanel, bar,
  ]);
}

// ---------------------------------------------------------------- detectors (log rules the service evaluates itself)
const DET_DEFAULTS = { enabled: true, mode: 'count', threshold: 1, window_min: 15, cooldown_min: 60, action: 'triage', severity: 'medium' };
const DET_ACTIONS = [['triage', 'Model triage (incident; notifies from the usual severity)'], ['direct', 'Notify directly (no model)'], ['none', 'Record only (Status page and log store)']];
const DET_TEMPLATES = {
  burst: { id: 'container-errors', name: 'Error burst in a container', query: 'pipeline:docker appname:"CONTAINER" _msg:~"(?i)(error|fatal|panic)"', group_by: [], threshold: 20, window_min: 15 },
  silence: { id: 'source-silent', name: 'Source went silent', query: 'pipeline:syslog host:"HOSTNAME"', mode: 'absent', window_min: 30, action: 'direct', severity: 'high' },
  message: { id: 'message-seen', name: 'A specific message appeared', query: '"Out of memory"', group_by: ['host'], threshold: 1, window_min: 15 },
};
S.det = null;
const detNorm = (d) => ({ detectors: (d && d.detectors) || [] });
const detFull = (d) => Object.assign({}, DET_DEFAULTS, d);
async function loadDet() {
  const [r, st, hl] = await Promise.all([api('GET', '/api/v1/config/detectors'), api('GET', '/api/v1/detectors/status').catch(() => null), api('GET', '/api/v1/detectors/health').catch(() => null)]);
  const keep = S.det || {};
  S.det = { rev: r.id, base: detNorm(r.content), draft: clone(detNorm(r.content)), edit: null, status: st, health: hl, bt: null, btError: '', btHours: keep.btHours || 168, diff: null, comment: '', error: '' };
}
function detSummary(d) {
  const f = detFull(d);
  return f.mode === 'absent' ? 'no matching line for ' + f.window_min + ' min'
    : '≥ ' + f.threshold + ' in ' + f.window_min + ' min' + ((f.group_by || []).length ? ' per ' + f.group_by.join(', ') : '');
}
// Detector health: which detectors fired in 30 days, which approved drafts were never switched on, which are too noisy or failing.
const DET_FLAG = { 'draft-disabled': ['b-stale', 'approved draft, still disabled', 'Approved but never switched on: tick On in the table below and save, or remove it.'],
  disabled: ['b-unknown', 'disabled', 'Switched off.'], noisy: ['sev-medium', 'noisy', 'Fired very often: the filter may be too broad or the cooldown too short.'],
  error: ['sev-high', 'error', 'The last evaluation failed.'], quiet: ['b-unknown', 'quiet 30 d', 'Enabled but did not fire in 30 days. Normal for a rare condition.'] };
function detHealthPanel(hl) {
  if (!hl || !hl.detectors) return null;
  const c = hl.counts || {};
  const flagged = hl.detectors.filter((x) => x.flags.some((f) => f !== 'quiet'));
  return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Detector health (last 30 days)'),
    h('p', { class: 'muted small' }, (c['draft-disabled'] || 0) + ' approved draft(s) still disabled · ' + (c.noisy || 0) + ' noisy (≥ ' + hl.noisy_30d + ' firings) · ' + (c.error || 0) + ' failing · '
      + (c.quiet || 0) + ' quiet for 30 days (not a problem by itself)' + (hl.fired_error ? ' · firing counts unavailable (' + hl.fired_error + ')' : '')),
    flagged.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Detector', 'Fired (30 d)', 'Last fired', 'Flags'].map((x) => h('th', {}, x)))),
      h('tbody', {}, flagged.map((x) => h('tr', {}, h('td', {}, h('strong', {}, x.name), h('div', { class: 'mono small muted' }, x.id)), h('td', { class: 'num' }, String(x.fired_30d)),
        h('td', { class: 'small nowrap' }, x.last_fired ? fmtTime(x.last_fired) : '-'),
        h('td', {}, x.flags.filter((f) => f !== 'quiet').map((f) => [h('span', { class: 'badge ' + DET_FLAG[f][0], title: DET_FLAG[f][2] }, DET_FLAG[f][1]), ' '])))))) : h('p', { class: 'muted' }, 'Nothing needs attention.'));
}
function detEditStart(d, isNew) { S.det.edit = { isNew, orig: d.id, d: clone(detFull(d)) }; S.det.bt = null; S.det.btError = ''; drawDet(); }
function detEditApply() {
  const e = S.det.edit, d = e.d, list = S.det.draft.detectors;
  if (!d.id) { toast('The id is required.', true); return; }
  if (!d.name) d.name = d.id;
  if (d.mode === 'absent') { d.group_by = []; }
  const out = Object.assign({}, d);
  for (const k of ['note']) { if (!out[k]) delete out[k]; }
  if (!out.group_by || !out.group_by.length) delete out.group_by;
  if (out.enabled === true) delete out.enabled;
  for (const [k, v] of Object.entries(DET_DEFAULTS)) { if (out[k] === v && k !== 'enabled') delete out[k]; }
  if (e.isNew) list.push(out); else list[list.findIndex((x) => x.id === e.orig)] = out;
  S.det.edit = null; S.det.bt = null; S.det.diff = null;
  drawDet();
}
async function detBacktest() {
  S.det.btError = ''; S.det.bt = null;
  const d = Object.assign({}, S.det.edit.d);
  if (d.mode === 'absent') d.group_by = [];
  try { S.det.bt = await api('POST', '/api/v1/test/detector', { detector: d, hours: S.det.btHours }); } catch (e) { S.det.btError = e.message; }
  drawDet();
}
async function detDiff() {
  try { S.det.diff = (await api('POST', '/api/v1/config/detectors/diff', { content: S.det.draft })).diff; } catch (e) { toast(e.message, true); }
  drawDet();
}
async function detSubmit(kind) {
  const t = S.det, comment = t.comment.trim();
  if (!comment) { toast('Add a short comment (what and why).', true); return; }
  t.error = '';
  try {
    if (kind === 'save') { const r = await api('PUT', '/api/v1/config/detectors', { content: t.draft, comment }); toast(r.changed ? 'Saved as revision ' + r.rev + '; active now.' : 'No changes.'); S.det.comment = ''; await loadDet(); }
    else { const r = await api('POST', '/api/v1/proposals', { key: 'detectors', content: t.draft, comment }); toast('Proposal #' + r.id + ' created.'); t.comment = ''; refreshPendingCount(); }
  } catch (e) { S.det.error = e.message; toast('Rejected: see the message above', true); }
  drawDet();
}
const pageDetectors = async () => { if (!S.det) await loadDet(); else { try { S.det.status = await api('GET', '/api/v1/detectors/status'); } catch (e) { /* keep the old one */ } try { S.det.health = await api('GET', '/api/v1/detectors/health'); } catch (e) { /* keep the old one */ } } drawDet(); };

function detEditor() {
  const e = S.det.edit, d = e.d, t = S.det;
  const lab = (text, node, hint) => h('div', { style: 'margin-bottom:6px' }, h('div', { class: 'muted small' }, text), node, hint ? h('div', { class: 'muted small' }, hint) : null);
  const num = (key, min, max) => h('input', { type: 'number', min, max, style: 'width:110px', value: d[key], oninput: (ev) => { d[key] = ev.target.value === '' ? '' : Number(ev.target.value); } });
  const selOf = (key, opts) => h('select', { onchange: (ev) => { d[key] = ev.target.value; if (key === 'mode') drawDet(); } },
    opts.map((o) => (Array.isArray(o) ? o : [o, o])).map(([v, l]) => h('option', { value: v, selected: v === d[key] }, l)));
  const absent = d.mode === 'absent';
  const bt = t.bt;
  const btBox = h('div', { class: 'panel', style: 'background:var(--bg)' },
    h('div', { class: 'row' }, h('strong', { class: 'grow' }, 'Backtest on the stored logs'),
      h('select', { onchange: (ev) => { t.btHours = Number(ev.target.value); } }, [[24, '24 h'], [72, '3 days'], [168, '7 days'], [336, '14 days']].map(([n, l]) => h('option', { value: n, selected: n === t.btHours }, l))),
      h('button', { class: 'btn primary', onclick: detBacktest }, 'Run backtest')),
    h('p', { class: 'muted small' }, 'Replays this rule (unsaved edits included) over consecutive windows of the past and shows when it would have fired. Nothing is sent or changed.'),
    t.btError ? h('div', { class: 'err' }, t.btError) : null,
    bt ? h('div', {},
      bt.no_match ? h('div', { class: 'err' }, absent ? 'The filter matches nothing at all in this period: a silence rule on a source that never logs would fire all the time. Check the filter.' : 'The filter matched no lines in this period. Check the filter.')
        : h('p', {}, h('strong', {}, bt.firings + ' firing' + (bt.firings === 1 ? '' : 's')), ' in ' + bt.hours + ' h (' + (bt.events_total || 0) + ' qualifying windows of ' + bt.window_min + ' min, ' + fmtN(bt.total) + ' matching lines in total). ',
          h('span', { class: 'muted' }, 'Each firing is one incident analysis / notification (cooldown ' + d.cooldown_min + ' min applied).')),
      (bt.samples && bt.samples.length) ? h('div', {}, h('div', { class: 'muted small' }, 'Most frequent matching messages'), bt.samples.map((s) => h('div', { class: 'mono small' }, fmtN(s.hits) + '×  ' + s.msg))) : null,
      (bt.events && bt.events.length) ? h('table', { style: 'margin-top:8px' }, h('thead', {}, h('tr', {}, ['Window starting', 'Group', 'Lines', ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, bt.events.slice(-25).map((ev) => h('tr', { class: ev.fires ? '' : 'unused' }, h('td', { class: 'small nowrap' }, fmtTime(ev.time)),
          h('td', { class: 'mono small' }, Object.entries(ev.group || {}).map(([k, v]) => k + '=' + v).join(' ') || '-'),
          h('td', { class: 'num' }, absent ? '0' : fmtN(ev.hits)), h('td', { class: 'small' }, ev.fires ? 'fires' : 'cooldown'))))) : null,
      bt.events_total > 25 ? h('p', { class: 'muted small' }, 'Showing the latest 25 of ' + bt.events_total + '.') : null) : null);
  return h('div', { class: 'panel', id: 'det-editor' },
    h('h3', { style: 'margin-top:0' }, e.isNew ? 'New detector' : 'Edit ' + e.orig),
    h('div', { class: 'grid' },
      h('div', {},
        lab('ID (unique; lowercase letters, digits, - _ .)', h('input', { class: 'mono', style: 'width:100%', value: d.id || '', oninput: (ev) => { d.id = ev.target.value; } })),
        lab('Name', h('input', { style: 'width:100%', value: d.name || '', oninput: (ev) => { d.name = ev.target.value; } })),
        lab('Log filter (LogsQL, no pipes; the window is added for you)', h('textarea', { class: 'mono', rows: 3, style: 'width:100%', value: d.query || '', oninput: (ev) => { d.query = ev.target.value; } }),
          'Examples: appname:"plex" _msg:~"(?i)error"   ·   host:"homeassistant"   ·   "Out of memory"'),
        lab('Note', h('input', { style: 'width:100%', value: d.note || '', oninput: (ev) => { d.note = ev.target.value; } }))),
      h('div', {},
        lab('Fires when', selOf('mode', [['count', 'enough matching lines'], ['absent', 'no matching line at all (silence)']])),
        absent ? null : lab('Threshold (lines in the window)', num('threshold', 1, 1000000)),
        lab('Window (minutes, 5-1440)', num('window_min', 5, 1440)),
        absent ? null : lab('Group by (comma separated fields, optional: one firing per group)', h('input', { class: 'mono', style: 'width:100%', value: (d.group_by || []).join(', '), placeholder: 'host, appname',
          oninput: (ev) => { d.group_by = ev.target.value.split(',').map((x) => x.trim()).filter(Boolean); } })),
        lab('Cooldown (minutes: no repeat for the same group)', num('cooldown_min', 5, 10080)),
        lab('Action', selOf('action', DET_ACTIONS)),
        lab('Severity (for "direct" and "record only")', selOf('severity', ['info', 'low', 'medium', 'high', 'critical'])),
        h('label', { class: 'row small' }, h('input', { type: 'checkbox', checked: d.enabled !== false, onchange: (ev) => { d.enabled = ev.target.checked; } }), ' Enabled'))),
    btBox,
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: detEditApply }, 'Apply to draft'),
      h('button', { class: 'btn', onclick: () => { S.det.edit = null; S.det.bt = null; drawDet(); } }, 'Cancel')));
}
function drawDet() {
  const t = S.det, d = t.draft, dirty = !same(d, t.base);
  const stMap = {};
  ((t.status && t.status.detectors) || []).forEach((s) => { stMap[s.id] = s; });
  const rows = d.detectors.map((x) => {
    const f = detFull(x), s = stMap[f.id];
    return h('tr', { class: f.enabled === false ? 'unused' : '' },
      h('td', {}, h('input', { type: 'checkbox', title: 'Enabled', checked: f.enabled !== false, onchange: (ev) => { x.enabled = ev.target.checked; if (x.enabled) delete x.enabled; else x.enabled = false; t.diff = null; drawDet(); } })),
      h('td', {}, h('strong', {}, f.name || f.id), h('div', { class: 'muted small mono' }, f.id)),
      h('td', { class: 'small' }, detSummary(f), h('div', { class: 'mono muted' }, f.query)),
      h('td', { class: 'small' }, f.action === 'triage' ? 'model triage' : f.action === 'direct' ? 'direct (' + f.severity + ')' : 'record (' + f.severity + ')'),
      h('td', { class: 'small' }, !s ? h('span', { class: 'muted' }, dirty ? 'unsaved' : 'not evaluated yet')
        : s.error ? h('span', { class: 'badge sev-high', title: s.error }, 'error') : h('span', { class: 'muted' }, s.last_eval ? 'checked ' + fmtTime(s.last_eval) : '-'),
        s && s.last_fired ? h('div', { class: 'muted' }, 'fired ' + fmtTime(s.last_fired)) : null),
      h('td', { class: 'nowrap' }, h('button', { class: 'btn small', onclick: () => detEditStart(x, false) }, 'Edit'), ' ',
        h('button', { class: 'icon', title: 'Remove', onclick: () => { if (confirm('Remove detector ' + (f.name || f.id) + '?')) { d.detectors = d.detectors.filter((y) => y.id !== x.id); t.diff = null; drawDet(); } } }, '×')));
  });
  const recent = (t.status && t.status.recent) || [];
  const bar = h('div', { class: 'savebar' },
    t.diff !== null ? diffEl(t.diff) : null,
    t.error ? h('div', { class: 'err' }, t.error) : null,
    h('div', { class: 'row', style: t.diff !== null ? 'margin-top:8px' : '' },
      h('input', { class: 'grow', placeholder: 'Comment: what and why', value: t.comment, oninput: (e) => { t.comment = e.target.value; } }),
      h('button', { class: 'btn', disabled: !dirty, onclick: detDiff }, 'Preview diff'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => { S.det.draft = clone(S.det.base); S.det.edit = null; S.det.diff = null; S.det.bt = null; drawDet(); } }, 'Discard edits'),
      h('button', { class: 'btn', disabled: !dirty, onclick: () => detSubmit('propose') }, 'Propose'),
      isAdmin() ? h('button', { class: 'btn primary', disabled: !dirty, onclick: () => detSubmit('save') }, 'Save') : null),
    h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Revision #' + t.rev + (dirty ? ' · unsaved changes' : '') + (isAdmin() ? '' : ' · read-only token: use Propose, an admin approves.')));
  const tplSel = h('select', { onchange: (ev) => {
    const v = ev.target.value; ev.target.value = '';
    if (v === 'blank') detEditStart({ id: '', name: '', query: '' }, true); else if (DET_TEMPLATES[v]) detEditStart(DET_TEMPLATES[v], true);
  } }, [['', '+ Add detector…'], ['blank', 'Blank'], ['burst', 'Template: error burst in a container'], ['silence', 'Template: a source went silent'], ['message', 'Template: a specific message appeared']]
    .map(([v, l]) => h('option', { value: v }, l)));
  renderShell([
    h('h2', {}, 'Detectors'),
    h('p', { class: 'muted' }, 'Rules over the logs that the service evaluates itself, every ' + ((t.status && t.status.interval_s) || 60) + ' s' + (t.status && t.status.mode === 'off' ? ' (currently OFF: setting DETECTOR_MODE)' : '') +
      '. A firing becomes a model-triaged incident (noise rules, snoozes and the topology apply), a direct notification, or just a record. Always run the backtest before saving: it shows how often the rule would have fired.'),
    t.edit ? detEditor() : null,
    detHealthPanel(t.health),
    h('div', { class: 'panel' }, h('div', { class: 'row' }, h('h3', { class: 'grow', style: 'margin:0' }, 'Detectors (' + d.detectors.length + ')'), tplSel),
      d.detectors.length ? h('table', {}, h('thead', {}, h('tr', {}, ['On', 'Detector', 'Condition', 'Action', 'State', ''].map((x) => h('th', {}, x)))), h('tbody', {}, rows))
        : h('p', { class: 'muted' }, 'No detectors yet. Start from a template: error burst in a container, a source going silent, or a specific message.')),
    recent.length ? h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Recent firings'),
      h('table', {}, h('tbody', {}, recent.map((r) => h('tr', {}, h('td', { class: 'small nowrap' }, fmtTime(r._time)), h('td', {}, r.name || r.detector),
        h('td', { class: 'mono small' }, r.group && r.group !== '{}' ? r.group : ''), h('td', { class: 'num small' }, r.hits + ' lines'), h('td', { class: 'small' }, r.action)))))) : null,
    bar,
  ]);
}

// ---------------------------------------------------------------- settings
async function pageSettings() {
  const r = await api('GET', '/api/v1/config/settings');
  const spec = r.spec, stored = r.content || {};
  const inputs = {};
  const val = (s) => (s.key in stored ? stored[s.key] : s.default);
  const toText = (v) => (Array.isArray(v) ? v.join('\n') : String(v));
  const parse = (s) => {
    const raw = inputs[s.key].value;
    if (s.type === 'int') return raw.trim() === '' ? raw : Number(raw);
    if (s.type === 'urls') return raw.split('\n').map((x) => x.trim()).filter(Boolean);
    if (s.type === 'tasks') return raw.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
    return raw.trim();
  };
  const overrides = () => {
    const o = {};
    for (const s of spec) { const v = parse(s); if (!same(v, s.default)) o[s.key] = v; }
    return o;
  };
  const status = h('span', { class: 'muted small' });
  const upd = () => { const dirty = !same(overrides(), stored); status.textContent = dirty ? 'Unsaved changes' : 'No changes'; saveBtn.disabled = proposeBtn.disabled = resetBtn2.disabled = !dirty; };
  const saveBtn = h('button', { class: 'btn primary', onclick: () => send('save') }, 'Save');
  const proposeBtn = h('button', { class: 'btn', onclick: () => send('propose') }, 'Propose');
  const resetBtn2 = h('button', { class: 'btn', onclick: () => { for (const s of spec) inputs[s.key].value = toText(val(s)); upd(); } }, 'Discard edits');
  const comment = h('input', { class: 'grow', placeholder: 'Comment: what and why' });
  const errBox = h('div');
  const send = async (kind) => {
    errBox.replaceChildren();
    if (!comment.value.trim()) { toast('Add a short comment (what and why).', true); return; }
    try {
      if (kind === 'save') { const x = await api('PUT', '/api/v1/config/settings', { content: overrides(), comment: comment.value }); toast(x.changed ? 'Saved as revision ' + x.rev + '; active now.' : 'No changes.'); render(); }
      else { const x = await api('POST', '/api/v1/proposals', { key: 'settings', content: overrides(), comment: comment.value }); toast('Proposal #' + x.id + ' created.'); refreshPendingCount(); }
    } catch (e) { errBox.replaceChildren(h('div', { class: 'err' }, e.message)); }
  };
  const field = (s) => {
    let el;
    if (s.type === 'choice') el = h('select', {}, s.choices.map((c) => h('option', { value: c, selected: c === val(s) }, c)));
    else if (s.type === 'urls' || s.type === 'tasks') el = h('textarea', { class: 'mono', rows: 2, value: toText(val(s)) });
    else el = h('input', Object.assign({ class: s.type === 'int' ? '' : 'mono', value: toText(val(s)), style: 'width:100%' }, s.type === 'int' ? { type: 'number', min: s.min, max: s.max } : {}));
    el.addEventListener('input', upd); el.addEventListener('change', upd);
    inputs[s.key] = el;
    return el;
  };
  renderShell([
    h('h2', {}, 'Settings'),
    h('p', { class: 'muted' }, 'Overrides on top of the container\'s environment defaults. A value equal to the default is not stored. Secrets (webhook URL, tokens) are never editable here.'),
    h('div', { class: 'panel' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Setting'), h('th', {}, 'Value'), h('th', {}, 'Default'))),
      h('tbody', {}, spec.map((s) => h('tr', {},
        h('td', {}, h('div', { class: 'mono small' }, s.key), h('div', { class: 'muted small' }, s.desc)),
        h('td', { style: 'min-width:230px' }, field(s)),
        h('td', { class: 'mono small muted' }, toText(s.default), s.key in stored ? h('div', {}, h('span', { class: 'badge sev-medium' }, 'overridden')) : null)))))),
    errBox,
    h('div', { class: 'savebar' }, h('div', { class: 'row' }, comment, resetBtn2, proposeBtn, isAdmin() ? saveBtn : null),
      h('div', { class: 'row', style: 'margin-top:6px' }, status, h('span', { class: 'muted small' }, 'Revision #' + (r.id || 0) + (isAdmin() ? '' : ' · read-only token: use Propose')))),
  ]);
  upd();
}

// ---------------------------------------------------------------- proposals
// Deterministic evidence for a noise-rule proposal (impact on the baseline and on open findings, flags, examples). Text only.
function evidenceEl(ev) {
  if (!ev || !ev.length) return null;
  return h('div', {}, ev.map((e) => e.error ? h('div', { class: 'err' }, e.error) : h('div', { class: 'panel', style: 'background:var(--bg);margin:8px 0' },
    h('div', {}, h('strong', {}, 'Impact of this rule'), ' · ' + fmtN(e.templates) + ' pattern(s) in the 7-day baseline, ' + fmtN(e.hits) + ' line(s), ' + e.hosts + ' host(s)'
      + (e.top_hosts.length ? ' (' + e.top_hosts.map((t) => t.host).join(', ') + ')' : '')),
    h('div', { class: 'small muted' }, 'levels: ' + (Object.entries(e.levels).map(([l, c]) => l + ' ' + c).join(' · ') || 'none') + ' · open findings it would close: ' + e.covered_open),
    e.important_templates ? h('div', { class: 'small', style: 'color:var(--warn)' }, e.important_templates + ' covered pattern(s) are error level or worse: check them.') : null,
    e.attention.length ? h('div', { class: 'small', style: 'color:var(--warn)' }, 'Check carefully: touches ' + e.attention.join(', ') + '.') : null,
    e.similar_rules.length ? h('div', { class: 'small muted' }, 'Also covered by existing rule(s): ', e.similar_rules.map((s) => [h('code', {}, s), ' '])) : null,
    e.examples.length ? h('ul', { class: 'small' }, e.examples.map((x) => h('li', { class: 'mono', style: 'word-break:break-word' }, x.host + ' | ' + x.ident + ' | [' + x.level + '] ' + x.text))) : null)));
}
async function pageProposals() {
  const PAGE = 50, filter = S.propFilter || 'all';
  const url = (before) => '/api/v1/proposals?limit=' + PAGE + (filter === 'all' ? '' : '&status=' + filter) + (before ? '&before=' + before : '');
  const all = await api('GET', url());
  let more = all.length === PAGE;
  S.proposalsPending = (await api('GET', '/api/v1/proposals?status=pending&limit=200')).length;
  const decide = async (id, what, force, enable) => {
    const q = [force ? 'force=true' : '', enable ? 'enable=true' : ''].filter(Boolean).join('&');
    try {
      const r = await api('POST', '/api/v1/proposals/' + id + '/' + what + (q ? '?' + q : ''));
      toast('Proposal #' + id + ' ' + what + 'd.' + (r && r.enabled && r.enabled.length ? ' Enabled: ' + r.enabled.join(', ') + '.' : '') + (r && r.enable_error ? ' Could not enable: ' + r.enable_error : ''), !!(r && r.enable_error));
      S.draft = null; S.det = null; render();
    } catch (e) { toast(e.message, true); }
  };
  const card = (p) => {
    const body = h('div', { class: 'muted small' }, 'Loading diff...');
    const det = h('details', { ontoggle: async () => {
      if (!det.open || det.dataset.loaded) return; det.dataset.loaded = '1';
      try { const x = await api('GET', '/api/v1/proposals/' + p.id); body.replaceChildren(...[evidenceEl(x.evidence), diffEl(x.diff)].filter(Boolean)); } catch (e) { body.textContent = e.message; }
    } }, h('summary', {}, 'Show impact and changes'), body);
    const enBox = p.key === 'detectors' && p.status === 'pending' && isAdmin() ? h('input', { type: 'checkbox', checked: true }) : null;
    return h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('strong', {}, '#' + p.id), h('span', { class: 'badge b-unknown' }, p.key), stateBadge(p.status),
        p.attention && p.attention.length ? h('span', { class: 'badge b-stale', title: 'The rule text touches security or availability keywords. Open the impact view and read the covered lines before approving. This is a flag, not a verdict.' }, 'check carefully: ' + p.attention.join(', ')) : null,
        p.stale ? h('span', { class: 'badge b-stale', title: p.merge === 'clean' ? 'The configuration changed after this proposal was made; approving merges it onto the newer revision' : 'The configuration changed in the same place: ' + (p.conflicts || []).join(', ') }, p.merge === 'clean' ? 'will merge' : 'conflict') : null,
        h('span', { class: 'muted small' }, p.author + ' · ' + fmtTime(p.ts) + (p.decided_by ? ' · ' + p.status + ' by ' + p.decided_by : ''))),
      h('p', {}, p.comment), det,
      p.status === 'pending' && isAdmin() ? h('div', { class: 'row', style: 'margin-top:8px' },
        h('button', { class: 'btn primary', disabled: p.stale && p.merge !== 'clean', onclick: () => decide(p.id, 'approve', false, enBox && enBox.checked) }, p.stale && p.merge === 'clean' ? 'Approve (merge)' : 'Approve'),
        enBox ? h('label', { class: 'small', title: 'Detector drafts arrive disabled. Tick to switch the new detector(s) on in the same step (a second revision, easy to roll back).' }, enBox, ' enable the new detector') : null,
        p.stale && p.merge !== 'clean' ? h('button', { class: 'btn', onclick: () => confirm('Conflicting changes in ' + (p.conflicts || []).join(', ') + '. Apply the proposal as written? This overwrites the newer changes there.') && decide(p.id, 'approve', true) }, 'Approve anyway (overwrite)') : null,
        h('button', { class: 'btn danger', onclick: () => decide(p.id, 'reject') }, 'Reject')) : null);
  };
  const sel = h('select', { 'aria-label': 'Filter by state', onchange: () => { S.propFilter = sel.value; render(); } },
    ['all', 'pending', 'approved', 'rejected'].map((v) => h('option', { value: v, selected: v === filter }, v === 'all' ? 'All states' : v + (v === 'pending' ? ' (' + S.proposalsPending + ')' : ''))));
  const draw = () => renderShell([h('div', { class: 'row' }, h('h2', { class: 'grow', style: 'margin:0' }, 'Proposals'), sel),
    !isAdmin() ? h('div', { class: 'note' }, 'You are signed in with a read token: you can create proposals, an admin approves them.') : null,
    all.length ? all.map(card) : h('p', { class: 'muted' }, filter === 'all' ? 'No proposals yet.' : 'No ' + filter + ' proposals.'),
    more ? h('div', { class: 'row', style: 'justify-content:center' }, h('button', { class: 'btn', onclick: async (ev) => {
      ev.target.disabled = true;
      try { const next = await api('GET', url(all[all.length - 1].id)); all.push(...next); more = next.length === PAGE; draw(); }
      catch (e) { toast(e.message, true); ev.target.disabled = false; }
    } }, 'Load older proposals (shown ' + all.length + ')')) : null]);
  draw();
}

// ---------------------------------------------------------------- supervisor (read-only periodic review by a separate model; reports only)
async function pageSupervisor() {
  const [st, runs] = await Promise.all([api('GET', '/api/v1/supervisor'), api('GET', '/api/v1/supervisor/runs?limit=20')]);
  const runNow = async () => {
    try { await api('POST', '/api/v1/supervisor/run'); toast('Run requested; it starts within 30 s.'); setTimeout(render, 8000); } catch (e) { toast(e.message, true); }
  };
  const pct = st.tokens_budget ? Math.min(100, Math.round(100 * st.tokens_today / st.tokens_budget)) : 0;
  const runCard = (r) => h('div', { class: 'panel' },
    h('div', { class: 'row' }, h('strong', {}, 'Run #' + r.id), h('span', { class: 'badge ' + (r.status === 'ok' ? 'b-up' : r.status === 'budget' || r.status === 'partial' ? 'b-unknown' : 'b-down') }, r.status),
      h('span', { class: 'muted small grow' }, fmtTime(r.ts) + ' · ' + r.model + ' · ' + r.secs + ' s · ' + r.tokens + ' tokens')),
    h('p', {}, r.report.summary || ''),
    h('div', { class: 'muted small' }, Object.entries(r.report.tasks || {}).map(([n, t]) => n + ': ' + t.status + (t.items !== undefined ? ' (' + t.items + ' items, ' + t.findings + ' findings, ' + t.rejected + ' rejected)' : '') + (t.error ? ' - ' + t.error : '')).join(' · ')),
    r.report.findings.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Task', 'Severity', 'Finding', 'Detail'].map((x) => h('th', {}, x)))),
      h('tbody', {}, r.report.findings.map((f) => h('tr', {}, h('td', { class: 'mono small' }, f.task), h('td', {}, sevBadge(f.severity)), h('td', {}, f.title),
        h('td', { class: 'small' }, f.detail, f.regex ? h('div', {}, 'Suggested noise regex: ', h('code', {}, f.regex)) : null,
          f.query ? h('div', {}, 'Suggested filter: ', h('code', {}, f.query)) : null,
          f.backtest ? h('div', { class: 'muted' }, 'Backtest ' + (f.backtest.hours / 24) + ' d: ' + f.backtest.firings + ' firing(s), ' + f.backtest.total + ' matching line(s)') : null,
          f.noise_scan ? h('div', { class: 'muted' }, '7-day scan: ' + f.noise_scan.lines + ' line(s) in ' + f.noise_scan.templates + ' template(s); covers ' + f.noise_scan.refs_matched + '/' + f.noise_scan.refs + ' referenced; ' + f.noise_scan.collateral_templates + ' other template(s) of the same source' + (f.noise_scan.collateral && f.noise_scan.collateral.length ? ' (e.g. ' + f.noise_scan.collateral[0].text + ')' : '')) : null,
          f.draft ? h('details', {}, h('summary', { class: 'muted' }, 'Detector draft (disabled, not applied)'), h('pre', { class: 'diff' }, JSON.stringify(f.draft, null, 1))) : null,
          f.refs && f.refs.length ? h('div', { class: 'muted' }, 'refs: ' + f.refs.join(', ')) : null))))) : null,
    (r.report.proposals || []).length ? h('div', { class: 'note' }, 'Filed for approval: ', (r.report.proposals).map((p, i) => [i ? ', ' : '', h('a', { href: '#', onclick: (e) => { e.preventDefault(); go('proposals'); } }, '#' + p.id), ' (' + p.key + ')'])) : null,
    (r.report.proposals_skipped || []).length ? h('details', {}, h('summary', { class: 'muted small' }, (r.report.proposals_skipped.length) + ' suggestion(s) not filed (duplicate, limit, ...)'),
      h('ul', { class: 'small' }, r.report.proposals_skipped.map((x) => h('li', {}, x.title + ': ' + x.reason)))) : null,
    (r.report.rejected || []).length ? h('details', {}, h('summary', { class: 'muted small' }, (r.report.rejected.length) + ' suggestion(s) rejected by the guards'),
      h('ul', { class: 'small' }, r.report.rejected.map((x) => h('li', {}, x.title + ': ' + x.reason + (x.regex ? ' (' + x.regex + ')' : ''))))) : null);
  renderShell([
    h('h2', {}, 'Supervisor'),
    h('div', { class: 'note' }, 'Periodic review of the service state by a separate model. It never changes anything itself: in report mode it writes reports, in propose mode it also files validated suggestions as proposals that an admin must approve. Off by default.'),
    h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('span', { class: 'badge ' + (st.mode === 'off' ? 'b-unknown' : 'b-up') }, st.mode),
        h('span', { class: 'muted small grow' }, 'API: ' + st.api + ' · model: ' + st.model + ' · endpoint ' + (st.endpoint_configured ? 'set' : 'not set') + ' · key ' + (st.key_configured ? 'set' : 'not set')
          + ' · every ' + st.interval_min + ' min' + (st.next_run_utc ? ' · next: ' + fmtTime(st.next_run_utc) : '')),
        isAdmin() && st.mode !== 'off' ? h('button', { class: 'btn', disabled: st.running, onclick: runNow }, st.running ? 'Running...' : 'Run now') : null),
      h('div', { class: 'muted small', style: 'margin-top:8px' }, 'Token budget today: ' + st.tokens_today + ' / ' + st.tokens_budget + ' (' + pct + '%)'
        + (st.mode === 'propose' ? ' · proposals filed today: ' + st.proposals_today + ' / ' + st.proposals_per_day : '') + '. Change the mode and the model on the Settings page.')),
    runs.length ? runs.map(runCard) : h('p', { class: 'muted' }, st.mode === 'off' ? 'The supervisor is off.' : 'No run yet.'),
  ]);
}

// ---------------------------------------------------------------- history & audit
async function pageHistory() {
  const key = S.historyKey || 'known';
  const revs = await api('GET', '/api/v1/config/' + key + '/revisions');
  let audit = null;
  if (isAdmin()) audit = await api('GET', '/api/v1/audit?limit=100');
  const rollback = async (id) => {
    if (!confirm('Roll back ' + key + ' to revision ' + id + '? The current state stays in the history.')) return;
    try { const r = await api('POST', '/api/v1/config/' + key + '/rollback/' + id); toast('Rolled back as revision ' + r.rev + '.'); S.draft = null; render(); } catch (e) { toast(e.message, true); }
  };
  const revRow = (r, i) => {
    const body = h('div', { class: 'muted small' }, 'Loading...');
    const det = h('details', { ontoggle: async () => {
      if (!det.open || det.dataset.loaded) return; det.dataset.loaded = '1';
      try { const x = await api('GET', '/api/v1/config/' + key + '/revisions/' + r.id + '/diff'); body.replaceChildren(h('div', { class: 'muted small' }, 'Changes a rollback to this revision would make:'), diffEl(x.diff)); } catch (e) { body.textContent = e.message; }
    } }, h('summary', { class: 'muted small' }, 'Compare with current'), body);
    return h('tr', {}, h('td', { class: 'num' }, '#' + r.id + (i === 0 ? ' (current)' : '')), h('td', { class: 'small' }, fmtTime(r.ts)), h('td', { class: 'small' }, r.author),
      h('td', {}, r.comment || '-', i > 0 ? det : null),
      h('td', {}, i > 0 && isAdmin() ? h('button', { class: 'btn', onclick: () => rollback(r.id) }, 'Roll back') : null));
  };
  renderShell([
    h('h2', {}, 'History'),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, h('span', { class: 'muted' }, 'Document'),
      h('select', { onchange: (e) => { S.historyKey = e.target.value; render(); } }, ['known', 'topology', 'detectors', 'rules', 'ingest', 'settings'].map((k) => h('option', { value: k, selected: k === key }, k)))),
    h('div', { class: 'panel' }, h('table', {}, h('thead', {}, h('tr', {}, ['Revision', 'When', 'Who', 'Comment', ''].map((x) => h('th', {}, x)))), h('tbody', {}, revs.map(revRow)))),
    audit ? h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Audit log'),
      h('table', {}, h('thead', {}, h('tr', {}, ['When', 'Who', 'Action', 'Detail'].map((x) => h('th', {}, x)))),
        h('tbody', {}, audit.map((a) => h('tr', {}, h('td', { class: 'small' }, fmtTime(a.ts)), h('td', { class: 'small' }, a.actor), h('td', { class: 'mono small' }, a.action), h('td', { class: 'small' }, a.detail)))))) : null,
  ]);
}

// ---------------------------------------------------------------- severity mapping & ingest
S.ing = null;
async function loadIng() {
  const r = await api('GET', '/api/v1/config/ingest');
  const keep = S.ing || {};
  S.ing = { rev: r.id, base: r.content, eff: r.effective, text: JSON.stringify(r.content, null, 2), comment: '', error: '', diff: null,
    src: keep.src || 'dynatrace', val: keep.val || '', res: null };
}
function ingDraft() {
  try {
    const d = JSON.parse(S.ing.text || '{}');
    if (!d || typeof d !== 'object' || Array.isArray(d)) throw new Error('the document must be a JSON object');
    S.ing.error = ''; return d;
  } catch (e) { S.ing.error = 'Not valid JSON: ' + e.message; drawIng(); return null; }
}
async function ingTry() {
  const d = ingDraft(); if (!d) return;
  try { S.ing.res = await api('POST', '/api/v1/test/ingest', { source: S.ing.src, value: S.ing.val, content: d }); } catch (e) { S.ing.res = null; S.ing.error = e.message; }
  drawIng();
}
async function ingDiff() {
  const d = ingDraft(); if (!d) return;
  try { S.ing.diff = (await api('POST', '/api/v1/config/ingest/diff', { content: d })).diff; S.ing.error = ''; } catch (e) { S.ing.error = e.message; }
  drawIng();
}
async function ingSubmit(kind) {
  const d = ingDraft(); if (!d) return;
  const comment = S.ing.comment.trim();
  if (!comment) { toast('Add a short comment (what and why).', true); return; }
  try {
    if (kind === 'save') {
      const r = await api('PUT', '/api/v1/config/ingest', { content: d, comment });
      toast(r.changed ? 'Saved as revision ' + r.rev + '; active now.' : 'No changes.');
      S.ing = null; await loadIng();
    } else {
      const r = await api('POST', '/api/v1/proposals', { key: 'ingest', content: d, comment });
      toast('Proposal #' + r.id + ' created.'); S.ing.comment = ''; refreshPendingCount();
    }
  } catch (e) { S.ing.error = e.message; toast('Rejected: see the message above', true); }
  drawIng();
}
const pageIngest = async () => { if (!S.ing) await loadIng(); drawIng(); };
const ingSev = (l) => (l === 'critical' ? 'critical' : l === 'error' ? 'high' : l === 'warning' ? 'medium' : 'info');
function drawIng() {
  const g = S.ing;
  const dirty = (() => { try { return JSON.stringify(JSON.parse(g.text || '{}')) !== JSON.stringify(g.base); } catch (e) { return true; } })();
  const effRows = Object.entries(g.eff || {}).map(([name, s]) => h('tr', {},
    h('td', { class: 'mono small nowrap' }, name, h('div', { class: 'muted' }, s.builtin ? 'built-in + overrides' : 'custom')),
    h('td', {}, h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px 12px' }, Object.entries(s.severity).map(([raw, lvl]) => h('span', { style: 'white-space:nowrap' },
      h('span', { class: 'mono small' }, raw + ' → '), sevBadge(ingSev(lvl)), ' ', h('span', { class: 'small muted' }, lvl))))),
    h('td', { class: 'small nowrap' }, 'unmapped → ', h('strong', {}, s.default)),
    h('td', { class: 'mono small muted' }, Object.entries(s.fields).map(([k, v]) => k + '=' + v).join(', ') || 'default field names')));
  const res = g.res ? h('span', {}, ' → ', sevBadge(ingSev(g.res.level)), ' ', h('strong', {}, g.res.level),
    g.res.mapped ? null : h('span', { class: 'err small' }, ' (not mapped: the default applies)')) : null;
  renderShell([
    h('h2', {}, 'Severity & ingest'),
    h('p', { class: 'muted' }, 'Every tool has its own severity scale. The console works on one: debug, info, warning, error, critical. The mapping turns a raw value into that scale. An unmapped value counts as the source default (error unless set), never silently as info.'),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Overrides (JSON document)'),
      h('p', { class: 'muted small' }, 'The built-in defaults for four common tools are typical scales, not vendor specifications: check them against your real values. Shape: sources.<tool>.severity {raw: level}, .default, .fields {host, msg, ts, level, ident: dotted paths}.'),
      h('textarea', { class: 'mono', rows: 12, style: 'width:100%', value: g.text, spellcheck: false, oninput: (e) => { g.text = e.target.value; g.diff = null; } }),
      g.error ? h('div', { class: 'err' }, g.error) : null,
      g.diff !== null ? diffEl(g.diff) : null,
      h('div', { class: 'row', style: 'margin-top:8px' },
        h('input', { class: 'grow', placeholder: 'Comment: what and why', value: g.comment, oninput: (e) => { g.comment = e.target.value; } }),
        h('button', { class: 'btn', onclick: ingDiff }, 'Preview diff'),
        h('button', { class: 'btn', onclick: () => ingSubmit('propose') }, 'Propose'),
        isAdmin() ? h('button', { class: 'btn primary', onclick: () => ingSubmit('save') }, 'Save') : null),
      h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Revision #' + g.rev + (dirty ? ' · unsaved changes' : '') + (isAdmin() ? '' : ' · read-only token: use Propose, an admin approves.'))),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Try a value'),
      h('div', { class: 'row' },
        h('input', { list: 'ing-src', value: g.src, placeholder: 'tool, e.g. dynatrace', oninput: (e) => { g.src = e.target.value; } }),
        h('datalist', { id: 'ing-src' }, Object.keys(g.eff || {}).map((n) => h('option', { value: n }))),
        h('input', { value: g.val, placeholder: 'raw severity, e.g. AVAILABILITY', oninput: (e) => { g.val = e.target.value; }, onkeydown: (e) => { if (e.key === 'Enter') ingTry(); } }),
        h('button', { class: 'btn primary', onclick: ingTry }, 'Normalise'), res),
      h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Uses the document above (unsaved edits included); nothing is changed.')),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Effective mapping (saved configuration)'),
      h('div', { style: 'overflow-x:auto' },
        h('table', {}, h('thead', {}, h('tr', {}, ['Tool', 'Raw value → level', 'Fallback', 'Field paths'].map((x) => h('th', {}, x)))), h('tbody', {}, effRows)))),
  ]);
}

// ---------------------------------------------------------------- alert rules (vmalert rules managed here; released to vmalert when RULES_SYNC is on)
S.rul = null;
const RULE_TEMPLATE = { rules: [{ id: 'ContainerLogFlood', kind: 'count', query: 'pipeline:docker', group_by: ['host', 'appname'], threshold: 12001, window_min: 1, severity: 'medium' }] };
async function loadRul() {
  const r = await api('GET', '/api/v1/config/rules');
  const keep = S.rul || {};
  S.rul = { rev: r.id, base: r.content, text: JSON.stringify(r.id ? r.content : RULE_TEMPLATE, null, 2), comment: '', error: '', diff: null, pre: keep.pre || null, sync: null };
  await loadRulSync();
}
async function loadRulSync() {
  try { S.rul.sync = await api('GET', '/api/v1/rules/sync'); } catch (e) { S.rul.sync = null; }
}
async function rulResync() {
  try { await api('POST', '/api/v1/rules/sync'); toast('Re-apply requested.'); } catch (e) { toast(e.message, true); return; }
  setTimeout(async () => { await loadRulSync(); if (S.tab === 'rules') drawRul(); }, 4000);
}
function rulDraft() {
  try {
    const d = JSON.parse(S.rul.text || '{}');
    if (!d || typeof d !== 'object' || Array.isArray(d)) throw new Error('the document must be a JSON object');
    S.rul.error = ''; return d;
  } catch (e) { S.rul.error = 'Not valid JSON: ' + e.message; drawRul(); return null; }
}
async function rulPreview() {
  const d = rulDraft(); if (!d) return;
  try { S.rul.pre = await api('POST', '/api/v1/rules/preview', { content: d }); S.rul.error = ''; } catch (e) { S.rul.pre = null; S.rul.error = e.message; }
  drawRul();
}
async function rulDiff() {
  const d = rulDraft(); if (!d) return;
  try { S.rul.diff = (await api('POST', '/api/v1/config/rules/diff', { content: d })).diff; S.rul.error = ''; } catch (e) { S.rul.error = e.message; }
  drawRul();
}
async function rulSubmit(kind) {
  const d = rulDraft(); if (!d) return;
  const comment = S.rul.comment.trim();
  if (!comment) { toast('Add a short comment (what and why).', true); return; }
  try {
    if (kind === 'save') {
      const r = await api('PUT', '/api/v1/config/rules', { content: d, comment });
      toast(r.changed ? 'Saved as revision ' + r.rev + '. Release to vmalert: see the panel below (a few seconds).' : 'No changes.');
      S.rul = null; await loadRul();
    } else {
      const r = await api('POST', '/api/v1/proposals', { key: 'rules', content: d, comment });
      toast('Proposal #' + r.id + ' created.'); S.rul.comment = ''; refreshPendingCount();
    }
  } catch (e) { S.rul.error = e.message; toast('Rejected: see the message above', true); }
  drawRul();
}
const pageRules = async () => { if (!S.rul) await loadRul(); else await loadRulSync(); drawRul(); };
function rulSyncPanel(g) {
  const y = g.sync;
  if (!y) return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Release to vmalert'), h('p', { class: 'muted' }, 'Status unavailable.'));
  const live = (y.vmalert || []).map((x) => h('tr', {}, h('td', { class: 'mono small' }, x.group), h('td', { class: 'mono small' }, x.rule),
    h('td', { class: 'small' }, x.state), h('td', { class: 'small' }, x.health === 'err' ? h('span', { class: 'err' }, x.error || 'error') : x.health || '-')));
  const behind = y.sync === 'on' && y.saved_rev !== y.applied_rev;
  return h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Release to vmalert'),
    h('div', { class: 'row' },
      stateBadge(y.state === 'ok' ? 'up' : y.state === 'error' ? 'down' : 'unknown'), h('strong', {}, y.sync === 'on' ? 'sync on' : 'sync off'),
      h('span', { class: 'muted small grow' }, y.configured ? '' : 'VMALERT_URL / RULES_DIR are not set on the service.'),
      isAdmin() && y.sync === 'on' ? h('button', { class: 'btn', onclick: rulResync }, 'Re-apply') : null),
    h('p', { class: 'small' }, y.message || 'No release attempt yet.', y.ts ? h('span', { class: 'muted' }, ' (' + fmtTime(y.ts) + ')') : null),
    h('div', { class: 'muted small' }, 'Saved revision #' + y.saved_rev + ' · released revision #' + (y.applied_rev || 0) + (behind ? ' · behind' : '')),
    live.length ? h('table', { style: 'margin-top:8px' }, h('thead', {}, h('tr', {}, ['Group', 'Rule', 'State', 'Health'].map((x) => h('th', {}, x)))), h('tbody', {}, live)) : null,
    y.vmalert_error ? h('div', { class: 'err small' }, 'vmalert: ' + y.vmalert_error) : null);
}
function drawRul() {
  const g = S.rul;
  const dirty = (() => { try { return JSON.stringify(JSON.parse(g.text || '{}')) !== JSON.stringify(g.base); } catch (e) { return true; } })();
  const saved = (g.base && g.base.rules) || [];
  const rows = saved.map((x) => h('tr', {},
    h('td', { class: 'mono small nowrap' }, x.id), h('td', { class: 'small' }, x.kind), h('td', { class: 'small nowrap' }, (x.interval_min || 1) + ' min'),
    h('td', {}, sevBadge(x.severity || 'medium')), h('td', { class: 'small' }, x.notify || 'triage'),
    h('td', { class: 'small' }, x.enabled === false ? h('span', { class: 'muted' }, 'off') : 'on')));
  const pre = g.pre;
  renderShell([
    h('h2', {}, 'Alert rules'),
    h('p', { class: 'muted' }, 'Detection runs in vmalert (VictoriaLogs rules) and Alertmanager; the console manages the rules here (proposal, approval, revision, audit) and turns them into the vmalert rule file. A saved revision reaches vmalert only when rule sync is on (Settings: RULES_SYNC, and the VMALERT_URL / RULES_DIR environment variables); the rules defined in the logstack compose file keep running as they are.'),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Rules (JSON document)'),
      h('p', { class: 'muted small' }, 'Kinds: count (threshold of matching lines in a window, optional group_by), silence (a source that was seen in history_h hours but not for window_min minutes), absent (no match at all in the window), raw (full LogsQL with a stats pipe, expert). notify: triage (AI analysis) | direct (straight to Home Assistant) | none (log only). The summary may only use {{ $value }} and {{ $labels.<field> }}.'),
      h('textarea', { class: 'mono', rows: 16, style: 'width:100%', value: g.text, spellcheck: false, oninput: (e) => { g.text = e.target.value; g.diff = null; g.pre = null; } }),
      g.error ? h('div', { class: 'err' }, g.error) : null,
      g.diff !== null ? diffEl(g.diff) : null,
      h('div', { class: 'row', style: 'margin-top:8px' },
        h('input', { class: 'grow', placeholder: 'Comment: what and why', value: g.comment, oninput: (e) => { g.comment = e.target.value; } }),
        h('button', { class: 'btn', onclick: rulPreview }, 'Validate & render'),
        h('button', { class: 'btn', onclick: rulDiff }, 'Preview diff'),
        h('button', { class: 'btn', onclick: () => rulSubmit('propose') }, 'Propose'),
        isAdmin() ? h('button', { class: 'btn primary', onclick: () => rulSubmit('save') }, 'Save') : null),
      h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Revision #' + g.rev + (dirty ? ' · unsaved changes' : '') + (isAdmin() ? '' : ' · read-only token: use Propose, an admin approves.'))),
    pre ? h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'vmalert rule file (preview)'),
      pre.errors && pre.errors.length ? h('div', { class: 'err' }, pre.errors.join('\n'))
        : [h('p', { class: 'muted small' }, pre.rules + ' enabled rule(s), ' + pre.disabled + ' disabled. This text would be written to the shared rules folder.'),
          h('pre', { class: 'diff' }, Object.values(pre.files)[0])]) : null,
    rulSyncPanel(g),
    h('div', { class: 'panel' }, h('h3', { style: 'margin-top:0' }, 'Saved rules (' + saved.length + ')'),
      saved.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Rule', 'Kind', 'Evaluated', 'Severity', 'Notify', 'State'].map((x) => h('th', {}, x)))), h('tbody', {}, rows))
        : h('p', { class: 'muted' }, 'No saved rules yet. The editor above starts from an example (the Docker log flood rule).')),
  ]);
}

render();
