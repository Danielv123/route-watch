const $ = selector => document.querySelector(selector);
const state = { demo: new URLSearchParams(location.search).get('demo') === '1', snapshot: null, selected: null, access: null, accessFilter: 'relevant', accessSequence: 0, loading: false };
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const badge = (label, kind = '') => `<span class="badge ${kind}">${escape(label)}</span>`;
const device = id => state.snapshot.devices.find(d => d.id === id) || { name: id, addresses: [], tags: [] };
const label = { danger: 'Duplicate', warning: 'Review', info: 'Pending / overlap', clear: 'No conflict found', allowed: 'Policy allows', conditional: 'Conditional', 'no-match': 'No matching rule' };
const api = async path => {
  const response = await fetch(path, { cache: 'no-store' });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
};
const query = () => state.demo ? '?demo=1' : '';
function time(value) { return value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Not reported'; }
function connection(d) { return d.connected === true ? 'Connected to control' : d.connected === false ? `Offline · seen ${time(d.lastSeen)}` : `Last seen ${time(d.lastSeen)}`; }

function notices(error) {
  const s = state.snapshot;
  const rows = [];
  if (state.demo) rows.push('<div class="notice"><strong>Sample inventory</strong> Fictional devices and policy. No connection to your tailnet. <a href="/">Connect your tailnet</a></div>');
  if (error) rows.push(`<div class="notice error" role="alert"><strong>Inventory unavailable</strong>${escape(error)}${s ? ' The inventory below is from the last successful refresh.' : ''}</div>`);
  if (s?.warnings.length) rows.push(`<div class="notice ${s.stale || !s.routesComplete ? 'error' : ''}"><strong>${s.stale ? 'Snapshot is stale' : !s.routesComplete ? 'Incomplete route inventory' : 'Some information needs attention'}</strong><ul>${s.warnings.map(w => `<li>${escape(w)}</li>`).join('')}</ul></div>`);
  $('#notices').innerHTML = rows.join('');
}
function metrics() {
  const s = state.snapshot;
  const count = type => s.routes.filter(r => r.findings.some(f => f.type === type)).length;
  $('#metrics').innerHTML = [
    ['Subnets tracked', s.routes.length, `${s.devices.length} devices in inventory`, ''],
    ['Duplicate approvals', count('duplicate'), 'Same prefix, multiple owners', 'danger'],
    ['Overlapping prefixes', count('overlap'), 'Routes on different devices', 'warning'],
    ['Unused approvals', count('stale'), 'Approved, no longer advertised', 'warning'],
  ].map(([title, number, note, style]) => `<div class="metric ${style}"><div class="metric-label">${title}</div><div class="metric-value">${number}${!s.routesComplete ? '+' : ''}</div><div class="metric-note">${note}</div></div>`).join('');
}
function routeList() {
  const s = state.snapshot; if (!s) return;
  const term = $('#search').value.trim().toLowerCase(), filter = $('#filter').value;
  const visible = s.routes.filter(r => {
    const text = `${r.cidr} ${r.entries.map(e => { const d = device(e.deviceId); return `${d.name} ${d.user} ${d.tags.join(' ')}`; }).join(' ')}`.toLowerCase();
    return text.includes(term) && (filter === 'all' || (filter === 'attention' ? r.findings.some(f => f.severity === 'danger' || f.severity === 'warning') : r.findings.some(f => f.type === filter)));
  });
  $('#route-count').textContent = `${visible.length} / ${s.routes.length}`;
  $('#route-list').innerHTML = visible.map(r => `<button class="route-row ${r.cidr === state.selected ? 'selected' : ''}" data-route="${escape(r.cidr)}" aria-pressed="${r.cidr === state.selected}"><div class="route-first"><span class="route-cidr">${escape(r.cidr)}</span>${badge(label[r.severity], r.severity)}</div><div class="route-owners">${r.entries.map(e => escape(device(e.deviceId).name)).join(' · ')}</div><div class="route-meta">${r.approvedCount} approved · ${r.advertisedCount} advertising</div></button>`).join('') || '<div class="empty"><strong>No routes to show</strong>Try a different search or filter.</div>';
  $('#exit-count').textContent = `${s.exitNodeCount} device(s) with default routes.`;
}
function routerCard(entry) {
  const d = device(entry.deviceId);
  const status = entry.approved ? (entry.advertised ? badge('Approved + advertised', 'info') : badge('Unused approval', 'warning')) : badge('Awaiting approval');
  return `<article class="router-card"><div><div class="router-name">${escape(d.name)}</div><div class="router-sub mono">${d.addresses.map(escape).join(' · ')}</div><div class="router-sub">${escape(d.tags.length ? d.tags.join(', ') : d.user || 'Owner not reported')} · ${escape(d.os)}</div>${!d.authorized ? '<div class="router-sub">Device is not authorized.</div>' : ''}${d.expires && !d.keyExpiryDisabled && new Date(d.expires) < new Date() ? '<div class="router-sub">Device key has expired.</div>' : ''}</div><div class="router-state">${status}<span class="connection">${escape(connection(d))}</span></div></article>`;
}
function detail() {
  const r = state.snapshot.routes.find(r => r.cidr === state.selected);
  if (!r) { $('#detail').innerHTML = '<div class="empty"><strong>Select a subnet</strong>Inspect route ownership and the devices permitted by policy.</div>'; return; }
  $('#detail').innerHTML = `<div class="detail-head"><div><h2>${escape(r.cidr)}</h2><p>${r.entries.length} configured device(s) · ${r.activeCount} approved advertisement(s)</p></div>${badge(label[r.severity], r.severity)}</div>
    ${r.findings.length ? `<div class="section">${r.findings.map(f => `<div class="finding ${f.severity}"><h3>${escape(f.title)}</h3><p>${escape(f.message)}</p>${f.related.map(cidr => `<button class="text-button" data-route="${escape(cidr)}">Inspect ${escape(cidr)}</button>`).join('')}</div>`).join('')}</div>` : '<div class="section"><p class="section-note">No duplicate or overlapping routes were found in this snapshot.</p></div>'}
    <div class="section"><div class="section-title"><h3>Advertising & approval</h3><span class="count">${r.entries.length} devices</span></div><div class="router-grid">${r.entries.map(routerCard).join('')}</div></div>
    <div class="section"><div class="section-title"><h3>Who can contact this subnet?</h3><span class="count">ACLs + grants</span></div><p class="section-note">Matching policy permissions for devices in this inventory. Expand a device to see destinations, ports and the rule behind its access.</p><div id="access"><div class="empty">Evaluating policy…</div></div></div>`;
  renderAccess();
}
function permission(m) {
  return `<div class="permission"><div class="permission-title"><strong>${escape(m.rule)}</strong>${badge(m.status === 'allowed' ? m.coverage : 'Needs verification', m.status)}</div><p><strong>Destination:</strong> <span class="mono">${m.destinations.map(escape).join(', ')}</span></p><p><strong>Permissions:</strong> <span class="mono">${m.permissions.map(escape).join(', ') || 'Unresolved'}</span></p><p><strong>Source:</strong> ${m.selectors.map(escape).join(', ')}</p>${m.reasons.length ? `<ul>${m.reasons.map(reason => `<li>${escape(reason)}</li>`).join('')}</ul>` : ''}${m.definition ? `<details class="rule-code"><summary>View policy rule</summary><pre>${escape(JSON.stringify(m.definition, null, 2))}</pre></details>` : ''}</div>`;
}
function renderAccess() {
  const root = $('#access'), access = state.access; if (!root || !access) return;
  if (access.error) { root.innerHTML = `<div class="notice error">${escape(access.error)}</div>`; return; }
  if (!access.available) { root.innerHTML = `<div class="notice">${escape(access.message)}</div>`; return; }
  const summary = access.summary;
  const choices = [['relevant', `Matching (${summary.allowed + summary.conditional})`], ['allowed', `Allowed (${summary.allowed})`], ['conditional', `Conditional (${summary.conditional})`], ['no-match', `No match (${summary.noMatch})`]];
  const rows = access.rows.filter(row => state.accessFilter === 'relevant' ? row.status !== 'no-match' : row.status === state.accessFilter);
  root.innerHTML = `${access.stale ? '<div class="notice error">Access results use a stale snapshot.</div>' : ''}<div class="access-filters" role="group" aria-label="Filter device access">${choices.map(([id, title]) => `<button class="pill ${id === state.accessFilter ? 'active' : ''}" data-access-filter="${id}" aria-pressed="${id === state.accessFilter}">${title}</button>`).join('')}</div>${rows.map(row => {
    const d = device(row.deviceId);
    return `<details class="access-row"><summary><div class="access-identity"><strong>${escape(d.name)}</strong><span>${escape(d.tags.length ? d.tags.join(', ') : d.user || d.addresses.join(', '))}</span></div>${badge(label[row.status], row.status)}</summary><div class="access-body"><p class="muted">${escape(connection(d))}${!d.authorized ? ' · Device not authorized' : ''}</p>${row.matches.length ? row.matches.map(permission).join('') : '<p>No matching network rule was found for this device and subnet. This is policy analysis, not a live connectivity test.</p>'}</div></details>`;
  }).join('') || '<div class="empty">No devices in this category.</div>'}<p class="section-note">${escape(access.message)}</p>`;
}
async function selectRoute(cidr) {
  state.selected = cidr; state.access = null; state.accessFilter = 'relevant';
  const sequence = ++state.accessSequence;
  routeList(); detail();
  if (!cidr) return;
  try {
    const result = await api(`/api/access?subnet=${encodeURIComponent(cidr)}${state.demo ? '&demo=1' : ''}`);
    if (sequence !== state.accessSequence) return;
    state.access = result;
  } catch (error) { if (sequence !== state.accessSequence) return; state.access = { error: error.message }; }
  renderAccess();
}
async function refresh() {
  if (state.loading) return;
  state.loading = true; $('#refresh').disabled = true; $('#refresh').textContent = 'Reading inventory…';
  try {
    state.snapshot = await api(`/api/snapshot${query()}`);
    const s = state.snapshot;
    $('#workspace').hidden = false; $('#setup').hidden = true;
    $('#subtitle').textContent = `${state.demo ? 'Sample tailnet' : s.tailnet === '-' ? 'Connected tailnet' : s.tailnet} · ${s.policy.available ? `${s.policy.rules} network policy rules` : 'Policy unavailable'}`;
    $('#freshness').textContent = `${s.stale ? 'Stale · ' : ''}Read ${time(s.fetchedAt)}`;
    notices(); metrics(); routeList();
    await selectRoute(s.routes.some(r => r.cidr === state.selected) ? state.selected : s.routes[0]?.cidr || null);
  } catch (error) { notices(error.message); $('#freshness').textContent = 'Refresh failed'; }
  finally { state.loading = false; $('#refresh').disabled = false; $('#refresh').textContent = 'Refresh inventory'; }
}
$('#refresh').addEventListener('click', refresh);
$('#search').addEventListener('input', routeList);
$('#filter').addEventListener('change', routeList);
document.addEventListener('click', event => {
  const route = event.target.closest('[data-route]');
  if (route) selectRoute(route.dataset.route);
  const access = event.target.closest('[data-access-filter]');
  if (access) { state.accessFilter = access.dataset.accessFilter; renderAccess(); }
});
async function start() {
  try {
    const config = await api('/api/config');
    if (!config.configured && !state.demo) {
      $('#setup').hidden = false; $('#refresh').hidden = true;
      $('#scopes').innerHTML = config.scopes.map(scope => `<code>${escape(scope)}</code>`).join('');
      $('#freshness').textContent = 'Not connected'; return;
    }
    await refresh();
    if (!state.demo) setInterval(() => { if (!document.hidden) refresh(); }, Math.max(15, config.refreshSeconds) * 1000);
  } catch (error) { notices(error.message); }
}
start();
