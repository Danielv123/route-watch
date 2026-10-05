import { network, overlaps } from './network.js';

export function normalizeDevice(d) {
  return {
    id: String(d.nodeId || d.id), name: d.hostname || d.name || String(d.nodeId || d.id),
    dnsName: d.name || '', addresses: d.addresses || [], user: d.user || '', tags: d.tags || [],
    os: d.os || 'unknown', lastSeen: d.lastSeen || null,
    connected: typeof d.connectedToControl === 'boolean' ? d.connectedToControl : null,
    authorized: d.authorized !== false, external: d.isExternal === true,
    expires: d.expires || null, keyExpiryDisabled: d.keyExpiryDisabled === true,
  };
}

export function analyzeRoutes(devices) {
  const byPrefix = new Map();
  const warnings = [];
  const exitNodeIds = new Set();
  for (const d of devices) {
    const canonical = values => new Set((values || []).flatMap(raw => {
      try {
        const n = network(raw);
        if (n.prefix === 0) { exitNodeIds.add(d.id); return []; }
        return [n.cidr];
      } catch { warnings.push(`Invalid route on ${d.name}: ${raw}`); return []; }
    }));
    const advertised = canonical(d.advertisedRoutes);
    const approved = canonical(d.enabledRoutes);
    for (const cidr of new Set([...advertised, ...approved])) {
      if (!byPrefix.has(cidr)) byPrefix.set(cidr, { cidr, entries: [], findings: [] });
      byPrefix.get(cidr).entries.push({ deviceId: d.id, advertised: advertised.has(cidr), approved: approved.has(cidr) });
    }
  }
  const routes = [...byPrefix.values()];
  function finding(route, type, severity, title, message, deviceIds, related = []) {
    route.findings.push({ type, severity, title, message, deviceIds, related });
  }
  for (const r of routes) {
    const approved = r.entries.filter(e => e.approved);
    const pending = r.entries.filter(e => e.advertised && !e.approved);
    if (approved.length > 1) finding(r, 'duplicate', 'danger', 'Duplicate approvals', `${approved.length} devices retain approval for this subnet. An old router can resume advertising it without a new approval. Confirm whether this is intentional high availability.`, approved.map(e => e.deviceId));
    else if (r.entries.length > 1) finding(r, 'potential', 'warning', 'Potential duplicate', 'Multiple devices have this route configured. Check the existing owner before approving another advertisement.', r.entries.map(e => e.deviceId));
    for (const e of r.entries.filter(e => e.approved && !e.advertised)) finding(r, 'stale', 'warning', 'Unused approval', 'This device is approved but no longer advertises the subnet. The approval can become active again if it re-advertises.', [e.deviceId]);
    if (pending.length) finding(r, 'pending', 'info', 'Awaiting approval', `${pending.length} device(s) advertise this route without approval.`, pending.map(e => e.deviceId));
  }
  for (let i = 0; i < routes.length; i++) for (let j = i + 1; j < routes.length; j++) {
    const a = routes[i], b = routes[j];
    if (!overlaps(network(a.cidr), network(b.cidr))) continue;
    const pairs = a.entries.flatMap(x => b.entries.filter(y => x.deviceId !== y.deviceId).map(y => [x, y]));
    if (!pairs.length) continue;
    const bothApproved = pairs.some(([x, y]) => x.approved && y.approved);
    for (const [r, other] of [[a, b], [b, a]]) finding(r, 'overlap', bothApproved ? 'warning' : 'info', bothApproved ? 'Overlapping approvals' : 'Potential overlap', `Overlaps ${other.cidr} on another device. The more-specific prefix wins; check that both paths lead to the intended network.`, [...new Set(pairs.flat().map(e => e.deviceId))], [other.cidr]);
  }
  const rank = { danger: 3, warning: 2, info: 1, clear: 0 };
  for (const r of routes) {
    r.severity = r.findings.reduce((s, f) => rank[f.severity] > rank[s] ? f.severity : s, 'clear');
    r.approvedCount = r.entries.filter(e => e.approved).length;
    r.advertisedCount = r.entries.filter(e => e.advertised).length;
    r.activeCount = r.entries.filter(e => e.approved && e.advertised).length;
  }
  routes.sort((a, b) => rank[b.severity] - rank[a.severity] || a.cidr.localeCompare(b.cidr, undefined, { numeric: true }));
  return { routes, warnings, exitNodeCount: exitNodeIds.size };
}
