import { parse } from 'jsonc-parser';
import { network, tryNetwork, contains, intersection, rangeLabel, subtract } from './network.js';

const yes = { state: 'yes', reasons: [] }, no = { state: 'no', reasons: [] };
const unknown = reason => ({ state: 'unknown', reasons: [reason] });
const own = (o, key) => Object.hasOwn(o || {}, key);
function any(results) {
  if (results.some(r => r.state === 'yes')) return yes;
  const reasons = results.flatMap(r => r.reasons);
  return reasons.length ? { state: 'unknown', reasons: [...new Set(reasons)] } : no;
}

export function parsePolicy(text) {
  const errors = [];
  const policy = parse(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length || !policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Tailscale returned an invalid policy document.');
  for (const key of ['acls', 'grants']) if (own(policy, key) && !Array.isArray(policy[key])) throw new Error(`Policy ${key} must be an array.`);
  return policy;
}

// Return null for unsupported selectors instead of inventing an allow/deny result.
export function addressRanges(selector, policy, seen = new Set()) {
  if (typeof selector !== 'string' || seen.has(selector)) return null;
  const next = new Set([...seen, selector]);
  if (selector === '*') return [network('0.0.0.0/0'), network('::/0')];
  const direct = tryNetwork(selector);
  if (direct) return [direct];
  const range = selector.split('-').map(tryNetwork);
  if (range.length === 2 && range.every(Boolean) && range[0].bits === range[1].bits && range[0].start <= range[1].end) return [{ bits: range[0].bits, start: range[0].start, end: range[1].end }];
  const host = selector.startsWith('host:') ? selector.slice(5) : selector;
  if (own(policy.hosts, host)) return addressRanges(policy.hosts[host], policy, next);
  if (selector.startsWith('ipset:') && own(policy.ipsets, selector)) {
    if (!Array.isArray(policy.ipsets[selector])) return null;
    let ranges = [];
    for (const item of policy.ipsets[selector]) {
      if (typeof item !== 'string') return null;
      const match = /^(add|remove)\s+(.+)$/.exec(item);
      const operand = addressRanges(match ? match[2] : item, policy, next);
      if (!operand) return null;
      ranges = match?.[1] === 'remove' ? subtract(ranges, operand) : [...ranges, ...operand];
    }
    return ranges;
  }
  return null;
}

export function sourceMatch(selector, device, policy, users = [], seen = new Set()) {
  if (typeof selector !== 'string') return unknown('Invalid source selector.');
  if (seen.has(selector)) return unknown(`Circular selector: ${selector}`);
  if (selector === 'autogroup:danger-all') return yes;
  if (device.external) return unknown('Shared/external device permissions require Tailscale verification.');
  if (selector === '*') return yes;
  if (selector.startsWith('tag:')) return device.tags.includes(selector) ? yes : no;
  if (selector === 'autogroup:tagged') return device.tags.length ? yes : no;
  if (selector === 'autogroup:member') return !device.tags.length && device.user ? yes : no;
  if (selector.startsWith('group:')) {
    if (!own(policy.groups, selector)) return unknown(`Group ${selector} is not in the policy (it may be synced).`);
    const members = policy.groups[selector];
    if (!Array.isArray(members)) return unknown(`Invalid group ${selector}.`);
    return any(members.map(member => sourceMatch(member, device, policy, users, new Set([...seen, selector]))));
  }
  if (/^autogroup:(owner|admin|it-admin|network-admin|billing-admin|auditor)$/.test(selector)) {
    if (device.tags.length) return no;
    const u = users.find(u => u.loginName === device.user || u.email === device.user);
    return u ? (u.role === selector.slice(10) ? yes : no) : unknown('User role is unavailable; add optional users:read scope.');
  }
  if (selector.includes('@')) return !device.tags.length && selector.toLowerCase() === device.user.toLowerCase() ? yes : no;
  const ranges = addressRanges(selector, policy);
  if (ranges) return ranges.some(r => device.addresses.some(a => { const n = tryNetwork(a); return n && contains(r, n); })) ? yes : no;
  return unknown(`Source selector ${selector} requires verification.`);
}

function destinationRanges(selector, source, policy, devices, users) {
  const ranges = addressRanges(selector, policy);
  if (ranges) return { ranges, reasons: [] };
  if (selector === 'autogroup:internet') return { ranges: [], reasons: ['Internet destination classification requires Tailscale verification.'] };
  if (selector === 'autogroup:self') return { ranges: source.tags.length ? [] : devices.filter(d => !d.tags.length && !d.external && d.user && d.user === source.user).flatMap(d => d.addresses.map(tryNetwork).filter(Boolean)), reasons: [] };
  if (/^(tag:|group:|autogroup:)/.test(selector) || selector.includes('@')) {
    const resolved = devices.map(d => ({ d, result: sourceMatch(selector, d, policy, users) }));
    return {
      ranges: resolved.filter(x => x.result.state === 'yes').flatMap(x => x.d.addresses.map(tryNetwork).filter(Boolean)),
      reasons: resolved.filter(x => x.result.state === 'unknown').flatMap(x => x.result.reasons),
    };
  }
  return { ranges: [], reasons: [`Destination selector ${selector} requires verification.`] };
}

function aclTarget(target) {
  if (typeof target !== 'string') return null;
  const bracket = /^\[([^\]]+)\]:(.+)$/.exec(target);
  if (bracket) return { selector: bracket[1], ports: bracket[2] };
  const colon = target.lastIndexOf(':');
  if (colon < 0) return null;
  return { selector: target.slice(0, colon), ports: target.slice(colon + 1) };
}

export function policyRules(policy) {
  const implicit = !own(policy, 'acls') && !own(policy, 'grants');
  const acls = implicit ? [{ action: 'accept', src: ['*'], dst: ['*:*'] }] : (policy.acls || []);
  return [
    ...acls.map((r, i) => ({ ...r, kind: 'acl', ref: implicit ? 'Default allow-all' : `ACL ${i + 1}` })),
    ...(policy.grants || []).filter(r => r.ip?.length).map((r, i) => ({ ...r, kind: 'grant', ref: `Grant ${policy.grants.indexOf(r) + 1}` })),
  ];
}

export function evaluateAccess(cidr, devices, policy, users = []) {
  if (!policy) return { available: false, rows: [], message: 'Policy could not be read. Device access is unknown.' };
  const subnet = network(cidr), rules = policyRules(policy);
  const rows = devices.map(device => {
    const matches = [];
    for (const rule of rules) {
      if (rule.kind === 'acl' && rule.action !== 'accept') continue;
      const sources = rule.src || rule.users || [];
      const src = any(sources.map(s => sourceMatch(s, device, policy, users)));
      if (src.state === 'no') continue;
      const targets = rule.kind === 'acl' ? (rule.dst || rule.ports || []).map(aclTarget) : (rule.dst || []).map(selector => ({ selector, ports: null }));
      for (const target of targets) {
        if (!target) { matches.push({ rule: rule.ref, status: 'conditional', destinations: ['Unresolved destination'], permissions: [], reasons: ['Unrecognized ACL destination.'], selectors: sources }); continue; }
        const dest = destinationRanges(target.selector, device, policy, devices, users);
        const intersections = dest.ranges.map(r => intersection(r, subnet)).filter(Boolean);
        if (!intersections.length && !dest.reasons.length) continue;
        const postures = own(rule, 'srcPosture') ? rule.srcPosture : policy.defaultSrcPosture;
        const reasons = [...src.reasons, ...dest.reasons];
        if (postures?.length) reasons.push(`Requires device posture: ${postures.join(', ')}`);
        if (rule.via?.length) reasons.push(`Must use a router matching: ${rule.via.join(', ')}`);
        const known = new Set(['action', 'src', 'users', 'dst', 'ports', 'proto', 'srcPosture', 'ip', 'app', 'via', 'kind', 'ref', 'comment']);
        for (const key of Object.keys(rule)) if (!known.has(key)) reasons.push(`Rule field ${key} is not evaluated.`);
        const permissions = rule.kind === 'grant' ? rule.ip : [`${rule.proto || 'tcp+udp'}:${target.ports}`];
        if (permissions.some(p => typeof p !== 'string')) reasons.push('Unrecognized network capability.');
        matches.push({
          rule: rule.ref, status: reasons.length ? 'conditional' : 'allowed',
          coverage: intersections.some(r => contains(r, subnet)) ? 'entire subnet' : 'part of subnet',
          destinations: intersections.length ? [...new Set(intersections.map(rangeLabel))] : ['Unresolved destination'],
          permissions: permissions.map(p => typeof p === 'string' ? p : 'unresolved'),
          selectors: sources, destinationSelector: target.selector, reasons: [...new Set(reasons)],
          definition: Object.fromEntries(Object.entries(rule).filter(([k]) => k !== 'kind' && k !== 'ref')),
        });
      }
    }
    return { deviceId: device.id, status: matches.some(m => m.status === 'allowed') ? 'allowed' : matches.length ? 'conditional' : 'no-match', matches };
  });
  const order = { allowed: 0, conditional: 1, 'no-match': 2 };
  rows.sort((a, b) => order[a.status] - order[b.status]);
  return { available: true, rows, evaluatedRules: rules.length,
    summary: { allowed: rows.filter(r => r.status === 'allowed').length, conditional: rows.filter(r => r.status === 'conditional').length, noMatch: rows.filter(r => r.status === 'no-match').length },
    message: 'Policy analysis, not a connectivity test. Allowed means at least one unconditional rule permits some traffic to the shown addresses. Posture, via, sharing and unresolved selectors remain conditional. Device approval, key expiry, routing, firewalls and service availability can still prevent access. TCP/UDP permissions also imply ICMP access under Tailscale policy semantics.' };
}
