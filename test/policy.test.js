import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAccess, parsePolicy } from '../server/policy.js';
const user = { id: 'user', name: 'laptop', user: 'alex@example.com', addresses: ['100.64.0.1', 'fd7a:115c:a1e0::1'], tags: [], external: false };
const tagged = { ...user, id: 'tagged', addresses: ['100.64.0.2'], tags: ['tag:monitor'] };
const acl = (src, dst, rest = {}) => ({ action: 'accept', src, dst, ...rest });
const evaluate = (policy, cidr = '10.1.0.0/24', devices = [user, tagged]) => evaluateAccess(cidr, devices, policy);
const row = (result, id = 'user') => result.rows.find(r => r.deviceId === id);

test('HuJSON comments/trailing commas parse, invalid syntax fails', () => {
  assert.deepEqual(parsePolicy('{ // comment\n"acls": [],}'), { acls: [] });
  assert.throws(() => parsePolicy('{broken}'));
});
test('groups and host aliases match; tagged nodes do not inherit owner permissions', () => {
  const result = evaluate({ groups: { 'group:eng': ['alex@example.com'] }, hosts: { yard: '10.1.0.0/24' }, acls: [acl(['group:eng'], ['yard:443'])] });
  assert.equal(row(result).status, 'allowed'); assert.equal(row(result, 'tagged').status, 'no-match');
  assert.equal(row(result).matches[0].coverage, 'entire subnet');
});
test('a host permission stays partial and retains ports and protocol', () => {
  const m = row(evaluate({ acls: [acl(['*'], ['10.1.0.24:443'], { proto: 'tcp' })] })).matches[0];
  assert.equal(m.coverage, 'part of subnet'); assert.deepEqual(m.destinations, ['10.1.0.24']); assert.deepEqual(m.permissions, ['tcp:443']);
});
test('router tag permission does not imply access to its advertised subnet', () => {
  const result = evaluate({ acls: [acl(['*'], ['tag:monitor:*'])] });
  assert.ok(result.rows.every(r => r.status === 'no-match'));
});
test('ACLs and grants union and app-only grants do not provide network access', () => {
  const result = evaluate({ acls: [acl(['tag:monitor'], ['10.1.0.0/24:22'])], grants: [{ src: ['alex@example.com'], dst: ['10.1.0.0/24'], ip: ['tcp:443'] }, { src: ['*'], dst: ['*'], app: { 'example.com/cap': [{}] } }] });
  assert.equal(result.summary.allowed, 2); assert.equal(result.evaluatedRules, 2);
});
test('empty explicit policy denies, absent ACL and grants uses documented default', () => {
  assert.equal(row(evaluate({ acls: [] })).status, 'no-match');
  assert.equal(row(evaluate({ grants: [] })).status, 'no-match');
  assert.equal(row(evaluate({})).status, 'allowed');
});
test('source posture, default posture, and via are conditional', () => {
  for (const policy of [
    { acls: [acl(['*'], ['*:*'], { srcPosture: ['posture:managed'] })] },
    { defaultSrcPosture: ['posture:managed'], acls: [acl(['*'], ['*:*'])] },
    { grants: [{ src: ['*'], dst: ['*'], ip: ['*'], via: ['tag:site'] }] },
  ]) assert.equal(row(evaluate(policy)).status, 'conditional');
  assert.equal(row(evaluate({ defaultSrcPosture: ['posture:managed'], acls: [acl(['*'], ['*:*'], { srcPosture: [] })] })).status, 'allowed');
});
test('unknown sources, synced groups and IP sets cannot become an unconditional allow', () => {
  for (const selector of ['group:synced', 'autogroup:future', 'ipset:missing']) assert.equal(row(evaluate({ acls: [acl([selector], ['*:*'])] })).status, 'conditional');
});
test('resolved source wins over unknown alternative in a union', () => {
  assert.equal(row(evaluate({ acls: [acl(['group:synced', 'alex@example.com'], ['*:*'])] })).status, 'allowed');
});
test('IPv6 ACL bracket form and grant CIDRs match', () => {
  const result = evaluate({ acls: [acl(['fd7a:115c:a1e0::/48'], ['[2001:db8:1::10]:443'])] }, '2001:db8:1::/64');
  assert.equal(row(result).status, 'allowed'); assert.deepEqual(row(result).matches[0].destinations, ['2001:db8:1::10']);
});
test('IP set subtraction excludes a host and preserves the remaining address ranges', () => {
  const policy = { ipsets: { 'ipset:yard': ['add 10.1.0.0/24', 'remove 10.1.0.24'] }, acls: [acl(['*'], ['ipset:yard:443'])] };
  assert.equal(row(evaluate(policy, '10.1.0.24/32')).status, 'no-match');
  assert.equal(row(evaluate(policy, '10.1.0.25/32')).status, 'allowed');
  assert.equal(row(evaluate(policy)).matches[0].coverage, 'part of subnet');
});
test('nested IP sets and host references work; circular IP sets are conditional', () => {
  const policy = { hosts: { panel: '10.1.0.24' }, ipsets: { 'ipset:a': ['host:panel'], 'ipset:b': ['ipset:a'] }, acls: [acl(['*'], ['ipset:b:443'])] };
  assert.equal(row(evaluate(policy)).status, 'allowed');
  policy.ipsets['ipset:a'] = ['ipset:b']; assert.equal(row(evaluate(policy)).status, 'conditional');
});
test('role autogroups are conditional without users inventory', () => {
  const p = { acls: [acl(['autogroup:admin'], ['*:*'])] };
  assert.equal(row(evaluate(p)).status, 'conditional');
  const result = evaluateAccess('10.1.0.0/24', [user, tagged], p, [{ loginName: 'alex@example.com', role: 'admin' }]);
  assert.equal(row(result).status, 'allowed'); assert.equal(row(result, 'tagged').status, 'no-match');
});
test('member and tagged autogroups distinguish identities', () => {
  const a = evaluate({ acls: [acl(['autogroup:member'], ['*:*'])] });
  assert.equal(row(a).status, 'allowed'); assert.equal(row(a, 'tagged').status, 'no-match');
  const b = evaluate({ acls: [acl(['autogroup:tagged'], ['*:*'])] });
  assert.equal(row(b).status, 'no-match'); assert.equal(row(b, 'tagged').status, 'allowed');
});
test('missing policy yields unknown availability, never no access', () => {
  assert.equal(evaluateAccess('10.1.0.0/24', [user], null).available, false);
});
test('unknown restrictive rule fields cannot become unconditional allows', () => {
  assert.equal(row(evaluate({ acls: [acl(['*'], ['*:*'], { futureCondition: 'restricted' })] })).status, 'conditional');
});
