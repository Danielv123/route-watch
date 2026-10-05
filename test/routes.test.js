import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRoutes } from '../server/routes.js';
import { network, overlaps } from '../server/network.js';
const d = (id, advertisedRoutes = [], enabledRoutes = advertisedRoutes) => ({ id, name: id, advertisedRoutes, enabledRoutes });

test('old, offline approval conflicts even when it is no longer advertised', () => {
  const { routes } = analyzeRoutes([d('old', [], ['10.1.0.0/24']), d('new', ['10.1.0.0/24'])]);
  assert.equal(routes.length, 1);
  assert.deepEqual(routes[0].findings.map(f => f.type), ['duplicate', 'stale']);
  assert.equal(routes[0].activeCount, 1);
});
test('pending reuse is flagged before it is approved', () => {
  const r = analyzeRoutes([d('old', [], ['10.1.0.0/24']), d('new', ['10.1.0.0/24'], [])]).routes[0];
  assert.ok(r.findings.some(f => f.type === 'potential'));
  assert.ok(!r.findings.some(f => f.type === 'duplicate'));
});
test('CIDRs are canonicalized and duplicate entries on one node are deduplicated', () => {
  const r = analyzeRoutes([d('one', ['10.1.0.4/24', '10.1.0.0/24'])]).routes[0];
  assert.equal(r.cidr, '10.1.0.0/24'); assert.equal(r.entries.length, 1); assert.equal(r.findings.length, 0);
});
test('overlapping routes on different devices are identified', () => {
  const { routes } = analyzeRoutes([d('one', ['10.0.0.0/8']), d('two', ['10.1.0.0/24']), d('three', ['172.16.0.0/16'])]);
  assert.equal(routes.filter(r => r.findings.some(f => f.type === 'overlap')).length, 2);
});
test('same-router nested routes and exit defaults do not create subnet conflicts', () => {
  const { routes, exitNodeCount } = analyzeRoutes([d('one', ['10.0.0.0/8', '10.1.0.0/24', '0.0.0.0/0', '::/0'])]);
  assert.equal(routes.length, 2); assert.equal(exitNodeCount, 1); assert.ok(routes.every(r => !r.findings.length));
});
test('IPv6 overlap, canonical equality and address families', () => {
  assert.equal(network('2001:0db8:0000::1234/48').cidr, '2001:db8::/48');
  assert.ok(overlaps(network('2001:db8::/32'), network('2001:db8:abcd::/48')));
  assert.ok(!overlaps(network('2001:db8::/32'), network('10.0.0.0/8')));
  assert.equal(analyzeRoutes([d('one', ['2001:db8::/32']), d('two', ['2001:db8:1::/48'])]).routes[0].findings[0].type, 'overlap');
});
test('invalid routes produce a warning without masking valid routes', () => {
  const result = analyzeRoutes([d('one', ['invalid', '10.0.0.0/24'])]);
  assert.equal(result.routes.length, 1); assert.ok(result.warnings.length);
});
