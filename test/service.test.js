import test from 'node:test';
import assert from 'node:assert/strict';
import { TailscaleReader, SnapshotCache, SCOPES } from '../server/tailscale.js';
import { createApp } from '../server/index.js';
import { demoInventory } from '../server/demo.js';
import http from 'node:http';
const token = 'test-token-do-not-expose';
const makeResponse = (body, status = 200) => new Response(JSON.stringify(body), { status });

test('Tailscale requests are GET-only and include offline-node routes and policy', async () => {
  const calls = [];
  const reader = new TailscaleReader({ TAILSCALE_API_TOKEN: token }, async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/devices?fields=all')) return makeResponse({ devices: [{ id: '1', hostname: 'offline', connectedToControl: false }] });
    if (url.endsWith('/acl')) return makeResponse({ acls: [] });
    if (url.endsWith('/device/1/routes')) return makeResponse({ advertisedRoutes: [], enabledRoutes: ['10.1.0.0/24'] });
    throw new Error('Unexpected endpoint');
  });
  const inventory = await reader.inventory();
  assert.ok(calls.every(c => c.options.method === 'GET' && c.options.redirect === 'error'));
  assert.deepEqual(inventory.devices[0].enabledRoutes, ['10.1.0.0/24']);
  assert.ok(!JSON.stringify(inventory).includes(token));
  await assert.rejects(reader.get('/device/1/authorized'));
  await assert.rejects(reader.get('/tailnet/-/acl/preview'));
});
test('missing routes are explicit incomplete inventory; missing ACL is unavailable', async () => {
  const reader = new TailscaleReader({ TAILSCALE_API_TOKEN: token }, async url => url.includes('/devices?') ? makeResponse({ devices: [{ id: '1', hostname: 'router' }] }) : makeResponse({ error: token }, 403));
  const result = await reader.inventory();
  assert.equal(result.routesComplete, false); assert.equal(result.policyAvailable, false);
  assert.equal(result.warnings.length, 2); assert.ok(!JSON.stringify(result).includes(token));
});
test('API errors redact upstream bodies and reject redirects', async () => {
  const reader = new TailscaleReader({ TAILSCALE_API_TOKEN: token }, async () => makeResponse({ secret: token }, 401));
  await assert.rejects(reader.inventory(), e => /expired or invalid/.test(e.message) && !e.message.includes(token));
});
test('OAuth requests only read scopes and reuses its access token', async () => {
  const calls = [];
  const reader = new TailscaleReader({ TAILSCALE_CLIENT_ID: 'client', TAILSCALE_CLIENT_SECRET: 'secret' }, async (url, options) => {
    calls.push({ url, options });
    return url.endsWith('/oauth/token') ? makeResponse({ access_token: token, expires_in: 3600 }) : makeResponse({});
  });
  await Promise.all([reader.get('/tailnet/-/acl'), reader.get('/tailnet/-/acl')]);
  const exchanges = calls.filter(c => c.options.method === 'POST'); assert.equal(exchanges.length, 1);
  assert.equal(exchanges[0].options.body.get('scope'), SCOPES.join(' '));
  assert.ok(SCOPES.every(scope => scope.endsWith(':read')));
});
test('cache coalesces reads and marks the last good snapshot stale on failure', async () => {
  let count = 0;
  const cache = new SnapshotCache({ inventory: async () => { count++; if (count > 1) throw new Error('failure'); return demoInventory(); } }, 60000);
  await Promise.all([cache.get(), cache.get()]); assert.equal(count, 1);
  cache.lastAttempt = 0;
  assert.equal((await cache.get()).stale, true);
  assert.equal((await cache.get()).stale, true); assert.equal(count, 2);
});
async function running(t, env = {}, reader = { configured: false }) {
  const server = createApp({ env, reader });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}
test('HTTP rejects writes, arbitrary files, cross-site requests and unknown hosts', async t => {
  const base = await running(t);
  assert.equal((await fetch(`${base}/api/snapshot`, { method: 'POST' })).status, 405);
  assert.equal((await fetch(`${base}/.env`)).status, 404);
  const rawStatus = (path, host) => new Promise((resolve, reject) => {
    const url = new URL(base);
    const req = http.request({ hostname: url.hostname, port: url.port, path, headers: { Host: host } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.end();
  });
  assert.equal(await rawStatus('/api/config', 'attacker.example'), 403);
  assert.equal(await rawStatus(`${base}/api/config`, 'attacker.example'), 400);
  assert.equal((await fetch(`${base}/api/config`, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fetch(`${base}/`)).headers.get('x-frame-options'), 'DENY');
});
test('Basic authentication protects all inventory endpoints', async t => {
  const base = await running(t, { DASHBOARD_USER: 'viewer', DASHBOARD_PASSWORD: 'test-password' });
  assert.equal((await fetch(`${base}/api/snapshot?demo=1`)).status, 401);
  const response = await fetch(`${base}/api/snapshot?demo=1`, { headers: { Authorization: `Basic ${Buffer.from('viewer:test-password').toString('base64')}` } });
  assert.equal(response.status, 200); assert.equal((await response.json()).mode, 'demo');
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
});
test('demo access exposes exact destinations and is independent from credentials', async t => {
  const base = await running(t);
  const snapshot = await (await fetch(`${base}/api/snapshot?demo=1`)).json();
  assert.equal(snapshot.routes.length, 5);
  const result = await (await fetch(`${base}/api/access?demo=1&subnet=10.118.0.0%2F24`)).json();
  assert.equal(result.summary.allowed, 5); assert.equal(result.summary.conditional, 1);
  assert.equal(result.rows.find(r => r.deviceId === 'monitor').matches[0].coverage, 'part of subnet');
  assert.equal((await fetch(`${base}/api/access?demo=1&subnet=0.0.0.0%2F0`)).status, 400);
});
