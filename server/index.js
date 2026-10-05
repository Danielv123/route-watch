import http from 'node:http';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createHash, timingSafeEqual } from 'node:crypto';
import { TailscaleReader, SnapshotCache, secret, SCOPES } from './tailscale.js';
import { analyzeRoutes } from './routes.js';
import { evaluateAccess, policyRules } from './policy.js';
import { demoInventory } from './demo.js';

export function createApp({ env = process.env, reader = new TailscaleReader(env) } = {}) {
  const seconds = Number(env.CACHE_SECONDS || 60);
  if (!Number.isFinite(seconds) || seconds < 15 || seconds > 3600) throw new Error('CACHE_SECONDS must be between 15 and 3600.');
  const cache = new SnapshotCache(reader, seconds * 1000);
  const username = env.DASHBOARD_USER || '', password = secret(env, 'DASHBOARD_PASSWORD');
  if (!!username !== !!password) throw new Error('Set both DASHBOARD_USER and DASHBOARD_PASSWORD.');
  const hosts = new Set((env.ALLOWED_HOSTS || 'localhost,127.0.0.1,[::1]').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
  const expected = createHash('sha256').update(`Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`).digest();
  const files = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
    ['/style.css', ['style.css', 'text/css; charset=utf-8']],
    ['/favicon.svg', ['favicon.svg', 'image/svg+xml']],
  ].map(([path, [file, type]]) => [path, { body: readFileSync(new URL(`../public/${file}`, import.meta.url)), type }]));
  return http.createServer(async (req, res) => {
    const headers = {
      'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY', 'Cross-Origin-Resource-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    };
    const send = (status, body, type = 'application/json; charset=utf-8', extra = {}) => { res.writeHead(status, { ...headers, 'Content-Type': type, ...extra }); res.end(type.startsWith('application/json') ? JSON.stringify(body) : body); };
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, { error: 'This service is read-only.' }, undefined, { Allow: 'GET, HEAD' });
      if (!req.url.startsWith('/') || req.url.startsWith('//')) return send(400, { error: 'Invalid request target.' });
      let url; try { url = new URL(req.url, `http://${req.headers.host}`); } catch { return send(400, { error: 'Invalid request.' }); }
      if (!hosts.has(url.hostname.toLowerCase()) && !(url.pathname === '/healthz' && url.hostname === '127.0.0.1')) return send(403, { error: 'Hostname is not in ALLOWED_HOSTS.' });
      if (url.pathname === '/healthz') return send(200, { status: 'ok' });
      if (req.headers['sec-fetch-site'] === 'cross-site') return send(403, { error: 'Cross-site requests are not allowed.' });
      if (username) {
        const supplied = createHash('sha256').update(req.headers.authorization || '').digest();
        if (!timingSafeEqual(supplied, expected)) return send(401, { error: 'Sign in to Route Watch.' }, undefined, { 'WWW-Authenticate': 'Basic realm="Route Watch", charset="UTF-8"' });
      }
      if (files.has(url.pathname)) { const file = files.get(url.pathname); return send(200, file.body, file.type); }
      if (url.pathname === '/api/config') return send(200, { configured: reader.configured, refreshSeconds: seconds, scopes: SCOPES });
      if (url.pathname === '/api/snapshot' || url.pathname === '/api/access') {
        const inv = url.searchParams.get('demo') === '1' ? demoInventory() : await cache.get();
        const analysis = analyzeRoutes(inv.devices);
        if (url.pathname === '/api/access') {
          const cidr = url.searchParams.get('subnet');
          if (!analysis.routes.some(r => r.cidr === cidr)) return send(400, { error: 'Select a subnet from the current inventory.' });
          return send(200, { ...evaluateAccess(cidr, inv.devices, inv.policy, inv.users), fetchedAt: inv.fetchedAt, stale: !!inv.stale });
        }
        return send(200, {
          ...analysis, mode: inv.mode, tailnet: inv.tailnet, devices: inv.devices,
          fetchedAt: inv.fetchedAt, stale: !!inv.stale, nextRefreshAt: inv.nextRefreshAt,
          warnings: [...inv.warnings, ...analysis.warnings], routesComplete: inv.routesComplete !== false,
          policy: { available: inv.policyAvailable, rules: inv.policy ? policyRules(inv.policy).length : null },
        });
      }
      return send(404, { error: 'Not found.' });
    } catch (error) {
      // Do not expose upstream response bodies, request headers, credentials or stacks.
      return send(error.status || 500, { error: error.status ? error.message : 'The service could not complete this request. Check server configuration.' });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const host = process.env.HOST || '127.0.0.1', port = Number(process.env.PORT || 8787);
    const server = createApp();
    server.requestTimeout = 30000;
    server.headersTimeout = 10000;
    server.on('error', error => { console.error(`Unable to start Route Watch (${error.code || 'server error'}).`); process.exitCode = 1; });
    server.listen(port, host, () => console.log(`Route Watch listening on ${host}:${port}`));
    const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
