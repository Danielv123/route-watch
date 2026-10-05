import { readFileSync } from 'node:fs';
import { parsePolicy } from './policy.js';
import { normalizeDevice } from './routes.js';

const API = 'https://api.tailscale.com/api/v2';
export const SCOPES = ['devices:core:read', 'devices:routes:read', 'policy_file:read', 'devices:posture_attributes:read'];
export class ApiError extends Error {
  constructor(message, status = 502) { super(message); this.status = status; }
}
export function secret(env, key) {
  if (env[key] && env[`${key}_FILE`]) throw new Error(`Configure either ${key} or ${key}_FILE, not both.`);
  return env[`${key}_FILE`] ? readFileSync(env[`${key}_FILE`], 'utf8').trim() : (env[key] || '').trim();
}

export class TailscaleReader {
  constructor(env = process.env, fetchImpl = fetch) {
    this.fetch = fetchImpl;
    this.tailnet = env.TAILSCALE_TAILNET || '-';
    this.apiToken = secret(env, 'TAILSCALE_API_TOKEN');
    this.clientId = env.TAILSCALE_CLIENT_ID || '';
    this.clientSecret = secret(env, 'TAILSCALE_CLIENT_SECRET');
    this.oauthScopes = [...SCOPES, ...(env.TAILSCALE_READ_USERS === 'true' ? ['users:read'] : [])];
    if (this.apiToken && (this.clientId || this.clientSecret)) throw new Error('Choose an API token or OAuth credentials, not both.');
    if (!!this.clientId !== !!this.clientSecret) throw new Error('Both OAuth client ID and secret are required.');
    this.configured = !!(this.apiToken || this.clientId);
  }
  async bearer() {
    if (this.apiToken) return this.apiToken;
    if (this.oauthToken && this.oauthExpiry > Date.now() + 60000) return this.oauthToken;
    if (!this.authPending) this.authPending = this.exchangeToken().finally(() => { this.authPending = null; });
    return this.authPending;
  }
  async exchangeToken() {
    let res;
    try {
      res = await this.fetch(`${API}/oauth/token`, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: this.clientId, client_secret: this.clientSecret, scope: this.oauthScopes.join(' ') }),
      });
    } catch { throw new ApiError('Unable to reach the Tailscale token endpoint.'); }
    if (!res.ok) throw new ApiError(`Tailscale OAuth authentication failed (HTTP ${res.status}). Check the read-only scopes and credentials.`);
    let body; try { body = await res.json(); } catch { throw new ApiError('Invalid OAuth response from Tailscale.'); }
    if (!body.access_token || !Number.isFinite(body.expires_in) || body.expires_in <= 60) throw new ApiError('Tailscale returned an invalid access token response.');
    this.oauthToken = body.access_token;
    this.oauthExpiry = Date.now() + body.expires_in * 1000;
    return body.access_token;
  }
  // Explicit GET allowlist. No route, device or policy mutation endpoint exists.
  async get(path) {
    if (!/^\/(tailnet\/[^/]+\/(devices(?:\?fields=all)?|acl|users)|device\/[^/]+\/routes)$/.test(path)) throw new Error('API path is not read-only allowlisted.');
    const token = await this.bearer();
    let res;
    try { res = await this.fetch(`${API}${path}`, { method: 'GET', redirect: 'error', headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, signal: AbortSignal.timeout(20000) }); }
    catch { throw new ApiError('Unable to reach the Tailscale API. Check network access.'); }
    if (!res.ok) {
      if (res.status === 401) throw new ApiError('Tailscale rejected the token. It may be expired or invalid.');
      if (res.status === 403) throw new ApiError('Tailscale denied this read. Check the credential scopes and tailnet.');
      if (res.status === 429) throw new ApiError('Tailscale API rate limit reached. Wait before refreshing.');
      throw new ApiError(`Tailscale read failed (HTTP ${res.status}).`);
    }
    return { text: await res.text(), etag: res.headers.get('etag') };
  }
  async json(path) {
    const result = await this.get(path);
    try { return JSON.parse(result.text); } catch { throw new ApiError('Tailscale returned invalid JSON.'); }
  }
  async inventory() {
    if (!this.configured) throw new ApiError('Configure a read-only Tailscale credential on the server.', 503);
    const base = `/tailnet/${encodeURIComponent(this.tailnet)}`;
    const [deviceResult, policyResult] = await Promise.allSettled([this.json(`${base}/devices?fields=all`), this.get(`${base}/acl`)]);
    if (deviceResult.status === 'rejected') throw deviceResult.reason;
    if (!Array.isArray(deviceResult.value.devices)) throw new ApiError('Tailscale returned an invalid device inventory.');
    const warnings = [], devices = deviceResult.value.devices.map(normalizeDevice);
    if (devices.some(d => d.id === 'undefined') || new Set(devices.map(d => d.id)).size !== devices.length) throw new ApiError('Device inventory has missing or duplicate identifiers.');
    let policy = null, policyEtag = null;
    if (policyResult.status === 'fulfilled') {
      try { policy = parsePolicy(policyResult.value.text); policyEtag = policyResult.value.etag; }
      catch { warnings.push('Policy could not be parsed. Access analysis is unavailable.'); }
    } else warnings.push('Policy could not be read. Check policy_file:read and its required device scopes. Access analysis is unavailable.');
    // Dedicated endpoint for every node catches approved-but-not-advertised routes.
    // Bound concurrency to avoid a request burst on larger tailnets.
    let cursor = 0;
    await Promise.all(Array.from({ length: Math.min(4, devices.length) }, async () => {
      while (cursor < devices.length) {
        const device = devices[cursor++];
        try {
          const routes = await this.json(`/device/${encodeURIComponent(device.id)}/routes`);
          if (!Array.isArray(routes.advertisedRoutes) || !Array.isArray(routes.enabledRoutes)) throw new Error('Missing route fields');
          device.advertisedRoutes = routes.advertisedRoutes;
          device.enabledRoutes = routes.enabledRoutes;
        } catch {
          device.routesUnavailable = true;
          warnings.push(`Routes unreadable for ${device.name}. Conflict detection is incomplete; check devices:routes:read or retry.`);
        }
      }
    }));
    let users = [];
    if (policy && /autogroup:(owner|admin|it-admin|network-admin|billing-admin|auditor)/.test(JSON.stringify(policy))) {
      try { const result = await this.json(`${base}/users`); users = result.users || []; }
      catch { warnings.push('User roles are unavailable. Role-based rules will be marked conditional; users:read is optional.'); }
    }
    return { devices, policy, users, policyEtag, policyAvailable: !!policy, warnings,
      mode: 'live', tailnet: this.tailnet, fetchedAt: new Date().toISOString(),
      routesComplete: devices.every(d => !d.routesUnavailable) };
  }
}

export class SnapshotCache {
  constructor(reader, ttlMs = 60000) { this.reader = reader; this.ttl = ttlMs; this.value = null; this.pending = null; this.lastAttempt = 0; this.lastError = null; }
  async get() {
    if (this.pending) return this.pending;
    if (this.value && Date.now() - this.lastAttempt < this.ttl) return this.withState();
    if (this.lastError && Date.now() - this.lastAttempt < this.ttl) throw this.lastError;
    this.lastAttempt = Date.now();
    this.pending = this.reader.inventory().then(value => { this.value = value; this.lastError = null; return this.withState(); })
      .catch(error => { this.lastError = error; if (this.value) return this.withState(); throw error; })
      .finally(() => { this.pending = null; });
    return this.pending;
  }
  withState() { return { ...this.value, stale: !!this.lastError, warnings: [...this.value.warnings, ...(this.lastError ? ['Refresh failed. Showing the last successful snapshot; approvals may have changed.'] : [])], nextRefreshAt: new Date(this.lastAttempt + this.ttl).toISOString() }; }
}
