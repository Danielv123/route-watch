# Route Watch

A self-hosted, read-only dashboard for Tailscale subnet routes and policy access.

## Use the published image

Images are published to `ghcr.io/danielv123/route-watch` after tests pass on GitHub Actions. The `latest` tag follows `main`; `sha-<full-commit>` tags identify individual builds. Version tags such as `v1.0.0` publish a corresponding image tag. Builds currently target Linux amd64.

Download `compose.production.yaml` and `.env.example`, copy `.env.example` to `.env`, and configure the credentials below. Then run:

```sh
docker compose -f compose.production.yaml up -d
```

For a later update:

```sh
docker compose -f compose.production.yaml pull
docker compose -f compose.production.yaml up -d
```

Use a `sha-<commit>` tag or image digest in `ROUTE_WATCH_IMAGE` to pin a deployment. The workflow uses GitHub's built-in `GITHUB_TOKEN` with package-write permission; no personal publishing secret or Tailscale credentials belong in GitHub Actions. For a new fork, make the GHCR package public once in its package settings to permit anonymous pulls.

## Start with Docker

1. Copy `.env.example` to `.env` in this directory.
2. Set `TAILSCALE_API_TOKEN` to a **scoped read-only API access token**, and set `TAILSCALE_TAILNET` to your organization or tailnet DNS name. `-` selects the credential's tailnet. An auth/join key (`tskey-auth-…`) is not an API token.
3. Run:

```sh
docker compose up --build -d
```

Open **http://localhost:8787**. Without credentials, the service displays setup instructions. **http://localhost:8787/?demo=1** uses fictional data and makes no Tailscale API calls.

PowerShell setup:

```powershell
Copy-Item .env.example .env
notepad .env
docker compose up --build -d
```

After editing `.env`, apply changes with `docker compose up -d --force-recreate`. Do not commit or share `.env`.

## Required read-only scopes

Create a scoped credential in Tailscale's **Trust credentials** settings. Grant only:

| Scope | Purpose |
| --- | --- |
| `devices:core:read` | Device inventory, identities, tags and addresses |
| `devices:routes:read` | Advertised and approved routes, including unused approvals |
| `policy_file:read` | Tailnet ACLs, grants, groups, hosts and IP sets |
| `devices:posture_attributes:read` | Required by Tailscale for `policy_file:read` |

Optional: `users:read` resolves role selectors such as `autogroup:admin`. Without it, those rules are conditional. For OAuth, also set `TAILSCALE_READ_USERS=true` so this optional scope is requested.

For automatic renewal, leave `TAILSCALE_API_TOKEN` empty and configure a read-only OAuth client:

```dotenv
TAILSCALE_CLIENT_ID=your-client-id
TAILSCALE_CLIENT_SECRET=your-client-secret
```

The service requests only the read scopes listed above. Static access tokens are used as supplied; this service cannot inspect or narrow their permissions, so provision the credential as read-only. Never paste credentials into chat or into the browser dashboard.

Secrets can instead be loaded using `TAILSCALE_API_TOKEN_FILE`, `TAILSCALE_CLIENT_SECRET_FILE` and `DASHBOARD_PASSWORD_FILE`. Do not set both the value and its `_FILE` alternative. For Docker secrets, mount the secret and set the corresponding path, for example `/run/secrets/tailscale_token`; add the mount to Compose yourself.

## What the dashboard detects

- **Duplicate approvals:** the same canonical IPv4 or IPv6 prefix remains approved on multiple devices, even if one is offline or no longer advertises it. Review intentional HA pairs manually.
- **Potential duplicates:** more than one device has the prefix configured, but not all are approved. This flags reuse before another approval is granted.
- **Overlapping prefixes:** broader and narrower routes on different devices. The dashboard distinguishes approved overlaps from potential ones.
- **Unused approvals:** a route remains approved on a device that no longer advertises it. These approvals may become active again without a new approval.
- **Awaiting approval:** advertised routes which are not enabled.

Default routes (`0.0.0.0/0`, `::/0`) are counted separately as exit-node configuration and excluded from subnet conflict analysis. The app cannot infer whether identically addressed networks at different sites are the same physical network. It does not probe the LAN or claim to identify the active router selected by a particular client.

The interface is read-only. Resolve findings in Tailscale after confirming the intended owner.

## Device access analysis

Select a subnet to list devices permitted by the fetched ACLs and grants. Expand a device to inspect the matched rule, source selector, destination IP/range and network permissions. A rule for one IP or one port is displayed as partial access, not whole-subnet access.

Supported analysis includes:

- Legacy ACLs and network-layer grants, including their union.
- Users, policy-defined groups, tags, wildcard sources, IPv4/IPv6 and host aliases.
- Member/tagged autogroups and role autogroups when user role data is available.
- IP sets with ordered add/remove operations, nested sets, address ranges and host references.
- Tagged-device identity: a tagged device does not inherit its former owner's user permissions.
- Destination identity selectors map to the selected devices' own Tailscale IPs; a subnet router's tag does **not** grant access to its advertised subnet.

**This is a conservative policy explanation, not Tailscale's full policy engine or a live reachability test.** Posture conditions (including default posture), `via`, external/shared-device behavior, synced groups not defined in the policy, internet classification and unsupported selectors/fields are marked **Conditional**. They are never promoted to unconditional access. The app does not evaluate SSH login policy or application-layer capabilities as network access. ICMP is implicitly permitted alongside TCP/UDP permissions according to Tailscale semantics.

“Policy allows” means at least one unconditional network rule matches some traffic to the displayed addresses. It does not prove the device is online, authorized, unexpired, accepting routes, or able to reach a running service. “No matching rule” is a result for the fetched policy and available device inventory, not a network test. Source devices behind subnet routers without Tailscale installed cannot be enumerated by the device API and are not listed.

## Runtime and deployment

- Node.js 22 or later, two runtime dependencies, no database or build step.
- Shared in-memory snapshots refreshed on demand, cached for 60 seconds by default. The browser refreshes while visible. There is no background monitor when nobody is viewing the dashboard.
- The Refresh button respects the shared cache window to avoid API bursts. `CACHE_SECONDS` supports 15–3600 seconds. Increase it for large tailnets: a refresh reads devices, policy, each device's routes with concurrency 4, and optionally users.
- Failed reads are reported. A failed full refresh retains the last snapshot with a prominent stale warning. Missing per-device route data produces an incomplete-inventory warning. No persistent storage of tokens, policy or inventory is performed by the app.
- Requests to Tailscale are allowlisted GET endpoints. OAuth authentication uses the token endpoint's POST exchange. There are no route, device or policy writes.
- No telemetry, third-party scripts, external fonts or external assets. Credentials never enter frontend responses or browser storage.

Compose publishes **127.0.0.1:8787** only. To let colleagues use it, put it behind an authenticated HTTPS reverse proxy or Tailscale Serve with an appropriate access policy. Add the browser-facing hostname to `ALLOWED_HOSTS` (comma-separated hostnames, without schemes or ports). Optional HTTP Basic authentication is available via `DASHBOARD_USER` and `DASHBOARD_PASSWORD`; use HTTPS remotely. Do not publish the port openly without access control because inventory and policy details are private.

The container runs as an unprivileged user with a read-only filesystem, dropped Linux capabilities and a health check. `/healthz` reports process health; it does not imply Tailscale credentials are valid. The service needs outbound HTTPS to `api.tailscale.com` and does not need a local Tailscale socket or host networking.

### Nginx Proxy Manager

For `compose.production.yaml`, set `BIND_ADDRESS` to the server's private LAN address if the proxy is on a separate container/host, and set `PUBLISHED_PORT` to a free port (default `8787`). Add the public hostname to `ALLOWED_HOSTS`. Set `DASHBOARD_USER` and a strong `DASHBOARD_PASSWORD` before making the dashboard internet-accessible.

In Nginx Proxy Manager, use the domain you own, forwarding scheme `http`, the server's private address, and port `8787`. Enable an SSL certificate and Force SSL. OAuth client credentials are for **server-to-Tailscale API authentication**, not browser sign-in; dashboard authentication is HTTP Basic or your own upstream identity proxy. The app needs no OAuth callback URL. Keep the proxy's original Host header and Authorization header.

Alternatively, use Docker DNS when Nginx Proxy Manager shares an external Docker network. Add these settings to the deployment's `.env` (Linux server):

```dotenv
COMPOSE_FILE=compose.production.yaml:compose.proxy.yaml
PROXY_NETWORK=web
```

The network must already exist and contain the proxy. Run `docker compose up -d`; then set Nginx's forward hostname to `route-watch`, scheme `http`, port `8787`. Use `docker compose` without `-f` for subsequent updates and recreations so both configured files are applied. The shared-network alias survives recreation. Keep the public hostname in `ALLOWED_HOSTS`; the proxy must preserve that Host header.

Without Docker:

```sh
npm ci
npm start
```

## Validation

```sh
npm test
```

Tests cover stale approvals, pending reuse, IPv4/IPv6 overlaps, partial destinations, tagged identities, groups, IP sets, ACL/grant union, conditional rules, missing data, credential redaction, OAuth scope restriction, read-only HTTP behavior, authentication and stale-cache handling. API contract tests use simulated Tailscale responses. A real scoped credential is required to verify against your tailnet.

## References

- [Tailscale route API and device schema](https://github.com/tailscale/tailscale-client-go-v2/blob/main/devices.go)
- [Read-only credential scopes](https://tailscale.com/docs/reference/trust-credentials)
- [Policy syntax](https://tailscale.com/docs/reference/syntax/policy-file)
- [Grants](https://tailscale.com/docs/reference/syntax/grants)
- [IP sets](https://tailscale.com/docs/features/tailnet-policy-file/ip-sets)

This is an independent application, not an official Tailscale product.
