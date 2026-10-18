# Phase 7 — progress log

## Slice 1 — OIDC single sign-on (2026-10-18)

**Delivered**

- `apps/api/src/auth/oidc.ts`: OpenID Connect authorization-code login with **PKCE (S256)**.
  State, nonce and the code verifier are created and stored server-side (`oidc_states`,
  single use, 10-minute TTL); the browser and the BFF only ever carry the opaque state. Discovery
  (`/.well-known/openid-configuration`, issuer must match) and JWKS are fetched with timeouts and
  cached; ID tokens are verified **locally with Node's crypto** — RS256 only (`alg=none` and
  everything else refused), signature against the published key (one JWKS refresh on unknown
  `kid` for rotation), issuer, audience (+ `azp` for multi-audience), `exp`/`iat` with 60 s skew,
  nonce, subject. No dependency added.
- Account resolution, in this order: existing SSO account by `issuer|sub` (never by e-mail) →
  local account with the same e-mail → **409 and audited `denied`** unless
  `OIDC_AUTO_LINK_BY_EMAIL=true` (an IdP identity must not inherit a local admin's account) →
  JIT provisioning (`OIDC_ALLOW_JIT`, default on) with roles from `OIDC_ROLE_CLAIM` mapped
  through `OIDC_ROLE_MAP`, falling back to `OIDC_DEFAULT_ROLES` (may be empty: the user can sign
  in and see nothing). When a role map is configured, roles are re-synced on every login and a
  change bumps `token_version`, invalidating outstanding access tokens. SSO accounts receive an
  unusable random password hash and password login refuses them before any hash comparison.
- Routes: `GET /api/v1/auth/providers` (public: which methods this deployment offers),
  `POST /api/v1/auth/oidc/start`, `POST /api/v1/auth/oidc/callback` (origin-checked, rate
  limited, same session issuance as password login: short-lived access token + rotating refresh
  cookie). Audit: `auth.oidc_provision`, `auth.oidc_login` (success/denied with reason),
  `auth.oidc_link`, `auth.oidc_role_sync`.
- Web: `/auth/oidc/start` sets a `SameSite=Lax` httpOnly state cookie scoped to `/auth/oidc` and
  redirects to the IdP; `/auth/oidc/callback` requires the returned state to equal that cookie,
  hands code+state to the API server-side, stores the BFF session cookies and redirects. The
  login page shows the SSO button only when the API advertises it; failures land back on the
  login page with specific reasons (unavailable, state, collision, refused, failed).
- Schema (`0011_phase7_sso_oidc`): `users.auth_provider`, `users.external_subject` (unique per
  provider), `oidc_states`. `User` contract exposes `authProvider`. Capability `auth.sso` is
  **dynamic**: `not_configured` until issuer/client/redirect are set, then `available` with the
  guarantees spelled out.

**Verified**

API: 3 integration tests against an in-process mock IdP (real RSA keys, discovery, JWKS, token
endpoint enforcing the PKCE verifier) — provider advertisement and capability; start URL with
PKCE; refusals for unknown state, token signed by an unpublished key, replayed state, `alg=none`,
wrong nonce, expired token, wrong audience, expired state record — and no user is created by any
of them; JIT provisioning with role mapping and permissions, refresh cookie, password login
refused for SSO accounts, role re-sync on the next login with old tokens invalidated, default
roles when nothing maps, e-mail collision with a local account → 409 while local login stays
intact, audit trail; JIT-off → 403; no settings → provider disabled and start → 503.
Totals: shared 98, API 90, web 4, pytest 8; e2e 5/5 (SSO button absent when not configured).

**Not delivered / limitations**

No OIDC logout (RP-initiated), no IdP-initiated session revocation (back-channel logout), no
MFA step-up for local accounts, no admin UI to link a local account to an SSO identity (the
409 path is deliberate and manual), no tenant/site scoping yet.

## Slice 2 — Site scoping and multi-instance rate limiting (2026-10-18)

**Delivered**

- **Site scoping as an authorization boundary.** `sites` catalogue (`GET/POST /api/v1/sites`;
  create needs `network.manage`), `user_site_grants` and `users.all_sites`. A principal carries
  `sites: null` (unrestricted) or the granted keys; `SessionUser` exposes it. Administrators set
  grants with `PUT /api/v1/users/{id}/sites` (`users.manage`, not on themselves, unknown keys
  refused, audited `users.set_sites`); the change bumps `token_version` and revokes refresh
  tokens, so it applies on the next request. Enforcement is in the queries, not the UI:
  `apps/api/src/middleware/scope.ts` adds a predicate to asset list/detail (via the asset's
  segment site), network segments, sensors (`sensors.site`), alert list/detail (via the alert's
  asset) and the event list (via src/dst asset). Out-of-scope detail requests return **404**, not
  403, so existence is not leaked; rows that cannot be attributed to a site (asset without a
  segment, alert or event without an asset, sensor without a site) are **hidden from restricted
  principals** — fail closed. A restricted user with no grants sees nothing.
- **Shared rate limiting.** `RedisRateLimiter` (`REDIS_URL`) runs the token bucket atomically in
  Redis via a Lua script so every API instance draws from the same bucket; the client is a
  dependency-free RESP2 implementation (`MiniRedis`). When Redis is unreachable the limiter
  **degrades to the per-instance bucket** and logs once per outage — it never fails open
  silently and never blocks all traffic because the cache is down. Unset `REDIS_URL` keeps the
  in-process limiter (single instance).
- Schema (`0012_phase7_site_scoping_redis`): `sites`, `user_site_grants`, `users.all_sites`.

**Verified**

API: site-scoping integration test — two sites with a segment, asset and sensor each, an
orphan asset, a site-less sensor, three alerts (DC asset, branch asset, no asset); unrestricted
user sees all; grant to `dc1` invalidates the session, then assets/segments/sensors/alerts/events
are filtered and out-of-scope or unattributable ids 404; restricted with no grants sees nothing;
back to unrestricted; unknown site key → 400; audit entries. Redis limiter test against a real
`redis-server` spawned on a free port — two limiter instances share one bucket (3 allowed, 4th
denied with retry-after), other keys unaffected, unreachable Redis degrades to per-instance
limits and still limits. Totals: shared 98, API 93, web 4, pytest 8; e2e 5/5.

**Known limitations**

Incidents, response actions, assessments, detection rules and ML results are not site-scoped
(they reference scoped objects but are visible to any holder of their permission); the SSE alert
stream is per-instance (a multi-instance deployment needs sticky sessions for `/stream/alerts`
or a shared bus — documented in the deployment profiles); writes (observations, sensor
registration) are not yet refused for sites outside the actor's grants.
