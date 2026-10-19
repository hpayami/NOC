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

## Slice 3 — Scoped SOC objects, shared alert bus, address-only re-attachment (2026-10-18)

**Delivered**

- **Site scoping extended to the SOC objects.** Incidents now carry a `site` (nullable; null =
  global). On creation the site is the explicit one, else the first attributable attached
  alert's (through its asset's segment). Enforcement is in `IncidentService` and the response,
  ML and findings services, not in routes: list/detail/stats/transition/update/note/link all
  carry the predicate; a response action is visible through its incident; a finding and an ML
  result through their asset; `POST /ml/score` and `POST /ml/score/batch` only touch assets in
  scope. Out-of-scope ids answer **404**; global incidents, actions without an incident and
  non-asset ML subjects are hidden from restricted principals.
- **Write-side refusal.** A restricted actor opening an incident outside their grants gets
  **403** and an audited `incidents.create` / `denied` (`reason: site_not_granted`); with nothing
  to attribute the site to they get **400** (a global incident they could never see again is not
  created silently); an alert outside their scope cannot be attached — it is reported as absent
  (404) and never reveals its site. Unknown explicit site keys are 400 for everyone.
- **Shared alert bus.** `RedisAlertBus` (`apps/api/src/events/redis-bus.ts`, active when
  `REDIS_URL` is set) fans alert stream events out over Redis pub/sub so an SSE client attached
  to any API instance sees alerts ingested on every instance. Semantics stay at-most-once and
  best effort (the stream is a nudge to re-fetch, never the record); payloads from the channel
  are validated against the shared `AlertStreamEvent` contract and dropped otherwise; an
  instance ignores the echo of its own messages; local subscribers are always served and a Redis
  outage is logged once with reconnect/backoff. `MiniRedis` gained pub/sub push and close hooks.
- **Address-only observations re-attach.** `resolveAssetIdentity` gained a last tier,
  `ip_sole_owner` (confidence 0.55): an observation that carries _only_ addresses (a discovery
  probe, an assessment hit) matches the asset that currently holds the address when exactly one
  does, is `ambiguous` when several do, and still creates when none does. Any stable identifier
  on the observation disables the tier — a new MAC on a reused IP is still a new device. The
  discovery and assessment workers now share this one path (the assessment worker's private
  lookup was removed), so repeated runs stop minting an asset per IP.
- Web: incident site in the list and detail, site selector on the new-incident form (restricted
  users must pick one of their sites; unrestricted users may leave it automatic/global).
- Schema (`0013_phase7_incident_site_bus`): `incidents.site` + index.

**Verified**

Shared: identity tier (sole owner match, two holders ambiguous, stable identifier disables the
tier). API: scoping test part 2 — inferred/explicit/global incident sites, unknown site 400;
after restriction: list/stats/detail/transition scoped, 403 + audit for a foreign site, 400 for
no site, 404 for foreign alerts at creation and link time, response actions scoped through the
incident (propose, list, detail), findings and ML results through the asset, scoring a foreign
asset 404. Bus test against a real `redis-server`: two instances, one delivery each, own echo
ignored, garbage and contract-violating payloads dropped, unreachable Redis still serves local
subscribers and reports degradation. Assets test: scan hit re-attaches to the sole holder and an
unowned address still creates. Totals: shared 99, API 97, web 4, pytest 8; e2e 5/5.

**Known limitations**

Assessment engagements and detection rules are still global (engagement scope is CIDR-based and
authorised per engagement, not per site); the bus does not replay missed events (reconnecting
clients re-fetch the queue); OIDC logout / back-channel logout remain open.

## Slice 4 — OIDC logout: RP-initiated and back-channel (2026-10-18)

**Delivered**

- **RP-initiated logout** (OpenID Connect RP-Initiated Logout 1.0). `POST /api/v1/auth/logout`
  now answers `{ idpLogoutUrl }`: for an SSO account, when `OIDC_POST_LOGOUT_REDIRECT_URI` is set
  and the IdP publishes `end_session_endpoint`, the URL carries `client_id` and
  `post_logout_redirect_uri`; the web logout route sends the browser there after clearing the
  local session. ID tokens are never stored, so no `id_token_hint` is sent. Local accounts, an
  unconfigured post-logout URI or an unreachable IdP give `null` and a plain local logout.
  `GET /auth/providers` advertises `rpInitiatedLogout`.
- **Back-channel logout** (OpenID Connect Back-Channel Logout 1.0).
  `POST /api/v1/auth/oidc/backchannel-logout` (form `logout_token`, server-to-server, no browser
  origin check, rate limited) verifies the token with the same RS256/JWKS path as ID tokens plus
  the logout-token rules: issuer, audience (+`azp`), `iat` not older than 5 minutes, the
  `http://schemas.openid.net/event/backchannel-logout` event, a `jti`, `sub` and/or `sid`, and
  **no `nonce`**. `jti` values are stored until expiry (`oidc_logout_tokens`); a replay is 400.
  Effect: `sid` → the refresh-token families of that IdP session end (the `sid` claim is stored on
  the SSO session's refresh tokens and carried across rotation); `sub` → every session of the
  subject ends and `token_version` is bumped so outstanding access tokens die immediately.
  Audited as `auth.oidc_backchannel_logout` with what matched. An unknown subject is still 200
  (processed, nothing to revoke) so the IdP does not retry forever.
- Schema (`0014_phase7_oidc_logout`): `refresh_tokens.external_sid` + index,
  `oidc_logout_tokens`.

**Verified**

API: SSO login with `sid` → logout returns the end-session URL with the right parameters and no
`id_token_hint`, refresh refused afterwards; local account logout → `null`. Two SSO sessions:
back-channel by `sid` ends one and leaves the other usable; refusals for a rogue key, wrong
audience, nonce present, missing event, stale `iat`, neither `sub` nor `sid`, `alg=none` — and the
live session is untouched by any of them; back-channel by `sub` ends the remaining session
including its access token; replay 400; unknown subject 200; the user can sign in again; audit
trail shows `none` / `sid` / `sub` matches and the IdP-logout flag.

**Known limitations**

Front-channel logout (iframe-based) is not implemented; a `sid`-only logout leaves already-issued
access tokens valid until they expire (default 15 minutes) because the platform never bumps a
whole user's `token_version` for one IdP session — use `sub` tokens from the IdP when immediate
revocation is required.

## Slice 5 — Platform conditions and signed webhook notifications (2026-10-18)

**Delivered**

- **Conditions** (`packages/shared/src/rules/conditions.ts`, pure): one evaluation over records
  the platform already holds, returning the conditions an operator should act on **and every
  check that ran** with `ok` / `failing` / `unavailable` — a quiet dashboard says "checked,
  nothing found", not "nothing checked". Checks: `sensors_silent` (critical; enabled sensor with
  no heartbeat within `IPS_HEARTBEAT_MAX_AGE_SECONDS`), `sensors_unhealthy` (warning; last
  reported health not `healthy`), `rule_bundles_out_of_sync` (warning; rule-consuming sensor not
  acknowledging the current bundle digest), `ips_policies_expiring` (warning; enabled inline
  policy within 2 h of its TTL), `ips_auto_disabled` (critical; watchdog returned a sensor to
  detect-only in the last 24 h), `analysis_reachable` (warning when down; `unavailable` when the
  probe itself could not run), `approvals_pending` (info; IPS policies, engagements, response
  actions awaiting a decision), `cves_uncatalogued` (info), `assets_unmonitored` (warning when
  more than half the inventory has no detection coverage — "unknown, not low"). Each condition
  carries a count and the workspace path to act on it. `GET /api/v1/operations/conditions`
  (`platform.status.read`).
- **Webhook channels** (`notifications.manage`, held by `platform_admin` only): name, http(s)
  URL, write-only shared secret (≥ 16 chars, stored, never returned, never logged), minimum
  severity, enabled flag. `POST /channels`, `PATCH /channels/{id}`, `GET /channels`,
  `POST /channels/{id}/test`, `GET /deliveries`. Every delivery body is signed
  `x-noc-signature: sha256=<HMAC-SHA256 hex>` with `x-noc-event` and `x-noc-timestamp`; the
  payload (`WebhookPayload`) is `{ event: raised|resolved|test, condition, platform, at }`.
  Redirects are not followed; 5 s timeout; the request is bounded to what the condition says.
- **Delivery semantics** (`OperationsService.notify`, `NotificationScheduler`,
  `NOTIFICATIONS_ENABLED` / `NOTIFICATIONS_INTERVAL_SECONDS` default 120 /
  `NOTIFICATIONS_REMIND_HOURS` default 6): per channel and condition the platform keeps a
  fingerprint (`id:severity:count`); a channel is told once when a condition appears or changes,
  reminded after the quiet period while it persists, and told once when it resolves. A failed
  delivery is recorded (`notification_deliveries`, channel `lastStatus`/`lastError`) and leaves
  the state untouched, so it is retried on the next cycle — never silently dropped, never
  duplicated on success. Channel create/update/test are audited; deliveries are their own ledger.
- Capability `ops.notifications`: `not_configured` without channels, `available` with enabled
  channels, `degraded` when a channel's last delivery failed.
- Web: the command centre shows the conditions panel (severity, detail, link to the workspace,
  checks tally) and links to `/operations`, which repeats the panel and — for
  `notifications.manage` — lists channels (state, last attempt and error), creates channels,
  sends test deliveries, enables/disables, and shows recent deliveries. Others see the panel and
  an explicit note that channel management is withheld by permission.
- Schema (`0018_phase7_notifications`): `notification_channels`, `notification_states` (PK
  channel + condition), `notification_deliveries`.

**Verified**

Shared (6): every check reported when quiet; silent/stale/degraded/disabled sensors and an
out-of-sync bundle ordered by severity with disabled sensors excluded; expiring vs later policies,
recent vs old watchdog disables, operator disables ignored; unreachable analysis vs probe not run;
info conditions, the >50 % unmonitored rule (exactly half and no assets are not warnings);
fingerprint ignores wording. API (4, with a local HTTP receiver): empty platform raises only the
genuinely unreachable analysis service; an enrolled sensor that never reports raises
`sensors_silent` + `rule_bundles_out_of_sync`, a heartbeat with the bundle digest clears both, a
degraded heartbeat raises `sensors_unhealthy`; channel CRUD under `notifications.manage` (403 for
a blue-team engineer), ftp URL and short secret rejected, secret absent from every response, 404
on unknown ids, audit entries; one signed raise (HMAC verified against the received body,
timestamp header, payload parses), quiet on repeat, reminder after 7 h, `resolved` after the
heartbeat, a 500 from the receiver recorded as failed with the channel and capability degraded,
retried and sent once the receiver recovers, delivery ledger in order, disabled channel receives
nothing; test deliveries signed and audited, an unreachable receiver reported as failed with the
error. Totals: shared 119, API 106 (25 files), web 4, pytest 8 + agent 7; e2e 5/5.

**Known limitations**

Webhook is the only channel kind (e-mail/chat connectors would be adapters over the same state
machine); the notifier runs on every instance unless disabled on all but one (states are keyed
per channel, so two instances would at worst send one duplicate per condition change); there is
no per-site routing of conditions; the receiver must verify the signature itself (a sample is in
the README).

## Slice 6 — E-mail notification channels over SMTP (2026-10-19)

**Delivered**

- **Contract**: `NotificationChannel.kind` is `webhook | email`; `CreateNotificationChannelRequest`
  is a union — the webhook variant is unchanged (and `kind` defaults to it, so existing clients
  keep working), the e-mail variant carries `EmailChannelConfig` (host, port default 587,
  `starttls` default true, optional username, from, 1–32 recipients) and a write-only SMTP
  password. Channels return their SMTP settings without the password.
- **Rendering** (`rules/notifications.ts`, pure): one deterministic plain-text e-mail per
  condition event — subject `[NOC] <SEVERITY|RESOLVED|TEST>: <title>`, body with condition id,
  severity, count, detail, workspace link, time and platform version, and the same honesty
  line as every other output.
- **SMTP client** (`apps/api/src/operations/smtp.ts`, no dependency added): EHLO, STARTTLS when
  the server offers it (refused when required but absent), implicit TLS on 465, AUTH PLAIN or
  LOGIN only on a TLS session, MAIL/RCPT/DATA with dot-stuffing, base64 body and encoded
  headers, QUIT; timeouts and the last server reply are captured. Certificate validation is
  never relaxed. A test-only `insecurePlain` flag exists for the in-process stub and is set
  nowhere in production code.
- **Service**: `deliver` branches on kind; the state machine (raise once, remind after the
  quiet period, resolve once, retry failures) is unchanged. Failed SMTP deliveries record the
  server reply (`550 5.1.1 User unknown`) on the delivery and the channel. Capability
  `ops.notifications` counts both kinds. Schema (`0022_phase7_email_channels`): `url` and
  `secret` nullable, `config` jsonb for kind-specific settings.
- Web: channel form with a kind switch (webhook fields or SMTP fields), channel table with
  kind and target (host:port → recipients), i18n fa/en.

**Verified**

Shared (2): rendering (subject per event, body facts, honesty line); contract (webhook without
`kind`, e-mail defaults, bad host / from / ftp URL refused). API (1 new, against an in-process
SMTP stub): invalid recipients 400; created channel shows settings but never the password
(list included); a test delivery authenticates with AUTH PLAIN, addresses both recipients,
carries the rendered subject and a base64 body with the condition; a critical condition raises
one e-mail and stays quiet on repeat; a recipient rejected with 550 is a failed delivery with
the reply on the channel, retried and sent once the server accepts; capability available.
Totals: shared 137, API 114 (30 files), web 5, pytest 8 + agent 10; e2e 5/5.

**Known limitations**

STARTTLS and implicit-TLS paths are exercised against real servers only (the stub speaks plain
SMTP); no HTML body, attachments or digest batching; one message per event per channel;
SMTP egress must be allowed from the API host (see deployment profiles).
