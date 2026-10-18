# Phase 0 — verification record

Executed 2026-10-18 on the environment described in `environment-report.md` (Ubuntu 24.04 VM,
Node 22.22, pnpm 10.28, Python 3.13, PostgreSQL 16.15 native cluster on port 5433, **no Docker daemon**).

## Automated gates (`scripts/verify.sh`) — all passed

| Step                     | Scope                                                                                                                                                                                                                                                                                                                                                                                            | Result           |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| `pnpm typecheck`         | shared, api, web (strict TS, `noUncheckedIndexedAccess`)                                                                                                                                                                                                                                                                                                                                         | pass             |
| `pnpm lint`              | ESLint flat config, typescript-eslint, react-hooks                                                                                                                                                                                                                                                                                                                                               | pass, 0 warnings |
| `pnpm format:check`      | Prettier                                                                                                                                                                                                                                                                                                                                                                                         | pass             |
| `@noc/shared` unit tests | 55 tests: RBAC catalog + separation of duties, schema strictness, secret-key audit over 24 public schemas, scope enforcement (exclusions, window, technique, public refusal, IPv4-mapped IPv6, garbage input), incident lifecycle, assurance derivation, priority, approvals                                                                                                                     | 55 passed        |
| `@noc/api` tests         | 36 tests against `noc_test`: env validation, JWT, Argon2id, rate limiter; login/lockout/refresh rotation + reuse detection/origin check/logout-all/password change/bootstrap guard; deny-by-default RBAC, role/status changes revoking tokens, strict bodies; audit chain genesis/alteration/deletion/concurrency/pagination; health/ready/status contract/metrics auth/OpenAPI/413/429/404/CORS | 36 passed        |
| `@noc/web` unit tests    | 4 tests: 19 workspaces, permission + i18n coverage, Phase-0-only `implemented`, fa/en key parity, RTL                                                                                                                                                                                                                                                                                            | 4 passed         |
| `pnpm build`             | API bundle (tsup) and Next.js 15 production build (standalone)                                                                                                                                                                                                                                                                                                                                   | pass             |
| `ruff check` / `pytest`  | analysis service: health/ready, advisory-only status, internal token, request id                                                                                                                                                                                                                                                                                                                 | pass / 4 passed  |

Migrations: `drizzle/0000_phase0_foundation.sql` generated from the schema and applied to `noc_dev`
and `noc_test` (25 tables, 29 enums). `syncRbacCatalog` mirrors the shared permission/role catalog
on every migrate and start.

## Live process smoke (`scripts/smoke.sh`) — 10/10 passed

Against the built API (`node dist/src/server.js`) and built web (`next start`), after
`bootstrap-admin` created the single administrator from environment variables:
health, ready, OpenAPI lists login, status denied without token, login issues token, status reports
`demoData:false`, audit chain verifies, login page `dir="rtl"`, `lang="fa"`, anonymous shell
request redirected.

## Browser end-to-end (`pnpm --filter @noc/web e2e`, Chromium) — 2/2 passed

1. Wrong credentials → API 401 → Persian error rendered, URL stays `/login`.
2. Correct credentials → BFF server action → httpOnly `noc_access` cookie, nothing in web storage →
   `/command-center` renders Persian title, `دادهٔ نمایشی: خیر`, `auth.rbac` = فعال,
   `nips.inline_prevention` = غیرفعال → `/administration` lists the admin → `/audit-logs` shows
   `auth.login` and chain verification reports intact → `/nids` placeholder shows real
   `nids.suricata` state → logout clears the session and `/command-center` redirects to `/login`.

## Not verified here (blocked by environment)

- Docker image builds and `infra/docker-compose.yml` (no Docker daemon). Covered structurally; CI
  (`.github/workflows/ci.yml`) is the first execution.
- Any packet capture, Suricata/Zeek, SNMP or discovery behaviour — none exists yet by design.

## Acceptance checklist (§27)

Environment inspected ✔ · existing work preserved (repository was empty apart from `.forge`) ✔ ·
pnpm workspace ✔ · shared Zod package compiles ✔ · Next.js 15 builds ✔ · Persian RTL shell + login ✔ ·
Hono API starts ✔ · PostgreSQL readiness ✔ · auth + RBAC foundations ✔ · FastAPI health ✔ ·
validated env config ✔ · Compose authored (unexecuted here) ⚠ · start/stop preserve data ✔ ·
logging + request correlation ✔ · tests/typecheck/lint/builds executed ✔ · README with limitations ✔ ·
no committed credentials or default passwords ✔ (secrets only in git-ignored `.env`/`.local`) ·
security operations disabled until integrations exist ✔ · no unsupported capability claims ✔.
