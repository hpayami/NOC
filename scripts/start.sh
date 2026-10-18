#!/usr/bin/env bash
# Starts the management plane for local development.
#   ./scripts/start.sh            # infra via Docker Compose (postgres, redis) + api/web/analysis natively
#   ./scripts/start.sh --native-db  # skip Docker; use an already-running PostgreSQL at DATABASE_URL
#   ./scripts/start.sh --infra-only # only start postgres/redis
# Persistent data lives in named Docker volumes (or your own cluster); this script never deletes it.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_env

NATIVE_DB=0; INFRA_ONLY=0
for a in "$@"; do case $a in --native-db) NATIVE_DB=1;; --infra-only) INFRA_ONLY=1;; *) die "unknown flag $a";; esac; done

if (( ! NATIVE_DB )); then
  have_docker || die "Docker is not available. Start PostgreSQL yourself and re-run with --native-db."
  log "starting postgres + redis (docker compose)"
  docker compose -f "$ROOT/infra/docker-compose.yml" up -d postgres redis
fi

log "waiting for PostgreSQL"
pg_ready "$DATABASE_URL" || die "PostgreSQL at DATABASE_URL is not reachable"
(( INFRA_ONLY )) && { log "infrastructure is up"; exit 0; }

log "applying migrations (idempotent)"
(cd "$ROOT" && pnpm --filter @noc/api db:migrate)

start_bg api "$ROOT/apps/api" pnpm dev
if command -v "$ROOT/services/analysis/.venv/bin/uvicorn" >/dev/null 2>&1; then
  start_bg analysis "$ROOT/services/analysis" .venv/bin/uvicorn app.main:app --host "${ANALYSIS_HOST:-127.0.0.1}" --port "${ANALYSIS_PORT:-8000}"
else
  warn "analysis venv missing — run: cd services/analysis && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'"
fi
start_bg web "$ROOT/apps/web" pnpm dev

wait_for api "http://${API_HOST:-127.0.0.1}:${API_PORT:-4000}/ready"
wait_for web "http://127.0.0.1:3000/login" 90
log "web: http://localhost:3000   api: http://${API_HOST:-127.0.0.1}:${API_PORT:-4000}/api/v1/openapi.json"
log "first run? create the administrator: pnpm --filter @noc/api bootstrap-admin"
