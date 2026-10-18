#!/usr/bin/env bash
# Full local verification gate — the same steps CI runs.
#   TEST_DATABASE_URL=postgres://noc:<pw>@127.0.0.1:5432/noc_test ./scripts/verify.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$ROOT"
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL is required (points at a *_test database)}"
export NEXT_TELEMETRY_DISABLED=1
step() { log "▶ $1"; shift; "$@" || die "step failed: see above"; }

step "typecheck" pnpm -s typecheck
step "lint" pnpm -s lint
step "format" pnpm -s format:check
step "tests (shared, api, web)" pnpm -s -r test
step "build (api, web)" pnpm -s -r build
if [[ -x services/analysis/.venv/bin/pytest ]]; then
  step "analysis: ruff" services/analysis/.venv/bin/ruff check services/analysis
  step "analysis: pytest" bash -c 'cd services/analysis && .venv/bin/pytest -q'
else
  warn "analysis venv missing; skipping python checks"
fi
log "all verification steps passed"
