#!/usr/bin/env bash
# End-to-end smoke test against a running stack (see start.sh). Exercises: health, readiness,
# OpenAPI, login via API, authenticated status, RTL login page, denied unauthenticated status.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_env
API="http://${API_HOST:-127.0.0.1}:${API_PORT:-4000}"
WEB="${WEB_ORIGIN:-http://localhost:3000}" # must match the Host Next.js expects for server actions
: "${SMOKE_EMAIL:?set SMOKE_EMAIL}"; : "${SMOKE_PASSWORD:?set SMOKE_PASSWORD}"
fail=0
check() { if "$@"; then log "ok: ${*: -1}"; else warn "FAIL: ${*: -1}"; fail=1; fi; }

check curl -fsS "$API/health" -o /dev/null
check curl -fsS "$API/ready" -o /dev/null
check bash -c "curl -fsS '$API/api/v1/openapi.json' | grep -q '\"/api/v1/auth/login\"'" "openapi lists login"
check bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' '$API/api/v1/platform/status') == 401 ]]" "status denied without token"

TOKEN=$(curl -fsS -H 'content-type: application/json' -H "origin: ${WEB_ORIGIN:-http://localhost:3000}" \
  -d "{\"email\":\"$SMOKE_EMAIL\",\"password\":\"$SMOKE_PASSWORD\"}" "$API/api/v1/auth/login" | node -pe 'JSON.parse(require("fs").readFileSync(0,"utf8")).accessToken' 2>/dev/null || true)
[[ -n "$TOKEN" ]] && log "ok: login issued a token" || { warn "FAIL: login"; fail=1; }
check bash -c "curl -fsS -H 'authorization: Bearer $TOKEN' '$API/api/v1/platform/status' | grep -q '\"demoData\":false'" "status reports demoData=false"
check bash -c "curl -fsS -H 'authorization: Bearer $TOKEN' -X POST '$API/api/v1/audit/verify' | grep -q '\"valid\":true'" "audit chain verifies"
check bash -c "curl -fsS '$WEB/login' | grep -q 'dir=\"rtl\"'" "web login page is RTL"
check bash -c "curl -fsS '$WEB/login' | grep -q 'lang=\"fa\"'" "web login page is Persian by default"
check bash -c "[[ \$(curl -s -o /dev/null -w '%{http_code}' '$WEB/command-center') == 307 ]]" "shell redirects anonymous users"

(( fail == 0 )) && log "smoke passed" || die "smoke failed"
