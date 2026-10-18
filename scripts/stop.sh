#!/usr/bin/env bash
# Stops local processes and pauses infra containers. Data volumes are preserved: this script
# never runs `docker compose down -v` or drops databases.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for name in web analysis api; do stop_bg "$name"; done

if [[ "${1:-}" != "--keep-infra" ]] && have_docker && [[ -f "$ROOT/.env" ]]; then
  log "stopping postgres + redis containers (volumes kept)"
  (cd "$ROOT" && docker compose -f infra/docker-compose.yml stop postgres redis) || warn "compose stop failed"
fi
log "stopped"
