#!/usr/bin/env bash
# Shared helpers for start/stop/smoke scripts. Sourced, not executed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT/.local/run"
LOG_DIR="$ROOT/.local/logs"
mkdir -p "$RUN_DIR" "$LOG_DIR"

log()  { printf '\033[1;34m[noc]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[noc]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[noc]\033[0m %s\n' "$*" >&2; exit 1; }

load_env() {
  [[ -f "$ROOT/.env" ]] || die ".env not found — copy .env.example to .env and set the secrets"
  set -a; # shellcheck disable=SC1091
  source "$ROOT/.env"; set +a
  : "${DATABASE_URL:?DATABASE_URL must be set in .env}"
  : "${AUTH_JWT_SECRET:?AUTH_JWT_SECRET must be set in .env}"
}

have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

wait_for() { # wait_for <name> <url> [attempts]
  local name=$1 url=$2 n=${3:-40}
  for ((i = 1; i <= n; i++)); do
    if curl -fsS -o /dev/null "$url"; then log "$name ready"; return 0; fi
    sleep 1
  done
  die "$name did not become ready at $url"
}

pg_ready() { # pg_ready <database_url>
  local url=$1
  for ((i = 1; i <= 60; i++)); do
    if psql "$url" -Atc 'select 1' >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

start_bg() { # start_bg <name> <cwd> <cmd...>
  local name=$1 cwd=$2; shift 2
  if [[ -f "$RUN_DIR/$name.pid" ]] && kill -0 "$(cat "$RUN_DIR/$name.pid")" 2>/dev/null; then
    log "$name already running (pid $(cat "$RUN_DIR/$name.pid"))"; return 0
  fi
  (cd "$cwd" && nohup "$@" >"$LOG_DIR/$name.log" 2>&1 & echo $! >"$RUN_DIR/$name.pid")
  log "$name started (pid $(cat "$RUN_DIR/$name.pid"), log $LOG_DIR/$name.log)"
}

stop_bg() { # stop_bg <name>
  local name=$1 pidfile="$RUN_DIR/$1.pid"
  [[ -f "$pidfile" ]] || return 0
  local pid; pid=$(cat "$pidfile")
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    log "$name stopped"
  fi
  rm -f "$pidfile"
}
