#!/usr/bin/env bash
# Read-only environment inspection. Prints Markdown. Changes nothing.
set -uo pipefail
v() { command -v "$1" >/dev/null 2>&1 && "$@" 2>&1 | head -1 || echo "missing"; }
echo "# Environment report ($(date -u +%FT%TZ))"
echo; echo "## Host"
echo "- kernel: $(uname -srm)"
echo "- os: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || sw_vers -productName 2>/dev/null || echo unknown)"
echo "- cpu cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null)"
echo "- memory: $(free -h 2>/dev/null | awk '/Mem:/{print $2" total, "$7" available"}' || echo n/a)"
echo "- disk (cwd): $(df -h . | awk 'NR==2{print $4" free of "$2}')"
echo "- virtualization: $(systemd-detect-virt 2>/dev/null || ( [ -f /.dockerenv ] && echo docker ) || echo unknown)"
echo "- capabilities (CapEff): $(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}' || echo n/a)"
echo; echo "## Toolchain"
for t in node pnpm npm python3 docker psql pg_isready redis-server suricata zeek tcpdump nats-server; do
  printf -- "- %s: %s\n" "$t" "$(v "$t" --version)"
done
echo; echo "## Network interfaces (read-only)"
if command -v ip >/dev/null; then ip -br addr; else
  for i in /sys/class/net/*; do n=$(basename "$i"); printf -- "- %s: state=%s mtu=%s mac=%s\n" "$n" "$(cat "$i/operstate")" "$(cat "$i/mtu")" "$(cat "$i/address")"; done
fi
echo; echo "## Listening TCP ports"
(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null) | head -30
echo; echo "## Packet-capture feasibility (facts, not a test)"
echo "- AF_PACKET requires CAP_NET_RAW; promiscuous mode requires CAP_NET_ADMIN on a Linux host with a mirror/TAP interface."
echo "- This report does not open any socket in promiscuous mode."
