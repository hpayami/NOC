# Environment report — Phase 0 inspection

Inspected 2026-10-18 with read-only commands (`uname`, `/proc`, `/sys/class/net`, `command -v`,
`pg_lsclusters`, `docker info`). No firewall, route, interface or service configuration was changed.
Re-run `scripts/env-report.sh` to regenerate the factual section on any host.

## Observed facts

| Item                             | Observation                                                                                                                |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Host                             | Linux 6.18 x86_64, Ubuntu 24.04.5; hostname `vm`; no `/.dockerenv`, cgroup root `/`                                        |
| CPU / RAM                        | 4 cores, 15 GiB RAM, no swap                                                                                               |
| Disk                             | 252 GB volume, ~29 GB available to this session                                                                            |
| Privileges                       | Running as root; `CapEff` includes `NET_RAW`/`NET_ADMIN` bits                                                              |
| Interfaces                       | `lo`, `eth0` (up, MTU 1400, 1 default route via 192.0.2.1-style gateway), `ifb0`/`ifb1` (down, 0 bytes)                    |
| Node.js / pnpm / npm             | 22.22.0 / 10.28.0 / 10.9.4                                                                                                 |
| Python                           | 3.13.16 (`fastapi` not installed system-wide; venv created for the service)                                                |
| Docker                           | CLI 29.8.2 present, **daemon not running** (`/var/run/docker.sock` missing)                                                |
| PostgreSQL                       | Server 16.15 binaries installed; cluster `main` down; a dedicated cluster `noc` was created on **port 5433** for this work |
| Redis                            | 7.0.15 binary present, not running                                                                                         |
| Suricata / Zeek / tcpdump / NATS | **not installed**                                                                                                          |
| Outbound network                 | HTTPS via a policy-enforcing proxy; npm and PyPI reachable                                                                 |

## Assumptions and non-observations

- The host is a cloud VM/sandbox. It has **no mirror port or TAP**; nothing on `eth0` other than
  this session's own traffic would be visible. No capture was attempted.
- `ifb0/ifb1` are kernel intermediate functional block devices (typically traffic shaping), not
  capture interfaces.
- Because the Docker daemon is unavailable, the Compose stack and Dockerfiles were **written but not
  executed** here. They are validated by structure only; CI builds them on a Docker-capable runner.
- Disk performance was not benchmarked.

## Consequences for Phase 0

- Development database: the native cluster on `127.0.0.1:5433` (`noc_dev`, `noc_test`), password in
  `.local/dev-db-password` (git-ignored). On Docker-capable machines use `scripts/start.sh` instead.
- Packet capture, NIDS and NIPS are reported by the API as `not_configured` / `disabled` — no claim
  of capture capability is made for this host.
- This machine is suitable as a **management-plane development node only** (see
  `docs/deployment-profiles.md`).
