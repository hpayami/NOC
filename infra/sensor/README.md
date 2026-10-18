# Network sensor deployment (Phase 2+ — not part of the development stack)

Packet capture and inline prevention are **never** run from `infra/docker-compose.yml`. Sensors are
separate Linux hosts or appliances with their own lifecycle, privileges and change control.

## Why this is separate

| Concern        | Management plane (compose stack)        | Sensor                                                                                         |
| -------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Network access | Loopback-bound service ports            | Mirror/TAP interface (out-of-band) or bridged pair (inline)                                    |
| Privileges     | `cap_drop: ALL`, read-only FS, non-root | `CAP_NET_RAW`, `CAP_NET_ADMIN` (+ `CAP_SYS_NICE`), host network namespace                      |
| OS             | Any Docker host                         | Linux kernel with AF_PACKET v3 (or NFQUEUE / XDP for inline)                                   |
| Failure mode   | Degraded UI/API                         | Out-of-band: blind spot. Inline: traffic impact — fail-open/closed is a network-owner decision |
| Ports          | Private                                 | None exposed; sensor pushes to the API over mTLS/token                                         |

macOS and Windows Docker Desktop cannot provide host-interface promiscuous capture from a container;
use a Linux host or VM with the mirror port attached.

## What `docker-compose.sensor.example.yml` shows

An **out-of-band Suricata** container template (Mode A). It is an example, not a default:

- `network_mode: host` and `cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]` — the minimum for AF_PACKET
  capture; **no** `privileged: true`.
- `SENSOR_INTERFACE` must be an interface that only receives mirrored traffic.
- EVE JSON is written to a named volume; the Phase 2 forwarder ships it to the API's ingestion
  endpoint with the sensor's enrolment credential.
- Inline mode (Mode B) is intentionally absent from the example. Enabling it requires the Phase 4
  approval workflow (two approvers, change ticket, validated rule set, rollback plan, allow-listed
  management paths) and is activated through the API — never by editing a compose file.

## Pre-deployment checklist (per sensor)

- [ ] Written authorization for the monitored segments
- [ ] NIC: speed, driver, offload settings (GRO/LRO disabled for capture), RSS queues
- [ ] CPU cores reserved for workers; NUMA locality for the capture NIC
- [ ] Storage throughput for EVE/PCAP retention; disk-full behavior
- [ ] Time sync (chrony/NTP) — correlation across Suricata/Zeek depends on it
- [ ] Rule set license reviewed (ET Open: BSD; ET Pro/commercial: per contract)
- [ ] Packet-drop counters exported and alerting thresholds set
