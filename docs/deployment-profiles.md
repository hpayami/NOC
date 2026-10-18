# Deployment profiles (sizing inputs, not guarantees)

Hardware cannot be recommended without four inputs: **sustained and burst packet rate** at each
capture point, **average event size** after normalization, **retention period** per data class, and
**query concurrency**. Each profile below lists what must be measured before committing hardware
and the structural shape that fits; numbers are starting points for a sizing exercise.

| Profile                    | Shape                                                                                                                                  | Measure first                                                                          | Typical starting point                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Local development          | Everything on one laptop/VM; no capture; Compose for PG/Redis                                                                          | —                                                                                      | 4 vCPU, 8–16 GB, SSD                                                    |
| Home lab                   | 1 management node + 1 small Linux sensor on a mirror port (out-of-band only)                                                           | Mirror-port peak Mbps; EVE events/s                                                    | Mgmt 4 vCPU/8 GB; sensor 4 cores/8 GB/1 GbE NIC                         |
| Small organization         | Mgmt node (PG + Redis + API/web), 1–3 out-of-band sensors, PG for events ≤ a few million/day                                           | events/day, retention days, concurrent analysts                                        | Mgmt 8 vCPU/32 GB/NVMe; sensors 8 cores/16 GB each                      |
| Medium enterprise          | HA mgmt pair, dedicated PG, dedicated event store (ClickHouse/OpenSearch), NATS, 5–20 sensors; inline IPS only on validated appliances | Per-segment pps, worst-case burst, p99 latency budget for inline paths, index overhead | Event store nodes sized from events/s × bytes × retention ÷ compression |
| High-throughput enterprise | Multi-site, distributed sensors with local buffering, sharded event store, dedicated IPS appliances with hardware bypass               | NUMA layout, NIC RSS queues, AF_XDP/DPDK feasibility, replication factor, RTO/RPO      | Capacity test with recorded production PCAP before purchase             |

## Role-specific evaluation checklists

**Management node**: CPU/RAM headroom for PG, API concurrency, WebSocket fan-out (later), background
jobs; disk latency (PG WAL), retention of transactional tables, backup window.

**Network sensor**: NIC speed and offload support, driver/kernel compatibility, capture method
(AF_PACKET v3 / AF_XDP), per-core throughput, RAM for flow tables, NUMA locality, storage throughput
for EVE/PCAP, measured packet-drop counters at target load.

**Inline IPS appliance** (additionally): forwarding capacity at worst-case packet size, latency
budget, fail-open vs fail-closed (network owner's decision), bypass NIC behavior on power loss,
redundant links, maintenance and rollback procedure.

**Storage/analytics nodes**: ingestion events/s, compression ratio (measure with real data), index
overhead, replication, backup capacity, query concurrency, recovery objectives.

Never report "zero packet loss" or "complete visibility" without counters from the sensor itself.

## Running more than one API instance (Phase 7)

- Set `REDIS_URL` on every instance so rate limits are shared (token bucket in Redis; the
  limiter degrades to per-instance limits and logs if Redis is unreachable).
- Sessions need nothing shared: access tokens are stateless JWTs and refresh-token families live
  in PostgreSQL.
- OIDC login state lives in PostgreSQL (`oidc_states`), so the callback may land on any instance.
- With `REDIS_URL` the SSE alert stream (`/api/v1/alerts/stream`) is fed by a Redis pub/sub bus:
  a browser attached to any instance sees alerts ingested on every instance, so no sticky
  sessions are needed. Delivery is at-most-once (the stream is a nudge to re-fetch); if Redis
  drops, each instance keeps serving its own alerts and reconnects with backoff. Without
  `REDIS_URL` the bus is in-process and an instance only pushes what it ingested itself.
- Schedulers (monitoring checks, retention, IPS expiry) are idempotent but run on every instance;
  set `MONITORING_SCHEDULER_ENABLED=false` / `RETENTION_ENABLED=false` on all but one.
