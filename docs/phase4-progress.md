# Phase 4 — progress log

## Slice 1 — Inline-prevention policy plane (2026-10-18)

**Invariant kept:** the management plane never switches a sensor inline on its own. Sensors
default to detect-only (`ids`) and the directive they fetch is fail-open by construction
(`failOpen: true` is a literal in the contract).

**Delivered**

- `packages/shared/src/entities/ips.ts`: policy modes (`ids` / `ips_test` / `ips`), statuses,
  proposal contract (private protected ranges, excluded ranges, validated rule ids, mandatory
  justification and rollback plan; `ids` cannot be proposed), decision/enable/disable requests,
  `IpsPolicy` record with approvals and sensor apply state, `SensorIpsDirective` (what a sensor
  runs now) and `IpsAckRequest` (what it confirmed).
- `packages/shared/src/rules/ips.ts`: `checkIpsEnable` — hard refusals for: not approved, fewer
  than the required approvals, enabler among approvers (user-level SoD on top of the
  `ips.approve`/`ips.enable` role pair), TTL outside 1–72 h, non-Suricata sensor, disabled
  sensor, no heartbeat in 5 min, sensor not reporting inline capability, last health not
  `healthy`, another policy already enabled on the sensor. `publicCidrs` fails closed.
- `apps/api/src/ips/service.ts` + `routes/ips.ts` (`/api/v1/ips/policies`): propose
  (`ips.propose`; rules must be enabled and validated/deployed; sensor must be Suricata) →
  approve/reject (`ips.approve`, two independent approvers via `checkApproval`, proposer
  excluded) → enable (`ips.enable`, gate above, sets `sensors.mode = inline_prevention`,
  version++, `expiresAt`) → disable (**kill switch**: `ips.enable` _or_ `ips.approve`, no
  approval, reason required). Expiry is enforced lazily on every sensor fetch and policy list:
  the sensor falls back to `ids` and the policy becomes `expired` (audited as `system:ips`).
  One enabled policy per sensor is a partial unique index, not just a check.
- Sensor side: `GET /api/v1/agents/ips-directive` (sensor credential) returns the enabled
  policy with engine rule refs resolved from the registry, or the detect-only default;
  `POST /api/v1/agents/ips-ack` records the applied version (failures audited). Heartbeats now
  carry `inlineCapable` (default false — never assumed).
- Schema (`0008_phase4_ips_policy_plane`): `ips_policies`, enums, `sensors.inline_capable`.
- Capabilities: `nips.policy_plane` → available; `nips.inline_prevention` is **dynamic** —
  `disabled` with no enabled policy, `degraded` while a sensor has not acknowledged the current
  version, `available` only when every enabled policy is acknowledged.
- Web **NIPS Policies** page: live capability state with reason, policy list (approvals, version,
  apply state, expiry, rollback plan), propose form (Suricata sensors only; flags sensors that
  have not reported inline capability), approve/reject, time-boxed enable, kill switch — each by
  permission. Platform admins have no `ips.read` and see the forbidden page.

**Verified**

Shared: 5 tests (gate passes only when all conditions hold; every refusal code; public-range
detection; proposal validation; fail-open literal). API: 2 integration tests — unsafe proposals
refused (public range, `ids`, draft rule, Zeek sensor, permissions) and the sensor untouched;
full flow with two approvals, each sensor gate in turn (silent → not capable → degraded →
healthy), TTL bound, directive content, platform capability `degraded` → `available` after the
sensor ack, one-enabled-per-sensor conflict, kill switch by an approver, sensor fallback and
ack of the disable version, lazy expiry, audit trail (`ips.expire` by `system:ips`).
Totals: shared 95, API 82, web 4, pytest 4; e2e 4/4 (new blue-team test: NIPS page shows
inline prevention disabled, detect-only reason, no sensor → no proposal form).

**Not delivered yet**

A sensor-side agent that applies the directive (Suricata config/NFQUEUE management), bypass/
fail-open hardware checks, policy diff/preview, automatic disable on sensor health degradation
while enabled (currently health is gated at enable time and TTL bounds exposure).
