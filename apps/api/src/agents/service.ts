import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { and, eq, isNull, sql } from 'drizzle-orm';
import { HTTPException } from 'hono/http-exception';
import type {
  AgentEnrolRequest,
  AgentInventory,
  NeighborBatch,
  NeighborBatchResult,
  SensorHeartbeatRequest,
} from '@noc/shared';
import type { AssetService, IngestActor } from '../assets/service';
import type { AuditService } from '../audit/service';
import type { Db } from '../db/client';
import { assetInterfaces, assetServices, assets, sensorHealth, sensors } from '../db/schema';
import type { SensorPrincipal } from '../middleware/context';

export const ENROLMENT_TOKEN_TTL_SECONDS = 24 * 3600;
export const AGENT_HEARTBEAT_INTERVAL_SECONDS = 60;

export const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
export function hashesMatch(storedHex: string | null, presented: string): boolean {
  if (!storedHex) return false;
  const a = Buffer.from(storedHex, 'hex');
  const b = Buffer.from(sha256(presented), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

const isLoopback = (ip: string) => ip.startsWith('127.') || ip === '::1';
const ZERO_MAC = '00:00:00:00:00:00';

export class AgentService {
  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    private readonly assetsSvc: AssetService,
  ) {}

  /** Operator action: mint a single-use enrolment token for an existing sensor (any previous token is invalidated). */
  async createEnrolmentToken(sensorId: string, actor: IngestActor) {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + ENROLMENT_TOKEN_TTL_SECONDS * 1000);
    return this.db.transaction(async (tx) => {
      const [s] = await tx
        .update(sensors)
        .set({ enrolmentTokenHash: sha256(token), enrolmentExpiresAt: expiresAt })
        .where(eq(sensors.id, sensorId))
        .returning({ id: sensors.id });
      if (!s) throw new HTTPException(404, { message: 'Sensor not found' });
      await this.audit.record(
        {
          actorId: actor.userId,
          actorLabel: actor.label,
          action: 'sensors.enrolment_token',
          outcome: 'success',
          targetType: 'sensor',
          targetId: sensorId,
          requestId: actor.requestId,
          sourceIp: actor.ip,
          metadata: { expiresAt: expiresAt.toISOString() },
        },
        tx,
      );
      return { sensorId, token, expiresAt: expiresAt.toISOString() };
    });
  }

  /** Agent action: exchange the enrolment token for a long-lived credential (hash stored, token burned). */
  async enrol(input: AgentEnrolRequest, ip: string | null, requestId: string | null) {
    const [sensor] = await this.db
      .select()
      .from(sensors)
      .where(sql`${sensors.enrolmentTokenHash} = ${sha256(input.enrolmentToken)}`)
      .limit(1);
    const deny = async (reason: string, sensorId: string | null = null) => {
      await this.audit.record({
        actorId: null,
        actorLabel: `agent:${input.hostname}`,
        action: 'agents.enrol',
        outcome: 'denied',
        targetType: 'sensor',
        targetId: sensorId,
        requestId,
        sourceIp: ip,
        metadata: { reason },
      });
      throw new HTTPException(401, { message: 'Enrolment rejected' });
    };
    if (!sensor) return deny('unknown_token');
    if (!sensor.enabled) return deny('sensor_disabled', sensor.id);
    if (!sensor.enrolmentExpiresAt || sensor.enrolmentExpiresAt.getTime() <= Date.now())
      return deny('token_expired', sensor.id);
    const credential = `${sensor.id}.${randomBytes(32).toString('base64url')}`;
    await this.db.transaction(async (tx) => {
      await tx
        .update(sensors)
        .set({
          credentialHash: sha256(credential),
          enrolmentTokenHash: null,
          enrolmentExpiresAt: null,
          enrolledAt: new Date(),
          engineVersion: input.agentVersion,
          lastHeartbeatAt: new Date(),
        })
        .where(eq(sensors.id, sensor.id));
      await this.audit.record(
        {
          actorId: null,
          actorLabel: `agent:${input.hostname}`,
          action: 'agents.enrol',
          outcome: 'success',
          targetType: 'sensor',
          targetId: sensor.id,
          requestId,
          sourceIp: ip,
          metadata: {
            hostname: input.hostname,
            platform: input.platform,
            agentVersion: input.agentVersion,
          },
        },
        tx,
      );
    });
    return {
      sensorId: sensor.id,
      credential,
      heartbeatIntervalSeconds: AGENT_HEARTBEAT_INTERVAL_SECONDS,
    };
  }

  async heartbeat(sensor: SensorPrincipal, body: SensorHeartbeatRequest): Promise<void> {
    const now = new Date();
    await this.db.transaction(async (tx) => {
      await tx.insert(sensorHealth).values({
        sensorId: sensor.sensorId,
        recordedAt: now,
        state: body.state,
        heartbeatAgeSeconds: 0,
        eventLagSeconds: body.eventLagSeconds,
        packetsCaptured: body.packetsCaptured,
        packetsDropped: body.packetsDropped,
        cpuPercent: body.cpuPercent,
        memoryPercent: body.memoryPercent,
        detail: body.detail,
      });
      await tx
        .update(sensors)
        .set({
          lastHeartbeatAt: now,
          engineVersion: body.engineVersion ?? sql`${sensors.engineVersion}`,
          inlineCapable: body.inlineCapable,
          ...(body.rulesBundleSha256
            ? { rulesBundleSha256: body.rulesBundleSha256, rulesBundleAppliedAt: now }
            : {}),
        })
        .where(eq(sensors.id, sensor.sensorId));
    });
  }

  /** Full inventory → observation (agent id is the identity anchor) + interfaces + listening services. */
  async applyInventory(
    sensor: SensorPrincipal,
    inv: AgentInventory,
    ip: string | null,
    requestId: string | null,
  ) {
    const macs = [
      ...new Set(
        inv.interfaces.map((i) => i.macAddress).filter((m): m is string => !!m && m !== ZERO_MAC),
      ),
    ];
    const ips = [
      ...new Set(inv.interfaces.flatMap((i) => i.addresses).filter((a) => !isLoopback(a))),
    ];
    const actor: IngestActor = { userId: null, label: `agent:${sensor.name}`, requestId, ip };
    const ingest = await this.assetsSvc.ingest(
      {
        source: `agent:${sensor.sensorId}`,
        method: 'endpoint_agent',
        observedAt: inv.observedAt,
        identifiers: {
          macAddresses: macs,
          ipAddresses: ips,
          hostnames: [inv.hostname],
          agentId: sensor.sensorId,
        },
        attributes: {
          osName: inv.platform.os,
          osVersion: inv.platform.osVersion,
          cpuArchitecture: inv.platform.arch,
          manufacturer: inv.hardware.manufacturer,
          model: inv.hardware.model,
          serialNumber: inv.hardware.serialNumber,
          ramMb: inv.hardware.ramMb,
          'agent.kernel': inv.platform.kernel,
          'agent.cpuModel': inv.hardware.cpuModel,
          'agent.cpuCores': inv.hardware.cpuCores,
          'agent.diskCount': inv.hardware.disks.length,
          'agent.diskTotalGb': Math.round(inv.hardware.disks.reduce((a, d) => a + d.sizeGb, 0)),
          'agent.bootTime': inv.bootTime,
          'agent.version': inv.agentVersion,
        },
      },
      actor,
    );
    if (!ingest.assetId) return { assetId: null, decision: ingest.decision.action, services: 0 };
    const assetId = ingest.assetId;
    const observedAt = new Date(inv.observedAt);
    const source = `agent:${sensor.sensorId}`;

    await this.db.transaction(async (tx) => {
      const existing = await tx
        .select()
        .from(assetInterfaces)
        .where(eq(assetInterfaces.assetId, assetId));
      for (const i of inv.interfaces) {
        if (i.addresses.every(isLoopback) && !i.macAddress) continue;
        const mac = i.macAddress && i.macAddress !== ZERO_MAC ? i.macAddress : null;
        const row =
          existing.find((e) => e.name === i.name) ??
          (mac ? existing.find((e) => e.macAddress?.toLowerCase() === mac) : undefined);
        const values = {
          name: i.name,
          macAddress: mac,
          ipAddresses: i.addresses,
          speedMbps: i.speedMbps,
          operState: i.operState,
          adminState: i.operState === 'up' ? 'up' : 'unknown',
        };
        if (row) await tx.update(assetInterfaces).set(values).where(eq(assetInterfaces.id, row.id));
        else await tx.insert(assetInterfaces).values({ assetId, ...values });
      }
      // Services: replace this source's view atomically, preserving first-seen for ones still present.
      const current = await tx
        .select()
        .from(assetServices)
        .where(and(eq(assetServices.assetId, assetId), eq(assetServices.source, source)));
      const key = (s: { proto: string; port: number; address: string | null }) =>
        `${s.proto}:${s.port}:${s.address ?? '*'}`;
      const firstSeen = new Map(current.map((s) => [key(s), s.firstSeenAt]));
      await tx
        .delete(assetServices)
        .where(and(eq(assetServices.assetId, assetId), eq(assetServices.source, source)));
      if (inv.listeningServices.length) {
        const seen = new Set<string>();
        const rows = inv.listeningServices
          .filter((s) => (seen.has(key(s)) ? false : seen.add(key(s))))
          .map((s) => ({
            assetId,
            proto: s.proto,
            port: s.port,
            address: s.address,
            process: s.process,
            source,
            firstSeenAt: firstSeen.get(key(s)) ?? observedAt,
            lastSeenAt: observedAt,
          }));
        await tx.insert(assetServices).values(rows);
      }
      await tx
        .update(sensors)
        .set({ hostAssetId: assetId, lastHeartbeatAt: new Date() })
        .where(and(eq(sensors.id, sensor.sensorId), isNull(sensors.hostAssetId)));
      await tx
        .update(sensors)
        .set({ lastHeartbeatAt: new Date() })
        .where(eq(sensors.id, sensor.sensorId));
      // An agent-reported host is at least partially covered (inventory + health), not security-monitored.
      await tx
        .update(assets)
        .set({
          monitoringCoverage: sql`(case when ${assets.monitoringCoverage} = 'monitored' then 'monitored' else 'partial' end)::coverage_state`,
          updatedAt: new Date(),
        })
        .where(eq(assets.id, assetId));
    });
    return { assetId, decision: ingest.decision.action, services: inv.listeningServices.length };
  }

  /** Passive neighbour batches (ARP/NDP/DHCP) from agents or collectors → one observation per entry. */
  async applyNeighbors(
    batch: NeighborBatch,
    sourceLabel: string,
    actor: IngestActor,
  ): Promise<NeighborBatchResult> {
    const result: NeighborBatchResult = {
      received: batch.entries.length,
      created: 0,
      matched: 0,
      ambiguous: 0,
      skipped: 0,
    };
    for (const e of batch.entries) {
      if (isLoopback(e.ip) || (!e.mac && !e.hostname)) {
        result.skipped++;
        continue;
      }
      const r = await this.assetsSvc.ingest(
        {
          source: sourceLabel,
          method: e.source === 'dhcp' ? 'dhcp_lease' : 'arp_neighbor',
          observedAt: e.observedAt,
          identifiers: {
            macAddresses: e.mac ? [e.mac] : [],
            ipAddresses: [e.ip],
            hostnames: e.hostname ? [e.hostname] : [],
          },
          attributes: {
            'neighbor.interface': e.interface,
            'neighbor.vlanId': e.vlanId,
            'neighbor.source': e.source,
          },
        },
        actor,
      );
      if (r.decision.action === 'create') result.created++;
      else if (r.decision.action === 'match') result.matched++;
      else result.ambiguous++;
    }
    return result;
  }
}
