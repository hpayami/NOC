import { z } from 'zod';
import { Id, ShortText, Timestamp } from '../common';
import { SensorHealthState, SensorKind, SensorMode } from '../enums';

export const Sensor = z.strictObject({
  id: Id,
  name: ShortText,
  kind: SensorKind,
  mode: SensorMode,
  hostAssetId: Id.nullable(),
  site: ShortText.nullable(),
  monitoredSegmentIds: z.array(Id),
  engineVersion: z.string().max(64).nullable(),
  ruleSetVersion: z.string().max(128).nullable(),
  enabled: z.boolean(),
  /** Reported by the sensor itself; never assumed. */
  inlineCapable: z.boolean(),
  registeredAt: Timestamp,
  lastHeartbeatAt: Timestamp.nullable(),
});
export type Sensor = z.infer<typeof Sensor>;

export const SensorHealth = z.strictObject({
  sensorId: Id,
  recordedAt: Timestamp,
  state: SensorHealthState,
  heartbeatAgeSeconds: z.number().nonnegative().nullable(),
  eventLagSeconds: z.number().nonnegative().nullable(),
  /** Counters are null when the engine does not expose them — never fabricated as zero. */
  packetsCaptured: z.number().int().nonnegative().nullable(),
  packetsDropped: z.number().int().nonnegative().nullable(),
  cpuPercent: z.number().min(0).max(100).nullable(),
  memoryPercent: z.number().min(0).max(100).nullable(),
  detail: z.string().max(512).nullable(),
});
export type SensorHealth = z.infer<typeof SensorHealth>;
