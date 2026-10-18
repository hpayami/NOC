import { z } from 'zod';
import { Id, IpAddress, LongText, Port, ShortText, Timestamp } from '../common';
import {
  CheckKind,
  CheckOutcome,
  OperationalStatus,
  SensorHealthState,
  SensorKind,
  SensorMode,
} from '../enums';
import { Sensor, SensorHealth } from './sensors';

export const MonitoringCheck = z.strictObject({
  id: Id,
  assetId: Id,
  kind: CheckKind,
  target: IpAddress,
  port: Port.nullable(),
  intervalSeconds: z.number().int().min(30).max(86_400),
  timeoutMs: z.number().int().min(200).max(10_000),
  enabled: z.boolean(),
  /** null = executed by the management plane; otherwise the collector that reports results. */
  collectorId: Id.nullable(),
  lastRunAt: Timestamp.nullable(),
  createdAt: Timestamp,
});
export type MonitoringCheck = z.infer<typeof MonitoringCheck>;

export const CreateCheckRequest = MonitoringCheck.pick({
  assetId: true,
  kind: true,
  target: true,
  port: true,
})
  .extend({
    intervalSeconds: z.number().int().min(30).max(86_400).default(60),
    timeoutMs: z.number().int().min(200).max(10_000).default(2000),
    collectorId: Id.nullable().default(null),
  })
  .refine((c) => c.kind === 'icmp' || c.port !== null, {
    message: 'tcp/http checks require a port',
  });
export type CreateCheckRequest = z.infer<typeof CreateCheckRequest>;

export const CheckResult = z.strictObject({
  id: z.number().int().nonnegative(),
  checkId: Id,
  observedAt: Timestamp,
  outcome: CheckOutcome,
  latencyMs: z.number().int().nonnegative().nullable(),
  detail: z.string().max(512).nullable(),
  /** Collector state when the result was recorded; 'platform' for platform-run checks. */
  collectorState: z.union([z.literal('platform'), SensorHealthState]),
});
export type CheckResult = z.infer<typeof CheckResult>;

export const ReportCheckResultRequest = z.strictObject({
  observedAt: Timestamp,
  outcome: CheckOutcome,
  latencyMs: z.number().int().nonnegative().nullable().default(null),
  detail: z.string().max(512).nullable().default(null),
});
export type ReportCheckResultRequest = z.infer<typeof ReportCheckResultRequest>;

export const MaintenanceWindow = z.strictObject({
  id: Id,
  assetId: Id.nullable(),
  segmentId: Id.nullable(),
  startsAt: Timestamp,
  endsAt: Timestamp,
  reason: LongText,
  createdBy: Id.nullable(),
  createdAt: Timestamp,
});
export type MaintenanceWindow = z.infer<typeof MaintenanceWindow>;

export const CreateMaintenanceWindowRequest = MaintenanceWindow.pick({
  assetId: true,
  segmentId: true,
  startsAt: true,
  endsAt: true,
  reason: true,
}).refine((w) => (w.assetId !== null) !== (w.segmentId !== null), {
  message: 'exactly one of assetId or segmentId is required',
});
export type CreateMaintenanceWindowRequest = z.infer<typeof CreateMaintenanceWindowRequest>;

export const MetricPoint = z.strictObject({
  metric: z.string().regex(/^[a-z][a-z0-9_.]{1,63}$/),
  observedAt: Timestamp,
  value: z.number().finite(),
  unit: z.string().max(16).nullable(),
});
export type MetricPoint = z.infer<typeof MetricPoint>;

export const IngestMetricsRequest = z.strictObject({
  source: ShortText,
  points: z.array(MetricPoint).min(1).max(500),
});
export type IngestMetricsRequest = z.infer<typeof IngestMetricsRequest>;

/** Bounded range query: at most 7 days and 5 000 points. */
export const MetricsQuery = z.strictObject({
  metric: z.string().regex(/^[a-z][a-z0-9_.]{1,63}$/),
  from: Timestamp,
  to: Timestamp,
  limit: z.coerce.number().int().min(1).max(5000).default(1000),
});
export type MetricsQuery = z.infer<typeof MetricsQuery>;

export const RegisterSensorRequest = Sensor.pick({
  name: true,
  kind: true,
  site: true,
  monitoredSegmentIds: true,
  engineVersion: true,
}).extend({
  /** Inline prevention can never be chosen at registration; it requires the Phase 4 approval flow. */
  mode: SensorMode.exclude(['inline_prevention']).default('out_of_band'),
});
export type RegisterSensorRequest = z.infer<typeof RegisterSensorRequest>;

export const SensorHeartbeatRequest = z.strictObject({
  state: SensorHealthState.exclude(['silent', 'unknown']),
  eventLagSeconds: z.number().int().nonnegative().nullable().default(null),
  packetsCaptured: z.number().int().nonnegative().nullable().default(null),
  packetsDropped: z.number().int().nonnegative().nullable().default(null),
  cpuPercent: z.number().min(0).max(100).nullable().default(null),
  memoryPercent: z.number().min(0).max(100).nullable().default(null),
  detail: z.string().max(512).nullable().default(null),
  engineVersion: z.string().max(64).nullable().default(null),
  ruleSetVersion: z.string().max(128).nullable().default(null),
});
export type SensorHeartbeatRequest = z.infer<typeof SensorHeartbeatRequest>;

export const SensorStatus = z.strictObject({
  sensor: Sensor,
  derivedState: SensorHealthState,
  heartbeatAgeSeconds: z.number().nonnegative().nullable(),
  latest: SensorHealth.nullable(),
});
export type SensorStatus = z.infer<typeof SensorStatus>;

export const MonitoringOverview = z.strictObject({
  assetsByStatus: z.record(OperationalStatus, z.number().int().nonnegative()),
  checks: z.strictObject({
    total: z.number().int().nonnegative(),
    enabled: z.number().int().nonnegative(),
    platformRun: z.number().int().nonnegative(),
  }),
  sensors: z.array(SensorStatus),
  activeMaintenanceWindows: z.array(MaintenanceWindow),
  recentResults: z.array(CheckResult.extend({ assetId: Id, target: IpAddress, kind: CheckKind })),
  generatedAt: Timestamp,
});
export type MonitoringOverview = z.infer<typeof MonitoringOverview>;

export { SensorKind };
