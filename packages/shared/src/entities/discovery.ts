import { z } from 'zod';
import { Id, IpAddress, Port, ShortText, Timestamp } from '../common';
import { DiscoveryJobStatus } from '../enums';
import { AuthorizedTargetScope } from './governance';

export const DEFAULT_DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 8080] as const;

export const DiscoveryJobSummary = z.strictObject({
  allowed: z.number().int().nonnegative(),
  denied: z.number().int().nonnegative(),
  reachable: z.number().int().nonnegative(),
  unreachable: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
  observationsCreated: z.number().int().nonnegative(),
});
export type DiscoveryJobSummary = z.infer<typeof DiscoveryJobSummary>;

export const DiscoveryJob = z.strictObject({
  id: Id,
  name: ShortText,
  status: DiscoveryJobStatus,
  /** Dry runs evaluate scope decisions per target and send nothing. Default for new jobs. */
  dryRun: z.boolean(),
  scope: AuthorizedTargetScope,
  ports: z.array(Port).max(16),
  requestedBy: Id,
  approvedBy: Id.nullable(),
  approvalNote: z.string().max(2048).nullable(),
  targetCount: z.number().int().nonnegative(),
  startedAt: Timestamp.nullable(),
  finishedAt: Timestamp.nullable(),
  summary: DiscoveryJobSummary.nullable(),
  createdAt: Timestamp,
});
export type DiscoveryJob = z.infer<typeof DiscoveryJob>;

export const CreateDiscoveryJobRequest = z.strictObject({
  name: ShortText,
  dryRun: z.boolean().default(true),
  scope: AuthorizedTargetScope,
  ports: z
    .array(Port)
    .min(1)
    .max(16)
    .default([...DEFAULT_DISCOVERY_PORTS]),
});
export type CreateDiscoveryJobRequest = z.infer<typeof CreateDiscoveryJobRequest>;

export const DiscoveryDecisionRequest = z.strictObject({
  decision: z.enum(['approved', 'rejected']),
  note: z.string().trim().min(10).max(2048),
});
export type DiscoveryDecisionRequest = z.infer<typeof DiscoveryDecisionRequest>;

export const DiscoveryJobTarget = z.strictObject({
  target: IpAddress,
  decision: z.enum(['pending', 'allowed', 'denied']),
  reasons: z.array(z.string().max(256)).max(16),
  outcome: z.enum(['pending', 'reachable', 'unreachable', 'skipped']),
  openPorts: z.array(Port).max(16),
  observedAt: Timestamp.nullable(),
});
export type DiscoveryJobTarget = z.infer<typeof DiscoveryJobTarget>;

export const DiscoveryJobDetail = z.strictObject({
  job: DiscoveryJob,
  targets: z.array(DiscoveryJobTarget),
});
export type DiscoveryJobDetail = z.infer<typeof DiscoveryJobDetail>;
