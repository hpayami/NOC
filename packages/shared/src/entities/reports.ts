import { z } from 'zod';
import { Timestamp } from '../common';

/**
 * Why a section carries no figures. `withheld` = the reader lacks the permission that governs
 * the underlying data; `not_configured` = the platform holds nothing of that kind yet;
 * `unavailable` = a dependency (sensor, service) could not answer.
 */
export const SectionState = z.enum(['available', 'withheld', 'not_configured', 'unavailable']);
export type SectionState = z.infer<typeof SectionState>;

const Counts = z.record(z.string(), z.number().int().nonnegative());

const section = <T extends z.ZodRawShape>(shape: T) =>
  z.strictObject({
    state: SectionState,
    /** Permission that governs the section; named so a withheld section is explainable. */
    permission: z.string().max(64),
    note: z.string().max(512).nullable(),
    data: z.strictObject(shape).nullable(),
  });

export const ReportPeriodQuery = z.strictObject({
  /** Days back from now; bounded so a report never scans unbounded history. */
  days: z.coerce.number().int().min(1).max(365).default(30),
  format: z.enum(['json', 'markdown']).default('json'),
});
export type ReportPeriodQuery = z.infer<typeof ReportPeriodQuery>;

export const PostureReport = z.strictObject({
  generatedAt: Timestamp,
  generatedBy: z.string().max(256),
  period: z.strictObject({ from: Timestamp, to: Timestamp, days: z.number().int().positive() }),
  /** null = unrestricted; otherwise the site keys the report is limited to. */
  sites: z.array(z.string().max(64)).nullable(),
  assets: section({
    total: z.number().int().nonnegative(),
    byCoverage: Counts,
    byCriticality: Counts,
    seenInPeriod: z.number().int().nonnegative(),
  }),
  sensors: section({
    total: z.number().int().nonnegative(),
    enabled: z.number().int().nonnegative(),
    heartbeating: z.number().int().nonnegative(),
    silent: z.number().int().nonnegative(),
    byKind: Counts,
    inlineCapable: z.number().int().nonnegative(),
  }),
  events: section({
    total: z.number().int().nonnegative(),
    byCategory: Counts,
    bySeverity: Counts,
    sensorsReporting: z.number().int().nonnegative(),
  }),
  alerts: section({
    opened: z.number().int().nonnegative(),
    bySeverity: Counts,
    byStatus: Counts,
    openAtEnd: z.number().int().nonnegative(),
    closedInPeriod: z.number().int().nonnegative(),
    falsePositives: z.number().int().nonnegative(),
    /** Acknowledgement time is not tracked per alert; stated rather than estimated. */
    meanTimeToAcknowledgeSeconds: z.number().nullable(),
  }),
  incidents: section({
    opened: z.number().int().nonnegative(),
    closed: z.number().int().nonnegative(),
    openAtEnd: z.number().int().nonnegative(),
    bySeverity: Counts,
    byStatus: Counts,
    /** Mean opened→closed for incidents closed in the period; null when none closed. */
    meanTimeToCloseSeconds: z.number().nullable(),
    medianTimeToCloseSeconds: z.number().nullable(),
  }),
  response: section({
    proposed: z.number().int().nonnegative(),
    byStatus: Counts,
    executed: z.number().int().nonnegative(),
    rolledBack: z.number().int().nonnegative(),
    rejected: z.number().int().nonnegative(),
  }),
  prevention: section({
    policiesTotal: z.number().int().nonnegative(),
    byStatus: Counts,
    enabledNow: z.number().int().nonnegative(),
    enabledInPeriod: z.number().int().nonnegative(),
    autoDisabledInPeriod: z.number().int().nonnegative(),
    sensorsInline: z.number().int().nonnegative(),
  }),
  assessments: section({
    engagementsTotal: z.number().int().nonnegative(),
    byStatus: Counts,
    runsInPeriod: z.number().int().nonnegative(),
    runsByStatus: Counts,
  }),
  findings: section({
    open: z.number().int().nonnegative(),
    bySeverity: Counts,
    newInPeriod: z.number().int().nonnegative(),
    closedInPeriod: z.number().int().nonnegative(),
    knownExploitedOpen: z.number().int().nonnegative(),
    cveReferenced: z.number().int().nonnegative(),
    cveCatalogued: z.number().int().nonnegative(),
  }),
  threatIntel: section({
    activeIndicators: z.number().int().nonnegative(),
    sources: z.number().int().nonnegative(),
    matchesInPeriod: z.number().int().nonnegative(),
    matchesByType: Counts,
    lastImportAt: Timestamp.nullable(),
  }),
  analytics: section({
    scoringsInPeriod: z.number().int().nonnegative(),
    highScores: z.number().int().nonnegative(),
    serviceReachable: z.boolean(),
  }),
  governance: section({
    auditEventsInPeriod: z.number().int().nonnegative(),
    denied: z.number().int().nonnegative(),
    failures: z.number().int().nonnegative(),
    chainVerified: z.boolean().nullable(),
    logins: z.number().int().nonnegative(),
    loginFailures: z.number().int().nonnegative(),
  }),
  limitations: z.array(z.string().max(512)).max(32),
});
export type PostureReport = z.infer<typeof PostureReport>;
