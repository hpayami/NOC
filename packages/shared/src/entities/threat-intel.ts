import { z } from 'zod';
import { Id, ShortText, Timestamp } from '../common';
import { Severity, type Confidence } from '../enums';

export const IndicatorTypeValues = [
  'ipv4',
  'ipv6',
  'cidr',
  'domain',
  'url',
  'sha256',
  'sha1',
  'md5',
] as const;
export const IndicatorType = z.enum(IndicatorTypeValues);
export type IndicatorType = z.infer<typeof IndicatorType>;

export const IndicatorFeedFormatValues = ['noc', 'csv', 'stix2'] as const;
export const IndicatorFeedFormat = z.enum(IndicatorFeedFormatValues);
export type IndicatorFeedFormat = z.infer<typeof IndicatorFeedFormat>;

/** Where in an event an indicator was seen. Only fields the normalisers keep are matchable. */
export const MatchedFieldValues = [
  'src_ip',
  'dst_ip',
  'dns.query',
  'tls.sni',
  'http.hostname',
  'http.url',
  'file.sha256',
  'file.sha1',
  'file.md5',
] as const;
export const MatchedField = z.enum(MatchedFieldValues);
export type MatchedField = z.infer<typeof MatchedField>;

export const IndicatorRecord = z.strictObject({
  id: Id,
  type: IndicatorType,
  value: z.string().min(1).max(2048),
  source: ShortText,
  /** 0–100 as feeds express it; mapped to the platform confidence scale for alerts. */
  confidence: z.number().int().min(0).max(100),
  severity: Severity,
  tags: z.array(z.string().max(64)).max(32),
  description: z.string().max(1024).nullable(),
  expiresAt: Timestamp.nullable(),
  revoked: z.boolean(),
  importedAt: Timestamp,
  updatedAt: Timestamp,
  matchCount: z.number().int().nonnegative(),
  lastMatchedAt: Timestamp.nullable(),
});
export type IndicatorRecord = z.infer<typeof IndicatorRecord>;

export const ImportIndicatorsRequest = z.strictObject({
  format: IndicatorFeedFormat,
  /** Feed label stored on every indicator; STIX bundles may override it per object via `created_by_ref` names. */
  source: ShortText,
  content: z
    .string()
    .min(1)
    .max(8 * 1024 * 1024),
  /** Used when the feed carries no severity for an indicator. */
  defaultSeverity: Severity.default('medium'),
});
export type ImportIndicatorsRequest = z.infer<typeof ImportIndicatorsRequest>;

export const ImportIndicatorsResponse = z.strictObject({
  parsed: z.number().int().nonnegative(),
  imported: z.number().int().nonnegative(),
  updated: z.number().int().nonnegative(),
  unchanged: z.number().int().nonnegative(),
  revoked: z.number().int().nonnegative(),
  /** Matches found by re-reading recent events with the new indicators (bounded window). */
  retroMatches: z.number().int().nonnegative(),
  retroWindowHours: z.number().int().nonnegative(),
  errors: z.array(z.string().max(256)).max(20),
  errorCount: z.number().int().nonnegative(),
});
export type ImportIndicatorsResponse = z.infer<typeof ImportIndicatorsResponse>;

export const IndicatorListQuery = z.strictObject({
  type: IndicatorType.optional(),
  source: z.string().max(256).optional(),
  q: z.string().max(256).optional(),
  includeInactive: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
});
export type IndicatorListQuery = z.infer<typeof IndicatorListQuery>;

export const IndicatorMatch = z.strictObject({
  id: Id,
  indicatorId: Id,
  type: IndicatorType,
  value: z.string().max(2048),
  source: ShortText,
  severity: Severity,
  eventId: Id,
  alertId: Id.nullable(),
  assetId: Id.nullable(),
  sensorId: Id.nullable(),
  matchedField: MatchedField,
  matchedValue: z.string().max(2048),
  observedAt: Timestamp,
});
export type IndicatorMatch = z.infer<typeof IndicatorMatch>;

export const ThreatIntelStats = z.strictObject({
  total: z.number().int().nonnegative(),
  active: z.number().int().nonnegative(),
  expired: z.number().int().nonnegative(),
  revoked: z.number().int().nonnegative(),
  byType: z.record(z.string(), z.number().int().nonnegative()),
  sources: z
    .array(
      z.strictObject({
        source: ShortText,
        active: z.number().int().nonnegative(),
        lastImportAt: Timestamp,
      }),
    )
    .max(100),
  lastImportAt: Timestamp.nullable(),
  matches24h: z.number().int().nonnegative(),
  lastMatchAt: Timestamp.nullable(),
});
export type ThreatIntelStats = z.infer<typeof ThreatIntelStats>;

/** Feed confidence (0–100) on the platform scale used for alert priority. */
export const indicatorConfidence = (c: number): Confidence =>
  c >= 75 ? 'high' : c >= 40 ? 'medium' : 'low';
