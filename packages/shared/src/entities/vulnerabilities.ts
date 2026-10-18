import { z } from 'zod';
import { Timestamp } from '../common';

export const CveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/);

/** One catalogue entry. Every field is what the imported feed said; nothing is derived. */
export const VulnerabilityRecord = z.strictObject({
  cveId: CveId,
  summary: z.string().max(4096),
  cvssBaseScore: z.number().min(0).max(10).nullable(),
  cvssVector: z.string().max(256).nullable(),
  cvssVersion: z.string().max(8).nullable(),
  cwe: z.array(z.string().max(16)).max(16),
  publishedAt: Timestamp.nullable(),
  lastModifiedAt: Timestamp.nullable(),
  /** From CISA KEV (or an equivalent feed): exploitation observed in the wild. */
  knownExploited: z.boolean(),
  kevAddedAt: Timestamp.nullable(),
  kevDueAt: Timestamp.nullable(),
  /** Feeds that contributed, e.g. `nvd_2`, `cisa_kev`, `noc`. */
  sources: z.array(z.string().max(32)).max(8),
  importedAt: Timestamp,
});
export type VulnerabilityRecord = z.infer<typeof VulnerabilityRecord>;

export const VulnerabilityFeedFormatValues = ['noc', 'nvd_2', 'cisa_kev'] as const;
export const VulnerabilityFeedFormat = z.enum(VulnerabilityFeedFormatValues);
export type VulnerabilityFeedFormat = z.infer<typeof VulnerabilityFeedFormat>;

export const VULN_IMPORT_MAX_BYTES = 8 * 1024 * 1024;

export const ImportVulnerabilitiesRequest = z.strictObject({
  format: VulnerabilityFeedFormat,
  /** The feed document as text (JSON). Bounded; large feeds are imported in slices. */
  content: z.string().min(2).max(VULN_IMPORT_MAX_BYTES),
});
export type ImportVulnerabilitiesRequest = z.infer<typeof ImportVulnerabilitiesRequest>;

export const ImportVulnerabilitiesResponse = z.strictObject({
  parsed: z.number().int().nonnegative(),
  imported: z.number().int().nonnegative(),
  updated: z.number().int().nonnegative(),
  unchanged: z.number().int().nonnegative(),
  /** Findings whose CVSS was filled in from the catalogue by this import. */
  findingsEnriched: z.number().int().nonnegative(),
  errors: z.array(z.string().max(256)).max(20),
  errorCount: z.number().int().nonnegative(),
});
export type ImportVulnerabilitiesResponse = z.infer<typeof ImportVulnerabilitiesResponse>;

export const VulnerabilityListQuery = z.strictObject({
  q: z.string().trim().max(128).optional(),
  knownExploited: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

export const VulnerabilityCatalogStats = z.strictObject({
  total: z.number().int().nonnegative(),
  knownExploited: z.number().int().nonnegative(),
  withCvss: z.number().int().nonnegative(),
  lastImportAt: Timestamp.nullable(),
});
export type VulnerabilityCatalogStats = z.infer<typeof VulnerabilityCatalogStats>;
