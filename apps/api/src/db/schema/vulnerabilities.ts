import { boolean, index, pgTable, real, text, timestamp } from 'drizzle-orm/pg-core';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

/** Imported vulnerability catalogue (NVD 2.0, CISA KEV, native). Findings reference it by CVE id. */
export const vulnerabilityCatalog = pgTable(
  'vulnerability_catalog',
  {
    cveId: text('cve_id').primaryKey(),
    summary: text('summary').notNull().default(''),
    cvssBaseScore: real('cvss_base_score'),
    cvssVector: text('cvss_vector'),
    cvssVersion: text('cvss_version'),
    cwe: text('cwe').array().notNull().default([]),
    publishedAt: ts('published_at'),
    lastModifiedAt: ts('last_modified_at'),
    knownExploited: boolean('known_exploited').notNull().default(false),
    kevAddedAt: ts('kev_added_at'),
    kevDueAt: ts('kev_due_at'),
    sources: text('sources').array().notNull().default([]),
    importedAt: ts('imported_at').notNull().defaultNow(),
  },
  (t) => [
    index('vuln_catalog_kev_idx').on(t.knownExploited),
    index('vuln_catalog_imported_idx').on(t.importedAt),
  ],
);
