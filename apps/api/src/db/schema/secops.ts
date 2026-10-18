import { sql } from 'drizzle-orm';
import {
  boolean,
  index,
  inet,
  integer,
  jsonb,
  pgTable,
  real,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets';
import {
  alertStatusEnum,
  confidenceEnum,
  eventCategoryEnum,
  eventSourceProductEnum,
  findingStatusEnum,
  incidentStatusEnum,
  incidentTypeEnum,
  ruleLifecycleEnum,
  ruleSourceEnum,
  severityEnum,
} from './enums';
import { users } from './identity';
import { sensors } from './sensors';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const detectionRules = pgTable(
  'detection_rules',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    source: ruleSourceEnum('source').notNull(),
    externalId: text('external_id').notNull(),
    revision: integer('revision').notNull().default(1),
    name: text('name').notNull(),
    lifecycle: ruleLifecycleEnum('lifecycle').notNull().default('draft'),
    severity: severityEnum('severity').notNull().default('medium'),
    attackTechniques: text('attack_techniques').array().notNull().default([]),
    license: text('license'),
    contentSha256: text('content_sha256').notNull(),
    validatedAt: ts('validated_at'),
    deployedAt: ts('deployed_at'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('detection_rules_source_ext_rev_idx').on(t.source, t.externalId, t.revision),
    index('detection_rules_lifecycle_idx').on(t.lifecycle),
  ],
);

/**
 * Lower-volume event metadata. High-volume telemetry belongs in the event-store adapter backend;
 * this table never holds raw packet payloads.
 */
export const securityEvents = pgTable(
  'security_events',
  {
    id: uuid('id').primaryKey(),
    schemaVersion: text('schema_version').notNull(),
    eventTime: ts('event_time').notNull(),
    ingestTime: ts('ingest_time').notNull().defaultNow(),
    sourceProduct: eventSourceProductEnum('source_product').notNull(),
    sourceSensorId: uuid('source_sensor_id').references(() => sensors.id, { onDelete: 'set null' }),
    category: eventCategoryEnum('category').notNull(),
    type: text('type').notNull(),
    severity: severityEnum('severity').notNull(),
    confidence: confidenceEnum('confidence').notNull().default('unknown'),
    srcAssetId: uuid('src_asset_id').references(() => assets.id, { onDelete: 'set null' }),
    dstAssetId: uuid('dst_asset_id').references(() => assets.id, { onDelete: 'set null' }),
    srcIp: inet('src_ip'),
    dstIp: inet('dst_ip'),
    srcPort: integer('src_port'),
    dstPort: integer('dst_port'),
    protocol: text('protocol'),
    ruleId: text('rule_id'),
    threatClassification: text('threat_classification').array().notNull().default([]),
    incidentId: uuid('incident_id'),
    correlationIds: text('correlation_ids').array().notNull().default([]),
    evidenceRefs: jsonb('evidence_refs').$type<unknown[]>().notNull().default([]),
    originalRef: jsonb('original_ref').$type<Record<string, unknown> | null>(),
    engine: jsonb('engine').$type<Record<string, unknown>>().notNull().default({}),
    /** Deduplication key: sha256 over (source, sensor, event_time, tuple, rule). */
    dedupHash: text('dedup_hash').notNull(),
  },
  (t) => [
    uniqueIndex('security_events_dedup_idx').on(t.dedupHash),
    index('security_events_time_source_idx').on(t.eventTime, t.sourceProduct),
    index('security_events_sensor_time_idx').on(t.sourceSensorId, t.eventTime),
    index('security_events_src_ip_time_idx').on(t.srcIp, t.eventTime),
    index('security_events_dst_ip_time_idx').on(t.dstIp, t.eventTime),
    index('security_events_src_asset_time_idx').on(t.srcAssetId, t.eventTime),
    index('security_events_incident_idx').on(t.incidentId),
  ],
);

export const incidents = pgTable(
  'incidents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    title: text('title').notNull(),
    type: incidentTypeEnum('type').notNull().default('security'),
    status: incidentStatusEnum('status').notNull().default('new'),
    severity: severityEnum('severity').notNull(),
    assigneeId: uuid('assignee_id').references(() => users.id, { onDelete: 'set null' }),
    commanderId: uuid('commander_id').references(() => users.id, { onDelete: 'set null' }),
    summary: text('summary').notNull().default(''),
    openedAt: ts('opened_at').notNull().defaultNow(),
    closedAt: ts('closed_at'),
    closureReason: text('closure_reason'),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('incidents_status_severity_idx').on(t.status, t.severity),
    index('incidents_assignee_status_idx').on(t.assigneeId, t.status),
    index('incidents_opened_idx').on(t.openedAt),
  ],
);

/** Append-only incident timeline: transitions, notes, evidence links, assignments. */
export const incidentEvents = pgTable(
  'incident_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    incidentId: uuid('incident_id')
      .notNull()
      .references(() => incidents.id, { onDelete: 'cascade' }),
    occurredAt: ts('occurred_at').notNull().defaultNow(),
    actorId: uuid('actor_id').references(() => users.id, { onDelete: 'set null' }),
    kind: text('kind').notNull(),
    fromStatus: incidentStatusEnum('from_status'),
    toStatus: incidentStatusEnum('to_status'),
    note: text('note'),
    payload: jsonb('payload').$type<Record<string, unknown>>().notNull().default({}),
  },
  (t) => [index('incident_events_incident_time_idx').on(t.incidentId, t.occurredAt)],
);

export const alerts = pgTable(
  'alerts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    title: text('title').notNull(),
    status: alertStatusEnum('status').notNull().default('new'),
    severity: severityEnum('severity').notNull(),
    confidence: confidenceEnum('confidence').notNull().default('unknown'),
    priorityScore: real('priority_score').notNull().default(0),
    ruleId: uuid('rule_id').references(() => detectionRules.id, { onDelete: 'set null' }),
    /** Engine rule reference (e.g. Suricata gid:sid:rev) until the rule registry is populated. */
    ruleRef: text('rule_ref'),
    sourceProduct: eventSourceProductEnum('source_product').notNull(),
    sourceSensorId: uuid('source_sensor_id').references(() => sensors.id, { onDelete: 'set null' }),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    srcIp: inet('src_ip'),
    dstIp: inet('dst_ip'),
    lastEventId: uuid('last_event_id'),
    dedupKey: text('dedup_key').notNull(),
    occurrenceCount: integer('occurrence_count').notNull().default(1),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    assigneeId: uuid('assignee_id').references(() => users.id, { onDelete: 'set null' }),
    incidentId: uuid('incident_id').references(() => incidents.id, { onDelete: 'set null' }),
    suppressedUntil: ts('suppressed_until'),
    dispositionNote: text('disposition_note'),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('alerts_status_severity_last_seen_idx').on(t.status, t.severity, t.lastSeenAt),
    index('alerts_asset_status_idx').on(t.assetId, t.status),
    index('alerts_assignee_idx').on(t.assigneeId),
    index('alerts_incident_idx').on(t.incidentId),
    // Partial unique index: one *open* alert per dedup key; resolved alerts may repeat the key.
    uniqueIndex('alerts_open_dedup_idx')
      .on(t.dedupKey)
      .where(sql`status not in ('resolved','false_positive')`),
  ],
);

export const vulnerabilityFindings = pgTable(
  'vulnerability_findings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    engagementId: uuid('engagement_id'),
    title: text('title').notNull(),
    status: findingStatusEnum('status').notNull().default('open'),
    severity: severityEnum('severity').notNull(),
    cve: text('cve').array().notNull().default([]),
    cwe: text('cwe').array().notNull().default([]),
    cvssBaseScore: real('cvss_base_score'),
    cvssVector: text('cvss_vector'),
    validated: boolean('validated').notNull().default(false),
    evidenceRefs: jsonb('evidence_refs').$type<unknown[]>().notNull().default([]),
    firstDetectedAt: ts('first_detected_at').notNull().defaultNow(),
    lastDetectedAt: ts('last_detected_at').notNull().defaultNow(),
  },
  (t) => [
    index('findings_asset_status_idx').on(t.assetId, t.status),
    index('findings_status_severity_idx').on(t.status, t.severity),
    index('findings_engagement_idx').on(t.engagementId),
  ],
);
