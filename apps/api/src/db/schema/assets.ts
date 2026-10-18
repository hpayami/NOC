import {
  boolean,
  cidr,
  index,
  inet,
  integer,
  jsonb,
  macaddr,
  pgTable,
  real,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  assetClassEnum,
  assuranceStateEnum,
  coverageStateEnum,
  criticalityEnum,
  discoveryMethodEnum,
  operationalStatusEnum,
  relationshipKindEnum,
  relationshipVerificationEnum,
} from './enums';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const networkSegments = pgTable(
  'network_segments',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    site: text('site'),
    cidr: cidr('cidr'),
    vlanId: integer('vlan_id'),
    /** Deny by default: active discovery must be explicitly enabled per segment. */
    activeDiscoveryAllowed: boolean('active_discovery_allowed').notNull().default(false),
    description: text('description'),
    createdAt: ts('created_at').notNull().defaultNow(),
  },
  (t) => [
    index('network_segments_site_idx').on(t.site),
    index('network_segments_cidr_idx').on(t.cidr),
  ],
);

export const assets = pgTable(
  'assets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    hostname: text('hostname'),
    assetClass: assetClassEnum('asset_class').notNull().default('unknown'),
    manufacturer: text('manufacturer'),
    model: text('model'),
    /** Sensitive: only returned to holders of assets.read_sensitive. */
    serialNumber: text('serial_number'),
    osName: text('os_name'),
    osVersion: text('os_version'),
    firmwareVersion: text('firmware_version'),
    cpuArchitecture: text('cpu_architecture'),
    ramMb: integer('ram_mb'),
    segmentId: uuid('segment_id').references(() => networkSegments.id, { onDelete: 'set null' }),
    role: text('role'),
    criticality: criticalityEnum('criticality').notNull().default('unclassified'),
    owner: text('owner'),
    responsibleTeam: text('responsible_team'),
    discoveryMethods: discoveryMethodEnum('discovery_methods').array().notNull().default([]),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
    operationalStatus: operationalStatusEnum('operational_status').notNull().default('unknown'),
    monitoringCoverage: coverageStateEnum('monitoring_coverage').notNull().default('unknown'),
    credentialedAssessmentStatus: text('credentialed_assessment_status')
      .notNull()
      .default('not_performed'),
    assuranceState: assuranceStateEnum('assurance_state').notNull().default('asset_not_monitored'),
    dataConfidence: real('data_confidence').notNull().default(0),
    provenance: jsonb('provenance').$type<unknown[]>().notNull().default([]),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    index('assets_last_seen_idx').on(t.lastSeenAt),
    index('assets_segment_class_idx').on(t.segmentId, t.assetClass),
    index('assets_hostname_idx').on(t.hostname),
    index('assets_status_criticality_idx').on(t.operationalStatus, t.criticality),
  ],
);

export const assetInterfaces = pgTable(
  'asset_interfaces',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    macAddress: macaddr('mac_address'),
    ipAddresses: inet('ip_addresses').array().notNull().default([]),
    speedMbps: integer('speed_mbps'),
    adminState: text('admin_state').notNull().default('unknown'),
    operState: text('oper_state').notNull().default('unknown'),
    vlanId: integer('vlan_id'),
  },
  (t) => [
    index('asset_interfaces_asset_idx').on(t.assetId),
    index('asset_interfaces_mac_idx').on(t.macAddress),
    // GIN over the inet[] column supports "which interface holds this address" lookups.
    index('asset_interfaces_ips_gin_idx').using('gin', t.ipAddresses),
  ],
);

/** Raw per-source observations; the identity-resolution job links them to assets. */
export const assetObservations = pgTable(
  'asset_observations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id').references(() => assets.id, { onDelete: 'set null' }),
    source: text('source').notNull(),
    method: discoveryMethodEnum('method').notNull(),
    observedAt: ts('observed_at').notNull(),
    macAddresses: macaddr('mac_addresses').array().notNull().default([]),
    ipAddresses: inet('ip_addresses').array().notNull().default([]),
    hostnames: text('hostnames').array().notNull().default([]),
    cloudInstanceId: text('cloud_instance_id'),
    agentId: text('agent_id'),
    attributes: jsonb('attributes').$type<Record<string, unknown>>().notNull().default({}),
    conflictsWith: uuid('conflicts_with').array().notNull().default([]),
    ingestedAt: ts('ingested_at').notNull().defaultNow(),
  },
  (t) => [
    index('asset_observations_asset_time_idx').on(t.assetId, t.observedAt),
    index('asset_observations_time_idx').on(t.observedAt),
    index('asset_observations_macs_gin_idx').using('gin', t.macAddresses),
    index('asset_observations_ips_gin_idx').using('gin', t.ipAddresses),
    index('asset_observations_agent_idx').on(t.agentId),
    index('asset_observations_cloud_idx').on(t.cloudInstanceId),
  ],
);

export const topologyRelationships = pgTable(
  'topology_relationships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    kind: relationshipKindEnum('kind').notNull(),
    sourceAssetId: uuid('source_asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    targetAssetId: uuid('target_asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    sourceInterfaceId: uuid('source_interface_id').references(() => assetInterfaces.id, {
      onDelete: 'set null',
    }),
    targetInterfaceId: uuid('target_interface_id').references(() => assetInterfaces.id, {
      onDelete: 'set null',
    }),
    verification: relationshipVerificationEnum('verification').notNull().default('inferred'),
    evidence: text('evidence').notNull().default(''),
    firstObservedAt: ts('first_observed_at').notNull().defaultNow(),
    lastObservedAt: ts('last_observed_at').notNull().defaultNow(),
  },
  (t) => [
    index('topology_source_idx').on(t.sourceAssetId, t.kind),
    index('topology_target_idx').on(t.targetAssetId, t.kind),
  ],
);
