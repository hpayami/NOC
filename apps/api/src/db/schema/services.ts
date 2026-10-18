import {
  index,
  inet,
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { assets } from './assets';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

/** Listening/open services per asset, as reported by agents or discovery. Never a vulnerability claim. */
export const assetServices = pgTable(
  'asset_services',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    proto: text('proto').notNull(),
    port: integer('port').notNull(),
    address: inet('address'),
    process: text('process'),
    source: text('source').notNull(),
    firstSeenAt: ts('first_seen_at').notNull().defaultNow(),
    lastSeenAt: ts('last_seen_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('asset_services_identity_idx').on(t.assetId, t.proto, t.port, t.address, t.source),
    index('asset_services_asset_idx').on(t.assetId, t.lastSeenAt),
    index('asset_services_port_idx').on(t.proto, t.port),
  ],
);
