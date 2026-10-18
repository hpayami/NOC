import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

export type Db = PostgresJsDatabase<typeof schema>;
export type DbTx = Parameters<Parameters<Db['transaction']>[0]>[0];

export interface DbHandle {
  db: Db;
  sql: postgres.Sql;
  close: () => Promise<void>;
}

export function createDb(url: string, opts: { max?: number } = {}): DbHandle {
  const sql = postgres(url, {
    max: opts.max ?? 10,
    idle_timeout: 30,
    connect_timeout: 10,
    prepare: true,
    onnotice: () => {},
  });
  const db = drizzle(sql, { schema, casing: 'snake_case' });
  return { db, sql, close: () => sql.end({ timeout: 5 }) };
}
