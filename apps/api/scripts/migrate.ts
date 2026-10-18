import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadEnv } from '../src/config/env';
import { createDb } from '../src/db/client';
import { syncRbacCatalog } from '../src/platform/seed';

/**
 * Applies pending SQL migrations from ./drizzle and syncs the RBAC catalog. Safe to re-run.
 * The target database is always the explicitly configured DATABASE_URL — never a default.
 */
export async function runMigrations(
  databaseUrl: string,
  opts: { quiet?: boolean } = {},
): Promise<void> {
  const handle = createDb(databaseUrl, { max: 1 });
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // Works from both `scripts/` (tsx) and `dist/` (bundled) layouts.
    const migrationsFolder = [
      path.resolve(here, '../drizzle'),
      path.resolve(here, './drizzle'),
    ].find((p) => p.includes('drizzle'))!;
    await migrate(handle.db, { migrationsFolder });
    await syncRbacCatalog(handle.db);
    if (!opts.quiet)
      process.stdout.write(
        `[migrate] migrations applied and RBAC catalog synced (${migrationsFolder})\n`,
      );
  } finally {
    await handle.close();
  }
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const env = loadEnv();
  runMigrations(env.DATABASE_URL).catch((err) => {
    process.stderr.write(`[migrate] failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
