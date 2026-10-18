import { count, sql } from 'drizzle-orm';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { PASSWORD_MIN_LENGTH } from '@noc/shared';
import { AuditService } from '../src/audit/service';
import { loadEnv } from '../src/config/env';
import { createDb, type Db } from '../src/db/client';
import { userRoles, users } from '../src/db/schema';
import { syncRbacCatalog } from '../src/platform/seed';
import { hashPassword } from '../src/security/password';

/**
 * Creates the first platform administrator. Refuses to run when any user already exists, so it can
 * never be used to add a backdoor account to a live deployment. Credentials come from the
 * environment, never from defaults.
 */
export async function bootstrapAdmin(
  db: Db,
  input: { email: string; displayName: string; password: string },
): Promise<{ id: string }> {
  if (input.password.length < PASSWORD_MIN_LENGTH)
    throw new Error(`password must be at least ${PASSWORD_MIN_LENGTH} characters`);
  await syncRbacCatalog(db);
  const passwordHash = await hashPassword(input.password);
  const audit = new AuditService(db);
  return db.transaction(async (tx) => {
    await tx.execute(sql`lock table users in exclusive mode`);
    const [row] = await tx.select({ n: count() }).from(users);
    if ((row?.n ?? 0) > 0) throw new Error('refusing to bootstrap: users already exist');
    const [u] = await tx
      .insert(users)
      .values({ email: input.email.toLowerCase(), displayName: input.displayName, passwordHash })
      .returning({ id: users.id });
    await tx.insert(userRoles).values({ userId: u!.id, roleKey: 'platform_admin' });
    await audit.record(
      {
        actorId: null,
        actorLabel: 'bootstrap',
        action: 'users.bootstrap_admin',
        outcome: 'success',
        targetType: 'user',
        targetId: u!.id,
      },
      tx,
    );
    return { id: u!.id };
  });
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const env = loadEnv();
  const email = process.env.BOOTSTRAP_ADMIN_EMAIL;
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const displayName = process.env.BOOTSTRAP_ADMIN_NAME ?? 'Platform Administrator';
  if (!email || !password) {
    process.stderr.write(
      '[bootstrap-admin] BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required\n',
    );
    process.exit(2);
  }
  const handle = createDb(env.DATABASE_URL, { max: 1 });
  bootstrapAdmin(handle.db, { email, displayName, password })
    .then(({ id }) =>
      process.stdout.write(`[bootstrap-admin] created platform_admin ${email} (${id})\n`),
    )
    .catch((err) => {
      process.stderr.write(
        `[bootstrap-admin] failed: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 1;
    })
    .finally(() => void handle.close());
}
