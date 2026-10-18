import { sql } from 'drizzle-orm';
import { PERMISSION_CATALOG, PERMISSIONS, ROLE_DEFINITIONS, ROLE_KEYS } from '@noc/shared';
import type { Db } from '../db/client';
import { permissions, rolePermissions, roles } from '../db/schema';

/**
 * Idempotently mirrors the shared RBAC catalog into the database. Built-in role grants are reset
 * to the catalog on every start so a stale database can never grant more than the code intends.
 */
export async function syncRbacCatalog(db: Db): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .insert(permissions)
      .values(PERMISSIONS.map((key) => ({ key, description: PERMISSION_CATALOG[key] })))
      .onConflictDoUpdate({
        target: permissions.key,
        set: { description: sql`excluded.description` },
      });

    await tx
      .insert(roles)
      .values(
        ROLE_KEYS.map((key) => ({
          key,
          name: ROLE_DEFINITIONS[key].name,
          nameFa: ROLE_DEFINITIONS[key].nameFa,
          description: ROLE_DEFINITIONS[key].description,
          builtin: true,
        })),
      )
      .onConflictDoUpdate({
        target: roles.key,
        set: {
          name: sql`excluded.name`,
          nameFa: sql`excluded.name_fa`,
          description: sql`excluded.description`,
          builtin: true,
        },
      });

    await tx
      .delete(rolePermissions)
      .where(sql`${rolePermissions.roleKey} in (select key from roles where builtin)`);
    await tx.insert(rolePermissions).values(
      ROLE_KEYS.flatMap((roleKey) =>
        ROLE_DEFINITIONS[roleKey].permissions.map((permissionKey) => ({
          roleKey,
          permissionKey,
        })),
      ),
    );
  });
}
