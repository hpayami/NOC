import { sql } from 'drizzle-orm';
import {
  boolean,
  index,
  inet,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { userStatusEnum } from './enums';

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').notNull(),
    displayName: text('display_name').notNull(),
    /** Argon2id PHC string. Never selected by public queries. */
    passwordHash: text('password_hash').notNull(),
    status: userStatusEnum('status').notNull().default('active'),
    /** Bumped to invalidate every outstanding access token for the user. */
    tokenVersion: integer('token_version').notNull().default(0),
    failedLoginCount: integer('failed_login_count').notNull().default(0),
    lockedUntil: ts('locked_until'),
    mfaEnrolled: boolean('mfa_enrolled').notNull().default(false),
    /** False restricts the user to the sites in user_site_grants (fail closed when empty). */
    allSites: boolean('all_sites').notNull().default(true),
    /** 'local' (password) or 'oidc'. SSO accounts hold an unusable password hash. */
    authProvider: text('auth_provider').notNull().default('local'),
    /** `${issuer}|${sub}` for SSO accounts; the stable identity, never the e-mail. */
    externalSubject: text('external_subject'),
    lastLoginAt: ts('last_login_at'),
    createdAt: ts('created_at').notNull().defaultNow(),
    updatedAt: ts('updated_at').notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('users_email_lower_idx').on(sql`lower(${t.email})`),
    uniqueIndex('users_external_subject_idx').on(t.authProvider, t.externalSubject),
    index('users_status_idx').on(t.status),
  ],
);

/** Single-use OIDC login state: PKCE verifier and nonce stay server-side. */
export const oidcStates = pgTable('oidc_states', {
  state: text('state').primaryKey(),
  nonce: text('nonce').notNull(),
  codeVerifier: text('code_verifier').notNull(),
  createdAt: ts('created_at').notNull().defaultNow(),
  expiresAt: ts('expires_at').notNull(),
  consumedAt: ts('consumed_at'),
});

export const roles = pgTable('roles', {
  key: text('key').primaryKey(),
  name: text('name').notNull(),
  nameFa: text('name_fa').notNull(),
  description: text('description').notNull().default(''),
  builtin: boolean('builtin').notNull().default(true),
});

export const permissions = pgTable('permissions', {
  key: text('key').primaryKey(),
  description: text('description').notNull().default(''),
});

export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleKey: text('role_key')
      .notNull()
      .references(() => roles.key, { onDelete: 'cascade' }),
    permissionKey: text('permission_key')
      .notNull()
      .references(() => permissions.key, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.roleKey, t.permissionKey] }),
    index('role_permissions_permission_idx').on(t.permissionKey),
  ],
);

export const userRoles = pgTable(
  'user_roles',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleKey: text('role_key')
      .notNull()
      .references(() => roles.key, { onDelete: 'restrict' }),
    grantedBy: uuid('granted_by'),
    grantedAt: ts('granted_at').notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.roleKey] }),
    index('user_roles_role_idx').on(t.roleKey),
  ],
);

/** Opaque refresh tokens stored only as SHA-256 digests; families enable reuse detection. */
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    familyId: uuid('family_id').notNull(),
    tokenHash: text('token_hash').notNull(),
    expiresAt: ts('expires_at').notNull(),
    createdAt: ts('created_at').notNull().defaultNow(),
    revokedAt: ts('revoked_at'),
    replacedBy: uuid('replaced_by'),
    createdIp: inet('created_ip'),
    userAgent: text('user_agent'),
  },
  (t) => [
    uniqueIndex('refresh_tokens_hash_idx').on(t.tokenHash),
    index('refresh_tokens_family_idx').on(t.familyId),
    index('refresh_tokens_user_expires_idx').on(t.userId, t.expiresAt),
  ],
);

/** Physical or logical sites; the key is what assets (via segments), sensors and segments carry. */
export const sites = pgTable('sites', {
  key: text('key').primaryKey(),
  name: text('name').notNull(),
  description: text('description'),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: ts('created_at').notNull().defaultNow(),
});

export const userSiteGrants = pgTable(
  'user_site_grants',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    siteKey: text('site_key')
      .notNull()
      .references(() => sites.key, { onDelete: 'cascade' }),
    grantedBy: uuid('granted_by').references(() => users.id, { onDelete: 'set null' }),
    grantedAt: ts('granted_at').notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.siteKey] })],
);
