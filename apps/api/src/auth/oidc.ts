import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';
import { HTTPException } from 'hono/http-exception';
import { and, eq, isNull, sql } from 'drizzle-orm';
import { ROLE_KEYS, type RoleKey } from '@noc/shared';
import type { AuditService } from '../audit/service';
import type { Env } from '../config/env';
import type { Db } from '../db/client';
import { oidcStates, userRoles, users } from '../db/schema';
import { hashPassword } from '../security/password';

const STATE_TTL_SECONDS = 600;

interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}
interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
}

const b64url = (buf: Buffer) => buf.toString('base64url');
const decodeB64url = (s: string) => Buffer.from(s, 'base64url');

export class OidcError extends HTTPException {
  constructor(
    public readonly code: string,
    message: string,
    status: 400 | 401 | 403 | 409 | 502 | 503 = 401,
  ) {
    super(status, { message });
  }
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string | null;
  redirectUri: string;
  scopes: string;
  roleClaim: string;
  roleMap: Record<string, RoleKey>;
  defaultRoles: RoleKey[];
  jit: boolean;
  autoLinkByEmail: boolean;
  displayName: string;
  clockSkewSeconds: number;
}

export function oidcConfigFromEnv(env: Env): OidcConfig | null {
  if (!env.OIDC_ISSUER || !env.OIDC_CLIENT_ID || !env.OIDC_REDIRECT_URI) return null;
  const roleMap: Record<string, RoleKey> = {};
  try {
    const raw = JSON.parse(env.OIDC_ROLE_MAP || '{}') as Record<string, string>;
    for (const [k, v] of Object.entries(raw)) {
      if (!(ROLE_KEYS as readonly string[]).includes(v)) throw new Error(`unknown role ${v}`);
      roleMap[k] = v as RoleKey;
    }
  } catch (err) {
    throw new Error(
      `OIDC_ROLE_MAP is invalid: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const defaultRoles = (env.OIDC_DEFAULT_ROLES ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const r of defaultRoles)
    if (!(ROLE_KEYS as readonly string[]).includes(r))
      throw new Error(`OIDC_DEFAULT_ROLES has unknown role ${r}`);
  return {
    issuer: env.OIDC_ISSUER.replace(/\/$/, ''),
    clientId: env.OIDC_CLIENT_ID,
    clientSecret: env.OIDC_CLIENT_SECRET ?? null,
    redirectUri: env.OIDC_REDIRECT_URI,
    scopes: env.OIDC_SCOPES,
    roleClaim: env.OIDC_ROLE_CLAIM,
    roleMap,
    defaultRoles: defaultRoles as RoleKey[],
    jit: env.OIDC_ALLOW_JIT,
    autoLinkByEmail: env.OIDC_AUTO_LINK_BY_EMAIL,
    displayName: env.OIDC_DISPLAY_NAME,
    clockSkewSeconds: 60,
  };
}

/**
 * OpenID Connect authorization-code login with PKCE. The code verifier and nonce never leave this
 * service (stored server-side per `state`, single use, 10-minute TTL); ID tokens are verified
 * locally against the issuer's JWKS (RS256) — signature, issuer, audience, expiry, nonce — before
 * any account is touched. Existing local accounts are never linked by e-mail unless explicitly
 * enabled: an attacker controlling an IdP account must not inherit a local admin's identity.
 */
export class OidcService {
  private discovery: { at: number; doc: Discovery } | null = null;
  private jwks: { at: number; keys: Jwk[] } | null = null;

  constructor(
    private readonly db: Db,
    private readonly audit: AuditService,
    readonly config: OidcConfig | null,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  get enabled(): boolean {
    return this.config !== null;
  }

  private cfg(): OidcConfig {
    if (!this.config) throw new OidcError('not_configured', 'SSO is not configured', 503);
    return this.config;
  }

  private async getJson<T>(url: string): Promise<T> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await this.fetchImpl(url, {
        headers: { accept: 'application/json' },
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as T;
    } catch (err) {
      throw new OidcError(
        'idp_unreachable',
        `Identity provider unreachable: ${err instanceof Error ? err.message : String(err)}`,
        503,
      );
    } finally {
      clearTimeout(t);
    }
  }

  async discover(): Promise<Discovery> {
    const cfg = this.cfg();
    if (this.discovery && Date.now() - this.discovery.at < 3_600_000) return this.discovery.doc;
    const doc = await this.getJson<Discovery>(`${cfg.issuer}/.well-known/openid-configuration`);
    if (doc.issuer !== cfg.issuer)
      throw new OidcError(
        'issuer_mismatch',
        'Discovery document issuer does not match OIDC_ISSUER',
        502,
      );
    for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const)
      if (!doc[k])
        throw new OidcError('discovery_incomplete', `Discovery document lacks ${k}`, 502);
    this.discovery = { at: Date.now(), doc };
    return doc;
  }

  private async keys(force = false): Promise<Jwk[]> {
    if (!force && this.jwks && Date.now() - this.jwks.at < 3_600_000) return this.jwks.keys;
    const doc = await this.discover();
    const body = await this.getJson<{ keys: Jwk[] }>(doc.jwks_uri);
    this.jwks = { at: Date.now(), keys: body.keys ?? [] };
    return this.jwks.keys;
  }

  /** Creates the single-use state record and the authorization URL. */
  async start(): Promise<{ authorizationUrl: string; state: string; expiresInSeconds: number }> {
    const cfg = this.cfg();
    const doc = await this.discover();
    const state = b64url(randomBytes(32));
    const nonce = b64url(randomBytes(32));
    const verifier = b64url(randomBytes(48));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    await this.db.insert(oidcStates).values({
      state,
      nonce,
      codeVerifier: verifier,
      expiresAt: new Date(Date.now() + STATE_TTL_SECONDS * 1000),
    });
    const url = new URL(doc.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', cfg.clientId);
    url.searchParams.set('redirect_uri', cfg.redirectUri);
    url.searchParams.set('scope', cfg.scopes);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return { authorizationUrl: url.toString(), state, expiresInSeconds: STATE_TTL_SECONDS };
  }

  /** Verifies a compact JWS ID token (RS256 only) and returns its claims. */
  async verifyIdToken(idToken: string, nonce: string): Promise<Record<string, unknown>> {
    const cfg = this.cfg();
    const parts = idToken.split('.');
    if (parts.length !== 3) throw new OidcError('malformed_token', 'ID token is not a compact JWS');
    const [h, p, s] = parts as [string, string, string];
    let header: { alg?: string; kid?: string };
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(decodeB64url(h).toString()) as { alg?: string; kid?: string };
      claims = JSON.parse(decodeB64url(p).toString()) as Record<string, unknown>;
    } catch {
      throw new OidcError('malformed_token', 'ID token header or payload is not JSON');
    }
    if (header.alg !== 'RS256')
      throw new OidcError(
        'alg_rejected',
        `ID token alg ${header.alg ?? 'none'} is not accepted (RS256 only)`,
      );
    let keys = await this.keys();
    let jwk = keys.find((k) => (header.kid ? k.kid === header.kid : k.kty === 'RSA'));
    if (!jwk) {
      keys = await this.keys(true); // key rotation: refresh once
      jwk = keys.find((k) => (header.kid ? k.kid === header.kid : k.kty === 'RSA'));
    }
    if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e)
      throw new OidcError('unknown_key', 'No RSA key matches the ID token kid');
    const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    const ok = cryptoVerify('sha256', Buffer.from(`${h}.${p}`), key, decodeB64url(s));
    if (!ok) throw new OidcError('bad_signature', 'ID token signature is invalid');
    const now = Math.floor(Date.now() / 1000);
    const skew = cfg.clockSkewSeconds;
    if (claims.iss !== cfg.issuer) throw new OidcError('bad_issuer', 'ID token issuer mismatch');
    const aud = Array.isArray(claims.aud) ? (claims.aud as string[]) : [claims.aud as string];
    if (!aud.includes(cfg.clientId))
      throw new OidcError('bad_audience', 'ID token audience mismatch');
    if (aud.length > 1 && claims.azp !== cfg.clientId)
      throw new OidcError('bad_azp', 'ID token azp mismatch');
    if (typeof claims.exp !== 'number' || claims.exp + skew <= now)
      throw new OidcError('expired', 'ID token has expired');
    if (typeof claims.iat === 'number' && claims.iat - skew > now)
      throw new OidcError('bad_iat', 'ID token issued in the future');
    if (claims.nonce !== nonce) throw new OidcError('bad_nonce', 'ID token nonce mismatch');
    if (typeof claims.sub !== 'string' || !claims.sub)
      throw new OidcError('no_subject', 'ID token has no subject');
    return claims;
  }

  private rolesFromClaims(claims: Record<string, unknown>): RoleKey[] {
    const cfg = this.cfg();
    const raw = claims[cfg.roleClaim];
    const values = Array.isArray(raw) ? raw.map(String) : typeof raw === 'string' ? [raw] : [];
    const mapped = values.map((v) => cfg.roleMap[v]).filter((r): r is RoleKey => Boolean(r));
    return [...new Set(mapped.length ? mapped : cfg.defaultRoles)];
  }

  /**
   * Completes the login: consumes the state, exchanges the code, verifies the ID token, then
   * finds or provisions the user. Returns the user row and the roles to issue.
   */
  async callback(
    input: { code: string; state: string },
    ctx: { ip: string | null; requestId: string | null },
  ) {
    const cfg = this.cfg();
    const now = new Date();
    const [st] = await this.db
      .update(oidcStates)
      .set({ consumedAt: now })
      .where(
        and(
          eq(oidcStates.state, input.state),
          isNull(oidcStates.consumedAt),
          sql`${oidcStates.expiresAt} > ${now.toISOString()}::timestamptz`,
        ),
      )
      .returning();
    if (!st) throw new OidcError('bad_state', 'Login state is unknown, expired or already used');
    const doc = await this.discover();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      code_verifier: st.codeVerifier,
    });
    if (cfg.clientSecret) body.set('client_secret', cfg.clientSecret);
    let tokenRes: Response;
    try {
      tokenRes = await this.fetchImpl(doc.token_endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body,
      });
    } catch (err) {
      throw new OidcError(
        'idp_unreachable',
        `Token endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`,
        503,
      );
    }
    if (!tokenRes.ok)
      throw new OidcError(
        'code_rejected',
        `Token endpoint rejected the code (HTTP ${tokenRes.status})`,
      );
    const tok = (await tokenRes.json()) as { id_token?: string };
    if (!tok.id_token) throw new OidcError('no_id_token', 'Token response has no id_token', 502);
    const claims = await this.verifyIdToken(tok.id_token, st.nonce);
    const sub = claims.sub as string;
    const email = typeof claims.email === 'string' ? claims.email.trim() : null;
    const displayName =
      (typeof claims.name === 'string' && claims.name.trim()) || email || `sso:${sub.slice(0, 12)}`;
    const roles = this.rolesFromClaims(claims);
    const subjectKey = `${cfg.issuer}|${sub}`;

    const [linked] = await this.db
      .select()
      .from(users)
      .where(and(eq(users.authProvider, 'oidc'), eq(users.externalSubject, subjectKey)))
      .limit(1);
    if (linked) {
      if (linked.status !== 'active')
        throw new OidcError('account_' + linked.status, 'Account is not active', 403);
      await this.db
        .update(users)
        .set({ lastLoginAt: now, updatedAt: now, displayName })
        .where(eq(users.id, linked.id));
      return { user: linked, roles: await this.syncRoles(linked.id, roles), provisioned: false };
    }
    if (email) {
      const [local] = await this.db
        .select()
        .from(users)
        .where(sql`lower(${users.email}) = lower(${email})`)
        .limit(1);
      if (local) {
        if (!cfg.autoLinkByEmail) {
          await this.audit.record({
            actorId: local.id,
            actorLabel: email.toLowerCase(),
            action: 'auth.oidc_login',
            outcome: 'denied',
            requestId: ctx.requestId,
            sourceIp: ctx.ip,
            metadata: { reason: 'email_collision_not_linked', issuer: cfg.issuer },
          });
          throw new OidcError(
            'email_collision',
            'An account with this e-mail exists and automatic linking is disabled; an administrator must link it',
            409,
          );
        }
        if (local.status !== 'active')
          throw new OidcError('account_' + local.status, 'Account is not active', 403);
        const [upd] = await this.db
          .update(users)
          .set({
            authProvider: 'oidc',
            externalSubject: subjectKey,
            lastLoginAt: now,
            updatedAt: now,
          })
          .where(eq(users.id, local.id))
          .returning();
        await this.audit.record({
          actorId: local.id,
          actorLabel: local.email,
          action: 'auth.oidc_link',
          outcome: 'success',
          requestId: ctx.requestId,
          sourceIp: ctx.ip,
          metadata: { issuer: cfg.issuer },
        });
        return { user: upd!, roles: await this.syncRoles(local.id, roles), provisioned: false };
      }
    }
    if (!cfg.jit) {
      await this.audit.record({
        actorId: null,
        actorLabel: email?.toLowerCase() ?? `sso:${sub}`,
        action: 'auth.oidc_login',
        outcome: 'denied',
        requestId: ctx.requestId,
        sourceIp: ctx.ip,
        metadata: { reason: 'jit_disabled' },
      });
      throw new OidcError(
        'jit_disabled',
        'No account exists for this identity and provisioning is disabled',
        403,
      );
    }
    if (!email)
      throw new OidcError(
        'no_email',
        'Identity provider did not supply an e-mail; cannot provision',
        403,
      );
    // SSO accounts carry an unusable local password; password login is refused by the provider check anyway.
    const unusable = await hashPassword(b64url(randomBytes(48)));
    const user = await this.db.transaction(async (tx) => {
      const [u] = await tx
        .insert(users)
        .values({
          email,
          displayName,
          passwordHash: unusable,
          authProvider: 'oidc',
          externalSubject: subjectKey,
          lastLoginAt: now,
        })
        .returning();
      if (roles.length)
        await tx.insert(userRoles).values(roles.map((roleKey) => ({ userId: u!.id, roleKey })));
      await this.audit.record(
        {
          actorId: u!.id,
          actorLabel: email.toLowerCase(),
          action: 'auth.oidc_provision',
          outcome: 'success',
          requestId: ctx.requestId,
          sourceIp: ctx.ip,
          metadata: { issuer: cfg.issuer, roles, claim: cfg.roleClaim },
        },
        tx,
      );
      return u!;
    });
    return { user, roles, provisioned: true };
  }

  /** Roles follow the IdP claim on every login when a map is configured; otherwise existing roles stay. */
  private async syncRoles(userId: string, claimRoles: RoleKey[]): Promise<RoleKey[]> {
    const cfg = this.cfg();
    const current = (
      await this.db
        .select({ r: userRoles.roleKey })
        .from(userRoles)
        .where(eq(userRoles.userId, userId))
    ).map((x) => x.r as RoleKey);
    if (Object.keys(cfg.roleMap).length === 0) return current;
    const same =
      current.length === claimRoles.length && current.every((r) => claimRoles.includes(r));
    if (same) return current;
    await this.db.transaction(async (tx) => {
      await tx.delete(userRoles).where(eq(userRoles.userId, userId));
      if (claimRoles.length)
        await tx.insert(userRoles).values(claimRoles.map((roleKey) => ({ userId, roleKey })));
      await tx
        .update(users)
        .set({ tokenVersion: sql`${users.tokenVersion} + 1`, updatedAt: new Date() })
        .where(eq(users.id, userId));
      await this.audit.record(
        {
          actorId: userId,
          actorLabel: 'system:oidc',
          action: 'auth.oidc_role_sync',
          outcome: 'success',
          metadata: { from: current, to: claimRoles },
        },
        tx,
      );
    });
    return claimRoles;
  }
}
