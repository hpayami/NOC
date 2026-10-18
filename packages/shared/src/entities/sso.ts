import { z } from 'zod';

export const AuthProviders = z.strictObject({
  local: z.literal(true),
  oidc: z.strictObject({
    enabled: z.boolean(),
    displayName: z.string().max(64),
    /** Just-in-time provisioning of first-time SSO users (roles from the configured claim map). */
    jitProvisioning: z.boolean(),
  }),
});
export type AuthProviders = z.infer<typeof AuthProviders>;

export const OidcStartResponse = z.strictObject({
  authorizationUrl: z.string().url(),
  /** Opaque; the BFF stores it in an httpOnly cookie and sends it back with the callback. */
  state: z.string().min(16).max(128),
  expiresInSeconds: z.number().int().positive(),
});
export type OidcStartResponse = z.infer<typeof OidcStartResponse>;

export const OidcCallbackRequest = z.strictObject({
  code: z.string().min(1).max(4096),
  state: z.string().min(16).max(128),
});
export type OidcCallbackRequest = z.infer<typeof OidcCallbackRequest>;
