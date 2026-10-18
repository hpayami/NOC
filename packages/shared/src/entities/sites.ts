import { z } from 'zod';
import { Timestamp } from '../common';

/** Site key: short, stable, lower-case; it is what assets/sensors/segments carry in `site`. */
export const SiteKey = z
  .string()
  .trim()
  .min(1)
  .max(32)
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'lower-case letters, digits and dashes');

export const Site = z.strictObject({
  key: SiteKey,
  name: z.string().trim().min(1).max(128),
  description: z.string().max(512).nullable(),
  createdAt: Timestamp,
});
export type Site = z.infer<typeof Site>;

export const CreateSiteRequest = z.strictObject({
  key: SiteKey,
  name: z.string().trim().min(1).max(128),
  description: z.string().trim().max(512).optional(),
});

/** Grant: `allSites` wins; otherwise the listed keys are the whole visible world. */
export const UserSitesRequest = z.strictObject({
  allSites: z.boolean(),
  sites: z.array(SiteKey).max(64).default([]),
});
export type UserSitesRequest = z.infer<typeof UserSitesRequest>;
