import { z } from 'zod';

export const Id = z.uuid();
export const Timestamp = z.iso.datetime({ offset: true });
export const IpAddress = z.union([z.ipv4(), z.ipv6()]);
export const Cidr = z.union([z.cidrv4(), z.cidrv6()]);
export const MacAddress = z
  .string()
  .regex(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/, 'MAC must be lowercase colon-separated');
export const Port = z.number().int().min(0).max(65535);
export const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/** Free-text fields are bounded so no public schema can carry an unbounded payload. */
export const ShortText = z.string().trim().min(1).max(256);
export const LongText = z.string().trim().max(8192);

/** Where a fact came from; every inventory field must be attributable. */
export const Provenance = z.strictObject({
  source: z.string().min(1).max(128),
  method: z.string().min(1).max(64),
  observedAt: Timestamp,
  confidence: z.number().min(0).max(1),
});
export type Provenance = z.infer<typeof Provenance>;

export const PageQuery = z.strictObject({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(512).optional(),
});
export type PageQuery = z.infer<typeof PageQuery>;

export const pageOf = <T extends z.ZodType>(item: T) =>
  z.strictObject({ items: z.array(item), nextCursor: z.string().nullable() });

export const ApiError = z.strictObject({
  error: z.strictObject({
    code: z.string(),
    message: z.string(),
    requestId: z.string().optional(),
    details: z.unknown().optional(),
  }),
});
export type ApiError = z.infer<typeof ApiError>;
