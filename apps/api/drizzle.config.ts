import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema/index.ts',
  out: './drizzle',
  // Only needed for introspection commands; `generate` never connects.
  dbCredentials: { url: process.env.DATABASE_URL ?? 'postgres://invalid' },
  strict: true,
  verbose: true,
});
