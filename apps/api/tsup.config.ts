import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/server.ts', 'scripts/migrate.ts', 'scripts/bootstrap-admin.ts'],
  format: ['esm'],
  target: 'node22',
  platform: 'node',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // The shared package is TypeScript source; bundle it. Native/runtime deps stay external.
  noExternal: ['@noc/shared'],
});
