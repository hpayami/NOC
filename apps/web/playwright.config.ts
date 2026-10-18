import { defineConfig } from '@playwright/test';

/**
 * Browser end-to-end tests against a running stack (API + web). Not part of `pnpm test`;
 * run with `pnpm e2e` after `scripts/start.sh`. Credentials come from E2E_EMAIL / E2E_PASSWORD.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3000',
    headless: true,
    locale: 'fa-IR',
    ...(process.env.PLAYWRIGHT_CHROMIUM_PATH
      ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } }
      : {}),
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
