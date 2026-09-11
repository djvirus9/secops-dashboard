import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/integration',
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  timeout: 120000,
  use: {
    baseURL: 'http://127.0.0.1:15110',
    trace: 'retain-on-failure',
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {},
  },
  webServer: {
    command: 'node tests/serve-integration.mjs',
    url: 'http://127.0.0.1:15110/_health',
    reuseExistingServer: false,
    timeout: 120000,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 },
  },
});
