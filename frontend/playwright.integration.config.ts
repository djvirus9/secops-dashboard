import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/integration',
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  timeout: 60000,
  use: {
    baseURL: 'http://127.0.0.1:15110',
    httpCredentials: { username: 'reviewer', password: 'Integration-password-9b7f2d1e6c4a' },
    trace: 'retain-on-failure',
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {},
  },
  webServer: {
    command: 'node tests/serve-integration.mjs',
    url: 'http://127.0.0.1:15110/_health',
    reuseExistingServer: false,
    timeout: 60000,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 },
  },
});
