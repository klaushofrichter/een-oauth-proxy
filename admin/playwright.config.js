import { defineConfig, devices } from '@playwright/test'
import { config } from 'dotenv'

// Load environment variables from .env
config()

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'html',
  timeout: 60000,
  maxFailures: 1,

  use: {
    baseURL: 'http://127.0.0.1:3333',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Run local dev server before tests
  // E2E_PROD=1 (set by npm run test:prod) starts the app with production
  // config so the tests run against the deployed proxy
  webServer: {
    command: process.env.E2E_PROD === '1' ? 'npm run dev:prod' : 'npm run dev',
    url: 'http://127.0.0.1:3333',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    env: {
      ...process.env,
      // Ensure VITE_PROXY_URL is passed to the dev server
      VITE_PROXY_URL: process.env.VITE_PROXY_URL || 'http://localhost:8787',
    },
  },
})
