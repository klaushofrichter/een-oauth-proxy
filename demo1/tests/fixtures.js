/**
 * Shared Playwright fixtures
 *
 * Extends the base test so every page automatically collects uncaught
 * exceptions and console errors, failing the test at teardown if any
 * unexpected ones occurred. A CORS rejection, an uncaught exception, or a
 * framework error in the browser fails the test even when the UI flow
 * happens to succeed (the class of failure behind issue #125 surfaced only
 * in the console).
 *
 * NOTE: this file is duplicated in admin/tests/ and demo1/tests/ - keep
 * both copies in sync.
 */

import { test as base, expect } from '@playwright/test'

// Expected browser noise that must not fail tests:
// - "Failed to load resource": negative-path tests deliberately trigger
//   4xx responses, which Chromium always logs as a console error
const IGNORED_CONSOLE_PATTERNS = [
  /Failed to load resource/i
]

// Only errors raised by our own app should fail tests. During the OAuth
// flow the page navigates to EEN's login site, whose scripts throw their
// own uncaught exceptions - those are not ours to fix.
const APP_ORIGINS = ['http://127.0.0.1:3333', 'http://localhost:3333']

// Caveat: page.url() reflects the URL at event-fire time, not where the
// error originated, so an error landing mid-navigation can be misattributed.
// Acceptable for this flow - errors during the brief OAuth redirects are
// dropped rather than failing tests spuriously.
function isAppPage(page) {
  const url = page.url()
  return APP_ORIGINS.some((origin) => url.startsWith(origin))
}

export const test = base.extend({
  // Tests that deliberately drive the app into an error path can declare
  // the error messages they expect: test.use({ allowedConsoleErrors: [/.../] })
  allowedConsoleErrors: [[], { option: true }],

  page: async ({ page, allowedConsoleErrors }, use) => {
    const errors = []
    page.on('pageerror', (err) => {
      if (!isAppPage(page)) return
      if (allowedConsoleErrors.some((re) => re.test(err.message))) return
      errors.push(`Uncaught exception: ${err.message}`)
    })
    page.on('console', (msg) => {
      if (!isAppPage(page)) return
      if (msg.type() !== 'error') return
      const text = msg.text()
      if (IGNORED_CONSOLE_PATTERNS.some((re) => re.test(text))) return
      if (allowedConsoleErrors.some((re) => re.test(text))) return
      errors.push(`Console error: ${text}`)
    })

    await use(page)

    expect.soft(errors, 'Unexpected browser errors during test').toEqual([])
  }
})

export { expect }
