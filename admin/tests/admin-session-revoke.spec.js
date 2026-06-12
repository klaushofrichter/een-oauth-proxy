/**
 * Admin Session Revoke Test (PRODUCTION-SAFE)
 *
 * Unlike admin-destructive.spec.js (mass removeSessions/revokeAll, local
 * proxy only), this test only ever touches the session it creates itself:
 * login, capture the session ID, revoke via "Logout & Revoke", then verify
 * the captured session is truly dead server-side. Safe to run against any
 * proxy, including production.
 */

import { test, expect } from './fixtures.js'
import {
  loginToAdmin,
  clearAppState,
  verifyOnDashboard,
  getProxyUrl,
  MAX_TEST_TIMEOUT
} from './utils.js'

test.describe('Admin Session Revoke (Production-Safe)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await clearAppState(page)
  })

  test('should revoke own session and reject it server-side afterwards', async ({ page, context }) => {
    console.log('\n▶️ Running Test: Self-scoped session revoke\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    const proxyUrl = getProxyUrl()
    console.log(`📍 Proxy URL: ${proxyUrl}`)

    // Step 1: Login (creates exactly one session - the only one this test touches)
    await loginToAdmin(page)
    await verifyOnDashboard(page)

    // Step 2: Capture the session ID
    const cookies = await context.cookies()
    const sessionCookie = cookies.find((c) => c.name === 'sessionId')
    expect(sessionCookie, 'Session cookie must exist after login').toBeTruthy()
    const sessionId = sessionCookie.value
    console.log('📋 Session ID captured: yes')

    // Step 3: Verify the session works server-side before revoking
    const beforeResponse = await fetch(`${proxyUrl}/admin/version`, {
      headers: {
        Origin: 'http://127.0.0.1:3333',
        Authorization: `Bearer ${sessionId}`
      }
    })
    expect(beforeResponse.status).toBe(200)
    console.log('✅ Session valid before revoke (admin/version returned 200)')

    // Step 4: Revoke own session via the UI
    const revokeButton = page.getByRole('button', { name: 'Logout & Revoke' })
    await revokeButton.click()
    await page.waitForURL('/', { timeout: 15000 })
    await expect(page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })).toBeVisible()
    console.log('🚪 Logout & Revoke completed')

    // Step 5: The captured session must now be rejected server-side
    const afterAdmin = await fetch(`${proxyUrl}/admin/version`, {
      headers: {
        Origin: 'http://127.0.0.1:3333',
        Authorization: `Bearer ${sessionId}`
      }
    })
    expect(afterAdmin.status).toBe(401)
    console.log('✅ Admin endpoint correctly rejected revoked session with 401')

    const afterRefresh = await fetch(`${proxyUrl}/proxy/refreshAccessToken`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://127.0.0.1:3333',
        Authorization: `Bearer ${sessionId}`
      }
    })
    expect(afterRefresh.status).toBe(401)
    console.log('✅ Token refresh correctly rejected revoked session with 401')

    console.log('\n✅ Self-scoped session revoke test completed!\n')
  })
})
