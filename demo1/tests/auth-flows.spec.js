/**
 * Authentication Flow Tests
 *
 * Tests various authentication scenarios:
 * 1. Wrong password login attempt
 * 2. Direct access with captured token
 * 3. Token revocation and failed re-use
 * 4. Token refresh and direct login with refreshed token
 */

import { test, expect } from './fixtures.js'
import {
  navigateToLogin,
  loginWithEEN,
  loginToApplication,
  logoutFromApplication,
  captureCredentialsFromProfile,
  loginWithDirectAccess,
  refreshTokenFromProfile,
  clearAppState,
  MAX_TEST_TIMEOUT
} from './utils.js'

test.describe('Authentication Flows', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing state before each test
    await page.goto('/')
    await clearAppState(page)
  })

  test('should fail login with wrong password', async ({ page }) => {
    console.log('\n▶️ Running Test: Wrong password login\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Navigate to login page
    await navigateToLogin(page)

    // Click sign in button
    const loginButton = page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })
    await loginButton.click()
    console.log('👆 Clicked Sign in button')

    // Complete EEN OAuth flow with WRONG password
    await loginWithEEN(page, 'wrong-password-12345')

    // Should stay on EEN page with error message
    // EEN shows error message when password is wrong
    await page.waitForTimeout(3000) // Wait for error to appear

    // Check that we're still on EEN auth page (not redirected back)
    const currentUrl = page.url()
    expect(currentUrl).toMatch(/eagleeyenetworks\.com/)
    console.log('✅ Still on EEN page (login failed as expected)')

    // Look for error message on the page
    const errorVisible = await page.locator('text=/incorrect|invalid|error|failed/i').isVisible().catch(() => false)
    if (errorVisible) {
      console.log('✅ Error message visible on EEN page')
    }

    console.log('\n✅ Wrong password test completed!\n')
  })

  test('should login via direct access with captured token', async ({ page }) => {
    console.log('\n▶️ Running Test: Direct access with captured token\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    // Step 1: Login via OAuth to get a valid token
    await loginToApplication(page)

    // Step 2: Wait for profile to load and capture credentials
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })
    const credentials = await captureCredentialsFromProfile(page)
    console.log('📋 Credentials captured from profile page')

    // Step 3: Clear app state (simulates closing browser)
    await clearAppState(page)
    console.log('🧹 Cleared app state')

    // Step 4: Navigate to login page to confirm we're logged out
    await page.goto('/')
    await expect(page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })).toBeVisible()
    console.log('✅ Confirmed logged out state')

    // Step 5: Use direct access with captured credentials
    await loginWithDirectAccess(page, credentials)

    // Step 6: Should redirect to profile page
    await page.waitForURL('/profile', { timeout: 15000 })
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })
    console.log('✅ Successfully logged in via direct access')

    console.log('\n✅ Direct access with captured token test completed!\n')
  })

  test('should fail token refresh after revocation', async ({ page, context }) => {
    console.log('\n▶️ Running Test: Token refresh fails after revocation\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    // Step 1: Login via OAuth to get a valid session
    await loginToApplication(page)

    // Step 2: Verify we're on profile page
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })
    console.log('✅ Logged in and on profile page')

    // Step 3: Capture the session cookie before logout (proxy uses 'sessionId')
    const cookies = await context.cookies()
    const sessionCookie = cookies.find(c => c.name === 'sessionId')
    expect(sessionCookie, 'Session cookie must exist after login').toBeTruthy()
    const sessionId = sessionCookie.value
    console.log('📋 Session ID captured: yes')

    // Step 4: Revoke token and logout
    await logoutFromApplication(page)
    console.log('🚪 Token revoked and logged out')

    // Step 5: Try to refresh using the old session ID via direct API call
    // Using Authorization Bearer header (supported by proxy for mobile/cross-site scenarios)
    const proxyUrl = process.env.VITE_PROXY_URL || 'http://localhost:8787'
    console.log(`🔄 Attempting refresh against ${proxyUrl}/proxy/refreshAccessToken`)

    // Add timeout to prevent test from hanging indefinitely
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), MAX_TEST_TIMEOUT)

    try {
      // Using Authorization Bearer header instead of credentials: 'include' because:
      // 1. The session cookie was cleared by logout, so there's nothing to include
      // 2. We're explicitly testing with the captured (now-revoked) session ID
      // 3. The proxy supports Bearer token auth for mobile/cross-site scenarios
      const refreshResponse = await fetch(`${proxyUrl}/proxy/refreshAccessToken`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://127.0.0.1:3333',
          'Authorization': `Bearer ${sessionId}`
        },
        signal: controller.signal
      })

      console.log(`📋 Refresh response status: ${refreshResponse.status}`)

      // Step 6: Verify refresh fails (401 - session no longer exists)
      expect(refreshResponse.status).toBe(401)
      console.log('✅ Refresh correctly rejected with 401 (session revoked)')

      const responseData = await refreshResponse.json().catch(() => ({}))
      console.log(`📋 Response: ${JSON.stringify(responseData)}`)
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error(`Refresh request timed out after ${MAX_TEST_TIMEOUT / 1000} seconds`)
      }
      throw error
    } finally {
      clearTimeout(timeoutId)
    }

    console.log('\n✅ Token refresh after revocation test completed!\n')
  })

  test('should refresh token and use it for direct login', async ({ page }) => {
    console.log('\n▶️ Running Test: Token refresh and direct login\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    // Step 1: Login via OAuth
    await loginToApplication(page)

    // Step 2: Wait for profile to load
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })

    // Step 3: Capture original credentials
    const originalCredentials = await captureCredentialsFromProfile(page)
    console.log('📋 Original credentials captured')

    // Step 4: Refresh the token
    await refreshTokenFromProfile(page)
    console.log('🔄 Token refreshed')

    // Step 5: Wait a moment for UI to update
    await page.waitForTimeout(1000)

    // Step 6: Capture new credentials (token should be different)
    const newCredentials = await captureCredentialsFromProfile(page)
    console.log('📋 New credentials captured after refresh')

    // Verify the token actually changed
    if (originalCredentials.token !== newCredentials.token) {
      console.log('✅ Token changed after refresh')
    } else {
      console.log('⚠️ Token appears unchanged (may be same token returned)')
    }

    // Step 7: Clear app state
    await clearAppState(page)
    console.log('🧹 Cleared app state')

    // Step 8: Use direct access with NEW token
    await page.goto('/')
    await loginWithDirectAccess(page, newCredentials)

    // Step 9: Should successfully redirect to profile
    await page.waitForURL('/profile', { timeout: 15000 })
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })
    console.log('✅ Successfully logged in with refreshed token')

    console.log('\n✅ Token refresh test completed!\n')
  })

  test('should verify old token behavior after refresh and logout', async ({ page }) => {
    // NOTE: This test verifies token behavior after refresh + logout.
    // EEN's behavior may vary:
    // - Standard OAuth: Access tokens are stateless JWTs valid until expiration
    // - EEN may invalidate access tokens when refresh token is revoked
    // This test accepts EITHER outcome since EEN's behavior is non-deterministic.
    console.log('\n▶️ Running Test: Old token behavior after refresh and logout\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    // Step 1: Login via OAuth
    await loginToApplication(page)

    // Step 2: Capture original credentials
    await expect(page.locator('h3', { hasText: 'User Profile' })).toBeVisible({ timeout: 15000 })
    const originalCredentials = await captureCredentialsFromProfile(page)
    console.log('📋 Original credentials captured')

    // Step 3: Refresh the token
    await refreshTokenFromProfile(page)
    console.log('🔄 Token refreshed')

    // Step 4: Logout (revokes refresh token at EEN)
    await logoutFromApplication(page)
    console.log('🚪 Logged out (refresh token revoked)')

    // Step 5: Try direct access with the OLD token
    await loginWithDirectAccess(page, originalCredentials)

    // Step 6: Wait for result - EEN behavior may vary
    await page.waitForTimeout(5000)

    // Check outcome - either the token works OR it's rejected
    const currentUrl = page.url()
    const onProfile = currentUrl.includes('/profile')
    const onDirect = currentUrl.includes('/direct')
    const errorVisible = await page.locator('text=/expired|invalid|unauthorized|failed/i').isVisible().catch(() => false)

    if (onProfile) {
      // Token still valid - standard OAuth behavior (stateless JWT)
      console.log('✅ Old token still valid (standard OAuth behavior - access tokens are stateless JWTs)')
    } else if (onDirect || errorVisible) {
      // Token rejected - EEN may invalidate access tokens upon refresh token revocation
      console.log('✅ Old token rejected (EEN invalidates access tokens on revocation)')
    }

    // Test passes either way - we're documenting EEN's behavior, not enforcing specific behavior
    console.log(`📋 Final URL: ${currentUrl}`)
    console.log(`📋 On Profile: ${onProfile}, On Direct: ${onDirect}, Error Visible: ${errorVisible}`)

    // Just ensure we ended up somewhere expected (either profile or direct with error)
    expect(onProfile || onDirect).toBe(true)

    console.log('\n✅ Old token behavior test completed!\n')
  })

  test.describe('with expected OAuth state rejection', () => {
    // This test deliberately presents an invalid OAuth state; the app logs
    // the rejection via console.error, which is the behavior under test
    test.use({ allowedConsoleErrors: [/Invalid OAuth state/] })

    test('should fail login if OAuth state is invalid (CSRF protection)', async ({ page }) => {
      console.log('\n▶️ Running Test: Invalid OAuth state (CSRF)\n')
      test.setTimeout(MAX_TEST_TIMEOUT)

    // Step 1: Inject a known 'state' into sessionStorage, simulating the start of a login flow
    await page.goto('/')
    await page.evaluate(() => {
      sessionStorage.setItem('oauth_state', 'my-secret-test-state')
    })
    console.log('🤫 Injected known state into sessionStorage')

    // Step 2: Intercept the getAccessToken call to prevent it from failing on the fake code
    await page.route('**/proxy/getAccessToken*', async (route) => {
      console.log('➡️ Intercepted getAccessToken call')
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          accessToken: 'fake-token-for-testing',
          expiresIn: 3600,
          userEmail: 'test@example.com'
        })
      })
    })

    // Step 3: Navigate to the callback URL with a valid-looking code but an *invalid* state
    const callbackUrl = `/?code=fake-code-for-csrf-test&state=this-is-wrong`
    await page.goto(callbackUrl)
    console.log(`🔀 Navigated to callback with invalid state: ${callbackUrl}`)

    // Step 4: Check for the specific CSRF error message
    // The app should detect the state mismatch and show an error.
    await expect(page.locator('text=Invalid OAuth state')).toBeVisible({ timeout: 10000 })
    console.log('✅ Error message displayed for invalid state')

    // Verify we are still on the login page and not redirected
    const currentUrl = page.url()
    expect(currentUrl).not.toContain('/profile')
    console.log('✅ Confirmed not redirected to profile')

    console.log('\n✅ CSRF (state) protection test completed!\n')
  })

  test('should fail login if OAuth state is missing (CSRF protection)', async ({ page }) => {
    console.log('\n▶️ Running Test: Missing OAuth state (CSRF)\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Step 1: Inject a known 'state' into sessionStorage, simulating the start of a login flow
    await page.goto('/')
    await page.evaluate(() => {
      sessionStorage.setItem('oauth_state', 'my-secret-test-state')
    })
    console.log('🤫 Injected known state into sessionStorage')

    // Step 2: Intercept the getAccessToken call to prevent it from failing on the fake code
    await page.route('**/proxy/getAccessToken*', async (route) => {
      console.log('➡️ Intercepted getAccessToken call')
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          accessToken: 'fake-token-for-testing',
          expiresIn: 3600,
          userEmail: 'test@example.com'
        })
      })
    })

    // Step 3: Navigate to the callback URL with a code but NO state parameter
    const callbackUrl = `/?code=fake-code-for-csrf-test`
    await page.goto(callbackUrl)
    console.log(`🔀 Navigated to callback with missing state: ${callbackUrl}`)

    // Step 4: Check for the specific CSRF error message
    // The app should detect the missing state and show an error.
    await expect(page.locator('text=Invalid OAuth state')).toBeVisible({ timeout: 10000 })
    console.log('✅ Error message displayed for missing state')

    // Verify we are still on the login page and not redirected
    const currentUrl = page.url()
    expect(currentUrl).not.toContain('/profile')
    console.log('✅ Confirmed not redirected to profile')

    console.log('\n✅ Missing state protection test completed!\n')
  })
  })
})
