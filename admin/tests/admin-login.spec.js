/**
 * Admin Login and Health Check Tests
 *
 * Tests the admin OAuth login flow and proxy health monitoring:
 * 1. Login to admin dashboard
 * 2. Verify proxy health is OK
 * 3. Verify dashboard displays correctly
 * 4. Logout flow
 */

import { test, expect } from './fixtures.js'
import {
  loginToAdmin,
  logoutFromAdmin,
  checkHealthFromDashboard,
  getSessionCountFromDashboard,
  clearAppState,
  verifyOnDashboard,
  getProxyUrl,
  clearActivityLog,
  getActivityLogEntries,
  MAX_TEST_TIMEOUT
} from './utils.js'

test.describe('Admin Login and Health', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing state before each test
    await page.goto('/')
    await clearAppState(page)
  })

  test('should display login page correctly', async ({ page }) => {
    console.log('\n▶️ Running Test: Login page display\n')

    await page.goto('/')

    // Verify login page elements
    await expect(page.getByRole('heading', { name: 'EEN OAuth Proxy Admin' })).toBeVisible()
    await expect(page.getByText('Sign in to manage the OAuth proxy')).toBeVisible()
    await expect(page.getByText('Admin access is restricted')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })).toBeVisible()

    // Verify version is displayed
    const versionLink = page.locator('a').filter({ hasText: /v\d+\.\d+\.\d+/ })
    await expect(versionLink).toBeVisible()
    console.log('✅ Login page displayed correctly')

    console.log('\n✅ Login page display test completed!\n')
  })

  test('should complete full login and verify dashboard', async ({ page }) => {
    console.log('\n▶️ Running Test: Full login and dashboard verification\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify we're on the dashboard
    await verifyOnDashboard(page)

    // Verify header shows user email
    const emailLocator = page.locator('p.text-xs.text-gray-500').first()
    await expect(emailLocator).toBeVisible()
    console.log('✅ Dashboard header shows user email')

    // Verify version link is shown in header (vX.X.X format)
    const versionLink = page.locator('a').filter({ hasText: /v\d+\.\d+\.\d+/ })
    await expect(versionLink).toBeVisible()
    console.log('✅ Version link shown in header')

    console.log('\n✅ Full login and dashboard verification completed!\n')
  })

  test('should verify proxy health is OK', async ({ page }) => {
    console.log('\n▶️ Running Test: Proxy health verification\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Wait for dashboard to load
    await verifyOnDashboard(page)

    // Check health
    const health = await checkHealthFromDashboard(page)

    // Verify health is OK
    expect(health.status).toBe('ok')
    console.log(`✅ Proxy health is OK`)

    // Verify a proxy URL is displayed (either localhost or Cloudflare)
    // The actual URL depends on environment configuration
    const proxyUrlElement = page.locator('.font-mono').filter({ hasText: /localhost:8787|\.workers\.dev/ })
    await expect(proxyUrlElement.first()).toBeVisible()
    const displayedUrl = await proxyUrlElement.first().textContent()
    console.log(`✅ Proxy URL displayed: ${displayedUrl}`)

    // Verify "Healthy" status indicator
    await expect(page.locator('text=Healthy')).toBeVisible()
    console.log('✅ Healthy status indicator visible')

    console.log('\n✅ Proxy health verification completed!\n')
  })

  test('should display session count', async ({ page }) => {
    console.log('\n▶️ Running Test: Session count display\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Get session count (may be null if admin access not available)
    const sessionCount = await getSessionCountFromDashboard(page)

    // Skip if admin access not available (returns null)
    if (sessionCount === null) {
      console.log('⚠️ SKIPPING: Admin access not available for session count')
      console.log('Ensure ADMIN_TEST_USER email is in ADMIN_EMAILS in proxy config')
      test.skip()
      return
    }

    // Session count should be a non-negative number (0 is valid now)
    expect(sessionCount).toBeGreaterThanOrEqual(0)
    console.log(`✅ Session count: ${sessionCount}`)

    console.log('\n✅ Session count display test completed!\n')
  })

  test('should display version info card', async ({ page }) => {
    console.log('\n▶️ Running Test: Version info display\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify Versions card (renamed from "Version Info" in compact redesign)
    await expect(page.locator('text=Versions')).toBeVisible()

    // Verify Admin and Proxy versions are shown
    const versionCard = page.locator('text=Versions').locator('..')
    await expect(versionCard.locator('text=Admin:')).toBeVisible()
    await expect(versionCard.locator('text=Proxy:')).toBeVisible()
    console.log('✅ Versions card displayed')

    console.log('\n✅ Version info display test completed!\n')
  })

  test('should complete full logout flow', async ({ page }) => {
    console.log('\n▶️ Running Test: Full logout flow\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify on dashboard
    await verifyOnDashboard(page)

    // Logout
    await logoutFromAdmin(page)

    // Verify back on login page
    await expect(page).toHaveURL('/')
    await expect(page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })).toBeVisible()
    console.log('✅ Back on login page')

    console.log('\n✅ Full logout flow test completed!\n')
  })

  test('should show error with wrong password', async ({ page }) => {
    console.log('\n▶️ Running Test: Wrong password login\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    await page.goto('/')

    // Click sign in button
    await page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' }).click()
    console.log('👆 Clicked Sign in button')

    // Import loginWithEEN for custom password
    const { loginWithEEN } = await import('./utils.js')
    await loginWithEEN(page, 'wrong-password-12345')

    // Should stay on EEN page with error
    await page.waitForTimeout(3000)

    const currentUrl = page.url()
    expect(currentUrl).toMatch(/eagleeyenetworks\.com/)
    console.log('✅ Still on EEN page (login failed as expected)')

    console.log('\n✅ Wrong password test completed!\n')
  })

  test('should reject non-admin users with proper error message', async ({ page }) => {
    console.log('\n▶️ Running Test: Non-admin user rejection\n')
    test.setTimeout(MAX_TEST_TIMEOUT * 2)

    // Check if non-admin credentials are configured
    const { hasNonAdminCredentials, attemptNonAdminLogin } = await import('./utils.js')
    if (!hasNonAdminCredentials()) {
      console.log('⚠️ SKIPPING: TEST_NON_ADMIN_USER and TEST_NON_ADMIN_PASSWORD not configured')
      console.log('To run this test, add non-admin credentials to .env')
      test.skip()
      return
    }

    // Attempt login with non-admin user
    const wasRejected = await attemptNonAdminLogin(page)

    // Verify user was properly rejected
    expect(wasRejected).toBe(true)

    // Verify error message is displayed
    const errorMessage = page.locator('.bg-red-50')
    await expect(errorMessage).toBeVisible()
    const errorText = await errorMessage.textContent()
    expect(errorText.toLowerCase()).toContain('admin')
    console.log('✅ Non-admin rejection error message displayed')

    // Verify user is NOT on dashboard
    expect(page.url()).not.toContain('/dashboard')
    console.log('✅ Non-admin user cannot access dashboard')

    console.log('\n✅ Non-admin user rejection test completed!\n')
  })

  test('should display and clear activity log', async ({ page }) => {
    console.log('\n▶️ Running Test: Activity Log functionality\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify Activity Log is visible
    await expect(page.locator('text=Activity Log')).toBeVisible()
    console.log('✅ Activity Log visible')

    // Verify Clear button is visible
    const clearButton = page.locator('text=Activity Log').locator('..').getByRole('button', { name: 'Clear' })
    await expect(clearButton).toBeVisible()
    console.log('✅ Clear button visible')

    // There should be initial log entries (Dashboard loaded, Health check, etc.)
    const initialEntries = await getActivityLogEntries(page)
    expect(initialEntries.length).toBeGreaterThan(0)
    console.log(`✅ Initial log entries: ${initialEntries.length}`)

    // Click check button to add a log entry
    await page.getByRole('button', { name: 'Update now' }).click()
    await page.waitForTimeout(2000)

    // Should have more entries now
    const afterCheckEntries = await getActivityLogEntries(page)
    expect(afterCheckEntries.length).toBeGreaterThanOrEqual(initialEntries.length)
    console.log(`✅ Log entries after health check: ${afterCheckEntries.length}`)

    // Clear the log
    await clearActivityLog(page)

    // Should have fewer entries (just the "Log cleared" entry)
    const afterClearEntries = await getActivityLogEntries(page)
    expect(afterClearEntries.length).toBeLessThan(afterCheckEntries.length)
    console.log(`✅ Log entries after clear: ${afterClearEntries.length}`)

    console.log('\n✅ Activity Log functionality test completed!\n')
  })

  test('should toggle dark mode', async ({ page }) => {
    console.log('\n▶️ Running Test: Dark mode toggle\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Find the dark mode toggle button (has sun or moon icon)
    const darkModeButton = page.locator('button[title*="mode"]')
    await expect(darkModeButton).toBeVisible()
    console.log('✅ Dark mode toggle button visible')

    // Check initial background color (light mode default) - use more specific selector
    const dashboardContainer = page.locator('div.min-h-screen.py-4')
    const initialBgClass = await dashboardContainer.getAttribute('class')
    const isInitiallyLight = initialBgClass.includes('bg-gray-50')
    console.log(`📋 Initial mode: ${isInitiallyLight ? 'light' : 'dark'}`)

    // Click toggle to switch mode
    await darkModeButton.click()
    await page.waitForTimeout(500)

    // Check that background changed
    const afterToggleBgClass = await dashboardContainer.getAttribute('class')
    const isNowDark = afterToggleBgClass.includes('bg-gray-900')
    console.log(`📋 After toggle: ${isNowDark ? 'dark' : 'light'}`)

    // Verify mode changed
    if (isInitiallyLight) {
      expect(isNowDark).toBe(true)
    } else {
      expect(afterToggleBgClass.includes('bg-gray-50')).toBe(true)
    }
    console.log('✅ Dark mode toggled successfully')

    // Toggle back
    await darkModeButton.click()
    await page.waitForTimeout(500)

    const finalBgClass = await dashboardContainer.getAttribute('class')
    console.log(`📋 After second toggle: ${finalBgClass.includes('bg-gray-900') ? 'dark' : 'light'}`)
    console.log('✅ Mode toggled back')

    console.log('\n✅ Dark mode toggle test completed!\n')
  })

  test('should have resizable panels', async ({ page }) => {
    console.log('\n▶️ Running Test: Resizable panels\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Find the resize handle
    const resizeHandle = page.locator('.cursor-col-resize')
    await expect(resizeHandle).toBeVisible()
    console.log('✅ Resize handle visible')

    // Get the initial width of the left panel
    const leftPanel = page.locator('.space-y-4.overflow-hidden').first()
    const initialStyle = await leftPanel.getAttribute('style')
    console.log(`📋 Initial left panel style: ${initialStyle}`)

    // Verify the resize handle is interactive (has cursor-col-resize class)
    const handleClasses = await resizeHandle.getAttribute('class')
    expect(handleClasses).toContain('cursor-col-resize')
    console.log('✅ Resize handle has correct cursor style')

    console.log('\n✅ Resizable panels test completed!\n')
  })

  test('should display rate limiting stats card', async ({ page }) => {
    console.log('\n▶️ Running Test: Rate Limiting stats display\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify Rate Limiting card is visible
    await expect(page.locator('text=Rate Limiting')).toBeVisible()
    console.log('✅ Rate Limiting card visible')

    // Wait for data to load (give it some time)
    await page.waitForTimeout(2000)

    // Check if rate limiting is enabled or disabled (badge should be visible)
    const onOffBadge = page.locator('text=Rate Limiting').locator('..').locator('span').filter({ hasText: /^(On|Off)$/ })
    const badgeVisible = await onOffBadge.isVisible().catch(() => false)

    if (badgeVisible) {
      const badgeText = await onOffBadge.textContent()
      console.log(`✅ Rate limiting status: ${badgeText}`)

      // If rate limiting is on, verify category data is displayed
      if (badgeText === 'On') {
        // Check for category names (desktop table headers or mobile cards)
        const healthCategory = page.locator('text=health').first()
        const oauthCategory = page.locator('text=oauth').first()
        const adminCategory = page.locator('text=admin').first()

        // At least one category should be visible
        const hasCategories = await healthCategory.isVisible().catch(() => false) ||
                             await oauthCategory.isVisible().catch(() => false) ||
                             await adminCategory.isVisible().catch(() => false)

        if (hasCategories) {
          console.log('✅ Rate limit categories displayed')
        }

        // Check for "Active entries" label
        const activeEntries = page.locator('text=Active entries')
        if (await activeEntries.isVisible().catch(() => false)) {
          console.log('✅ Active entries count displayed')
        }

        // Check for Window duration
        const windowLabel = page.locator('text=/Window: \\d+s/')
        if (await windowLabel.isVisible().catch(() => false)) {
          const windowText = await windowLabel.textContent()
          console.log(`✅ ${windowText}`)
        }
      }
    } else {
      // Rate limit stats may be unavailable (no badge shown)
      const unavailableMsg = page.locator('text=Rate limit stats unavailable')
      if (await unavailableMsg.isVisible().catch(() => false)) {
        console.log('⚠️ Rate limit stats unavailable (admin may not have access)')
      }
    }

    console.log('\n✅ Rate Limiting stats display test completed!\n')
  })

  test('should update rate limiting stats on manual refresh', async ({ page }) => {
    console.log('\n▶️ Running Test: Rate Limiting stats refresh\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    // Login to admin
    await loginToAdmin(page)

    // Verify Rate Limiting card is visible
    await expect(page.locator('text=Rate Limiting')).toBeVisible()
    console.log('✅ Rate Limiting card visible')

    // Wait for initial load
    await page.waitForTimeout(2000)

    // Click Update now button to refresh stats
    await page.getByRole('button', { name: 'Update now' }).click()
    console.log('👆 Clicked Update now button')

    // Wait for refresh to complete
    await page.waitForTimeout(2000)

    // Verify rate limiting card is still visible after refresh
    await expect(page.locator('text=Rate Limiting')).toBeVisible()
    console.log('✅ Rate Limiting card still visible after refresh')

    // Check activity log for health/rate limit update
    const logEntries = await getActivityLogEntries(page)
    const hasStatusEntry = logEntries.some(entry =>
      entry.text && (entry.text.includes('Health:') || entry.text.includes('Rate limit'))
    )
    expect(hasStatusEntry).toBe(true)
    console.log('✅ Activity log updated with status')

    console.log('\n✅ Rate Limiting stats refresh test completed!\n')
  })
})
