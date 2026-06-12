/**
 * Admin Destructive Tests (LOCAL PROXY ONLY)
 *
 * These tests perform destructive operations and should ONLY run against
 * a local proxy, never against production.
 *
 * REQUIREMENTS:
 * 1. Local proxy must be running (npm run dev in proxy/)
 * 2. TEST_USER email must be in ADMIN_EMAILS in proxy/.dev.vars
 *
 * Tests include:
 * 1. Remove other sessions
 * 2. Revoke all tokens
 */

import { test, expect } from './fixtures.js'
import {
  loginToAdmin,
  clearAppState,
  verifyOnDashboard,
  getSessionCountFromDashboard,
  hasAdminAccess,
  dismissErrors,
  isLocalProxy,
  getProxyUrl,
  MAX_TEST_TIMEOUT
} from './utils.js'

test.describe('Admin Destructive Operations (Local Proxy Only)', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing state before each test
    await page.goto('/')
    await clearAppState(page)
  })

  test('should verify admin access is available', async ({ page }) => {
    console.log('\n▶️ Running Test: Verify admin access\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    const proxyUrl = getProxyUrl()
    console.log(`📍 Proxy URL: ${proxyUrl}`)
    console.log(`📍 Is local proxy: ${isLocalProxy()}`)

    if (!isLocalProxy()) {
      console.log('⚠️ SKIPPING: Not a local proxy')
      test.skip()
      return
    }

    // Login to admin
    await loginToAdmin(page)

    // Verify on dashboard
    await verifyOnDashboard(page)

    // Check admin access
    const adminAccessOk = await hasAdminAccess(page)

    if (!adminAccessOk) {
      console.log('\n⚠️ ADMIN ACCESS NOT AVAILABLE')
      console.log('Make sure TEST_USER email is in ADMIN_EMAILS in proxy config')
      console.log('This may also occur if the proxy cannot fetch user profile from EEN')
      console.log('SKIPPING test as admin access is required\n')
      test.skip()
      return
    }

    console.log('\n✅ Admin access verification completed!\n')
  })

  test('should remove other sessions', async ({ page }) => {
    console.log('\n▶️ Running Test: Remove other sessions\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    if (!isLocalProxy()) {
      console.log('⚠️ SKIPPING: Not a local proxy')
      test.skip()
      return
    }

    // Login to admin
    await loginToAdmin(page)
    await verifyOnDashboard(page)

    // Check admin access first
    const adminAccessOk = await hasAdminAccess(page)
    if (!adminAccessOk) {
      console.log('⚠️ SKIPPING: Admin access not available')
      console.log('Ensure TEST_USER email is in ADMIN_EMAILS in proxy/.dev.vars')
      test.skip()
      return
    }

    // Dismiss any existing errors
    await dismissErrors(page)

    // Get initial session count
    const initialCount = await getSessionCountFromDashboard(page)
    console.log(`📊 Initial session count: ${initialCount}`)

    // Click "Remove" button - find the row containing "Remove Other Sessions" then get the button
    const removeRow = page.locator('div').filter({ hasText: /Remove Other Sessions/ }).filter({ has: page.getByRole('button', { name: 'Remove' }) }).first()
    const removeButton = removeRow.getByRole('button', { name: 'Remove' })
    await expect(removeButton).toBeVisible()
    await removeButton.click()
    console.log('👆 Clicked Remove')

    // Wait for operation
    await page.waitForTimeout(3000)

    // Check for success in activity log (success entries are text-green-500 in new design)
    const successLog = page.locator('.text-green-500').filter({ hasText: /Removed.*session/i })
    await expect(successLog).toBeVisible({ timeout: 10000 })
    console.log('✅ Success message in activity log')

    // Verify session count is now 1 (current session)
    const newCount = await getSessionCountFromDashboard(page)
    expect(newCount).toBe(1)
    console.log(`📊 New session count: ${newCount}`)

    console.log('\n✅ Remove other sessions test completed!\n')
  })

  test('should revoke all tokens and redirect to login', async ({ page }) => {
    console.log('\n▶️ Running Test: Revoke all tokens\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    if (!isLocalProxy()) {
      console.log('⚠️ SKIPPING: Not a local proxy')
      test.skip()
      return
    }

    // Login to admin
    await loginToAdmin(page)
    await verifyOnDashboard(page)

    // Check admin access first
    const adminAccessOk = await hasAdminAccess(page)
    if (!adminAccessOk) {
      console.log('⚠️ SKIPPING: Admin access not available')
      test.skip()
      return
    }

    // Click "Revoke All" button - find the row containing "Revoke All Tokens" then get the button
    const revokeRow = page.locator('div').filter({ hasText: /Revoke All Tokens/ }).filter({ has: page.getByRole('button', { name: 'Revoke All' }) }).first()
    const revokeButton = revokeRow.getByRole('button', { name: 'Revoke All' })
    await expect(revokeButton).toBeVisible()
    await revokeButton.click()
    console.log('👆 Clicked Revoke All')

    // Confirmation modal should appear
    await expect(page.locator('text=Confirm Revoke All')).toBeVisible()
    console.log('✅ Confirmation modal displayed')

    // Click confirm in modal
    const confirmButton = page.locator('.fixed').getByRole('button', { name: 'Revoke All' })
    await confirmButton.click()
    console.log('👆 Confirmed revoke all')

    // Should be redirected to login page
    await page.waitForURL('/', { timeout: 20000 })
    await expect(page.getByRole('button', { name: 'Sign in with Eagle Eye Networks' })).toBeVisible()
    console.log('✅ Redirected to login page')

    console.log('\n✅ Revoke all tokens test completed!\n')
  })

  test('should cancel revoke all when clicking cancel', async ({ page }) => {
    console.log('\n▶️ Running Test: Cancel revoke all\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    if (!isLocalProxy()) {
      console.log('⚠️ SKIPPING: Not a local proxy')
      test.skip()
      return
    }

    // Login to admin
    await loginToAdmin(page)
    await verifyOnDashboard(page)

    // Check admin access first
    const adminAccessOk = await hasAdminAccess(page)
    if (!adminAccessOk) {
      console.log('⚠️ SKIPPING: Admin access not available')
      test.skip()
      return
    }

    // Click "Revoke All" button - find the row containing "Revoke All Tokens" then get the button
    const revokeRow = page.locator('div').filter({ hasText: /Revoke All Tokens/ }).filter({ has: page.getByRole('button', { name: 'Revoke All' }) }).first()
    const revokeButton = revokeRow.getByRole('button', { name: 'Revoke All' })
    await revokeButton.click()
    console.log('👆 Clicked Revoke All')

    // Modal should appear
    await expect(page.locator('text=Confirm Revoke All')).toBeVisible()
    console.log('✅ Confirmation modal displayed')

    // Click cancel
    await page.getByRole('button', { name: 'Cancel' }).click()
    console.log('👆 Clicked Cancel')

    // Modal should close
    await expect(page.locator('text=Confirm Revoke All')).not.toBeVisible()
    await verifyOnDashboard(page)
    console.log('✅ Modal closed, still on dashboard')

    console.log('\n✅ Cancel revoke all test completed!\n')
  })

  test('should show admin actions section', async ({ page }) => {
    console.log('\n▶️ Running Test: Admin actions section\n')
    test.setTimeout(MAX_TEST_TIMEOUT)

    if (!isLocalProxy()) {
      console.log('⚠️ SKIPPING: Not a local proxy')
      test.skip()
      return
    }

    // Login to admin
    await loginToAdmin(page)
    await verifyOnDashboard(page)

    // Remove Other Sessions action should be visible
    await expect(page.locator('text=Remove Other Sessions')).toBeVisible()
    await expect(page.locator('text=Log out other users')).toBeVisible()
    const removeRow = page.locator('div').filter({ hasText: /Remove Other Sessions/ }).filter({ has: page.getByRole('button', { name: 'Remove' }) }).first()
    const removeButton = removeRow.getByRole('button', { name: 'Remove' })
    await expect(removeButton).toBeVisible()
    console.log('✅ Remove Other Sessions option visible')

    // Revoke All Tokens action should be visible
    await expect(page.locator('text=Revoke All Tokens')).toBeVisible()
    await expect(page.locator('text=Emergency: logs out everyone including you')).toBeVisible()
    const revokeRow = page.locator('div').filter({ hasText: /Revoke All Tokens/ }).filter({ has: page.getByRole('button', { name: 'Revoke All' }) }).first()
    const revokeButton = revokeRow.getByRole('button', { name: 'Revoke All' })
    await expect(revokeButton).toBeVisible()
    console.log('✅ Revoke All Tokens option visible')

    console.log('\n✅ Admin actions section test completed!\n')
  })
})
