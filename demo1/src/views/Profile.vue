<template>
  <div class="min-h-screen bg-gray-50 py-6 px-4 sm:px-6 lg:px-8">
    <div class="max-w-3xl mx-auto">
      <!-- Loading state -->
      <div v-if="loading && !userProfile" class="bg-white shadow rounded-lg p-8 text-center">
        <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p class="mt-4 text-gray-600">Loading your profile...</p>
      </div>

      <!-- Error state -->
      <div v-else-if="error" class="bg-white shadow rounded-lg p-8 text-center">
        <p class="text-red-600">{{ error }}</p>
        <button
          class="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          @click="fetchUserProfile"
        >
          Retry
        </button>
      </div>

      <!-- Profile content -->
      <div v-else class="space-y-6">
        <!-- Header row with title, proxy URL, and version -->
        <div class="flex justify-between items-center">
          <div class="flex items-center gap-4">
            <h1 class="text-2xl font-bold text-gray-900">{{ appTitle }}</h1>
            <span class="text-sm text-gray-500">
              OAuth Proxy: <span class="font-mono text-gray-700">{{ proxyUrl }}</span>
            </span>
          </div>
          <a
            :href="githubRepoUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-gray-500 hover:text-blue-600 hover:underline"
          >
            v{{ appVersion }}
          </a>
        </div>

        <!-- User Profile Card -->
        <div class="bg-white shadow rounded-lg overflow-hidden">
          <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
            <h3 class="text-lg font-medium text-gray-900">User Profile</h3>
            <p class="mt-1 text-sm text-gray-500">Your Eagle Eye Networks account information</p>
          </div>

          <div class="px-4 py-5 sm:p-6">
            <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
              <div>
                <dt class="text-sm font-medium text-gray-500">First Name</dt>
                <dd class="mt-1 text-sm text-gray-900">{{ userProfile?.firstName || 'N/A' }}</dd>
              </div>
              <div>
                <dt class="text-sm font-medium text-gray-500">Last Name</dt>
                <dd class="mt-1 text-sm text-gray-900">{{ userProfile?.lastName || 'N/A' }}</dd>
              </div>
              <div class="sm:col-span-2">
                <dt class="text-sm font-medium text-gray-500">Email</dt>
                <dd class="mt-1 text-sm text-gray-900">{{ userProfile?.email || 'N/A' }}</dd>
              </div>
              <div class="sm:col-span-2">
                <dt class="text-sm font-medium text-gray-500">User ID</dt>
                <dd class="mt-1 text-sm text-gray-900 font-mono">{{ userProfile?.id || 'N/A' }}</dd>
              </div>
            </dl>
          </div>
        </div>

        <!-- Credentials Card -->
        <div class="bg-white shadow rounded-lg overflow-hidden">
          <div class="px-4 py-5 sm:px-6 border-b border-gray-200">
            <h3 class="text-lg font-medium text-gray-900">Credentials</h3>
          </div>

          <div class="px-4 py-5 sm:p-6 space-y-4">
            <!-- Base URL -->
            <div class="flex items-center space-x-4">
              <label class="w-28 flex-shrink-0 text-sm font-medium text-gray-500">Base URL</label>
              <input
                :value="authStore.hostname"
                readonly
                class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-sm"
              />
              <button
                class="px-3 py-2 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700"
                @click="copyToClipboard(authStore.hostname)"
              >
                Copy
              </button>
            </div>

            <!-- Port -->
            <div class="flex items-center space-x-4">
              <label class="w-28 flex-shrink-0 text-sm font-medium text-gray-500">Port</label>
              <input
                :value="authStore.port"
                readonly
                class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-sm"
              />
            </div>

            <!-- Access Token -->
            <div class="flex items-center space-x-4">
              <label class="w-28 flex-shrink-0 text-sm font-medium text-gray-500">Access Token</label>
              <input
                :type="showToken ? 'text' : 'password'"
                :value="authStore.token"
                readonly
                class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-sm font-mono"
              />
              <button
                class="px-3 py-2 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700"
                @click="toggleAndCopyToken"
              >
                {{ showToken ? 'Hide' : 'Show & Copy' }}
              </button>
            </div>

            <!-- Token Expiration -->
            <div class="flex items-center space-x-4">
              <label class="w-28 flex-shrink-0 text-sm font-medium text-gray-500">Expiration</label>
              <div class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-sm">
                {{ tokenExpirationText }}
              </div>
            </div>

            <!-- Refresh Token Status -->
            <div class="flex items-center space-x-4">
              <label class="w-28 flex-shrink-0 text-sm font-medium text-gray-500">Refresh Token</label>
              <input
                :value="authStore.refreshTokenMarker ? 'Available' : 'Not available'"
                readonly
                class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50 text-sm"
              />
              <button
                v-if="authStore.refreshTokenMarker"
                :disabled="isRefreshing"
                class="px-3 py-2 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700 disabled:opacity-50"
                @click="handleRefresh"
              >
                {{ isRefreshing ? 'Refreshing...' : 'Refresh' }}
              </button>
            </div>
          </div>
        </div>

        <!-- Actions Card -->
        <div class="bg-white shadow rounded-lg overflow-hidden">
          <div class="px-4 py-5 sm:p-6 flex justify-end">
            <button
              :disabled="isLoggingOut"
              class="px-4 py-2 bg-red-600 text-white text-sm rounded-md hover:bg-red-700 disabled:opacity-50"
              @click="handleLogout"
            >
              {{ isLoggingOut ? 'Logging out...' : 'Revoke & Logout' }}
            </button>
          </div>
        </div>
      </div>

      <!-- Session Expired Modal (z-[60] to override other modals) -->
      <div
        v-if="authStore.refreshFailed"
        class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60]"
      >
        <div class="bg-white rounded-lg p-5 max-w-sm mx-4">
          <h3 class="text-base font-bold text-orange-500 mb-3">Session Expired</h3>
          <p class="text-sm text-gray-700 mb-4">
            Your session could not be refreshed automatically. Please log in again to continue.
          </p>
          <p v-if="authStore.refreshFailedMessage" class="text-xs text-gray-500 italic mb-4">
            {{ authStore.refreshFailedMessage }}
          </p>
          <button
            class="w-full px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
            @click="handleRefreshFailureAck"
          >
            Go to Login
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { getUserProfile } from '../services/user'
import { refreshToken as refreshTokenService } from '../services/auth'
import { getProxyUrl } from '../services/proxy'
import packageJson from '../../package.json'

const router = useRouter()
const authStore = useAuthStore()

const loading = ref(false)
const error = ref(null)
const showToken = ref(false)
const isRefreshing = ref(false)
const isLoggingOut = ref(false)
const forceUpdate = ref(0)

let expirationInterval = null

const userProfile = computed(() => authStore.userProfile)
const appTitle = computed(() => packageJson.displayName || packageJson.name)
const appVersion = computed(() => packageJson.version)
const githubRepoUrl = computed(() => {
  const baseUrl = import.meta.env.VITE_GITHUB_REPO || 'https://github.com/your-username/een-oauth-proxy'
  const branch = import.meta.env.VITE_GITHUB_BRANCH || 'develop'
  return `${baseUrl}/tree/${branch}`
})
const proxyUrl = computed(() => getProxyUrl())

const tokenExpirationText = computed(() => {
  forceUpdate.value // Trigger reactivity
  const remaining = authStore.getTokenTimeRemaining()

  if (remaining === null || remaining === undefined) {
    return 'Unknown'
  }
  if (remaining <= 0) {
    return 'Token expired'
  }

  const hours = Math.floor(remaining / 3600000)
  const minutes = Math.floor((remaining % 3600000) / 60000)
  const seconds = Math.floor((remaining % 60000) / 1000)

  // Calculate absolute expiration time
  const expirationTime = new Date(Date.now() + remaining)
  const timeString = expirationTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  // Determine day indicator
  const today = new Date()
  const tomorrow = new Date(today)
  tomorrow.setDate(tomorrow.getDate() + 1)

  let dayIndicator
  if (expirationTime.toDateString() === today.toDateString()) {
    dayIndicator = 'today'
  } else if (expirationTime.toDateString() === tomorrow.toDateString()) {
    dayIndicator = 'tomorrow'
  } else {
    dayIndicator = expirationTime.toLocaleDateString()
  }

  let remainingText
  if (hours >= 1) {
    remainingText = `${hours}h ${minutes}m remaining`
  } else if (minutes >= 1) {
    remainingText = `${minutes}m ${seconds}s remaining`
  } else {
    remainingText = `${seconds}s remaining`
  }

  return `${remainingText} (expires at ${timeString} ${dayIndicator})`
})

async function fetchUserProfile() {
  if (authStore.userProfile) {
    return // Already have profile
  }

  loading.value = true
  error.value = null

  try {
    const data = await getUserProfile()
    authStore.setUserProfile({
      id: data.id,
      firstName: data.firstName,
      lastName: data.lastName,
      email: data.email
    })
  } catch (e) {
    error.value = e.message || 'Failed to load profile'
  } finally {
    loading.value = false
  }
}

function copyToClipboard(text) {
  if (text) {
    // Clipboard access can be denied (permissions, insecure context) - the
    // copy is a convenience, not worth an uncaught rejection
    navigator.clipboard.writeText(text).catch(() => {})
  }
}

function toggleAndCopyToken() {
  showToken.value = !showToken.value
  if (showToken.value && authStore.token) {
    navigator.clipboard.writeText(authStore.token).catch(() => {})
  }
}

async function handleRefresh() {
  if (isRefreshing.value) return

  isRefreshing.value = true
  try {
    await refreshTokenService()
    showToken.value = false
    forceUpdate.value++
  } catch (e) {
    error.value = e.message || 'Failed to refresh token'
  } finally {
    isRefreshing.value = false
  }
}

async function handleLogout() {
  if (isLoggingOut.value) return

  isLoggingOut.value = true
  try {
    await authStore.logout()
    router.push('/')
  } catch (e) {
    console.error('Logout error:', e)
    // Still navigate to login even on error
    router.push('/')
  }
}

function handleRefreshFailureAck() {
  authStore.acknowledgeRefreshFailure()
  router.push('/')
}

onMounted(async () => {
  document.title = `${appTitle.value} - Profile`
  await fetchUserProfile()

  // Update expiration display every second
  expirationInterval = setInterval(() => {
    forceUpdate.value++
  }, 1000)
})

onUnmounted(() => {
  if (expirationInterval) {
    clearInterval(expirationInterval)
  }
})
</script>
