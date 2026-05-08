#!/usr/bin/env node

/**
 * Deployment script for EEN OAuth Proxy
 *
 * This script:
 * 1. Reads version from package.json
 * 2. Deploys the worker to Cloudflare
 * 3. Sets secrets from .env file
 * 4. Stores DEPLOY_VERSION in KV
 */

import { execSync } from 'child_process'
import { randomUUID } from 'crypto'
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { config } from 'dotenv'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const projectRoot = join(__dirname, '..')

// Load .env file
const envPath = join(projectRoot, '.env')
if (existsSync(envPath)) {
  config({ path: envPath })
}

// Read package.json
const packageJson = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf-8'))
const version = packageJson.version
const name = packageJson.name

// Generate version string with timestamp
const deployTime = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
const versionString = `${name} - ${version} - ${deployTime}`

console.log('========================================')
console.log('EEN OAuth Proxy Deployment')
console.log('========================================')
console.log(`Version: ${versionString}`)
console.log('')

function run(command, options = {}) {
  console.log(`> ${command}`)
  try {
    // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process — `command` callers are hardcoded strings within this script, not user input
    execSync(command, {
      cwd: projectRoot,
      stdio: 'inherit',
      ...options
    })
  } catch (error) {
    console.error(`Command failed: ${command}`)
    process.exit(1)
  }
}

function runSilent(command) {
  try {
    // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process — `command` callers are hardcoded strings within this script, not user input
    return execSync(command, {
      cwd: projectRoot,
      encoding: 'utf-8'
    }).trim()
  } catch (error) {
    return null
  }
}

// Check if KV namespace exists, create if not
console.log('Checking KV namespace...')
const wranglerToml = readFileSync(join(projectRoot, 'wrangler.toml'), 'utf-8')

if (!wranglerToml.includes('id = "') || wranglerToml.includes('# id = "')) {
  console.log('KV namespace not configured. Creating...')

  const output = runSilent('npx wrangler kv namespace create EEN_OAUTH_SESSIONS')
  if (output) {
    // Extract namespace ID from output
    const match = output.match(/id = "([^"]+)"/)
    if (match) {
      const namespaceId = match[1]
      console.log(`Created KV namespace with ID: ${namespaceId}`)
      console.log('')
      console.log('Please update wrangler.toml with:')
      console.log('[[kv_namespaces]]')
      console.log('binding = "EEN_OAUTH_SESSIONS"')
      console.log(`id = "${namespaceId}"`)
      console.log('')
      process.exit(1)
    }
  }
}

// Allowlist of valid secret names (prevents command injection via modified array)
const VALID_SECRET_NAMES = new Set([
  'CLIENT_ID',
  'CLIENT_SECRET',
  'ADMIN_EMAILS',
  'ALLOWED_ORIGINS',
  'ALLOWED_API_DOMAINS',
  'REFRESH_TOKEN_TTL',
  'MAX_KV_KEYS'
])

// Critical secrets that must be set for the proxy to function
const CRITICAL_SECRETS = ['CLIENT_ID', 'CLIENT_SECRET']

const secrets = ['CLIENT_ID', 'CLIENT_SECRET', 'ADMIN_EMAILS', 'ALLOWED_ORIGINS', 'ALLOWED_API_DOMAINS', 'REFRESH_TOKEN_TTL', 'MAX_KV_KEYS']

// Pre-validate all critical secrets exist before any deployment actions
console.log('')
console.log('Validating critical secrets...')
const missingCritical = CRITICAL_SECRETS.filter(secret => !process.env[secret])
if (missingCritical.length > 0) {
  console.error(`Error: Missing critical secrets: ${missingCritical.join(', ')}`)
  console.error('Aborting deployment - all critical secrets must be present')
  process.exit(1)
}
console.log('All critical secrets present')

// Check if worker exists (required before setting secrets)
// Distinguish between "no worker" and "command failed" to avoid false positives
console.log('')
console.log('Checking if worker exists...')
let isFirstDeployment = false
try {
  const output = execSync('npx wrangler deployments list', {
    cwd: projectRoot,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe']
  })
  // If command succeeds but output is empty or shows no deployments, it's first deployment
  // Use case-insensitive check to handle variations in wrangler output
  if (!output || output.trim() === '' || output.toLowerCase().includes('no deployment')) {
    isFirstDeployment = true
  }
} catch (error) {
  const errorMsg = error.stderr?.toString() || error.message || ''
  // Check for specific error messages indicating worker doesn't exist
  if (errorMsg.includes('could not find') || errorMsg.includes('not found') ||
      errorMsg.includes('does not exist') || errorMsg.includes('no deployments')) {
    isFirstDeployment = true
  } else {
    // Other errors (auth, network, etc.) - fail loudly instead of assuming first deployment
    console.error('Error checking worker status:', errorMsg)
    console.error('Cannot determine if worker exists. Please check your credentials and network.')
    process.exit(1)
  }
}

if (isFirstDeployment) {
  console.log('First-time deployment detected, deploying worker first...')
  run('npx wrangler deploy')
  console.log('Initial worker deployed, now setting secrets...')
} else {
  console.log('Worker exists, proceeding with secrets...')
}

// Set secrets (after ensuring worker exists)
console.log('')
console.log('Setting secrets...')

for (const secret of secrets) {
  const value = process.env[secret]
  const isCritical = CRITICAL_SECRETS.includes(secret)

  if (value) {
    // Validate secret name against allowlist (defense in depth)
    if (!VALID_SECRET_NAMES.has(secret)) {
      console.warn(`Warning: Secret name '${secret}' not in allowlist, skipping`)
      continue
    }
    console.log(`Setting ${secret}...`)
    try {
      // Pass secret value via stdin to prevent shell injection
      // Using input option instead of shell interpolation for security
      execSync(`npx wrangler secret put ${secret}`, {
        cwd: projectRoot,
        stdio: ['pipe', 'pipe', 'pipe'],
        input: value
      })
    } catch (error) {
      if (isCritical) {
        console.error(`Error: Failed to set critical secret ${secret}`)
        process.exit(1)
      }
      console.warn(`Warning: Failed to set ${secret}`)
    }
  } else {
    // Non-critical secrets can be missing (critical ones were pre-validated)
    console.warn(`Warning: ${secret} not found in environment`)
  }
}

// Deploy worker with updated secrets (skip if this was a first-time deployment)
if (isFirstDeployment) {
  console.log('')
  console.log('Skipping final deploy (already deployed for first-time setup)')
} else {
  console.log('')
  console.log('Deploying worker...')
  run('npx wrangler deploy')
}

// Store version in KV
console.log('')
console.log('Storing deploy version in KV...')

// Extract namespace ID from wrangler.toml
const namespaceMatch = wranglerToml.match(/id = "([^"]+)"/)
if (namespaceMatch) {
  const namespaceId = namespaceMatch[1]
  // Validate namespace ID format (32-char hex) to prevent injection
  if (!/^[a-f0-9]{32}$/.test(namespaceId)) {
    console.warn('Warning: Invalid namespace ID format, skipping version storage')
  } else {
    // Write version to temp file to avoid shell injection of versionString
    const tmpVersionFile = join(tmpdir(), `deploy-version-${randomUUID()}.tmp`)
    try {
      writeFileSync(tmpVersionFile, versionString)
      execSync(
        `npx wrangler kv key put DEPLOY_VERSION --namespace-id="${namespaceId}" --remote --path="${tmpVersionFile}"`,
        {
          cwd: projectRoot,
          stdio: 'inherit'
        }
      )
    } catch (error) {
      console.warn('Warning: Failed to store deploy version')
    } finally {
      try {
        unlinkSync(tmpVersionFile)
      } catch (cleanupError) {
        console.warn(`Warning: Failed to clean up temp file ${tmpVersionFile}: ${cleanupError.message}`)
      }
    }
  }
}

console.log('')
console.log('========================================')
console.log('Deployment complete!')
console.log('========================================')

// Verify deployment with production tests
console.log('')
console.log('Waiting 5 seconds for deployment to propagate...')

await new Promise(resolve => setTimeout(resolve, 5000))

console.log('')
console.log('Running production verification tests...')
console.log('')

const testScript = join(__dirname, '..', '..', 'scripts', 'test-production-proxy.sh')
const testResult = (() => {
  try {
    execSync(`BRIEF=1 bash "${testScript}"`, {
      cwd: projectRoot,
      stdio: 'inherit'
    })
    return { success: true }
  } catch (error) {
    return { success: false, error }
  }
})()

console.log('')
if (testResult.success) {
  console.log('========================================')
  console.log('Deployment verified successfully!')
  console.log('========================================')
} else {
  console.log('========================================')
  console.log('WARNING: Production verification failed!')
  console.log('The deployment completed but tests failed.')
  if (testResult.error) {
    console.log(`Exit code: ${testResult.error.status || 'unknown'}`)
    if (testResult.error.stderr && testResult.error.stderr.length > 0) {
      console.log(`Error output: ${testResult.error.stderr.toString()}`)
    }
  }
  console.log('Please investigate the proxy status.')
  console.log('========================================')
  process.exit(1)
}
