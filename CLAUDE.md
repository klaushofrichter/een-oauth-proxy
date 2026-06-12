# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EEN OAuth Proxy — a Cloudflare Worker that securely handles OAuth authentication with Eagle Eye Networks (EEN). It keeps CLIENT_SECRET server-side, stores refresh tokens in Cloudflare KV, and serves two Vue 3 frontend apps (admin + demo1) deployed to GitHub Pages.

## Architecture

```
GitHub Pages (admin & demo1 Vue apps)
        │ HTTPS + CORS
        ▼
Cloudflare Worker (proxy/src/index.js)
   ├── Cloudflare KV (session/token storage)
   └── EEN OAuth API (eagleeyenetworks.com)
```

- **proxy/** — Single-file Cloudflare Worker (`src/index.js`) handling OAuth token exchange, session management, admin endpoints, rate limiting, and SSRF protection
- **admin/** — Vue 3 + Pinia + TailwindCSS 4 admin dashboard for session management
- **demo1/** — Vue 3 + Pinia + TailwindCSS 4 demo app showing OAuth login flow
- **scripts/** — Build, deploy, and test automation

The proxy is the only component with access to CLIENT_SECRET. Frontend apps communicate via session cookies (HttpOnly, Secure, SameSite=None) or header-based auth (`Authorization: Bearer <sessionId>`).

### Frontend Pattern

Both admin and demo1 follow the same Vue 3 structure:
- **Pinia stores** (`src/stores/auth.js`) — composition API style, manage auth state, token refresh, session tracking
- **Services** (`src/services/`) — API call wrappers (auth.js in both; admin.js + admin.test.js in admin; user.js + proxy.js in demo1)
- **CSP plugin** (`vite-plugin-csp.js`) — shared Vite plugin that injects `connect-src` at build time based on `VITE_PROXY_URL`
- Auth stores validate `hostname` from EEN token responses against a domain allowlist before storing

## Commands

### Proxy (Cloudflare Worker)
```bash
cd proxy && npm run dev          # Start local dev server on port 8787
cd proxy && npm test             # Run all proxy tests (vitest)
cd proxy && npx vitest run test/security.test.js  # Run a single test file
cd proxy && npm run test:watch   # Watch mode
cd proxy && npm run test:perf    # Performance tests only
cd proxy && npm run deploy       # Deploy to Cloudflare
```

### Admin (Vue 3)
```bash
cd admin && npm run dev          # Dev server on 127.0.0.1:3333
cd admin && npm run dev:prod     # Dev server with production config
cd admin && npm run build        # Production build
cd admin && npm test             # Playwright E2E tests
cd admin && npm run test:unit    # Vitest unit tests
```

### Demo1 (Vue 3)
```bash
cd demo1 && npm run dev          # Dev server on 127.0.0.1:3333
cd demo1 && npm run dev:prod     # Dev server with production config
cd demo1 && npm run build        # Production build
cd demo1 && npm test             # Playwright E2E tests
```

### All Tests
```bash
npm test                         # Runs scripts/run-all-tests.sh (proxy + demo1 + admin sequentially)
```

Admin and demo1 share port 3333 — they cannot run simultaneously. **Port 3333 is required and must never be changed**: the OAuth redirect URL registered with EEN is fixed to `http://127.0.0.1:3333`, so both apps are forced onto that port. Do not propose splitting the apps onto different ports.

Caveat for Playwright runs: because of the shared port and `reuseExistingServer: true`, a stale dev server from the *other* app on 3333 gets silently reused, and the suite then runs against the wrong app — failures show up as misleading element timeouts, not a clear error. If E2E tests fail oddly, check what is serving 3333 (`lsof -i :3333`) and kill it before re-running.

## Testing

- **Proxy tests** use Vitest with `@cloudflare/vitest-pool-workers` (Miniflare). Test config is in `proxy/vitest.config.js` with mock bindings for KV, secrets, etc.
- **Frontend tests** use Playwright. They require the proxy running on port 8787 and the app on port 3333.
- Proxy has 12 test files covering integration, security, CORS, OAuth, admin, auth-header, rate limiting (including low-limits variant), SSRF (integration + unit), workflow, and performance.

## Key Conventions

- **Single-file worker**: All proxy logic lives in `proxy/src/index.js` (~1435 lines). No module splitting.
- **Version bumping**: Husky pre-commit hook auto-increments patch version in package.json for changed directories. It also checks proxy deployment status (skip with `SKIP_DEPLOYMENT_CHECK=1`).
- **Version numbers differ** across proxy, admin, and demo1 — this is intentional.
- **Environment files**: Proxy uses `.dev.vars` (local secrets) and `.env` (deploy secrets). Frontend apps use `.env` and `.env.prod` with `VITE_` prefix.
- **Node 20+** required (Wrangler v4, Vite 7).

## Deployment

- Proxy deploys to Cloudflare Workers via `proxy/scripts/deploy.js` (reads secrets from `proxy/.env`)
- Admin/demo1 deploy to GitHub Pages under `/een-oauth-proxy/` and `/een-oauth-proxy/demo1/`
- CI/CD via GitHub Actions: PR gets AI review + tests; merge to production triggers deploy with automatic rollback on failure

## Commit Message Conventions

- Use imperative mood in commit subjects (e.g., "Add cache headers" not "Added cache headers")
- Conventional commit prefixes are encouraged for automatic changelog grouping: `feat:`, `fix:`, `docs:`, `chore:`, `security:`, `ci:`
- Examples: `feat: Add OAuth PKCE support`, `fix: Prevent token refresh race condition`, `docs: Update deployment instructions`
- Commits without a prefix are still valid — they appear under "Other Changes" in release notes
- Avoid prefixing with `bump version` — the Husky pre-commit hook generates these automatically and they are excluded from changelogs

## Review Notes

- No branch protection on `develop` branch (intentional)
- Version jumps between commits are expected (not every version is committed)
- Admin and demo1 sharing port 3333 is by design
