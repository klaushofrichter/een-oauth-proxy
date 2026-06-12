#!/bin/bash
#
# Production E2E Tests
#
# Runs the full production verification suite against the deployed proxy:
#   1. API tests (scripts/test-production-proxy.sh) - read-only curl checks
#   2. demo1 Playwright E2E in production mode (real OAuth logins)
#   3. admin Playwright E2E in production mode
#
# The apps run locally on port 3333 in production config (npm run dev:prod),
# talking to the deployed proxy. Destructive admin tests skip automatically
# against a non-local proxy; the self-scoped session-revoke test still runs
# and only ever touches the session it creates.
#
# Requirements: TEST_USER/TEST_PASSWORD (demo1/.env) and
# ADMIN_TEST_USER/ADMIN_TEST_PASSWORD (admin/.env) must be valid EEN
# credentials, since logins go against the real EEN OAuth service.
#
# Usage:
#   ./scripts/test-e2e-production.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

FAILED=0

cleanup() {
  # Stop whatever is on the app port; the apps' own npm scripts also do this
  lsof -ti :3333 2>/dev/null | xargs kill 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${BLUE}=== 1/3 Production proxy API tests ===${NC}"
if ! BRIEF=1 "$SCRIPT_DIR/test-production-proxy.sh"; then
  FAILED=1
fi

echo -e "\n${BLUE}=== 2/3 demo1 E2E against production ===${NC}"
cleanup
if ! (cd "$ROOT_DIR/demo1" && npm run test:prod); then
  FAILED=1
fi

echo -e "\n${BLUE}=== 3/3 admin E2E against production ===${NC}"
cleanup
if ! (cd "$ROOT_DIR/admin" && npm run test:prod); then
  FAILED=1
fi

echo ""
if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}All production test suites passed${NC}"
  exit 0
else
  echo -e "${RED}One or more production test suites failed${NC}"
  exit 1
fi
