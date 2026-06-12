#!/bin/bash
#
# Production Proxy API Tests
#
# Runs API tests against the deployed Cloudflare proxy to verify
# it's functioning correctly in production.
#
# Usage:
#   ./scripts/test-production-proxy.sh [proxy-url]
#   BRIEF=1 ./scripts/test-production-proxy.sh [proxy-url]  # Compact output
#
# If no URL is provided, uses the default production URL.
#

set -e

# Check for required dependencies
for cmd in curl jq; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: Required command '$cmd' not found. Please install it first."
    exit 1
  fi
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Brief mode - compact output for CI/deployment
BRIEF="${BRIEF:-0}"

# Default production proxy URL (can be overridden via first argument or PROXY_URL env var)
DEFAULT_PROXY_URL="https://een-oauth-proxy.klaushofrichter.workers.dev"
PROXY_URL="${1:-${PROXY_URL:-$DEFAULT_PROXY_URL}}"

# Allowed origin for CORS tests (must match proxy's ALLOWED_ORIGINS)
# Can be overridden via ALLOWED_ORIGIN environment variable for forks/other deployments
ALLOWED_ORIGIN="${ALLOWED_ORIGIN:-https://klaushofrichter.github.io}"

# Track results
PASSED=0
FAILED=0

# Test function
run_test() {
  local test_name="$1"
  local expected="$2"
  local actual="$3"

  if [ "$expected" = "$actual" ]; then
    [ "$BRIEF" = "1" ] && echo -e "${GREEN}✓${NC} $test_name" || echo -e "   ${GREEN}✅ PASSED${NC} - $test_name"
    ((PASSED++)) || true
  else
    [ "$BRIEF" = "1" ] && echo -e "${RED}✗${NC} $test_name" || echo -e "   ${RED}❌ FAILED${NC} - $test_name (expected: $expected, got: $actual)"
    ((FAILED++)) || true
  fi
}

run_test_contains() {
  local test_name="$1"
  local needle="$2"
  local haystack="$3"

  if echo "$haystack" | grep -qi "$needle"; then
    [ "$BRIEF" = "1" ] && echo -e "${GREEN}✓${NC} $test_name" || echo -e "   ${GREEN}✅ PASSED${NC} - $test_name"
    ((PASSED++)) || true
  else
    [ "$BRIEF" = "1" ] && echo -e "${RED}✗${NC} $test_name" || echo -e "   ${RED}❌ FAILED${NC} - $test_name (missing: $needle)"
    ((FAILED++)) || true
  fi
}

run_test_not_contains() {
  local test_name="$1"
  local needle="$2"
  local haystack="$3"

  if echo "$haystack" | grep -qi "$needle"; then
    [ "$BRIEF" = "1" ] && echo -e "${RED}✗${NC} $test_name" || echo -e "   ${RED}❌ FAILED${NC} - $test_name (unexpected: $needle)"
    ((FAILED++)) || true
  else
    [ "$BRIEF" = "1" ] && echo -e "${GREEN}✓${NC} $test_name" || echo -e "   ${GREEN}✅ PASSED${NC} - $test_name"
    ((PASSED++)) || true
  fi
}

if [ "$BRIEF" = "1" ]; then
  echo -e "${BLUE}Production Proxy Tests${NC} - $PROXY_URL"
else
  echo -e "${BLUE}============================================${NC}"
  echo -e "${BLUE}Production Proxy API Tests${NC}"
  echo -e "${BLUE}============================================${NC}"
  echo -e "URL: ${YELLOW}$PROXY_URL${NC}"
  echo -e "Origin: ${YELLOW}$ALLOWED_ORIGIN${NC}"
  echo ""
fi

# 1. Health Check
[ "$BRIEF" != "1" ] && echo -e "${BLUE}1. Health Check${NC}"
HEALTH=$(curl -s --max-time 10 "$PROXY_URL/health" 2>/dev/null || echo '{"status":"error"}')
HEALTH_STATUS=$(echo "$HEALTH" | jq -r '.status' 2>/dev/null || echo "error")
HEALTH_VERSION=$(echo "$HEALTH" | jq -r '.version' 2>/dev/null || echo "unknown")
if [ "$HEALTH_STATUS" = "ok" ]; then
  [ "$BRIEF" = "1" ] && echo -e "${GREEN}✓${NC} Health: ok ($HEALTH_VERSION)" || echo -e "   ${GREEN}✅ PASSED${NC} - Status: ok\n   Version: ${YELLOW}$HEALTH_VERSION${NC}"
  ((PASSED++)) || true
else
  [ "$BRIEF" = "1" ] && echo -e "${RED}✗${NC} Health: $HEALTH_STATUS" || echo -e "   ${RED}❌ FAILED${NC} - Status: $HEALTH_STATUS"
  ((FAILED++)) || true
fi

# 2. CORS Preflight (OPTIONS)
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}2. CORS Preflight (OPTIONS)${NC}"
CORS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X OPTIONS "$PROXY_URL/proxy/getAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" \
  -H "Access-Control-Request-Method: POST" 2>/dev/null || echo "000")
run_test "OPTIONS returns 204" "204" "$CORS_STATUS"

# 3. CORS Headers Present
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}3. CORS Headers Present${NC}"
CORS_HEADERS=$(curl -s -I --max-time 10 -X OPTIONS "$PROXY_URL/proxy/getAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" \
  -H "Access-Control-Request-Method: POST" 2>/dev/null || echo "")
run_test_contains "Access-Control-Allow-Origin header" "access-control-allow-origin" "$CORS_HEADERS"
run_test_contains "Access-Control-Allow-Methods header" "access-control-allow-methods" "$CORS_HEADERS"
run_test_contains "Access-Control-Allow-Credentials header" "access-control-allow-credentials" "$CORS_HEADERS"

# 4. Security Headers Present
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}4. Security Headers${NC}"
SECURITY_HEADERS=$(curl -s -I --max-time 10 "$PROXY_URL/health" -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "")
run_test_contains "X-Content-Type-Options header" "x-content-type-options" "$SECURITY_HEADERS"
run_test_contains "X-Frame-Options header" "x-frame-options" "$SECURITY_HEADERS"
run_test_contains "Content-Security-Policy header" "content-security-policy" "$SECURITY_HEADERS"
run_test_contains "Referrer-Policy header" "referrer-policy" "$SECURITY_HEADERS"
# HSTS is only set outside development, so production is the only place to test it
run_test_contains "Strict-Transport-Security header" "strict-transport-security" "$SECURITY_HEADERS"
run_test_contains "Vary: Origin header" "vary: origin" "$SECURITY_HEADERS"

# 5. Reject Invalid Origin
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}5. Reject Invalid Origin${NC}"
INVALID_ORIGIN=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$PROXY_URL/health" \
  -H "Origin: https://malicious-site.com" 2>/dev/null || echo "000")
run_test "Invalid origin rejected" "403" "$INVALID_ORIGIN"

# The 403 must be readable by the calling page (issue #125): CORS headers echo
# the rejected origin, and the body must stay the exact static string - it is
# readable cross-origin with credentials, so any dynamic content would leak
INVALID_ORIGIN_HEADERS=$(curl -s -i --max-time 10 "$PROXY_URL/health" \
  -H "Origin: https://malicious-site.com" 2>/dev/null || echo "")
run_test_contains "403 echoes rejected origin in ACAO" "access-control-allow-origin: https://malicious-site.com" "$INVALID_ORIGIN_HEADERS"
run_test_contains "403 includes Vary: Origin" "vary: origin" "$INVALID_ORIGIN_HEADERS"
INVALID_ORIGIN_BODY=$(curl -s --max-time 10 "$PROXY_URL/health" \
  -H "Origin: https://malicious-site.com" 2>/dev/null || echo "")
run_test "403 body is the exact static string" "Forbidden: Invalid origin" "$INVALID_ORIGIN_BODY"

# 6. Missing Session Returns 401
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}6. Authentication - Missing Session${NC}"
NOSESSION=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$PROXY_URL/proxy/refreshAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" \
  -H "Content-Type: application/json" 2>/dev/null || echo "000")
run_test "No session returns 401" "401" "$NOSESSION"

# 7. Invalid Session ID Rejected
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}7. Authentication - Invalid Session${NC}"
INVALID_SESSION=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$PROXY_URL/proxy/refreshAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" \
  -H "Cookie: sessionId=invalid-session-12345" 2>/dev/null || echo "000")
run_test "Invalid session rejected" "401" "$INVALID_SESSION"

# 8. Admin Endpoint Without Auth
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}8. Admin - Requires Authentication${NC}"
ADMIN_NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$PROXY_URL/admin/version" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "Admin requires auth" "401" "$ADMIN_NOAUTH"

ADMIN_SESSIONS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$PROXY_URL/admin/sessionsCount" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "Sessions count requires auth" "401" "$ADMIN_SESSIONS"

# 9. HEAD Request
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}9. HEAD Request Support${NC}"
HEAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -I "$PROXY_URL/health" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "HEAD /health returns 200" "200" "$HEAD_STATUS"

# 10. OAuth Endpoints Exist
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}10. OAuth Endpoints${NC}"
# getAccessToken without required params should return 400
OAUTH_GET=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$PROXY_URL/proxy/getAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "getAccessToken endpoint exists (400 without params)" "400" "$OAUTH_GET"

# revoke without session should return 401
OAUTH_REVOKE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$PROXY_URL/proxy/revoke" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "revoke endpoint exists (401 without session)" "401" "$OAUTH_REVOKE"

# 11. CSRF Protection - POST Without Origin
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}11. CSRF Protection - POST Without Origin${NC}"
CSRF_RESPONSE=$(curl -s -i --max-time 10 -X POST "$PROXY_URL/proxy/getAccessToken" 2>/dev/null || echo "")
CSRF_STATUS=$(echo "$CSRF_RESPONSE" | head -1 | grep -oE '[0-9]{3}' | head -1)
run_test "POST without Origin rejected" "403" "$CSRF_STATUS"
# The wildcard lets a stripped-Origin client read the explanation, but
# credentials must never be allowed together with a wildcard origin
run_test_contains "CSRF 403 has wildcard ACAO" "access-control-allow-origin: \*" "$CSRF_RESPONSE"
run_test_not_contains "CSRF 403 has no Allow-Credentials" "access-control-allow-credentials" "$CSRF_RESPONSE"

# 12. Preflight From Disallowed Origin
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}12. Preflight From Disallowed Origin${NC}"
BAD_PREFLIGHT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X OPTIONS "$PROXY_URL/proxy/getAccessToken" \
  -H "Origin: https://malicious-site.com" \
  -H "Access-Control-Request-Method: POST" 2>/dev/null || echo "000")
run_test "Preflight from disallowed origin rejected" "403" "$BAD_PREFLIGHT"

# 13. Token Responses Are Not Cacheable (RFC 6749 Section 5.1)
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}13. Token Responses Not Cacheable${NC}"
REFRESH_401=$(curl -s -i --max-time 10 -X POST "$PROXY_URL/proxy/refreshAccessToken" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "")
run_test_contains "Refresh 401 has Cache-Control: no-store" "cache-control: no-store" "$REFRESH_401"
run_test_contains "Refresh 401 has Pragma: no-cache" "pragma: no-cache" "$REFRESH_401"

# 14. Disallowed redirect_uri Rejected
[ "$BRIEF" != "1" ] && echo -e "\n${BLUE}14. Redirect URI Validation${NC}"
BAD_REDIRECT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST \
  "$PROXY_URL/proxy/getAccessToken?code=test&redirect_uri=https://evil.example.com" \
  -H "Origin: $ALLOWED_ORIGIN" 2>/dev/null || echo "000")
run_test "Disallowed redirect_uri rejected" "400" "$BAD_REDIRECT"

# Summary
if [ "$BRIEF" = "1" ]; then
  if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All $PASSED tests passed${NC}"
    exit 0
  else
    echo -e "${RED}$FAILED failed${NC}, ${GREEN}$PASSED passed${NC}"
    exit 1
  fi
else
  echo -e "\n${BLUE}============================================${NC}"
  echo -e "${BLUE}Test Summary${NC}"
  echo -e "${BLUE}============================================${NC}"
  echo -e "Passed: ${GREEN}$PASSED${NC}"
  echo -e "Failed: ${RED}$FAILED${NC}"

  if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
  else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
  fi
fi
