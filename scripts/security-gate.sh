#!/usr/bin/env bash
# Local-build security gate. Spec: personality/architecture/local-build-security-gate.md.
#
# Adaptive — runs only the tools that apply to this repo's content.
# JIT-installs missing tools to ~/.local/ (no sudo). Exits non-zero on
# any blocking finding (verified secret, medium+ Bandit, ERROR Semgrep,
# moderate+ npm-audit, any pip-audit). Report-only findings print but
# don't fail.
#
# Override: SECURITY_GATE_SKIP=1 (full skip), SECURITY_GATE_SKIP_TOOLS=trufflehog,bandit (subset).
# Findings: security-results/*.json (gitignored).

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

if [ -n "${SECURITY_GATE_SKIP:-}" ]; then
  echo "▶ SECURITY_GATE_SKIP=1 — gate bypassed."
  exit 0
fi

mkdir -p security-results
FAIL=0
SKIPS="${SECURITY_GATE_SKIP_TOOLS:-}"

skip_tool() { echo ",$SKIPS," | grep -q ",$1,"; }

# ── detect repo shape ─────────────────────────────────────────────────
HAS_PY=""
[ -n "$(find . -maxdepth 4 -name '*.py' -not -path './node_modules/*' -not -path './.venv/*' -not -path './security-results/*' 2>/dev/null | head -1)" ] && HAS_PY=1

HAS_NODE=""
[ -f package.json ] && HAS_NODE=1

HAS_PIP_DEPS=""
{ [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f Pipfile ]; } && HAS_PIP_DEPS=1

HAS_JS_TS=""
[ -n "$(find . -maxdepth 4 \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' \) -not -path './node_modules/*' -not -path './.wrangler/*' -not -path './security-results/*' 2>/dev/null | head -1)" ] && HAS_JS_TS=1

# ── JIT installers ────────────────────────────────────────────────────
need() {
  local cmd="$1" install="$2"
  if ! command -v "$cmd" >/dev/null 2>&1 && ! [ -x "$HOME/.local/bin/$cmd" ]; then
    echo "  Installing $cmd..."
    eval "$install" 1>/dev/null 2>&1 || { echo "  ✗ install failed for $cmd"; return 1; }
  fi
  return 0
}

# ── 1. TruffleHog (always) ────────────────────────────────────────────
if ! skip_tool trufflehog; then
  echo "▶ TruffleHog (secret scan, working tree)..."
  need trufflehog 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/.local/bin'
  if command -v trufflehog >/dev/null 2>&1 || [ -x "$HOME/.local/bin/trufflehog" ]; then
    TH_BIN=$(command -v trufflehog || echo "$HOME/.local/bin/trufflehog")
    "$TH_BIN" filesystem . --results=verified --json > security-results/trufflehog.json 2>/dev/null || true
    VERIFIED=$(wc -l < security-results/trufflehog.json 2>/dev/null || echo 0)
    if [ "$VERIFIED" -gt 0 ]; then
      echo "  ✗ $VERIFIED verified secret(s) — see security-results/trufflehog.json"
      FAIL=1
    else
      echo "  ✓ no verified secrets"
    fi
  fi
fi

# ── 2. Bandit (Python only) ───────────────────────────────────────────
if [ -n "$HAS_PY" ] && ! skip_tool bandit; then
  echo "▶ Bandit (Python SAST)..."
  need bandit 'pipx install bandit 2>/dev/null || pip install --user --break-system-packages "bandit[toml]>=1.7"'
  if command -v bandit >/dev/null 2>&1 || [ -x "$HOME/.local/bin/bandit" ]; then
    BD_BIN=$(command -v bandit || echo "$HOME/.local/bin/bandit")
    "$BD_BIN" -r . --exclude ./tests,./node_modules,./cache,./.venv,./security-results \
      --severity-level medium --confidence-level medium \
      -f json -o security-results/bandit.json 2>/dev/null
    BD_EXIT=$?
    if [ "$BD_EXIT" -ne 0 ]; then
      ISSUES=$(python3 -c "import json; print(len(json.load(open('security-results/bandit.json'))['results']))" 2>/dev/null || echo "?")
      echo "  ✗ $ISSUES finding(s) at medium+ severity/confidence"
      FAIL=1
    else
      echo "  ✓ clean"
    fi
  fi
fi

# ── 3. Semgrep (any code) ─────────────────────────────────────────────
if { [ -n "$HAS_PY" ] || [ -n "$HAS_JS_TS" ]; } && ! skip_tool semgrep; then
  echo "▶ Semgrep (multilang SAST)..."
  need semgrep 'pipx install semgrep 2>/dev/null || pip install --user --break-system-packages semgrep'
  if command -v semgrep >/dev/null 2>&1 || [ -x "$HOME/.local/bin/semgrep" ]; then
    SG_BIN=$(command -v semgrep || echo "$HOME/.local/bin/semgrep")
    SG_RULES="--config=p/security-audit"
    [ -n "$HAS_JS_TS" ] && SG_RULES="$SG_RULES --config=p/javascript --config=p/typescript"
    [ -n "$HAS_PY" ] && SG_RULES="$SG_RULES --config=p/python"
    "$SG_BIN" $SG_RULES --severity ERROR --json --quiet \
      --exclude=node_modules --exclude=.venv --exclude=.wrangler --exclude=security-results \
      -o security-results/semgrep.json . 2>/dev/null
    ERRORS=$(python3 -c "import json; print(len(json.load(open('security-results/semgrep.json'))['results']))" 2>/dev/null || echo 0)
    if [ "$ERRORS" -gt 0 ]; then
      echo "  ✗ $ERRORS ERROR-severity finding(s)"
      FAIL=1
    else
      echo "  ✓ clean"
    fi
  fi
fi

# ── 4. npm audit (Node only) ──────────────────────────────────────────
if [ -n "$HAS_NODE" ] && ! skip_tool npm-audit; then
  echo "▶ npm audit..."
  npm audit --audit-level=moderate --json > security-results/npm-audit.json 2>/dev/null
  NA_EXIT=$?
  if [ "$NA_EXIT" -ne 0 ]; then
    VULN=$(python3 -c "import json; d=json.load(open('security-results/npm-audit.json')); print(d.get('metadata',{}).get('vulnerabilities',{}).get('moderate',0)+d.get('metadata',{}).get('vulnerabilities',{}).get('high',0)+d.get('metadata',{}).get('vulnerabilities',{}).get('critical',0))" 2>/dev/null || echo "?")
    echo "  ✗ $VULN moderate+ vulnerabilities"
    FAIL=1
  else
    echo "  ✓ clean"
  fi
fi

# ── 5. pip-audit (Python deps only) ───────────────────────────────────
if [ -n "$HAS_PIP_DEPS" ] && ! skip_tool pip-audit; then
  echo "▶ pip-audit..."
  need pip-audit 'pipx install pip-audit 2>/dev/null || pip install --user --break-system-packages pip-audit'
  if command -v pip-audit >/dev/null 2>&1 || [ -x "$HOME/.local/bin/pip-audit" ]; then
    PA_BIN=$(command -v pip-audit || echo "$HOME/.local/bin/pip-audit")
    "$PA_BIN" --format json > security-results/pip-audit.json 2>/dev/null
    PA_EXIT=$?
    if [ "$PA_EXIT" -ne 0 ]; then
      echo "  ✗ vulnerable Python deps"
      FAIL=1
    else
      echo "  ✓ clean"
    fi
  fi
fi

# ── summary ───────────────────────────────────────────────────────────
echo
echo "=== Security gate summary ==="
echo "Repo shape: PY=${HAS_PY:-no} NODE=${HAS_NODE:-no} JS/TS=${HAS_JS_TS:-no} PIP-DEPS=${HAS_PIP_DEPS:-no}"
echo "Results in: security-results/*.json"
if [ "$FAIL" -eq 0 ]; then
  echo "✓ PASS"
else
  echo "✗ FAIL — see results"
fi
exit $FAIL
