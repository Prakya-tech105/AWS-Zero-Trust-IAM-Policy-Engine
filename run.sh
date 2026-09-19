#!/usr/bin/env bash
# =============================================================================
# Zero-Trust IAM Policy Engine Dashboard — startup script
#
# Starts the FastAPI backend (:8000) and the Vite frontend (:5173) together.
# Frontend calls are proxied to the backend via Vite's /api proxy.
#
# Usage:
#   ./run.sh              start both servers
#   ./run.sh --check      pre-flight checks only (no servers)
#   ./run.sh --backend    backend only
#   ./run.sh --frontend   frontend only
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT/backend"
FRONTEND_DIR="$ROOT/frontend"

BACKEND_PORT=8000
FRONTEND_PORT=5173

MODE="both"
[[ "${1:-}" == "--check" ]] && MODE="check"
[[ "${1:-}" == "--backend" ]] && MODE="backend"
[[ "${1:-}" == "--frontend" ]] && MODE="frontend"

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[1;33m'; c_off='\033[0m'
ok()   { echo -e "${c_green}[ok]${c_off} $*"; }
warn() { echo -e "${c_yellow}[!!]${c_off} $*"; }
fail() { echo -e "${c_red}[FAIL]${c_off} $*"; exit 1; }

cleanup() {
  [[ -z "${BACKEND_PID:-}" && -z "${FRONTEND_PID:-}" ]] && return 0
  echo ""
  echo "Shutting down..."
  [[ -n "${BACKEND_PID:-}" ]] && kill "$BACKEND_PID" 2>/dev/null || true
  [[ -n "${FRONTEND_PID:-}" ]] && kill "$FRONTEND_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------------
preflight() {
  echo "==> Pre-flight checks"
  command -v python >/dev/null 2>&1 || fail "python not found (need Python 3.11+)"
  python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || fail "Python 3.11+ required (found $(python --version 2>&1))"
  ok "Python $(python --version 2>&1 | cut -d' ' -f2)"

  command -v npm >/dev/null 2>&1 || fail "npm not found (need Node 18+)"
  ok "npm $(npm --version)"

  # Backend deps importable?
  if python -c "import fastapi, uvicorn, boto3, pydantic" 2>/dev/null; then
    ok "backend dependencies installed"
  else
    warn "backend dependencies missing — installing from backend/requirements.txt"
    python -m pip install -r "$BACKEND_DIR/requirements.txt" --quiet \
      || fail "pip install failed"
    ok "backend dependencies installed"
  fi

  # Frontend deps present?
  if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    warn "frontend dependencies missing — running npm install"
    (cd "$FRONTEND_DIR" && npm install --no-audit --no-fund) || fail "npm install failed"
  fi
  ok "frontend dependencies present"

  # AWS credentials (non-fatal — dashboard degrades to demo mode)
  if python -c "import boto3; sys_exit = boto3.Session().get_credentials(); exit(0 if sys_exit else 1)" 2>/dev/null; then
    ok "AWS credentials detected (live simulator mode)"
  else
    warn "no AWS credentials — dashboard will run in demo mode"
    warn "run 'aws configure' or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for live mode"
  fi
  echo ""
}

# -----------------------------------------------------------------------------
# Servers
# -----------------------------------------------------------------------------
start_backend() {
  echo "==> Starting FastAPI backend on :$BACKEND_PORT"
  (cd "$BACKEND_DIR" && python -m uvicorn main:app --host 127.0.0.1 --port "$BACKEND_PORT" --reload) &
  BACKEND_PID=$!
  ok "backend pid $BACKEND_PID  ->  http://127.0.0.1:$BACKEND_PORT  (docs: /docs)"
}

start_frontend() {
  echo "==> Starting Vite frontend on :$FRONTEND_PORT"
  (cd "$FRONTEND_DIR" && npm run dev -- --port "$FRONTEND_PORT" --strictPort) &
  FRONTEND_PID=$!
  ok "frontend pid $FRONTEND_PID  ->  http://localhost:$FRONTEND_PORT"
}

case "$MODE" in
  check)
    preflight
    echo "All checks passed. Run ./run.sh to start both servers."
    ;;
  backend)
    preflight
    start_backend
    wait "$BACKEND_PID"
    ;;
  frontend)
    preflight
    start_frontend
    wait "$FRONTEND_PID"
    ;;
  both)
    preflight
    start_backend
    sleep 2
    start_frontend
    echo ""
    echo "=============================================="
    echo "  Dashboard : http://localhost:$FRONTEND_PORT"
    echo "  API       : http://127.0.0.1:$BACKEND_PORT/api/v1/health"
    echo "  API docs  : http://127.0.0.1:$BACKEND_PORT/docs"
    echo "=============================================="
    echo "Press Ctrl+C to stop both servers."
    echo ""
    wait
    ;;
esac
