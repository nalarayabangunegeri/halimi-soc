#!/usr/bin/env bash
# Run the full HalimiSOC demonstration on one machine.
#
# The script starts the API, runs the deterministic synthetic attack scenario
# through the normal ingestion path, and then prints the resulting alerts and
# incident. Nothing it does touches the host: the "attack" is a set of log lines.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ADMIN_PASSWORD="${HALIMISOC_ADMIN_PASSWORD:-halimisoc-demo-admin}"
ENROLL_SECRET="${HALIMISOC_AGENT_ENROLL_SECRET:-halimisoc-demo-enrollment-secret}"
PORT="${HALIMISOC_PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"

if [[ -z "${HALIMISOC_DATABASE_URL:-}" ]]; then
  echo "HALIMISOC_DATABASE_URL must be set" >&2
  exit 1
fi

echo "==> building"
make build >/dev/null

echo "==> starting API on ${BASE}"
HALIMISOC_DATABASE_URL="$HALIMISOC_DATABASE_URL" \
HALIMISOC_RULES_PATH=packages/rules \
HALIMISOC_ADMIN_USER=admin \
HALIMISOC_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
HALIMISOC_AGENT_ENROLL_SECRET="$ENROLL_SECRET" \
HALIMISOC_LISTEN_ADDR="127.0.0.1:${PORT}" \
  ./bin/halimisoc-api >/tmp/halimisoc-demo.log 2>&1 &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT

# Wait for readiness rather than sleeping a fixed amount: the API is ready when
# it reports its rules are loaded, which is the condition the demo depends on.
for _ in $(seq 1 60); do
  if curl -fsS "${BASE}/readyz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "${BASE}/readyz" >/dev/null || { echo "API did not become ready" >&2; cat /tmp/halimisoc-demo.log >&2; exit 1; }

echo "==> running synthetic attack scenario"
DEMO_DIR="$(mktemp -d)"
./bin/halimisoc-agent \
  -server "$BASE" -insecure \
  -enroll-token "$ENROLL_SECRET" \
  -host demo-host -simulate \
  -spool-dir "$DEMO_DIR/spool" -state-dir "$DEMO_DIR/state"

echo "==> logging in"
COOKIE_JAR="$DEMO_DIR/cookies"
CSRF=$(curl -fsS -c "$COOKIE_JAR" -X POST "${BASE}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')

if [[ -z "$CSRF" ]]; then
  echo "login failed" >&2
  exit 1
fi

echo
echo "==> alerts"
curl -fsS -b "$COOKIE_JAR" "${BASE}/api/v1/alerts?limit=20" | python3 -m json.tool

echo
echo "==> incidents"
curl -fsS -b "$COOKIE_JAR" "${BASE}/api/v1/incidents?limit=5" | python3 -m json.tool

echo
echo "==> metrics"
curl -fsS "${BASE}/metrics" | grep -E '^(events_received_total|events_processed_total|detection_total|incident_created_total)'

echo
echo "Demo complete. API log: /tmp/halimisoc-demo.log"
