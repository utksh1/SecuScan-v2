#!/usr/bin/env bash
# End-to-end smoke test: server + SPA + login + scan + findings + SSE + reports.
set -euo pipefail
cd "$(dirname "$0")/.."

export SECUSCAN_ADDR=127.0.0.1:8099
export SECUSCAN_DB_URL="sqlite:///tmp/e2e-data/e2e.db?mode=rwc"
export SECUSCAN_ADMIN_EMAIL=e2e@test.local
export SECUSCAN_ADMIN_PASSWORD=e2e-password-123
export SECUSCAN_JWT_SECRET=e2e-secret
export RUST_LOG=secuscan=info

rm -rf /tmp/e2e-data && mkdir -p /tmp/e2e-data

# Live listener for the port scanner to find.
python3 - <<'EOF' &
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9933)); s.listen(10)
end = time.time() + 90
while time.time() < end:
    try:
        s.settimeout(2); c,_ = s.accept(); c.close()
    except Exception: pass
EOF
LISTENER_PID=$!

./target/debug/secuscan-server > /tmp/e2e-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID $LISTENER_PID 2>/dev/null || true' EXIT
sleep 2

echo "=== 1. health ==="
curl -sf http://127.0.0.1:8099/api/v1/health
echo

echo "=== 2. SPA served ==="
curl -sf http://127.0.0.1:8099/ | grep -o '<title>SecuScan</title>'
curl -sf http://127.0.0.1:8099/ | grep -o 'assets/index-[^"]*\.js' | head -1

echo "=== 3. login ==="
TOKEN=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"e2e@test.local","password":"e2e-password-123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "token: ${TOKEN:0:24}..."

echo "=== 4. start scan (port-scanner native) ==="
TASK_ID=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"plugin_id":"port-scanner","inputs":{"target":"127.0.0.1","ports":"9933,9934"},"consent_granted":true}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "task: $TASK_ID"

echo "=== 5. poll to completion ==="
for i in $(seq 1 40); do
  STATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/tasks/$TASK_ID" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then break; fi
  sleep 0.3
done
echo "status: $STATUS"
[ "$STATUS" = "completed" ] || { echo "SCAN DID NOT COMPLETE"; exit 1; }

echo "=== 6. findings ==="
curl -sf "http://127.0.0.1:8099/api/v1/tasks/$TASK_ID/result" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
r = json.load(sys.stdin)
print('findings:', len(r['findings']))
for f in r['findings']:
    print('  -', f['severity'], '|', f['title'])
assert any('9933' in f['title'] for f in r['findings']), 'expected the open port!'
print('E2E FINDINGS OK')
"

echo "=== 7. SSE replay ==="
curl -sf -N --max-time 4 "http://127.0.0.1:8099/api/v1/tasks/$TASK_ID/stream" -H "authorization: Bearer $TOKEN" > /tmp/e2e-sse.txt || true
grep -q '"finished"' /tmp/e2e-sse.txt && echo "SSE replay contains finished event ($(wc -l < /tmp/e2e-sse.txt) lines)"

echo "=== 8. reports ==="
for fmt in md csv sarif html json; do
  CODE=$(curl -sf -o /tmp/e2e-report.$fmt -w '%{http_code}' "http://127.0.0.1:8099/api/v1/tasks/$TASK_ID/report/$fmt" -H "authorization: Bearer $TOKEN")
  echo "  $fmt → HTTP $CODE ($(wc -c < /tmp/e2e-report.$fmt) bytes)"
done
grep -q 'SecuScan Report' /tmp/e2e-report.md && echo "markdown report contains title"
grep -q '"2.1.0"' /tmp/e2e-report.sarif && echo "SARIF version 2.1.0"

echo "=== 9. dashboard ==="
curl -sf http://127.0.0.1:8099/api/v1/dashboard/summary -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('tasks.total:', d['tasks']['total'])
print('findings.info:', d['findings']['info'])
assert d['tasks']['total'] >= 1 and d['findings']['info'] >= 1
print('E2E DASHBOARD OK')
"

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  E2E SMOKE TEST: ALL STEPS PASSED      ║"
echo "╚════════════════════════════════════════╝"
