#!/usr/bin/env bash
# End-to-end smoke test: server + SPA + login + scan + findings + SSE + reports.
set -euo pipefail
cd "$(dirname "$0")/.."

export SECUSCAN_ADDR=127.0.0.1:8099
export SECUSCAN_DB_URL="sqlite:///tmp/e2e-data/e2e.db?mode=rwc"
export SECUSCAN_ADMIN_EMAIL=e2e@test.local
export SECUSCAN_ADMIN_PASSWORD=e2e-password-123
export SECUSCAN_JWT_SECRET=e2e-secret
export SECUSCAN_SCHEDULE_TICK_SECS=2
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

echo "=== 10. workspaces + targets + scoped views ==="
WS_ID=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/workspaces \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"E2E Workspace","description":"smoke"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "workspace: $WS_ID"

TG_ID=$(curl -sf -X POST "http://127.0.0.1:8099/api/v1/workspaces/$WS_ID/targets" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"127.0.0.1","description":"loopback"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['id']); import sys as s; s.stderr.write('kind: '+d['kind']+'\n')")
echo "target: $TG_ID"

# Duplicate target must 409.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8099/api/v1/workspaces/$WS_ID/targets" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"127.0.0.1"}')
[ "$CODE" = "409" ] && echo "duplicate target -> 409 OK"

# Scoped scan inside the workspace.
WS_TASK=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"plugin_id\":\"port-scanner\",\"inputs\":{\"target\":\"127.0.0.1\",\"ports\":\"9933\"},\"consent_granted\":true,\"workspace_id\":\"$WS_ID\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
for i in $(seq 1 40); do
  STATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/tasks/$WS_TASK" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then break; fi
  sleep 0.3
done
[ "$STATUS" = "completed" ] || { echo "WORKSPACE SCAN DID NOT COMPLETE"; exit 1; }

curl -sf "http://127.0.0.1:8099/api/v1/tasks?workspace_id=$WS_ID" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
r = json.load(sys.stdin)
assert r['total'] == 1, f'expected 1 workspace task, got {r[\"total\"]}'
print('workspace task scoping OK')
"
curl -sf "http://127.0.0.1:8099/api/v1/tasks?workspace_id=none" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
r = json.load(sys.stdin)
assert r['total'] == 1, f'expected 1 personal task, got {r[\"total\"]}'
print('personal task scoping OK')
"
curl -sf "http://127.0.0.1:8099/api/v1/workspaces/$WS_ID/targets" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
r = json.load(sys.stdin)
t = r['items'][0]
assert t['scans_total'] == 1, f\"expected 1 scan on target, got {t['scans_total']}\"
assert t['last_scanned_at'], 'expected last_scanned_at'
print('target stats OK')
"
curl -sf "http://127.0.0.1:8099/api/v1/dashboard/summary?workspace_id=$WS_ID" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['tasks']['total'] == 1, f\"expected 1 workspace task on dashboard, got {d['tasks']['total']}\"
print('workspace dashboard scoping OK')
"
# Unknown workspace filter must 404.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8099/api/v1/tasks?workspace_id=nope" -H "authorization: Bearer $TOKEN")
[ "$CODE" = "404" ] && echo "unknown workspace filter -> 404 OK"

echo "=== 11. scan diff ==="
# A second identical port-scanner run gives an auto-baseline diff that must
# be entirely "unchanged" (deterministic tool, same target, same ports).
TASK2=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"plugin_id":"port-scanner","inputs":{"target":"127.0.0.1","ports":"9933"},"consent_granted":true}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
for i in $(seq 1 40); do
  STATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/tasks/$TASK2" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then break; fi
  sleep 0.3
done
[ "$STATUS" = "completed" ] || { echo "DIFF RUN DID NOT COMPLETE"; exit 1; }

curl -sf "http://127.0.0.1:8099/api/v1/tasks/$TASK2/diff" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['auto_baseline'] is True, 'expected auto-selected baseline'
assert d['baseline']['id'] != d['task']['id'], 'baseline must not be the task itself'
s = d['summary']
assert s['new'] == 0 and s['fixed'] == 0 and s['regressed'] == 0 and s['improved'] == 0, f'unexpected changes: {s}'
assert s['unchanged'] >= 1, 'expected at least one unchanged finding'
print('diff vs auto-baseline OK:', s['unchanged'], 'unchanged, 0 new/fixed/regressed')
"
# Explicit reverse diff works too.
curl -sf "http://127.0.0.1:8099/api/v1/tasks/$TASK_ID/diff?against=$TASK2" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['auto_baseline'] is False and d['baseline']['id'] == '$TASK2'
print('explicit against= diff OK')
"

echo "=== 12. async report jobs ==="
# Queue a PDF job on the completed scan and poll it to `finished`.
REPORT=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/tasks/$TASK2/reports \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"format":"pdf"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
for i in $(seq 1 40); do
  RSTATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/reports/$REPORT" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [ "$RSTATUS" = "finished" ] || [ "$RSTATUS" = "failed" ]; then break; fi
  sleep 0.3
done
[ "$RSTATUS" = "finished" ] || { echo "REPORT JOB DID NOT FINISH"; exit 1; }
echo "report job lifecycle OK (waiting -> finished)"

# The artifact is a real PDF and the list endpoint sees it.
curl -sf "http://127.0.0.1:8099/api/v1/reports/$REPORT/download" -H "authorization: Bearer $TOKEN" -o /tmp/secuscan-e2e-report.pdf
head -c 5 /tmp/secuscan-e2e-report.pdf | grep -q '%PDF-' || { echo "PDF MAGIC MISSING"; exit 1; }
curl -sf "http://127.0.0.1:8099/api/v1/reports" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
r = json.load(sys.stdin)
assert r['total'] >= 1, 'expected at least one report job in the list'
job = [j for j in r['items'] if j['id'] == '$REPORT'][0]
assert job['status'] == 'finished' and job['file_bytes'] > 0
print('report listing + artifact OK')
"
# Severity-filtered XLSX job: port-scanner findings are info-severity, so a
# `critical` filter must produce an (empty but valid) workbook.
XLSX=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/tasks/$TASK2/reports \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"format":"xlsx","severity":"critical"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
for i in $(seq 1 40); do
  XSTATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/reports/$XLSX" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  if [ "$XSTATUS" = "finished" ] || [ "$XSTATUS" = "failed" ]; then break; fi
  sleep 0.3
done
[ "$XSTATUS" = "finished" ] || { echo "XLSX JOB DID NOT FINISH"; exit 1; }
curl -sf "http://127.0.0.1:8099/api/v1/reports/$XLSX/download" -H "authorization: Bearer $TOKEN" -o /tmp/secuscan-e2e-report.xlsx
head -c 2 /tmp/secuscan-e2e-report.xlsx | grep -q 'PK' || { echo "XLSX MAGIC MISSING"; exit 1; }
echo "severity-filtered xlsx job OK"
# Bad format is rejected with 400.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8099/api/v1/tasks/$TASK2/reports \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"format":"exe"}')
[ "$CODE" = "400" ] && echo "invalid report format -> 400 OK"

echo "=== 13. recurring schedules ==="
# Create a schedule (daily port sweep) via the API.
SCHED=$(curl -sf -X POST http://127.0.0.1:8099/api/v1/schedules \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"E2E daily sweep","plugin_id":"port-scanner","inputs":{"target":"127.0.0.1","ports":"9933"},"interval_seconds":86400,"consent_granted":true}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
# Interval bounds are enforced.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8099/api/v1/schedules \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"too fast","plugin_id":"port-scanner","inputs":{"target":"127.0.0.1"},"interval_seconds":30,"consent_granted":true}')
[ "$CODE" = "400" ] && echo "interval below 5min -> 400 OK"

# Backdate the schedule so the background loop (2s tick) fires it.
python3 -c "
import sqlite3
c = sqlite3.connect('/tmp/e2e-data/e2e.db')
c.execute('UPDATE schedules SET next_run_at = ? WHERE id = ?', ('2000-01-01T00:00:00.000Z', '$SCHED'))
c.commit()
"
SCHED_TASK=""
for i in $(seq 1 20); do
  SCHED_TASK=$(curl -sf "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('last_task_id') or '')")
  [ -n "$SCHED_TASK" ] && break
  sleep 0.5
done
[ -n "$SCHED_TASK" ] || { echo "SCHEDULER DID NOT FIRE"; exit 1; }
echo "background scheduler fired OK (task $SCHED_TASK)"

# The launched task is linked to the schedule and completes for real.
for i in $(seq 1 40); do
  SSTATUS=$(curl -sf "http://127.0.0.1:8099/api/v1/tasks/$SCHED_TASK" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'])")
  case "$SSTATUS" in completed|failed|cancelled) break;; esac
  sleep 0.3
done
curl -sf "http://127.0.0.1:8099/api/v1/tasks/$SCHED_TASK" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
t = json.load(sys.stdin)
assert t['schedule_id'] == '$SCHED', t['schedule_id']
assert t['status'] == 'completed', t['status']
print('scheduled task linked + completed OK')
"

# Run-now launches an extra occurrence without touching the anchor.
ANCHOR_BEFORE=$(curl -sf "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['next_run_at'])")
RUNNOW_TASK=$(curl -sf -X POST "http://127.0.0.1:8099/api/v1/schedules/$SCHED/run" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['task_id'])")
ANCHOR_AFTER=$(curl -sf "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['next_run_at'])")
[ "$ANCHOR_BEFORE" = "$ANCHOR_AFTER" ] || { echo "RUN-NOW MOVED THE ANCHOR"; exit 1; }
echo "run-now OK (anchor untouched, task $RUNNOW_TASK)"

# Run history + patch (disable) + delete keep history intact.
HIST=$(curl -sf "http://127.0.0.1:8099/api/v1/schedules/$SCHED/runs" -H "authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
[ "$HIST" -ge 2 ] || { echo "RUN HISTORY INCOMPLETE ($HIST)"; exit 1; }
curl -sf -X PATCH "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"enabled":false}' | python3 -c "
import sys, json
s = json.load(sys.stdin)
assert s['enabled'] is False
print('schedule disable OK')
"
curl -sf -X DELETE "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8099/api/v1/schedules/$SCHED" -H "authorization: Bearer $TOKEN")
[ "$CODE" = "404" ] || { echo "SCHEDULE NOT DELETED"; exit 1; }
curl -sf "http://127.0.0.1:8099/api/v1/tasks/$SCHED_TASK" -H "authorization: Bearer $TOKEN" | python3 -c "
import sys, json
t = json.load(sys.stdin)
assert t['schedule_id'] is None, 'history must survive schedule deletion'
print('history survives schedule deletion OK')
"

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  E2E SMOKE TEST: ALL STEPS PASSED      ║"
echo "╚════════════════════════════════════════╝"
