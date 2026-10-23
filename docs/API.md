# HTTP API reference

Base URL: `/api/v1` · JSON everywhere · Errors: `{"error":{"code":<int>,"message":<string>}}`

**Authentication** — one of:
- `Authorization: Bearer <access-token>` (30-minute JWT from login/refresh)
- `X-API-Key: <api-key>` (automation)

The refresh token travels as an httpOnly cookie (`secuscan_refresh`) and is rotated on
every `/auth/refresh` call.

## Auth

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/login` | `{email,password}` → `{access_token,user}` + refresh cookie. Rate limited 30/min per IP+email. |
| POST | `/auth/refresh` | cookie → rotated cookie + `{access_token,user}` |
| POST | `/auth/logout` | revokes the presented refresh token |
| GET | `/auth/me` | current user |
| POST | `/auth/register` | disabled unless `SECUSCAN_ALLOW_REGISTER=true` |
| POST | `/auth/api-keys` | `{name}` → `{key}` (shown **once**) |
| GET | `/auth/api-keys` | your keys (prefix only) |
| DELETE | `/auth/api-keys/:id` | revoke |
| POST | `/auth/password` | `{current_password,new_password}` — revokes all sessions |

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@secuscan.local","password":"…"}' | jq -r .access_token)
```

## Plugins

| Method | Path | Notes |
|---|---|---|
| GET | `/plugins` | catalogue with availability/enabled flags + load issues |
| GET | `/plugins/:id` | one plugin (full manifest) |
| GET | `/plugins/:id/schema` | fields + presets (drives the task wizard) |
| POST | `/plugins/:id/preview` | `{inputs, preset?}` → rendered command preview |
| PUT | `/plugins/:id/enabled` | admin: `{enabled}` |

## Tasks

| Method | Path | Notes |
|---|---|---|
| POST | `/tasks` | start a task — see admission pipeline below |
| GET | `/tasks` | `?workspace_id=<id\|none>` scopes to a workspace (Personal = `none`) | `?status=&plugin_id=&workflow_run_id=&search=&limit=&offset=` (admins see all; users see their own) |
| GET | `/tasks/:id` | task detail (no raw output) |
| DELETE | `/tasks/:id` | cancels first if still active |
| POST | `/tasks/:id/cancel` | cooperative cancellation (kills subprocesses) |
| POST | `/tasks/:id/retry` | creates a **new** task with the same inputs |
| GET | `/tasks/:id/result` | task + findings + severity counts |
| GET | `/tasks/:id/output` | raw captured output + truncation flag |
| GET | `/tasks/:id/stream` | **SSE** live console; `?after=<event id>` resumes |
| GET | `/tasks/:id/report/{md\|csv\|html\|sarif\|json\|pdf\|docx\|xlsx}` | synchronous report download (optional `?severity=low..critical` min-severity filter) |

### Starting a task

```bash
curl -X POST localhost:8080/api/v1/tasks \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{
    "plugin_id": "port-scanner",
    "inputs": {"target": "127.0.0.1", "ports": "22,80,443"},
    "consent_granted": true
  }'
```

Admission pipeline (in order): plugin exists → available → enabled → capabilities not
denied → inputs valid (+preset merge) → consent → target policy (denials audited).
Rejections: 404/400/403 with a specific message.

### Scan diff

`GET /tasks/:id/diff` compares the task's findings against a baseline run and classifies
every finding as `new` / `fixed` / `regressed` (severity worsened) / `improved` /
`unchanged`. Identity across runs is (plugin_id, category, title) — the declarative
parser templates produce stable titles for deterministic tools.

- Baseline: auto-selected as the latest *other* completed run of the same plugin against
  the same target visible to the caller; or explicit via `?against=<task_id>`.
- Both tasks must be `completed` (findings are only recorded at completion) — else `400`.
- No baseline exists → `404` with guidance.
- Response: `{task, baseline, auto_baseline, summary{new,fixed,regressed,improved,unchanged}, items[]}`
  where each item carries `finding` (current) and/or `previous_finding` (+ `previous_severity`
  for regressed/improved/unchanged).

### SSE stream format

```
id: 42
event: task
data: {"ts":"2026-10-22T20:52:09.123Z","event":{"type":"log_line","stream":"stdout","line":"…"}}

```

Event types: `phase`, `log_line`, `info`, `warn`, `error`, `progress`, `finished`.
Frames carry their DB row id — replay with `?after=` for gap-free reconnection.

### Async report jobs

Reports can also be generated in the background — the request returns `202`
immediately and the job transitions `waiting` → `in_progress` → `finished` /
`failed`. Artifacts are written under the reports dir (`SECUSCAN_REPORTS_DIR`,
default `<data>/reports`) and served by the download endpoint.

| Method | Path | Notes |
|---|---|---|
| POST | `/tasks/:id/reports` | queue a job; body `{format, severity?, webhook_url?, webhook_secret?}` → `202` + job |
| GET | `/reports` | list the caller's jobs (admins see all); `?task_id=&limit=&offset=` |
| GET | `/reports/:id` | job status |
| GET | `/reports/:id/download` | the artifact (finished jobs only) |
| DELETE | `/reports/:id` | delete the job and its artifact |

Formats: `md`, `csv`, `html`, `sarif`, `json`, `pdf`, `docx`, `xlsx` (the
historical `markdown` alias is accepted and canonicalized to `md`). The
severity filter is a minimum threshold (`low|medium|high|critical`); `pdf`,
`docx` and `xlsx` wrap finding details plus a summary; `xlsx` adds a frozen,
filterable sheet per finding and a metadata/severity-breakdown sheet.

Guards and limits: 20 concurrent active jobs per user (429 beyond), the most
recent 100 finished jobs are retained per user, jobs are visible only to
their owner (or admins), and jobs interrupted by a restart are marked
`failed` at boot.

**Webhooks.** When `webhook_url` is set, a callback is POSTed after the job
reaches a terminal state:

```
POST <webhook_url>
content-type: application/json
x-secuscan-event: report.finished
x-secuscan-delivery: <report job id>
x-secuscan-signature: sha256=<hex hmac-sha256 of the raw body, keyed by webhook_secret>

{"event":"report.finished","report":{ ...same shape as GET /reports/:id... }}
```

The signature scheme matches GitHub's webhook signatures (verify with
`HMAC-SHA256(secret, raw_body)`), so existing verifiers port directly.
Delivery retries up to 3 attempts (1s / 4s backoff, 10s timeout); failures
are recorded in `webhook_attempts` but never fail the job. Webhook URLs must
be absolute `http(s)://` URLs.

## Findings

| Method | Path | Notes |
|---|---|---|
| GET | `/findings` | `?task_id=&severity=`(repeatable)`&kind=&analyst_status=&category=&search=&limit=&offset=` — sorted critical→info |
| GET | `/findings/:id` | single finding |
| PATCH | `/findings/:id/triage` | `{analyst_status}` ∈ new/confirmed/needs_review/false_positive/accepted_risk/fixed (scanner+) |

## Workspaces & targets

Workspaces group tasks and registered targets into project hubs (e.g. per client or
environment). Every authenticated user can read them; the scanner role is required to
create/update; deletion is admin-only. Tasks with no workspace belong to the synthetic
**Personal** scope (`workspace_id = null`) — `?workspace_id=none` selects it.

| Method | Path | Notes |
|---|---|---|
| GET | `/workspaces` | list + per-workspace `tasks_total` / `tasks_active` / `targets_total` + `personal` counters |
| POST | `/workspaces` | `{name (1–100), description?}` (scanner+) |
| GET | `/workspaces/:id` | workspace + counters |
| PATCH | `/workspaces/:id` | `{name?, description?}` (scanner+) |
| DELETE | `/workspaces/:id` | admin only; its tasks fall back to Personal, targets are removed |
| GET | `/workspaces/:id/targets` | registry with `kind` (hostname/ip_address/url, server-derived), `scans_total`, `last_scanned_at` |
| POST | `/workspaces/:id/targets` | `{name (1–255, no whitespace), description?}`; unique per workspace (409) |
| PATCH | `/targets/:id` | `{name?, description?}`; rename re-derives the kind (scanner+) |
| DELETE | `/targets/:id` | scanner+ |

Scoping: `GET /tasks`, `GET /findings` and `GET /dashboard/summary` accept
`?workspace_id=<id>` or `?workspace_id=none`; an unknown id is a 404. `POST /tasks` and
`POST /workflows/:id/run` accept a `workspace_id` in the body; task retry preserves it.

## Workflows

| Method | Path | Notes |
|---|---|---|
| POST | `/workflows` | `{name,description,steps:[{plugin_id,inputs,preset?,label?}]}` (scanner+) |
| GET | `/workflows` | list |
| GET | `/workflows/:id` | workflow + run history |
| PATCH | `/workflows/:id` | update (creator or admin) |
| DELETE | `/workflows/:id` | delete |
| POST | `/workflows/:id/run` | sequential execution; a failed step stops the run |
| GET | `/workflows/:id/runs` | run history |
| POST | `/workflows/runs/:run_id/cancel` | cancels all active tasks of the run |

## Schedules

Recurring scans (pentest-tools.com "schedule scans"). A schedule stores the
full task admission payload (plugin, inputs, preset, workspace) plus an
`interval_seconds`; a background scheduler launches a **normal task** from it
each time the interval elapses, so every run re-passes the full admission
pipeline — plugin availability, enabled flags, capability denials and target
policy. Tightening policy after a schedule was created stops future runs.

| Method | Path | Notes |
|---|---|---|
| POST | `/schedules` | `{name, plugin_id, inputs, preset?, interval_seconds, consent_granted, workspace_id?}` (scanner+) → `201` |
| GET | `/schedules` | list the caller's (admins see all); `?workspace_id=<id\|none>` |
| GET | `/schedules/:id` | detail (owner or admin; strangers get 404) |
| PATCH | `/schedules/:id` | partial update (owner or admin) |
| DELETE | `/schedules/:id` | delete; past tasks survive with `schedule_id` nulled |
| POST | `/schedules/:id/run` | launch one extra run now; the recurring anchor is untouched |
| GET | `/schedules/:id/runs` | run history (newest first, max 50) |

Semantics:

- **Intervals** are 300 s (5 min) to 31 536 000 s (365 days). The first
  automated run happens one interval after creation.
- **Missed occurrences are skipped, not replayed** — the anchor is always
  re-anchored to `now + interval`, so a disabled schedule or server downtime
  never produces a burst of catch-up scans.
- **Overlap guard**: if the previous run of a schedule is still queued or
  running when the next is due, the occurrence is skipped. `POST …/run`
  intentionally bypasses the guard (explicit user action wins).
- **Re-anchoring**: changing `interval_seconds`, or re-enabling a disabled
  schedule, restarts the cadence from `now + interval`. Other edits keep the
  stored anchor.
- **PATCH semantics**: absent fields are unchanged; `workspace_id: null`
  moves the schedule to the Personal scope. Changing `inputs`, `preset` or
  `workspace_id` re-runs admission, so the stored payload is always
  admissible; a policy denial is a clean `403`.
- **Failures**: an admission rejection (plugin disabled, policy change) is
  recorded in `last_error`, the anchor still advances, and the next interval
  retries automatically. Failures never disable the schedule.
- **Consent** is captured once at creation (`consent_granted` follows the
  same rules as task creation); automated runs re-check policy but not the
  checkbox.

Tasks launched by a schedule carry `schedule_id`; the field is `null` for
manual and workflow starts. Example payload:

```json
{
  "name": "Daily port sweep",
  "plugin_id": "port-scanner",
  "inputs": { "target": "10.0.0.5", "ports": "22,80,443" },
  "interval_seconds": 86400,
  "consent_granted": true
}
```

## Dashboard & admin

| Method | Path | Notes |
|---|---|---|
| GET | `/dashboard/summary` | counters (scoped to the user unless admin) + recent tasks; `?workspace_id=<id\|none>` |
| GET | `/health` | public liveness |
| GET/POST | `/admin/users` · PATCH/DELETE `/admin/users/:id` | user management (admin; last-admin guarded) |
| GET/PUT | `/admin/network-policy` | `{allow:[],deny:[]}` globs/CIDRs |
| GET | `/admin/audit?limit=` | policy-blocked target attempts |
| GET/PUT | `/admin/settings` | `{require_consent}` |
| POST | `/admin/plugins/refresh` | re-check plugin binaries on PATH |

## Status codes

`400` validation (message says exactly which field) · `401` auth · `403` policy/RBAC ·
`404` not found (also used to avoid leaking other users' resources) · `409` conflict ·
`429` rate limited.
