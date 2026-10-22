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
| GET | `/tasks` | `?status=&plugin_id=&workflow_run_id=&search=&limit=&offset=` (admins see all; users see their own) |
| GET | `/tasks/:id` | task detail (no raw output) |
| DELETE | `/tasks/:id` | cancels first if still active |
| POST | `/tasks/:id/cancel` | cooperative cancellation (kills subprocesses) |
| POST | `/tasks/:id/retry` | creates a **new** task with the same inputs |
| GET | `/tasks/:id/result` | task + findings + severity counts |
| GET | `/tasks/:id/output` | raw captured output + truncation flag |
| GET | `/tasks/:id/stream` | **SSE** live console; `?after=<event id>` resumes |
| GET | `/tasks/:id/report/{md\|csv\|html\|sarif\|json}` | report download |

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

### SSE stream format

```
id: 42
event: task
data: {"ts":"2026-10-22T20:52:09.123Z","event":{"type":"log_line","stream":"stdout","line":"…"}}

```

Event types: `phase`, `log_line`, `info`, `warn`, `error`, `progress`, `finished`.
Frames carry their DB row id — replay with `?after=` for gap-free reconnection.

## Findings

| Method | Path | Notes |
|---|---|---|
| GET | `/findings` | `?task_id=&severity=`(repeatable)`&kind=&analyst_status=&category=&search=&limit=&offset=` — sorted critical→info |
| GET | `/findings/:id` | single finding |
| PATCH | `/findings/:id/triage` | `{analyst_status}` ∈ new/confirmed/needs_review/false_positive/accepted_risk/fixed (scanner+) |

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

## Dashboard & admin

| Method | Path | Notes |
|---|---|---|
| GET | `/dashboard/summary` | counters (scoped to the user unless admin) + recent tasks |
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
