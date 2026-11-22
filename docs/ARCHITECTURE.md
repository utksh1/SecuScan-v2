# Architecture

## Workspace layout

```
secuscan-v2/
├── crates/
│   ├── core/      domain models, plugin manifests + validation, safe argv
│   │              builder, declarative parser engine, target policy,
│   │              net-scope classification, LLM/soft-404 groundwork
│   ├── exec/      subprocess runner (process trees, bounded output, honest
│   │              exits), 20 native scanners, OOB context, net guard,
│   │              plugin rate limiter, live event stream
│   ├── db/        SQLite (sqlx) migrations + repositories, at-rest
│   │              encryption of credential columns
│   ├── api/       axum HTTP server: auth, routes, SSE, TaskManager,
│   │              scheduler, notifications, reports, OOB receiver,
│   │              rate limiting, destination policy
│   ├── mcp/       JSON-RPC 2.0 MCP server (scoped keys, one-use approvals)
│   └── cli/       the `secuscan` command line tool
├── plugins/       50 declarative plugin manifests (.toml)
├── frontend/      React 18 + TypeScript + Vite + Tailwind + React Query
├── docs/          this documentation
├── docker/        Dockerfile + compose file
└── .github/       CI
```

Dependency direction (no cycles):

```
core ← exec ← api → db
       ↑          ↘ mcp (core + db, talks to the API over HTTP)
       └───── cli (core + exec + db)
```

`core` is deliberately free of async-runtime and framework concerns: everything in it is
pure data transformation, which is what makes its 37 unit tests trivial to reason about.

## The task lifecycle

```
POST /api/v1/tasks
  │
  ├─ 1. plugin exists & available (binaries on PATH)      → 404 / 400
  ├─ 2. plugin enabled (admin toggle)                     → 403
  ├─ 3. capabilities not denied (SECUSCAN_DENIED_CAP…)    → 403
  ├─ 4. inputs validated + defaults applied
  │     (unknown keys rejected, patterns, select options,
  │      integer bounds, flag-injection guard)            → 400
  ├─ 5. consent required? consent_granted == true         → 400
  ├─ 6. target policy: deny → allow → plugin targets,
  │     on hosts canonicalized first; denials audited     → 403
  └─ 7. task row created (queued) → TaskManager::spawn
        │
        ├─ acquire global slot (cancellable)
        ├─ acquire plugin slot + hourly window reservation
        ├─ mark running → execute (CLI subprocess | native)
        │     • events streamed → recorder → DB + broadcast
        │     • timeout kill / cancel kill / output caps
        ├─ parse output (line_regex | json_lines | static rules)
        └─ persist findings + final status + stats
```

Statuses: `queued → running → completed | failed | cancelled`, with `status_detail`
carrying the precise terminal reason (`timed_out`, `auth_failed`,
`max_scan_time_reached`, `cancelled`) so a timeout is never mistaken for a plain
failure. A server restart sweeps orphaned queued/running rows to `failed` at boot so
the UI never shows zombie scans. Cancelling a scan persists the partial findings
captured before the stop, and `max_scan_time_minutes` is a reporting-friendly soft
cap that ends Completed-with-partials.

## Event pipeline (live console)

1. The executor emits `EventEnvelope`s into a bounded mpsc channel (4096); a stalled
   consumer can never block a scan (sends time out after 2s and drop).
2. The **recorder** task persists each event (capped at 10 000/task — beyond the cap
   events are only broadcast), then fans it out on a broadcast channel **carrying the DB
   row id**.
3. `GET /tasks/:id/stream` (SSE) subscribes *before* reading the DB, replays persisted
   events, then forwards live frames — skipping any frame with `id <= replay cursor`.
   This makes replay/live transitions exactly-once. The client reconnects with
   `?after=<last id>` and exponential backoff.

## Auth model

- **Access tokens**: HS256 JWTs, 30-minute TTL, kept in browser memory only.
- **Refresh tokens**: opaque 384-bit random values, stored **hashed** (SHA-256) in the
  DB, delivered as an httpOnly `SameSite=Lax` cookie, **rotated on every use** — reuse of
  a rotated token fails.
- **API keys** (`X-API-Key`): for automation; shown once, stored hashed.
- **Roles**: `admin` (everything), `scanner` (run scans, triage), `viewer` (read-only).
- Passwords: Argon2id. Login is timing-safe (dummy hash for unknown emails) and rate
  limited (30/min per IP+email). Password change revokes all sessions.

## Parser engine (why no plugin code runs)

v1 executed each plugin's `parser.py` in a subprocess sandbox. v2 replaces the entire
concept: a plugin's output normalization is *data* —

- `line_regex`: one finding per matching line; `{group}` templates, severity-elevation
  rules (glob or exact match on captured groups), metadata passthrough.
- `json_lines`: one finding per JSON object line; dot-path field mapping + severity map.
- `static_rules`: whole-output regex heuristics (e.g. nmap `VULNERABLE`).

All templates are cross-validated at load time (every `{group}` must exist in the
pattern; every `{field}` must be declared), so a broken plugin is rejected at startup
rather than mid-scan. Findings are deduplicated and capped at 5 000/task.

## Native scanners

Twenty in-process Rust scanners sharing the same contract as CLI plugins —
`port_scanner`, `http_headers`, `http_recon`, `tls_check`, `dns_lookup`,
`reverse_dns`, `subdomain_finder`, `domain_finder` (CT subdomains + TLS-certificate
organization pivot + redirect verification), `email_security`, `cors_check`,
`vhost_finder`, `password_audit`, `api_scanner`, `website_scanner` (crawl + DAST +
OOB arming), `people_hunter`, `google_dorks`, `param_finder`, `js_analyzer`,
`drupal_scanner`, `cloud_scanner`, `xss_exploiter`, `http_request_logger` —
registered in a static registry.

Every scan start runs the **connect-time destination guard** (`net_guard`): the
target is resolved and every DNS answer is classified (`core::net_scope`); cloud
metadata endpoints are always refused, strict mode (env) refuses private resolutions
for hostname targets, and the website scanner **pins** the validated addresses into
its HTTP clients so mid-scan DNS rebinding cannot move the scan. Redirects stay on
the original host (case-insensitive comparison). Output capture is bounded per
stream and per line; subprocesses run in their own process group so cancel/timeout
terminates the whole tree.

### OOB (out-of-band) pipeline

`http_request_logger` and `xss_exploiter` provision OOB callback handlers backed by
the API's public receiver (`/api/v1/oob/:secret`, CORS-open). The receiver serves a
live browser-capture script (cookies, HTML, keystrokes, optional screenshot) built
from the handler config; captured beacons are recorded as hits, correlated to the
originating task via per-scan markers, and **automatically open validated
findings**. Requires `SECUSCAN_PUBLIC_URL` (the deployment's externally reachable
base URL); the OOB tools fail loudly without it. Handlers cap at 500 hits and a
daily maintenance pass purges expired handlers.

### MCP server (agentic surface)

`crates/mcp` is a JSON-RPC 2.0 MCP server (stdio + HTTP transports) exposing scans,
findings triage, robots, sniper, reports and attack-surface reads to LLM agents.
Governance: HTTP transport requires `Authorization: Bearer`; API keys can be issued
with an `mcp_scan` scope that an exhaustive route allowlist confines to approved
endpoints; every scan requires **consent plus a one-use, admin-issued approval
token** bound to the scanner user, the exact inputs and the plugin version/engine —
unapproved robot and sniper runs are disabled. See `docs/MCP_CONSENT.md`.

## Database

SQLite via sqlx (WAL, foreign keys on, 5 connections). All queries are parameterized —
there is no string-built SQL anywhere. Tables: `users`, `refresh_tokens`, `api_keys` (scoped, expiring),
`plugin_states`, `workspaces` (access modes + members), `targets`, `tasks`
(schedule/robot/sniper/workflow linkage, OOB markers, status detail),
`task_events`, `findings` (dedup groups, FP-triage surface, enrichment, evidence),
`oob_handlers` + `oob_hits`, `fp_memory`, `notification_rules` +
`notification_log`, `report_jobs`, `schedules` (named frequencies),
`workflows`/`workflow_runs`, `robots`/`robot_runs`, `sniper_runs`,
`auth_profiles`, `vpn_profiles`, `attack_surface`, `finding_templates`,
`branding`, `policy_audit`, `settings`. Findings/tasks/events cascade on delete.

**At-rest encryption**: `auth_profiles.config_json` (cookies, bearer tokens, form
passwords) and `vpn_profiles.config_text` are sealed with AES-256-GCM
(`secuscan_core::crypto`, `enc:v1:` format) — key from `SECUSCAN_ENC_KEY` or an
auto-generated `data/.secuscan-enc-key` (0600). The SQLite file alone no longer
recovers credentials; rows re-seal on write and legacy plaintext decrypts
transparently.

### Workspaces

Workspace authorization uses an explicit compatibility boundary.
**Existing workspaces remain `shared`** after migration 0011 (visible to all
authenticated users, global scanners can edit, workspace creator/admin manages).
**New workspaces are `private` by default** (creator is owner; admins can
override; explicitly invited `editor`/`viewer` members have different
permissions). Only administrators can deliberately create a new `shared`
workspace using `access_mode: "shared"`. There is no implicit conversion
from private to shared through a PATCH.

Global `admin` bypasses workspace RBAC. The global `scanner` role is
required in addition to private `owner/editor` membership for write
operations; global `viewer` is always read-only. Unknown workspaces and
private non-member IDs respond with the same 404. List filtering happens
server-side, including counts, instead of trusting the UI's workspace filter.
An existing workspace's `created_by` is treated as owner even if an old
database lacks a membership row; migration 0011 backfills those rows.

`tasks.workspace_id` is nullable — NULL is the synthetic *Personal*
scope. Personal tasks, findings, schedules, reports and live streams remain
restricted to their creator (admins can inspect). For `shared` workspaces,
the previous per-user task isolation is retained; for `private` workspaces,
members may read the workspace's task/findings evidence and editors may
modify it. Auth profiles and report jobs retain additional credential/job
owner restrictions.
Deleting a workspace sets its tasks' `workspace_id` to NULL (they fall back to Personal)
and cascades its targets away. Registered targets are unique per workspace and their
kind (hostname / IP address / URL) is derived server-side. Dynamic query fragments
(workspace scope, severity sets) share a running placeholder counter so bind order can
never drift from placeholder numbering — the class of bug found and fixed in cycle 7.

### Workspace authorization matrix

| Resource | Private owner | Private editor | Private viewer | Non-member | Legacy shared |
|---|---|---|---|---|---|
| Workspace metadata, targets, member roster | Read/write/manage | Read/write targets | Read only | 404 | Read by all, scanner writes, creator/admin manages |
| Workspace member changes | Manage | No | No | 404 | Creator/admin |
| Task creation, robot/workflow/sniper launch | Global scanner needed | Global scanner needed | Denied | 404 | Global scanner |
| Task/findings read, synchronous export, SSE | Read | Read | Read | 404 | Existing task-owner/admin visibility |
| Task/findings mutation | Global scanner needed | Global scanner needed | Denied | 404 | Task owner/admin with scanner role |
| Schedules, auth profiles, notification rules | Owner-specific plus workspace permission | Owner-specific plus workspace permission | No mutation | 404 | Creator/admin + global role |
| Asynchronous report jobs and downloads | Job owner (with workspace read) | Job owner (with workspace read) | Existing job restrictions | 404 | Existing job owner/admin rules |
| Personal (no workspace) | Creator only | — | — | 404 | Creator only |
| Admin across all workspaces | Full access | Full access | Full access | Full access | Full access |

The workspace authorizer is centralized in `crates/api/src/access.rs`;
routes must use `require_workspace` for workspace IDs and
`require_resource` for task-linked records, including mutation, export,
and live-stream paths. Workflow templates are globally reusable; executing
one into a private workspace requires editor permissions.

### Schedules

A schedule persists a full admission payload (plugin, normalized inputs, preset,
workspace) plus a cadence: either a legacy `interval_seconds` or a **named
frequency** (`hourly | daily | weekly | monthly | quarterly | once`) with an
`anchor_time` ('HH:MM') in an IANA `tz` — monthly/quarterly clamp to the month's
last day, and `once` disables itself after firing. A single background worker
(`scheduler::run_due`, tick `SECUSCAN_SCHEDULE_TICK_SECS`) launches a *normal task*
through the same admission pipeline on every occurrence — policy or plugin changes
take effect immediately, retroactively, for existing schedules. The anchor always
moves to the next occurrence (no catch-up bursts), an occurrence whose previous task
is still queued/running is skipped, and admission rejections land in `last_error`
and retry next interval. Tasks carry `schedule_id` (`ON DELETE SET NULL`), so
history survives schedule deletion. `POST /schedules/:id/run` is an explicit user
override: it launches an extra occurrence, bypassing the overlap guard, without
touching the anchor.

**Auto-diff (the monitoring loop)**: a completed scheduled occurrence diffs itself
against the previous completed run of the same plugin+target (workspace-scoped
baseline). The summary — new / fixed / regressed / improved / unchanged — is logged
on the task, and a `diff` notification trigger fires **only when something actually
changed**, delivering a `scan.diff` webhook payload with the classified diff. First
runs (no baseline) and unchanged runs stay silent.

## Finding provenance and identity (evidence schema)

Every finding carries defensible provenance (issue #15):

| Field | Source | Meaning |
|---|---|---|
| `plugin_id`, `plugin_version` | stamped at insert | which scanner, at which version, made the claim |
| `task_id` → task (target, inputs, output, ran-at) | FK | the run that observed it, including the raw captured output |
| `created_at` | insert time | observed-at |
| `fingerprint` | sha256(plugin_id \| target \| endpoint \| category \| title) | deterministic cross-scan identity |
| `confidence`, `kind` | scanner + analyst | observed vs validated, without overstating verification |
| `analyst_status` | triage lifecycle | new → confirmed / needs_review / false_positive / accepted_risk / fixed |

The **fingerprint** is the deterministic identity: stable across identical
re-scans, scoped to target + endpoint (never falsely merging distinct
targets), independent of proof/description text, with volatile query
parameters (session tokens, CSRF nonces, cache busters) stripped from the
endpoint while functional parameters (an IDOR's `?id=`) are preserved. The
diff engine prefers the stored fingerprint and falls back to the historical
(plugin, category, title) triple for pre-migration rows.

**Retention and redaction**: stored evidence (proof, OOB hits, task output)
is kept raw — analysts need the real capture; OOB hits expire with their
handler TTL and the daily purge. Analyst-facing reports render `proof`
through `redact_secrets`, which masks credential **values** (Authorization
headers, Set-Cookie values, password/token/api-key/secret/session params)
while preserving the credential names that carry the signal.

### Soft-404 classification (first ML touchpoint)

`core::soft404` is the shipped ML component (issue #31, the first of the six
planned AI touchpoints): a feature-based logistic classifier over the
de-boilerplated page — body/word counts, link/form/script density, error
keywords in title vs body, requested-path echo — producing a probability and
a four-way label (hit / partial / miss / inconclusive). The website scanner
gates discovery-path findings with it: hits are skipped (counted in a task
event), partials are demoted to Info, misses are trusted. Weights are
hand-calibrated against the labeled fixture set in the unit tests (precision
and recall 1.0 on that corpus); `scripts/soft404_dataset.mjs` collects a live
labeled corpus for offline recalibration. Fully local, zero model download,
graceful fallback to the legacy heuristic predicate.

## Notifications, callbacks and egress policy

Notification rules (per workspace) trigger on scan status, severity-threshold
findings or **diff events**; channels are Slack/Teams/Discord webhooks, generic
HMAC-SHA256-signed webhooks (`X-SecuScan-Signature`) and email (stubbed). Scan
launches can carry a `report_callback` — the server pushes a signed
`task.finished` payload (`raw_status`, `raw_json` or a base64 branded PDF) instead
of forcing the client to poll.

All webhook egress runs one policy layer at send time: destination hostnames are
resolved and every DNS answer classified (metadata refused unconditionally;
private/loopback per `SECUSCAN_WEBHOOK_ALLOW_PRIVATE` / `SECUSCAN_OUTBOUND_*`),
deliveries never follow redirects, response reads are bounded, and every attempt —
including failures — lands in the delivery log. See `SECURITY.md` for the knob
table and threat boundary.

## Frontend

React 18 + TypeScript strict + Vite + Tailwind CSS + React Query. Auth lives in a context
(single-flight refresh, query-cache wipe on logout, global 401 → login redirect). The
live console is a fetch-based SSE reader (EventSource cannot send Authorization headers)
with cursor reconnection. All state is server-state via React Query — the client holds
almost no local state beyond forms and filters (URL search params).

## Roadmap (deliberately deferred)

Already shipped since v2.6.0: CVE/CVSS/EPSS/KEV enrichment, finding templates +
manual findings, the MCP server, notification rules, attack-surface aggregation,
VPN-pinned internal scanning, Sniper auto-exploiter, OOB callbacks, branded
multi-format reporting with signed callbacks, false-positive memory, at-rest
encryption, MCP scan approvals, named schedule frequencies with auto-diff, and
connect-time destination enforcement.

Remaining, in rough priority order: TOTP 2FA and SSO · aggregated multi-scan
reports with an executive-summary layer · structured evidence items
(request/response pairs, screenshots) with an evidence viewer · OpenVAS engine ·
distributed workers behind a Redis queue · the AI layer (soft-404 classifier,
LLM finding enrichment, Mini-Specter agent over MCP) · WASM plugin engine for
parsers that genuinely need code. The full acceptance-criteria plan lives in
`docs/MAX_PARITY_PLAN.md`; per-domain criteria in `docs/MAX_PARITY_CRITERIA.md`.
