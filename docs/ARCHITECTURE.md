# Architecture

## Workspace layout

```
secuscan-v2/
├── crates/
│   ├── core/      domain models, plugin manifests + validation, safe argv
│   │              builder, declarative parser engine, target policy
│   ├── exec/      subprocess runner, native scanners, plugin rate limiter,
│   │              live event stream
│   ├── db/        SQLite (sqlx) migrations + repositories
│   ├── api/       axum HTTP server: auth, routes, SSE, TaskManager, reports
│   └── cli/       the `secuscan` command line tool
├── plugins/       13 declarative plugin manifests (.toml)
├── frontend/      React 18 + TypeScript + Vite + Tailwind + React Query
├── docs/          this documentation
├── docker/        Dockerfile + compose file
└── .github/       CI
```

Dependency direction (no cycles):

```
core ← exec ← api → db
             ↘ cli (core + exec + db)
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

Statuses: `queued → running → completed | failed | cancelled`. A server restart sweeps
orphaned queued/running rows to `failed` at boot so the UI never shows zombie scans.

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

In-process Rust scanners sharing the same contract as CLI plugins:
`port_scanner` (async TCP connect, CIDR expansion, per-host DNS resolution up front),
`http_headers`, `http_recon` (same-host-only redirects, 2 MiB body cap), and `tls_check`
(rustls handshake with WebPKI validation, cert-error classification).

## Database

SQLite via sqlx (WAL, foreign keys on, 5 connections). All queries are parameterized —
there is no string-built SQL anywhere. Tables: `users`, `refresh_tokens`, `api_keys`,
`plugin_states`, `tasks`, `task_events`, `findings`, `workflows`, `workflow_runs`,
`policy_audit`, `settings`. Findings/tasks/events cascade on delete.

## Frontend

React 18 + TypeScript strict + Vite + Tailwind CSS + React Query. Auth lives in a context
(single-flight refresh, query-cache wipe on logout, global 401 → login redirect). The
live console is a fetch-based SSE reader (EventSource cannot send Authorization headers)
with cursor reconnection. All state is server-state via React Query — the client holds
almost no local state beyond forms and filters (URL search params).

## Roadmap (deliberately deferred from v1)

credential vault · notification/webhook rules · scheduled workflow ticks · saved views ·
attack-surface asset graph · WASM plugin engine (for parsers that genuinely need code) ·
multi-node scan workers.
