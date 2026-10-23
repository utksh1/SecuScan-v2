# Changelog

All notable changes to SecuScan v2. This project follows semantic versioning from its
first tagged release.

## 2.4.0 — recurring scan schedules

Automated recurring scans (pentest-tools.com gap #4):

- New `schedules` domain: a schedule stores the full task admission payload
  (plugin, inputs, preset, workspace) plus an interval (5 min – 365 days); a
  background scheduler worker (`scheduler::run_due` on a configurable tick,
  `SECUSCAN_SCHEDULE_TICK_SECS`, default 30 s) launches a **normal task** every
  time the interval elapses.
- Every automated run re-passes the full admission pipeline extracted into
  `admit_request` (plugin existence/availability/enabled, capability denials,
  input normalization, consent, workspace, target policy + audit trail) —
  tightening policy after creation stops future runs instead of blind-firing.
- Semantics: missed occurrences are skipped (anchor re-anchored to
  `now + interval`, no catch-up bursts); overlap guard skips an occurrence
  whose previous task is still queued/running; admission rejections are
  recorded in `last_error` and retried next interval without disabling the
  schedule.
- API: `POST/GET /schedules`, `GET/PATCH/DELETE /schedules/:id`,
  `POST /schedules/:id/run` (extra occurrence, anchor untouched, bypasses the
  overlap guard by design), `GET /schedules/:id/runs`. Owner-or-404 access,
  viewer read-only, `?workspace_id=` scoping; PATCH distinguishes absent vs
  `null` for `workspace_id`/`preset` (double-Option) so fields can be cleared,
  and re-runs admission on input changes.
- Tasks carry `schedule_id` (migration 0004, `ON DELETE SET NULL` — scan
  history survives schedule deletion); retry preserves it like the workspace.
- UI: **Schedules** page — table with interval/next-run/last-run (+ task link)
  /`last_error` visibility, enable toggles, run-now/edit/delete, create+edit
  form with plugin-typed inputs (shared `FieldInput` component extracted from
  NewTask), interval presets + custom minutes (client-validated ≥ 5 min),
  workspace picker, recurring-consent checkbox, and `?create=1&plugin=&target=`
  deep-link prefill.
- Fixed while building: `?target=` prefill race in NewTask/Schedules forms
  (the plugin-defaults seed effect wiped a prefill that landed while the
  plugins query was still in flight).

## 2.3.0 — async report jobs, webhooks, PDF/DOCX/XLSX

Background report generation with signed callbacks (pentest-tools.com gaps #6 + #7):

- `POST /tasks/:id/reports` queues a job (`waiting` → `in_progress` → `finished` /
  `failed`) and returns `202`; `GET /reports[/:id]`, `GET /reports/:id/download`,
  `DELETE /reports/:id` manage the lifecycle. Jobs are owner-scoped (admins see all).
- New artifact formats: **PDF** (genpdf + embedded DejaVu Sans, tables + per-finding
  detail, control characters normalized, exotic glyphs substituted not panicked),
  **DOCX** (docx-rs, summary table + details) and **XLSX** (rust_xlsxwriter, frozen
  header + autofilter on the findings sheet, metadata + severity-breakdown sheet).
  The synchronous export endpoint serves all 8 formats too, with a new
  `?severity=` min-severity filter shared by both surfaces.
- **Webhooks**: HMAC-SHA256 signed callbacks (`x-secuscan-signature: sha256=…`,
  GitHub-compatible scheme), `x-secuscan-event` / `x-secuscan-delivery` headers,
  3 attempts with 1s/4s backoff, 10s timeout; delivery failures recorded in
  `webhook_attempts` but never fail the job. Secrets never appear in any API
  response or callback payload.
- Guards: 20 active jobs per user, 100 finished jobs retained (oldest pruned with
  their files), absolute http(s) URLs only, path-containment check on download,
  atomic write-then-rename artifacts, startup recovery marks interrupted jobs
  failed, task deletion cascades jobs and removes files.
- UI: global **Reports** page (live-polling job table with status/format/severity/
  size/webhook columns, download + delete) and a per-task **Reports** tab (instant
  downloads for all 8 formats, background generation form with severity filter and
  webhook fields, job history).
- Renderers extracted to a shared module; the historical `markdown` alias is
  canonicalized to `md` on both surfaces (DB CHECK stores canonical ids only).
- Tests: 6 renderer/filter unit tests (magic bytes for every format, severity
  ordering, CSV formula guard, exotic-glyph PDF safety, HMAC RFC 4231 vector) and
  5 integration tests (full lifecycle across all formats with download verification,
  webhook signature verified against an independent HMAC computation, delivery-failure
  isolation with retry accounting, 3-user isolation + viewer RBAC + validation
  matrix + task-deletion cascade, severity filter parity between sync and async
  surfaces + markdown alias), 8 frontend tests, E2E step 12.

## 2.2.0 — scan diff

Proof-of-progress between runs (pentest-tools.com gap #3):

- `GET /tasks/:id/diff` — findings of a completed task classified as
  new / fixed / regressed / improved / unchanged against a baseline run.
- Baseline auto-selection: latest other completed run of the same plugin against
  the same target visible to the caller (NULL targets match via `IS`); explicit
  `?against=<task_id>` for arbitrary comparisons. User isolation enforced on both
  sides (foreign tasks 404).
- Cross-run identity: (plugin_id, category, title); severity tracked separately so
  a severity change reports as regressed/improved rather than fixed+new.
- UI: "Diff vs previous run" tab on completed tasks — summary chips, attention
  ordering (new → regressed → fixed → improved → unchanged), severity arrows for
  changed findings, link to the baseline run, friendly empty state when no
  baseline exists yet.
- Tests: 3 diff-engine unit tests, 2 integration tests (full classification matrix
  over a deterministic `difftest` fixture plugin with a mode switch, reverse diff,
  user isolation across three users, error paths), frontend tab tests, E2E step
  (identical runs → all unchanged, auto + explicit baseline).

## 2.1.0 — workspaces & first-class targets

Client/project scoping modeled after commercial scanning platforms (pentest-tools.com):

- **Workspaces**: project hubs grouping tasks and registered targets. The synthetic
  *Personal* scope (tasks with no workspace) keeps everything backward compatible;
  deleting a workspace preserves its tasks (they fall back to Personal) while removing
  its targets. Visible to all users; scanner role creates/updates; admin deletes.
- **Registered targets**: per-workspace asset registry with server-derived kind
  (hostname / IP address / URL), unique per workspace, per-target scan counts and
  last-scanned timestamps, and a "scan this target" quick-launch in the UI.
- **Scoped views**: `?workspace_id=<id|none>` on tasks, findings and dashboard; the UI
  workspace switcher scopes all data views; new scans can be filed into a workspace;
  workflow runs accept a workspace; task retry preserves it.
- **UI**: sidebar workspace switcher with active-task badges, Targets page with
  registry management and workspace overview in the Personal scope.
- Fixed during this work: findings multi-severity filter placeholder/OFFSET collision
  (single-severity filters returned nothing, multi-severity silently dropped all but
  the first value, count/list disagreed); dashboard bind-index mismatch when no user
  scope was active.
- Performance: workspace and target counters use fixed-count GROUP BY queries (no N+1).
- Tests: 90 backend (incl. a full workspace/target/scoping lifecycle and a severity
  filter matrix over a deterministic fixture plugin) + 48 frontend; E2E smoke covers
  the workspace flow end to end.

## 2.0.0 — the Rust + React rewrite

Ground-up rewrite of SecuScan (Python/FastAPI) in Rust (axum + tokio + sqlx) and
React 18 + TypeScript, developed with six documented review cycles
(see `docs/REVIEW_LOG.md`: 40+ confirmed findings found and fixed).

### Platform
- Hybrid plugin engine: declarative TOML manifests + 4 native Rust scanners
  (TCP port scan, HTTP security headers, HTTP recon, TLS handshake check) + CLI
  wrappers (nmap, nikto, nuclei, gobuster, whatweb, traceroute, whois, ping, sqlmap).
- **No plugin-supplied code executes** — the v1 parser sandbox is replaced by a
  declarative parser (line_regex / json_lines / static rules), load-time validated.
- Task admission pipeline: availability → enabled → capabilities → input validation →
  consent → canonicalized target policy (deny → allow → plugin) with audit log.
- Live SSE console with DB replay, cursor-based reconnection, event caps.
- Findings: severity/kind model, analyst triage workflow, 5 000/task cap, dedup.
- Reports: Markdown, CSV (formula-injection guarded), standalone HTML, SARIF 2.1.0, JSON.
- Workflows: ordered plugin chains, run history, cancellation.
- Auth: Argon2id + JWT access tokens + rotating httpOnly refresh cookies + API keys +
  RBAC (admin/scanner/viewer) + timing-safe, rate-limited login.
- Hardened subprocess runner: argv-only (no shell), scrubbed env, temp working dirs,
  timeouts, kill-on-cancel, output caps, signal-death reporting.
- CLI (`secuscan`): local scans without a server, plugin validation, server launcher.
- SQLite persistence, WAL, parameterized queries, startup orphan sweep.
- CI (fmt + clippy -D warnings + tests + frontend build), Docker (multi-stage, non-root,
  localhost-bound), full docs suite.

### Security fixes during review cycles
Timing-safe login · host canonicalization in policy matching · same-host-only redirects ·
CSV formula-injection guard · event-persistence caps · hourly-limit erosion · signal-death
status · SSE finished-tag parsing · session revocation on password change · last-admin
guard · zombie-task sweep · login-limiter pruning · body-size caps · native cancellation.

### Removed vs v1 (deliberate, documented)
credential vault · notification/webhook rules · scheduled workflow ticks · saved views ·
attack-surface assets · PDF report export (HTML is print-friendly).
