# Changelog

All notable changes to SecuScan v2. This project follows semantic versioning from its
first tagged release.

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
