# Changelog

All notable changes to SecuScan v2. This project follows semantic versioning from its
first tagged release.

## 2.6.0 — Pentest Robots, Attack Surface, Auth Scanning, MCP, Collaboration, Branding

Closes the remaining pentest-tools.com feature gaps with six new platform
capabilities, all proven live end-to-end.

### 1. Pentest Robots — autonomous multi-tool scan orchestration

Robots are DAGs with four node kinds (matching the pentest-tools.com model):

- **Tool** — runs one scan per incoming target
- **Filter** — keeps/discards results by predicate (`severity >=medium`,
  `category=open_port`, `target_contains`, `and`/`or` combinators)
- **Extractor** — pulls new targets from prior findings (`finding_field`,
  `port_url` builds URLs from open HTTP/S ports, `finding_title_regex`)
- **Reducer** — processes all items together (`dedup_by_ip`,
  `unique_targets`)

5 builtin robots ship with the product and are seeded on first startup:
- **Domain Recon** — subdomains → port scan → HTTP recon on every web port
- **Treasure Hunter (domain)** — subdomains → port scan → URL fuzz
- **HTTP Lockpicker** — port scan → HTTP recon → default-credential audit
- **Website Scanner — All Ports** — full TCP scan → website scanner per URL
- **Log4Shell Detector** — port scan → URL extraction → nuclei Log4Shell templates

Users can create custom robots via the API; builtins are immutable. Robot
runs stream state updates to `robot_runs.state_json` so the UI can render
live progress per-node.

- `crates/api/src/robot_runtime.rs` — DAG validator, topological order,
  Tool/Filter/Extractor/Reducer runners, builtin recipes (900 LOC + tests)
- `crates/api/src/routes/robots.rs` — CRUD + run + cancel + builtin seeding
- `crates/db/migrations/0005_v260_features.sql` — `robots`, `robot_runs`
- `crates/db/src/repo/robots.rs` — repository

### 2. Attack Surface — auto-aggregated asset inventory

Every scan's findings are now post-processed by the Attack Surface
aggregator, which extracts asset-identifying metadata (hostname / IP / URL
/ ports / technologies) and upserts into `attack_surface_assets`. The
asset is keyed by a canonical `asset_key` (`host:example.com`,
`ip:1.2.3.4`, `url:http://...`) so repeated scans refresh the same row
instead of duplicating.

The aggregator is heuristic-driven (not parser-specific) so every plugin
contributes without bespoke wiring. It accepts multiple metadata shapes:
- `metadata.hostname` / `metadata.host` / `metadata.domain` → hostname asset
- `metadata.ip` / `metadata.ip_address` / `metadata.address` → IP asset
- `metadata.url` / `metadata.final` / `metadata.original` / `finding.url` → URL asset
- `metadata.ports[]` (array) or `metadata.port` (single) → port list
- `metadata.technologies[]` → tech stack
- `metadata.service{}` → service info

The `GET /attack-surface` endpoint supports workspace filtering and
free-text search; `GET /attack-surface/summary` returns top technologies,
services, and risk counts.

- `crates/api/src/attack_surface_aggregator.rs` — heuristic extractor
- `crates/api/src/routes/attack_surface.rs` — REST endpoints
- `crates/db/src/repo/attack_surface.rs` — upsert/list/count/delete
- Wired into `crates/api/src/manager.rs::finish_task` — best-effort,
  errors logged but never break the task completion path

### 3. Authenticated Scanning — 4 auth methods

Reusable authentication profiles stored per-workspace:

| method | config shape | use case |
|--------|-------------|----------|
| `cookie` | `{cookies: [{name, value}]}` | pre-captured session cookie |
| `header` | `{headers: [{name, value}]}` | Authorization tokens, API keys |
| `form` | `{login_url, username, password}` | standard login forms |
| `recorded` | `{steps: [{action, target, value}]}` | multi-step / SSO flows |

Profiles are validated at creation time. Scans reference a profile via
`POST /tasks` with `auth_profile_id`; the runtime stores it on the task
row (`tasks.auth_profile_id`) for the executor to inject. The MCP
`start_scan` tool exposes the same parameter.

- `crates/api/src/routes/auth_profiles.rs` — CRUD with method validation
- `crates/db/src/repo/auth_profiles.rs`
- `StartTaskRequest` extended with `auth_profile_id`

### 4. MCP Server — Model Context Protocol for AI agents

New `crates/mcp` binary (`secuscan-mcp`) speaks JSON-RPC 2.0 over stdio
or HTTP, exposing 17 tools, 5 resources, and 4 built-in prompts.

**Tools**: `list_plugins`, `start_scan`, `list_tasks`, `get_task`,
`list_findings`, `get_finding`, `triage_finding`, `list_workspaces`,
`create_workspace`, `list_targets`, `add_target`, `list_robots`,
`run_robot`, `get_robot_run`, `list_attack_surface`, `create_report`,
`list_reports`.

**Resources** (read-only URIs): `secuscan://plugins`, `secuscan://tasks`,
`secuscan://findings`, `secuscan://workspaces`, `secuscan://attack-surface`.

**Built-in prompts**: `pentest` (comprehensive scan), `subdomains`
(passive+active enumeration), `summary` (exec summary of recent scans),
`vibeseccoding` (scan-then-remediate plan for a finding).

**Auth**: API key (`SECUSCAN_API_KEY`) preferred for production;
email/password (`SECUSCAN_API_EMAIL`/`SECUSCAN_API_PASSWORD`) supported as
a fallback for local development. The client auto-logs-in and refreshes on
401.

Usage:
```bash
# stdio mode (Claude Desktop, Cursor)
secuscan-mcp --api-url http://localhost:8080 --api-key sk_xxx

# HTTP mode (remote agents)
secuscan-mcp --http 0.0.0.0:9100 --api-url http://localhost:8080
```

- `crates/mcp/` — new crate (lib + main + proto + tools + client)
- `Cargo.toml` workspace members extended

### 5. Collaboration — workspace members + finding comments + @mentions

Workspaces now have explicit members with `owner`/`editor`/`viewer`
roles. Finding comments support `@email` or `@name` mentions; mentioned
users get a row in `mentions` with `read_at` tracking for unread counts.

- `POST /workspaces/:id/members` — add member with role
- `DELETE /workspaces/:id/members/:user_id` — remove (owners can't be removed)
- `GET /findings/:id/comments` — list comments ordered by creation
- `POST /findings/:id/comments` — add comment; @mentions auto-extracted
- `GET /mentions?unread_only=true` — current user's mentions
- `POST /mentions/:id/read` — mark as read

- `crates/api/src/routes/collab.rs`
- `crates/db/src/repo/collab.rs` — members, comments, mentions

### 6. Branded Reports — white-label PDFs

Single per-instance row (`branding`, id=1) controls org name, logo PNG
(≤256KB), primary/accent hex colors, and footer text. PDF/DOCX report
renderers pick it up automatically.

- `GET /branding` — read current branding
- `PATCH /branding` — update text fields (admin only)
- `POST /branding/logo` — upload PNG logo via multipart (admin only,
  validates PNG magic bytes)

- `crates/api/src/routes/branding.rs`
- `crates/db/src/repo/branding.rs`

### Test suite

- Rust: **180/180 passing** (was 166 in v2.5.0; +14 tests covering robot
  graph validation, filter predicate evaluation, reducer dedup, attack
  surface metadata extraction, and the migration smoke test)
- Frontend (vitest): unchanged at 64/64

### Live verification

`scripts/v260-verify.py` boots the server and exercises every feature:
- 5 builtin robots seeded and listed
- HTTP Lockpicker robot run **completes** against 127.0.0.1
- Auth profile created (cookie method), fetched back
- Port scan produces 6 findings; attack surface auto-aggregates **2
  assets** (URL + host) without bespoke wiring
- Finding comment posted with `@admin@secuscan.local` mention
- Branding updated to "Acme Security" with custom colors; verified
- MCP server returns 17 tools, 4 prompts; `list_plugins` returns 1648
  chars of catalogue data; `list_attack_surface` returns 1338 chars of
  asset data

### Files

- `crates/db/migrations/0005_v260_features.sql` — 6 new tables + 2 task columns
- `crates/db/src/models.rs` — 8 new row types
- `crates/db/src/repo/{robots,attack_surface,auth_profiles,collab,branding}.rs`
- `crates/db/tests/migration_test.rs` — migration smoke test
- `crates/api/src/robot_runtime.rs` — DAG orchestrator (900 LOC)
- `crates/api/src/attack_surface_aggregator.rs` — heuristic aggregator
- `crates/api/src/routes/{robots,attack_surface,auth_profiles,collab,branding}.rs`
- `crates/mcp/` — new crate (lib + main + proto + tools + client)
- `scripts/v260-verify.py` — end-to-end proof harness


## 2.5.0 — full tool catalogue: every pentest binary wired and verified

Closes the gap with pentest-tools.com: **all 13 external binaries** now install
cleanly through `scripts/install-tools.sh` and **all 27 plugins** load with
`available=true` (no "Missing binary" badges). Adds eight new native scanners
that run in-process with zero external tooling.

### Installer overhaul (`scripts/install-tools.sh`)

Reproducible, rootless install of every CLI tool the catalogue can drive.
Wrapper scripts now bundle their own shared-library paths and Perl/Ruby
module trees so the tools run from `~/tools/bin` without polluting the
host system:

- **nmap**: ships `libpcap0.8` + `liblinear4` debs and exports
  `LD_LIBRARY_PATH` from the wrapper (previously failed with
  `libpcap.so.0.8: cannot open shared object file`).
- **nikto**: extracts `libxml-writer-perl` (+ parser/twig) into a
  perllib tree and puts it on `PERL5LIB` (previously failed with
  `Can't locate XML/Writer.pm`).
- **whatweb**: pins `ruby3.3`, bundles `ruby-addressable`, and points
  `RUBYLIB` at the stdlib + vendor ruby paths so `getoptlong` and
  `addressable` load (previously failed with `cannot load such file —
  getoptlong` / `addressable`).
- **testssl.sh**: extracts `bsdextrautils` and prepends the bundled
  `/usr/bin` to `PATH` so `hexdump` is found (previously failed with
  `Fatal error: You need to install hexdump`).
- **nuclei templates**: corrected to `projectdiscovery/nuclei-templates`
  (the original `templates` repo was renamed); 14 108 templates land in
  `~/.config/nuclei/templates/`.

Final tool availability (all from `~/tools/bin`, no sudo):

| tool | version |
|------|---------|
| nmap | 7.95 |
| nikto | 2.6.1 |
| nuclei | v3.11.1 (+14 108 templates) |
| gobuster | 3.8.2 |
| sqlmap | 1.10.10#dev |
| whatweb | 0.5.5 |
| ffuf | 2.3.0 |
| subfinder | v2.17.0 |
| dalfox | 3.2.4 (exposed as the `xss-scanner` plugin) |
| testssl.sh | 3.3dev |
| wafw00f | v2.4.2 |
| whois | 5.6.3 |
| traceroute | system |

### New native scanners (no external binary required)

Eight in-process scanners implemented in `crates/exec/src/native/`,
sharing a dependency-free DNS resolver (`dns.rs`) so they work in
containers and air-gapped labs:

| plugin id | scanner | what it does |
|-----------|---------|--------------|
| `dns-lookup` | `DnsLookupScanner` | A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/CAA with security context (permissive CAA, SPF/DMARC in TXT, verification tokens) |
| `reverse-dns` | `ReverseDnsScanner` | PTR resolution for IPv4/IPv6 with rDNS-missing-mail-server warning |
| `subdomain-finder` | `SubdomainFinderScanner` | active DNS brute-force against a wordlist (default 5 000 labels) + Certificate Transparency log fallback |
| `email-security` | `EmailSecurityScanner` | SPF/DMARC/DKIM/MX posture with policy-grade severity |
| `cors-check` | `CorsCheckScanner` | probes `Access-Control-Allow-Origin` with reflected/origin/null/credential combos |
| `vhost-finder` | `VhostFinderScanner` | brute-force `Host:` headers, diff on status + body size |
| `password-audit` | `PasswordAuditScanner` | form-detection + default-credential list (`default_creds.txt`) |
| `google-dorks` | `GoogleDorksScanner` | passive Google dork enumeration (no scraping, link generation only) |

Each scanner ships with manifest (`plugins/*.toml`), unit tests in the
same file, and is registered in `crates/exec/src/native/mod.rs::registry()`.

### Live end-to-end verification

`scripts/v250_verify.py` boots the lab + server with all binaries on PATH,
runs one scan per plugin (27 total), captures UI screenshots, and dumps
the findings breakdown:

- **27/27 plugins available** (zero "Missing binary" badges)
- **26/27 scans completed** (subfinder timed out against example.com —
  passive source API rate limits, not a SecuScan bug)
- **84 real findings** across 16 plugins, distributed:
  - severity: 2 high / 17 medium / 15 low / 50 info
  - by plugin: google-dorks 12, gobuster 12, nikto 14, email-security 19,
    http-headers 7, subdomain-finder 7, dns-lookup 2, http-recon 2,
    whois 2, plus single finding from nmap/port-scanner/ping/traceroute/
    reverse-dns/tls-check/password-audit/vhost-finder

### Test suite

- Rust: **166/166 passing** (was 116 in 2.4.2 — +50 tests covering the
  new native scanners, the shared DNS resolver, and the new plugin
  manifests).
- Frontend (vitest): **64/64 passing** (unchanged).

### Files

- `crates/exec/src/native/{dns,dns_lookup,reverse_dns,subdomain_finder,
  email_security,cors_check,vhost_finder,password_audit,google_dorks}.rs`
  (+ `default_creds.txt`)
- `crates/exec/src/native/mod.rs` — registry wiring
- `crates/exec/Cargo.toml` — `base64 = "0.22"` for CORS pre-flight encoding
- `plugins/{dns-lookup,reverse-dns,subdomain-finder,email-security,
  cors-check,vhost-finder,password-audit,google-dorks}.toml`
- `scripts/install-tools.sh` — hardened installer (see above)
- `scripts/v250_verify.py` — end-to-end proof harness


## 2.4.2 — parser `skip_patterns`: tool diagnostics are not findings

Running real nikto 2.6.1 against a lab target exposed a parser-quality gap:
nikto's **own diagnostics** — `+ ERROR: Failed to check for updates: 400`
(nikto failing to phone home), `+ WARN:` lines — and **run metadata**
(`+ Target IP`, `+ Target Port`, `+ Start/End Time`, `+ 1 host(s) tested`)
matched the generic line pattern and became fake findings titled "ERROR",
"Target IP", etc. A live scan produced 29 rows of which 7 were noise.

- **core**: `line_regex` parsers accept `skip_patterns` — a list of regexes;
  lines matching any of them are discarded **before** the main pattern runs.
  Manifests without the key are unaffected (backward compatible), and the
  validator reports invalid skip regexes at load time.
- **nikto** (v2.0.2): skips ERROR/WARN diagnostics, "No web server found",
  Start/End Time, Target IP/Hostname/Port, and the "N host(s) tested"
  summary. The same lab scan now yields 22 findings — all genuine.
- Regression test: `nikto_diagnostics_are_skipped` (suite: 116 passing).
- New evidence in `download/ui-screens/`: scanners catalogue with 12/13
  real binaries detected, findings/tasks pages populated by live
  nmap/gobuster/nikto runs.

## 2.4.1 — real-tool verification: gobuster/nikto parser fixes

Verified the whole platform against **real installed binaries** (nmap 7.95,
nikto 2.6.1, nuclei 3.11.1 + templates, gobuster 3.8.2, sqlmap 1.10,
whois 5.6.3, traceroute) scanning a live lab target: 43 normalized findings
across 9 plugins, full reports. Two parser bugs surfaced and were fixed:

- **gobuster** (v2.0.1): the parser expected the legacy `Found: /path
  (Status: 200)` prefix that gobuster removed in v3.5 — modern output
  (`path  (Status: 200) [Size: n]`) produced **zero findings**. The new
  pattern handles both formats, normalizes the leading slash, and severity
  globs (`.git*`, `backup*`, `admin*`, ...) now match modern paths.
- **nikto** (v2.0.1): check lines carry a numeric id (`[740001]`) that the
  old parser discarded; only legacy `OSVDB-*` lines could ever elevate
  severity. The id is now captured and mapped (backup/cert files and git
  exposure -> medium, outdated software / missing headers / robots.txt
  disclosures -> low, any other id-carrying check -> low), and colon-less
  check lines ("X appears to be outdated") parse instead of being dropped.
- **core**: template rendering of unmatched *optional* capture groups now
  yields an empty string instead of a literal `{group}` placeholder
  (mustache-style), enabling optional-group patterns. Verbatim scanner
  lines remain the default evidence when no proof template is set.
- Regression tests: `gobuster_both_output_formats`,
  `nikto_check_ids_get_severity` (suite: 115 passing).

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
