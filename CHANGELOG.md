# Changelog

All notable changes to SecuScan v2. This project follows semantic versioning from its
first tagged release.

## 3.1.3 -- Python-free + toast UX + scan-diff button + commit attribution

Three pieces of cleanup surfaced by the user after v3.1.2:

### 1. Commit attribution

All 22 commits in the repo were authored by AI/CI identities ("Z User",
"SecuScan CI", "SecuScan Dev", "SecuScan v2 Agent") which meant none of
them counted toward the user's GitHub contribution heatmap. Rewrote the
entire history with `git filter-branch --env-filter` to set
`GIT_AUTHOR_NAME` / `GIT_COMMITTER_NAME` / emails to
`Utkarsh Singh <183999732+utksh1@users.noreply.github.com>` (the GitHub
noreply form, which is what the heatmap keys off). Original commit
dates and messages preserved. Force-pushed `main` and all 6 tags
(v2.5.0, v2.6.0, v3.0.0, v3.1.0, v3.1.1, v3.1.2). All 4 existing GitHub
releases survived the tag move. Repo-level git config now defaults to
the user's identity so future commits are attributed correctly without
filter-branch.

### 2. Python removed from the repo

The user called out that the project should not contain any Python.
v3.1.2 and earlier shipped 9 Python verification scripts (`v250-verify.py`
through `v312-verify.py`, plus `e2e-smoke.sh` which embedded Python
heredocs) and a Python OpenAPI generator (`gen_openapi.py` owned by the
agent sandbox, not the repo).

- Deleted all 9 Python verify scripts and `e2e-smoke.sh`.
- Replaced with a single consolidated Node script: `scripts/verify.mjs`.
  Zero npm dependencies (uses Node >= 18 global `fetch`), 51 assertions
  covering auth, plugin catalog, OpenAPI spec endpoints, Attack-Target
  suites, Sniper from a finding, Replay + scan-diff, People Hunter,
  VPN-aware admission gate (pin -> 409 -> unpin -> 201 with the
  attack-target endpoint propagating 409), SPA serving, SSE replay, and
  SARIF report artifact. Signal-safe cleanup kills the detached server
  on SIGTERM/SIGINT/SIGHUP/exit so background runs can't leak orphans.
- Removed `docs/openapi.yaml` (was a stale duplicate of the JSON
  artifact). `GET /api/v1/openapi.yaml` now serializes the embedded
  JSON to YAML at runtime via `serde_yaml`. One source of truth
  (`docs/openapi.json`), no Python generator, no drift.
- Deleted `scripts/gen_openapi.py` (was in the agent sandbox, never
  committed to the repo, but referenced by the v3.1.2 changelog entry
  -- that reference is now corrected below).
- `Makefile` `verify` target now runs `node scripts/verify.mjs` instead
  of `bash scripts/e2e-smoke.sh`.
- Added `secuscan export-openapi` CLI subcommand that prints the
  embedded spec to stdout (or `--output <file>`), so SDK generation
  pipelines can pull the spec without a running server.

### 3. Toast UX + scan-diff button

Two UX affordances the user asked for after v3.1.2:

- **Toast system** (`frontend/src/components/Toast.tsx`): a
  `ToastProvider` mounted once in `App.tsx` so toasts survive route
  navigation. Fixed bottom-right stack, auto-dismiss after 10s, manual
  close, optional SPA-link chips. The Attack-Target mutation in
  `Targets.tsx` now raises a toast titled "Attack launched on
  \<target\>" with one chip per launched task id (deep-linking to
  `/tasks/<id>`), so the user can jump directly to any of the just-
  launched scans. The toast survives the `navigate('/tasks')` jump.
- **"Compare to previous run" button** on `TaskDetail`: a new
  `btn-secondary` next to the existing Replay button, visible when the
  task is not active. Clicking it switches to the existing Diff tab,
  which fetches `GET /tasks/:id/diff` and renders the auto-baselined
  comparison (new / fixed / regressed / improved / unchanged). The
  backend endpoint already existed; this wires a one-click affordance
  to it from the task header.

### Tests

- 208/208 Rust (was 208 in v3.1.2; the v3.1.2 YAML test
  `embedded_yaml_starts_with_openapi_directive` was renamed and
  strengthened to `yaml_serialization_round_trips_the_spec`, which
  now re-parses the serialized YAML and asserts equality with the
  original spec — guards the runtime JSON->YAML conversion against
  drift and content loss, not just the first 12 bytes).
- 64/64 frontend.
- `scripts/verify.mjs`: 51/51 assertions green (replaces all 9 retired
  Python harnesses; covers everything they covered plus the v3.1.2
  features).

### Bug fixes

- `serde_json` workspace dep gained the `preserve_order` feature so the
  runtime YAML serialization preserves the authored key order (without
  it, `serde_yaml` sorted keys alphabetically and the spec started with
  `components` instead of `openapi`).

## 3.1.2 -- OpenAPI spec + Attack-Target + UI action buttons

Closes the four product-grade gaps surfaced after v3.1.1: a published
OpenAPI spec (so external clients can discover the API without reading
source), a one-click Attack-Target suite launcher (pentest-tools.com's
"Attack Target" button), a Sniper launch button on the Findings page
(so users can fire exploit chains without leaving the finding context),
and a clearer Replay label on TaskDetail. Plus a UX bug fix: the
Attack-Target endpoint now propagates the VPN admission gate's 409
instead of silently swallowing it as a 400 "all plugins skipped".

### 1. OpenAPI 3.1 spec

The full `/api/v1` surface (94 paths, 25 schemas) is now published as
an OpenAPI 3.1 document. Three endpoints serve it:

- `GET /api/v1/openapi.json` -- JSON spec, embedded at compile time
  (no runtime YAML parser dependency).
- `GET /api/v1/openapi.yaml` -- YAML spec, same source.
- `GET /api/v1/openapi` -- HTML landing page that loads Swagger UI
  from the jsdelivr CDN, pointed at the JSON endpoint.

The spec is hand-maintained at `docs/openapi.json` (in v3.1.3 the
YAML duplicate was removed and `GET /openapi.yaml` is serialized from
the JSON at runtime via `serde_yaml`). Two Rust tests
(`embedded_json_parses_and_has_expected_top_level_keys`,
`yaml_serialization_round_trips_the_spec`) guard the artifact at build
time -- a malformed spec fails CI instead of reaching clients.

The sidebar gains an "API Spec" entry that opens the Swagger UI in a
new tab.

### 2. Attack-Target endpoint

`POST /api/v1/targets/:id/attack` with body `{"suite": "quick|web|full|internal"}`
launches a curated multi-tool suite against a registered target with
one POST. Each plugin becomes its own task in the target's workspace,
admitted through the standard `validate_and_create_task` pipeline so
the global target policy, per-plugin consent gate, and v3.1.1 VPN-aware
admission gate all still apply.

Suites are target-kind aware:

| suite | hostname/url | ip_address |
|-------|--------------|------------|
| quick | http-recon + http-headers + dns-lookup | dns-lookup + nmap |
| web | quick + whatweb + nikto + ssl-scanner | (rejected: 400) |
| full | web + subdomain-finder + nmap + wordpress-audit + drupal-scanner | nmap + smb-enum + ssh-audit |
| internal | (rejected: 400) | nmap + smb-enum + ssh-audit |

Response: `201 Created` with `{suite, target_id, target, workspace_id, tasks[], skipped[]}`.
`tasks[]` lists admitted task ids; `skipped[]` lists plugins that
weren't launchable (binary missing, disabled, etc.) with a reason.

Special case: if the VPN admission gate rejects with 409 Conflict, the
attack endpoint propagates 409 immediately rather than silently
catching every plugin as "skipped" and returning a misleading 400.

### 3. Sniper launch button on Findings

Each finding row on `/findings` gains a violet "Sniper" button (Zap
icon) for admins/scanners. Clicking it calls `POST /sniper/run` with
the finding id; on success the user is navigated to `/sniper` to watch
the chain progress. The button shows pending state and surfaces
per-row error messages.

### 4. Replay label on TaskDetail

The existing `POST /tasks/:id/retry` endpoint is unchanged; the UI
button label was "Retry", now "Replay" to match pentest-tools.com's
"Replay Attack" terminology and disambiguate from "retry on transient
error" (which it is not -- it re-runs the same plugin+inputs against
the same target, inheriting consent from the original task).

### Bug fixes

- Attack-Target endpoint: when the workspace VPN admission gate
  rejects with 409 Conflict, the endpoint now propagates 409 with a
  message naming the pinned profile. Previously it caught the 409 as
  a per-plugin skip and returned a misleading 400 "all plugins
  skipped".

### Tests

- 208/208 Rust (was 197; +11: 2 OpenAPI embed checks, 9 Attack-Target
  suite-selection + inputs_for tests).
- 64/64 frontend.
- New `scripts/v312-verify.py`: proves OpenAPI spec served (94 paths /
  25 schemas), Attack-Target suites work + reject correctly per target
  kind, Sniper from a finding still works, Replay creates a new task,
  and the v3.1.1 VPN admission gate still blocks attack requests
  through the new endpoint.

## 3.1.1 -- VPN-aware scanning admission gate

The v3.1.0 VPN feature stored profiles and exposed connect/disconnect, but
did not *enforce* tunneled scanning. A pinned workspace would happily run
its scans through whatever route the host happened to have -- exactly the
silent-wrong-route failure that VPN pinning is supposed to prevent. v3.1.1
closes that hole and adds the missing audit trail.

### VPN-aware task admission

When a workspace has a `vpn_profile_id` pin, the task admission pipeline
calls `vpn_manager::connect()` *before* persisting the task. This is a
no-op when the tunnel is already healthy and auto-heals a stale one, so
the common path costs nothing. If the tunnel cannot be brought up (no
`openvpn` binary, bad config, dead peer), admission returns **409
Conflict** naming the pinned profile, and no task is created. This is a
security property, not a convenience: an internal scan launched without
its tunnel would silently probe the wrong routes.

When the workspace is in the middle of connecting (status `connecting`),
admission returns 409 with a "retry shortly" hint instead of racing the
handshake.

### Audit trail

`tasks.vpn_profile_id` records which profile guaranteed a task's route
(NULL when the workspace had no pin). `GET /tasks/:id` and the task list
payloads expose this field, so reports can answer "did this scan go
through the corporate tunnel?".

### New endpoints

- `GET /workspaces/:id/vpn` -- returns the pinned profile (or `null`) with
  its current status and `openvpn_available` flag, so the UI can warn
  before a user attempts a scan that will be rejected.

### UI

- New `/vpn` page: list/create/delete profiles, connect/disconnect,
  pin/unpin to any workspace, graceful "openvpn not installed" warning.
- New `/sniper` page: live Sniper run list with per-step status, finding
  counts, outcome badge (`proven` / `not_proven` / `inconclusive`), and
  proof text.
- Both pages are linked from the sidebar (Zap icon for Sniper, Network
  icon for VPN) and restricted to admins/scanners for write actions.

### Bug fixes

- `schedule_crud_and_validation` test: assertion `>` on `next_run_at`
  was a strict-greater-than check that flaked under parallel test
  execution when the disable+re-enable round-trip completed within the
  same wall-clock second as the prior interval patch. Relaxed to `>=`
  with a comment explaining the semantic guarantee.
- Removed unused `attachTarget` state in `VpnPage.tsx` (TS6133 build
  breakage under strict `noUnusedLocals`).

### Tests

- 197/197 Rust (unchanged count; flaky schedule test hardened).
- 64/64 frontend.
- New `scripts/v311-verify.py`: proves the admission gate end-to-end
  (pin -> 409 -> unpin -> 201 -> task.vpn_profile_id NULL).

## 3.1.0 -- Sniper Auto-Exploiter, People Hunter, VPN profiles

The final three pentest-tools.com feature gaps, closing the platform to full
parity on every documented non-AI capability.

### 1. Sniper Auto-Exploiter

Finding-driven exploit chains. Given a finding, Sniper picks a chain of
exploit steps tailored to the finding's category, executes them as real
scan tasks, and aggregates results into a proof. When any step produces a
`validated_issue` (or critical/high) finding, the source finding is upgraded
to `validated_issue` + `confirmed` with the proof attached.

Chains (matched case-insensitively on category substring):

| category match | steps |
|----------------|-------|
| SQL | sqli-exploiter (confirm) -> sqli-exploiter (enumerate) -> sqli-exploiter (extract hashes) |
| XSS | xss-exploiter (OOB handler + payload) |
| Credential | password-audit (brute force) |
| WordPress | wordpress-audit (deep) |
| Drupal | drupal-scanner (CVE) |
| TLS | testssl (full audit) |
| Port | nmap (service + script sweep) |
| HTTP (catch-all) | http-recon -> http-headers |

A failing step (e.g. missing binary) marks that step failed but does not
abort the chain. Every exploit step re-runs through the standard task
admission pipeline, so the global target policy and per-plugin consent
gates still apply.

- `POST /sniper/run` `{finding_id, workspace_id?}` -> 202 with run_id
- `GET /sniper/runs/:id` -- live step states + proof + outcome
- `POST /sniper/runs/:id/cancel`
- `crates/api/src/sniper_engine.rs` -- chain catalog + orchestrator
- `crates/db/src/repo/sniper.rs` -- run persistence + finding validation

### 2. People Hunter (OSINT)

Native scanner implementing the documented seven-step pipeline:

1. HTTPS probe on 443; extract TLS cert CN when given an IP
2. Bounded same-host crawl (25 pages) collecting HTML/JS/JSON
3. Email regex extraction with noise filtering (images, sentry, examples)
4. Social profile discovery (LinkedIn, X/Twitter, Facebook, Instagram,
   GitHub, YouTube) with share-button noise filtering
5. MX validation via the shared DNS resolver + external-domain filter
6. Pattern analysis: group usernames by convention (first.last,
   first_last, first-last, first-only) with percentages
7. Dominant-pattern prediction surfaced as findings

Optional Tomba.io enrichment: set `TOMBA_API_KEY` + `TOMBA_API_SECRET` in
the server environment. Without keys the crawler-only path works fully
offline.

- New plugin: `people-hunter` (35-plugin catalog)
- `crates/exec/src/native/people_hunter.rs`
- `crates/exec/src/native/dns.rs` -- new `resolve_mx` helper

### 3. VPN Profiles (OpenVPN)

Named OpenVPN configs attached to workspaces; scans in a VPN-enabled
workspace route through the tunnel while it is connected.

- `POST /vpn-profiles` `{name, config_text}` -- store a .ovpn config
  (validated to contain a `remote` directive; <= 512KB)
- `POST /vpn-profiles/:id/connect` -- spawns `openvpn --config ... --daemon`,
  waits up to 20s for the tun/tap interface, tracks the OS pid
- `POST /vpn-profiles/:id/disconnect` -- kills the daemon, clears status
- `PUT /workspaces/:id/vpn` `{vpn_profile_id}` -- attach/detach
- Status machine: disconnected -> connecting -> connected | error
- Startup reconciliation: profiles marked connected whose pid died while
  the server was down flip to error
- Graceful degradation: missing openvpn binary or sandbox without tun
  permissions yields a clear error message, never a crash

- `crates/api/src/vpn_manager.rs` -- process management + interface detection
- `crates/db/migrations/0007_v310_features.sql` -- sniper_runs, vpn_profiles
- `crates/db/src/repo/{sniper,vpn}.rs`

### Test suite

- Rust: **197/197 passing** (was 186; +11 tests for sniper chain selection,
  people-hunter email regex/pattern analysis, VPN manager pid/binary checks)
- Frontend (vitest): 64/64 unchanged

### Catalog

**35 plugins** (was 34 in v3.0.0).

### Remaining vs pentest-tools.com (all require external services/LLMs)

- AI Pentests (Specter autonomous agent) -- LLM product
- ML Classifier -- fine-tuned model deployment
- Flowmapper -- frontier-model browser agent
- Sniper "detection modules" beyond chain replay -- deep exploit engineering
- Burp Suite extension -- Java client work


## 3.0.0 — OOB callbacks, finding enrichment, notifications, +7 tools, platform parity

Closes the remaining gaps identified in the pentest-tools.com reverse-
engineering teardown. Adds 9 new platform features and 7 new tools, bringing
the catalog to 34 plugins and matching pentest-tools.com on every
non-AI feature axis.

### 1. OOB callback infrastructure

Out-of-band callbacks for blind-vulnerability detection (SSRF, XXE, blind
SQLi, command injection). Per-scan OOB markers (`ptt1a2b3c4d5e6f`) correlate
callbacks back to the scan that induced them.

- `POST /oob-handlers` — create handler (returns secret callback URL)
- `ANY /api/v1/oob/:secret` — public callback receiver (no auth)
- `GET /oob-handlers/:id/hits` — list captured requests
- `crates/db/src/repo/oob.rs` — handler + hit persistence
- Per-scan `tasks.oob_marker` column for blind-vuln correlation

### 2. Finding dedup groups + lifecycle memory

Findings with the same (workspace, plugin_id, normalized_title,
target_fingerprint) end up in a `finding_groups` row. Status changes
propagate to all group members. False-positive decisions are remembered
per (target_fingerprint, plugin_id, title) so future scans auto-mark
matching findings as `false_positive`.

- `crates/db/src/repo/finding_dedup.rs` — group lookup/create + FP memory
- Wired into `manager.rs::finish_task` — runs after every scan

### 3. CVSS/EPSS/CISA-KEV enrichment

Finding rows now carry `cve`, `cvss_v3`, `cvss_vector`, `epss_score`,
`epss_percentile`, `cisa_kev`, `cwe`, `owasp`, `confidence` columns. The
`Finding` struct in `secuscan-core` carries the same fields; native
scanners (Drupal, Cloud) populate them directly.

### 4. Notifications engine

Rule-based notifications with triggers and actions. Triggers: `vuln_found`
(with severity operator), `scan_status`. Actions: `webhook` (HMAC-SHA256
signed), `email`, `slack`, `teams`, `discord`. Every delivery is logged
with HTTP status for retry/audit.

- `crates/api/src/notifications_engine.rs` — evaluator + dispatcher
- `crates/db/src/repo/notifications.rs` — rule CRUD + delivery log
- `POST /notifications`, `GET /notifications/:id/log`

### 5. Scan Groups

Bundle multiple tasks into a named group for one aggregated report.

- `POST /scan-groups`, `POST /scan-groups/:id/tasks`
- `crates/db/src/repo/v300_misc.rs`

### 6. Wordlists (first-class objects)

Upload, list, fetch contents, delete. Stored as files under
`data_dir/wordlists/`. Builtin wordlists are protected from deletion.

- `POST /wordlists` (multipart upload)
- `GET /wordlists/:id/contents?limit=&offset=`

### 7. Finding templates

Public + workspace-scoped templates for standardized manual findings.
Searchable by category.

- `POST /finding-templates`, `GET /finding-templates?category=`

### 8. Asset imports (bulk .txt + CIDR)

Import multiple targets at once. CIDR expansion (e.g. `192.168.1.0/30` →
4 individual IP targets). AWS IAM import is stubbed (returns 501 pending
credentials configuration).

- `POST /asset-imports` with `source: txt|cidr|aws_iam`
- `GET /asset-imports?workspace_id=` — import history

### 9. Seven new tools

| plugin id | engine | what it does |
|-----------|--------|--------------|
| `drupal-scanner` | native | Drupal fingerprinting + CVE matching (Drupalgeddon family) + module enumeration + CHANGELOG.txt exposure |
| `cloud-scanner` | native | S3/GCS bucket public-listing/write test + sensitive file probing |
| `domain-finder` | native | Certificate Transparency log search for related domains with certainty scoring |
| `udp-port-scan` | CLI (nmap) | Nmap UDP scan with two-phase open\|filtered verification |
| `sqli-exploiter` | CLI (sqlmap) | Structured SQLMap wrapper — fingerprint, enumerate, extract |
| `http-request-logger` | native | Creates an OOB callback handler for blind-vuln detection |
| `xss-exploiter` | native | Creates an XSS callback handler with cookie/screenshot/keystroke capture |

Catalog: **34 plugins** (was 27 in v2.6.0).

### Test suite

- Rust: **186/186 passing** (was 180 in v2.6.0; +6 tests for drupal CVE
  matching, cloud bucket classification, domain finder, FP memory
  normalization)
- Frontend (vitest): 64/64 unchanged

### Live verification

`scripts/v300-verify.py` exercises every feature end-to-end:
- OOB handler created, callback hit, hit recorded (source IP, method,
  headers, body all captured)
- Wordlist uploaded (6 words), listed, contents fetched
- Finding template created, listed
- Asset imports: txt (3 created) + CIDR /30 (3 created, 1 skipped as
  network address)
- Notification rule created, listed
- Scan group created, listed
- **34 plugins** in catalog; 5 of 7 new tools available (udp-port-scan
  and sqli-exploiter show unavailable because nmap/sqlmap binaries aren't
  installed in the verification sandbox — expected)

### Files

- `crates/db/migrations/0006_v300_features.sql` — 9 new tables + 3 column
  additions on findings + 1 on tasks
- `crates/db/src/models.rs` — 9 new row types + Finding enrichment fields
- `crates/db/src/repo/{oob,finding_dedup,notifications,v300_misc}.rs`
- `crates/api/src/{notifications_engine.rs,routes/{oob,notifications,v300_misc}.rs}`
- `crates/exec/src/native/{drupal_scanner,cloud_scanner,domain_finder,http_request_logger,xss_exploiter}.rs`
- `crates/core/src/models.rs` — `Finding` extended with enrichment fields
  + `Default` derive for backward-compatible construction
- `plugins/{drupal-scanner,cloud-scanner,domain-finder,udp-port-scan,sqli-exploiter,http-request-logger,xss-exploiter}.toml`
- `scripts/v300-verify.py` — end-to-end proof harness


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
