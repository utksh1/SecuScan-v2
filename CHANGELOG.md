# Changelog

All notable changes to SecuScan v2. This project follows semantic versioning from its
first tagged release.

## 4.8.1 -- Docs refresh + API contract reconciliation

Closes the documentation debt (issues #12, #13, #14).

### README rewritten against v4.8 reality (#12)

v2.0.0 badge, the "13 plugins" catalogue table and the hardcoded test counts
were stale. Now: v4.8 badge, the 50-plugin inventory (17 native / 33 CLI,
grouped), a capability-highlights table covering everything shipped since
(OOB pipeline, Sniper, robots, MCP governance, FP memory, encryption,
destination policy, named schedules, branded reports), a refreshed safety
model (process trees, exit honesty, connect-time destination enforcement),
test counts delegated to CI so they cannot go stale, and the stale "deferred
features" section replaced (everything listed there has shipped).

### ARCHITECTURE.md: six crates + new subsystems (#13)

Workspace layout gains the `mcp` crate and the encrypted-db/destination-
policy/net-scope modules; the crate graph includes mcp; native-scanner
section covers all 20 scanners + the connect-time destination guard + the
OOB pipeline; new sections for the MCP governance model (scoped keys,
one-use approvals) and notifications/callbacks/egress policy; the database
inventory lists all 25+ tables and the at-rest encryption design; the
schedule section documents named frequencies + auto-diff; the roadmap is
refreshed (shipped items removed, remaining priorities point at
MAX_PARITY_PLAN.md).

### API contract reconciliation (#14)

- `docs/openapi.json`: `/tasks/:id/report/:format` corrected POST → **GET**
  (sync export, per-format responses + `severity`/`include_ignored` query
  params); missing `/reports/:id` (GET + DELETE) added; missing
  `PATCH /findings/bulk` (4.6.0) documented with its request schema.
- `docs/API.md`: sync-export filter row updated, `DELETE /reports/:id`
  added, and a source-of-truth note pointing at the live OpenAPI spec.
- MCP doc comment: the ghost `create_report` tool (removed during the
  governance refactor) and the templated per-id resource URIs (never
  implemented — collection URIs only) are gone.
- **Drift tripwires in verify.mjs**: the historically-drifted endpoints
  (sync export method, `/reports/:id`, `/findings/bulk`, diff, run-now,
  delivery log) are pinned — a spec edit that reverts them fails E2E.

### Tests
verify.mjs 214/214 (+6 contract-drift checks). No behavior changes.

## 4.8.0 -- Max-Parity Sprint 2.3: connect-time destination enforcement

Closes the SSRF pair (issues #6 and #8): destination checks now run at
**connection time**, not only at admission.

### #6 — DNS rebinding + redirect escapes closed

- New `secuscan_core::net_scope`: full address taxonomy (v4-mapped unwrap,
  NAT64 form, ULA, link-local, **cloud metadata**, documentation, loopback,
  private, unspecified, global) + a deployment-configurable
  `OutboundPolicy` (`SECUSCAN_OUTBOUND_ALLOW_PRIVATE`,
  `SECUSCAN_OUTBOUND_ALLOWED_CIDRS`, `SECUSCAN_OUTBOUND_STRICT`).
- `check_target_scope` runs at scan start for every task: resolves the
  target, validates **every** DNS answer, refuses metadata endpoints
  always, and hands the validated addresses to the scanners.
- Website-scanner HTTP clients **pin** the validated addresses
  (`reqwest::resolve`) — a mid-scan DNS flip cannot walk the crawl onto a
  different address. Same-host redirect comparison is case-insensitive and
  trailing-dot-normalized.
- Local-first defaults preserved: loopback/private scanning keeps working
  (the product's own verify suite scans 127.0.0.1); strict mode is opt-in.

### #8 — webhook egress hardening

- Webhook deliveries (notification rules + scan-completion callbacks)
  resolve the destination at **send time** and refuse loopback/private/
  metadata answers (rebinding defense on top of the hostname deny-list).
- Webhook clients **never follow redirects**; captured error bodies are
  capped (4 KiB delivery log, 1 MiB callback ack) — a hostile receiver
  cannot make the server buffer arbitrary bytes.

### Tests
core 68 (+5 net_scope matrix: v4-mapped, NAT64, ULA, CIDR v4/v6, policy
overrides), exec 121 (+2 net_guard), api_test 36 (+1: metadata refusal at
admission + loopback preserved), frontend 75, verify.mjs 208/208.

## 4.7.0 -- Max-Parity Sprint 2.2: monitoring loop + honest lifecycle

Closes issue #25 — the scheduler/lifecycle work package: the auto-diff
monitoring loop, partial-findings preservation, max_scan_time, a richer
terminal-state vocabulary, named schedule frequencies and a gated
pre-flight probe.

### Auto-diff on scheduled runs (the monitoring loop)

A scheduled run that completes now **diffs itself against the previous
completed run** of the same plugin+target (`compute_scheduled_diff`, reusing
the 5-way diff engine with a workspace/user-scoped baseline). The summary
(new / fixed / regressed / improved / unchanged) is logged on the task and —
when anything actually changed — fires the previously-dead **"diff"
notification trigger**: rules with `{ "kind": "diff" }` now receive a
`scan.diff` webhook payload carrying the classified diff. Unchanged runs and
first runs (no baseline) stay silent. E2E: three scheduled runs prove
baseline→silent→silent→fire with new=1/regressed=1.

### Partial findings survive cancel and time caps

- Cancelling a scan now **persists the partial findings** captured before
  the stop (CLI output is parsed regardless of terminal status; native
  scanners returning partials on cancel are recorded as Cancelled-with-
  findings instead of silently Completed).
- New `max_scan_time_minutes` (1..=1440) on `POST /tasks`: a soft cap that
  ends the run **Completed** with partial findings (reporting-friendly),
  distinct from the hard manifest timeout which still fails.

### Honest terminal states via `status_detail`

`tasks.status_detail` (migration 0014) carries the precise terminal reason —
`timed_out`, `max_scan_time_reached` (plumbed), `auth_failed` (auth-profile
resolution failure), `cancelled` — without rebuilding the tasks CHECK
constraint. Exposed via the task JSON. ConnectionError auto-stop and
workflow `Skipped` remain roadmap (documented on the issue).

### Named schedule frequencies

`frequency` (hourly | daily | weekly | monthly | quarterly | once) +
`anchor_time` ('HH:MM') + `tz` (IANA) on schedules; `compute_next_named_anchor`
(chrono-tz) computes the next occurrence after each run — monthly/quarterly
clamp to the month's last day (documented day-drift after a clamp); `once`
schedules disable themselves after firing. Legacy `interval_seconds`
schedules are untouched. Schedule UI: cadence select + time/timezone inputs.

### Gated pre-flight reachability

`SECUSCAN_PREFLIGHT_REACHABILITY=true` (default off) runs a 4 s probe
against URL targets at admission and rejects unreachable hosts with a clear
error instead of burning a full scan.

### Webhook failure logging (found on the way)

A webhook whose **send** failed (DNS, timeout, refused) previously skipped
the delivery log entirely — unreachable receivers left no trace. Failed
sends are now logged as failed deliveries.

### Tests
api_test 35 (+2: auto-diff monitoring loop, named frequencies), core 63
(+5 anchor math incl. DST + month-end clamp), frontend 75, verify.mjs
208/208 (+6 Sprint 2.2 checks).

## 4.6.0 -- Max-Parity Sprint 2.1: analyst-grade findings surface

Closes issue #24 — the findings/report work package: enrichment rendering,
severity override, richer triage, bulk operations, manual findings, keyset
pagination and scan-completion callbacks.

### Enrichment is now visible everywhere

`cve / cvss_v3 / cvss_vector / cwe / owasp / epss_score / epss_percentile /
cisa_kev` sat in the DB since v3.0.0 and appeared in NO output. Now rendered
in CSV (6 new columns), XLSX (6 new columns), HTML (badge chips incl. KEV),
PDF + DOCX (enrichment line per finding detail), SARIF properties, Markdown
and the Findings UI.

### Severity override (analyst wins, resettable)

`severity_override` + `severity_original` columns; the PATCH accepts
`severity_override` ("" resets). Original severity is frozen on first
override and survives reset. Effective severity (override wins) drives all
renderers, CSV/XLSX columns, Markdown table and the UI badge. Overrides
**survive re-scans**: a regenerated finding joins the dedup group and
inherits the group's override/risk/verified (deliberately NOT analyst
status — FP-memory forgetting semantics stay intact, per the Sprint 1.1
contract).

### Richer triage + bulk operations

`PATCH /findings/:id/triage` accepts optional `analyst_status`,
`severity_override`, `risk_level`, `verified`, `reason` (≤1000 chars,
recorded with acting user + timestamp). New `PATCH /findings/bulk` updates
1..=1000 findings in one statement, propagates to dedup groups and
remembers FP-memory per unique tuple. The Findings page grew checkbox
selection, a bulk toolbar, per-row severity override select and
enrichment badges.

### Manual findings + scan-completion callbacks

`POST /findings` creates analyst findings anchored to a task (template
pre-fill via `from_template`). `POST /tasks` accepts
`report_callback {url, format, secret}`: on task finish the server POSTs a
signed payload (`raw_status` | `raw_json` | `pdf_report` — base64 branded
PDF) with the same HMAC-SHA256 scheme as notification webhooks and behind
the same SSRF guard, which gained `SECUSCAN_WEBHOOK_ALLOW_PRIVATE` for
local-first deployments (default-deny unchanged).

### Cursor pagination

`GET /findings` supports `?cursor=` keyset pagination over the exact sort
tuple (severity rank, created_at, id) — stable under concurrent writes;
`next_cursor` in responses; offset mode unchanged. The UI gained Load-more.

### Test-infrastructure fixes found on the way

- The login rate limiter is process-global keyed by (ip, email) — parallel
  tests sharing one admin email exhausted the 30/min bucket. Tests now use
  unique admin emails per server.
- `login_rate_limit_kicks_in` gained window-reset headroom.
- api_test 33 (+3), reports_render 8 (+1 branding already), frontend 75 +
  tsc clean, verify.mjs 202/202 (+17 Sprint 2.1 checks).

## 4.5.0 -- Max-Parity Sprint 1.4: quick wins (org pivot, branding, expiry, TTL purge, rate limits)

Closes the remaining Sprint 1.3 quick-win package (issue #23). Each item is
independently shippable; all are wired end-to-end with tests.

### Domain Finder: Organization pivot + redirect verification (task 3.1)

The manifest always advertised three techniques; the code implemented only
CT-subdomain search — which can never find sibling *root* domains
(`%.target` only returns names ending in `.target`). Now:

- **Org pivot**: reads the Organization (`O=`) from the target's live TLS
  certificate (`x509-parser`), then searches crt.sh for *other* certificates
  issued to the same organization — facebook.com → fbcdn.net territory.
- **Redirect verification**: bounded probe (max 10 candidates) checks
  whether a candidate's web endpoint redirects to the target — the strongest
  ownership signal.
- Signals stack into the certainty score (CT hits, org match, redirect,
  trigram-overlap name similarity). `check_redirects` input field added.
- 12 unit tests (scoring, similarity metric, registrable domains, cert-org
  extraction via an rcgen fixture); manifest description now matches reality.

### Branding actually applies to reports (task 3.2)

`org_name`, brand colors, footer text and the PNG logo are stored and
editable in Settings since v2.6.0 — and every renderer hardcoded "SecuScan
Report". Now PDF, DOCX, HTML, Markdown and XLSX are branded (title, heading
color, footer, CSS variables, base64 logo in HTML/PDF). The Settings claim
is finally true. New `Branding` loader with safe defaults; `parse_hex_color`
falls back on garbage input.

### API keys can expire (task 3.3)

`POST /auth/api-keys` accepts `expires_in_days` (1..=3650, validated);
expired keys verify as rejected and are stamped `revoked_at` on first sight;
the listing and Settings UI (never/30/90/365 selector + Expires column) show
the state. E2E: fresh key works → backdated expiry → 401 → revoked stamp.

### OOB handler TTL cleanup (task 3.5)

TTL was stored at creation but nothing ever expired handlers. A daily
maintenance pass in the scheduler purges expired handlers + their hits
(`repo::oob::purge_expired`, DB-tested).

### API rate limiting (task 3.7)

Per-identity fixed-window quotas on `/api/v1`: reads (GET/HEAD/OPTIONS)
250/min, writes 125/min — `SECUSCAN_RATE_LIMIT_GET`/`_WRITE` env-tunable,
`0` disables. Responses carry `X-RateLimit-Limit/Remaining/Reset`; the 429
carries `Retry-After` and a structured error body. Buckets key on credential
hash (JWT / API-key — the raw secret never appears anywhere); the public OOB
receiver is exempt so target callbacks are never throttled. Login keeps its
own tighter limiter.

## 4.4.1 -- Max-Parity Sprint 1.3: honest executor (process trees, bounded output, exit truth)

Fixes the executor-reliability trio (issues #9, #10, #11) in `runner.rs` —
the layer every scan's result depends on.

### Process trees are terminated (#9)

- CLI tools now spawn in their own **process group**; cancellation and
  timeout terminate the whole tree (SIGTERM → 2 s grace → SIGKILL) and reap
  it — nmap NSE scripts, sqlmap workers, hydra children can no longer
  survive a cancelled scan. Two survivor-file regression tests prove
  grandchildren die on both cancel and timeout.

### Output capture is bounded (#10)

- The line reader allocated unboundedly for a line without newlines; it now
  reads fixed 8 KiB chunks, truncates single lines at 64 KiB (head + marker),
  caps total output at `max_output_bytes` with a visible
  `[secuscan: output truncated]` marker, and caps log events at 20 000 per
  stream. Invalid UTF-8 (binary output) is lossy-decoded instead of aborting
  the pump and losing the rest of the stream. Four regression tests:
  giant line, endless chatter, binary bytes, dual-stream ordering.

### Exit codes tell the truth (#11)

- A non-zero scanner exit now classifies the task as **Failed** (exit code
  surfaced, output preserved) instead of silently Completed. Plugins declare
  `ok_exit_codes` in their manifest for tools whose contract documents
  non-error exits (testssl.sh 1-4 severity tiers, dalfox 1 on found XSS).
- **Fixed a pre-existing bug found on the way**: signal-killed children were
  mapped to exit code -1 *before* the signal check, so they were reported as
  Completed — they now fail with a distinct signal error. Every terminal
  category (success / non-zero / signal / timeout / cancel) is now
  distinguishable and regression-tested.

## 4.4.0 -- Max-Parity Sprint 1.2: OOB pipeline end-to-end

Second slice of the Max-Parity Phased Implementation Plan
(`docs/MAX_PARITY_PLAN.md`). The OOB (out-of-band callback) infrastructure
existed as scaffolding — a receiver that recorded hits, a per-scan marker on
every task, and two scanner stubs handing out dead `secuscan.local` URLs.
Sprint 1.2 wires the whole blind-vulnerability chain: the receiver now serves
a live browser-capture payload, callbacks that echo the task marker are
auto-correlated and auto-open validated findings, and the website scanner
plants marker-correlated callbacks into blind SSRF/XXE probes.

### The XSS Exploiter is functional (Plan tasks 2.1-2.3)

- `GET /api/v1/oob/:secret` now **serves the capture script** built from the
  handler's config: cookies (`document.cookie`), page HTML, keystrokes
  (buffered keydown listener, flushed every 3 s via `sendBeacon`), and an
  optional html2canvas screenshot (CDN-loaded, degrades gracefully). The
  script beacons back with `?t=<stream>&d=<data>` — hits are now
  self-describing (`stream`/`data` fields) instead of requiring URL parsing.
- **CORS**: the payload and hit responses carry
  `Access-Control-Allow-Origin: *` (scoped to those routes only), so the
  `fetch_eval` delivery mode works cross-origin.
- Serve-vs-record is decided by intent, not guessing: a classic
  `<script src>` (`Sec-Fetch-Dest: script`) or the payload snippet's
  `Accept: application/javascript` fetch serves the script; bare callbacks
  (curl, SSRF probes) record hits. Serving is silent — the `t=ping` beacon
  the script fires on execution is what actually proves it ran.
- **`SECUSCAN_PUBLIC_URL`** (env, `.env.example`, DEPLOYMENT.md) replaces the
  hardcoded `https://secuscan.local`. Tools that need callbacks fail loudly
  when it is unset instead of emitting dead URLs.

### Marker injection + auto-findings (Plan tasks 2.4-2.5)

- `execute_task` gained an `OobCtx` (task id, workspace, per-scan marker,
  public URL) built by the manager and threaded through `NativeCtx`.
- The **website scanner adopts the task's marker** (previously it rolled a
  local one) and, when OOB is armed, provisions a handler and plants the
  marker-correlated callback into **blind SSRF probes** (6 common fetch
  parameters) and an **XXE probe** (DOCTYPE entity). Bounded: 7 requests.
- A hit whose URL/body echoes the task's marker **automatically opens a
  validated finding** (`Out-of-band interaction confirmed` /
  `XSS payload executed`, kind `validated_issue`, confidence `certain`) on the
  originating task — through the same FP-memory + dedup-group pipeline as
  scanner findings. Repeated beacons dedup to one finding.
- **Hit cap enforced**: 500 per handler (429 beyond). Previously unbounded.

## 4.3.0 -- Max-Parity Sprint 1.1: FP memory, authenticated scanning, encryption at rest

First slice of the Max-Parity Phased Implementation Plan
(`docs/MAX_PARITY_PLAN.md`): "fix the broken plumbing first". The false-positive
memory, dedup-group propagation, authenticated scanning and Sniper XSS chain
that existed as scaffolding are now wired end-to-end, credential columns are
encrypted at rest, and the Phase 0 groundwork (AI env vars, acceptance
criteria, baseline benchmark) is in place for the phases that follow.

### False-positive memory is now a closed loop (Plan tasks 1.1-1.3)

- Marking a finding `false_positive` now persists to `fp_memory` with the
  **acting user and an optional reason**; re-scans of the same target
  auto-suppress the identical finding (insert-time suppression was already
  in place — the triage side simply never recorded anything, so the memory
  could never be written through the UI).
- Any non-FP triage status **forgets** the memory, so the next scan reports
  the finding fresh again.
- Triage responses and `GET /findings/:id` carry an `fp_memory` audit block
  (deciding user's email, timestamp, reason) which the Findings page renders
  in the expanded row.
- The Findings UI asks for an optional justification when a finding is
  marked false-positive (inline input + **Mark FP** button; Enter applies,
  Escape cancels).
- **Bug found and fixed along the way**: dedup groups were silently dead —
  the post-insert attach used `UPDATE … ORDER BY … LIMIT 1`, which SQLite
  does not support, and the swallowed error meant `group_id` was never set.
  Rows are now attached via the ids `insert_many` returns, so status changes
  **propagate to duplicate findings across scans** (task 1.2 actually
  works now, with an E2E test proving run-1 → run-2 propagation).

### Authenticated scanning (Plan task 1.4)

- Tasks that carry an `auth_profile_id` now resolve their profile into
  concrete request material **before** execution: `cookie` profiles inject a
  Cookie header, `header` profiles inject arbitrary headers (Bearer tokens,
  API keys), and `form` profiles perform the login POST and harvest the
  session cookies automatically.
- The website scanner applies the material as **client-level default
  headers**, so every request — crawl, discovery paths, canaries, CORS
  preflight, redirects, host-header probes, SSTI, form reflection and the
  DAST engine's active probes — runs with the session. http-recon applies
  it per request.
- A task whose profile cannot be resolved **fails loudly** ("auth profile
  resolution failed") instead of silently scanning unauthenticated.
- Admission now **validates ownership**: attaching an auth profile you do
  not own (and are not admin for) is a 404, closing an access-control gap
  where any logged-in scanner could attach another user's credentials by id.
- `recorded` (multi-step) profiles return a clear "not yet supported by the
  executor" error rather than being silently ignored.

### Encryption at rest (Plan task 1.5)

- New `secuscan_core::crypto`: AES-256-GCM with a versioned `enc:v1:`
  ciphertext format. Key from `SECUSCAN_ENC_KEY` (64-hex used verbatim, any
  other string stretched via SHA-256) or an auto-generated 0600 key file at
  `data/.secuscan-enc-key` — encryption is on by default, and the SQLite
  file alone is no longer enough to recover secrets.
- `auth_profiles.config_json` and `vpn_profiles.config_text` are sealed on
  write and opened on read at the repository layer; legacy plaintext rows
  decrypt transparently (no migration), and rows re-seal on their next write.
- The E2E suite now initializes crypto and proves the raw SQLite row holds
  ciphertext while the API transparently returns the plaintext config to
  the owner.

### Sniper XSS chain unblocked (Plan task 1.6)

- The XSS chain step defines its own `target` — the **handler name** — via
  an `@run:` sentinel that expands to a per-run unique, pattern-valid label
  (`sniper-xss-<run prefix>`). Previously the finding's URL overwrote the
  handler field, failed the `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` pattern at
  admission, and made the XSS chain **impossible to run**.
- Step-defined inputs now always win: the finding target (URL, else task
  target) is injected only when the step doesn't provide one, and a step
  that cannot resolve a target is marked failed without aborting the chain.

### Phase 0 groundwork

- `docs/MAX_PARITY_PLAN.md` — the full 30-week phased implementation plan
  (phases 0-5, sprints, dependency graph, staffing, risks, success metrics).
- `docs/MAX_PARITY_CRITERIA.md` — per-domain acceptance criteria that the
  final parity audit runs against, with verification keys.
- `scripts/benchmark.mjs` — baseline metrics harness (FP suppression rate,
  scan latency p50/p95, OOB callback hit rate, per-format report
  generation time); writes `data/baseline-metrics.json`. First capture:
  latency p50 ≈ 260ms, FP suppression 1/1, OOB 3/3, reports 1-2ms/format.
- `.env.example` + `config.rs`: `SECUSCAN_AI_BASE_URL` / `SECUSCAN_AI_API_KEY`
  (parsed now, consumed by the Phase 3 AI layer) and `SECUSCAN_ENC_KEY`.
- CI workflow branch filter repaired (`branches: [main]`).

### Smaller fixes

- `auth_profiles::get` / `vpn::get` now return 404 (not 500) for unknown ids.
- `http_headers::client_builder` extracted so auth-aware clients share the
  same redirect policy/timeout profile.

### Tests

- Rust: 284 passed (was 259) — +7 sniper input-resolution, +9 crypto
  round-trip/tamper, +8 auth-material parsing, +2 E2E (FP-memory lifecycle
  incl. re-scan suppression + group propagation; encryption-at-rest with
  raw-row ciphertext assertion).
- Frontend: 75 passed (was 73) — FP reason input sends `reason` in the
  PATCH body; expanded FP row renders the audit trail.
- `scripts/verify.mjs`: 150 checks passed (was 129) — Sprint 1.1 section
  (triage audit echo, re-scan auto-suppression, forget-on-unmark, auth
  profile round-trip, loud failure on unknown profile) + Phase 0 artifact
  checks.

## 4.2.2 -- Profiles in the UI browser, in the attack suites, and with runtime hints

Follow-up polish to the scan-profile program (85 profiles across 32
scanners as of v4.2.1): the profiles are now surfaced where users
actually make decisions — a category-grouped browser on the New Task
page, depth-matched presets inside every Attack-Target suite, and an
estimated-runtime hint on every profile card.

### New Task page: category-grouped scanner browser

Step 1 grew from a bare `<select>` into a full **Browse by category**
panel: scanners are bucketed into Network / Web / Recon / Exploitation /
Cloud sections (known categories first, then anything else
alphabetically), and every scanner row surfaces its scan profiles as
one-click chips — colored by badge, tooltip'd with the profile
description + runtime estimate. Clicking a chip jumps straight into the
configured task: scanner selected *and* profile applied (a
pending-preset ride-along survives the plugin-switch re-seed). The
`<select>` itself now groups options by category via `<optgroup>`.
Scanners without profiles show a neutral `manual` chip.

### Profile cards: estimated runtime from the badge

Every scan-profile card (and browser-chip tooltip) now carries a
badge-derived runtime ballpark:

| Badge | Estimate |
|-------|----------|
| fast | est. seconds – a few minutes |
| thorough | est. a few minutes |
| intense | est. 10+ minutes |
| stealth | est. slow by design (low & slow) |

Honest ballparks, not SLAs — a `fast` profile against a slow host can
still take minutes.

### Attack-Target suites run depth-matched profiles

`POST /targets/:id/attack` now picks a scan profile per plugin
following a per-suite depth preference list:

- **web / quick** run each plugin's Quick/Light profile (nuclei→light,
  http-headers→quick, whatweb→passive, xss-scanner→verified, …)
- **full** runs each plugin's Deep/Full profile (nmap→deep — never the
  65,535-port full-sweep; whatweb→aggressive — never `heavy`;
  xss-scanner→all-reflections; http-headers→full; subfinder→exhaustive; …)
- **internal** runs deep-then-standard.

The preset flows through the standard admission pipeline (caller
inputs still win over preset values), is recorded on the task
(`options.preset`), and is echoed per task in the attack response so
the UI can show "this ran the Deep profile" without a follow-up GET.
The v4.2.0 nmap top-1000 input hint now only fires as a fallback when
no preset was picked.

### Tests

- 259 Rust tests pass (was 253; +6: suite preset-selection preferences,
  hazardous-extreme avoidance, nmap hint gating, no-preset fallbacks).
- 73 frontend tests pass (was 69; +4: category-grouped browser renders
  with chips, ETA hints render per badge, chip-jump applies the preset
  end-to-end, chip-on-selected-scanner applies directly).
- verify.mjs ships 8 new attack-suite assertions (quick nmap light,
  full website-scanner/api-scanner/param-finder deep, http-headers
  full, no-preset plugins stay null, web-suite nuclei light when
  engines installed). 131/131 pass.

## 4.2.1 -- Scan profiles for the remaining scanners

Direct follow-up to v4.2.0's scan-profile rollout. v4.2.0 covered the 13
"headliner" scanners (nmap, nuclei, port-scanner, fast-port-scan,
website-scanner, wordpress-audit, xss-scanner, sqlmap, command-injection,
nikto, testssl, crawler, feroxbuster); this release extends the same
Light/Deep/Custom customization surface to the **remaining 19 active
scanners** the user called out by name (`smb-enum`, `ssh-audit`,
`api-scanner`, `subdomain-finder`) plus every other scanner in the catalog
that has a meaningful depth dimension.

### Scan profiles for 19 more scanners (44 new profiles)

| Plugin | Profiles |
|--------|----------|
| `smb-enum` | Quick · Standard · Deep |
| `ssh-audit` | Quick · Standard · Deep |
| `api-scanner` | Quick · Standard · Deep |
| `subdomain-finder` | Passive · Standard · Deep |
| `ffuf` | Quick · Deep |
| `gobuster` | Quick · Deep |
| `http-probe` (httpx) | Light · Deep |
| `whatweb` | Passive · Polite · Aggressive · Heavy |
| `waf-detect` (wafw00f) | Quick · Deep |
| `http-smuggling` (smuggler) | Quick · Full |
| `secrets-scanner` (gitleaks) | Quick · Full |
| `subdomain-takeover` (subzy) | Quick · Full |
| `subfinder` | Light · Standard · Exhaustive |
| `service-defaults` | Quick · Standard · Deep |
| `http-headers` | Quick · Full |
| `vhost-finder` | Light · Deep |
| `domain-finder` | Light · Deep |
| `param-finder` | Light · Deep |
| `js-analyzer` | Light · Deep |

Combined with v4.2.0's 39 profiles, the catalog now ships **83 named scan
profiles across 32 scanners** — every active scanner in the catalog that
has a real depth axis offers one-click Light/Deep/Custom customization
matching the pentest-tools.com model.

### Native engine extensions

- **api-scanner** gains three profile knobs (`max_operations`,
  `probe_verb_tamper`, `probe_graphql`) honored by the native Rust
  engine: Quick skips the GraphQL probe and the DELETE verb-tamper pass,
  Standard adds GraphQL but skips verb tamper, Deep enables every
  active check and caps operations at 80.
- **subdomain-finder** gains `enable_bruteforce` honored by the native
  engine: the Passive profile queries crt.sh only with zero DNS traffic
  to the target's nameserver (safe for pre-engagement recon), Standard
  adds the embedded ~300-name DNS brute list, Deep extends to 2000
  labels.

### What's NOT profiled (and why)

A handful of scanners intentionally have no profiles because their
depth axis is degenerate or would require invasive native rewrites for
marginal value:

- `ping`, `traceroute`, `whois`, `reverse-dns` — single-purpose passive
  tools with no meaningful depth dimension.
- `dns-lookup` — single-record-type lookup (the user picks ONE record
  type per task). Profiles would be redundant with the existing
  `record_type` select.
- `tls-check` — single rustls handshake; a deep/quick split would
  require rewriting the native module to enumerate protocols and
  ciphers individually.
- `http-recon`, `drupal-scanner`, `cloud-scanner`, `google-dorks`,
  `people-hunter`, `cors-check`, `email-security`, `password-audit` —
  either a single fixed check pass or only one tunable knob whose
  "profile" would be a one-field triviality. Their existing fields
  remain fully user-tunable.

### Tests

- 253 Rust tests pass (was 241 in v4.2.0; the existing preset loader
  tests cover the new plugins without modification).
- 68 frontend tests pass (unchanged from v4.2.0; the NewTask profile
  card grid renders preset_meta from any plugin that exposes it, so
  the new scanners appear automatically).
- verify.mjs ships 7 new profile assertions covering the four
  user-named plugins' preset_meta, the api-scanner deep-preset
  merged-inputs contract, and a catalog-wide total-profiles ≥80
  guard.

## 4.2.0 -- Full scan customization: Light / Deep / Custom scan profiles

Direct response to "the input taking is too generic — pentest-tools.com is
fully customizable, light to deep." Their model, researched from their
published docs: every scanner offers **Light / Deep / Custom** scan types
(Light = fast presets + passive-leaning checks; Deep = full coverage + all
active checks; Custom = every knob exposed), port presets from Top 10 to
the full 65,535 range, and per-scan technique selection. SecuScan had the
`presets` mechanism in the manifest schema since v2 but **zero plugins
defined any** — every scan started from raw, generic form fields. This
release ships the whole surface.

Also ships the CI hardening batch (catalog + parser-fixture integration
tests, E2E and Docker smoke jobs in GitHub Actions) that landed
concurrently with this feature work.

### Scan profiles everywhere (35+ profiles across 13 scanners)

| Plugin | Profiles |
|--------|----------|
| `nmap` | Light · Deep · Full sweep · Top 5000 · Stealth · Vuln scripts |
| `nuclei` | KEV only · Light · CVE checks · Exposures · Misconfig · Panels & logins · Deep |
| `port-scanner` | Fast · Light · Deep |
| `fast-port-scan` (naabu) | Light · Deep · Full |
| `website-scanner` | Light · Deep |
| `wordpress-audit` | Light · Deep |
| `xss-scanner` (dalfox) | Verified only · All reflections |
| `sqlmap` | Conservative · Balanced · Aggressive · Exhaustive |
| `command-injection` (commix) | Conservative · Aggressive |
| `nikto` | Quick · Standard |
| `testssl` | Quick · Full |
| `crawler` (katana) | Shallow · Deep |
| `feroxbuster` | Light · Deep |

The `nuclei` profiles map the pentest-tools.com Network Scanner's KEV-only
and CVE-focused custom modes onto the template engine; `nmap`'s
Light/Deep mirror their ~187/~3,845-port equivalents.

### nmap: every Port Scanner knob pentest-tools.com exposes

- **Twelve scan techniques** (was 3): SYN, Connect, UDP, ACK, Window,
  Maimon, NULL, FIN, Xmas, SCTP INIT, SCTP COOKIE-ECHO, IP protocol.
- **Timing templates** T0 paranoid .. T5 insane (replaces the old
  safe_mode boolean).
- **Top-N port preset** as a field (10 / 100 / 1000 / 5000) with explicit
  list / range / full `1-65535` sweep in the ports field.
- **Version probe intensity** 0-9, **NSE script categories** (vuln /
  default,safe / auth,brute / exploit), **traceroute**, and
  **no-ping (-Pn)** toggles.

### New field-level options on other engines

- `nikto`: check-category tuning (-T) with the id legend in the help text.
- `testssl`: fast mode (--fast).
- `fast-port-scan` (naabu): top-N preset field replacing the hardcoded
  top-1000 default.
- `port-scanner` (native): Top 10 preset option added to the select.

### `[preset_meta.NAME]` — presentation metadata for profiles

New optional manifest table: `label` (human name), `description` (what
the profile does), `badge` (`fast` / `thorough` / `intense` /
`stealth`). Validated (every meta key must match a declared preset),
serialized through `GET /plugins`, `/plugins/:id` and `/plugins/:id/schema`,
and rendered by the UI.

### Frontend: Scan profile cards (New Task page)

The flat lowercase preset chips are replaced with a **Scan profile**
grid: one card per profile showing its icon + badge chip, label,
description, and the exact values it seeds (`key=value` monospace line),
plus a dashed **Custom** card that restores defaults for full manual
configuration. Badges are color-coded (sky = fast, violet = thorough,
rose = intense, slate = stealth).

### Fixes

- **Attack-target full suite silently skipped nmap**: `inputs_for`
  passed `ports: "top-1000"`, which never matched the ports field
  pattern (letters are not valid port syntax) — the nmap task was
  rejected at admission and skipped with a reason on every `full` /
  `internal` suite run. Now the suite supplies `top_ports: 1000` +
  `service_detection: true` (the deep-profile equivalent).

### Tests

- 241/241 Rust (was 238; +3 loader tests: presets + preset_meta parse,
  preset_meta-without-preset rejected, preset-referencing-unknown-field
  rejected).
- 68/68 frontend (was 65; +3: profile cards render labels/badges/Custom,
  applying a profile seeds the form and sends the preset, switching to
  Custom clears the preset).
- verify.mjs: 97/97 (was 75; +13 per-plugin profile expectations, +2
  preset_meta API assertions, +5 live preset-task assertions: 201 +
  completion + preset recorded on the task + merged inputs
  (concurrency=256, timeout_ms=400) + caller-supplied ports winning over
  the preset merge).

## 4.1.0 -- Stronger attack vectors: 7 power engines pentest-tools.com lacks

Direct response to "the plugins are too weak, make them stronger than
pentest-tools.com." v4.0.0 wrapped the two biggest engines (nuclei + dalfox)
and wired them into Sniper + the attack-target suites; v4.1.0 closes the
remaining capability gaps by wrapping seven more best-in-class engines,
each filling a class pentest-tools.com does not cover at all.

### New engines (7 plugins, 50-plugin catalog)

| Plugin | Engine | Class | Why pentest-tools.com lacks it |
|--------|--------|-------|--------------------------------|
| `subdomain-takeover` | subzy (L4ays) | Subdomain takeover | No SaaS-edge CNAME fingerprinting |
| `http-probe` | httpx (projectdiscovery) | HTTP probe + tech fingerprint | No Wappalyzer-class tech detect |
| `crawler` | katana (projectdiscovery) | Next-gen crawler (standard + headless) | No SPA-aware crawler |
| `fast-port-scan` | naabu (projectdiscovery) | Fast port scanner (top-N in seconds) | nmap-only, no fast-path |
| `http-smuggling` | smuggler (defparam) | CL.TE / TE.CL / TE.TE detection | No request-smuggling scanner |
| `command-injection` | commix (commixproject) | OS command injection auto-exploit | No command-injection scanner |
| `secrets-scanner` | gitleaks (gitleaks) | Secret detection (AWS/GCP/Azure/JWT/...) | No secret-pattern scanner |

Each plugin normalises the underlying engine's output through the
existing declarative parser engine:

- `subdomain-takeover` parses logrus-formatted lines into per-finding
  Subdomain Takeover entries with the affected URL + service edge.
- `http-probe`, `crawler`, `fast-port-scan` consume JSONL streams;
  per-line severity is derived from the response status / port via
  `severity_map`, and tech-stack / endpoint / port metadata flows into
  the finding's `metadata` for the attack-surface aggregator.
- `http-smuggling` parses `[+]` positive-hit lines into Request
  Smuggling findings with the verified class (CL.TE / TE.CL / TE.TE)
  and endpoint.
- `command-injection` uses `passthrough` + three static_rules covering
  commix's "is vulnerable", "injection point detected", and "is not
  vulnerable" markers.
- `secrets-scanner` parses gitleaks v8's `path:line:rule:secret` lines
  into Secret Exposure findings; `severity_rules` elevate AWS / GCP /
  Azure / GitHub / GitLab / private-key / JWT hits to `critical`.

### Sniper Auto-Exploiter -- 4 new chains

Each new finding category gets a re-verification + DAST refresh chain,
matching the v4.0.0 nuclei pattern:

- **Subdomain Takeover** -> `subdomain-takeover` re-verification + http-recon edge fingerprint.
- **Request Smuggling** -> `http-smuggling` verbose re-verification + website-scanner DAST refresh.
- **Command Injection** -> `command-injection` level-2 re-verification + website-scanner DAST refresh.
- **Secret Exposure** -> `secrets-scanner` re-verification + js-analyzer JS secret-pattern sweep.

### Attack-Target suites -- power-engine slots added

- `web` suite (hostname/URL): gains `http-probe` + `crawler` (tech
  fingerprint + endpoint discovery before DAST).
- `full` suite (hostname/URL): gains `subdomain-takeover` +
  `http-smuggling` + `http-probe` + `crawler`.
- `full` suite (IP): gains `fast-port-scan` alongside nmap.
- `command-injection` and `secrets-scanner` are kept as standalone
  plugins (not in the suite) because they require URL-with-parameter /
  filesystem-path inputs the generic suite cannot supply.

### install-tools.sh -- 7 new tool installs

A reusable `install_go_binary OWNER REPO BIN ASSET_SUBSTR` helper
installs subzy, httpx, katana, naabu, smuggler, gitleaks via GitHub
release assets (commix is a python repo clone + wrapper, matching the
sqlmap pattern). The report-card section now lists 20 tools (was 13).

### verify.mjs -- bugfix + 14 new assertions

- Bugfix: the `haveNuclei` / `haveDalfox` checks were wrapped in
  `await (async () => { try { await ... ; return true } catch { return false } })()`
  -- but `execFileChecked` never throws (it resolves to a boolean), so
  the wrapper always returned `true`. Engine tests ran even when the
  engines were absent, producing misleading FAIL lines. Fixed to use
  `execFileChecked`'s resolved value directly.
- New: 7 catalog-presence assertions (one per new plugin), 7 suite-
  wiring assertions (gated on engine presence so they pass when
  installed, skip when not).

### Tests

- 238/238 Rust (was 232 in v4.0.0; +6 net: 4 new Sniper chain tests
  for the new finding categories, 3 new suite-membership tests, 1
  deleted suite test that asserted the old IP-full-suite contents).
- 65/65 frontend (unchanged).
- verify.mjs: 75/75 green when engines are not installed (was 81/15
  with the misleading-FAIL bug); ~105/105 expected when engines are
  installed (75 baseline + 7 catalog + up to 23 engine / suite
  assertions).

Catalog: **50 plugins** (was 43).

## 4.0.0 -- Power engines: nuclei template library + dalfox XSS, deeply wired

The check-library force multiplier. Hand-written checks top out at dozens
of detections; the nuclei community template library ships **14,109
templates** (3,587 CVE checks, 1,496 actively-exploited KEV entries,
exposures, misconfigurations, panels, default logins) and updates daily.
This release wraps the two strongest open-source engines and wires them
into every layer of the platform instead of leaving them as standalone
plugin manifests.

### Parser engine: deep JSONL extraction (generic)

`JsonFindingTemplate` (the `[parser.finding]` table for `json_lines`
plugins) gained five capabilities, all exercised by nuclei + dalfox:

- `category_field` + `category_map` -- per-finding categories derived
  from a tag list (string or JSON array; nuclei emits arrays). Tags map
  to platform categories (sqli -> SQL Injection, xss -> XSS, wordpress
  -> WordPress, credential -> Credential, ...) so Sniper chains pick
  the right follow-up automatically; unmapped tags fall back to the
  static `category`.
- `cve_field` / `cvss_field` / `cvss_vector_field` -- CVE ids (string
  or array, first valid CVE- entry wins), CVSS scores (clamped to
  0..=10) and vectors flow into the platform's EPSS/KEV enrichment.
- `proof_fields` -- joined reproduction proof (nuclei: the exact
  `curl-command` + template id).
- `metadata_fields` -- arbitrary dot-paths copied into finding
  metadata (tags, references, host, type, template-path).

### nuclei (Vulnerability Templates) -- deep rewrite

- argv gains `-duc` (deterministic scans: the platform owns template
  updates, never the scan-time binary -- nuclei's update check stalls
  in restricted networks) and `-ni` (out-of-band detection runs through
  SecuScan's OWN OOB callback system, not nuclei's external
  Interactsh service).
- New `tags` field (e.g. `kev` for actively-exploited-only runs)
  alongside `templates` and `severity`.
- Findings now carry: curl reproduction commands as proof, CVE + CVSS
  score + vector, template tags + references in metadata, and
  tag-derived categories.

### dalfox (XSS Scanner) -- JSONL rewrite

- dalfox v3's structured JSONL replaces regex scraping: findings carry
  the payload, evidence, injection location, CWE, confidence and the
  verified-parameter name. `kind = validated_issue` -- dalfox's "V"
  type asserts exploitability, so findings are validated, not
  suspected.
- `--no-spinner` (removed in dalfox v3.2.4) dropped; `-f jsonl` added;
  new `param` and `only_vulnerable` fields.
- Category "XSS" routes findings into the existing Sniper XSS chain
  (OOB callback handler).

### Sniper: Vulnerability chain

New chain for nuclei template hits (unmapped tags -> "Vulnerability"):
nuclei re-verification focused on high/critical severities, then
website-scanner DAST refresh, then http-headers audit. Tag-mapped
findings (SQL Injection / XSS / WordPress / Credential / TLS) continue
to route to their existing specialized chains.

### Attack-Target suites

- `web` suite (hostname/URL) now launches nuclei.
- `full` suite (hostname/URL) now launches nuclei + xss-scanner.

### Fixes + hardening

- install-tools.sh: nuclei templates now clone to `~/nuclei-templates`
  (the path nuclei actually searches by default; the previous
  `~/.config/nuclei/templates` location was never picked up).
- verify.mjs: `--if:`-style PATH propagation for tool installs, a
  deliberately-vulnerable local test app (`scripts/vuln-app.mjs`) so
  the engines prove real findings end-to-end, deterministic process
  exit, and the Power engines section runs before the suites (the
  `max_concurrent = 1` slot would otherwise be held by a suite task
  scanning the internet).
- Task findings fetch corrected to `GET /tasks/:id/result` in the E2E
  harness.

### Tests

- 232/232 Rust (was 231; +1 real-manifest parse guard
  `nuclei_manifest_parses_real_template_output` including array-tag
  category mapping; suite inclusion tests updated for nuclei +
  xss-scanner).
- 65/65 frontend.
- verify.mjs: 91/91 assertions green, including live nuclei (4
  exposures on the vuln app: .env x2, MySQL dump, git config -- with
  curl proofs, tag metadata, category mapping) and live dalfox
  (verified reflected XSS with CWE-79, param + payload metadata).

## 3.3.0 -- Stronger native DAST than a SaaS shortlist

GitHub-informed upgrade. Check *classes* from cyweb, scant3r, x8, crlfuzz,
and feroxbuster — implemented as original Rust, not a source copy.

- `website-scanner` now also runs TRACE/XST, CRLF header injection, LFI
  canaries, X-Forwarded-Host reflection, NoSQL operator errors, JWT cookie
  inventory (`alg=none` high), CSRF token absence, HTTP password forms,
  source maps, stack traces, Referrer-Policy / Permissions-Policy.
- New native `param-finder` (x8-class hidden parameters).
- New native `js-analyzer` (redacted AWS/GitHub/Google/Slack/JWT/key
  patterns, source maps, `/api` paths).
- Optional CLI wrap of `feroxbuster` (best-in-class Rust dirbuster).
- Sniper chains for CRLF, LFI, JWT. Attack-Target `web`/`full` launch
  param-finder + js-analyzer.

Catalog: **43 plugins**.

## 3.2.1 -- Deeper DAST, API, service defaults, Sniper chains

Second professional-depth slice. Detection and proof only — no loot extractors.

- `website-scanner`: cookie flags, permissive CORS, open redirect, Host
  reflection, SSTI canary, GET-form reflection, JS path harvest, larger
  discovery list. XSS/SQL/CORS findings use those categories so Sniper
  can follow up.
- `api-scanner`: auto-discover OpenAPI at well-known paths, unauthenticated
  GET count, JSON secret-key observation, DELETE-on-GET verb check.
- `password-audit`: `http-form` protocol (conservative success: redirect or
  logout/dashboard without failure phrases).
- `service-defaults`: nmap NSE pass for anonymous/empty-password on 17
  common service ports (internal ranges only).
- Attack-Target `web`/`full` include website-scanner (and api-scanner on
  full); `internal`/`full` IP include service-defaults.
- Sniper chains for Web, API, Auth, CORS.
- HTTP recon: security.txt, JS paths, sensitive HTML comments.

Catalog: **40 plugins**.

## 3.2.0 -- Professional-depth start: trust, cockpit, DAST, API, internal plugins

First slice of the professional-engagement plan (P0–P5 start). Not a SaaS
clone — a local box a pentester can actually work from.

### Trust (P0)

- Sniper requires `consent_granted` and `load_finding_for_user` (no IDOR).
- Sniper / VPN / OOB / auth-profile list+get scoped to owner or admin.
- OOB: secrets omitted from list JSON; callback URL is `/api/v1/oob/:secret`;
  expired handlers 404; body cap 256 KiB.
- OpenVPN upload rejects `up`/`plugin`/`script-security` and related
  host-command directives. `POST /vpn-profiles/:id/test` dry-runs the config.
- Notification webhooks refuse loopback, RFC1918, link-local, and metadata IPs.

### Cockpit (P1)

- New pages: `/surface` (Attack Surface), `/handlers` (OOB).
- Settings: auth profiles, wordlists, notification rules, report branding.
- Notification create/update rejects loopback and RFC1918 webhook URLs;
  list/get/log scoped to owner or admin.
- Wordlist get/delete/contents scoped to owner (builtins remain shared).
- VPN Test button. Sniper UI sends consent with the click.

### Scanners (P3–P5)

- `website-scanner` — native DAST: bounded spider, sensitive paths, headers,
  reflected-marker XSS candidate, SQL-error detection, req/resp proof + CWE/OWASP.
- `api-scanner` — OpenAPI/Postman from disk or URL, GET probes, GraphQL
  introspection finding.
- `smb-enum` and `ssh-audit` nmap NSE wrappers so Attack-Target
  `full`/`internal` suites actually launch.
- Attack-Target `web`/`full` now use `testssl` (the plugin that exists).

### MCP

- `run_sniper`, `get_sniper_run`, `list_vpn_profiles`, `test_vpn_profile`,
  `start_people_hunter`.

Catalog: **39 plugins**.

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
