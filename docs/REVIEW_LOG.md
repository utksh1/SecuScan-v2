# Review log — how this release was hardened

The user-facing requirement for this rewrite: *verify every line, find bugs, fix them,
repeat — more than five times, looking for professionalism improvements each round.*
This file documents those cycles honestly, including the bugs that escaped earlier
reviews.

## Cycle 1 — mechanical (clippy / rustfmt / warnings)

**Found & fixed**
- `runner.rs`, `manager.rs`: `never_loop` — `loop { select! { … break } }` wrappers where
  every branch terminated the loop. Replaced with plain `select!` expressions.
- 8× needless borrows, doc-list indentation, `print_literal`, redundant local rebinding,
  identity mask operation in CIDR expansion.
- `too_many_arguments` on `tasks::finish` → `FinishTask`/`FinishOutcome` structs.

**Result:** `cargo clippy --workspace --all-targets` = 0 warnings.

## Cycle 2 — security audit (self, line-by-line threat model)

**Found & fixed**
- Login user-enumeration via timing → dummy-hash verification for unknown emails.
- Redirect-based SSRF pivot in native HTTP scanners → same-host-only redirect policy.
- CSV export formula injection (`=`, `+`, `-`, `@` prefixes) → quoted guard.
- Unbounded `task_events` growth from chatty tools → 10k/task persistence cap with
  synthetic-id live broadcast.
- No way to set cookie `Secure` → `SECUSCAN_COOKIE_SECURE`.

## Cycle 3 — independent backend review (fresh eyes, subagent)

15 confirmed findings; the significant ones:

| # | Finding | Fix |
|---|---|---|
| 1 | Rejected plugin-limit acquire called `release_hourly`, eroding a *different* task's reservation — hourly caps could be exceeded indefinitely | never release on rejection |
| 2 | Target policy matched literal text: `192.168.attacker.com` glob-matched `192.168.*.*`; `::ffff:169.254.169.254` and integer-IP forms bypassed everything | host canonicalization (v4-mapped unwrap, integer/hex forms) + IP-shaped globs only match literal IPs; DNS trust boundary documented |
| 3 | Login limiter keyed on spoofable `X-Forwarded-For`; map grew unboundedly | prune-on-check + hard 10k safety valve |
| 4 | Restart left queued/running tasks as permanent zombies | startup sweep marks orphans failed |
| 5 | Deleting a queued task left the scan running against the target | delete cancels first |
| 6 | Native scanners ignored cancellation (cancel returned success, task completed anyway) | `select!` on the cancel token in every native |
| 7 | Password change left 7-day refresh tokens alive | revoke all sessions |
| 8 | nikto OSVDB severity rule exact-matched only single digits — elevation never fired | glob values (`OSVDB-*`) in severity rules |
| 9 | Last admin could demote themselves → lockout | demotion guard |
| 10 | Blocking DNS inside probe futures stalled the runtime | up-front async resolution per host |
| 11 | Unbounded `resp.text()` in recon | content-length check + 2 MiB cap |
| 12 | Signal-killed children reported as `completed` | signal death → `failed` with explicit error |
| 13 | SSE "finished" detection by string match (false positives on echoed argv) | parse the JSON `type` tag |
| 14 | Non-admin dashboards exposed global counters | scope to the requesting user |
| 15 | Recorder counter map never shrank | drop the entry on the task's finished event |

## Cycle 4 — independent frontend review (fresh eyes, subagent)

12 confirmed findings:

| # | Finding | Fix |
|---|---|---|
| 1 | Dashboard linked to `?severity=critical&severity=high` — backend rejected repeated keys (400) on the app's own primary CTA | backend accepts repeated `severity` (OR-combined, parameterized IN) |
| 2 | Settings read `GET /admin/settings` which didn't exist — the consent checkbox always showed `true` | endpoint added; frontend renders real state |
| 3 | Task findings never refreshed when a running task's stream finished | invalidate `task-findings` on stream completion |
| 4 | SSE reader never reconnected (contradicting its own docstring) | cursor-based reconnect with backoff |
| 5 | Tasks page fired two HTTP requests per poll (dead first call) | removed |
| 6 | Mutations failed silently; retry/delete not role-gated; `/auth/*` blanket-excluded from token refresh | error surfacing, role gates, narrowed exclusion |
| 7 | Wizard sent `""` for cleared selects → guaranteed 400 | omit empty optional values |
| 8 | Logout failure broke the UI; query cache survived logout | `finally` + `queryClient.clear()` |
| 9 | AuthContext raced its own refresh under StrictMode (double-mount) | single-flight `tryRefresh` |
| 10 | No way to cancel a running workflow | cancel button wired to the existing endpoint |
| 11 | Expired sessions left every page stuck on raw 401 errors | global unauthorized event → redirect to login |
| 12 | The riskiest frontend code was untested | +9 contract tests (SSE parsing, multi-severity URL, badges) |

## Cycle 5 — regression coverage + robustness

- 6 new backend integration tests locking in every audit fix above (rate limiting 429,
  multi-severity + settings, policy bypass forms, session revocation, last-admin guard,
  admission under repeated scans).
- Discovered while writing them: `serde_urlencoded` rejects duplicate query keys before
  any custom deserializer runs → raw query-string parsing in the findings route.
- Plugin target patterns rejected IPv6 literals and dashed hostnames → fixed across the
  network plugins.
- Login rate limit 10→30/min per IP+email (parallel-friendly; Argon2 remains the real
  cost control).

## Cycle 6 — end-to-end verification + packaging

- Full E2E over real HTTP: server + built SPA + login + consent-gated scan against a
  live listener + findings + SSE replay + all five report formats + dashboard counters.
- `cargo test --workspace` = 88 backend · `npm test` = 41 frontend · clippy clean ·
  plugin catalogue validates 13/13.
- Docs, CI, Docker, Makefile finalized; this log written.

## Honest residuals

- Hostname-based policy matching trusts DNS at task-creation time (records can change).
  Strict deployments should use IP/CIDR patterns — documented in SECURITY.md.
- `X-Forwarded-For` is trusted for rate-limit keys; run behind a trusted proxy or accept
  shared-key behaviour.
- Workflow inputs are JSON textareas in the UI (power-user oriented).
- v1 features intentionally deferred: vault, notifications, schedulers, saved views.


## Review cycle 7 — workspaces & targets feature audit

Scope: every file added or modified for the workspace/target feature (migration 0002,
`repo/workspaces.rs`, `repo/tasks.rs`, `repo/findings.rs`, `repo/misc.rs`,
`routes/{workspaces,tasks,findings,dashboard,workflows}.rs`, the full frontend diff)
plus a re-read of every query the feature touches.

Found and fixed:

1. **Pre-existing (cycle 5 miss): findings multi-severity placeholder collision** —
   `severity_clause(8)` generated `?8..` while the 8th bound argument was `OFFSET`;
   single-severity filters compared severity against the offset (returned nothing),
   multi-severity silently kept only the first value, and `count`/`list` disagreed.
   The existing test only asserted HTTP 200 on an empty table. Fixed with a running
   placeholder counter (`Ph`) shared by every optional clause; regression test matrix
   over a deterministic `sevtest` fixture plugin (1/2/3-severity combinations,
   items == total).
2. **Self-introduced (caught by the new integration test before merge): dashboard
   bind-index mismatch** — with no user scope active, the workspace fragment still
   referenced `?2` while the bind landed on `?1` (empty dashboards). Restructured to
   pick the fragment by user-scope presence.
3. **N+1 queries** — workspace list ran 3 COUNT queries per workspace (UI polls it
   every 15 s) and the target list ran 2 per target; replaced with fixed-count
   GROUP BY stitching (`all_workspace_counts`, `target_stats_many`).
4. **Check-then-insert race on target uniqueness** — two concurrent creates could
   both pass the pre-check and surface a raw 500 on the UNIQUE constraint; now the
   constraint violation itself is mapped to 409 via `is_unique_violation()`
   (create and rename paths).
5. Minor: `list_workspaces` ordering simplified to `name COLLATE NOCASE`; unused
   import; stale comments removed.

Verified (no action needed): all new SQL is parameterized; RBAC on every new route
(viewer read-only, scanner mutate, admin delete); task retry and workflow runs carry
the workspace; ON DELETE SET NULL fallback asserted by test + E2E; placeholder
numbering in tasks list/count/recent now derived from a shared counter; frontend
`scopeParam` never produces an unvalidated id (backend 404s unknown ids); the
WorkspaceProvider falls back to Personal when the stored selection disappears.

Totals after this cycle: 90 backend + 48 frontend tests, E2E smoke extended with the
workspace flow, clippy/fmt clean.


## Review cycle 8 — scan diff feature audit

Scope: `routes/diff.rs` (engine + route), `repo/findings.rs::list_all_for_task`,
`repo/tasks.rs::find_previous_run`, the TaskDetail diff tab, both test additions,
E2E step 11.

Audited specifically:

- **Fingerprint collisions**: identity is (plugin_id, category, title) joined with
  U+001F unit separators — concatenated-field collisions impossible; verified a
  same-title/different-category pair classifies as new+fixed, not unchanged (unit
  test).
- **Auto-baseline ordering**: `created_at` has millisecond resolution and the query
  excludes the task itself (`id != ?`), so self-selection is impossible; the
  same-millisecond ambiguity between two *other* runs is benign and `?against=`
  exists as the escape hatch.
- **NULL targets**: `target IS ?` (NULL-safe equality) so target-less plugins diff
  correctly.
- **User isolation**: `load_task_for_user` on both the task and the explicit
  baseline (foreign tasks 404, existence hidden); auto-baseline query is scoped to
  the caller unless admin. Covered by a three-user integration test.
- **Non-completed tasks**: 400 on both sides (findings only persist at completion —
  diffing a running task would have reported everything as fixed).
- **`list_all_for_task`**: no user filter needed (task ownership already checked at
  the route); bounded by the 5 000-per-task insert cap; severity-ordered.

Found and fixed during the cycle:

1. Double `fingerprint()` computation per current finding (perf nit, now computed
   once and reused for the status match and the previous-finding attachment).
2. E2E script: f-string with nested double quotes broke the bash `python3 -c`
   quoting (SyntaxError) — rewritten as a plain print.
3. Test-quality fixes from clippy: `then().unwrap_or()` → `if/else`, an unused
   binding, and the admin diff assertion now also verifies the baseline id.

Verified totals after the cycle: 95 backend + 50 frontend tests green, clippy and
rustfmt clean, tsc clean, production build OK, E2E smoke (11 steps) green.

## Cycle 9 — async report jobs + webhooks + new formats (line-by-line)

Scope: migration 0003, `repo/reports.rs`, `reports_render.rs`, `report_jobs.rs`,
`routes/reports.rs`, config/main/tasks-deletion changes, the new frontend surface,
and their tests.

**Verified during the cycle (no changes needed)**

- **Artifact integrity**: write-to-`.tmp` + atomic rename means downloads never
  observe a half-written file; `file_bytes` cross-checked at download (mismatch
  logged, not fatal — the rename guarantees a consistent file).
- **Arbitrary-file-read hardening**: `download_job` canonicalizes both the stored
  path and the configured reports dir and requires `starts_with` containment, so a
  tampered/restored DB row cannot turn the endpoint into a file reader. Paths are
  `<job uuid>.<ext>` — no user-controlled components.
- **Deleted-mid-run jobs**: `finish()` reports rows-affected; 0 rows (job deleted
  while rendering) triggers artifact removal instead of an orphaned file. Task
  deletion removes artifacts before the cascade drops the rows that locate them.
- **Webhook signature correctness**: RFC 4231 HMAC-SHA256 test vector; the
  integration test recomputes the HMAC independently (never the server's own
  function) over the raw body received by a real HTTP receiver.
- **Webhook failure isolation**: a dead endpoint cannot fail the job; retries
  (3 attempts, 1s/4s backoff) are recorded in `webhook_attempts`; verified by
  polling the counter to 3 while the job stays `finished`.
- **Crash recovery**: `fail_interrupted` marks `waiting`/`in_progress` jobs failed
  at boot (mirrors the task orphan sweep); the reports dir is created before serve.
- **Panics in renderers**: CJK/emoji/control-character findings render through all
  8 formats without panicking (genpdf substitutes missing glyphs; `pdf_safe`
  normalizes control chars and tabs; DOCX/XLSX are XML-safe by construction).
- **XLSX formula injection**: cells are written as shared strings (explicit cell
  types), so spreadsheet apps cannot evaluate them — the CSV prefix guard is not
  needed there and the difference is documented.
- **Isolation**: job detail/download/delete 404 for foreign users; the job list is
  caller-scoped; creation requires scanner role (viewers 403) and a visible task.

**Found & fixed during the cycle**

1. **Backward-compat regression (self-caught)**: the first cut rejected the
   historical `markdown` alias on the sync export route (the old handler accepted
   it), and the new DB CHECK constraint only stores canonical ids — fixed with a
   `canonical_format()` normalizer used by both surfaces, plus regression tests
   on both paths.
2. Borrow error from `&&str` in `export_sync` after the normalizer change
   (`render(.., format)` instead of `&format`).
3. Test-quality: `break`-with-value inside a `for` loop, `StatusCode` scope,
   `reqwest::Response` move-before-header-read, and jsdom's missing
   `URL.createObjectURL` stubbed in tests (download flow).
4. A mangled edit (`vec!eader]`) introduced during refactoring was caught by the
   compiler and rebuilt cleanly — noted here because it is exactly the class of
   accident line-by-line review exists to catch.

Verified totals after the cycle: 108 backend + 58 frontend tests green, clippy and
rustfmt clean, tsc clean, production build OK, E2E smoke (12 steps) green.

## Cycle 10 — recurring schedules (line-by-line)

Scope: migration 0004, `repo/schedules.rs`, `scheduler.rs`, `routes/schedules.rs`,
the `admit_request` extraction from `routes/tasks.rs`, tasks-repo `schedule_id`
threading, the Schedules frontend surface, and their tests.

**Found & fixed during the cycle**

1. **`double_option` serde helper was a no-op** (self-caught by the integration
   test): `Option::deserialize(de)?` deserialized the full `Option<Option<T>>`,
   making JSON `null` indistinguishable from an absent field — `PATCH
   {"workspace_id": null}` would have silently done nothing in production. Fixed
   to `<Option<T>>::deserialize(de).map(Some)`; the workspace-clear PATCH is now
   regression-tested.
2. **COALESCE-update null trap**: the first `schedules::update` used COALESCE
   semantics, which cannot *clear* `workspace_id`/`preset` to NULL. Replaced with
   a merge-then-full-write model (the route loads the row for the auth check
   anyway), which also made the double-Option semantics above meaningful.
3. **`?target=` prefill race (pre-existing, in NewTask too)**: the plugin-defaults
   seed effect replaced state wholesale, so a prefill applied while the plugins
   query was still in flight was wiped the moment the plugin resolved. Both forms
   now fold the prefill into the seed. Found by a frontend test that failed only
   under async plugin resolution.
4. **Custom-interval edit round-trip**: editing a schedule whose interval is not
   a preset left the custom-minutes input empty; saving unchanged submitted
   `interval_seconds: 0` → 400. The input is now prefilled from the stored
   interval, and `canSubmit` validates the *effective* seconds (NaN/empty/<5 min
   disable submit) instead of the preset state.
5. **Silent mutation failures**: run-now/toggle/delete mutations had no `onError`
   — failures were invisible. All three now surface an `ErrorNote`.
6. Re-anchor assertion in the CRUD test was directionally wrong (a shorter new
   interval legitimately moves `next_run_at` *earlier* than the old anchor);
   replaced with a `now < anchor < now+interval+slack` window check.
7. Mechanical: needless borrow (`&state`), doc-comment `///` dropped on a wrapped
   line (syntax error), sqlx `QueryAs` move-after-bind, test-file placeholder
   edit left in during drafting.

**Verified during the cycle (no changes needed)**

- **Admission fidelity after extraction**: `admit_request` is a verbatim lift of
  task-admission steps 1–8 (including the policy-audit write on denial);
  `validate_and_create_task` = `admit_request` + persist. Call sites updated:
  task create (schedule `None`), retry (preserves `schedule_id` like
  `workspace_id`), workflow runner (`None`).
- **No catch-up bursts**: the anchor is always `now + interval` (never
  `old_anchor + interval`), so downtime or a long-disabled schedule yields one
  run, not a replay of every missed occurrence.
- **Overlap guard**: single indexed EXISTS over `tasks.schedule_id` +
  queued/running; verified deterministically with the sleepy plugin (second due
  pass → `OverlapSkipped`, still exactly one task).
- **Failure semantics**: plugin-disable → `Rejected` with `last_error` recorded,
  anchor advanced (no busy loop), no task created; re-enable + backdate → fires
  again. `last_task_id` uses COALESCE so a rejection never clears the last
  launched task.
- **No partial writes on rejected PATCH**: workspace resolution and admission
  both happen before the single UPDATE.
- **History integrity**: `ON DELETE SET NULL` verified end-to-end — deleting a
  schedule nulls `tasks.schedule_id` while the rows survive; deleting a user
  cascades schedules away; deleting a workspace detaches (SET NULL) to Personal.
- **Access control**: owner-or-404 on get/patch/delete/run (no existence leak),
  viewer 403 on create/run, list caller-scoped (admin all) with
  `?workspace_id=` parity to tasks; scheduler acts as the owner row so tasks are
  owned by the schedule owner.
- **Consent model**: consent captured at creation; automated runs and PATCH
  re-admissions pass `consent_granted: true` (same convention as retry and
  workflow steps) while target policy is re-evaluated on every occurrence.
- **Timestamp math**: `add_seconds_iso` preserves the canonical fixed-width
  RFC 3339 shape so lexical due-comparison stays valid; unit tests cover
  round-trip, negative offsets, ordering, and corrupt-input fallback.
- **Scheduler/user races**: single-worker loop is sequential; the only
  concurrent launcher is run-now, which deliberately bypasses the overlap guard
  (documented in both the route and the module docs). `mark_run` failures are
  logged; worst case is a re-fire next tick, never a lost anchor update.
