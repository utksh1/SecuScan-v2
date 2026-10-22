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
