# SecuScan-v2 — Maximum Parity Phased Implementation Plan

**Goal**: Reach full parity with pentest-tools.com + exceed on orchestration, MCP, diffing, attack suites
**Timeline**: ~30 weeks (7.5 months) with 2-3 engineers
**Philosophy**: Fix broken plumbing first, then depth, then AI, then distributed

---

## Phase 0: Foundation (Week 0) — Prerequisites

| Task | Owner | Files | Done? |
|------|-------|-------|-------|
| Set up feature branches + CI gates | DevOps | `.github/workflows/ci.yml` | ☐ |
| Add `SECUSCAN_AI_BASE_URL` / `_API_KEY` env (unused for now) | Backend | `.env.example`, `crates/api/src/config.rs` | ☐ |
| Document "max parity" acceptance criteria per domain | PM | `docs/MAX_PARITY_CRITERIA.md` | ☐ |
| Baseline metrics: FP rate, scan latency, OOB hit rate, report gen time | QA | `scripts/benchmark.mjs` (new) | ☐ |

---

## Phase 1: Critical Plumbing Fixes (Weeks 1-3)
**Theme**: "Make what we have actually work" — unblock core scanning flows

### Sprint 1.1 (Week 1): FP Memory + Auth Injection + Encryption

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 1.1 | Wire `remember_false_positive` / `forget_false_positive` in triage PATCH | `crates/api/src/routes/findings.rs:177`, `crates/db/src/repo/finding_dedup.rs:125` | Mark FP → next same-scan run auto-suppresses duplicate |
| 1.2 | Call `propagate_status_to_group` on any status change | `crates/db/src/repo/finding_dedup.rs:108` | Group duplicates inherit status |
| 1.3 | Add `reason` + `acting_user` to `TriageRequest`; persist to `fp_memory` | `routes/findings.rs:172`, `models.rs:86` | Audit trail visible in UI |
| 1.4 | Pass `auth_profile_id` from `manager.rs` → `execute_task` → native HTTP clients | `crates/api/src/manager.rs:163`, `crates/exec/src/lib.rs:48`, `http_recon.rs`, `website_scanner.rs` | Authenticated scan runs with cookies/headers |
| 1.5 | AES-GCM encrypt `auth_profiles.config_json` + `vpn_profiles.config` at rest | `crates/db/src/repo/auth_profiles.rs:20`, `vpn_manager.rs:123`, new `crates/core/src/crypto.rs` | SQLite shows ciphertext; decryption only in memory |
| 1.6 | Fix Sniper XSS chain target collision (don't overwrite handler field) | `crates/api/src/sniper_engine.rs:283` | XSS chain step accepts handler name, not finding URL |

**Exit criteria**: FP suppression works cross-scan; authenticated scan proves via OOB hit; secrets encrypted

### Sprint 1.2 (Week 2): OOB Pipeline End-to-End

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 2.1 | Dynamic payload at `/oob/:secret` built from `handler.config_json` (JS beacon) | `crates/api/src/routes/oob.rs:177`, `crates/exec/src/native/xss_exploiter.rs:34` | XSS Exploiter delivers payload; cookie/keystroke exfil works |
| 2.2 | `Access-Control-Allow-Origin: *` on `/oob/:secret` route only | `oob.rs:177` | fetch+eval mode works cross-origin |
| 2.3 | Configurable public base URL (env `SECUSCAN_PUBLIC_URL`) replacing `secuscan.local` | `http_request_logger.rs:44`, `xss_exploiter.rs:56`, `config.rs` | OOB callbacks reachable from internet |
| 2.4 | Inject `tasks.oob_marker` + callback URL into website-scanner/dast blind payloads | `crates/exec/src/native/website_scanner.rs`, `dast_engine.rs` | SSRF/XXE/blind-SQLi auto-detect via OOB correlation |
| 2.5 | Auto-create finding from correlated OOB hit (dedup by marker+task) | `crates/api/src/routes/oob.rs:209`, `manager.rs` | Blind vulm appears in findings without manual step |

**Exit criteria**: XSS Exploiter functional; blind SSRF/XXE/SQLi auto-found via OOB

### Sprint 1.3 (Week 3): Quick Wins + Hardening

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 3.1 | Domain Finder org-pivot (crt.sh org field → sibling domains) | `crates/exec/src/native/domain_finder.rs:29` | Finds facebook.com → fbcdn.net etc. |
| 3.2 | Branding → renderers (logo/colors/org-name/footer for PDF/DOCX/HTML) | `crates/api/src/reports_render.rs` | Reports show custom branding |
| 3.3 | API key expiry field + validation | `crates/api/src/auth/extractor.rs:76`, `routes/auth.rs:265` | Keys auto-expire |
| 3.4 | Workspace list membership gate | `crates/api/src/routes/workspaces.rs:106` | Users see only their workspaces |
| 3.5 | OOB handler TTL cleanup cron (daily) | `crates/api/src/routes/oob.rs`, new `scheduler.rs` job | Expired handlers purged |
| 3.6 | Soft-404 logistic regression (replace 4-line heuristic) | `crates/exec/src/native/website_scanner.rs:543` | Measurable FP reduction vs baseline |
| 3.7 | Rate limiting middleware (per-user quotas + headers) | `crates/api/src/auth.rs:62` template | `X-RateLimit-*` on all endpoints |

**Exit criteria**: All "10-line fixes" shipped; branding visible; rate limits enforced

---

## Phase 2: Core Parity Features (Weeks 4-8)
**Theme**: "Match pentest-tools.com feature-for-feature on scanning"

### Sprint 2.1 (Week 4): Multi-Scan Reports + Bulk Triage

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 4.1 | `POST /reports` with `source: scans|findings`, `resources[]`, `group_by`, `include_*` | `crates/api/src/report_jobs.rs`, `routes/reports.rs` | Aggregated report across N scans |
| 4.2 | Render CVE/CVSS/CWE/OWASP/EPSS/KEV in all 8 formats | `crates/api/src/reports_render.rs` | Finding details show enrichment |
| 4.3 | Bulk triage endpoint `PATCH /findings/bulk` (id list + status + reason) | `crates/api/src/routes/findings.rs`, `repo/findings.rs` | 1000 findings bulk-edit in <2s |
| 4.4 | Findings UI: checkbox selection + bulk toolbar | `frontend/src/pages/Findings.tsx` | Check all → bulk status change |
| 4.5 | Pagination on Tasks/Findings (cursor-based) | `routes/tasks.rs:337`, `findings.rs:63`, `frontend` | 10k+ records scroll smoothly |

### Sprint 2.2 (Week 5): WordPress Scanner Rebuild + Subdomain Depth

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 5.1 | WordPress enumeration toggles (users, vuln plugins/themes, config backups, DB exports, TimThumb) | New `crates/exec/src/native/wordpress_audit.rs`, `plugins/wordpress-audit.toml` | Matches WPScan surface |
| 5.2 | 3-vector user enumeration (author archives, REST API, login errors) | `wordpress_audit.rs` | User list extracted |
| 5.3 | XML-RPC/wp-cron/readme/install.php checks + Basic auth support | `wordpress_audit.rs` | Interesting findings detected |
| 5.4 | Subdomain Finder: AXFR attempt + NS/MX/TXT/CNAME harvest | `crates/exec/src/native/subdomain_finder.rs` | Zone transfer + record types |
| 5.5 | Subdomain permutations (api→api2/api-dev) + `include_unresolved` toggle | `subdomain_finder.rs` | Discovers dev/staging variants |
| 5.6 | Per-subdomain tech fingerprint (chain http-probe/whatweb) | `subdomain_finder.rs` + existing plugins | Tech tags on each subdomain |

### Sprint 2.3 (Week 6): Network Scanner Unification + Password Auditor Expansion

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 6.1 | Unified Network Scanner plugin (nmap version-based + nuclei + testssl + OpenVAS stub) | `plugins/network-scanner.toml`, new `crates/exec/src/native/network_scanner.rs` | Single tool, per-engine toggles |
| 6.2 | Password Auditor: add SSH/FTP/Telnet/MySQL/MSSQL/PostgreSQL/Redis/SMB/RDP/VNC/WinRM/MQTT/AMQP/STOMP/Docker | `plugins/password-audit.toml`, `crates/exec/src/native/password_audit.rs` | 17 protocols (PTT parity) |
| 6.3 | Dictionary vs spray modes + lockout pacing (period/attempts/delay) | `password_audit.rs` | Spray respects lockout windows |
| 6.4 | Auto login-form detection (Jenkins, Tomcat, phpMyAdmin, router admin) | `password_audit.rs` | Zero-config for common targets |
| 6.5 | UDP two-phase: real `-sV` re-verify of `open|filtered` + Light/Deep presets | `plugins/udp-port-scan.toml`, `udp_port_scan.rs` | Proper UDP semantics |

### Sprint 2.4 (Week 7): API Scanner Depth + URL Fuzzer Parity

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 7.1 | GraphQL introspection → endpoint map + DoS checks (deep nesting, resource exhaustion) | `crates/exec/src/native/api_scanner.rs` | GraphQL attack surface mapped |
| 7.2 | Mass-assignment probe + IDOR probes (±1 resource IDs) | `api_scanner.rs` | Finds overposting/IDOR |
| 7.3 | Auth headers field (Bearer/Basic/X-API-Key) surfaced in TOML | `plugins/api-scanner.toml` | Authenticated API scans |
| 7.4 | ffuf: auto soft-404 calibration + extension categories + custom headers/POST + mutations | `plugins/ffuf.toml`, `ffuf.rs` | URL Fuzzer parity |
| 7.5 | gobuster: recursion + soft-404 + extension categories | `plugins/gobuster.toml` | Feature parity |

### Sprint 2.5 (Week 8): Recon Depth + Vulnissimo Parity

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 8.1 | Website Recon: origin-IP hunt (DNS history + crt.sh SAN pivot) | `crates/exec/src/native/http_recon.rs`, `whatweb.rs` | Finds real IP behind WAF |
| 8.2 | Vhost Finder passive pre-stage (TLS SAN + PTR + redirects) | `crates/exec/src/native/vhost_finder.rs` | Passive→active pipeline |
| 8.3 | People Hunter: TLS CN extraction + pattern-based address prediction | `crates/exec/src/native/people_hunter.rs` | Implements advertised steps |
| 8.4 | Google Dorks: category selector (files/dirs, auth, errors, external sources, discovery) | `plugins/google-dorks.toml`, `google_dorks.rs` | 5 dork groups |
| 8.5 | Vulnissimo-style passive "browsing-like" scan mode (optional flag) | `website_scanner.rs` | Low-noise reconnaissance |

**Phase 2 Exit**: All 20+ tools at ≥90% technique parity; multi-scan reports; bulk triage; pagination

---

## Phase 3: AI/ML Layer (Weeks 9-14)
**Theme**: "Build the 6 touchpoints + Mini-Specter" — local-first, deterministic validation

### Sprint 3.1 (Week 9): Provider-Agnostic LLM Client + Finding Enrichment

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 9.1 | `crates/core/src/ai_client.rs`: OpenAI-compatible client (base_url, api_key, retry, timeout) | New file | Works with OpenAI, Anthropic, Ollama, vLLM |
| 9.2 | Post-scan enrichment hook: rewrite Nuclei/parser descriptions → triage prose + next_steps | `crates/api/src/manager.rs` (after finding insert), `ai_client.rs` | Findings have `ai_summary`, `ai_next_steps` |
| 9.3 | Store enrichment on existing columns (`models.rs:204`); render in reports | `reports_render.rs` | AI prose in PDF/HTML/SARIF |
| 9.4 | Per-feature AI opt-out env flags (`SECUSCAN_AI_ENRICHMENT=false`) | `config.rs`, `.env.example` | Zero data egress when disabled |
| 9.5 | Strip credentials from any prompt sent to vendor | `ai_client.rs` sanitizer | No secrets in LLM requests |

### Sprint 3.2 (Week 10): Soft-404 Classifier (Local Model)

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 10.1 | Dataset: crawl 10k pages → label HIT/MISS/PARTIAL/INCONCLUSIVE | `scripts/soft404_dataset.mjs` (new) | Labeled dataset |
| 10.2 | Train logistic regression / small MLP (candle/ort) on de-boilerplated features | `crates/core/src/soft404_classifier.rs` (new) | >95% precision on holdout |
| 10.3 | Replace `is_soft_404` heuristic; emit probability + label | `website_scanner.rs:543` | Classifier drives crawl decisions |
| 10.4 | Wire into URL fuzzing (ffuf/gobuster) for auto-calibration | `plugins/ffuf.toml`, `gobuster.toml` | Soft-404 aware fuzzing |

### Sprint 3.3 (Week 11): Mini-Specter Agent Loop

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 11.1 | LLM planner over MCP tools: `plan → execute → observe → replan` loop | `crates/core/src/agent_loop.rs` (new) | Autonomous multi-step scan |
| 11.2 | **Mandatory validator stage**: every candidate finding must pass deterministic re-confirmation | `agent_loop.rs` + existing OOB/replay | Zero false positives reported |
| 11.3 | Validator checks: replay request / OOB callback / CVSS v3.1 vector / ≥1 proof artifact | `agent_loop.rs`, `oob.rs`, `reports_render.rs` | Matches 18.4 doctrine |
| 11.4 | Time-budgeted (max 4h), graceful stop on CAPTCHA/bot signatures | `agent_loop.rs` | Respects limits |
| 11.5 | MCP tool `run_specter` (consent-gated, human approval required) | `crates/mcp/src/tools.rs:103` | LLM can't launch without operator |

### Sprint 3.4 (Week 12): Flowmapper-Lite + translate_report

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 12.1 | Flowmapper-lite: LLM-driven crawl fed into spider queue (≤50% scan budget) | `crates/core/src/flowmapper.rs` (new), `website_scanner.rs` queue | Discovers hidden endpoints |
| 12.2 | Graceful stop on bot-protection signatures (CAPTCHA, challenge pages) | `flowmapper.rs` | Doesn't hammer defenses |
| 12.3 | MCP `translate_report` tool: fetch findings → translate → re-import → regenerate | `crates/mcp/src/tools.rs`, `proto.rs` | 50 findings/hour quota |
| 12.4 | AI-assisted auth fallback: LLM login-form locator + outcome adjudication | `crates/exec/src/native/password_audit.rs:170` | Resolves ambiguous login |

### Sprint 3.5 (Week 13): Governance Hardening

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 13.1 | Per-feature opt-out flags (enrichment, classifier, agent, flowmapper, translate) | `config.rs` | Granular control |
| 13.2 | No prompt/completion logging (configurable audit log for compliance only) | `ai_client.rs` | Privacy by default |
| 13.3 | Exploit determination stays deterministic (only classifier/validator see content) | `agent_loop.rs` | Doctrine enforced in code |
| 13.4 | MCP governance: `readOnlyHint`/`destructiveHint` on all tools; `run_sniper` requires elicitation | `crates/mcp/src/tools.rs:136` | LLM clients auto-gate destructive calls |
| 13.5 | HTTP transport: require Bearer auth (config `SECUSCAN_MCP_REQUIRE_AUTH=true`) | `crates/mcp/src/lib.rs:123` | No unauthenticated MCP |

### Sprint 3.6 (Week 14): AI Integration Testing + Docs

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 14.1 | E2E test: Mini-Specter finds real vuln on vuln-app.mjs | `scripts/verify.mjs` | Autonomous agent works |
| 14.2 | Benchmark: classifier FP reduction vs heuristic baseline | `scripts/benchmark.mjs` | Quantified improvement |
| 14.3 | Document AI architecture, data flows, opt-outs in `docs/AI_ARCHITECTURE.md` | New file | Compliance-ready |

**Phase 3 Exit**: 6 touchpoints + Mini-Specter operational; all local-first; governance hardened

---

## Phase 4: Distributed Architecture (Weeks 15-22)
**Theme**: "Horizontal scaling + regional fleet + DNS OOB"

### Sprint 4.1 (Weeks 15-16): Worker Binary + Redis Queue

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 15.1 | Extract `TaskManager` → separate `secuscan-worker` binary | `crates/api/src/manager.rs` → new `crates/worker/` | Worker registers, picks tasks |
| 15.2 | Redis queue (sorted sets for priority + scheduled) + task serialization | `crates/worker/src/queue.rs` (new) | Tasks survive API restart |
| 15.3 | Worker registration + heartbeat + capacity reporting | `crates/worker/src/registration.rs` | Fleet visible in API |
| 15.4 | API: task submission → queue (not in-process spawn) | `crates/api/src/manager.rs` | Zero in-process execution |
| 15.5 | Plugin limiter: distributed semaphore via Redis | `crates/exec/src/limiter.rs` | Per-plugin caps across fleet |

### Sprint 4.2 (Weeks 17-18): Regional Deployment + Asset Metering

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 16.1 | Worker tags (region, capabilities, max_concurrent) | `crates/worker/src/registration.rs` | Scheduler routes by tag |
| 16.2 | Asset-based metering: 30-day scan cycle, workspace asset counts, quota enforcement | `crates/api/src/routes/workspaces.rs`, `models.rs` | Mirrors PTT Ch.4.3 billing |
| 16.3 | Scan scheduling: named frequencies (daily/weekly/monthly) + timezone + month-end anchor | `crates/api/src/scheduler.rs` | Human-readable schedules |
| 16.4 | Per-user concurrency/queue caps for multi-tenant | `manager.rs`, `config.rs` | Fair sharing |

### Sprint 4.3 (Weeks 19-20): DNS OOB Receiver (interact.sh-style)

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 17.1 | Subdomain delegation: `*.oob.secuscan.local` → DNS server | New `crates/oob_dns/` (trust-dns) | DNS callbacks received |
| 17.2 | DNS record logging (A/AAAA/TXT/MX + query metadata) | `oob_dns/src/` | Full DNS exfil capture |
| 17.3 | Correlate DNS queries to tasks via marker subdomain (`ptt{marker}.oob...`) | `oob_dns/src/`, `routes/oob.rs` | Blind vuln via DNS exfil |
| 17.4 | Auto marker injection for DNS payloads (MySQL UNC, Log4j JNDI, etc.) | `website_scanner.rs`, `dast_engine.rs` | DNS OOB works automatically |

### Sprint 4.4 (Weeks 21-22): SDK Generation + Remote CLI + Contract Tests

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 18.1 | CI job: openapi.json → Python SDK (`openapi-generator`) → publish to PyPI (test) | `.github/workflows/sdk.yml` (new) | `pip install secuscan-sdk` |
| 18.2 | CI job: openapi.json → TypeScript SDK → publish to npm (test) | `.github/workflows/sdk.yml` | `npm install @secuscan/sdk` |
| 18.3 | Remote CLI mode: `secuscan --server-url https://… scan …` | `crates/cli/src/main.rs` | CI/CD integration parity |
| 18.4 | OpenAPI contract tests (spec ↔ impl drift detection) | `crates/api/tests/contract.rs` (new) | CI fails on drift |
| 18.5 | GitHub Action + Docker scan image | `.github/actions/secuscan-scan/`, `Dockerfile.scan` | One-liner CI integration |

**Phase 4 Exit**: Multi-worker fleet; regional scans; DNS OOB; SDKs published; CI/CD ready

---

## Phase 5: Advanced Differentiation (Weeks 23-30)
**Theme**: "Exceed pentest-tools.com on orchestration, evidence, UX"

### Sprint 5.1 (Weeks 23-24): OpenVAS Engine + Unified Network Scanner

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 19.1 | `plugins/openvas.toml` + Greenbone OSP/GVM API client in `crates/exec/src/native/openvas.rs` | New files | Authenticated vuln scans |
| 19.2 | Integrate into Unified Network Scanner (per-engine toggles, RPS 1-1000, custom-CVE ≤500, KEV-only) | `network_scanner.rs` | Single tool, full config |
| 19.3 | Confirmed-tag auto-assignment (OpenVAS → validated_issue) | `openvas.rs` + finding parser | Auto-confirmed findings |

### Sprint 5.2 (Weeks 25-26): Evidence Richness + Attack Surface v2

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 20.1 | Structured evidence model: `http_pair`/`screenshot`/`command_output` with content hashes | `crates/db/migrations/0008_evidence.sql`, `models.rs` | Replaces single `proof` string |
| 20.2 | Website scanner captures req/resp pairs + screenshots (headless) | `website_scanner.rs`, new `screenshot.rs` (headless_chrome) | Evidence viewer has data |
| 20.3 | Evidence viewer tab (request/response/screenshot/hex) | `frontend/src/pages/TaskDetail.tsx`, new `EvidenceViewer.tsx` | PTT-level evidence UI |
| 20.4 | Attack Surface v2: group-by selector, port/service/tech columns, scan linkage, CSV/JSON export | `frontend/src/pages/AttackSurfacePage.tsx`, `routes/attack_surface.rs` | Navigable attack surface |

### Sprint 5.3 (Weeks 27-28): Report Builder Wizard + Executive Summary

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 21.1 | Aggregated report wizard: multi-task select → format + include-filters + grouping | `frontend/src/pages/ReportBuilder.tsx` (new), `report_jobs.rs` | Visual report builder |
| 21.2 | Executive summary layer: cover page + severity dist + risk overview (reuse XLSX Summary) | `reports_render.rs` (PDF/DOCX/HTML) | Client-ready deliverable |
| 21.3 | Finding templates + manual finding creation + Engagement object | `crates/db/migrations/0009_engagements.sql`, `routes/engagements.rs` (new) | Pentest report workflow |

### Sprint 5.4 (Weeks 29-30): Polish + Compliance + Launch

| # | Task | Files | Acceptance |
|---|------|-------|------------|
| 22.1 | TOTP 2FA (QR enrollment + recovery codes) | `crates/api/src/auth/mod.rs`, `frontend/src/pages/Settings.tsx` | 2FA parity |
| 22.2 | i18n wrapper + cmd-K command palette | `frontend/src/i18n/` (new), `AppShell.tsx` | English + 1 more lang |
| 22.3 | Keyboard shortcuts (global + per-page) | `frontend/src/hooks/useShortcuts.ts` (new) | Power-user UX |
| 22.4 | Finding-change audit log (who/when/old→new) | `crates/db/migrations/0010_audit.sql`, `routes/findings.rs` | PCI/SOC2 evidence |
| 22.5 | DNS rebinding protection: resolve at admission → pin all A/AAAA | `crates/core/src/policy.rs` + admission | Closes documented gap |
| 22.6 | Load/chaos tests (100 concurrent scans, worker failover) | `scripts/load_test.mjs` (new) | Production hardening |
| 22.7 | Final parity audit vs `docs/MAX_PARITY_CRITERIA.md` | All domains | 100% criteria met |

**Phase 5 Exit**: Shippable product that exceeds pentest-tools.com on orchestration, evidence, reporting, MCP

---

## Dependency Graph (Critical Path)

```
Phase 1.1 (FP memory + Auth injection + Encryption)
    │
    ├──→ Phase 1.2 (OOB pipeline) ──────────────────┐
    │                                                │
    ├──→ Phase 1.3 (Quick wins)                     │
    │                                                ▼
    └────────────────────────────────→ Phase 2 (Core Parity)
                                                          │
                    ┌────────────────────────────────────┘
                    ▼
            Phase 3 (AI/ML) ◄────── Requires: auth injection, OOB, encryption
                    │
                    ▼
            Phase 4 (Distributed) ◄── Requires: Redis, worker extraction
                    │
                    ▼
            Phase 5 (Differentiation) ◄── Requires: distributed fleet, AI layer
```

---

## Staffing Model (2-3 Engineers)

| Role | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|------|---------|---------|---------|---------|---------|
| Backend (Rust) | 2 | 2 | 1.5 | 2 | 1.5 |
| Frontend (React) | 0.5 | 1 | 0.5 | 0.5 | 1.5 |
| DevOps/Infra | 0.5 | 0.5 | 0 | 1.5 | 0.5 |
| **Total FTE** | **3** | **3.5** | **2** | **4** | **3.5** |

*Adjust: hire 1 contractor for Phase 4 distributed systems work*

---

## Risk Register & Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| OpenVAS GVM API complexity | High | High | Start PoC Week 10; fallback to nuclei-only unified scanner |
| Distributed queue stability | Medium | High | Use battle-tested `redis` crate; extensive integration tests |
| LLM cost / latency in Mini-Specter | Medium | Medium | Strict time budgets; local models (Ollama) as default |
| DNS OOB subdomain delegation ops | Low | High | Document DNS setup; provide managed subdomain option |
| Schema migrations on live data | Low | Critical | Test migrations on production dump; backward-compatible |

---

## Success Metrics (Per Phase)

| Phase | Metric | Target |
|-------|--------|--------|
| 1 | FP suppression rate | >90% cross-scan |
| 1 | Authenticated scan success | 100% on vuln-app.mjs |
| 1 | OOB blind vuln detection | SSRF/XXE/SQLi auto-found |
| 2 | Tool technique parity | ≥90% per tool vs PTT |
| 2 | Multi-scan report generation | <30s for 50 scans |
| 3 | AI enrichment quality | Human-rated ≥4/5 |
| 3 | Mini-Specter true positive rate | >80% on vuln-app |
| 3 | Classifier precision | >95% (vs 70% heuristic) |
| 4 | Horizontal scaling | 100 concurrent scans |
| 4 | DNS OOB detection | Log4j/SSRF via DNS |
| 5 | Report builder adoption | >50% reports via wizard |
| 5 | Evidence viewer usage | >80% findings have req/resp |

---

## Definition of "Max Parity" (Ship Criteria)

- **All 20+ tools at ≥95% technique parity** with pentest-tools.com
- **6 AI touchpoints + Mini-Specter** operational, local-first, governed
- **Multi-worker fleet** with regional tags, asset metering, named schedules
- **HTTP + DNS OOB** with automatic marker injection
- **Evidence-rich findings** (req/resp/screenshot/CVSS/CVE/CWE) in all 8 formats
- **Aggregated reports + executive summary + engagement workflow**
- **Bulk triage + pagination + attack surface v2 + i18n + 2FA**
- **Python/TS SDKs + GitHub Action + remote CLI**
- **Encryption at rest + audit logs + DNS rebinding protection**
- **Load-tested: 100 concurrent scans, zero data loss on worker failure**

---

## Quick-Start Commands (for each phase)

```bash
# Phase 1
cargo test --workspace --lib fp_memory auth_injection encryption
cargo test --workspace --lib oob_pipeline

# Phase 2
cargo test --workspace --lib network_scanner wordpress password_audit
cargo test --workspace --integration multi_scan_reports bulk_triage

# Phase 3
cargo test --workspace --lib ai_client soft404 agent_loop
cargo run --example specter_demo -- vuln-app.mjs

# Phase 4
docker compose -f docker-compose.distributed.yml up
cargo test --workspace --integration distributed_queue dns_oob

# Phase 5
cargo test --workspace --lib openvas evidence attack_surface_v2
cargo test --workspace --integration load_test
```

---

*Document version: 1.0 | Generated from 15-domain gap analysis | Update per sprint retro*
