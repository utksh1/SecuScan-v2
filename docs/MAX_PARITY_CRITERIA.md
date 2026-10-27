# Max-Parity Acceptance Criteria

Per-domain, testable acceptance criteria for "maximum parity with
pentest-tools.com". Each domain lists the bar we must clear and how it is
verified. The phased delivery schedule lives in
[`MAX_PARITY_PLAN.md`](./MAX_PARITY_PLAN.md); this file is the scoreboard
the final audit (Sprint 22.7) runs against.

Verification keys: **[T]** automated test · **[V]** `scripts/verify.mjs` ·
**[B]** `scripts/benchmark.mjs` baseline comparison · **[M]** manual review
with evidence (screenshots / sample artifacts).

---

## 1. Scan Customization (depth profiles)

- Every catalog scanner with a meaningful depth axis offers ≥2 named scan
  profiles with distinct runtime behavior (not just relabeling). **[T][V]**
- Profile selection is one-click from: NewTask cards, the category browser
  chips, and Attack-Target suites (web→Quick tier, full→Deep tier). **[M]**
- Estimated-runtime hints derived from badges render on every profile card. **[T]**

## 2. False-Positive Handling

- Marking a finding `false_positive` persists to `fp_memory` with acting
  user + optional reason; the identical finding on any later scan of the
  same target auto-suppresses (>90% suppression rate). **[T][B]**
- Dedup-group duplicates inherit triage status changes. **[T]**
- Any non-FP status forgets the memory; the next scan reports fresh. **[T]**
- The audit trail (who/when/why) is visible in the Findings UI. **[T][M]**

## 3. Authenticated Scanning

- Tasks can attach an auth profile; cookie/header/form methods resolve to
  concrete request material. **[T]**
- Native HTTP scanners (website-scanner incl. DAST engine, http-recon) send
  the session on every request. **[T]**
- Form-login profiles harvest Set-Cookie automatically; failed logins fail
  the task loudly (never silently scan unauthenticated). **[T]**
- 100% authenticated-scan success on the vuln-app fixture. **[B]**

## 4. Secrets Handling

- `auth_profiles.config_json` and `vpn_profiles.config_text` are AES-256-GCM
  ciphertext in SQLite (`enc:v1:` prefix); plaintext never touches disk
  after first write; legacy plaintext rows still decrypt. **[T]**
- Key source: `SECUSCAN_ENC_KEY` or auto-generated 0600 key file. **[T]**

## 5. Out-of-Band Detection

- `/oob/:secret` serves a dynamic beacon built from handler config;
  CORS-open for cross-origin fetch+eval; public base URL configurable. **[T]**
- Blind SSRF/XXE/SQLi payloads auto-inject per-task markers; correlated
  callbacks auto-create findings. **[T][B]**
- Handlers expire (TTL) and are purged by a cleanup cron. **[T]**

## 6. Reconnaissance Depth

- Subdomain finder: passive (crt.sh), brute-force, AXFR attempt, NS/MX/TXT/
  CNAME harvest, permutations, per-subdomain tech fingerprinting. **[T][M]**
- Domain finder performs crt.sh organization pivoting. **[T]**
- Website recon hunts origin IP (DNS history + SAN pivot). **[T]**

## 7. Web / CMS / API Scanning

- WordPress enumeration surface matches WPScan (users ×3 vectors, plugins,
  themes, backups, TimThumb, XML-RPC, wp-cron, readme). **[T][M]**
- API scanner: GraphQL introspection + DoS probes, mass-assignment, IDOR,
  verb tampering, auth-header support. **[T]**
- URL fuzzers (ffuf/gobuster): soft-404 auto-calibration, extension
  categories, recursion, custom headers, POST bodies. **[T]**

## 8. Network Scanning

- Unified Network Scanner: one tool, per-engine toggles (nmap/nuclei/
  testssl/OpenVAS), version-based detection, safe defaults. **[T][M]**
- UDP scan: two-phase `open|filtered` re-verification. **[T]**
- Password auditor: 17 protocols, dictionary + spray modes with lockout
  pacing, auto login-form detection. **[T]**

## 9. Reporting

- All 8 formats render CVE/CVSS/CWE/OWASP/EPSS/KEV enrichment. **[T]**
- Aggregated multi-scan reports (<30s for 50 scans) with grouping and
  include-filters; executive summary layer; report builder wizard. **[T][B][M]**
- Branding (logo/colors/org/footer) on PDF/DOCX/HTML. **[M]**

## 10. Findings Workflow

- Bulk triage (1000 findings <2s) + checkbox UI. **[T][M]**
- Cursor pagination on tasks/findings at 10k+ records. **[T][B]**
- Structured evidence (req/resp pairs, screenshots, command output with
  content hashes) + evidence viewer. **[T][M]**
- Finding-change audit log (who/when/old→new). **[T]**

## 11. Attack Surface Management

- Attack surface auto-aggregates from scans; v2 UI with group-by,
  port/service/tech columns, scan linkage, CSV/JSON export. **[T][M]**

## 12. AI Layer (6 touchpoints + Mini-Specter)

- Provider-agnostic client (OpenAI-compatible: OpenAI/Anthropic/Ollama/vLLM). **[T]**
- Touchpoints: finding enrichment, soft-404 classifier (≥95% precision),
  Mini-Specter agent loop, flowmapper-lite crawl, translate_report,
  AI-assisted auth fallback. **[T][B]**
- Mini-Specter: mandatory deterministic validator (zero FPs reported),
  time-budgeted, consent-gated via MCP. **[T]**
- Per-feature opt-out env flags; no prompt/completion logging; credential
  stripping on all outbound prompts. **[T]**

## 13. Orchestration & Scale

- Worker binary + Redis queue: tasks survive API restarts; 100 concurrent
  scans; zero data loss on worker failure. **[T][B]**
- Worker regional/capability tags; asset-based metering (30-day cycle);
  named scan schedules with timezones. **[T][M]**

## 14. Integrations

- Python SDK (PyPI) + TypeScript SDK (npm) generated from openapi.json. **[M]**
- Remote CLI mode (`--server-url`) + GitHub Action + Docker scan image. **[M]**
- OpenAPI contract tests fail CI on spec/impl drift. **[T]**

## 15. Platform & Security

- TOTP 2FA with recovery codes; API key expiry; workspace membership
  gating; per-user rate limits with `X-RateLimit-*` headers. **[T]**
- DNS rebinding protection (resolve + pin at admission). **[T]**
- Encryption at rest (see §4); audit logs; i18n + command palette + keyboard
  shortcuts. **[T][M]**

---

## Baseline Metrics (Phase 0 capture)

Run `scripts/benchmark.mjs` against a running server to capture the
pre-Phase-1 baseline; each phase's success metrics are compared against it.

| Metric | How measured | Baseline |
|--------|--------------|----------|
| FP suppression rate | re-scan after FP-marking, count auto-suppressed | *capture* |
| Scan latency (native) | website-scanner p50/p95 on vuln-app | *capture* |
| OOB hit rate | blind payload → finding, over N runs | *capture* |
| Report generation time | 8 formats, 50-finding task | *capture* |

*Update this table from benchmark output at each phase exit.*
