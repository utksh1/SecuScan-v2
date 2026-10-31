# Engineering Quality Improvement Roadmap

> Status: proposal / implementation plan  
> Scope: scanner parsing and finding quality, evidence provenance, reporting, UI/UX, and local-first reliability.  
> This document describes proposed work. It does not claim that the work items below have been implemented or verified.

## 1. Purpose

SecuScan is a local-first security scanning workspace. The next quality phase should improve the reliability and usefulness of the data produced by scanners, the reports built from that data, and the workflows used by analysts.

The guiding principle is:

**Treat normalized, traceable, analyst-reviewed findings as the product's primary data—not raw output from individual tools.**

This roadmap complements the existing [Architecture](ARCHITECTURE.md), [Plugin Development](PLUGIN_DEVELOPMENT.md), [API](API.md), and [Deployment](DEPLOYMENT.md) documentation. It does not replace those implementation references.

## 2. Current baseline (from repository inspection)

The following are existing repository capabilities, not roadmap proposals:

- Plugins are declarative TOML manifests; plugin-supplied parser code is not executed.
- The parser engine currently supports `passthrough`, `line_regex`, and `json_lines`, plus whole-output static rules.
- Parser behavior includes manifest-time validation, skip patterns, severity rules/maps, metadata mapping, finding deduplication, and a per-task finding cap.
- The core parser currently consumes captured output as text and has an 8 MiB parser input cap.
- Finding records already include fields such as kind, severity, category, title, description, remediation, proof, URL, metadata, CVE/CVSS fields, and analyst status.
- Report rendering already supports JSON, Markdown, CSV, HTML, SARIF, PDF, DOCX, and XLSX; synchronous exports and asynchronous report jobs share rendering code.
- CSV formula-injection mitigation and HTML escaping are present in the report renderer.
- The frontend already has dashboard, findings, reports, scanners, task, target, schedule, workflow, settings, and other pages, with tests for several primary pages.

These existing features mean the work should focus on **coverage, consistency, correctness, usability, and regression protection**, rather than reimplementing systems that already exist.

## 3. Goals and non-goals

### Goals

1. Make parser behavior observable, testable, and predictable across supported plugins.
2. Preserve enough raw-output provenance to explain where every normalized finding came from.
3. Make finding identity and cross-scan correlation more reliable without merging unrelated issues.
4. Improve reports for both executive readers and technical analysts.
5. Improve the consistency and efficiency of the analyst UI.
6. Keep local-first security controls proportionate to the actual deployment model.
7. Define measurable acceptance criteria and regression tests.

### Non-goals for this phase

- Replacing the current Rust/Axum and React architecture.
- Executing arbitrary plugin-supplied parser code.
- Requiring a cloud service, hosted database, or external AI provider.
- Adding scanners solely to increase the plugin count.
- Treating scanner output as proof that a vulnerability is confirmed.
- Rewriting every frontend page before validating the design system and highest-value workflows.

## 4. Workstream A — Parser coverage and diagnostics

**Priority: P0**

### A1. Build a parser support inventory

Create a machine-readable or test-backed inventory for every shipped plugin:

- Plugin ID and scanner name.
- Execution mode (CLI or native).
- Declared output format and parser type.
- Expected output version/range where known.
- Parser fixture availability.
- Last successful fixture validation.
- Known limitations and unsupported output variants.

The inventory must distinguish "binary installed" from "parser validated". A scanner being executable does not prove its output is correctly interpreted.

### A2. Add fixture-based parser regression tests

Store sanitized representative outputs under a stable fixture layout, for example:

```text
crates/core/tests/fixtures/parsers/
  nuclei/
    valid.jsonl
    multiple-findings.jsonl
    malformed-record.jsonl
    empty.jsonl
  nmap/
    valid.xml-or-text.txt
    no-findings.txt
  sqlmap/
    vulnerable.txt
    not-vulnerable.txt
```

Use the actual output formats declared by each plugin; the examples above are illustrative. Fixtures must not contain real credentials, tokens, session cookies, or customer data.

For each supported parser, test:

- Expected finding count and key fields.
- Severity and category mapping.
- URL/endpoint and proof extraction.
- Missing optional fields.
- Empty output and no-finding output.
- Malformed or truncated records.
- Multiple records where one record is malformed.
- Diagnostic lines that must not become findings.
- Duplicate records and static-rule overlap.
- Output-size and finding-count limits.

Where a parser currently fails the partial-record case, record the limitation and decide explicitly whether the correct behavior is fail-fast or retain-valid-records. Do not silently swallow parse failures.

### A3. Make parser diagnostics first-class

Return or persist structured parse diagnostics alongside findings. A diagnostic should include:

- Plugin ID and parser type.
- Error category (invalid JSON, missing mapped field, invalid severity, malformed line, output truncated, unsupported format).
- Record/line index when available.
- Safe, bounded message.
- Count of parsed, skipped, rejected, and truncated records.

Do not place secrets or unbounded raw output in diagnostic messages. Keep raw output access separately controlled.

### A4. Output format strategy

Continue to prefer structured output (JSON/JSONL/XML) where a scanner supports it. Add a parser type only when a real plugin requires it and tests demonstrate the need. Avoid adding a generic "guess everything" parser that turns arbitrary log lines into false-positive findings.

**Acceptance criteria**

- Every shipped CLI plugin has at least one sanitized fixture or a documented reason it cannot have one.
- Parser tests assert normalized fields, not merely that parsing returns successfully.
- Parser failures are visible to the operator and do not masquerade as a clean scan.
- The UI can distinguish "scan completed with parser warnings" from "scan completed with no findings".
- Parser tests run in CI without requiring external scanner binaries.

## 5. Workstream B — Finding model, provenance, and correlation

**Priority: P0**

### B1. Preserve source provenance

Every normalized finding should be traceable to the execution that produced it. Review the existing task/plugin fields and add only missing provenance. Candidate attributes:

- Task/run ID and plugin ID.
- Scanner binary name and detected version (when available).
- Parser type and manifest version/hash.
- Output artifact reference and byte/record offset where practical.
- First-seen and last-seen timestamps.
- Source record fingerprint.
- Whether the record came from a parser rule or a static rule.

Prefer references to bounded, access-controlled raw-output artifacts over copying large raw logs into every finding row. Define retention and deletion behavior for artifacts. Redact secrets before presenting evidence, while preserving the original artifact only where retention policy and access controls permit.

### B2. Separate independent dimensions

Do not collapse these into one status or score:

- **Severity:** impact classification from the scanner or normalized model.
- **Confidence:** how strongly the evidence supports the detection.
- **Verification state:** analyst workflow state.
- **Lifecycle state:** whether the issue is new, unchanged, fixed, regressed, or otherwise changed between scans.

Recommended verification states:

`needs_review`, `confirmed`, `false_positive`, `unable_to_verify`.

Use explicit transition rules and record who changed the state, when, and why. A scanner's severity or confidence must never automatically mark a finding as confirmed.

### B3. Improve finding identity and deduplication

The current parser deduplication key is severity + title + URL. That is useful for eliminating exact duplicates within one parse, but it is not a sufficient long-term identity across scanners or scans.

Introduce a versioned finding fingerprint based on available normalized attributes, such as:

- Canonical target/host.
- HTTP method and normalized endpoint.
- Parameter or affected component.
- Vulnerability class/CWE.
- Stable scanner rule ID or plugin-specific identifier.
- Relevant evidence signature.

Do not include volatile fields (timestamps, random request IDs, changing line numbers) in the stable identity. Do not merge findings solely because titles match. Preserve source observations when multiple scanners report the same underlying issue.

Use conservative matching: uncertain matches should be shown as possible duplicates for analyst review rather than silently merged.

### B4. Scan-to-scan lifecycle

For each comparison, record the matching method and confidence. Distinguish:

- New: no credible prior match.
- Unchanged: credible match with materially equivalent state.
- Improved: evidence or severity materially reduced, with a documented rule.
- Fixed: prior issue was not observed in a comparable assessment; label as "not observed" unless the verification process justifies "fixed".
- Regressed: previously absent/fixed issue is observed again.
- Inconclusive: scans are not comparable or evidence is insufficient.

**Acceptance criteria**

- Every finding can be traced to its task, plugin, and source evidence.
- Severity, confidence, verification, and lifecycle are separate fields/concepts.
- Fingerprint algorithm is versioned and covered by positive and negative matching tests.
- Cross-scanner correlation preserves individual source observations.
- Scan diff does not call an issue fixed merely because a later scan omitted it without recording comparability limits.

## 6. Workstream C — Report quality and trustworthiness

**Priority: P0**

SecuScan already supports multiple export formats. The objective is to improve report content, consistency, readability, and validation—not simply add more formats.

### C1. Define report profiles

1. **Executive summary** — assessment scope, date, overall risk summary, severity distribution, material risks, and prioritized actions.
2. **Technical assessment** — finding details, affected assets/endpoints, evidence, reproduction guidance, impact, remediation, references, and verification state.
3. **Machine-readable export** — stable JSON/SARIF with schema/version metadata and traceable source identifiers.

A compliance-oriented profile should only claim coverage against a framework when the mapping and assessment methodology are documented. A tag or CWE mapping alone is not proof of compliance.

### C2. Standardize finding detail

Where data exists, include:

- Stable finding reference.
- Title, severity, confidence, verification state.
- Affected asset, endpoint, method, parameter/component.
- Description and impact.
- Evidence with source scanner and collection timestamp.
- Reproduction steps appropriate to the authorized assessment.
- Remediation and references (CWE/CVE/OWASP as applicable).
- Analyst notes and state history.

Clearly label unavailable data instead of inventing values. Distinguish scanner-supplied evidence from analyst-added evidence.

### C3. Improve report navigation and presentation

- Table of contents and stable finding anchors.
- Summary charts/tables with counts that reconcile to the included findings.
- Severity filters reflected consistently across all formats.
- Page breaks and readable tables in PDF/DOCX.
- Consistent metadata and timestamps.
- Report generation warnings when findings or evidence were truncated.
- Clear scope and limitations section.
- Branding/project metadata configurable without allowing untrusted HTML injection.

### C4. Validate exports

Add tests for:

- HTML escaping of every user/scanner-controlled field.
- CSV formula-injection protection, including leading whitespace/control characters and quoted cells.
- JSON/SARIF schema validity.
- PDF/DOCX/XLSX generation with long values, Unicode, empty datasets, and large finding sets.
- Severity-filter consistency across all formats.
- Reconciliation between summary counts and detailed findings.
- Deterministic output where practical.

Treat scanner output as untrusted content in every report format.

**Acceptance criteria**

- Report profile selection changes content and emphasis, not underlying finding truth.
- Every report identifies its scope, run, generation time, and limitations.
- Summary counts reconcile with detailed findings.
- All supported formats have security and correctness regression tests.
- Reports never label unverified scanner output as confirmed vulnerabilities.

## 7. Workstream D — UI/UX and analyst workflow

**Priority: P1**

The repository already has the core pages. Improve the highest-value analyst journeys first rather than redesigning every page at once.

### D1. Establish design tokens and shared components

Define tokens for typography, spacing, layout, borders, surfaces, focus states, and semantic severity colors. Keep dark and light themes consistent. Reuse existing components where they meet the standard; avoid creating a parallel component library without need.

Shared patterns should cover:

- Page headers and action placement.
- Data tables, filtering, sorting, pagination.
- Severity and verification badges.
- Empty, loading, error, and partial-success states.
- Dialogs, forms, validation, and confirmation.
- Evidence/code/request viewers.
- Toasts and accessible feedback.

### D2. Prioritize these user journeys

1. **Dashboard:** explain current risk and recent activity without decorative or misleading metrics.
2. **Scan creation:** make scope, consent, scan intensity, and intrusive behavior explicit.
3. **Live scan:** show execution state, current tool, progress when known, parser warnings, and cancellation.
4. **Findings:** support useful filters, grouping, bulk triage with confirmation, and stable links.
5. **Finding detail:** organize overview, evidence, remediation, provenance, and history.
6. **Reports:** show profile, scope, filters, generation status, preview, and export.
7. **Plugin catalogue:** distinguish installed, available, enabled, and parser-validated states.

### D3. Accessibility and usability

- Keyboard-operable navigation and dialogs.
- Visible focus indicators.
- Semantic labels and accessible status announcements.
- Do not rely on color alone for severity/status.
- Responsive layouts for common desktop and laptop widths.
- Useful empty/error states with next actions.
- Preserve user filters and navigation state where appropriate.

**Acceptance criteria**

- Primary workflows are covered by component/integration tests.
- Shared components use the same tokens and status semantics.
- Critical actions have clear confirmation and error recovery.
- No key status is communicated by color alone.
- Usability review is performed against real workflows, not screenshots alone.

## 8. Workstream E — Local-first reliability and security

**Priority: P1; address critical defects immediately**

Local-first deployment changes exposure and operational assumptions; it does not make the application inherently risk-free. Prioritize realistic local threats and avoid adding cloud-only complexity without a requirement.

Review and test:

- Loopback binding defaults and explicit opt-in for network exposure.
- Host/Origin validation and browser-to-localhost request protections.
- Authentication requirements for sensitive local operations.
- Path validation and safe artifact access.
- Secret storage, key backup, rotation, and loss behavior.
- Process-tree termination on timeout/cancel (not only direct-child termination).
- Temporary directory permissions and cleanup.
- DNS resolution and connection-time destination enforcement, including redirects.
- Resource limits for scanner output, report generation, and concurrent jobs.
- SQLite backup, restore, migration, and file-permission behavior.
- Safe rendering of scanner-controlled data in the UI and exports.

For network policy, document the boundary between task-creation checks and the actual destination reached at connection time. Where a tool cannot enforce destination policy itself, state that limitation and use an appropriate wrapper or deny the unsupported mode.

**Acceptance criteria**

- Security tests cover local browser-origin abuse, path traversal, malicious output, process descendants, and destination changes.
- The default local setup is not exposed to the LAN unless explicitly configured.
- Cancellation and timeout leave no owned scanner descendants running.
- Backup/restore behavior for encrypted secrets is documented and tested.

## 9. Delivery plan

| Phase | Scope | Exit condition |
|---|---|---|
| 0 — Baseline | Inventory parsers, report formats, current UI journeys, and known gaps | Reviewed inventory and prioritized issues |
| 1 — Data quality | Parser fixtures, diagnostics, provenance, finding-state semantics | CI-backed parser coverage and traceable findings |
| 2 — Correlation | Versioned fingerprints, conservative deduplication, scan lifecycle | Positive/negative matching tests and explainable diffs |
| 3 — Reporting | Report profiles, evidence layout, format validation | Consistent, secure exports with reconciled counts |
| 4 — UX | Tokens/components and prioritized analyst journeys | Tested, accessible workflows |
| 5 — Reliability | Local threat tests, process cleanup, destination enforcement | Reproducible security regression tests |

Phases can overlap only when interfaces and acceptance criteria are agreed. Do not block parser/data correctness on a visual redesign.

## 10. Suggested implementation issue breakdown

Create separate issues/PRs rather than one broad change:

- [ ] Inventory parser support and scanner output fixtures.
- [ ] Add structured parser diagnostics and partial-output policy.
- [ ] Add raw-output artifact references and source provenance.
- [ ] Define finding verification-state transitions and audit history.
- [ ] Introduce versioned finding fingerprints and correlation tests.
- [ ] Make scan-diff matching explainable and conservative.
- [ ] Define executive and technical report profiles.
- [ ] Add cross-format report security and consistency tests.
- [ ] Establish UI design tokens and shared analyst components.
- [ ] Improve dashboard, findings, finding detail, and report journeys.
- [ ] Add local browser-origin, process-tree, and destination-enforcement regression tests.

## 11. Definition of done

This quality phase is complete when:

- Parser support is inventoried and fixture-tested for every supported CLI plugin.
- Parser warnings and truncation are visible and cannot be mistaken for a clean result.
- Findings preserve source provenance and distinguish severity, confidence, verification, and lifecycle.
- Deduplication and scan comparison are explainable and tested against false matches.
- Reports provide scope, evidence, limitations, remediation, and consistent counts.
- Report exports pass security and schema/correctness tests.
- Core analyst workflows are consistent, accessible, and regression-tested.
- Local-first security assumptions and limitations are documented and tested.
- CI runs the relevant tests without requiring live external targets.

## 12. Engineering principles

1. Prefer structured scanner output over heuristic text parsing.
2. Preserve raw evidence with explicit access and retention controls.
3. Never infer confirmation from scanner severity alone.
4. Prefer explainable, conservative correlation over aggressive deduplication.
5. Treat scanner output, filenames, URLs, and report fields as untrusted input.
6. Distinguish implemented behavior from proposed behavior in documentation and release notes.
7. Add scanners only when parsing, evidence quality, and maintenance are supportable.
8. Keep local-first defaults simple, explicit, and secure.
