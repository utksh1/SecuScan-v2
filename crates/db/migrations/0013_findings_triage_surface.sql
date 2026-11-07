-- Max-Parity Sprint 2.1 (issue #24): analyst-grade triage surface.
-- severity_override wins over the scanner-reported severity in reports/UI;
-- severity_original freezes the scanner value on first override so the
-- override is resettable. risk_level/verified extend the triage vocabulary;
-- triage_reason/by/at record the last triage decision (audit).
ALTER TABLE findings ADD COLUMN severity_override TEXT;
ALTER TABLE findings ADD COLUMN severity_original TEXT;
ALTER TABLE findings ADD COLUMN risk_level TEXT;
ALTER TABLE findings ADD COLUMN verified INTEGER;
ALTER TABLE findings ADD COLUMN triage_reason TEXT;
ALTER TABLE findings ADD COLUMN triage_by TEXT;
ALTER TABLE findings ADD COLUMN triage_at TEXT;
