-- Max-Parity Sprint 2.4 (issue #15): finding provenance + deterministic
-- cross-scan identity.
--   plugin_version: the manifest version of the plugin that produced the
--     finding at observation time (defensible evidence requires knowing
--     WHICH scanner version made the claim).
--   fingerprint: sha256(plugin_id | target | url | category | title) — the
--     stable cross-scan identity used by the diff engine and provenance
--     display. Excludes proof/description (trivial output changes must not
--     change identity) and includes target+url (distinct endpoints never
--     falsely merge). NULL for rows created before migration; computed
--     lazily by the diff engine via fallback.
ALTER TABLE findings ADD COLUMN plugin_version TEXT;
ALTER TABLE findings ADD COLUMN fingerprint TEXT;
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
