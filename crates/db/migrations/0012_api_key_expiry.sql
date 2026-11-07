-- Max-Parity Sprint 1.3 (task 3.3): API keys can carry an optional expiry
-- (ISO 8601). NULL = no expiry (backwards compatible with existing keys).
ALTER TABLE api_keys ADD COLUMN expires_at TEXT;
