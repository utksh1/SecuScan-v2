-- Restricted API keys for MCP agents. Existing keys remain full-access.
-- New keys can use the approved-scan API but cannot directly invoke
-- privileged scan/mutation routes, regardless of the MCP client implementation.
ALTER TABLE api_keys
    ADD COLUMN scope TEXT NOT NULL DEFAULT 'full'
    CHECK (scope IN ('full', 'mcp_scan'));

-- The admin who issued the scoped credential (legacy keys have NULL).
ALTER TABLE api_keys ADD COLUMN issued_by TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_api_keys_scope ON api_keys(scope, user_id, revoked_at);
