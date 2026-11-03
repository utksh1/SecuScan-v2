-- One-time, server-validated authorizations for scans initiated by MCP agents.
-- The raw secret is never stored; consumption is atomic and auditable.
CREATE TABLE mcp_scan_approvals (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    approved_by TEXT NOT NULL REFERENCES users(id),
    issued_to_user_id TEXT NOT NULL REFERENCES users(id),
    request_hash TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    target TEXT NOT NULL,
    workspace_id TEXT,
    created_at TEXT NOT NULL,
    expires_at_epoch INTEGER NOT NULL,
    consumed_at TEXT,
    task_id TEXT
);

CREATE INDEX idx_mcp_approvals_actor
    ON mcp_scan_approvals(issued_to_user_id, created_at);
