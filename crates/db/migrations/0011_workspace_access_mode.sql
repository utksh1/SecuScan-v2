-- Existing single-team workspaces remain shared for compatibility.
-- Workspaces created by v3.2+ default to private with explicit membership.
ALTER TABLE workspaces ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'shared'
    CHECK (access_mode IN ('shared', 'private'));

-- Backfill owners of existing workspaces for a consistent membership model.
INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role, added_at, added_by)
SELECT w.id, w.created_by, 'owner', w.created_at, w.created_by
FROM workspaces w JOIN users u ON u.id = w.created_by;

CREATE INDEX idx_workspaces_visibility ON workspaces(access_mode, created_by);
