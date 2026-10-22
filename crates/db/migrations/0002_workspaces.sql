-- Workspaces + first-class targets (pentest-tools.com parity).
--
-- Model decisions:
-- * Workspaces are visible to every authenticated user (single-team
--   self-hosted instance). Tasks keep `user_id` for attribution and the
--   existing per-user isolation is preserved; the workspace is a grouping
--   layer on top.
-- * `tasks.workspace_id` is nullable: NULL means the synthetic "Personal"
--   workspace (pre-workspace tasks and quick ad-hoc scans live there), so
--   the feature is fully backward compatible.
-- * Deleting a workspace keeps its tasks (ON DELETE SET NULL moves them to
--   Personal) but removes its registered targets (CASCADE) — targets have
--   no meaning outside their workspace.

CREATE TABLE workspaces (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    updated_at  TEXT
);

CREATE TABLE targets (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('hostname', 'ip_address', 'url')),
    description  TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    UNIQUE(workspace_id, name)
);
CREATE INDEX idx_targets_workspace ON targets(workspace_id, created_at DESC);

ALTER TABLE tasks ADD COLUMN workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_workspace ON tasks(workspace_id);
