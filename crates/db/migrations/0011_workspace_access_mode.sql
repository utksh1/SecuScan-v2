-- Existing single-team workspaces remain shared for compatibility.
-- Workspaces created by v3.2+ default to private with explicit membership.
ALTER TABLE workspaces ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'shared'
    CHECK (access_mode IN ('shared', 'private'));

-- Backfill owners of existing workspaces for a consistent membership model.
INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role, added_at, added_by)
SELECT w.id, w.created_by, 'owner', w.created_at, w.created_by
FROM workspaces w JOIN users u ON u.id = w.created_by;

CREATE INDEX idx_workspaces_visibility ON workspaces(access_mode, created_by);

-- A workflow template is global, but each execution belongs to its
-- initiating user and selected workspace (never expose history by template ID).
ALTER TABLE workflow_runs ADD COLUMN created_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE workflow_runs ADD COLUMN workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL;

-- Preserve attribution for historical runs with tasks; fall back to the
-- template creator for old empty runs.
UPDATE workflow_runs SET created_by = COALESCE(
    (SELECT t.user_id FROM tasks t WHERE t.workflow_run_id = workflow_runs.id LIMIT 1),
    (SELECT wf.created_by FROM workflows wf WHERE wf.id = workflow_runs.workflow_id)
);
UPDATE workflow_runs SET workspace_id = (
    SELECT t.workspace_id FROM tasks t
    WHERE t.workflow_run_id = workflow_runs.id AND t.workspace_id IS NOT NULL LIMIT 1
);
CREATE INDEX idx_workflow_run_scope ON workflow_runs(workspace_id, created_by);
