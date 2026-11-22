-- Max-Parity Sprint 4 (issue #34): distributed execution — worker fleet.
-- Workers poll for claimed-able queued tasks and execute them out-of-process.
-- `claimed_by`/`claimed_at` are an atomic claim (NULL = unclaimed); the
-- API's orphan sweeper releases claims from workers whose heartbeat died.
ALTER TABLE tasks ADD COLUMN claimed_by TEXT;
ALTER TABLE tasks ADD COLUMN claimed_at TEXT;
CREATE INDEX idx_tasks_claimable ON tasks(status, claimed_by) WHERE status = 'queued';

-- Worker fleet registry: registration + heartbeat + capacity reporting.
CREATE TABLE workers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    tags          TEXT NOT NULL DEFAULT '[]',
    max_concurrent INTEGER NOT NULL DEFAULT 4,
    claimed_count INTEGER NOT NULL DEFAULT 0,
    last_heartbeat TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
