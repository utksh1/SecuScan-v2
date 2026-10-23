-- Recurring scan schedules (pentest-tools.com parity: "schedule scans").
--
-- Model decisions:
-- * A schedule stores the full task admission payload (plugin, inputs,
--   preset, workspace) plus an interval. The scheduler worker launches a
--   normal task from it every time the interval elapses, so every run goes
--   through the same validation pipeline (plugin availability, enabled
--   flags, capability denials, target policy) as a manual start — a policy
--   tightened after the schedule was created stops future runs.
-- * Interval-based, not cron-expression-based: `interval_seconds` with a
--   5-minute floor (checked at admission AND in the DB) keeps the engine
--   trivially correct and testable; missed occurrences are skipped, not
--   replayed (next_run_at is always re-anchored to "now + interval").
-- * `next_run_at` / `last_run_at` are RFC 3339 strings like every other
--   timestamp; the due query compares them lexically (fixed-width format).
-- * `target` is denormalized from the normalized inputs (the field named
--   `target` or `url`) for display; it is recomputed whenever inputs change.
-- * `last_task_id` links to the most recent launched task for one-click
--   jump; `last_error` records the admission failure of the most recent
--   attempt (cleared on the next success). Failures never disable the
--   schedule — the next interval retries.
-- * Overlap rule: if the previous run of a schedule is still queued/running
--   when the next one is due, the occurrence is skipped (the task keeps a
--   `schedule_id` so this check is a single indexed EXISTS).
-- * Deleting a schedule nulls `tasks.schedule_id` (ON DELETE SET NULL):
--   scan history survives; only future automation stops. Deleting a user
--   cascades to their schedules; deleting a workspace detaches them.

CREATE TABLE schedules (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id     TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
    name             TEXT NOT NULL,
    plugin_id        TEXT NOT NULL,
    inputs_json      TEXT NOT NULL DEFAULT '{}',
    preset           TEXT,
    target           TEXT,
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds BETWEEN 300 AND 31536000),
    enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    next_run_at      TEXT NOT NULL,
    last_run_at      TEXT,
    last_task_id     TEXT,
    last_error       TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT
);

CREATE INDEX idx_schedules_due ON schedules(enabled, next_run_at);
CREATE INDEX idx_schedules_user ON schedules(user_id);

-- Tasks remember which schedule launched them (overlap check + run history).
ALTER TABLE tasks ADD COLUMN schedule_id TEXT REFERENCES schedules(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_schedule ON tasks(schedule_id);
