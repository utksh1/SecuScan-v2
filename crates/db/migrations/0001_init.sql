-- SecuScan v2 initial schema

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'scanner', 'viewer')),
    created_at    TEXT NOT NULL
);

CREATE TABLE refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix);

CREATE TABLE plugin_states (
    plugin_id TEXT PRIMARY KEY,
    enabled   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE tasks (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plugin_id        TEXT NOT NULL,
    plugin_name      TEXT NOT NULL,
    target           TEXT,
    status           TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    inputs_json      TEXT NOT NULL,
    options_json     TEXT NOT NULL DEFAULT '{}',
    exit_code        INTEGER,
    error            TEXT,
    stats_json       TEXT,
    output           TEXT,
    output_truncated INTEGER NOT NULL DEFAULT 0,
    workflow_run_id  TEXT,
    created_at       TEXT NOT NULL,
    started_at       TEXT,
    finished_at      TEXT
);
CREATE INDEX idx_tasks_user ON tasks(user_id, created_at DESC);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_workflow_run ON tasks(workflow_run_id);

CREATE TABLE task_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id       TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    ts            TEXT NOT NULL,
    level         TEXT NOT NULL,
    payload_json  TEXT NOT NULL
);
CREATE INDEX idx_task_events_task ON task_events(task_id, id);

CREATE TABLE findings (
    id              TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    plugin_id       TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    kind            TEXT NOT NULL CHECK (kind IN ('observation', 'suspected_issue', 'validated_issue')),
    analyst_status  TEXT NOT NULL DEFAULT 'new'
                    CHECK (analyst_status IN ('new', 'confirmed', 'needs_review', 'false_positive', 'accepted_risk', 'fixed')),
    category        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    proof           TEXT NOT NULL DEFAULT '',
    url             TEXT,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_findings_task ON findings(task_id, severity);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE workflows (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    steps_json  TEXT NOT NULL,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    updated_at  TEXT
);

CREATE TABLE workflow_runs (
    id            TEXT PRIMARY KEY,
    workflow_id   TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    status        TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    task_ids_json TEXT NOT NULL DEFAULT '[]',
    error         TEXT,
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX idx_workflow_runs_workflow ON workflow_runs(workflow_id, created_at DESC);

CREATE TABLE policy_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    user_id   TEXT,
    plugin_id TEXT NOT NULL,
    target    TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    layer     TEXT NOT NULL,
    pattern   TEXT NOT NULL,
    reason    TEXT NOT NULL
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
