-- Async report jobs (pentest-tools.com parity).
--
-- Model decisions:
-- * A report job renders one task's findings into a downloadable artifact.
--   Generation runs in the background so the HTTP request returns 202
--   immediately (`waiting` -> `in_progress` -> `finished` | `failed`),
--   matching the reference platform's async report lifecycle.
-- * The artifact lives on disk under the configured reports dir; `file_path`
--   is the on-disk location, `file_bytes` its size (also used as a download
--   sanity check). Rows without a file (failed jobs) are deletable metadata.
-- * `severity_filter` is a minimum-severity threshold (NULL = all findings).
-- * `webhook_url` + `webhook_secret`: when set, a signed callback is POSTed
--   after the job finishes. The secret is needed verbatim to compute the
--   HMAC-SHA256 signature, so it is stored as-is — self-hosted instances
--   should treat their database with the same care as their vault (see
--   SECURITY.md). It is never returned by the API.
-- * Deleting a task cascades to its report jobs; the API layer removes the
--   orphaned files.

CREATE TABLE report_jobs (
    id               TEXT PRIMARY KEY,
    task_id          TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    format           TEXT NOT NULL CHECK (format IN ('json','md','csv','html','sarif','pdf','docx','xlsx')),
    severity_filter  TEXT,
    status           TEXT NOT NULL CHECK (status IN ('waiting','in_progress','finished','failed')),
    error            TEXT,
    file_path        TEXT,
    file_bytes       INTEGER,
    webhook_url      TEXT,
    webhook_secret   TEXT,
    webhook_attempts INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    started_at       TEXT,
    finished_at      TEXT
);

CREATE INDEX idx_report_jobs_user ON report_jobs(user_id, created_at DESC);
CREATE INDEX idx_report_jobs_task ON report_jobs(task_id);
