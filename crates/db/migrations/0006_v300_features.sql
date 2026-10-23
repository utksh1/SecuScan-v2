-- v3.0.0 — OOB callbacks, finding dedup/enrichment, notifications, scan groups,
--          wordlists, finding templates, asset import, audit log extensions.
--
-- Design notes:
-- * OOB callbacks are the backbone for blind-vuln detection (XSS/SSRF/XXE/SQLi).
--   Each handler gets a unique secret URL; hits correlate back via handler_id.
-- * Finding dedup groups link findings with the same (target, plugin_id, title)
--   so a status change on one propagates to all duplicates. The fp_memory table
--   remembers false-positive decisions per (target_fingerprint, finding_type)
--   so future scans auto-mark them.
-- * CVSS/EPSS/KEV enrichment is stored on the finding row itself (nullable
--   columns) so reports can render it without a join.
-- * Notifications are rule-based: triggers fire actions. Webhooks carry a
--   signed payload (HMAC-SHA256 with the workspace's notify_secret).
-- * Scan groups bundle tasks for one aggregated report.
-- * Wordlists are first-class: stored as files, referenced by id in scans.
-- * Finding templates are public, searchable manual-finding presets.

-- ---------------------------------------------------------------------------
-- 1. OOB callback infrastructure
-- ---------------------------------------------------------------------------
CREATE TABLE oob_handlers (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    -- 'http_logger' | 'xss_exploiter'
    kind         TEXT NOT NULL CHECK (kind IN ('http_logger', 'xss_exploiter')),
    -- capture config: {cookies, screenshot, keystrokes, html} for xss;
    -- {} for http_logger
    config_json  TEXT NOT NULL DEFAULT '{}',
    -- the secret path segment embedded in the callback URL
    -- e.g. handler with secret "a1b2c3d4" receives callbacks at /oob/a1b2c3d4
    secret       TEXT NOT NULL UNIQUE,
    -- TTL: handlers auto-expire after this many seconds (default 60 days)
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    -- count of callbacks received
    hit_count    INTEGER NOT NULL DEFAULT 0,
    last_hit_at  TEXT
);
CREATE INDEX idx_oob_handlers_workspace ON oob_handlers(workspace_id, created_at DESC);
CREATE INDEX idx_oob_handlers_secret ON oob_handlers(secret);

CREATE TABLE oob_hits (
    id           TEXT PRIMARY KEY,
    handler_id   TEXT NOT NULL REFERENCES oob_handlers(id) ON DELETE CASCADE,
    -- the task that induced this callback (NULL for manual payload testing)
    task_id      TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    -- captured request data (JSON): {source_ip, method, url, headers, body,
    -- user_agent, timestamp, extra (cookies/screenshot/keystrokes for xss)}
    payload_json TEXT NOT NULL,
    received_at  TEXT NOT NULL
);
CREATE INDEX idx_oob_hits_handler ON oob_hits(handler_id, received_at DESC);
CREATE INDEX idx_oob_hits_task ON oob_hits(task_id);

-- Per-scan OOB markers: every scan gets a unique marker (e.g. "ptt1a2b3c4d")
-- that's appended to payloads. When a callback arrives carrying the marker,
-- we correlate it back to the scan via this table.
ALTER TABLE tasks ADD COLUMN oob_marker TEXT;
CREATE INDEX idx_tasks_oob_marker ON tasks(oob_marker);

-- ---------------------------------------------------------------------------
-- 2. Finding dedup groups + lifecycle memory + enrichment
-- ---------------------------------------------------------------------------
-- Dedup group: findings with the same (workspace, plugin_id, normalized_title,
-- target_fingerprint) end up in the same group. Status changes propagate.
CREATE TABLE finding_groups (
    id                  TEXT PRIMARY KEY,
    workspace_id        TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    plugin_id           TEXT NOT NULL,
    -- normalized title (lowercased, trimmed, collapse whitespace)
    title_norm          TEXT NOT NULL,
    -- fingerprint of the target (hostname or IP or URL host)
    target_fingerprint  TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    UNIQUE(workspace_id, plugin_id, title_norm, target_fingerprint)
);
CREATE INDEX idx_fg_lookup ON finding_groups(workspace_id, plugin_id, title_norm, target_fingerprint);

ALTER TABLE findings ADD COLUMN group_id TEXT REFERENCES finding_groups(id) ON DELETE SET NULL;
CREATE INDEX idx_findings_group ON findings(group_id);

-- False-positive memory: once an analyst marks a (target_fingerprint,
-- plugin_id, title_norm) as FP, future findings matching it auto-mark FP.
CREATE TABLE fp_memory (
    id                  TEXT PRIMARY KEY,
    workspace_id        TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    plugin_id           TEXT NOT NULL,
    title_norm          TEXT NOT NULL,
    target_fingerprint  TEXT NOT NULL,
    decided_by          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    decided_at          TEXT NOT NULL,
    reason              TEXT,
    UNIQUE(workspace_id, plugin_id, title_norm, target_fingerprint)
);
CREATE INDEX idx_fp_memory_lookup ON fp_memory(workspace_id, plugin_id, title_norm, target_fingerprint);

-- CVSS/EPSS/KEV enrichment columns on findings.
ALTER TABLE findings ADD COLUMN cve          TEXT;
ALTER TABLE findings ADD COLUMN cvss_v3     REAL;
ALTER TABLE findings ADD COLUMN cvss_vector  TEXT;
ALTER TABLE findings ADD COLUMN epss_score   REAL;
ALTER TABLE findings ADD COLUMN epss_percentile REAL;
ALTER TABLE findings ADD COLUMN cisa_kev     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN cwe          TEXT;
ALTER TABLE findings ADD COLUMN owasp        TEXT;
-- 'certain' | 'uncertain' | NULL (NULL = not applicable, e.g. observations)
ALTER TABLE findings ADD COLUMN confidence   TEXT CHECK (confidence IS NULL OR confidence IN ('certain', 'uncertain'));
CREATE INDEX idx_findings_cve ON findings(cve);

-- ---------------------------------------------------------------------------
-- 3. Notifications engine
-- ---------------------------------------------------------------------------
CREATE TABLE notification_rules (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    -- JSON: {triggers: [{kind, conditions}], actions: [{kind, config}]}
    -- trigger kinds: vuln_found, scan_status, port_change, diff, weak_password
    -- action kinds: email, webhook, slack, teams, discord
    rules_json    TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT
);
CREATE INDEX idx_notify_workspace ON notification_rules(workspace_id, enabled);

-- Per-workspace notify secret for signing webhook payloads (HMAC-SHA256).
ALTER TABLE workspaces ADD COLUMN notify_secret TEXT;

-- Notification delivery log (for retry + audit).
CREATE TABLE notification_log (
    id            TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL REFERENCES notification_rules(id) ON DELETE CASCADE,
    task_id       TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    finding_id    TEXT REFERENCES findings(id) ON DELETE SET NULL,
    -- 'email' | 'webhook' | 'slack' | 'teams' | 'discord'
    channel       TEXT NOT NULL,
    -- 'sent' | 'failed' | 'retrying'
    status        TEXT NOT NULL DEFAULT 'sent',
    -- HTTP status code for webhook-type channels
    http_status   INTEGER,
    error         TEXT,
    payload_json  TEXT,
    sent_at       TEXT NOT NULL
);
CREATE INDEX idx_notify_log_rule ON notification_log(rule_id, sent_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Scan Groups
-- ---------------------------------------------------------------------------
CREATE TABLE scan_groups (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_scan_groups_workspace ON scan_groups(workspace_id, created_at DESC);

CREATE TABLE scan_group_members (
    scan_group_id TEXT NOT NULL REFERENCES scan_groups(id) ON DELETE CASCADE,
    task_id       TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_group_id, task_id)
);

-- ---------------------------------------------------------------------------
-- 5. Wordlists (first-class objects)
-- ---------------------------------------------------------------------------
CREATE TABLE wordlists (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    -- 'builtin' | 'user'
    source        TEXT NOT NULL DEFAULT 'user',
    -- file path on disk (under data_dir/wordlists/)
    file_path     TEXT NOT NULL,
    word_count    INTEGER NOT NULL DEFAULT 0,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    -- optional content-type hint: 'subdomains' | 'urls' | 'passwords' | 'generic'
    kind          TEXT NOT NULL DEFAULT 'generic',
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    UNIQUE(workspace_id, name)
);
CREATE INDEX idx_wordlists_workspace ON wordlists(workspace_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 6. Public finding templates
-- ---------------------------------------------------------------------------
CREATE TABLE finding_templates (
    id            TEXT PRIMARY KEY,
    -- 'public' | 'workspace'
    scope         TEXT NOT NULL DEFAULT 'public',
    workspace_id  TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description   TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    -- optional CWE / OWASP mapping
    cwe           TEXT,
    owasp         TEXT,
    created_by    TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_ft_scope ON finding_templates(scope, category);

-- ---------------------------------------------------------------------------
-- 7. Asset import tracking (bulk .txt / CIDR / AWS)
-- ---------------------------------------------------------------------------
-- We don't add a separate table; instead we track import jobs for audit.
CREATE TABLE asset_imports (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    -- 'txt' | 'cidr' | 'aws_iam'
    source        TEXT NOT NULL,
    -- raw input summary (file name + line count, or CIDR, or IAM role ARN)
    summary       TEXT NOT NULL,
    -- how many targets were created
    created_count INTEGER NOT NULL DEFAULT 0,
    -- how many were skipped (duplicates)
    skipped_count INTEGER NOT NULL DEFAULT 0,
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_asset_imports_workspace ON asset_imports(workspace_id, created_at DESC);
