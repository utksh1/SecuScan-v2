-- v2.6.0 — Pentest Robots, Attack Surface, Auth Profiles, Collaboration, Branding
--
-- Design notes:
-- * Robots are DAGs of nodes (Tool/Filter/Extractor/Reducer). The node graph
--   is stored as JSON so the runtime can interpret it without schema migrations.
-- * Attack Surface is a *materialised view* of scan outputs — rows are
--   upserted by the runtime whenever a finding carries asset-like metadata
--   (ip/hostname/port/service). We don't redefine scans; we re-derive assets.
-- * Auth profiles are reusable across scans. The runtime injects the chosen
--   profile into web plugins via env / inputs (`SECUSCAN_AUTH_PROFILE_ID`).
-- * Workspace members + finding comments enable collaboration. Comments are
--   per-finding, ordered; @mentions are stored as plain text in body and a
--   separate `mentions` table indexes user_id for fast "my mentions" queries.
-- * Branding is a single per-instance row (logo bytes, colours, footer text).
--   The PDF/DOCX renderers pick it up automatically.

-- ---------------------------------------------------------------------------
-- 1. Pentest Robots
-- ---------------------------------------------------------------------------
CREATE TABLE robots (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    -- JSON DAG: [{id, kind: tool|filter|extractor|reducer, ...}]
    nodes_json   TEXT NOT NULL,
    -- JSON edges: [{from, to}]
    edges_json   TEXT NOT NULL DEFAULT '[]',
    -- 'builtin' robots ship with the product and can't be deleted.
    source       TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'builtin')),
    created_by   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    updated_at   TEXT
);
CREATE INDEX idx_robots_creator ON robots(created_by, created_at DESC);

CREATE TABLE robot_runs (
    id          TEXT PRIMARY KEY,
    robot_id    TEXT NOT NULL REFERENCES robots(id) ON DELETE CASCADE,
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
    status      TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled'))
                DEFAULT 'queued',
    -- snapshot of node states: {node_id: {status, task_ids[], counts, error}}
    state_json  TEXT NOT NULL DEFAULT '{}',
    -- targets the run started from (JSON array of strings)
    targets_json TEXT NOT NULL DEFAULT '[]',
    error       TEXT,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX idx_robot_runs_robot ON robot_runs(robot_id, created_at DESC);
CREATE INDEX idx_robot_runs_status ON robot_runs(status);

ALTER TABLE tasks ADD COLUMN robot_run_id TEXT REFERENCES robot_runs(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_robot_run ON tasks(robot_run_id);

-- ---------------------------------------------------------------------------
-- 2. Attack Surface — materialised asset inventory
-- ---------------------------------------------------------------------------
CREATE TABLE attack_surface_assets (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    -- asset identity: one of hostname/ip_address/url is set; the others are
    -- populated opportunistically (e.g. url implies hostname).
    hostname     TEXT,
    ip_address   TEXT,
    url          TEXT,
    -- canonical key used for dedup: 'host:example.com' / 'ip:1.2.3.4' / 'url:...'
    asset_key    TEXT NOT NULL UNIQUE,
    -- aggregated metadata (JSON, appended by each contributing scan)
    -- {os, services: [{port, proto, product, version}], technologies: [],
    --  screenshots: [], risks: [], last_seen, last_scan_id}
    metadata_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_asa_workspace ON attack_surface_assets(workspace_id, last_seen_at DESC);
CREATE INDEX idx_asa_host ON attack_surface_assets(hostname);
CREATE INDEX idx_asa_ip ON attack_surface_assets(ip_address);

-- ---------------------------------------------------------------------------
-- 3. Authentication profiles (reusable across scans)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_profiles (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    -- 'cookie' | 'header' | 'form' | 'recorded'
    method       TEXT NOT NULL CHECK (method IN ('cookie','header','form','recorded')),
    -- JSON blob, method-specific. For 'cookie': {cookies: [{name,value}]}
    -- For 'header': {headers: [{name,value}]}  For 'form': {login_url, username,
    -- password, username_selector, password_selector, submit_selector}
    -- For 'recorded': {steps: [{action, target, value}]}
    config_json  TEXT NOT NULL DEFAULT '{}',
    -- Encrypted at rest with SECUSCAN_AUTH_PROFILE_KEY (best-effort).
    notes        TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    updated_at   TEXT
);
CREATE INDEX idx_auth_profiles_workspace ON auth_profiles(workspace_id, created_at DESC);

-- Tasks may reference an auth profile; the runtime injects it.
ALTER TABLE tasks ADD COLUMN auth_profile_id TEXT REFERENCES auth_profiles(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_auth_profile ON tasks(auth_profile_id);

-- ---------------------------------------------------------------------------
-- 4. Collaboration — workspace members + finding comments
-- ---------------------------------------------------------------------------
CREATE TABLE workspace_members (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('owner','editor','viewer'))
                 DEFAULT 'viewer',
    added_at     TEXT NOT NULL,
    added_by     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX idx_wsm_user ON workspace_members(user_id);

CREATE TABLE finding_comments (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body        TEXT NOT NULL,
    -- 'comment' | 'status_change' | 'mention'. status_change rows are
    -- auto-generated when an analyst moves a finding between statuses; their
    -- body is the human-readable transition (e.g. "moved from new to confirmed").
    kind        TEXT NOT NULL DEFAULT 'comment'
                CHECK (kind IN ('comment','status_change','mention')),
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_fc_finding ON finding_comments(finding_id, created_at);
CREATE INDEX idx_fc_author ON finding_comments(author_id, created_at DESC);

CREATE TABLE mentions (
    id          TEXT PRIMARY KEY,
    comment_id  TEXT NOT NULL REFERENCES finding_comments(id) ON DELETE CASCADE,
    mentioned_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    workspace_id TEXT,
    read_at     TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_mentions_user ON mentions(mentioned_user_id, read_at, created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Branding — single per-instance row
-- ---------------------------------------------------------------------------
CREATE TABLE branding (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    org_name      TEXT NOT NULL DEFAULT 'SecuScan',
    -- logo bytes (PNG, <= 256KB). NULL = use default.
    logo_png      BLOB,
    -- hex colour codes (no leading #)
    primary_color TEXT NOT NULL DEFAULT '0F172A',
    accent_color  TEXT NOT NULL DEFAULT '2563EB',
    -- footer text shown on every report page (markdown allowed, <= 500 chars)
    footer_text   TEXT NOT NULL DEFAULT 'Generated by SecuScan v2 — local-first security scanning',
    updated_at    TEXT NOT NULL,
    updated_by    TEXT REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO branding (id, org_name, primary_color, accent_color, footer_text, updated_at)
VALUES (1, 'SecuScan', '0F172A', '2563EB',
        'Generated by SecuScan v2 — local-first security scanning',
        strftime('%Y-%m-%dT%H:%M:%SZ','now'));
