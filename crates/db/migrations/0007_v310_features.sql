-- v3.1.0 — Sniper Auto-Exploiter, People Hunter support, VPN profiles.
--
-- Design notes:
-- * Sniper runs are tracked like robot runs: a chain of tasks derived from a
--   source finding. Each step maps a finding category to an exploit plugin.
-- * VPN profiles store the raw .ovpn config text (encrypted at rest via the
--   existing auth-profile key when set). Status transitions are tracked so
--   the UI can show connected/connecting/error states.
-- * People Hunter needs no schema — it is a native scanner emitting findings.

-- ---------------------------------------------------------------------------
-- 1. Sniper Auto-Exploiter
-- ---------------------------------------------------------------------------
CREATE TABLE sniper_runs (
    id            TEXT PRIMARY KEY,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    workspace_id  TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
    -- finding category snapshot at launch time
    category      TEXT NOT NULL,
    target        TEXT,
    status        TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled'))
                  DEFAULT 'queued',
    -- snapshot of step states: [{step, plugin_id, task_id, status, findings_count}]
    state_json    TEXT NOT NULL DEFAULT '[]',
    -- final proof extracted from the chain (markdown)
    proof         TEXT,
    -- whether the chain produced a validated exploitation
    outcome       TEXT CHECK (outcome IS NULL OR outcome IN ('proven', 'not_proven', 'inconclusive')),
    error         TEXT,
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX idx_sniper_runs_finding ON sniper_runs(finding_id, created_at DESC);
CREATE INDEX idx_sniper_runs_status ON sniper_runs(status);

ALTER TABLE tasks ADD COLUMN sniper_run_id TEXT REFERENCES sniper_runs(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_sniper_run ON tasks(sniper_run_id);

-- ---------------------------------------------------------------------------
-- 2. VPN profiles (OpenVPN)
-- ---------------------------------------------------------------------------
CREATE TABLE vpn_profiles (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    -- raw .ovpn config text (may embed certs; treat as secret)
    config_text   TEXT NOT NULL,
    -- 'disconnected' | 'connecting' | 'connected' | 'error'
    status        TEXT NOT NULL DEFAULT 'disconnected',
    -- error message from the last connect attempt
    last_error    TEXT,
    -- OS process id of the openvpn daemon while connected
    process_id    INTEGER,
    -- the tun interface name once connected (e.g. tun0)
    interface     TEXT,
    -- when the tunnel last transitioned to connected
    connected_at  TEXT,
    created_by    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT
);
CREATE INDEX idx_vpn_profiles_status ON vpn_profiles(status);

-- Workspaces can pin a VPN profile: scans in that workspace route through
-- the tunnel while it is connected.
ALTER TABLE workspaces ADD COLUMN vpn_profile_id TEXT REFERENCES vpn_profiles(id) ON DELETE SET NULL;
