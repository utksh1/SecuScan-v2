-- v3.1.1 — VPN-aware scanning.
--
-- Tasks remember which VPN profile they were admitted under: workspaces
-- pinned to a VPN profile require the tunnel to be up (or auto-connectable)
-- before any task is admitted, and the task row records the profile that
-- guaranteed the route. This is the audit trail for "this scan ran through
-- the corporate tunnel".

ALTER TABLE tasks ADD COLUMN vpn_profile_id TEXT REFERENCES vpn_profiles(id) ON DELETE SET NULL;
CREATE INDEX idx_tasks_vpn_profile ON tasks(vpn_profile_id);
