-- Max-Parity Sprint 2.2 (issue #25): honest terminal-state vocabulary
-- without rebuilding the tasks CHECK constraint. `status` keeps the 5-state
-- vocabulary (constraint-compatible); `status_detail` carries the precise
-- reason: timed_out | max_scan_time_reached | auth_failed | oob_disabled |
-- cancelled_before_start | ... (NULL for plain outcomes).
ALTER TABLE tasks ADD COLUMN status_detail TEXT;
