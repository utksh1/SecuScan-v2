-- Max-Parity Sprint 2.2 (issue #25): named schedule frequencies.
-- frequency: NULL = legacy interval_seconds behavior | hourly | daily |
-- weekly | monthly | quarterly | once. anchor_time = 'HH:MM' local time in
-- `tz` (IANA name, default UTC); monthly/quarterly clamp to month end.
ALTER TABLE schedules ADD COLUMN frequency TEXT;
ALTER TABLE schedules ADD COLUMN anchor_time TEXT;
ALTER TABLE schedules ADD COLUMN tz TEXT;
