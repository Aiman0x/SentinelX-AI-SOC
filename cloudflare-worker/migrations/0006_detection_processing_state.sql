ALTER TABLE security_events ADD COLUMN detection_processed_at TEXT;
CREATE INDEX IF NOT EXISTS idx_security_events_detection_pending ON security_events(detection_processed_at,received_at);