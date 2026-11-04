-- Durable normalized security event store. Tenant identity is resolved before queueing.
CREATE TABLE IF NOT EXISTS security_events (
 id TEXT PRIMARY KEY,
 org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 event_id TEXT NOT NULL,
 dedup_key TEXT NOT NULL,
 source TEXT NOT NULL,
 collector_id TEXT,
 event_type TEXT NOT NULL,
 severity TEXT NOT NULL DEFAULT 'unknown' CHECK (severity IN ('critical','high','medium','low','info','unknown')),
 observed_at TEXT NOT NULL,
 received_at TEXT NOT NULL,
 host TEXT,
 source_ip TEXT,
 destination_ip TEXT,
 username TEXT,
 message TEXT NOT NULL DEFAULT '',
 normalized_json TEXT NOT NULL,
 raw_json TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(org_id,dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_security_events_org_received ON security_events(org_id,received_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_org_source ON security_events(org_id,source,received_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_org_severity ON security_events(org_id,severity,received_at DESC);
