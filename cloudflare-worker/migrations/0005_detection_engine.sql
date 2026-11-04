-- Detection, correlation and evidence engine. All records are tenant scoped.
CREATE TABLE IF NOT EXISTS detection_rules (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 rule_key TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
 confidence INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 1 AND 100),
 rule_type TEXT NOT NULL DEFAULT 'builtin' CHECK(rule_type IN ('builtin','sigma')),
 sigma_yaml TEXT, definition_json TEXT NOT NULL DEFAULT '{}',
 mitre_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(org_id,rule_key)
);
CREATE TABLE IF NOT EXISTS security_incidents (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 incident_key TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
 confidence INTEGER NOT NULL CHECK(confidence BETWEEN 1 AND 100),
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','resolved','false_positive')),
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
 host TEXT, username TEXT, source_ip TEXT, mitre_json TEXT NOT NULL DEFAULT '[]',
 detection_json TEXT NOT NULL DEFAULT '{}', evidence_count INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(org_id,incident_key)
);
CREATE TABLE IF NOT EXISTS incident_events (
 org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
 event_row_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
 rule_key TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 PRIMARY KEY(org_id,incident_id,event_row_id,rule_key)
);
CREATE TABLE IF NOT EXISTS evidence_records (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 incident_id TEXT NOT NULL REFERENCES security_incidents(id) ON DELETE CASCADE,
 event_row_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
 rule_key TEXT NOT NULL, evidence_type TEXT NOT NULL, captured_at TEXT NOT NULL,
 sha256 TEXT NOT NULL, payload_json TEXT NOT NULL,
 UNIQUE(org_id,incident_id,event_row_id,rule_key)
);
CREATE INDEX IF NOT EXISTS idx_detection_rules_org_enabled ON detection_rules(org_id,enabled);
CREATE INDEX IF NOT EXISTS idx_incidents_org_updated ON security_incidents(org_id,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_events_org_incident ON incident_events(org_id,incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_org_incident ON evidence_records(org_id,incident_id,captured_at);
