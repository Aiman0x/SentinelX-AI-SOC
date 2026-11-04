-- Tracks automatic triage of newly ingested alert/finding records.
CREATE TABLE IF NOT EXISTS monitoring_processed (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  record_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PROCESSING',
  attempts INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(org_id, record_id)
);
CREATE INDEX IF NOT EXISTS idx_monitoring_processed_status ON monitoring_processed(org_id, status, updated_at);
