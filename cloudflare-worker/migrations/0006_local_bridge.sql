-- Outbound-only local bridge enrollment and short-lived read-only task queue.
ALTER TABLE host_collectors ADD COLUMN bridge_enabled INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_host_collectors_bridge ON host_collectors(org_id, bridge_enabled, last_seen_at);
CREATE TABLE IF NOT EXISTS bridge_tasks (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  collector_id TEXT NOT NULL REFERENCES host_collectors(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','claimed','completed','failed','expired')),
  result_json TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  claimed_at TEXT,
  completed_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bridge_tasks_poll ON bridge_tasks(collector_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_bridge_tasks_org ON bridge_tasks(org_id,created_at);
