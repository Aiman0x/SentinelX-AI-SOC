-- Per-organization host collectors. Tokens are stored only as SHA-256 hashes.
-- Use org_id consistently with the Worker data-access layer and SOC schema.
CREATE TABLE IF NOT EXISTS host_collectors (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('windows','linux','macos','other')),
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_seen_at TEXT,
  revoked_at TEXT,
  last_ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_host_collectors_org ON host_collectors(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_host_collectors_token ON host_collectors(token_hash);
