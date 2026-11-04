-- Platform-wide AI model configuration is managed only by explicit platform admins.
CREATE TABLE IF NOT EXISTS platform_admins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- Bootstrap existing workspace owner(s) as initial platform administrators.
-- This does not automatically promote future tenant owners.
INSERT OR IGNORE INTO platform_admins(user_id)
SELECT DISTINCT user_id FROM organization_memberships WHERE role='owner';
