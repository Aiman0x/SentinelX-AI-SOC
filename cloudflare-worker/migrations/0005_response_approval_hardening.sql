-- Approval actor columns are declared in 0002_soc_data.sql so this migration
-- is safe for the existing production D1 schema as well as a fresh database.
-- The production database already contains these columns; only ensure the index exists.
CREATE INDEX IF NOT EXISTS idx_approvals_org_lifecycle ON approvals(org_id,lifecycle_state,expires_at);
