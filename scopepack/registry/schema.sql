PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dataset_versions (
  id INTEGER PRIMARY KEY,
  version TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  row_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS field_catalog (
  field TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purposes (
  id INTEGER PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id INTEGER PRIMARY KEY,
  purpose_id INTEGER NOT NULL REFERENCES purposes(id),
  version INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  policy_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  UNIQUE(purpose_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_one_active
  ON policy_versions(purpose_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS policy_rules (
  policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id),
  field TEXT NOT NULL REFERENCES field_catalog(field),
  allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
  reason TEXT NOT NULL,
  PRIMARY KEY (policy_version_id, field)
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY,
  consumer_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  purpose_id INTEGER NOT NULL REFERENCES purposes(id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
  id INTEGER PRIMARY KEY,
  package_key TEXT NOT NULL UNIQUE,
  purpose_id INTEGER NOT NULL REFERENCES purposes(id),
  policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id),
  dataset_version_id INTEGER NOT NULL REFERENCES dataset_versions(id),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'building', 'ready', 'blocked', 'failed', 'retired')),
  allowed_fields TEXT NOT NULL,
  fields_hash TEXT NOT NULL,
  content_sha256 TEXT,
  size_bytes INTEGER,
  row_count INTEGER,
  artifact_path TEXT,
  manifest_json TEXT,
  signature TEXT,
  created_at TEXT NOT NULL,
  ready_at TEXT,
  retired_at TEXT,
  blocked_at TEXT,
  blocked_reason TEXT,
  failure_reason TEXT,
  retention_note TEXT NOT NULL DEFAULT '',
  build_attempts INTEGER NOT NULL DEFAULT 0,
  UNIQUE(purpose_id, policy_version_id, dataset_version_id)
);

CREATE INDEX IF NOT EXISTS idx_packages_purpose ON packages(purpose_id);
CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(status);

CREATE TABLE IF NOT EXISTS contracts (
  id INTEGER PRIMARY KEY,
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id),
  version INTEGER NOT NULL,
  purpose_id INTEGER NOT NULL REFERENCES purposes(id),
  package_id INTEGER NOT NULL REFERENCES packages(id),
  policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id),
  allowed_fields TEXT NOT NULL,
  disallowed_fields TEXT NOT NULL,
  fields_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'superseded', 'revoked')),
  change_kind TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  effective_at TEXT NOT NULL,
  superseded_at TEXT,
  renewal_key TEXT,
  UNIQUE(subscription_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_contracts_renewal_key
  ON contracts(subscription_id, renewal_key) WHERE renewal_key IS NOT NULL;

-- Idempotency keys for renewal retries.  Kept separately from contracts so a
-- no-op renewal (same policy, same fields) still records the retried key.
CREATE TABLE IF NOT EXISTS renewal_requests (
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id),
  renewal_key TEXT NOT NULL,
  contract_id INTEGER NOT NULL REFERENCES contracts(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY (subscription_id, renewal_key)
);

CREATE INDEX IF NOT EXISTS idx_contracts_subscription ON contracts(subscription_id, status);

CREATE TABLE IF NOT EXISTS build_jobs (
  id INTEGER PRIMARY KEY,
  package_id INTEGER NOT NULL UNIQUE REFERENCES packages(id),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'leased', 'done', 'failed', 'cancelled')),
  lease_owner TEXT,
  lease_token TEXT,
  lease_expires_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_build_jobs_status ON build_jobs(status, lease_expires_at);

CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY,
  grant_id TEXT NOT NULL UNIQUE,
  package_id INTEGER NOT NULL REFERENCES packages(id),
  contract_id INTEGER NOT NULL REFERENCES contracts(id),
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id),
  consumer_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_reason TEXT,
  node_id TEXT NOT NULL,
  issue_key TEXT
);

CREATE INDEX IF NOT EXISTS idx_grants_package ON grants(package_id);
CREATE INDEX IF NOT EXISTS idx_grants_subscription ON grants(subscription_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_issue_key
  ON grants(subscription_id, issue_key) WHERE issue_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS download_events (
  id INTEGER PRIMARY KEY,
  grant_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  event TEXT NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0,
  at TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_download_events_grant ON download_events(grant_id);

CREATE TABLE IF NOT EXISTS acks (
  id INTEGER PRIMARY KEY,
  ack_id TEXT NOT NULL UNIQUE,
  grant_id TEXT NOT NULL,
  package_id INTEGER NOT NULL REFERENCES packages(id),
  contract_id INTEGER NOT NULL REFERENCES contracts(id),
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id),
  consumer_id TEXT NOT NULL,
  node_id TEXT NOT NULL DEFAULT '',
  bytes INTEGER NOT NULL DEFAULT 0,
  reported_sha256 TEXT,
  classification TEXT NOT NULL,
  retained INTEGER NOT NULL DEFAULT 1,
  counts_current INTEGER NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_acks_grant ON acks(grant_id);
CREATE INDEX IF NOT EXISTS idx_acks_package ON acks(package_id);
CREATE INDEX IF NOT EXISTS idx_acks_subscription ON acks(subscription_id);

CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  last_seen TEXT,
  cache_bytes INTEGER NOT NULL DEFAULT 0,
  cached_packages INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_events(at);
