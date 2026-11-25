CREATE TABLE IF NOT EXISTS site_content (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  payload TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS content_revisions (
  revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_content_revisions_created_at
  ON content_revisions(created_at DESC);

CREATE TABLE IF NOT EXISTS login_attempts (
  attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_created
  ON login_attempts(ip_hash, created_at DESC);
