-- Relevant v0.1.6 schema after migrations 020, 021, 022, 031, 070 and 071.
-- Source: pingdotgg/t3code tag v0.1.6 (2359643c); no real credentials.
CREATE TABLE effect_sql_migrations (migration_id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO effect_sql_migrations (migration_id,name) VALUES (76,'ProjectionProjectsPinArchive');
CREATE TABLE auth_sessions (
  session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, method TEXT NOT NULL,
  issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
  client_label TEXT, client_ip_address TEXT, client_user_agent TEXT,
  client_device_type TEXT NOT NULL DEFAULT 'unknown', client_os TEXT, client_browser TEXT,
  last_connected_at TEXT, scopes TEXT NOT NULL, client_surface TEXT, client_app_version TEXT
);
CREATE TABLE peer_environment_links (
  environment_id TEXT PRIMARY KEY, secret_name TEXT NOT NULL, label TEXT NOT NULL,
  urls_json TEXT NOT NULL, access TEXT NOT NULL, linked_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, last_reached_at TEXT, last_error TEXT,
  fenced INTEGER NOT NULL DEFAULT 0
);
