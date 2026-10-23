-- 0007_access: requests, decisions, grants, access sessions, SSH connections/channels and the timeline (WP09, PLAN §5).

-- +goose Up
CREATE TABLE access_requests (
  id                   TEXT PRIMARY KEY,
  agent_id             TEXT NOT NULL REFERENCES agents (id),
  agent_key_id         TEXT NOT NULL REFERENCES agent_keys (id),
  server_id            TEXT NOT NULL REFERENCES servers (id),
  role_id              TEXT NOT NULL REFERENCES server_roles (id),
  reason_enc           BLOB,
  requested_duration_s INTEGER NOT NULL CHECK (requested_duration_s > 0),
  state                TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'canceled')),
  state_reason         TEXT,
  idempotency_key      TEXT,
  policy_version       INTEGER NOT NULL,
  created_at           INTEGER NOT NULL,
  expires_at           INTEGER NOT NULL,
  decided_at           INTEGER,
  updated_at           INTEGER NOT NULL,
  UNIQUE (agent_id, idempotency_key)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_req_pending ON access_requests (agent_id, server_id, role_id) WHERE state = 'pending';
CREATE INDEX ix_req_state_exp ON access_requests (state, expires_at);
CREATE INDEX ix_req_agent_created ON access_requests (agent_id, created_at);
CREATE INDEX ix_req_created ON access_requests (created_at);

CREATE TABLE approval_decisions (
  id                  TEXT PRIMARY KEY,
  request_id          TEXT NOT NULL UNIQUE REFERENCES access_requests (id),
  outcome             TEXT NOT NULL CHECK (outcome IN ('approved', 'denied')),
  actor_type          TEXT NOT NULL CHECK (actor_type IN ('operator', 'policy')),
  actor_id            TEXT NOT NULL,
  channel             TEXT NOT NULL CHECK (channel IN ('web', 'slack', 'telegram', 'policy', 'api')),
  approved_duration_s INTEGER,
  comment_enc         BLOB,
  policy_version      INTEGER NOT NULL,
  approver_rule_id    TEXT,
  idempotency_key     TEXT,
  decided_at          INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE grants (
  id                TEXT PRIMARY KEY,
  request_id        TEXT NOT NULL UNIQUE REFERENCES access_requests (id),
  decision_id       TEXT NOT NULL UNIQUE REFERENCES approval_decisions (id),
  agent_id          TEXT NOT NULL REFERENCES agents (id),
  server_id         TEXT NOT NULL REFERENCES servers (id),
  role_id           TEXT NOT NULL REFERENCES server_roles (id),
  remote_user       TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  policy_version    INTEGER NOT NULL,
  starts_at         INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  state             TEXT NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
  ended_at          INTEGER,
  end_reason        TEXT,
  revoked_by        TEXT,
  updated_at        INTEGER NOT NULL,
  CHECK (expires_at > starts_at)
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_grant_lookup ON grants (agent_id, server_id, role_id, state, expires_at);
CREATE INDEX ix_grant_active_exp ON grants (state, expires_at);
CREATE INDEX ix_grant_updated ON grants (updated_at);

CREATE TABLE access_sessions (
  id              TEXT PRIMARY KEY,
  grant_id        TEXT NOT NULL UNIQUE REFERENCES grants (id),
  state           TEXT NOT NULL CHECK (state IN ('open', 'closing', 'closed')),
  seq_reserved    INTEGER NOT NULL DEFAULT 0,
  opened_at       INTEGER NOT NULL,
  closed_at       INTEGER,
  close_reason    TEXT,
  retention_class TEXT NOT NULL,
  delete_after    INTEGER
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_sessions_state ON access_sessions (state, opened_at);

CREATE TABLE ssh_connections (
  id             TEXT PRIMARY KEY,
  agent_id       TEXT NOT NULL REFERENCES agents (id),
  agent_key_id   TEXT NOT NULL REFERENCES agent_keys (id),
  client_user    TEXT NOT NULL,
  client_version TEXT NOT NULL,
  source_ip      TEXT NOT NULL,
  state          TEXT NOT NULL CHECK (state IN ('open', 'closed', 'interrupted')),
  opened_at      INTEGER NOT NULL,
  closed_at      INTEGER,
  close_reason   TEXT,
  boot_id        TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_conn_state ON ssh_connections (state, boot_id);
CREATE INDEX ix_conn_agent ON ssh_connections (agent_id, opened_at);

CREATE TABLE ssh_channels (
  id                TEXT PRIMARY KEY,
  connection_id     TEXT NOT NULL REFERENCES ssh_connections (id),
  access_session_id TEXT NOT NULL REFERENCES access_sessions (id),
  grant_id          TEXT NOT NULL REFERENCES grants (id),
  agent_id          TEXT NOT NULL,
  role_id           TEXT NOT NULL,
  kind              TEXT NOT NULL CHECK (kind IN ('shell', 'exec')),
  pty               INTEGER NOT NULL CHECK (pty IN (0, 1)),
  credential_ref    TEXT,
  state             TEXT NOT NULL CHECK (state IN ('opening', 'active', 'closed', 'failed', 'interrupted')),
  exit_status       INTEGER,
  exit_signal       TEXT,
  opened_at         INTEGER NOT NULL,
  closed_at         INTEGER,
  close_reason      TEXT,
  boot_id           TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX ix_chan_live_role ON ssh_channels (role_id, state);
CREATE INDEX ix_chan_live_agent_role ON ssh_channels (agent_id, role_id, state);
CREATE INDEX ix_chan_session ON ssh_channels (access_session_id, opened_at);
CREATE INDEX ix_chan_grant ON ssh_channels (grant_id, state);
CREATE INDEX ix_chan_state_boot ON ssh_channels (state, boot_id);

CREATE TABLE timeline_events (
  id                TEXT PRIMARY KEY,
  access_session_id TEXT REFERENCES access_sessions (id) ON DELETE CASCADE,
  request_id        TEXT REFERENCES access_requests (id),
  seq               INTEGER,
  type              TEXT NOT NULL,
  schema_version    INTEGER NOT NULL,
  at                INTEGER NOT NULL,
  connection_id     TEXT,
  channel_id        TEXT,
  segment_id        TEXT,
  data_json         TEXT NOT NULL DEFAULT '{}',
  idempotency_key   TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX ux_tl_seq ON timeline_events (access_session_id, seq) WHERE seq IS NOT NULL;
CREATE INDEX ix_tl_request ON timeline_events (request_id, at);
CREATE INDEX ix_tl_session_at ON timeline_events (access_session_id, at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
