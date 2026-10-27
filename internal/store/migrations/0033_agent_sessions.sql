-- 0033_agent_sessions: one agent (one key) can run several independent conversations, for example several Claude
-- Code sessions. Each connection may name its agent session; requests and grants belong to that session, and a grant
-- is usable only by connections of the same session. '' is the shared default session of connections that name none.
-- The session is stated by the agent, not proven: it separates conversations, it is not a security boundary.

-- +goose Up
ALTER TABLE access_requests ADD COLUMN agent_session TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN agent_session TEXT NOT NULL DEFAULT '';
ALTER TABLE ssh_connections ADD COLUMN agent_session TEXT NOT NULL DEFAULT '';

-- One pending request per agent session, server and role (was per agent, server and role).
DROP INDEX ux_req_pending;
CREATE UNIQUE INDEX ux_req_pending ON access_requests (agent_id, agent_session, server_id, role_id) WHERE state = 'pending';
DROP INDEX ix_grant_lookup;
CREATE INDEX ix_grant_lookup ON grants (agent_id, agent_session, server_id, role_id, state, expires_at);

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
