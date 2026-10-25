-- 0029_web_terminal: administrators open recorded terminals from the console (ADR-0055). A web terminal runs as an
-- ordinary request → decision → grant → session for one built-in agent that can never authenticate: it is created
-- disabled and already deleted (hidden from lists and policy), and its only key is revoked. operator_id names the
-- administrator on the request, the grant and the connection of each web terminal; it is NULL for agent access.

-- +goose Up
ALTER TABLE access_requests ADD COLUMN operator_id TEXT REFERENCES operators (id);
ALTER TABLE grants ADD COLUMN operator_id TEXT REFERENCES operators (id);
ALTER TABLE ssh_connections ADD COLUMN operator_id TEXT REFERENCES operators (id);
CREATE INDEX ix_grant_operator ON grants (operator_id, state) WHERE operator_id IS NOT NULL;

INSERT INTO agents (id, name, description, enabled, version, created_at, created_by, updated_at, updated_by,
  disabled_at, disabled_by, deleted_at, deleted_by, deleted_name)
VALUES ('agt_00000000000000000000000000', '~agt_00000000000000000000000000', 'Web terminals opened by administrators', 0, 1,
  0, 'system', 0, 'system', 0, 'system', 0, 'system', 'web terminal');

INSERT INTO agent_keys (id, agent_id, fingerprint_sha256, algorithm, bits, public_key, comment, state, created_at, created_by,
  revoked_at, revoked_by)
VALUES ('key_00000000000000000000000000', 'agt_00000000000000000000000000', 'SHA256:none-web-terminal', 'none', 0, 'none',
  'web terminal: never authenticates', 'revoked', 0, 'system', 0, 'system');

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
