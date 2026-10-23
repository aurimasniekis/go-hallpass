-- 0013_session_provider: record which OIDC provider created a web session, so logout offers that provider's
-- end-session endpoint (HP-OIDC-015).

-- +goose Up
ALTER TABLE web_sessions ADD COLUMN auth_provider TEXT NOT NULL DEFAULT '';

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
