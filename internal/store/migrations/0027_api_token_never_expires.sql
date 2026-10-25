-- 0027_api_token_never_expires: API tokens may be issued without expiry (ADR-0053). Their expires_at holds a far-future
-- value so every expiry comparison stays unchanged; never_expires records that the operator chose it.

-- +goose Up
ALTER TABLE api_tokens ADD COLUMN never_expires INTEGER NOT NULL DEFAULT 0 CHECK (never_expires IN (0, 1));

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
