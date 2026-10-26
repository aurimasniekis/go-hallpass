-- 0031_api_token_parent: an administrator API token may issue tokens (ADR-0058). parent_token_id names the token that
-- issued one; revoking a token also revokes the tokens it issued, and a token issued by a token cannot issue tokens.

-- +goose Up
ALTER TABLE api_tokens ADD COLUMN parent_token_id TEXT REFERENCES api_tokens (id);
CREATE INDEX ix_api_tokens_parent ON api_tokens (parent_token_id) WHERE parent_token_id IS NOT NULL;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
