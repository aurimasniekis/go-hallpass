-- 0022_multi_approval: a role can require several distinct approvers. Each approval is recorded here; the request
-- stays pending until the required number is reached, and the last approval creates the decision and the grant
-- (approval_decisions keeps one final decision per request).

-- +goose Up
ALTER TABLE server_roles ADD COLUMN approvals_required INTEGER NOT NULL DEFAULT 1 CHECK (approvals_required BETWEEN 1 AND 5);

CREATE TABLE request_approvals (
  request_id          TEXT NOT NULL REFERENCES access_requests (id),
  operator_id         TEXT NOT NULL,
  channel             TEXT NOT NULL CHECK (channel IN ('web', 'slack', 'telegram', 'api')),
  approved_duration_s INTEGER NOT NULL CHECK (approved_duration_s > 0),
  comment_enc         BLOB,
  approver_rule_id    TEXT,
  approved_at         INTEGER NOT NULL,
  PRIMARY KEY (request_id, operator_id)
) STRICT, WITHOUT ROWID;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
