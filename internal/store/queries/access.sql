-- name: InsertRequest :exec
INSERT INTO access_requests (id, agent_id, agent_key_id, server_id, role_id, reason_enc, requested_duration_s, state,
  idempotency_key, policy_version, created_at, expires_at, updated_at, operator_id)
VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?);

-- name: GetRequest :one
SELECT * FROM access_requests WHERE id = ?;

-- name: GetRequestByIdempotencyKey :one
SELECT * FROM access_requests WHERE agent_id = ? AND idempotency_key = ?;

-- name: GetPendingRequest :one
SELECT * FROM access_requests WHERE agent_id = ? AND server_id = ? AND role_id = ? AND state = 'pending';

-- name: CountRecentRequests :one
SELECT count(*) FROM access_requests WHERE agent_id = ? AND created_at > ?;

-- name: CountPendingRequests :one
SELECT count(*) FROM access_requests WHERE agent_id = ? AND state = 'pending';

-- name: TransitionRequest :execrows
UPDATE access_requests SET state = sqlc.arg(state), state_reason = sqlc.narg(state_reason),
  decided_at = coalesce(sqlc.narg(decided_at), decided_at), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'pending';

-- name: DuePendingRequests :many
SELECT id FROM access_requests WHERE state = 'pending' AND expires_at <= ? ORDER BY expires_at LIMIT ?;

-- name: PendingRequests :many
SELECT * FROM access_requests WHERE state = 'pending' ORDER BY created_at;

-- name: PendingRequestsForAgent :many
SELECT id FROM access_requests WHERE state = 'pending' AND agent_id = ?;

-- name: PendingRequestsForServer :many
SELECT id FROM access_requests WHERE state = 'pending' AND server_id = ?;

-- name: PendingRequestsForRole :many
SELECT id FROM access_requests WHERE state = 'pending' AND role_id = ?;

-- name: ListRequestsForAgent :many
SELECT * FROM access_requests WHERE agent_id = ? AND created_at > ? ORDER BY created_at DESC LIMIT ?;

-- name: InsertDecision :exec
INSERT INTO approval_decisions (id, request_id, outcome, actor_type, actor_id, channel, approved_duration_s, comment_enc,
  policy_version, approver_rule_id, idempotency_key, decided_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDecisionByRequest :one
SELECT * FROM approval_decisions WHERE request_id = ?;

-- name: InsertGrant :exec
INSERT INTO grants (id, request_id, decision_id, agent_id, server_id, role_id, remote_user, capabilities_json, policy_version,
  starts_at, expires_at, state, updated_at, operator_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?);

-- name: GetGrant :one
SELECT * FROM grants WHERE id = ?;

-- name: GetGrantByRequest :one
SELECT * FROM grants WHERE request_id = ?;

-- name: FindActiveGrant :one
SELECT * FROM grants
WHERE agent_id = ? AND server_id = ? AND role_id = ? AND state = 'active' AND expires_at > ?
ORDER BY expires_at DESC, id ASC LIMIT 1;

-- name: ActiveGrants :many
SELECT * FROM grants WHERE state = 'active' ORDER BY expires_at;

-- name: ActiveGrantsForAgent :many
SELECT * FROM grants WHERE state = 'active' AND agent_id = ? ORDER BY expires_at;

-- name: ActiveGrantIDsForAgent :many
SELECT id FROM grants WHERE state = 'active' AND agent_id = ?;

-- name: ActiveGrantIDsForServer :many
SELECT id FROM grants WHERE state = 'active' AND server_id = ?;

-- name: ActiveGrantIDsForRole :many
SELECT id FROM grants WHERE state = 'active' AND role_id = ?;

-- name: DueGrants :many
SELECT id FROM grants WHERE state = 'active' AND expires_at <= ? ORDER BY expires_at LIMIT ?;

-- name: EndGrant :execrows
UPDATE grants SET state = sqlc.arg(state), ended_at = sqlc.arg(now), end_reason = sqlc.arg(end_reason),
  revoked_by = sqlc.narg(revoked_by), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'active';

-- name: ClampGrant :execrows
UPDATE grants SET expires_at = sqlc.arg(expires_at), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND state = 'active' AND expires_at > sqlc.arg(expires_at);

-- name: GrantsChangedAfter :many
-- Keyset page over (updated_at, id), the key of the WITHOUT ROWID index ix_grant_updated: a mass revocation that stamps
-- more than one page of rows with the same timestamp cannot stall the enforcer's safety net (SR-13).
SELECT id, state, expires_at, updated_at FROM grants
WHERE updated_at >= sqlc.arg(after_at) AND (updated_at > sqlc.arg(after_at) OR id > sqlc.arg(after_id))
ORDER BY updated_at, id LIMIT sqlc.arg(lim);

-- name: InsertSession :exec
INSERT INTO access_sessions (id, grant_id, state, seq_reserved, opened_at, retention_class) VALUES (?, ?, 'open', ?, ?, ?);

-- name: GetSession :one
SELECT * FROM access_sessions WHERE id = ?;

-- name: GetSessionByGrant :one
SELECT * FROM access_sessions WHERE grant_id = ?;

-- name: ReserveSeq :one
UPDATE access_sessions SET seq_reserved = seq_reserved + sqlc.arg(n) WHERE id = sqlc.arg(id) RETURNING seq_reserved;

-- name: SetSessionState :execrows
UPDATE access_sessions SET state = sqlc.arg(state), closed_at = sqlc.narg(closed_at), close_reason = sqlc.narg(close_reason)
WHERE id = sqlc.arg(id) AND state != 'closed';

-- name: ClosableSessions :many
SELECT s.id, s.grant_id FROM access_sessions s JOIN grants g ON g.id = s.grant_id
WHERE s.state != 'closed' AND (g.state != 'active' OR g.expires_at <= ?)
  AND NOT EXISTS (SELECT 1 FROM ssh_channels c WHERE c.access_session_id = s.id AND c.state IN ('opening', 'active'))
LIMIT ?;

-- name: InsertConnection :exec
INSERT INTO ssh_connections (id, agent_id, agent_key_id, client_user, client_version, source_ip, state, opened_at, boot_id, operator_id)
VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?);

-- name: CloseConnection :execrows
UPDATE ssh_connections SET state = 'closed', closed_at = ?, close_reason = ? WHERE id = ? AND state = 'open';

-- name: GetConnection :one
SELECT * FROM ssh_connections WHERE id = ?;

-- name: InterruptStaleConnections :execrows
UPDATE ssh_connections SET state = 'interrupted', closed_at = ?, close_reason = 'process_restart' WHERE state = 'open' AND boot_id != ?;

-- name: InsertChannel :exec
INSERT INTO ssh_channels (id, connection_id, access_session_id, grant_id, agent_id, role_id, kind, pty, credential_ref, state,
  opened_at, boot_id, git_service, git_repo, subsystem)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'opening', ?, ?, ?, ?, ?);

-- name: GetChannel :one
SELECT * FROM ssh_channels WHERE id = ?;

-- name: ActivateChannel :execrows
UPDATE ssh_channels SET state = 'active', credential_ref = coalesce(sqlc.narg(credential_ref), credential_ref)
WHERE id = sqlc.arg(id) AND state = 'opening';

-- name: EndChannel :execrows
UPDATE ssh_channels SET state = sqlc.arg(state), exit_status = sqlc.narg(exit_status), exit_signal = sqlc.narg(exit_signal),
  closed_at = sqlc.arg(now), close_reason = sqlc.arg(close_reason), close_detail = sqlc.narg(close_detail),
  gateway_exit_code = sqlc.narg(gateway_exit_code)
WHERE id = sqlc.arg(id) AND state IN ('opening', 'active');

-- name: RecentlyEndedChannels :many
SELECT * FROM ssh_channels WHERE closed_at >= sqlc.arg(since) ORDER BY closed_at DESC LIMIT sqlc.arg(lim);

-- name: CountLiveChannelsForRole :one
SELECT count(*) FROM ssh_channels WHERE role_id = ? AND state IN ('opening', 'active');

-- name: CountLiveChannelsForAgentRole :one
SELECT count(*) FROM ssh_channels WHERE agent_id = ? AND role_id = ? AND state IN ('opening', 'active');

-- name: LiveChannels :many
SELECT * FROM ssh_channels WHERE state IN ('opening', 'active') ORDER BY opened_at;

-- name: ChannelsForSession :many
SELECT * FROM ssh_channels WHERE access_session_id = ? ORDER BY opened_at;

-- name: InterruptStaleChannels :many
UPDATE ssh_channels SET state = 'interrupted', closed_at = ?, close_reason = 'process_restart'
WHERE state IN ('opening', 'active') AND boot_id != ?
RETURNING id, access_session_id, connection_id;

-- name: InsertTimelineEvent :execrows
INSERT INTO timeline_events (id, access_session_id, request_id, seq, type, schema_version, at, connection_id, channel_id,
  segment_id, data_json, idempotency_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: TimelineForSession :many
SELECT * FROM timeline_events WHERE access_session_id = ? AND (seq IS NULL OR seq > ?) ORDER BY seq LIMIT ?;

-- name: TimelineForRequest :many
SELECT * FROM timeline_events WHERE request_id = ? ORDER BY at, id;

-- name: RevokedKeysSince :many
SELECT id, agent_id, revoked_at FROM agent_keys WHERE state = 'revoked' AND revoked_at > ? ORDER BY revoked_at;

-- name: RevokedCredentialsSince :many
SELECT id, revoked_at FROM login_credentials WHERE state = 'revoked' AND revoked_at > ? ORDER BY revoked_at;

-- name: CountChannelsForConnectionInSession :one
SELECT count(*) FROM ssh_channels WHERE connection_id = ? AND access_session_id = ?;

-- name: SessionsForConnection :many
SELECT DISTINCT access_session_id FROM ssh_channels WHERE connection_id = ?;

-- name: RecentGrantsForAgent :many
SELECT * FROM grants WHERE agent_id = ? AND (state = 'active' OR ended_at > ?) ORDER BY starts_at DESC LIMIT 100;

-- name: CountChannelsForSession :one
SELECT count(*) AS total, count(*) FILTER (WHERE state IN ('opening', 'active')) AS live
FROM ssh_channels WHERE access_session_id = ?;

-- name: InsertRequestApproval :execrows
INSERT INTO request_approvals (request_id, operator_id, channel, approved_duration_s, comment_enc, approver_rule_id, approved_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (request_id, operator_id) DO NOTHING;

-- name: ListRequestApprovals :many
SELECT * FROM request_approvals WHERE request_id = ? ORDER BY approved_at, operator_id;

-- name: ActiveConsoleGrantsOfIneligibleOperators :many
-- Web terminal grants whose administrator is disabled or no longer holds the administrator role (ADR-0055).
SELECT g.id FROM grants g JOIN operators o ON o.id = g.operator_id
WHERE g.operator_id IS NOT NULL AND g.state = 'active' AND (o.enabled = 0 OR NOT EXISTS (
  SELECT 1 FROM operator_roles r WHERE r.operator_id = o.id AND r.role = 'administrator'));

-- name: CountLiveChannelsForOperator :one
SELECT count(*) FROM ssh_channels c JOIN grants g ON g.id = c.grant_id
WHERE g.operator_id = sqlc.arg(operator_id) AND c.state IN ('opening', 'active');
