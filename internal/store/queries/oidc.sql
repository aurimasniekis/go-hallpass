-- name: InsertOIDCProvider :exec
INSERT INTO oidc_providers (id, slug, display_name, issuer, client_id, client_secret_enc, scopes_json, groups_claim, provisioning, jit_json,
  allow_private_network, allow_cross_origin_endpoints, ca_bundle_pem, stepup_fallback, acr_values, end_session_enabled, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateOIDCProvider :execrows
UPDATE oidc_providers SET slug = ?, display_name = ?, issuer = ?, client_id = ?, client_secret_enc = ?, scopes_json = ?, groups_claim = ?,
  provisioning = ?, jit_json = ?, allow_private_network = ?, allow_cross_origin_endpoints = ?, ca_bundle_pem = ?, stepup_fallback = ?,
  acr_values = ?, end_session_enabled = ?, enabled = ?, test_login_ok_at = ?, test_login_by = ?, version = version + 1, updated_at = ?
WHERE id = ? AND version = ?;

-- name: GetOIDCProvider :one
SELECT * FROM oidc_providers WHERE id = ?;

-- name: GetOIDCProviderBySlug :one
SELECT * FROM oidc_providers WHERE slug = ?;

-- name: ListOIDCProviders :many
SELECT * FROM oidc_providers ORDER BY display_name;

-- name: DeleteOIDCProvider :execrows
DELETE FROM oidc_providers WHERE id = ?;

-- name: SetOIDCTestLogin :exec
UPDATE oidc_providers SET test_login_ok_at = ?, test_login_by = ? WHERE id = ?;

-- name: InsertOIDCMapping :exec
INSERT INTO oidc_group_mappings (id, provider_id, group_value, role, group_id, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteOIDCMapping :execrows
DELETE FROM oidc_group_mappings WHERE id = ? AND provider_id = ?;

-- name: ListOIDCMappings :many
SELECT * FROM oidc_group_mappings WHERE provider_id = ? ORDER BY group_value, role, group_id;

-- name: GetIdentity :one
SELECT * FROM operator_identities WHERE issuer = ? AND subject = ?;

-- name: InsertIdentity :exec
INSERT INTO operator_identities (issuer, subject, provider_id, operator_id, linked_via, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: TouchIdentity :exec
UPDATE operator_identities SET last_login_at = ? WHERE issuer = ? AND subject = ?;

-- name: ListIdentitiesForOperator :many
SELECT * FROM operator_identities WHERE operator_id = ? ORDER BY created_at;

-- name: DeleteIdentity :execrows
DELETE FROM operator_identities WHERE issuer = ? AND subject = ? AND operator_id = ?;

-- name: InsertAuthState :exec
INSERT INTO oidc_auth_states (state_hash, provider_id, purpose, nonce_hash, verifier_enc, binding_hash, return_to, operator_id, session_display, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TakeAuthState :one
DELETE FROM oidc_auth_states WHERE state_hash = ? RETURNING *;

-- name: PurgeAuthStates :execrows
DELETE FROM oidc_auth_states WHERE expires_at < ?;

-- name: DeleteSSORoles :exec
DELETE FROM operator_roles WHERE operator_id = ? AND source = 'sso';

-- name: InsertSSORole :exec
INSERT OR IGNORE INTO operator_roles (operator_id, role, source, source_ref) VALUES (?, ?, 'sso', ?);

-- name: DeleteSSOGroups :exec
DELETE FROM operator_group_members WHERE operator_id = ? AND source = 'sso';

-- name: InsertSSOGroup :exec
INSERT OR IGNORE INTO operator_group_members (group_id, operator_id, source) VALUES (?, ?, 'sso');

-- name: CountSSOAdmins :one
SELECT count(DISTINCT o.id) FROM operators o
JOIN operator_roles r ON r.operator_id = o.id AND r.role = 'administrator'
JOIN operator_identities i ON i.operator_id = o.id
JOIN oidc_providers p ON p.id = i.provider_id AND p.enabled = 1
WHERE o.enabled = 1;

-- name: ListOperatorIDsForProvider :many
SELECT DISTINCT operator_id FROM operator_identities WHERE provider_id = ? ORDER BY operator_id;
