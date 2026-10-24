-- 0020_access_chat_link_revocation: chat provider links (and unused link codes) end when the operator is disabled or
-- its local password is set, reset or changed (security review SR-10, HP-NTF-011, T-11). A stolen web session can
-- create a link; the standard incident response (disable the account, reset the password) must also remove that
-- persistent chat approval power. The operator links the chat identity again after the incident. Triggers keep this
-- atomic with every path that changes these rows (API, CLI recovery, invitations, restores of older code paths).
-- Password rehashing on login keeps changed_at and so leaves links alone.

-- +goose Up
-- +goose StatementBegin
CREATE TRIGGER tr_provider_links_operator_disabled AFTER UPDATE OF enabled ON operators
WHEN NEW.enabled = 0 AND OLD.enabled = 1
BEGIN
  DELETE FROM provider_links WHERE operator_id = NEW.id;
  DELETE FROM provider_link_codes WHERE operator_id = NEW.id AND used_at IS NULL;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER tr_provider_links_password_changed AFTER UPDATE OF changed_at ON operator_local_credentials
WHEN NEW.changed_at IS NOT OLD.changed_at
BEGIN
  DELETE FROM provider_links WHERE operator_id = NEW.operator_id;
  DELETE FROM provider_link_codes WHERE operator_id = NEW.operator_id AND used_at IS NULL;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER tr_provider_links_password_set AFTER INSERT ON operator_local_credentials
BEGIN
  DELETE FROM provider_links WHERE operator_id = NEW.operator_id;
  DELETE FROM provider_link_codes WHERE operator_id = NEW.operator_id AND used_at IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
