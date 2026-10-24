-- 0021_git_remotes: git remotes are servers of kind 'git'. Their roles are access profiles whose git_rules_json holds
-- repository patterns and push ref rules; a git operation is an exec channel that records the git service and the
-- normalized repository (metadata only, no pack data).

-- +goose Up
ALTER TABLE servers ADD COLUMN kind TEXT NOT NULL DEFAULT 'ssh' CHECK (kind IN ('ssh', 'git'));
ALTER TABLE server_roles ADD COLUMN git_rules_json TEXT;
ALTER TABLE ssh_channels ADD COLUMN git_service TEXT
  CHECK (git_service IS NULL OR git_service IN ('git-upload-pack', 'git-receive-pack', 'git-upload-archive'));
ALTER TABLE ssh_channels ADD COLUMN git_repo TEXT;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
