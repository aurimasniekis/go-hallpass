# Versioning policy

HallPass has several independently versioned interfaces (HP-DOC-006). The binary version says which release you run.
Each interface below has its own version and compatibility rules. A release lists every interface change in
[`CHANGELOG.md`](../CHANGELOG.md).

| Interface | Version marker | Where it is defined |
|---|---|---|
| Binary / release | `vMAJOR.MINOR.PATCH[-PRERELEASE]` (SemVer 2.0.0) | git tag, `hallpass version` |
| REST API | URL prefix `/api/v1` | OpenAPI spec (WP15, HP-API-001/002) |
| Agent JSON output | `"schema": "hallpass.<name>/v1"` | [`api/ssh-schemas/`](../api/ssh-schemas), [agent/json-schemas.md](agent/json-schemas.md) |
| Agent exit codes | stable numeric codes 80–90 | [agent/exit-codes.md](agent/exit-codes.md) |
| Recording format | magic `HPREC1`, header `v`, event types `<name>@N` | [formats/hprec1.md](formats/hprec1.md) §11 |
| Database schema | goose migration number (`0001`, `0002`, …) | `internal/store/migrations/` |
| Configuration | YAML keys and `HALLPASS_*` variables | [operator/configuration.md](operator/configuration.md) |

## Binary and releases

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), tags `vX.Y.Z`; pre-releases `vX.Y.Z-rc.N`.
The release workflow rejects any other tag format.

The version is embedded at link time (`internal/buildinfo`) and printed by `hallpass version` and over SSH by `version`.
Container image tags drop the `v` (`aurimasniekis/hallpass:X.Y.Z` on Docker Hub, mirrored to
`ghcr.io/aurimasniekis/go-hallpass:X.Y.Z`), and `latest` only follows final releases. The release procedure is in
[RELEASING.md](RELEASING.md).

The binary version summarizes the interfaces below:

- **MAJOR**: a breaking change to any public interface. That means a new REST API major version (`/api/v2`) or removal
  of `/api/v1`, removal of a JSON schema version or exit code, the end of reading support for a recording format version
  that may still be in retention, removal or renaming of a configuration key or default, or a change that requires a
  manual migration step.
- **MINOR**: new features, additive API and schema changes, new configuration keys, new database migrations,
  deprecations, and a new recording format version that is written by default (older versions stay readable).
- **PATCH**: bug and security fixes with no interface change. A patch release may include a database migration only
  when it is needed for a fix, and it is called out in the changelog.

Before 1.0.0, MINOR releases may contain breaking changes. Each one is listed under **Changed** or **Removed** with
upgrade instructions.

Security fixes are released as PATCH releases for the latest MINOR line. Older lines are not maintained unless a release
note says otherwise.

## REST API (`/api/v1`)

- Changes within `/api/v1` are additive only (HP-API-002): new endpoints, new optional request fields, new response
  fields, new enum values in fields documented as open. Clients must ignore unknown response fields.
- Breaking changes (removing or renaming fields or endpoints, changing types or semantics, new required inputs,
  stricter validation of existing inputs) require `/api/v2`. `/api/v1` and `/api/v2` are then served side by side for at
  least one MINOR release, and the changelog announces the deprecation first.
- Deprecations are marked in the OpenAPI spec (`deprecated: true`) and listed under **Deprecated** in the changelog at
  least one MINOR release before removal.
- Server-sent event types on `/api/v1/events` follow the same rules.

## Agent JSON schemas (`hallpass.<name>/v1`)

- Every `--json` document carries a `schema` field (HP-SSH-018). Published JSON Schema files are in
  `api/ssh-schemas/hallpass.<name>.v1.json`.
- Within `v1`, only additive changes are allowed: new optional fields, and new values for fields documented as open sets.
  Agents must ignore unknown fields.
- Removing or renaming a field, changing a type, or changing the meaning of a value requires `hallpass.<name>/v2`, a
  new schema file, and a **Changed** changelog entry. Moving an existing schema to `v2` is a MAJOR binary change.
- Exit codes 80–90 and error `code` strings are never renumbered or reused. New codes may be added.

## Recording format (`HPREC1`)

Defined in [formats/hprec1.md](formats/hprec1.md) §11, summarized here:

- The magic `HPREC1` fixes the container layout, framing and cryptography. Any change to these requires a new magic
  (`HPREC2`).
- The header `v` fixes the record-type registry and payload encodings. New record types or payload fields require a new `v`.
  Readers reject an unknown `v` instead of skipping records.
- Event types are versioned individually (`terminal.output@1`, HP-REC-001). Type codes and names are never reused.
- Writers write only the newest version they implement. Readers keep support for every version that can still exist
  within the configured retention, so a release can drop reading support for a format only in a MAJOR release, and only
  after the longest supported retention has passed.
- A format change that has not been externally reviewed is labeled as such in the release notes (RG-9).

## Database schema (migrations)

- Migrations are embedded, numbered sequentially, applied in order at startup or with `hallpass migrate`, and forward-only.
  Applied migrations are never edited. Fixes ship as new migrations.
- A pre-migration snapshot is written before any migration runs on an existing database.
- A binary refuses a database whose schema is newer than it supports. Downgrade only by restoring a pre-upgrade backup
  ([operator/upgrade.md](operator/upgrade.md)).
- Each release's changelog states whether it contains migrations, and whether they are long-running (data rewrites).
- Upgrades are supported from the previous MINOR release. The release test upgrades a database fixture from the
  previous release (RG-7).

## Configuration

- Configuration keys and `HALLPASS_*` variables are part of the public interface. Unknown keys are errors, so removing
  or renaming a key is a breaking change. Keys are deprecated first: still accepted, with a warning, for at least one
  MINOR release.
- Changing a default that weakens a security property requires a recorded ADR labeled **security-relevant change**
  (AGENTS.md) and a **Security** entry in the changelog.

## Changelog

[`CHANGELOG.md`](../CHANGELOG.md) follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), with sections
Added, Changed, Deprecated, Removed, Fixed, Security. Entries name affected interfaces (API, schema, format, migration,
config) and requirement IDs where relevant. Status words follow GOAL.md §7: an entry never claims more than
*implemented*, *tested* or *externally verified* evidence supports.
