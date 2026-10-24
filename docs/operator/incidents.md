# Incident runbooks

Runbooks for common incidents. Each one gives the trigger, the containment steps and
the follow-up. Actions named "API" are REST calls under `/api/v1` made by an administrator with a fresh login (and MFA
where it is enrolled). The web console offers the same actions. Every action listed here is audited.

Before you need these runbooks:
- export integrity anchors regularly to append-only storage (`hallpass anchors export`, see [backup.md](backup.md));
- keep the KEK backed up offline, separately from data backups ([keys.md](keys.md));
- route alerts on `/readyz`, disk usage and the `hallpass_*` failure metrics ([observability.md](observability.md)).

## Lockdown

Use lockdown when you cannot yet tell what is affected. It revokes every active grant (gateway-managed channels end
within 5 seconds), cancels pending requests and refuses new requests and channels. Agents can still connect and run
`list` and `status`.

1. Enable: `POST /system/lockdown`. This needs `system.lockdown.enable`: administrators, plus approvers when
   `rbac.approvers_can_lockdown` is set.
2. Investigate.
3. Lift: `DELETE /system/lockdown`. This needs `system.lockdown.lift`, administrators only, with a fresh login.
   Lifting does not restore revoked grants; agents request access again.

## Suspected agent compromise (§18.12)

Signs: unexpected requests or reasons, access from unusual source addresses, or destination audit records
(`destination.exec`) that don't match the agent's task.

1. Contain:
   - revoke the affected key (`POST /agents/{id}/keys/{kid}/revoke`); or
   - disable the agent (`POST /agents/{id}/disable`).
   Either ends the agent's live channels within 5 seconds and refuses new logins.
2. Export anchors now (`hallpass anchors export --since <last shipped seq>`), so the history up to this point is
   pinned outside the gateway.
3. Review the agent's requests, sessions and recordings, and the destination audit records if a collector is enrolled.
   Treat everything the agent printed or typed as untrusted.
4. For each destination where the agent had a shell, rotate the role's login credential: generate, install, probe,
   activate, then remove the old `authorized_keys` line (§18.11). Also check for persistence the agent may have left
   (cron, `authorized_keys`, systemd units, detached processes; see [../destination/hardening.md](../destination/hardening.md)).
5. Give the agent a new key only once the cause is understood.

## Suspected gateway compromise (§18.13)

Assume an attacker with the running process or the host plus the KEK can read all recordings and credentials and act
as HallPass toward every destination ([../security-guarantees.md](../security-guarantees.md)).

1. Enable lockdown, if the API is still trustworthy enough to use.
2. Isolate the host at the network level, keeping its disk for forensics.
3. On every destination, remove HallPass `authorized_keys` lines and distrust HallPass user CAs. These credentials
   must be considered stolen.
4. Build a clean host. Create a **new KEK** (`hallpass keys init-kek`) and restore the last backup taken before the
   compromise (`hallpass restore`). Because a restore needs the backup's own KEK, first rewrap it under the new KEK
   (`hallpass keys rotate-kek`).
5. Before serving, run `hallpass verify`, then compare the chain heads with your external anchors
   (`hallpass anchors verify FILE`). History after the last anchor cannot be trusted.
6. Rotate the gateway SSH host key (`hallpass hostkey stage`, distribute the new known_hosts line, then
   `hallpass hostkey promote`). Then generate and install new login credentials for every role.
7. Rotate integration secrets (Slack, Telegram, OIDC client secrets) and force operator password resets.

## Destination host key changed

Signs: `exec`/`connect` fail with exit 88, and a host-key alert is recorded for the server. HallPass never sends
credentials to a host whose key does not match.

1. Confirm out of band (console, cloud provider, the host's own administrators) whether the key change is expected.
2. If it is expected (reinstall, key rotation), enroll the new key and confirm its fingerprint, then retire the old
   identity.
3. If it is not, treat it as an attack on the network path or the destination: keep the server disabled
   (`PATCH /servers/{id}` with `enabled: false`) and investigate.

## Disk full / storage degraded (§18.14)

Signs: `/readyz` degraded with `disk_full` or `storage_degraded`, or free-space alerts. New requests and channels are
refused; established channels continue unless their recording fails, and mandatory recording then ends them (exit
80).

1. Free space or grow the volume. The usual causes are recordings (check retention classes, [recording.md](recording.md)),
   old backups or the pre-migration snapshots on the same volume, or WAL growth from a long-running reader.
2. Readiness recovers on its own. A database that reported "disk full" clears only after a test write of 64 KiB
   commits; recovery does not need a restart.
3. Recordings interrupted during the incident keep their `interrupted` or `failed` label. That is expected and
   accurate.

## Database corruption (§18.15)

Signs: startup refused with `storage corrupt …`, the daily integrity check failing, or readiness `failed`.

1. Stop HallPass. Keep the data directory as it is for analysis.
2. Run `hallpass verify` and keep its report.
3. Restore the latest backup that passes verification (`hallpass backup verify`, then `hallpass restore`), start, and
   let startup reconciliation run.
4. Compare chain heads with external anchors. Changes made after the backup are lost; agents request access again.

## Lost KEK

Without the KEK, encrypted data (login credentials, recordings, sealed fields) cannot be recovered, by design.

1. If any copy of the KEK exists (offline backup, secret manager), restore it to its configured location with
   mode 0400 and start.
2. If none exists, rebuild: install fresh, create a new KEK, then:
   - re-enroll servers and generate new login credentials;
   - recreate integrations and operators.
   Old recordings stay unreadable.

## Locked out of administration (§18.16)

1. On the host, as the service account: stop HallPass, then run
   `hallpass admin recover --email EMAIL` or `hallpass admin recover --email EMAIL --new-admin`. This needs the
   data-directory lock and the KEK.
2. Use the single-use recovery login within 30 minutes and fix the cause (re-enroll MFA, re-enable an account, repair
   SSO settings).
3. Every start logs a break-glass alert until an administrator acknowledges it (`POST /system/breakglass-ack`).
   Review the audit log before acknowledging.

## Approval channel or IdP outage

- **Slack or Telegram down:** a failed notification never changes a request. Approve in the web console. Outbox
  delivery retries and then gives up; delivery history shows the failures.
- **OIDC provider down:** SSO logins fail; existing web sessions continue until they expire. If SSO-only mode is on,
  use the break-glass procedure above only when access is urgent.
- **Suspected IdP or chat-account compromise:**
  - disable the affected operators or the provider mapping;
  - unlink chat identities (`DELETE /operators/{id}/provider-links/...`);
  - rotate the integration secrets.
  A compromised IdP can log in as any identity mapped for its issuer.
